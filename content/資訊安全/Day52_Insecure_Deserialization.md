---
title: "Day 52：不安全的反序列化（Insecure Deserialization）— 從 Java 原生序列化到 JSON/YAML 的 RCE"
date: 2026-06-17
tags: ["Deserialization", "RCE", "Java", "Gadget Chain"]
---

# Day 52：不安全的反序列化（Insecure Deserialization）— 從 Java 原生序列化到 JSON/YAML 的 RCE

> 「我只是把使用者傳來的資料還原成物件，能有多危險？」
> —— 危險到可以直接幫攻擊者在你的伺服器上執行任意指令（RCE）。反序列化是少數「一個漏洞 = 直接拿 shell」的類型。

接續 Day51 預告：昨天 gRPC 講的是「結構性」反序列化的 DoS（輸入小、記憶體大）；今天升級到更致命的一種——攻擊者**控制序列化資料的內容**，在反序列化的瞬間觸發任意程式碼執行。這是 OWASP 長年榜上有名的 A08:2021 *Software and Data Integrity Failures*。

---

## 一、為什麼反序列化能變成 RCE？

序列化（serialization）是把記憶體裡的物件變成 bytes / 字串，反序列化（deserialization）則是反過來把 bytes 還原成物件。問題出在：**還原的過程不只是「填資料」，它可能會呼叫建構子、setter、特殊的回呼方法**。

如果這些方法在「物件被還原時」會自動執行，而攻擊者又能決定「要還原成哪個類別、欄位塞什麼值」，那他就能拼湊出一條 **gadget chain**——利用 classpath 上既有的類別，串成一連串方法呼叫，最後落到 `Runtime.exec()` 之類的危險呼叫。

核心心法一句話：**永遠不要對「不可信來源」的資料做「會自動決定型別」的反序列化。**

---

## 二、Java 原生序列化：`ObjectInputStream` 的原罪

Java 的 `Serializable` + `ObjectInputStream` 是最經典的雷。`readObject()` 在還原時會：

1. 依照資料流裡指定的類別名稱去 classpath 找類別並實例化；
2. 自動呼叫該類別的 `readObject()` / `readResolve()` / `finalize()` 等魔術方法。

只要 classpath 上存在像 Apache Commons Collections（早期版本）這類含有可利用魔術方法的類別，攻擊者送一段精心構造的 byte stream，就能在 `readObject()` 期間觸發 RCE——這就是 ysoserial 那一整套 payload 的原理。

### ❌ 危險寫法

```java
// 直接把 HTTP body / 訊息佇列訊息 / cookie 丟進 ObjectInputStream
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject(); // 還原的瞬間就可能被 RCE，連你自己的程式碼都還沒跑到
```

### ✅ 防禦一：根本不要用 Java 原生序列化處理外部資料

最徹底的做法是**改用資料型格式（JSON / Protobuf）**，並只反序列化成你定義好的 DTO。Day51 的 Protobuf 就是好選擇——它沒有「依名稱實例化任意類別」的能力。

### ✅ 防禦二：非用不可時，套用型別白名單（ObjectInputFilter）

Java 9+ 內建 `ObjectInputFilter`（JEP 290），可以在還原**之前**就攔截不允許的類別：

```java
import java.io.ObjectInputStream;
import java.io.ObjectInputFilter;

ObjectInputStream ois = new ObjectInputStream(request.getInputStream());

// 只允許自家 DTO 套件 + 基本型別，其餘一律拒絕（白名單，預設拒絕）
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
        "com.myapp.dto.*;java.lang.*;java.util.*;!*");
ois.setObjectInputFilter(filter);

Object obj = ois.readObject();
```

> `ObjectInputFilter` 與 `ObjectInputFilter.Config.createFilter(String)` 是 `java.io` 自 Java 9 起的標準 API（JEP 290），Java 8 後期版本也有 backport。filter 字串中 `!*` 代表「其餘全部拒絕」，是白名單的關鍵——白名單永遠優於黑名單，因為黑名單永遠補不完 gadget。

---

## 三、JSON 也會中招：Jackson 的「多型」陷阱

很多人以為「我用 JSON 就安全了」。錯。JSON 本身是資料格式很安全，但**當你開啟「依 JSON 內容決定 Java 型別」的功能時**，就重現了 Java 原生序列化的問題。

罪魁禍首是 Jackson 的 **default typing**：

### ❌ 危險寫法

```java
ObjectMapper mapper = new ObjectMapper();
// 開啟後，JSON 裡可以用 "@class":"任意類別" 指定要反序列化成什麼，
// 攻擊者就能指定一個 gadget 類別 → RCE
mapper.enableDefaultTyping(); // 已被官方標記為危險 / deprecated
```

`enableDefaultTyping()` 會讓 Jackson 信任 JSON 裡攜帶的型別資訊（如 `@class`），等於把「決定要實例化哪個類別」的權力交給輸入者。

### ✅ 安全做法：不要 default typing，反序列化成明確的 DTO

```java
ObjectMapper mapper = new ObjectMapper();
// 預設就不開 default typing，直接綁定到具體型別
UserDto user = mapper.readValue(json, UserDto.class);
```

如果業務真的需要多型（polymorphism），用 `@JsonTypeInfo` 搭配 `@JsonSubTypes` **明確列舉允許的子型別**，或用 Jackson 的 `PolymorphicTypeValidator`（`BasicPolymorphicTypeValidator`）限制 base type，而不是放任 `activateDefaultTyping`。

```java
// 若一定要多型，限制只允許特定 base type 底下的子類別
PolymorphicTypeValidator ptv = BasicPolymorphicTypeValidator.builder()
        .allowIfSubType("com.myapp.dto.")   // 只信任自家 DTO 套件
        .build();
ObjectMapper mapper = JsonMapper.builder()
        .activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.NON_FINAL)
        .build();
```

> `PolymorphicTypeValidator` / `BasicPolymorphicTypeValidator` 是 Jackson 2.10+ 提供、用來取代裸 default typing 的安全機制；舊的 `enableDefaultTyping()` 已 deprecated。能不用多型就不用，是最安全的。

---

## 四、YAML 的隱形地雷：SnakeYAML

YAML 比 JSON 更危險，因為它原生就支援「指定型別標籤」。SnakeYAML 舊版用裸 `new Yaml()` 搭配 `load()` 時，YAML 文件裡可以寫 `!!javax.script.ScriptEngineManager [...]` 之類的標籤，直接建構任意類別 → RCE。

### ❌ 危險寫法

```java
// 舊版 SnakeYAML 的 load() 會信任 YAML 裡的 !!型別 標籤
Yaml yaml = new Yaml();
MyConfig cfg = yaml.load(untrustedYamlString); // 可被構造成 RCE
```

### ✅ 安全做法：用 SafeConstructor / 明確型別

```java
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.LoaderOptions;

// SafeConstructor 只還原基本型別（Map / List / String / Number），
// 不會去實例化任意類別
Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
Object data = yaml.load(untrustedYamlString);
```

> `SafeConstructor` 是 SnakeYAML 官方提供的安全建構子。SnakeYAML 2.x 起，預設行為已改得更安全（不再允許任意全域型別），但**明確使用 `SafeConstructor`** 仍是最保險的寫法。也可以改用只做資料綁定的 SnakeYAML Engine 或 Jackson YAML（同樣不要開 default typing）。

---

## 五、Go 的情況：天生比較安全，但別大意

Go 沒有「依資料內容自動實例化任意型別」的機制——`encoding/json` 一定要你給定目標 struct，所以 Go **基本免疫於 Java 那種 gadget chain RCE**。但仍有幾個要注意的點：

```go
type UserDTO struct {
    Name string `json:"name"`
    Role string `json:"role"`
}

func handler(w http.ResponseWriter, r *http.Request) {
    // 限制 body 大小，避免反序列化 DoS（呼應 Day51 的訊息大小上限）
    r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB

    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields() // 拒絕未知欄位，避免被塞奇怪資料

    var u UserDTO
    if err := dec.Decode(&u); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    // u 只會是你定義的 DTO，不會變成別的型別
}
```

Go 真正要小心的是：

- **`encoding/gob`**：Go 自己的二進位序列化，雖然不會 RCE，但對不可信來源仍要設大小上限、避免 gob bomb（巨大 / 深巢狀資料耗盡記憶體，本質同 Day51）。
- **反序列化進 `interface{}` / `map[string]interface{}`**：型別不明確時容易在後續處理踩雷，盡量綁到明確 struct。
- **第三方 YAML（`gopkg.in/yaml.v3`）**：同樣只綁到明確 struct，不要 unmarshal 進 `interface{}` 後再「依內容當作型別」處理。

核心對比：**Java 的危險來自「資料能決定型別」；Go 把型別權力留在程式碼這端**——這正是防禦的本質：永遠由你的程式碼決定要還原成什麼，而不是由輸入決定。

---

## 六、容易被忽略的細節

1. **反序列化點藏得很深**：cookie、session、訊息佇列（JMS / Kafka 的物件訊息）、快取（Redis 存 Java 物件）、RMI、JNDI——不是只有 HTTP body。盤點所有「外部資料變成物件」的入口。
2. **黑名單擋不完**：嘗試用「禁止某些類別」來防 gadget 註定失敗，新 gadget chain 一直被挖出來。一律用**白名單**（只允許自家 DTO）。
3. **依賴版本要顧**：Commons Collections、Jackson、SnakeYAML、Fastjson 都出過反序列化 CVE。搭配 Day（依賴掃描）做 SCA，定期升級。
4. **簽章 / 完整性保護**：若資料一定要序列化後傳遞（如 token），用 Day48 的 HMAC 簽章驗證來源與完整性，確保資料沒被竄改——不過簽章只防竄改，**不能取代**「不要反序列化不可信型別」。
5. **最小化攻擊面**：production 移除用不到的、含已知 gadget 的函式庫，縮小可被串連的類別池。

---

## 七、後端工程師的 Checklist

- [ ] **絕不**對不可信來源用 Java 原生 `ObjectInputStream.readObject()`；改用 JSON / Protobuf + 明確 DTO。
- [ ] 非用原生序列化不可時，設定 **`ObjectInputFilter` 型別白名單**（`!*` 結尾，預設拒絕）。
- [ ] Jackson **不要 `enableDefaultTyping()`**；需要多型就用 `PolymorphicTypeValidator` 限制 base type。
- [ ] YAML 用 **`SafeConstructor`** 或只綁定明確 struct，不要裸 `new Yaml().load()`。
- [ ] Go 反序列化綁到**明確 struct**，搭配 `MaxBytesReader` 與 `DisallowUnknownFields`。
- [ ] 盤點所有反序列化入口（cookie / MQ / cache / RMI / JNDI），不是只看 HTTP body。
- [ ] 對含已知 gadget 的依賴做 **SCA 掃描與升級**，移除不用的函式庫。

---

## 八、一句話總結

> **不安全反序列化的本質是「讓輸入決定要實例化哪個類別」。防禦只有一招最可靠——由你的程式碼決定型別（明確 DTO + 白名單），永遠不要相信資料自帶的型別資訊。**
> Java 原生序列化能避就避、Jackson 別開 default typing、YAML 用 SafeConstructor、Go 綁明確 struct。

---

## 延伸閱讀

- OWASP — A08:2021 Software and Data Integrity Failures、Deserialization Cheat Sheet
- Java — `ObjectInputFilter`（JEP 290 Serialization Filtering）
- Jackson — `PolymorphicTypeValidator`、為何 `enableDefaultTyping` 危險
- SnakeYAML — `SafeConstructor`
- ysoserial — Java 反序列化 gadget chain 工具（理解攻擊原理用）
- 前文：Day48 HMAC API 簽章、Day49 BFLA / 微服務授權、Day50 GraphQL 安全、Day51 gRPC / Protobuf 安全

---

明天預告：**Day 53 — SSRF（Server-Side Request Forgery）：當你的伺服器變成攻擊者的跳板**
（今天反序列化講的是「攻擊者控制資料內容」；明天換成「攻擊者控制伺服器發出的請求」——讓你的後端去打內網服務、雲端 metadata endpoint（如 169.254.169.254）竊取憑證。會講 URL 解析繞過、DNS rebinding、為何黑名單 IP 過濾擋不住，並用 Java 與 Go 示範「白名單 + 禁用 redirect + 阻擋內網網段」的安全 HTTP client 寫法。）
