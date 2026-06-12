---
title: "Day 29：NoSQL Injection（NoSQL 注入攻擊）"
date: 2026-05-25
tags: ["Injection", "NoSQL", "MongoDB"]
---

# Day 29：NoSQL Injection（NoSQL 注入攻擊）

> 「沒有 SQL，就不會被 SQL Injection 攻擊了吧？」
> 很抱歉，這是個迷思。NoSQL 一樣會被注入，只是換了一種姿勢而已。

---

## 一、什麼是 NoSQL Injection？

**NoSQL Injection** 指的是攻擊者透過操控傳入 NoSQL 資料庫（如 **MongoDB**、**CouchDB**、**Cassandra**、**DynamoDB** 等）的查詢內容，繞過原本的邏輯、取得不該看到的資料、或執行未授權的操作。

在 Day01 我們談過 SQL Injection 是「字串拼接 SQL 語法」造成的，那 NoSQL 沒有 SQL 語法，怎麼會被注入？

關鍵在於：

1. **NoSQL 查詢通常是 JSON / BSON 物件**：如果直接把使用者輸入塞進物件結構，攻擊者就能注入「查詢運算子」。
2. **某些 NoSQL（如 MongoDB）支援 JavaScript 表達式**：例如 `$where`、`mapReduce`，這等於把字串當程式執行，跟 `eval()` 一樣危險。
3. **驅動 / ORM 預期型別**：你以為傳進來的是 `String`，但其實是 `Map<String, Object>`，造成型別混淆攻擊。

---

## 二、最經典的範例：MongoDB 登入繞過

假設你有個登入 API（用 Node.js / Express，這是為了示範最常被攻擊的場景；待會我們再看 Java/Go）：

```js
// 危險寫法（示意）
app.post('/login', async (req, res) => {
  const user = await db.collection('users').findOne({
    username: req.body.username,
    password: req.body.password
  });
  if (user) return res.json({ ok: true });
  return res.status(401).json({ ok: false });
});
```

正常使用者會送：

```json
{ "username": "edison", "password": "P@ssw0rd" }
```

但攻擊者送出：

```json
{ "username": "edison", "password": { "$ne": null } }
```

實際被執行的查詢變成：

```js
db.collection('users').findOne({
  username: "edison",
  password: { $ne: null }   // 「密碼不等於 null」永遠為真！
});
```

→ 攻擊者**不需要知道密碼**就能登入任何帳號。

這就是最常見的 **Operator Injection（運算子注入）**。

---

## 三、其他常見的 NoSQL 注入手法

### 1. `$ne` / `$gt` / `$regex` 比較運算子注入

```json
{ "username": { "$gt": "" }, "password": { "$gt": "" } }
```

→ 兩個欄位都「大於空字串」永遠為真，等同於 `WHERE 1=1`。

### 2. `$where` JavaScript 注入（MongoDB 特有）

```js
db.users.find({
  $where: "this.username == '" + req.body.username + "'"
});
```

攻擊者傳入：

```
admin'; return true; var x='
```

→ 整個 `$where` 變成一段惡意 JavaScript，可以做 DoS（無窮迴圈）或資料外洩。

### 3. Blind NoSQL Injection（盲注）

利用 `$regex` 一個一個字元猜密碼：

```json
{ "username": "admin", "password": { "$regex": "^a" } }
{ "username": "admin", "password": { "$regex": "^ab" } }
...
```

只要 API 回傳的「成功 / 失敗」不同，攻擊者就能逐字推算密碼。

### 4. Aggregation Pipeline 注入

如果允許前端傳入 pipeline JSON 直接放進 `aggregate(...)`，攻擊者可以注入 `$lookup` 撈出其他 collection 的資料。

---

## 四、後端工程師最該注意的「型別混淆」

這是 Java / Go 工程師特別需要警惕的地方。

許多 Web Framework 會自動把 JSON body 反序列化成物件。如果你定義成 `Map<String, Object>` 或寬鬆型別，就會把 `{"$ne": null}` 當成合法資料傳給 MongoDB Driver。

> 核心防禦觀念：**永遠把使用者輸入當作「值」（Value），絕對不要當成「查詢結構」（Query Structure）**。

---

## 五、Java 範例（Spring Boot + Spring Data MongoDB）

### 危險寫法 1：直接收 `Map` 拼查詢

```java
// BAD：型別寬鬆，攻擊者可以注入運算子
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody Map<String, Object> body) {
    Query query = new Query();
    query.addCriteria(Criteria.where("username").is(body.get("username"))
                              .and("password").is(body.get("password")));
    User user = mongoTemplate.findOne(query, User.class);
    return user != null ? ResponseEntity.ok().build()
                        : ResponseEntity.status(401).build();
}
```

當 `body.get("password")` 是 `{"$ne": null}`（一個 `Map`）時，`Criteria.is(...)` 會把整個 `Map` 當成 BSON 物件丟下去查 → **登入繞過**。

### 安全寫法 1：強型別 DTO + 驗證

```java
// GOOD：明確宣告型別，框架會做型別轉換失敗即拒絕
public record LoginRequest(
    @NotBlank @Size(max = 64) String username,
    @NotBlank @Size(max = 128) String password
) {}

@PostMapping("/login")
public ResponseEntity<?> login(@Valid @RequestBody LoginRequest req) {
    Query query = new Query(
        Criteria.where("username").is(req.username())
                .and("passwordHash").is(hash(req.password()))   // 比對 hash，不是明文！
    );
    User user = mongoTemplate.findOne(query, User.class);
    return user != null ? ResponseEntity.ok().build()
                        : ResponseEntity.status(401).build();
}
```

關鍵點：

- 用 `record` 或強型別 DTO 把 `password` 宣告成 `String`。當攻擊者送 `{"$ne": null}`（一個物件）時，Jackson 沒辦法把物件塞進 `String` 欄位，會直接拋例外（回 400），運算子根本進不到查詢裡。
- 加上 `@Valid` + `@NotBlank` + `@Size` 過濾異常值。
- 密碼必須比對 **bcrypt / Argon2** 雜湊（複習 Day04）。

### 危險寫法 2：使用 `$where`

```java
// BAD：絕對不要這樣做！
String js = "this.username == '" + username + "'";
Query query = new BasicQuery("{ $where: \"" + js + "\" }");
```

→ 完全等同於 `eval()`，任意 JavaScript 都能執行。

### 安全寫法 2：禁用 `$where`

- **永遠不要**用字串拼接 `$where`。
- 若 MongoDB 部署可控，建議在 Server 端設定 `--noscripting` 或 Atlas 環境直接禁用 server-side JS。

---

## 六、Go 範例（mongo-go-driver）

### 危險寫法：用 `bson.M` 接收任意輸入

```go
// BAD：把 request body 直接餵給 MongoDB
type LoginReq struct {
    Username interface{} `json:"username"`
    Password interface{} `json:"password"`
}

func login(w http.ResponseWriter, r *http.Request) {
    var req LoginReq
    json.NewDecoder(r.Body).Decode(&req)

    filter := bson.M{
        "username": req.Username,
        "password": req.Password,
    }
    var user User
    err := coll.FindOne(r.Context(), filter).Decode(&user)
    if err == nil {
        w.WriteHeader(http.StatusOK)
        return
    }
    w.WriteHeader(http.StatusUnauthorized)
}
```

當 JSON 是 `{"password": {"$ne": null}}` 時，`req.Password` 會是 `map[string]interface{}{"$ne": nil}`，filter 變成查詢運算子 → **登入繞過**。

### 安全寫法：強型別 + 驗證

```go
// GOOD：明確使用 string，並驗證長度
type LoginReq struct {
    Username string `json:"username" validate:"required,min=1,max=64"`
    Password string `json:"password" validate:"required,min=8,max=128"`
}

var validate = validator.New()

func login(w http.ResponseWriter, r *http.Request) {
    var req LoginReq
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    if err := validate.Struct(req); err != nil {
        http.Error(w, "invalid input", http.StatusBadRequest)
        return
    }

    // 比對密碼雜湊，而不是明文
    filter := bson.M{"username": req.Username}
    var user User
    if err := coll.FindOne(r.Context(), filter).Decode(&user); err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(req.Password)); err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    w.WriteHeader(http.StatusOK)
}
```

關鍵點：

- 用 `string`（而非 `interface{}` 或 `bson.M`）強制反序列化，攻擊者送 `{"$ne": null}` 時 JSON decode 會直接失敗。
- 使用 `go-playground/validator` 做欄位驗證。
- 用 `bcrypt.CompareHashAndPassword` 比對密碼，邏輯與儲存分離。

---

## 七、Aggregation Pipeline 也要小心

```go
// BAD：讓使用者控制 pipeline
var pipeline []bson.M
json.NewDecoder(r.Body).Decode(&pipeline)
cursor, _ := coll.Aggregate(ctx, pipeline)
```

→ 攻擊者可以注入 `$lookup`、`$out`、`$merge` 撈光整個資料庫，甚至寫入其他 collection。

**永遠在後端組裝 pipeline，前端只傳「參數」**。

---

## 八、防禦清單（NoSQLi Checklist）

1. **強型別 DTO**：所有 request body 反序列化到 `String`、`int`、`record` / `struct`，**禁用** `Map<String, Object>` / `bson.M` / `interface{}` 接收使用者輸入。
2. **輸入驗證**：用 `@Valid` (Java) 或 `validator` (Go) 限制長度、格式、白名單。
3. **比對密碼用 hash，不要直接查詢**：先查使用者，再用 `bcrypt.compare` 驗密碼（即使 username 被注入，也撈不出來）。
4. **禁用 `$where` 與 server-side JavaScript**：MongoDB 啟動參數加 `--noscripting`，或在 Atlas 上停用 server JS。
5. **白名單欄位 / 運算子**：若真的要讓使用者篩選，後端限定允許的欄位與運算子（例如只允許 `$eq`、`$in`）。
6. **最小權限原則**：應用程式用的 DB 帳號只能 read / write 必要 collection，不要給 `dbOwner`、`root`。
7. **Logging & Monitoring**：偵測異常查詢（複習 Day16），例如出現 `$ne`、`$gt`、`$where` 但前端沒這功能 → 告警。
8. **WAF / Schema Validation**：MongoDB 4.2+ 支援 [JSON Schema Validator](https://www.mongodb.com/docs/manual/core/schema-validation/)，可在 collection 層級強制欄位型別。

---

## 九、一個自我檢測小練習

下面這段 Java 程式，看出問題了嗎？

```java
@GetMapping("/search")
public List<Product> search(@RequestParam Map<String, String> params) {
    Query query = new Query();
    params.forEach((k, v) -> query.addCriteria(Criteria.where(k).is(v)));
    return mongoTemplate.find(query, Product.class);
}
```

問題：

1. **欄位名稱**由使用者控制 → 可查詢任何欄位（如 `creditCardNumber`、`passwordHash`）。
2. **沒做白名單** → 即便 `v` 是 `String`，攻擊者也能透過 query string 傳入 `?passwordHash=xxx` 偷資訊。

**修正方向**：建立允許查詢欄位的白名單，並用 enum / switch 對應，禁止讓使用者直接決定 field name。

---

## 十、今日重點回顧

- NoSQL Injection 不靠 SQL 語法，靠的是**注入查詢運算子**或**注入 JavaScript**。
- 最危險的根因是「**型別寬鬆**」：把使用者輸入當成查詢結構而非純值。
- 三道牆：**強型別 DTO → 輸入驗證 → 邏輯分離（查使用者 vs 比密碼）**。
- 額外加固：禁 `$where`、限制 DB 帳號權限、加 schema validator、紀錄異常查詢。

---

**明天預告 (Day 30)**：我們會談 **Server-Side Cache Poisoning（伺服器端快取污染）**，看看 CDN / Reverse Proxy 怎麼變成攻擊的幫兇。

> 系列文章索引：Day01 (SQL Injection) → Day28 (FIDO2/Passkey) → **Day29 (NoSQL Injection)**
