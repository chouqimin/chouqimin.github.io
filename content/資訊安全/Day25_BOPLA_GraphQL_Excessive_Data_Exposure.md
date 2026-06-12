---
title: "Day 25：Broken Object Property Level Authorization (BOPLA) 與 GraphQL 過度資料暴露"
date: 2026-05-21
tags: ["API 安全", "GraphQL", "存取控制"]
---

# Day 25：Broken Object Property Level Authorization (BOPLA) 與 GraphQL 過度資料暴露

> 後端工程師資安系列 — Day 25
> 日期：2026-05-21

## 一、前情提要

Day 07 我們講過 **Broken Object Level Authorization (BOLA)**，俗稱 IDOR：「你不是 user 42，但你呼叫 `/api/users/42` 我居然回給你」。
Day 08 補強了輸入端的 **Mass Assignment**：「你不該能改的欄位（例如 `is_admin`），你用 JSON 送過來我居然改了」。

今天的主題是 OWASP **API Security Top 10 2023** 新版的第三名 — **Broken Object Property Level Authorization (BOPLA)**。它把舊版「Excessive Data Exposure（過度資料暴露）」與「Mass Assignment」合併為一個更精準的命名：

> **「我有權限讀／改這個物件，不代表我有權限讀／改這個物件的『每一個欄位』。」**

舉個血淋淋的例子：
- API `/api/users/me` 確實只回登入者自己的資料（BOLA 過關 ✅）。
- 但 response body 把 `password_hash`、`internal_score`、`stripe_customer_id`、`is_admin` 通通吐出來（BOPLA 失敗 ❌）。

這類漏洞在「資料模型直接序列化丟給前端」「GraphQL 沒做欄位級授權」的後端特別常見。今天就把它講清楚。

---

## 二、BOLA vs BOPLA 一張表看懂

| 角度 | BOLA（物件層級） | BOPLA（屬性層級） |
| --- | --- | --- |
| 漏洞核心 | 我能存取到「不是我的」物件 | 我能存取到「同物件中不該給我看／給我改」的欄位 |
| 典型例子 | `/orders/123` 不是我的訂單卻能讀 | `/orders/123` 是我的，但 response 含 `internal_cost`、`refund_token` |
| 修法重點 | 在 controller / service 用 owner / role 判斷物件存取 | 在 DTO / serializer / GraphQL resolver 做欄位級白名單 |
| 工具 | Spring `@PreAuthorize`、Casbin、OPA | DTO、`@JsonView`、欄位授權 directive、GraphQL field resolver |

兩者經常並存。**BOLA 是門禁；BOPLA 是房間裡的抽屜鎖**。門禁鬆了當然糟，但門禁守得很嚴、抽屜全部不上鎖也照樣外洩。

---

## 三、漏洞範例：Excessive Data Exposure（讀取面）

### 反例 1：把 Entity 直接當 Response

```java
// 反例：直接把 JPA Entity 序列化回前端
@Entity
public class User {
    @Id Long id;
    String email;
    String passwordHash;        // ❌ 不該外洩
    String stripeCustomerId;    // ❌ 內部使用
    boolean isAdmin;            // ❌ 內部使用
    BigDecimal internalScore;   // ❌ 風控分數
    String displayName;
    Instant createdAt;
}

@GetMapping("/api/users/me")
public User me(@AuthenticationPrincipal Long uid) {
    return userRepository.findById(uid).orElseThrow();
}
```

執行 `curl /api/users/me` 你就會在 response 看到 `passwordHash`、`internalScore` 等欄位 — 即使前端網頁從來沒用到它們，**API 已經把它們交出去了**。

許多開發者覺得「前端反正沒顯示，沒人會看到」，但攻擊者第一件事就是打開 DevTools 看 Network。Day 02 講過的 XSS 一旦命中，這些欄位就是直接拿來提權的素材。

### 正解：用獨立 DTO（Response 模型）

```java
// 對外回應專用的 DTO（也叫 View / Response Model）
public record UserMeResponse(
    Long id,
    String email,
    String displayName,
    Instant createdAt
) {
    public static UserMeResponse from(User u) {
        return new UserMeResponse(u.getId(), u.getEmail(),
                                  u.getDisplayName(), u.getCreatedAt());
    }
}

@GetMapping("/api/users/me")
public UserMeResponse me(@AuthenticationPrincipal Long uid) {
    return UserMeResponse.from(userRepository.findById(uid).orElseThrow());
}
```

幾條基本準則：

1. **永遠不要把 Entity（ORM 物件）直接當 Controller 回傳值**。中間放一層 DTO / Response Model。
2. DTO 採用 **opt-in**（白名單）而非 **opt-out**：要新增欄位才放，而不是預設全部、再 `@JsonIgnore` 排除 — 一旦團隊忘了標記，敏感資料就漏了。
3. 不同情境用不同 DTO：`/users/me`、`/admin/users/{id}`、`/public/users/{id}` 各自獨立。

### Go 範例：明確列出欄位

Go 的好處是 struct tag 必須明寫，但同樣容易踩雷：

```go
// 反例：domain model 直接當 response
type User struct {
    ID             int64     `json:"id"`
    Email          string    `json:"email"`
    PasswordHash   string    `json:"passwordHash"`   // ❌
    StripeID       string    `json:"stripeId"`       // ❌
    IsAdmin        bool      `json:"isAdmin"`        // ❌
    InternalScore  float64   `json:"internalScore"`  // ❌
    DisplayName    string    `json:"displayName"`
    CreatedAt      time.Time `json:"createdAt"`
}
```

正解一樣：

```go
type UserMeResponse struct {
    ID          int64     `json:"id"`
    Email       string    `json:"email"`
    DisplayName string    `json:"displayName"`
    CreatedAt   time.Time `json:"createdAt"`
}

func toUserMeResponse(u *User) UserMeResponse {
    return UserMeResponse{
        ID: u.ID, Email: u.Email,
        DisplayName: u.DisplayName, CreatedAt: u.CreatedAt,
    }
}
```

> 小技巧：在 Go 的 domain model 把敏感欄位直接標 `json:"-"`，做為「Defense in Depth」。即使有人不小心把 `*User` 回給前端，也不會洩漏。但 **這只是保險，不是主要防線**。

---

## 四、漏洞範例：Mass Assignment（寫入面）

回到 Day 08 的延伸：寫入端的 BOPLA 是 Mass Assignment。

```java
// 反例：直接 bind 到 Entity
@PutMapping("/api/users/me")
public User update(@AuthenticationPrincipal Long uid,
                   @RequestBody User payload) {
    payload.setId(uid);
    return userRepository.save(payload);   // ❌ 攻擊者可送 isAdmin:true
}
```

攻擊者送：
```json
{"displayName": "test", "isAdmin": true, "internalScore": 999}
```

`isAdmin` 就被默默改了。

正解：**Request DTO 也要白名單**，並且在 service 層只更新允許的欄位。

```java
public record UpdateUserRequest(
    @Size(max = 50) String displayName,
    @Email String email
) {}

@PutMapping("/api/users/me")
public UserMeResponse update(@AuthenticationPrincipal Long uid,
                             @Valid @RequestBody UpdateUserRequest req) {
    User u = userRepository.findById(uid).orElseThrow();
    u.setDisplayName(req.displayName());
    if (req.email() != null) u.setEmail(req.email());
    return UserMeResponse.from(userRepository.save(u));
}
```

Go 一樣：定義一個 `UpdateUserRequest` struct，只 unmarshal 允許的欄位。

```go
type UpdateUserRequest struct {
    DisplayName string `json:"displayName"`
    Email       string `json:"email"`
}

func (h *Handler) UpdateMe(w http.ResponseWriter, r *http.Request) {
    uid := auth.UserID(r.Context())
    var req UpdateUserRequest
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields()                // 拒絕未知欄位（多一層保險）
    if err := dec.Decode(&req); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest); return
    }
    // 只更新明列的欄位
    if err := h.users.UpdateProfile(r.Context(), uid, req.DisplayName, req.Email); err != nil {
        http.Error(w, "internal", http.StatusInternalServerError); return
    }
    w.WriteHeader(http.StatusNoContent)
}
```

`DisallowUnknownFields()` 在 Go 是非常便宜的安全保險，遇到惡意送入 `isAdmin` 會直接 400 拒絕。

---

## 五、進階：「同物件，不同角色看不同欄位」

真實世界常見的需求：
- 一般使用者只能看到 order 的 `id`、`status`、`amount`、`createdAt`。
- 客服看得到 `customerEmail`、`note`、`refundReason`。
- 風控看得到 `riskScore`、`ipCountry`、`deviceFingerprint`。

如果你只用一個 DTO + 一堆 `if (role == "support") {...}`，很快會變地獄。三種常見做法：

### 5.1 Spring `@JsonView`：靜態欄位分群

```java
public class Views {
    public static class Public {}
    public static class Support extends Public {}
    public static class Risk extends Public {}
}

public class OrderResponse {
    @JsonView(Views.Public.class)  Long id;
    @JsonView(Views.Public.class)  String status;
    @JsonView(Views.Public.class)  BigDecimal amount;
    @JsonView(Views.Support.class) String customerEmail;
    @JsonView(Views.Support.class) String note;
    @JsonView(Views.Risk.class)    BigDecimal riskScore;
}

@GetMapping("/api/orders/{id}")
@JsonView(Views.Public.class)
public OrderResponse getForCustomer(...) { ... }

@GetMapping("/api/support/orders/{id}")
@JsonView(Views.Support.class)
public OrderResponse getForSupport(...) { ... }
```

優點：欄位歸屬一目了然。
缺點：只能處理「靜態」分群，不適合「同一個 endpoint、依登入者欄位動態調整」。

### 5.2 多個 DTO + Mapper

當欄位差異大、邏輯複雜時，乾脆寫多個 Response 類別。MapStruct、Mapper 函式都可以。**寧可重複，也比鋪 if-else 安全**。

### 5.3 Policy 框架：Casbin / OPA

針對「動態、跨角色、可外部設定」的場景，可以把欄位授權拉到 policy engine：

```text
# Casbin policy (簡化示意)
p, customer, order, read, [id,status,amount,createdAt]
p, support,  order, read, [id,status,amount,createdAt,customerEmail,note]
p, risk,     order, read, [id,status,amount,createdAt,riskScore,ipCountry]
```

Controller 或 mapper 統一查 policy：「這個 role 對這個物件，可讀哪些欄位？」回應前依清單過濾。
**好處**：規則集中、可審計（policy 是 code，能進 git）、能用 OPA / Cedar 等成熟引擎做 unit test。

---

## 六、GraphQL 的特殊風險

GraphQL 的設計哲學「Client 自己決定要什麼欄位」對於 BOPLA 是個放大鏡。常見問題如下：

### 6.1 Resolver 只在「物件層」做授權，沒做欄位層

```graphql
type User {
  id: ID!
  email: String!
  passwordHash: String!     # ❌
  internalScore: Float!     # ❌
  orders: [Order!]!
}

type Query { me: User! }
```

如果你只在 `me` resolver 確認登入，沒在 `passwordHash`、`internalScore` 做欄位級檢查，攻擊者只要：

```graphql
query { me { id passwordHash internalScore } }
```

就拿到了。**GraphQL 沒有「response shape 預設」這件事，client 想問什麼就會回什麼，除非 schema 本身就沒這欄位。**

### 6.2 解法：Schema 設計 + 欄位級 Resolver

**最簡單也最有效**：敏感欄位「不要寫進對外的 GraphQL schema」。GraphQL 不像 REST，schema 是 source of truth — 沒寫的就拿不到。

需要保留欄位但要限制權限時，加 **field-level resolver**：

```java
// Spring for GraphQL 範例
@SchemaMapping(typeName = "User", field = "internalScore")
public BigDecimal internalScore(User user,
                                @AuthenticationPrincipal AppUser caller) {
    if (!caller.hasRole("RISK")) {
        return null;   // 或丟例外，讓 GraphQL 回 errors
    }
    return user.getInternalScore();
}
```

或用 **directive** 在 schema 上宣告：

```graphql
directive @auth(requires: Role!) on FIELD_DEFINITION
enum Role { USER SUPPORT RISK ADMIN }

type User {
  id: ID!
  email: String!
  internalScore: Float @auth(requires: RISK)
  stripeId: String     @auth(requires: ADMIN)
}
```

然後在 server 端把 `@auth` 編譯為對應的 instrumentation，沒有對應 role 的查詢就拒絕。

### 6.3 Introspection 與 Query Depth/Complexity

GraphQL 還有兩個「不是 BOPLA 但常一起出包」的問題：

1. **Introspection**：production 環境如果開著 `__schema` introspection，攻擊者可以一鍵把所有 type / field 名稱抓出來，找出哪些是敏感欄位。**production 建議關掉**（或限制 admin token 才能用）。
2. **Query Depth / Complexity**：GraphQL 可以寫巢狀 query（`me { orders { items { product { reviews { user { orders { ... } } } } } } }`）。沒設深度與複雜度上限會被 DoS。`graphql-java` 有 `MaxQueryDepthInstrumentation`、`gqlgen` 有 `extension.FixedComplexityLimit` / `ComplexityLimit`。

### 6.4 Go 範例：gqlgen 欄位授權

```go
// schema.graphql
// directive @hasRole(role: Role!) on FIELD_DEFINITION

func HasRole(ctx context.Context, _ interface{}, next graphql.Resolver,
             role model.Role) (interface{}, error) {
    caller, ok := auth.From(ctx)
    if !ok {
        return nil, errors.New("unauthenticated")
    }
    if !caller.HasRole(role) {
        // 回 nil + nil 讓欄位變 null（GraphQL spec 允許 nullable 欄位）
        // 或回 error 把它列在 errors[]
        return nil, fmt.Errorf("forbidden: %s requires %s", caller.ID, role)
    }
    return next(ctx)
}

// 在 generated config 註冊 directive
c := generated.Config{ Resolvers: &Resolver{} }
c.Directives.HasRole = HasRole
```

對應 schema：

```graphql
directive @hasRole(role: Role!) on FIELD_DEFINITION
enum Role { USER SUPPORT RISK ADMIN }

type User {
  id: ID!
  email: String!
  internalScore: Float @hasRole(role: RISK)
}
```

---

## 七、N+1 與 DataLoader：效能議題也會變成 BOPLA

GraphQL 的另一個陷阱：用 DataLoader 批次抓資料時，**容易 bypass 欄位授權**。

範例：`User.orders` 欄位有 `@hasRole(SUPPORT)`，但 DataLoader 的批次 fetch 直接 SQL `SELECT * FROM orders WHERE user_id IN (...)` 沒做欄位過濾。如果你把整個 row 載進 cache、之後其他 resolver 又從 cache 撈用，敏感欄位可能就會被別的查詢繞過授權拿到。

**原則**：
1. DataLoader 拿到的資料要當成「raw entity」，**輸出前一定要走欄位授權層**。
2. cache key 要包含「caller 的 role / scope」 — 不要把不同權限使用者的查詢結果混存。

---

## 八、自動化檢測

幾個能加進 CI 的工具：

1. **Schemathesis**（OpenAPI/GraphQL fuzzer）：對每個 endpoint 自動產生變異請求，能抓到「送奇怪欄位居然回 200」這類問題。
2. **InQL** / **graphql-cop**：GraphQL 專用，檢查 introspection、深度限制、batching。
3. **Spring Boot 端**：unit test 強制 controller 回的型別是 DTO 而非 Entity（可寫一條 ArchUnit rule）。
4. **Go 端**：用 `golangci-lint` + 自訂規則禁止 handler 直接回傳 ORM struct；或在 PR review 上把 `json.Encode(*db.User)` 列為阻擋條件。
5. **Snapshot test**：對重要 API 寫 snapshot，回應內容變動（多了新欄位）就強制 review。

---

## 九、防禦清單（Cheat Sheet）

1. **永遠不要把 ORM Entity 直接當 Response**，中間放 DTO。
2. **DTO 採白名單（opt-in）**，新增欄位才放進去。
3. **Request 端也用 DTO + 嚴格欄位**；Go 用 `DisallowUnknownFields`；Java 用 `@Validated` + 明確欄位 record。
4. **依角色／scope 分流不同 DTO**（`@JsonView`、多 DTO、Policy engine 三選一）。
5. **GraphQL 敏感欄位優先「不上 schema」**；必須上的用 directive 或 field-level resolver 控管。
6. **Production 關閉 GraphQL introspection**（或限制 token）。
7. **GraphQL 設 query depth / complexity / aliasing 上限**（同時防 DoS，回 Day 17 Rate Limiting）。
8. **DataLoader 與 cache 要做 role-aware**，避免欄位授權被繞過。
9. **CI 加自動化檢測**：snapshot test、Schemathesis、InQL。
10. **日誌脫敏**（回 Day 16）：log 中也不該出現 `passwordHash`、`stripeId`，避免 BOPLA 從 log 端漏出。

---

## 十、一句話帶走

> BOLA 守門、BOPLA 守欄位。
> **「我有權讀／改這個物件」≠「我有權讀／改這個物件的每一個欄位」。**
> 後端工程師最該養成的本能是：**Controller 的回傳型別不是 Entity，是 DTO**；GraphQL 不該回傳的欄位，**直接不寫進 schema** 才是真的安全。

---

## 十一、延伸閱讀

- OWASP — *API Security Top 10 2023*，特別是 API3:2023 *Broken Object Property Level Authorization*
- OWASP — *Mass Assignment Cheat Sheet*
- OWASP — *GraphQL Cheat Sheet*
- Spring for GraphQL 官方文件 — Field-level resolvers、Schema mapping
- gqlgen 官方文件 — Directives、Complexity、DataLoaders
- Brandur Leach, *APIs and Mass Assignment*（Rails Strong Parameters 起源討論）
- Daniel Stenberg / Apollo Blog — *Securing your GraphQL API* 系列

明天 Day 26 我們會把焦點轉到「**Webhook 安全性**」 — 當你接收第三方（金流、GitHub、Slack…）打進來的 webhook 時，怎麼用 HMAC 簽章確認「真的是它送的」、怎麼防重放攻擊，以及為什麼「主動對外打 webhook」這件事本身就藏著 SSRF 風險。
