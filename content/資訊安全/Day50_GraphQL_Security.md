---
title: "Day 50：GraphQL 安全專題 — Introspection、深度攻擊與 Batching 濫用"
date: 2026-06-15
tags: ["GraphQL", "API 安全", "DoS", "Rate Limiting"]
---

# Day 50：GraphQL 安全專題 — Introspection、深度攻擊與 Batching 濫用

> 「GraphQL 一個端點就搞定所有查詢，多方便。」
> —— 一個端點、自帶 schema 文件、可以任意巢狀與批次——這三點對前端是便利，對攻擊者是禮物。

（接續 Day49 預告：Day25 BOPLA 提過 GraphQL 容易過度暴露資料；今天完整講 GraphQL **特有**的攻擊面——introspection 洩漏整份 schema、巢狀查詢打爆資料庫（query depth / complexity 限制）、用 alias batching 繞過 rate limit（串回 Day17）。並用 Java `graphql-java` 與 Go `gqlgen` 示範防禦設定。）

---

## 一、GraphQL 為什麼是新的攻擊面？

REST 是「每個資源一條 URL、每個方法各自管控」；GraphQL 把所有查詢收斂到**單一端點**（通常是 `POST /graphql`），由 client 自己組裝要查什麼、查多深、查幾次。

這帶來三個 REST 世界沒有的問題：

1. **Schema 自我揭露**：GraphQL 內建 introspection，client 可以查出整份型別、欄位、參數——等於把 API 藍圖交出去。
2. **查詢複雜度由 client 決定**：一個請求可以巢狀很多層、扇出（fan-out）大量資料，後端在 resolver 才知道代價有多大。
3. **單請求多操作**：用 alias 或 batch，一個 HTTP 請求裡塞進上百個操作——傳統「每 IP 每秒幾次請求」的 rate limit 完全擋不到。

下面逐一拆解。

---

## 二、Introspection：把 schema 拱手送人

GraphQL 的 introspection query 讓任何人都能撈出完整 schema：

```graphql
# 攻擊者第一步，幾乎是固定動作
query {
  __schema {
    types { name fields { name } }
  }
}
```

配合 GraphiQL / Voyager 這類工具，攻擊者幾秒鐘就能畫出你所有的型別關係，找出 `internalNotes`、`passwordHash`、`adminOnlyMutation` 這種「以為沒人知道」的欄位。這是 Day49 BFLA 講的「隱藏端點」在 GraphQL 的翻版——**沒連結不等於沒曝光**。

### 防禦原則

- **production 關閉 introspection**（開發 / staging 可開）。
- 但**別只靠關 introspection**：它只是提高門檻，攻擊者仍可用欄位猜測（field suggestion）+ 字典爆破。真正的資料保護還是要靠授權（Day07 IDOR、Day49 BFLA）。
- 同時關掉 GraphiQL / Playground 這類互動式 IDE。

### ✅ Java：graphql-java 關閉 introspection

`graphql-java` 提供 instrumentation，可在 production 環境停用 introspection：

```java
import graphql.GraphQL;
import graphql.analysis.MaxQueryDepthInstrumentation;
import graphql.execution.instrumentation.ChainedInstrumentation;
import graphql.introspection.GoodFaithIntrospection;

// graphql-java 內建 GoodFaithIntrospection（預設啟用），會擋掉惡意放大的
// introspection 查詢；要「完全關閉」introspection，用以下旗標：
GraphQL graphQL = GraphQL.newGraphQL(schema)
        // 直接關掉 introspection（回傳前移除 __schema / __type 能力）
        .doNotAddDefaultInstrumentations() // 視版本而定
        .build();
```

> 實作上更穩的做法是用一個 `Instrumentation`，在 `instrumentExecutionInput` 階段偵測查詢字串含 `__schema` / `__type` 就拒絕；或直接在 schema 建立時用 `GraphQLSchema` 的 introspection 開關。請以你使用的 `graphql-java` 版本文件為準，因為 introspection 控制的 API 在不同版本（19.x → 21.x → 22.x）有調整。`GoodFaithIntrospection` 是 17+ 引入、用來防 introspection DoS 的內建保護。

### ✅ Go：gqlgen 關閉 introspection

`gqlgen` 預設**會關閉** introspection，需要時才手動開啟，這個預設值本身就比較安全：

```go
import "github.com/99designs/gqlgen/graphql/handler"

srv := handler.New(generated.NewExecutableSchema(cfg))
// ...註冊 transport...

// 預設不開 introspection；只有在受信任環境（如帶 dev token）才開
if os.Getenv("APP_ENV") != "production" {
    srv.Use(extension.Introspection{})
}
```

如果你用的是 `handler.NewDefaultServer`，它**會自動啟用** introspection——production 請改用 `handler.New` 自行組裝，不要直接用 default server。

---

## 三、深度 / 複雜度攻擊：一個查詢打爆資料庫

GraphQL 允許巢狀關聯查詢。若型別之間有環狀關係（很常見，例如 `User → posts → author → posts → ...`），攻擊者可以寫出指數級放大的查詢：

```graphql
# 惡意巢狀：每層 fan-out，深度一拉就把 DB 打到趴
query Bomb {
  user(id: 1) {
    posts {
      author {
        posts {
          author {
            posts {
              author { posts { id } }   # ...繼續疊下去
            }
          }
        }
      }
    }
  }
}
```

這是 GraphQL 版的 DoS，本質和 Day31 ReDoS 一樣——**小輸入、大代價**。防禦有三道：

1. **深度限制（max query depth）**：限制巢狀層數，例如最多 10 層。
2. **複雜度 / 成本分析（query complexity）**：給每個欄位算「成本分數」，列表型欄位乘上分頁筆數，超過預算就拒絕。比純深度限制更精準。
3. **逾時與分頁強制**：resolver 設 timeout，列表欄位強制 `first`/`limit` 上限（呼應 Day25 過度暴露）。

### ✅ Java：graphql-java 深度與複雜度限制

`graphql-java` 內建兩個 instrumentation，直接掛上即可：

```java
import graphql.analysis.MaxQueryDepthInstrumentation;
import graphql.analysis.MaxQueryComplexityInstrumentation;
import graphql.execution.instrumentation.ChainedInstrumentation;

import java.util.List;

GraphQL graphQL = GraphQL.newGraphQL(schema)
        .instrumentation(new ChainedInstrumentation(List.of(
                // 1. 最大巢狀深度 10 層，超過直接拒絕
                new MaxQueryDepthInstrumentation(10),
                // 2. 最大複雜度 200（預設每欄位成本 1，可自訂 FieldComplexityCalculator）
                new MaxQueryComplexityInstrumentation(200)
        )))
        .build();
```

自訂成本（列表欄位乘上請求筆數）：

```java
new MaxQueryComplexityInstrumentation(200, (env, childComplexity) -> {
    // 取 first 參數當乘數，例如 posts(first: 50) 成本 = 50 * 子複雜度
    Integer first = env.getArguments().get("first") instanceof Integer i ? i : 1;
    return 1 + first * childComplexity;
});
```

> `MaxQueryDepthInstrumentation` 與 `MaxQueryComplexityInstrumentation` 是 `graphql-java` 長期維護的官方 API（`graphql.analysis` 套件），版本相當穩定。

### ✅ Go：gqlgen 的 complexity limit

`gqlgen` 直接支援欄位複雜度設定與全域上限：

```go
import (
    "github.com/99designs/gqlgen/graphql/handler"
    "github.com/99designs/gqlgen/graphql/handler/extension"
)

srv := handler.New(generated.NewExecutableSchema(cfg))

// 為高成本欄位指定成本：列表筆數當乘數
cfg.Complexity.Query.Posts = func(childComplexity, first int) int {
    return first * childComplexity
}

// 全域複雜度上限：超過直接回錯，不進 resolver
srv.Use(extension.FixedComplexityLimit(300))
```

`gqlgen` 沒有內建「深度」限制，但複雜度上限通常能達到同樣效果（深巢狀自然會累積高複雜度）；需要嚴格深度限制可自行寫一個 `OperationMiddleware` 遍歷 AST。

---

## 四、Alias / Batching 濫用：繞過 rate limit

這是 GraphQL 最容易被忽略的一招。傳統 rate limit（Day17）數的是「HTTP 請求數」，但 GraphQL 讓你在**一個請求裡塞很多操作**。

### 手法 1：alias 放大

同一個欄位用不同 alias 重複呼叫，一個請求觸發上百次後端操作：

```graphql
mutation BruteForce {
  a: login(user: "admin", pass: "p1") { token }
  b: login(user: "admin", pass: "p2") { token }
  c: login(user: "admin", pass: "p3") { token }
  # ...重複 1000 次，全部在「一個」HTTP 請求裡
}
```

→ 你以為「每 IP 每分鐘 5 次登入」很安全，攻擊者一個請求就試了 1000 組密碼。這直接打穿 Day17 的速率限制，也讓暴力破解（Day32 提過的帳號安全）變得超有效率。

### 手法 2：query batching

GraphQL 支援把多個操作放進一個 JSON 陣列送出：

```json
[
  { "query": "mutation { login(user:\"admin\", pass:\"p1\"){token} }" },
  { "query": "mutation { login(user:\"admin\", pass:\"p2\"){token} }" }
]
```

效果一樣：一個 HTTP 請求 = 多個操作。

### 防禦原則

- **限制單一查詢的 alias / 同名欄位數量**（例如同一 mutation 最多出現 1 次 `login`）。
- **限制 batch 陣列長度**（或乾脆關閉 array batching）。
- **rate limit 要數「操作數」而非「請求數」**——把上面的複雜度分數累加進限流預算，是最一致的做法。
- 敏感操作（login、OTP、付款）改用**業務層**節流：以「帳號 + 動作」為 key 計數，而不是只看 IP。

### ✅ Java：限制 batch 與 alias

`graphql-java` 本身不處理 HTTP batching（那在 transport 層）。若你用 Spring for GraphQL：

```java
// 1. batch：在 controller / filter 層限制 JSON 陣列長度（自行解析 body 後檢查）
//    或直接只接受單一 operation 的請求。

// 2. alias 爆量：用 Instrumentation 在執行前掃描 AST，
//    統計同一欄位的 alias 次數，超過門檻就拒絕
public class MaxAliasInstrumentation extends SimplePerformantInstrumentation {
    private final int maxAliasesPerField = 10;
    // 在 beginExecuteOperation 階段遍歷 OperationDefinition 的 selection set，
    // 統計每個 field name 出現次數，超過 maxAliasesPerField 就 throw AbortExecutionException
}
```

> 重點：把「敏感 mutation（login）」的業務節流做在 resolver 層，以帳號為 key，不被單請求多 alias 繞過。

### ✅ Go：gqlgen 關閉 / 限制 batching

`gqlgen` 的 array batching 透過 transport 控制，預設**不啟用** `POST` array batch（要顯式加 `transport.POST` 才有單操作；array batch 需另外處理），這點同樣偏安全：

```go
import "github.com/99designs/gqlgen/graphql/handler/transport"

srv.AddTransport(transport.POST{})   // 單操作 POST
// 不加會啟用 array batching 的 transport，就維持不開

// alias 爆量：用 OperationMiddleware 掃 AST，統計同名欄位次數
srv.AroundOperations(func(ctx context.Context, next graphql.OperationHandler) graphql.ResponseHandler {
    oc := graphql.GetOperationContext(ctx)
    if countAliases(oc.Operation, "login") > 5 {
        return graphql.OneShot(graphql.ErrorResponse(ctx, "too many login aliases"))
    }
    return next(ctx)
})
```

---

## 五、容易被忽略的細節

1. **錯誤訊息洩漏**：GraphQL 預設常把 stack trace、SQL 錯誤塞進 `errors` 陣列。production 要包裝成通用錯誤（串回 Day25 過度暴露、一般的資訊洩漏）。
2. **欄位層級授權**：別只在 query 入口擋。GraphQL 一個查詢可橫跨多型別，每個敏感欄位 / mutation 都要在 resolver 內做授權檢查（Day49 BFLA：預設拒絕）。
3. **N+1 與 DataLoader**：巢狀查詢若沒用 DataLoader 批次化，光是正常使用就會 N+1 打爆 DB——這既是效能也是 DoS 面。
4. **持久化查詢（persisted queries）**：高安全場景可只接受預先註冊的查詢雜湊，client 不能送任意查詢，從根本消滅深度 / alias 攻擊。
5. **introspection 關了仍可被猜**：field suggestion（「你是不是要找 `password`？」）會洩漏欄位名，可考慮關掉建議或加 WAF 規則。

---

## 六、後端工程師的 Checklist

- [ ] production **關閉 introspection 與 GraphiQL / Playground**（gqlgen 預設關、用 `handler.New`；graphql-java 自行停用）。
- [ ] 設定 **max query depth**（如 10 層）。
- [ ] 設定 **query complexity 上限**，列表欄位以分頁筆數當乘數計分。
- [ ] **限制 alias / batch 數量**，敏感 mutation 以「帳號 + 動作」做業務層節流。
- [ ] rate limit 數「**操作數 / 複雜度分數**」而非單純 HTTP 請求數（串回 Day17）。
- [ ] 每個敏感欄位與 mutation 在 resolver **重做授權**（Day49 預設拒絕）。
- [ ] 錯誤訊息包裝、列表欄位強制分頁上限、用 DataLoader 解 N+1。

---

## 七、一句話總結

> **GraphQL 把「查什麼、查多深、查幾次」的決定權交給了 client——安全的責任就是把這三個維度全部加上後端強制的上限。**
> Introspection 控曝光、depth/complexity 控放大、alias/batch 控繞過，三者缺一不可。

---

## 延伸閱讀

- OWASP — GraphQL Cheat Sheet
- graphql-java Documentation — Instrumentation / Query Complexity & Depth
- gqlgen Documentation — Complexity, Introspection, Transports
- 前文：Day17 Rate Limiting、Day25 BOPLA / 過度暴露、Day31 ReDoS、Day49 BFLA

---

明天預告：**Day 51 — gRPC 與 Protobuf 安全：反序列化、訊息大小限制與 TLS/mTLS**
（講完 HTTP 系的 REST、GraphQL，明天轉向內部服務常用的 gRPC：protobuf 反序列化的資源耗盡風險、`MaxRecvMsgSize` 訊息大小上限、以及 service-to-service 一定要做的 mTLS（串回 Day48 HMAC 簽章、Day49 微服務間授權）。會用 Java（grpc-java）與 Go（grpc-go）示範 server 端的安全預設值。）
