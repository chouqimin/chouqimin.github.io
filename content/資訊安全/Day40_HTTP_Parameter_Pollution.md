---
title: "Day 40 - HTTP Parameter Pollution (HPP)：當「同一個參數出現兩次」變成攻擊"
date: 2026-06-05
tags: ["HTTP", "輸入驗證"]
---

# Day 40 - HTTP Parameter Pollution (HPP)：當「同一個參數出現兩次」變成攻擊

## 一、什麼是 HTTP Parameter Pollution？

HTTP Parameter Pollution（HPP，HTTP 參數污染）是指攻擊者在一次 HTTP 請求中，**故意送出多個同名的參數**，藉此讓伺服器、Web 框架、WAF、反向代理之間對「該採用哪一個值」產生不一致的解讀，最後達到繞過驗證、權限提升、邏輯篡改、注入等目的。

舉一個最直觀的例子：

```
GET /transfer?account=ATTACKER&account=VICTIM HTTP/1.1
```

同樣是 `account` 參數，有的框架會取第一個 `ATTACKER`，有的會取最後一個 `VICTIM`，有的甚至會自動串成 `ATTACKER,VICTIM`。如果前面的 WAF 看到的是 `ATTACKER`（合法的攻擊者帳號）所以放行，但後端應用實際讀到 `VICTIM` 然後執行轉帳，整個業務邏輯就被攻擊者控制了。

HPP 屬於 **OWASP API Security Top 10** 中「API8: Security Misconfiguration」與「Injection」的衍生攻擊面，很多新手後端工程師完全不知道這個行為差異，所以是非常經典又容易踩雷的議題。

---

## 二、為什麼會發生？各個框架的處理差異

當 URL 是 `?id=1&id=2&id=3` 時，不同語言/框架的預設行為差異極大：

| 平台 / 框架 | 預設取得 `id` 的結果 |
| --- | --- |
| Java Servlet `request.getParameter("id")` | 取第一個（`1`） |
| Java Servlet `request.getParameterValues("id")` | 全部陣列（`["1","2","3"]`） |
| Spring MVC `@RequestParam String id` | 取第一個（`1`） |
| Spring MVC `@RequestParam List<String> id` | 全部陣列 |
| Go `net/http` `r.URL.Query().Get("id")` | 取第一個（`1`） |
| Go `net/http` `r.URL.Query()["id"]` | 全部陣列 |
| PHP（預設） | 取最後一個（`3`） |
| ASP.NET | 自動串成 `1,2,3`（逗號分隔） |
| Node.js Express（qs） | 自動轉成陣列 `["1","2","3"]` |

光從這張表就可以看出：當你的系統前後有不同語言的元件（例如 Nginx + Lua WAF + Java 後端，或 CloudFront + Node.js Edge + Go 服務），同一個請求很可能在不同層被解讀成不同的值。這就是 HPP 攻擊的根本機會。

---

## 三、實際攻擊情境

### 情境 A：繞過 WAF 規則

WAF 看到的請求：

```
GET /search?q=hello&q=' UNION SELECT password FROM users--
```

部分 WAF 只檢查「第一個 `q`」是不是有 SQL 注入特徵，看到 `hello` 就放行；但後端框架取的是「最後一個 `q`」，於是 SQL 注入 payload 順利進入 SQL 引擎。

### 情境 B：權限提升

```
POST /api/order/cancel
Content-Type: application/x-www-form-urlencoded

orderId=MY_OWN_ID&orderId=VICTIM_ID
```

驗證程式檢查「`orderId` 屬於目前登入者」用的是 `getParameter`（取第一個 `MY_OWN_ID`，通過驗證）；但實際取消訂單時用的是 `getParameterValues` 的最後一個（`VICTIM_ID`）。結果攻擊者取消了別人的訂單。

### 情境 C：覆蓋系統內部欄位（Server-Side HPP）

當後端把使用者的參數拼接進對下游服務的呼叫時：

```java
// 將前端來的 userId 拼進對 Service B 的呼叫
String url = "http://service-b/api/profile?role=user&userId=" + userInputId;
```

如果攻擊者送 `userInputId=123&role=admin`，組出來的 URL 就會變成：

```
http://service-b/api/profile?role=user&userId=123&role=admin
```

下游服務若採「取最後一個」邏輯，攻擊者就把 `role` 從 `user` 升級成 `admin`。這是非常經典的「Server-Side HPP」。

---

## 四、漏洞程式碼示範

### Java（Spring Boot）有問題寫法

```java
@RestController
@RequestMapping("/api/transfer")
public class TransferController {

    @PostMapping
    public ResponseEntity<?> transfer(HttpServletRequest req) {
        // 驗證階段：用 getParameter（第一個值）
        String fromAccount = req.getParameter("fromAccount");
        if (!isOwnedByCurrentUser(fromAccount)) {
            return ResponseEntity.status(403).build();
        }

        // 執行階段：用 getParameterValues 的最後一個（不一致！）
        String[] values = req.getParameterValues("fromAccount");
        String actualFrom = values[values.length - 1];

        accountService.transfer(actualFrom, req.getParameter("toAccount"),
                                Long.parseLong(req.getParameter("amount")));
        return ResponseEntity.ok().build();
    }
}
```

攻擊者送 `fromAccount=自己帳號&fromAccount=受害者帳號`，驗證通過、轉帳卻是從受害者帳號扣款。

### Go（net/http）有問題寫法

```go
func transferHandler(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query()

    // 驗證階段：Get 取第一個值
    from := q.Get("fromAccount")
    if !isOwnedByCurrentUser(r.Context(), from) {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }

    // 執行階段：取陣列的最後一個（不一致！）
    all := q["fromAccount"]
    actualFrom := all[len(all)-1]

    if err := accountSvc.Transfer(r.Context(), actualFrom,
        q.Get("toAccount"), q.Get("amount")); err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusOK)
}
```

---

## 五、防禦實作

防禦 HPP 的核心原則只有一句話：**整條請求生命週期內，同一個參數只能有一個「正確」的取得方式，且重複時必須拒絕或一致化處理**。

### 原則 1：禁止同名重複參數，遇到就直接 400

最安全也最簡單。對絕大多數 API 而言，使用者根本沒有理由送兩個同名參數。

#### Java（Spring Boot）Filter 範例

```java
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class DuplicateParamRejectFilter extends OncePerRequestFilter {

    // 例外清單：明確允許接受陣列的參數（如 ?tag=a&tag=b）
    private static final Set<String> ALLOW_LIST =
            Set.of("tag", "category", "ids");

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse resp,
                                    FilterChain chain)
            throws ServletException, IOException {

        Map<String, String[]> params = req.getParameterMap();
        for (Map.Entry<String, String[]> e : params.entrySet()) {
            if (e.getValue().length > 1 && !ALLOW_LIST.contains(e.getKey())) {
                resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                resp.setContentType("application/json;charset=UTF-8");
                resp.getWriter().write(
                    "{\"error\":\"duplicated parameter: " + e.getKey() + "\"}");
                return;
            }
        }
        chain.doFilter(req, resp);
    }
}
```

#### Go middleware 範例

```go
var allowMultiple = map[string]bool{
    "tag":      true,
    "category": true,
    "ids":      true,
}

func RejectDuplicateParams(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Query string
        for key, values := range r.URL.Query() {
            if len(values) > 1 && !allowMultiple[key] {
                http.Error(w, fmt.Sprintf("duplicated query parameter: %s", key),
                    http.StatusBadRequest)
                return
            }
        }
        // form body（如果 Content-Type 是 form-urlencoded）
        if err := r.ParseForm(); err == nil {
            for key, values := range r.PostForm {
                if len(values) > 1 && !allowMultiple[key] {
                    http.Error(w, fmt.Sprintf("duplicated form parameter: %s", key),
                        http.StatusBadRequest)
                    return
                }
            }
        }
        next.ServeHTTP(w, r)
    })
}
```

### 原則 2：使用結構化的 Schema 綁定（DTO）取代手動讀參數

讓框架幫你做 binding，並把 DTO 的欄位型別宣告成 `String` 而非 `List<String>`，可以強制只接受單一值。

#### Java（Spring Boot）

```java
public record TransferReq(
    @NotBlank String fromAccount,
    @NotBlank String toAccount,
    @Positive long amount
) {}

@PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<?> transfer(@Valid @RequestBody TransferReq req) {
    if (!isOwnedByCurrentUser(req.fromAccount())) {
        return ResponseEntity.status(403).build();
    }
    accountService.transfer(req.fromAccount(), req.toAccount(), req.amount());
    return ResponseEntity.ok().build();
}
```

幾個重點：

- **改用 JSON body**：JSON 物件的 key 在解析時若重複，Jackson 預設取最後一個，且建議再加 `FAIL_ON_READING_DUP_TREE_KEY` 直接拋錯（見下）。
- 用 record / DTO 取代直接讀 `HttpServletRequest`，框架幫你型別檢查。
- 用 `@Valid` 觸發 Bean Validation，少寫一堆 `if`。

額外把 Jackson 開成「JSON 重複 key 就拋例外」：

```java
@Bean
public Jackson2ObjectMapperBuilderCustomizer strictJsonCustomizer() {
    return builder -> builder.featuresToEnable(
        com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION
    );
}
```

#### Go（搭配 `encoding/json` + validator）

```go
type TransferReq struct {
    FromAccount string `json:"fromAccount" validate:"required"`
    ToAccount   string `json:"toAccount"   validate:"required"`
    Amount      int64  `json:"amount"      validate:"gt=0"`
}

func transferHandler(w http.ResponseWriter, r *http.Request) {
    var req TransferReq
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields() // 阻擋 mass assignment
    if err := dec.Decode(&req); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    if err := validate.Struct(req); err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    // 驗證與執行用同一個來源
    if !isOwnedByCurrentUser(r.Context(), req.FromAccount) {
        http.Error(w, "forbidden", http.StatusForbidden)
        return
    }
    _ = accountSvc.Transfer(r.Context(), req.FromAccount, req.ToAccount, req.Amount)
    w.WriteHeader(http.StatusOK)
}
```

### 原則 3：對下游呼叫時，務必經過正確的 URL 編碼

防止 Server-Side HPP 最直接的辦法是：**自己組裝下游 URL 時，永遠用 URL builder，不要字串拼接**。

#### Java

```java
URI uri = UriComponentsBuilder.fromHttpUrl("http://service-b/api/profile")
        .queryParam("role", "user")
        .queryParam("userId", userInputId) // 自動編碼
        .build()
        .toUri();
```

如果 `userInputId` 是 `"123&role=admin"`，會被編碼成 `123%26role%3Dadmin`，下游就只會看到一個 `role=user`，HPP 無從成立。

#### Go

```go
u, _ := url.Parse("http://service-b/api/profile")
q := u.Query()
q.Set("role", "user")
q.Set("userId", userInputId) // 自動編碼
u.RawQuery = q.Encode()
// 用 u.String() 去發 request
```

### 原則 4：驗證階段與業務階段，用同一個來源、同一個變數

絕對不要「驗證時讀第一個值、執行時讀最後一個值」。最好把參數讀進 DTO，後續通通只引用 DTO，杜絕重讀。

---

## 六、檢測與測試

可以寫一個非常輕量的測試，把所有端點打一輪「重複參數」的請求，預期回應應為 `400 Bad Request`。

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class HppFilterTest {

    @Autowired TestRestTemplate rest;

    @Test
    void duplicatedQueryParamShouldReject() {
        ResponseEntity<String> resp = rest.getForEntity(
            "/api/users?id=1&id=2", String.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
}
```

也可以用 curl 快速驗證：

```bash
curl -i "https://your-api.example.com/api/users?id=1&id=2"
# 預期：HTTP/1.1 400 Bad Request
```

---

## 七、給後端工程師的重點整理

1. **HPP 的本質是「不同層對同名參數的解讀不一致」**，不一定是某一層有 bug，而是組合在一起的時候出問題。
2. **預設拒絕同名重複參數** 是 CP 值最高的防禦，例外的少數（多選 tag、ids）才加入白名單。
3. **改用 JSON body + DTO** 比讀 query string 安全得多，並把 JSON 開啟「重複 key 拋錯」。
4. **下游呼叫不要字串拼接 URL**，永遠用 URL builder，自動編碼 `&` 與 `=`。
5. **驗證與業務邏輯用同一個變數**，杜絕「驗證讀 A、執行讀 B」的取值落差。
6. **撰寫一條 e2e 測試**，固定打重複參數驗證 400，避免後人改 code 後又把防禦關掉。

下一篇預告（Day41）：**LDAP Injection（被遺忘的注入漏洞）**——當後端用使用者輸入去組 LDAP 查詢字串（例如企業帳號登入、組織通訊錄查詢），一個 `*` 或 `)(` 就能繞過認證、甚至撈出整本目錄。
