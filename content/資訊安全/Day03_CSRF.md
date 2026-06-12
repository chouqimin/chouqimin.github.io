---
title: "Day 03 — CSRF（Cross-Site Request Forgery，跨站請求偽造）"
date: 2026-04-23
tags: ["CSRF", "Session", "前端安全"]
---

# Day 03 — CSRF（Cross-Site Request Forgery，跨站請求偽造）

> 日期：2026-04-23
> 適合對象：後端工程師初學者
> 主題難度：★★☆☆☆（基礎必學）

---

## 一、什麼是 CSRF？

CSRF（Cross-Site Request Forgery，中文叫「跨站請求偽造」，也有人念作「Sea-Surf」）是一種**利用使用者「已登入」狀態，替他發送不知情請求**的攻擊手法。

一句話說明：

> **「XSS 是騙瀏覽器執行壞腳本；CSRF 是借用瀏覽器自動帶上的 Cookie，冒充你本人發請求。」**

關鍵在於一個瀏覽器行為：**只要你在 A 網站登入過，之後不管你人在哪個網站，瀏覽器對 A 網站發出的任何請求，都會自動帶上 A 網站的 Cookie。** 攻擊者不需要知道你的密碼、也不需要偷你的 Cookie，他只要想辦法讓你的瀏覽器**對目標網站發一個請求**，就能用你的身份做事。

### 常見 CSRF 危害

- 你正在逛某個論壇，同時你銀行 App 網頁還開著 → 你在論壇點了一張圖 → 圖的 `src` 其實是銀行的轉帳 API → 錢被轉走。
- 以你身份修改 Email / 密碼 / 安全問題 → 帳號被接管。
- 後台管理系統：誘騙管理員點連結，就能新增一個攻擊者帳號或提升權限。

---

## 二、CSRF 的攻擊條件

要成立 CSRF，幾乎都同時具備下面這三個條件：

1. **使用者已登入目標網站**（瀏覽器裡有該網站有效的 Session Cookie）。
2. **目標網站的狀態變更操作只靠 Cookie 判斷身份**（沒有額外的 Token 或 Header）。
3. **使用者被誘導造訪一個攻擊者控制的頁面**（通常是一個惡意網站、論壇貼文、釣魚信件）。

只要這三個條件齊備，攻擊者就能讓你的瀏覽器替他發請求。

---

## 三、經典情境：一鍵轉帳攻擊

假設某銀行後端有這樣一個 API：

```
POST /api/transfer
Content-Type: application/x-www-form-urlencoded
Cookie: SESSION=abc123   ← 瀏覽器自動帶

to=0987654321&amount=100000
```

後端只檢查 `SESSION` Cookie 是不是有效的，有效就執行轉帳。

攻擊者在自己架的惡意網站放一張「圖片」：

```html
<!-- evil.com/funny-cat.html -->
<h1>來看一隻可愛的貓</h1>
<img src="https://bank.example.com/api/transfer?to=ATTACKER&amount=100000"
     width="0" height="0">
```

或是藏一個自動提交的表單：

```html
<form id="f" action="https://bank.example.com/api/transfer" method="POST">
  <input name="to" value="ATTACKER">
  <input name="amount" value="100000">
</form>
<script>document.getElementById('f').submit();</script>
```

當受害者**同時在另一個分頁登入著銀行網站**，然後打開這個惡意頁面，瀏覽器就會對銀行發出請求，並**自動帶上銀行的 Session Cookie**。銀行後端一看：「Cookie 有效、Session 沒過期」，就真的把錢轉走了。

受害者全程可能只看到一張「看不見的 0x0 圖片」。

---

## 四、為什麼 XSS 防禦不等於 CSRF 防禦？

這是新手很容易混淆的點：

| 問題 | XSS | CSRF |
|------|-----|------|
| 攻擊者在哪裡寫程式？ | 在**目標網站**頁面上執行 JS | 在**自己的網站**寫一個表單/連結 |
| 需要讀取受害者資料嗎？ | 需要（偷 cookie、偽造頁面） | 不需要（只要能送出請求就好） |
| `HttpOnly` Cookie 能擋嗎？ | 能擋「偷 cookie」 | **擋不住**（瀏覽器照樣自動帶出去） |
| 主要防禦 | Output Encoding、CSP | CSRF Token、SameSite Cookie |

所以你就算把 XSS 防得完美，CSRF 一樣可能中。反過來也一樣。**這是兩個獨立的問題，要分別處理。**

---

## 五、正確防禦方式

### 防禦 1：CSRF Token（Synchronizer Token Pattern）—— 最經典

核心思路：伺服器在使用者拿到表單頁面時，**額外發一個只有伺服器知道的隨機 Token**（放在頁面或回應 Header）。提交時 client 必須把這個 Token 附上，伺服器驗證通過才執行。

攻擊者在他自己的網站上**讀不到這個 Token**（因為有 Same-Origin Policy 保護），所以他沒辦法偽造出有效請求。

#### Java Spring Security 範例（Spring Security 6，Spring Boot 3.x）

Spring Security 預設就開啟了 CSRF 保護，會自動為 HTML 表單注入 `_csrf` 欄位。你要做的是**不要自己關掉它**：

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                // 使用 Cookie 模式，讓前端 JS 可以讀到 token 再放進 header
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                // 對「給 API 用」的路徑若確定是 stateless(JWT)，再考慮忽略
                // .ignoringRequestMatchers("/api/public/**")
            );
        return http.build();
    }
}
```

Thymeleaf 模板裡（Spring 會自動注入，但你可以明寫出來確認）：

```html
<form th:action="@{/transfer}" method="post">
    <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}"/>
    <input name="to"/>
    <input name="amount"/>
    <button>送出</button>
</form>
```

如果是 SPA + REST API：前端讀取後端放在 Cookie 的 `XSRF-TOKEN`，把值塞進 `X-XSRF-TOKEN` Header 後再送出。Spring Security 會比對這兩個值。

⚠️ 常見地雷：很多教學直接寫 `http.csrf(csrf -> csrf.disable())`「為了方便」。**正式環境不要這樣**，除非你是 100% stateless、純 Token（如 JWT）、而且確定不吃任何 Cookie。

#### Go 範例（net/http + gorilla/csrf）

Go 標準庫沒內建 CSRF middleware，常用套件是 `github.com/gorilla/csrf`：

```go
import (
    "net/http"
    "github.com/gorilla/csrf"
)

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/transfer", transferHandler)

    // 32 bytes 的 secret key，正式環境放環境變數 / KMS
    csrfMiddleware := csrf.Protect(
        []byte("32-byte-long-auth-key-xxxxxxxxxxx"),
        csrf.Secure(true),            // 正式環境必開
        csrf.SameSite(csrf.SameSiteLaxMode),
    )

    http.ListenAndServe(":8080", csrfMiddleware(mux))
}

func showForm(w http.ResponseWriter, r *http.Request) {
    // 在 template 中把 token 帶進 form
    tmpl.Execute(w, map[string]any{
        csrf.TemplateTag: csrf.TemplateField(r),
    })
}
```

HTML 模板：

```html
<form method="POST" action="/transfer">
    {{.csrfField}}
    <input name="to">
    <input name="amount">
    <button>送出</button>
</form>
```

> 提醒：根據最新檢查，`github.com/gorilla/csrf` 由 gorilla toolkit 社群在 2023 年之後重新活躍維護，仍是 Go 生態圈最常見的選擇。若是較新的專案，也可評估 `github.com/justinas/nosurf`。

### 防禦 2：SameSite Cookie —— 現代瀏覽器的一道重要防線

CSRF 會成立的根本原因是「瀏覽器在跨站請求時也會自動帶 Cookie」。瀏覽器的 `SameSite` 屬性就是針對這件事的補丁：

| SameSite 值 | 跨站請求時會帶 Cookie 嗎？ |
|-------------|---------------------------|
| `Strict` | **完全不帶**。最安全，但使用者從外站點連結進來會「看起來沒登入」。 |
| `Lax` | **只對 top-level GET 導航帶** (如點連結)。POST / iframe / img 都不會帶。**目前多數瀏覽器預設值。** |
| `None` | 跨站一律帶（必須同時 `Secure`）。要跨站嵌入時才用。 |

Java（Spring Boot）：

```java
ResponseCookie cookie = ResponseCookie.from("SESSION", value)
    .httpOnly(true)
    .secure(true)
    .sameSite("Lax")   // 或 "Strict"
    .path("/")
    .build();
response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
```

Go：

```go
http.SetCookie(w, &http.Cookie{
    Name:     "SESSION",
    Value:    value,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteLaxMode, // 或 http.SameSiteStrictMode
    Path:     "/",
})
```

⚠️ `SameSite=Lax` **不是萬靈丹**：
- 攻擊者仍可能用 GET 做 CSRF（如果你的 API 用 GET 改狀態，那就是自找麻煩）。
- 有些瀏覽器版本、跨子網域場景（`a.example.com` vs `b.example.com`）需要特別確認行為。
- 所以 SameSite 是**額外一層防禦**，不是 Token 的替代品。

### 防禦 3：任何會改變狀態的 API，絕不用 GET

REST 語意本來就規定：

- `GET` 應該是**安全、等冪**的（只讀、多次呼叫不造成副作用）。
- 改狀態要用 `POST` / `PUT` / `PATCH` / `DELETE`。

這不只是「漂亮」，也是 CSRF 防禦的基礎。因為 `<img src>`、`<script src>`、`<link>` 這些元素**只能發 GET 請求**。如果你的轉帳 API 要求 POST + JSON body，攻擊者要成功的門檻就高得多。

### 防禦 4：檢查 Origin / Referer Header（輔助）

對敏感 API，在後端比對請求的 `Origin`（較可靠）或 `Referer`（較舊）是否是你自己的網域。這不是主防線，但可以擋掉一部分粗糙的攻擊。

```go
func isSameOrigin(r *http.Request) bool {
    origin := r.Header.Get("Origin")
    return origin == "https://bank.example.com"
}
```

### 防禦 5：敏感操作要求重新認證

轉帳、改密碼、改 Email 這類高風險動作，要求使用者**再輸一次密碼**或 **輸入 OTP**。就算 CSRF Token 被繞過（例如同時中了 XSS），這道二次驗證還是能擋下來。

---

## 六、純 API（JWT / Bearer Token）專案還需要擔心 CSRF 嗎？

這是面試愛問、也最容易答錯的題目。分兩種情況：

- **Token 放在 `Authorization: Bearer ...` header，不用 Cookie**：瀏覽器**不會自動帶** Authorization header，跨站攻擊者的頁面也讀不到你的 Token（Same-Origin Policy + localStorage 隔離），因此 **CSRF 風險很低**。但要注意：這種做法對 **XSS 反而更脆弱**，因為 JS 讀得到 Token。
- **Token 放在 Cookie（即使是 JWT）**：瀏覽器仍會自動帶 → **仍需 CSRF 防禦**。不要因為「我是 REST API」就關掉 CSRF，這是新手最常踩的坑。

沒有所謂「API 就不用 CSRF」這件事，**真正的判斷依據是「身份憑證放在哪裡，瀏覽器會不會自動帶」**。

---

## 七、後端工程師的 CSRF 自我檢查清單

寫每一個 API 前，問自己這六個問題：

1. 這支 API 會改變狀態嗎？如果會，有沒有用 POST/PUT/DELETE 而不是 GET？
2. 身份憑證是放在 Cookie 還是 Authorization header？
3. 如果用 Cookie：CSRF Token 有開嗎？SameSite 設了嗎？
4. 是不是為了「讓前端好接」就 `csrf.disable()` / 忽略掉整段 `/api/**`？
5. 敏感操作（改密碼、轉帳、關閉 2FA）有沒有二次認證？
6. 測試環境有沒有跑一次「從別的網域 POST」的流程驗證？

---

## 八、一句話總結

> **「只要瀏覽器會自動帶上身份憑證，你就需要 CSRF 防禦。Token、SameSite、POST 三件事，缺一不可。」**

明天預告：Day 04 — **身份驗證 (Authentication) 基礎**：密碼應該怎麼存？為什麼 `MD5(password)` 是災難？聊聊 bcrypt、Argon2 與加鹽 (salt)。

---

## 參考資料

- OWASP: [Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
- OWASP Cheat Sheet: [CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- Spring Security [CSRF 官方文件](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html)
- MDN: [SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value)
- [gorilla/csrf](https://github.com/gorilla/csrf)
