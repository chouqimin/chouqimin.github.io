---
title: "Day 09 — Security Headers 與 CORS：一行設定擋掉一整類攻擊，但設錯一行就把 Cookie 送人"
date: 2026-05-04
tags: ["HTTP Header", "CORS", "瀏覽器安全"]
---

# Day 09 — Security Headers 與 CORS：一行設定擋掉一整類攻擊，但設錯一行就把 Cookie 送人

> 日期：2026-05-04
> 適合對象：後端工程師初學者
> 主題難度：★★★☆☆（觀念不難，但「設了沒效」、「設太鬆」、「設太嚴擋到自己」都很常見）

---

## 一、開場白：為什麼瀏覽器需要「後端告訴它要小心」？

前面 8 天我們講的多半是「請求進來時要怎麼防」——SQL Injection、CSRF、Mass Assignment ⋯⋯這些都是「攻擊者直接打你 API」的場景。

但網頁安全還有另一條主戰場：**攻擊者騙使用者的瀏覽器替他做事**。

例如：
- 把你的網站塞進 `<iframe>` 裡，蓋一個透明按鈕誘導點擊（Clickjacking）。
- 在惡意網站用 `<script src="https://your-bank.com/api/me">` 拿你的個資（CORS 沒設好）。
- 中間人把 `https://` 降級成 `http://` 偷流量（沒有 HSTS）。
- 一個被注入的 `<script>` 偷偷把資料送到攻擊者的 server（沒有 CSP）。

這些攻擊**伺服器端的程式碼通常完全沒漏洞**——是「瀏覽器不知道你不希望它做這些事」。

**Security Headers 就是後端對瀏覽器下的安全指令。** 它們是 HTTP response 上的幾行字串，但效果是：「請瀏覽器幫我把這些事情擋掉」。

---

## 二、必備的六個 Security Headers

| Header | 防什麼攻擊 | 一句話說明 |
| :-- | :-- | :-- |
| `Strict-Transport-Security` | 降級攻擊 / SSL Strip | 強制瀏覽器之後一律走 HTTPS |
| `Content-Security-Policy` | XSS、資料外洩 | 規定哪些來源的 JS / 圖片 / 連線是被允許的 |
| `X-Frame-Options` / `frame-ancestors` | Clickjacking | 不准別人把我的網頁包進 iframe |
| `X-Content-Type-Options: nosniff` | MIME sniffing 攻擊 | 不准瀏覽器自己猜 Content-Type |
| `Referrer-Policy` | URL 隱私洩漏 | 控制跨站連結時 Referer header 帶多少資訊 |
| `Permissions-Policy` | 濫用瀏覽器 API | 關掉不需要的相機、麥克風、地理位置權限 |

我們一個一個看。

---

## 三、HSTS（Strict-Transport-Security）：強制 HTTPS

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**意思：** 「親愛的瀏覽器，從現在起的 1 年（31536000 秒）內，只要看到我的網域（含子網域），就一律走 HTTPS。即使使用者在網址列打 `http://`，你也要自動改成 `https://`。」

### 為什麼重要？

沒有 HSTS 時，使用者打 `http://your-bank.com` → 你的伺服器回 301 redirect 到 `https://...`。**第一個 http request** 是明文的——攻擊者只要在這 1 秒鐘的視窗裡攔截，就能完成中間人攻擊（SSL Strip）。

HSTS 解決的是「**第二次以後**」的訪問：瀏覽器記住「這個網域只走 HTTPS」，連 redirect 的機會都不給。

### `preload` 是什麼？

加上 `preload` 並把網域提交到 [hstspreload.org](https://hstspreload.org/)，Chrome / Firefox / Safari **內建的 HSTS 清單**就會包含你的網域——使用者**第一次**打開都會走 HTTPS。

> ⚠️ 注意：`preload` 是**單向操作**。一旦加入清單，要移除非常困難（要等所有瀏覽器釋出新版本）。如果你的子網域有任何一個還沒準備好上 HTTPS（例如內網舊系統），**先不要加 preload**，否則會把自己玩死。

### Spring Boot 設定（Spring Security 6.x）

```java
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.headers(headers -> headers
            .httpStrictTransportSecurity(hsts -> hsts
                .maxAgeInSeconds(31536000)
                .includeSubDomains(true)
                .preload(true)
            )
        );
        return http.build();
    }
}
```

### Gin 設定（中介層）

```go
func SecurityHeaders() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
        c.Next()
    }
}
```

---

## 四、CSP（Content-Security-Policy）：XSS 的最後一道防線

CSP 是**這 6 個 header 裡威力最大、也最複雜**的一個。它告訴瀏覽器：

> 「我的網頁只允許從這幾個來源載入腳本、樣式、圖片、字型⋯⋯其它一律拒絕。」

### 為什麼這是「最後一道防線」？

Day 02 我們講過 XSS——只要有一個 `<script>alert(1)</script>` 漏進你的 HTML，攻擊者就能執行任意 JavaScript。但**如果 CSP 設成「只允許從 self（自己網域）的 JS」**，攻擊者注入 `<script src="https://evil.com/steal.js">` 也會被瀏覽器擋下來。

### 一個務實的起手式

```http
Content-Security-Policy:
    default-src 'self';
    script-src 'self';
    style-src 'self';
    img-src 'self' data: https:;
    connect-src 'self';
    font-src 'self';
    object-src 'none';
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'self';
```

**逐行解釋：**
- `default-src 'self'` —— 預設只允許自己網域的資源。
- `script-src 'self'` —— JS 只能從自己網域載入（**沒有 `'unsafe-inline'`、沒有 `'unsafe-eval'`**）。
- `img-src 'self' data: https:` —— 圖片可以從 self、`data:` URL 跟任何 HTTPS 來源（通常 CDN 圖片不好限制）。
- `object-src 'none'` —— 禁用 Flash / Java applet 等老古董，避免被當成攻擊載體。
- `frame-ancestors 'none'` —— 不准任何網站把我的頁面包進 iframe（取代 `X-Frame-Options`）。
- `base-uri 'self'` —— 防止攻擊者透過 `<base>` tag 改變相對路徑的解析基底。
- `form-action 'self'` —— 表單只能 submit 到自己網域，防止資料被釣到外部。

### `'unsafe-inline'` 是大坑

很多新手寫 CSP 第一個動作就是加 `'unsafe-inline'`，因為「我的網頁就有 `<script>` 內嵌啊、有 `style="..."` 啊」。**加了 `'unsafe-inline'` 等於 CSP 沒設**——XSS 注入的 inline script 就是 inline script。

正確做法：
1. **把 inline script 移到 `.js` 檔案**裡。
2. 真的非要 inline，用 **nonce** 或 **hash**：

```http
Content-Security-Policy: script-src 'self' 'nonce-abc123XYZ';
```

```html
<script nonce="abc123XYZ">
  // 只有帶這個 nonce 的 inline script 才會被執行
  // nonce 必須是每個 request 隨機產生
</script>
```

### Spring Boot：用 nonce 的 CSP

```java
@Component
public class CspNonceFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws ServletException, IOException {
        // 每個 request 產生一個隨機 nonce
        byte[] random = new byte[16];
        new SecureRandom().nextBytes(random);
        String nonce = Base64.getEncoder().encodeToString(random);
        req.setAttribute("cspNonce", nonce);

        res.setHeader("Content-Security-Policy",
            "default-src 'self'; " +
            "script-src 'self' 'nonce-" + nonce + "'; " +
            "style-src 'self'; " +
            "object-src 'none'; " +
            "frame-ancestors 'none'; " +
            "base-uri 'self'");

        chain.doFilter(req, res);
    }
}
```

然後在 Thymeleaf / JSP / 你的 template engine 裡：

```html
<script th:nonce="${cspNonce}">
  // 這裡的 inline script 才會被允許執行
</script>
```

### 先用 Report-Only 模式試水溫

直接上線 CSP 風險很高——你可能不知道哪個第三方 SDK（Google Analytics、客服 widget、廣告商）有 inline script。

**先用 Report-Only：**

```http
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report
```

`Report-Only` 不會真的擋，只會把違規事件 POST 到 `/csp-report` endpoint。蒐集 1~2 週，看看違規日誌，把合法的來源加進白名單，再切到 enforce 模式。

```java
@PostMapping(value = "/csp-report", consumes = "application/csp-report")
public ResponseEntity<Void> handleCspReport(@RequestBody String body) {
    log.warn("CSP violation: {}", body);
    return ResponseEntity.noContent().build();
}
```

---

## 五、X-Frame-Options：防 Clickjacking

```http
X-Frame-Options: DENY
```

意思：**任何網站都不能用 `<iframe>` 把我的頁面嵌進去**。

### Clickjacking 怎麼運作？

1. 攻擊者做一個網站 `evil.com`，把 `your-bank.com/transfer` 用 `<iframe>` 嵌進來，並用 CSS 設成透明、覆蓋在誘餌按鈕上。
2. 使用者已經登入 `your-bank.com`（Cookie 還在），到 `evil.com` 看到「點我抽 iPhone 17」。
3. 使用者點擊 → 實際上點到了透明 iframe 裡 your-bank 的「轉帳」按鈕。
4. 因為帶著正確的 Cookie，後端認為這是合法請求。

### 三個值

- `DENY` —— 完全不准被 iframe（最安全）。
- `SAMEORIGIN` —— 只有同網域可以 iframe（適合單頁應用內部嵌套）。
- `ALLOW-FROM` —— 已被淘汰，**不要用**。

### CSP `frame-ancestors` 取代它

CSP 第 2 版以後新增了 `frame-ancestors`：

```http
Content-Security-Policy: frame-ancestors 'none';
```

這個比 `X-Frame-Options` **更靈活**（可以列多個來源），而且**新瀏覽器優先讀 CSP**。建議兩個都設（`X-Frame-Options` 給舊瀏覽器當 fallback）。

---

## 六、X-Content-Type-Options: nosniff

```http
X-Content-Type-Options: nosniff
```

意思：**瀏覽器你閉嘴，不要自己猜 Content-Type**。

### 為什麼要這個？

舊瀏覽器有個「貼心」功能叫 MIME sniffing：如果伺服器回的 `Content-Type` 是 `text/plain`，但實際內容看起來像 HTML，瀏覽器會「幫你」當成 HTML 渲染。

問題：你的網站允許使用者上傳「文字檔」，攻擊者上傳一個 `evil.txt`，內容是 `<script>...</script>`。如果伺服器回 `Content-Type: text/plain`，沒設 `nosniff`——某些瀏覽器會把它當 HTML 執行，XSS 完成。

加上 `nosniff` 後：「Content-Type 是 text/plain 就乖乖當文字顯示。」

**這個 header 沒有副作用、沒有需要調的參數，所有網站都該加。**

---

## 七、Referrer-Policy：控制 Referer 洩漏

當使用者從 `https://your-bank.com/account/12345/transactions` 點到 `https://external-site.com`，預設情況下 `external-site.com` 會收到一個 `Referer` header，**包含完整 URL（含 `12345` 這種 ID 跟 query string）**。

這會洩漏：
- 內部頁面結構
- 資源 ID
- 寫在 query string 裡的 token、session ID（雖然 token 不該放 URL，但很多人這樣做）

### 推薦設定

```http
Referrer-Policy: strict-origin-when-cross-origin
```

意思：
- 同網域之間 → 帶完整 URL（內部 navigation 需要）。
- 跨網域 → 只帶 origin（`https://your-bank.com`），不帶路徑跟 query。
- HTTPS → HTTP 降級 → 完全不帶 Referer。

更嚴格可以用 `no-referrer`，但會影響 Google Analytics 等工具的來源追蹤。`strict-origin-when-cross-origin` 是現在主流瀏覽器的**預設值**，但明確設定還是比較保險。

---

## 八、Permissions-Policy：關掉不需要的瀏覽器功能

```http
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

意思：**這個網站完全不需要相機、麥克風、地理位置、Payment Request API**。

如果你的網站被 XSS 注入，攻擊者本來可以呼叫 `navigator.mediaDevices.getUserMedia()` 開啟相機——加上這個 header，瀏覽器會直接拒絕。

**最小權限原則**：你的網站不用就關掉，總比哪天被注入時手忙腳亂好。

---

## 九、CORS：最容易設錯、後果最嚴重的 header

CORS（Cross-Origin Resource Sharing）跟前面的 header 完全是不同邏輯：前面的是「告訴瀏覽器**多保護一點**」，**CORS 是「告訴瀏覽器我願意打開哪些保護」**——設錯就是把保護拆掉。

### 9.1 同源政策（Same-Origin Policy）— 預設就在保護你

瀏覽器預設有一條鐵則：**A 網域的 JS 不能讀 B 網域的 response**。

這就是為什麼：
- 你登入了 gmail.com 後，惡意網站 evil.com 的 JS **無法直接讀** `https://gmail.com/api/inbox`——即使瀏覽器會帶 Cookie 過去，response 也讀不到。

**CORS 是這條鐵則的「例外清單」**——如果你的 API 想讓某個前端（不同網域）讀，就要透過 CORS 明確開放。

### 9.2 災難級錯誤：`Access-Control-Allow-Origin: *` 配 `credentials: true`

很多人 Google 一下「CORS 怎麼設」，第一個答案就是：

```java
// ❌ 災難寫法
response.setHeader("Access-Control-Allow-Origin", "*");
response.setHeader("Access-Control-Allow-Credentials", "true");
```

**這兩行同時出現是規格上不允許的**——瀏覽器會拒絕這個 response。但問題是：**很多後端為了「方便」會根據 request 的 Origin 動態填回去：**

```java
// ❌ 還是災難
String origin = request.getHeader("Origin");
response.setHeader("Access-Control-Allow-Origin", origin); // 完全反射
response.setHeader("Access-Control-Allow-Credentials", "true");
```

這等於：「**任何網域都可以帶著使用者的 Cookie 讀我的 API**」。

實際攻擊：
1. 使用者已經登入 `your-bank.com`（Cookie 在）。
2. 使用者瀏覽 `evil.com`，evil.com 的 JS 發 `fetch("https://your-bank.com/api/me", { credentials: "include" })`。
3. 你的後端看到 `Origin: https://evil.com`，照單反射回 `Access-Control-Allow-Origin: https://evil.com`。
4. 瀏覽器：「OK 你授權了，evil.com 你可以讀這個 response」。
5. **使用者的個資、token、餘額全被 evil.com 拿走。**

### 9.3 正確寫法：白名單 + 不要反射

**Spring Boot：**

```java
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                // ✅ 白名單，明確列出允許的 origin
                .allowedOrigins(
                    "https://app.your-bank.com",
                    "https://admin.your-bank.com"
                )
                .allowedMethods("GET", "POST", "PUT", "DELETE")
                .allowedHeaders("Authorization", "Content-Type")
                .allowCredentials(true)
                .maxAge(3600);
    }
}
```

**Gin（用 [gin-contrib/cors](https://github.com/gin-contrib/cors)）：**

```go
import "github.com/gin-contrib/cors"

func setupCors(r *gin.Engine) {
    r.Use(cors.New(cors.Config{
        AllowOrigins: []string{
            "https://app.your-bank.com",
            "https://admin.your-bank.com",
        },
        AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
        AllowHeaders:     []string{"Authorization", "Content-Type"},
        AllowCredentials: true,
        MaxAge:           time.Hour,
    }))
}
```

### 9.4 常見的 CORS 設定錯誤

| 錯誤寫法 | 問題 |
| :-- | :-- |
| `Access-Control-Allow-Origin: *` 配 credentials | 規格不允許，但很多人改成反射 origin → 等於關閉保護 |
| 反射 `Origin` header（不檢查白名單） | 任何網域都能帶 Cookie 打 API |
| 子網域用 wildcard：`*.your-bank.com` | 子網域被接管時（subdomain takeover）就完蛋 |
| 把 staging 的 `localhost:3000` 留在 production 白名單 | 攻擊者開個 localhost 的釣魚 link 就能打你的 production |
| 只在 nginx 設 CORS，後端框架也設了一次 | 兩邊不一致，會出現 `Access-Control-Allow-Origin` 出現兩次 → 瀏覽器報錯 |

### 9.5 Preflight 是什麼？

當前端發送「非簡單請求」（含自定義 header、PUT/DELETE 等），瀏覽器**會先發一個 `OPTIONS` request 詢問**：「我能不能用 PUT method 加 Authorization header 打你？」

伺服器回：

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.your-bank.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Max-Age: 3600
```

`Access-Control-Max-Age: 3600` 表示「這個 preflight 答案 1 小時內有效」——同一個 endpoint 每次請求都跑 preflight 會嚴重影響效能。

> ⚠️ 注意：認證授權檢查 **不要放在 preflight (OPTIONS) 上**——preflight 不會帶 Cookie / Authorization header（按設計）。讓 OPTIONS 直接通過（CORS middleware 會處理），實際的鑑權在 GET/POST/PUT/DELETE 上做。

---

## 十、實戰：一份 production-ready 的 Spring Boot 設定

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // CORS（從另一個 Bean 設定）
            .cors(Customizer.withDefaults())
            // CSRF（API 用 JWT 可以關，用 Cookie session 不要關）
            .csrf(csrf -> csrf.disable())
            // Security Headers
            .headers(headers -> headers
                // HSTS
                .httpStrictTransportSecurity(hsts -> hsts
                    .maxAgeInSeconds(31536000)
                    .includeSubDomains(true)
                    .preload(true))
                // X-Frame-Options
                .frameOptions(frame -> frame.deny())
                // X-Content-Type-Options
                .contentTypeOptions(Customizer.withDefaults())
                // Referrer-Policy
                .referrerPolicy(ref -> ref.policy(
                    ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN))
                // CSP
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                    "default-src 'self'; " +
                    "script-src 'self'; " +
                    "style-src 'self'; " +
                    "img-src 'self' data: https:; " +
                    "connect-src 'self'; " +
                    "object-src 'none'; " +
                    "frame-ancestors 'none'; " +
                    "base-uri 'self'; " +
                    "form-action 'self'"))
                // Permissions-Policy（Spring Security 6 要自己加）
                .addHeaderWriter((req, res) -> res.setHeader(
                    "Permissions-Policy",
                    "camera=(), microphone=(), geolocation=(), payment=()"))
            );
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(List.of(
            "https://app.your-bank.com",
            "https://admin.your-bank.com"
        ));
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        cfg.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        cfg.setAllowCredentials(true);
        cfg.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", cfg);
        return source;
    }
}
```

---

## 十一、實戰：一份 Gin 中介層

```go
package middleware

import (
    "github.com/gin-contrib/cors"
    "github.com/gin-gonic/gin"
    "time"
)

func SecurityHeaders() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
        c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        c.Header("Content-Security-Policy",
            "default-src 'self'; "+
            "script-src 'self'; "+
            "style-src 'self'; "+
            "img-src 'self' data: https:; "+
            "object-src 'none'; "+
            "frame-ancestors 'none'; "+
            "base-uri 'self'; "+
            "form-action 'self'")
        c.Next()
    }
}

func CorsConfig() gin.HandlerFunc {
    return cors.New(cors.Config{
        AllowOrigins: []string{
            "https://app.your-bank.com",
            "https://admin.your-bank.com",
        },
        AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
        AllowHeaders:     []string{"Authorization", "Content-Type"},
        AllowCredentials: true,
        MaxAge:           time.Hour,
    })
}

// main.go
func main() {
    r := gin.Default()
    r.Use(middleware.SecurityHeaders())
    r.Use(middleware.CorsConfig())
    // ...
}
```

---

## 十二、怎麼確認 Header 真的有設？

不要相信「我設了就一定有」。**永遠用 curl 或瀏覽器 DevTools 驗證一次：**

```bash
curl -I https://your-bank.com/api/health
```

或用線上掃描工具：
- [Mozilla Observatory](https://observatory.mozilla.org/) —— 給網站打分數，告訴你哪些 header 缺、哪些設錯。
- [SecurityHeaders.com](https://securityheaders.com/) —— 同上，介面更直觀。

A+ 評級的 header 設定大概長這樣（六個都齊全且 CSP 沒有 `unsafe-inline`）。

---

## 十三、實戰檢查表

1. ☐ `Strict-Transport-Security` 已設，`max-age` 至少 1 年？
2. ☐ `Content-Security-Policy` 已設，**沒有** `'unsafe-inline'` 或 `'unsafe-eval'`？
3. ☐ CSP 上線前先用 `Content-Security-Policy-Report-Only` 跑過？
4. ☐ `X-Frame-Options: DENY`（或 CSP `frame-ancestors 'none'`）？
5. ☐ `X-Content-Type-Options: nosniff`？
6. ☐ `Referrer-Policy` 已設（推薦 `strict-origin-when-cross-origin`）？
7. ☐ `Permissions-Policy` 把不用的 API 都關掉？
8. ☐ CORS **沒有**用 `*` 配 credentials，**沒有**反射 Origin？
9. ☐ CORS 白名單**沒有** `localhost`、staging URL 殘留在 production？
10. ☐ 用 `curl -I` 或 SecurityHeaders.com 驗證過實際輸出？

---

## 十四、今日重點回顧

1. **Security Headers 是後端對瀏覽器的安全指令**——很多攻擊（Clickjacking、SSL Strip、XSS 後續行為）只能在瀏覽器端擋。
2. **HSTS** 強制 HTTPS，但 `preload` 是單向操作要謹慎。
3. **CSP 是 XSS 的最後一道防線**，但 `'unsafe-inline'` 會讓它形同虛設；先用 Report-Only 跑一陣子再 enforce。
4. **`X-Frame-Options: DENY` / CSP `frame-ancestors 'none'`** 防 Clickjacking，兩個都設。
5. **`X-Content-Type-Options: nosniff`** 沒有副作用、所有網站都該加。
6. **CORS 不是「保護」，是「打開保護的例外清單」**——白名單明確列、不要反射 Origin、不要 `*` 配 credentials。
7. **OPTIONS preflight 不要做鑑權**，鑑權放在實際的 GET/POST 上。
8. **設完一定要用 curl 或 Observatory 驗證**——「我以為我設了」是最常見的失誤。

---

## 十五、明天預告

Day 10 我們進到 **SSRF（Server-Side Request Forgery，伺服器端請求偽造）**——當你的後端會「主動對外發 request」（例如抓使用者給的圖片網址、打 webhook、串第三方 API），攻擊者怎麼騙它去打雲端的 metadata endpoint（如 `169.254.169.254`）或內網服務，把你的伺服器當成打進內網的跳板。也會講為什麼「擋掉內網 IP」沒有你想的那麼簡單。

---

> 參考資料
> - OWASP Secure Headers Project
> - MDN — Content Security Policy (CSP)
> - MDN — HTTP Strict Transport Security
> - MDN — Cross-Origin Resource Sharing (CORS)
> - Mozilla Observatory — Web Security Best Practices
> - PortSwigger Web Security Academy — CORS vulnerabilities
> - W3C Content Security Policy Level 3
