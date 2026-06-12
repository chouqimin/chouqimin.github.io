---
title: "Day 46：HTTP Host Header Attack（主機標頭注入攻擊）"
date: 2026-06-11
tags: ["HTTP Header", "Injection", "網路"]
---

# Day 46：HTTP Host Header Attack（主機標頭注入攻擊）

> 後端工程師資安系列 Day 46
> 適合對象：後端入門到中階工程師
> 主要範例語言：Java（Spring Boot）、Go

---

## 一、什麼是 Host Header？

當瀏覽器發送 HTTP 請求時，會在標頭中帶上 `Host`，告訴伺服器「我要訪問哪一個網域」。同一台伺服器（同一個 IP）上可能掛了好幾個網站，伺服器要靠 `Host` 來決定要回應哪個虛擬主機。

一個典型的 HTTP 請求長這樣：

```
GET /reset-password HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0
```

問題出在哪？**`Host` 是由「客戶端」送進來的，攻擊者可以隨便填**。如果後端在程式裡直接信任 `Host`、`X-Forwarded-Host`、`X-Host` 這類由前端傳入的值，就可能踩雷。

---

## 二、為什麼後端會踩雷？

後端常見的「信任 Host」的場景：

1. **產生絕對網址**：寄出密碼重設信、Email 驗證信時，要組「點擊這個連結 → `https://{host}/reset?token=xxx`」。
2. **產生 OAuth / Webhook callback URL**。
3. **快取鍵（cache key）只用 path 不含 host**：CDN 或反向代理可能把不同 host 的回應混在一起。
4. **多租戶（multi-tenant）系統**：用 Host 判斷是哪個客戶的資料。
5. **CORS 白名單檢查**：把 Host 當成可信來源。

只要後端從 `request.getHeader("Host")` 或 `r.Host` 拿值，再放進信件、Log、SQL、Redirect URL，就有風險。

---

## 三、常見的攻擊手法

### 1. 密碼重設毒化（Password Reset Poisoning）—— 最經典

情境：使用者按下「忘記密碼」，後端寄信，內容含有：

```
請點擊以下連結重設密碼：
https://{Host}/reset?token=ABC123
```

如果後端直接用 `request.Host` 組這個 URL，攻擊者可以這樣做：

```
POST /forgot-password HTTP/1.1
Host: evil.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```

後端寄出的信件就會變成：

```
請點擊以下連結重設密碼：
https://evil.com/reset?token=ABC123
```

受害者點下去 → token 被攻擊者拿到 → 帳號被接管。

### 2. 利用 `X-Forwarded-Host` 繞過

很多框架在反向代理後面會優先讀 `X-Forwarded-Host`。攻擊者只要送：

```
GET /forgot-password HTTP/1.1
Host: www.example.com
X-Forwarded-Host: evil.com
```

後端誤以為自己是 `evil.com`，效果同上。

### 3. Web Cache Poisoning（搭配 CDN）

如果 CDN 的快取鍵不含 Host，而後端會把 Host 反射到回應裡（例如 `<link rel="canonical" href="https://{host}/...">`），攻擊者就能讓 CDN 快取一個指向惡意網域的頁面，影響所有後續訪客。

### 4. 伺服器端 SSRF / 路由旁路

某些反向代理（Nginx、Apache、雲端 LB）會用 Host 來決定要轉發到哪個 upstream。亂改 Host 有機會打到內部後台、admin 服務、metadata 端點。

---

## 四、漏洞程式碼範例

### Java（Spring Boot）— ❌ 錯誤示範

```java
@RestController
public class PasswordResetController {

    @Autowired
    private MailService mailService;

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgot(@RequestParam String email,
                                    HttpServletRequest request) {
        String token = TokenGenerator.create(email);

        // ❌ 直接信任客戶端送來的 Host
        String host = request.getHeader("Host");
        String resetUrl = "https://" + host + "/reset?token=" + token;

        mailService.send(email,
            "重設密碼",
            "請點擊：" + resetUrl);

        return ResponseEntity.ok().build();
    }
}
```

### Go — ❌ 錯誤示範

```go
func forgotPassword(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    token := generateToken(email)

    // ❌ r.Host 來自客戶端 Host 標頭，可被偽造
    resetURL := fmt.Sprintf("https://%s/reset?token=%s", r.Host, token)

    sendMail(email, "重設密碼", "請點擊："+resetURL)
    w.WriteHeader(http.StatusOK)
}
```

兩個版本都把不可信的 Host 直接組進 URL，攻擊者就能把連結改成自己網域。

---

## 五、正確的防禦做法

### 防禦原則一句話

> **絕對網址、Email、OAuth callback 等敏感資訊，不要從 Request Header 動態組出來；改用「伺服器端設定」的固定值。**

### 防禦 1：用設定檔寫死 Base URL

#### Java（Spring Boot）— ✅ 正確示範

`application.yml`：

```yaml
app:
  public-base-url: https://www.example.com
```

```java
@RestController
public class PasswordResetController {

    @Value("${app.public-base-url}")
    private String baseUrl;          // ✅ 從設定檔讀取

    @Autowired
    private MailService mailService;

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgot(@RequestParam String email) {
        String token = TokenGenerator.create(email);
        String resetUrl = baseUrl + "/reset?token=" + token;

        mailService.send(email, "重設密碼", "請點擊：" + resetUrl);
        return ResponseEntity.ok().build();
    }
}
```

#### Go — ✅ 正確示範

```go
// 從環境變數讀取，例如 APP_BASE_URL=https://www.example.com
var baseURL = os.Getenv("APP_BASE_URL")

func forgotPassword(w http.ResponseWriter, r *http.Request) {
    email := r.FormValue("email")
    token := generateToken(email)

    resetURL := fmt.Sprintf("%s/reset?token=%s", baseURL, token)
    sendMail(email, "重設密碼", "請點擊："+resetURL)
    w.WriteHeader(http.StatusOK)
}
```

### 防禦 2：建立 Host 白名單（Allowlist）

如果系統真的有「多網域」需求（例如 SaaS 多租戶），就「驗證」Host 是否在白名單裡。

#### Java：寫一個 Filter

```java
@Component
public class HostAllowlistFilter extends OncePerRequestFilter {

    private static final Set<String> ALLOWED_HOSTS = Set.of(
        "www.example.com",
        "api.example.com",
        "tenant-a.example.com"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain)
            throws ServletException, IOException {

        String host = req.getHeader("Host");
        if (host == null || !ALLOWED_HOSTS.contains(host.toLowerCase())) {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid Host");
            return;
        }
        chain.doFilter(req, res);
    }
}
```

#### Go：寫一個 Middleware

```go
var allowedHosts = map[string]struct{}{
    "www.example.com":      {},
    "api.example.com":      {},
    "tenant-a.example.com": {},
}

func HostAllowlist(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        host := strings.ToLower(r.Host)
        // 去掉 port，例如 example.com:8080 -> example.com
        if h, _, err := net.SplitHostPort(host); err == nil {
            host = h
        }
        if _, ok := allowedHosts[host]; !ok {
            http.Error(w, "Invalid Host", http.StatusBadRequest)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

### 防禦 3：留意 `X-Forwarded-Host` / `Forwarded` 標頭

如果你的服務在反向代理（Nginx、ALB、Cloudflare）後面，那些代理會幫你補上 `X-Forwarded-Host`、`X-Forwarded-For`、`Forwarded`。**只有「你自己控制」的反向代理送來的這些標頭才能信任。**

實作要點：

1. 在 Nginx / ALB 設定：對外部請求送入的 `X-Forwarded-Host` 一律覆寫或刪除，不要讓使用者偽造。
2. 後端框架（如 Spring Boot 的 `ForwardedHeaderFilter`、Go 的 reverse proxy library）只在「來源 IP 是可信代理」時才接受這些標頭。
3. 不需要支援多網域時，後端**不要**讀 `X-Forwarded-Host`，直接用設定檔即可。

### 防禦 4：反向代理層加固（Nginx 範例）

```nginx
server {
    listen 443 ssl;
    server_name www.example.com;

    # 任何不認得的 Host 直接回 404，不讓它打到後端
    if ($host !~* ^(www\.example\.com|api\.example\.com)$ ) {
        return 444;
    }

    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;                  # 用 Nginx 認可的 host
        proxy_set_header X-Forwarded-Host $host;      # 覆寫，不讓客戶端偽造
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 防禦 5：另外設定一個「預設虛擬主機」吃掉怪異 Host

很多攻擊者是用 IP 直連發 `Host: evil.com`。在 Nginx / Apache 設一個 `default_server`，把所有未知 Host 直接回 444 或 400，能擋掉大部分自動化掃描。

---

## 六、自我檢查清單

寄信、產生網址、OAuth callback 之類的場景，你的程式碼裡是不是有：

- [ ] `request.getHeader("Host")`、`request.getServerName()`
- [ ] `r.Host`、`r.URL.Host`
- [ ] `request.getHeader("X-Forwarded-Host")`
- [ ] 用 Host 拼字串組成 URL 後寫進 Email
- [ ] 把 Host 反射到 HTML（例如 `<link rel="canonical">`）

如果有 → 改成從設定檔讀，或者加白名單驗證。

---

## 七、小結

Host Header Attack 看似不起眼，但因為它常常出現在「密碼重設信」這類最敏感的流程，造成的後果就是帳號被接管。後端工程師要記住的核心觀念是：

1. **任何來自客戶端的標頭都是不可信的**，Host 也一樣。
2. **絕對網址用伺服器端設定值**，不要動態組。
3. **必要時做白名單**，並在反向代理層補一道防線。
4. **`X-Forwarded-Host` 只信任自己的代理送的**。

明天 Day 47 我們會講 **Insecure Randomness（不安全的隨機性）**——你的密碼重設 token、session ID、邀請碼如果是用 `java.util.Random` / `math/rand` 產生的，其實是「可預測的偽隨機」，攻擊者能反推出後續的值。今天可以先回頭看自己負責的服務有沒有「忘記密碼信」相關程式碼，順手檢查一下吧。

---

### 延伸閱讀

- OWASP：Host Header Injection
- PortSwigger Web Security Academy：HTTP Host header attacks
- CWE-20：Improper Input Validation
