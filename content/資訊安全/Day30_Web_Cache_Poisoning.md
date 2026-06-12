---
title: "Day 30：Web Cache Poisoning（伺服器端快取污染）"
date: 2026-05-26
tags: ["快取", "HTTP Header", "CDN"]
---

# Day 30：Web Cache Poisoning（伺服器端快取污染）

> 「Cache 是工程師的好朋友，也是攻擊者的好朋友。」
> 當你不小心把攻擊者的輸入也一起快取下來，整台 CDN 都會幫你免費散播 payload。

---

## 一、什麼是 Web Cache Poisoning？

**Web Cache Poisoning（網頁快取污染）** 是指攻擊者透過一次特製的 HTTP 請求，**讓 CDN、Reverse Proxy 或應用層快取**儲存一份「被污染過」的回應，之後所有正常使用者拿到的都是這份惡意回應。

跟 XSS（Day02）比起來，最可怕的差別在於：

- **XSS** 通常只影響「中招的那位使用者」。
- **Cache Poisoning** 一次中招，**之後所有人都會被打**，直到 cache 過期或手動清除。

而且攻擊者**不需要登入、不需要互動**，只要找到一個 cache 與後端對「同一個 request」的看法不一致的縫，就能持續放毒。

---

## 二、核心觀念：Cache Key vs Unkeyed Input

要理解 Cache Poisoning，必須先理解快取怎麼判斷「兩個請求是不是同一個」。

每一台 cache（Varnish、Cloudflare、Nginx、CloudFront…）都會用一組「**Cache Key**」當索引，常見組成是：

```
Method + Host + Path + (部分) Query String
```

**有被納入 cache key 的欄位 = keyed**，沒被納入的 = **unkeyed**。

問題是：後端應用程式在處理 request 時，**會用到很多 unkeyed 的欄位**（例如某些 header、cookie），這就形成了「快取的視角」與「後端的視角」不一致。

> 攻擊者的目標就是：**找出一個會影響後端回應，但不會影響 cache key 的輸入**，然後把惡意內容種進 cache。

這類輸入稱為 **unkeyed input**，是 Cache Poisoning 的鑰匙。

---

## 三、最經典的例子：`X-Forwarded-Host` 污染

許多後端框架會用 `X-Forwarded-Host`（或 `X-Host`、`X-Forwarded-Server`）來組裝**絕對網址**，例如重設密碼信、Open Graph 標籤、`<link rel="canonical">`、JSONP callback 等。

但是 CDN 通常**不會把這個 header 納入 cache key**。

### 攻擊流程

1. 攻擊者送一個請求到 `https://example.com/`，並附上：
   ```
   X-Forwarded-Host: evil.com
   ```
2. 後端產生的 HTML 變成：
   ```html
   <script src="https://evil.com/static/app.js"></script>
   ```
3. CDN 認為這只是個普通的 `GET /`，把這份 HTML 存起來。
4. 之後所有訪問首頁的人，都會去 `evil.com` 載入 JS，等同於全站 XSS + RCE 跳板。

---

## 四、其他常見的污染手法

### 1. Unkeyed Query Parameter

部分快取只把 query string 排序後納入 key，但有些參數（例如 `utm_*`、`fbclid`）會被「忽略」。攻擊者把惡意 payload 塞進這些被忽略的參數，後端卻照單全收。

### 2. HTTP Method Override

像 `X-HTTP-Method-Override: POST` 這種 header，可以讓 `GET` 請求被後端當成 `POST` 處理。一旦回應被 cache 起來，後續使用者一個普通 `GET` 就會拿到「POST 回應」。

### 3. Fat GET

讓 `GET` 請求帶 body：cache 通常只看 URL，但後端會解析 body 並產生不一樣的回應。

### 4. Cache Key Normalization 差異

`/profile` 與 `/profile/` 被視為同一個 key，但後端走的是不同 route。或是 `?lang=en` 與 `?LANG=en` 被視為同一個 key，但後端會回不同語系。

### 5. Cache Deception（快取欺騙）

請求 `/account.php/nonexistent.css` → 後端解析成 `/account.php`（回傳含敏感資料的 HTML），但 CDN 看到 `.css` 副檔名就快取下來，之後攻擊者直接訪問這個 URL 就能拿到別人的 session 資料。

---

## 五、簡單情境：你以為很安全的「歡迎頁」

```http
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: evil.com
```

後端產出：

```html
<!doctype html>
<html>
  <head>
    <link rel="canonical" href="https://evil.com/">
    <script src="https://evil.com/track.js"></script>
  </head>
  ...
</html>
```

接著正常使用者：

```http
GET / HTTP/1.1
Host: example.com
```

由於 cache key 一樣 → 拿到上面那份惡意 HTML。**全站炸開**。

---

## 六、Java 範例（Spring Boot）

### 危險寫法：信任 `X-Forwarded-Host` 組絕對網址

```java
// BAD：直接用使用者傳進來的 header 組 URL
@GetMapping("/")
public String home(HttpServletRequest req, Model model) {
    String host = req.getHeader("X-Forwarded-Host");
    if (host == null) host = req.getHeader("Host");

    // 這個 URL 會被印到 <link rel="canonical"> 與 <script src="...">
    model.addAttribute("canonical", "https://" + host + "/");
    model.addAttribute("trackerUrl", "https://" + host + "/track.js");
    return "index";
}
```

只要 CDN（CloudFront / Cloudflare / Akamai）沒把 `X-Forwarded-Host` 納入 cache key，這個回應就會被毒化並快取給所有人。

### 安全寫法：白名單 + 設定可信任的 host

```java
// GOOD：絕對網址只能來自設定檔的白名單
@Component
public class SiteProperties {
    @Value("${site.canonical-host}") // e.g. "www.example.com"
    private String canonicalHost;
    public String canonicalHost() { return canonicalHost; }
}

@RestController
@RequiredArgsConstructor
public class HomeController {
    private final SiteProperties site;

    @GetMapping("/")
    public ModelAndView home() {
        var mv = new ModelAndView("index");
        mv.addObject("canonical", "https://" + site.canonicalHost() + "/");
        mv.addObject("trackerUrl", "https://" + site.canonicalHost() + "/track.js");
        return mv;
    }
}
```

關鍵點：

- **絕對網址永遠來自設定檔或環境變數**，不要從 request header 取。
- 若需要支援多個合法 host，建立一份「允許清單」並做嚴格比對。
- 若一定要看 `X-Forwarded-*`，請使用 Spring 的 `ForwardedHeaderFilter`，並只在**信任的反向代理之後**啟用。

### 加碼：對快取的回應加上 `Vary`

若你的回應**真的會根據** `Accept-Language`、`Origin` 等 header 變化，請主動告訴 cache：

```java
@GetMapping("/api/profile")
public ResponseEntity<Profile> profile(@RequestHeader("Accept-Language") String lang) {
    Profile p = service.byLanguage(lang);
    return ResponseEntity.ok()
            .header(HttpHeaders.VARY, "Accept-Language")
            .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic())
            .body(p);
}
```

`Vary: Accept-Language` 會讓 cache 把該 header 也納入 key，避免被污染。

### 對「個人化頁面」用 `Cache-Control: private`

```java
@GetMapping("/dashboard")
public ResponseEntity<String> dashboard(Principal user) {
    return ResponseEntity.ok()
            .cacheControl(CacheControl.noStore())  // 完全不要快取
            // 或：.cacheControl(CacheControl.empty().cachePrivate())
            .body(render(user));
}
```

> 含登入狀態 / Cookie 的回應 **絕對不要** `cachePublic()`。

---

## 七、Go 範例（net/http + chi / gin）

### 危險寫法：用 `r.Host` 或 `X-Forwarded-Host` 組重設密碼連結

```go
// BAD：把 request header 拼進回應
func resetEmail(w http.ResponseWriter, r *http.Request) {
    host := r.Header.Get("X-Forwarded-Host")
    if host == "" {
        host = r.Host
    }
    link := "https://" + host + "/reset?token=" + token

    // 將 link 寫進 email、HTML，且這個 endpoint 被快取（例如 /pwreset/form）
    fmt.Fprintf(w, `<a href="%s">Reset</a>`, link)
}
```

→ 攻擊者送一次 `X-Forwarded-Host: evil.com`，之後正常使用者打開重設信，連結就會指向 evil.com，token 直接外流。

### 安全寫法 1：固定 host 來源

```go
// GOOD：canonical host 由設定檔提供
type Config struct {
    CanonicalHost string `env:"CANONICAL_HOST,required"`
}

func (s *Server) resetEmail(w http.ResponseWriter, r *http.Request) {
    link := "https://" + s.cfg.CanonicalHost + "/reset?token=" + token
    fmt.Fprintf(w, `<a href="%s">Reset</a>`, link)
}
```

### 安全寫法 2：白名單驗證 `Host` header

```go
// 中介層：拒絕不在白名單的 Host
func AllowedHosts(allowed map[string]struct{}) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            host := strings.ToLower(stripPort(r.Host))
            if _, ok := allowed[host]; !ok {
                http.Error(w, "invalid host", http.StatusBadRequest)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

func stripPort(h string) string {
    if i := strings.Index(h, ":"); i >= 0 {
        return h[:i]
    }
    return h
}
```

### 加碼：標記回應的 `Vary` 與 `Cache-Control`

```go
func apiHandler(w http.ResponseWriter, r *http.Request) {
    // 若回應會隨 Origin 變化（CORS）
    w.Header().Set("Vary", "Origin, Accept-Language")

    // 不含個人化資料 → 可被共用快取存 60 秒
    w.Header().Set("Cache-Control", "public, max-age=60")

    // 若含登入資料：絕對禁用共用快取
    // w.Header().Set("Cache-Control", "private, no-store")

    json.NewEncoder(w).Encode(data)
}
```

### 避免 Cache Deception：固定 URL 規則

```go
// BAD：允許任意尾綴
r.Get("/account/*", showAccount)   // /account/foo.css 也會匹配

// GOOD：嚴格路徑
r.Get("/account", showAccount)
```

不要讓 `/account.php/x.css` 這種模糊路徑通過。

---

## 八、CDN / Reverse Proxy 設定建議

不論你前面是 Cloudflare、CloudFront、Nginx、Varnish，都有兩條金律：

1. **明確列出哪些 header / query 會進入 cache key**。預設一律不要納入。
2. **任何含 `Authorization`、`Cookie`、`Set-Cookie` 的回應，禁止共用快取**。

以 Nginx 為例：

```nginx
# 個人化頁面不快取
location /dashboard {
    proxy_pass http://app;
    proxy_no_cache 1;
    proxy_cache_bypass 1;
    add_header Cache-Control "private, no-store" always;
}

# 公開頁面：明確列出參與 cache key 的 header
proxy_cache_key "$scheme$request_method$host$uri$is_args$args";
# 注意這裡完全沒有把 X-Forwarded-Host 放進來 → 那後端也不該信任它
```

以 Cloudflare 為例：

- 在 Cache Rules 裡明確設定 **Cache Key**，把不該影響回應的 header 全部排除。
- 對含 `Set-Cookie` 的回應，啟用 **Bypass cache on cookie**。

---

## 九、防禦清單（Cache Poisoning Checklist）

1. **不要信任 `Host` / `X-Forwarded-Host` / `X-Forwarded-Proto` / `Referer` 來組絕對網址**：使用設定檔的 canonical host。
2. **嚴格控制 cache 邊界**：個人化、含登入態的頁面一律 `Cache-Control: private, no-store`。
3. **正確使用 `Vary`**：若回應會隨某 header 改變，加入 `Vary`，讓 cache 把它納入 key。
4. **CDN 層白名單 cache key**：明列哪些 header / query 進入 key，其他全部忽略。
5. **路徑正規化**：避免 `/x` 與 `/x/`、`/x.PHP/y.css` 等被視為同一個 key。
6. **禁用 method override**：除非真的需要，否則拒絕 `X-HTTP-Method-Override`。
7. **拒絕 fat GET**：對 `GET` 請求忽略 body，或回 `400`。
8. **監測異常 cache hit**：若同一個 URL 短時間內回應內容大幅變化，告警（Day16 的延伸）。
9. **滲透測試**：使用 [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943)（Burp 外掛）尋找 unkeyed input。
10. **明確區分「靜態」與「動態」域名**：把靜態資源放到 `static.example.com`，動態內容放 `www.example.com`，避免互相污染。

---

## 十、自我檢測小練習

下面這段 Spring Boot 程式，看出問題了嗎？

```java
@RestController
public class ApiController {
    @GetMapping("/api/promo")
    public ResponseEntity<Map<String, Object>> promo(HttpServletRequest req) {
        String lang = req.getHeader("X-User-Lang"); // 由前端帶
        Map<String, Object> body = service.promo(lang);
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofHours(1)).cachePublic())
                .body(body);
    }
}
```

問題：

1. **回應隨 `X-User-Lang` 變化，但沒設定 `Vary: X-User-Lang`** → CDN 會把第一個請求拿到的版本快取給所有人。
2. **`X-User-Lang` 通常不在 cache key 內** → 攻擊者送一個 `X-User-Lang: <script>...</script>` 就能毒化全站 promo 內容（若內容會渲染這欄位）。
3. **`cachePublic()` 用在會變動的回應**：要嘛把該 header 進入 cache key（並且在 CDN 設定一致），要嘛就改用 `cachePrivate()`。

**修正方向**：

- 用白名單驗證 `lang`（只接受 `zh-TW` / `en` / `ja`）。
- 加入 `Vary: X-User-Lang`，並在 CDN 同步設定。
- 或直接從 URL 路徑帶語系：`/api/promo/zh-TW`，讓 key 自動正確。

---

## 十一、今日重點回顧

- Web Cache Poisoning 的根因是「**cache 與後端對 request 的解讀不一致**」。
- 攻擊鑰匙叫做 **unkeyed input**：會影響後端但不會影響 cache key 的欄位。
- 後端工程師最常踩的雷：**信任 `X-Forwarded-Host` 組絕對網址 + 回應被 CDN 快取**。
- 三招最有效：
  1. 絕對網址只用設定檔的 canonical host。
  2. 個人化頁面一律 `private, no-store`。
  3. 任何隨 header 變化的回應都要加 `Vary`，並在 CDN cache key 同步設定。
- 別忘了 Cache Deception：嚴格的路徑規則能擋掉大半。

---

**明天預告 (Day 31)**：我們會談 **ReDoS（Regular Expression Denial of Service，正則表達式阻斷服務）**，看看一行看似無害的正則（例如 `^(a+)+$`）怎麼讓一段短短的字串就把你的 CPU 燒到 100%、整個服務卡死。

> 系列文章索引：Day01 (SQL Injection) → Day29 (NoSQL Injection) → **Day30 (Web Cache Poisoning)**
