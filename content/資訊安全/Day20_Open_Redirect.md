---
title: "Day 20：Open Redirect（開放重新導向漏洞）"
date: 2026-05-16
tags: ["Open Redirect", "輸入驗證", "前端安全"]
---

# Day 20：Open Redirect（開放重新導向漏洞）

> **適合對象**：後端工程師初學者
> **語言範例**：Java（1.8 / 21）、Go
> **OWASP 對應**：A01:2021 - Broken Access Control（間接）、釣魚攻擊與 OAuth 接管的常見起點
> **CWE 編號**：CWE-601（URL Redirection to Untrusted Site）

---

## 一、開場故事：一封來自「銀行」的信

某天，阿美收到一封 Email：

> **主旨**：您的帳戶有異常登入，請立即驗證
> **內文**：請點擊以下連結登入您的銀行帳戶：
> `https://www.mybank.com.tw/login?next=https://mybank-secure.evil.com/login`

阿美看到網址開頭是 `www.mybank.com.tw`，**確實是真的銀行網址**，安心地點了進去。

頁面真的跳轉到銀行的登入頁，她順手登入後——系統「自動」幫她跳轉到 `https://mybank-secure.evil.com/login`，這是攻擊者架的**長得一模一樣的釣魚頁**。

阿美沒注意到網址列已經悄悄換了，又輸入了一次帳密「確認」。

幾分鐘後，攻擊者已經用她的帳密轉走了所有存款。

> **教訓**：使用者只會看「網址開頭」是不是真的網域，後面那串 `?next=...` 沒人會仔細檢查。
> 而後端如果**無條件信任這個參數**，就成了釣魚信的最佳跳板。

---

## 二、什麼是 Open Redirect？

**Open Redirect**（開放重新導向）指的是：

> 你的後端程式接受一個「目的地網址」參數，然後**未經驗證就把使用者導向過去**。

常見的場景：

- **登入後跳回原頁**：`/login?return_to=/dashboard`
- **登出後回首頁**：`/logout?next=/home`
- **OAuth 回呼**：`/oauth/callback?redirect_uri=...`
- **短網址服務**：`/r?url=https://...`
- **廣告追蹤連結**：`/click?target=...`

如果這個參數沒有白名單檢查，攻擊者就可以放任意網址進去：

```
https://yourapp.com/login?return_to=https://evil.com/fake-login
```

使用者點下去後：
1. 看到的網址是 **yourapp.com**（合法），所以信任。
2. 登入完成後，瀏覽器被導到 **evil.com/fake-login**。
3. 攻擊者收集到密碼，或在 referer 中拿到 token。

---

## 三、為什麼這個漏洞「看起來很小」卻很危險？

很多工程師會說：「我只是做個跳轉，又沒洩漏資料，怕什麼？」

但 Open Redirect 通常**不是單獨被利用**，而是**串接**其他攻擊：

### 危害 1：釣魚攻擊（Phishing）

攻擊者寄出包含**你公司網域**的釣魚信，過濾器與使用者都更容易放行。
登入完成後再導到偽造頁面騙再次輸入密碼或 2FA 驗證碼。

### 危害 2：OAuth Token 竊取

OAuth 流程中，`redirect_uri` 如果驗證不嚴，攻擊者可把 token 導到自己的伺服器：

```
https://yourapp.com/oauth/authorize?
  client_id=legit-app
  &redirect_uri=https://evil.com/steal-token
  &response_type=token
```

token 直接落在 evil.com 的 access log 裡。

### 危害 3：繞過 SSRF / CSRF 的同源檢查

某些防禦會檢查「Referer 是不是同網域」。
攻擊者用 Open Redirect 從你網域跳出去，**Referer 還是你的網域**，繞過檢查。

### 危害 4：搭配 XSS 提升危害

如果這個跳轉值不是走後端的 `Location` header，而是被前端拿去做 `window.location = next`、或塞進 `<a href>`、`<meta refresh>`，那麼 `?next=javascript:alert(1)` 這種 `javascript:` 協定就會被瀏覽器執行，瞬間升級成 XSS。（純後端 302 的 `Location: javascript:...` 現代瀏覽器多半會直接忽略，但只要這個值有機會流到前端導頁，就一定要擋掉 `javascript:`。）

---

## 四、危險的後端寫法

### 危險範例 1：Java（Spring Boot）

```java
// ❌ 危險寫法：直接信任 query 參數
@GetMapping("/login/success")
public String loginSuccess(@RequestParam("next") String next,
                           HttpServletResponse response) throws IOException {
    response.sendRedirect(next);  // 任何網址都會跳！
    return null;
}
```

攻擊者只要送出 `/login/success?next=https://evil.com`，就直接跳走了。

### 危險範例 2：Go（net/http）

```go
// ❌ 危險寫法
func loginSuccessHandler(w http.ResponseWriter, r *http.Request) {
    next := r.URL.Query().Get("next")
    http.Redirect(w, r, next, http.StatusFound)  // 信任使用者輸入！
}
```

### 危險範例 3：「我有檢查 http:// 開頭」

```java
// ❌ 看起來有防護，其實沒用
if (next.startsWith("http")) {
    return "/dashboard";  // 拒絕外部網址
}
response.sendRedirect(next);
```

繞過方式：

| 攻擊 payload | 為什麼能繞過 |
|--------------|--------------|
| `//evil.com/path` | 瀏覽器會解讀為 `https://evil.com`（協定相對 URL） |
| `/\evil.com` | 某些瀏覽器把 `\` 當 `/` 處理 |
| `https:evil.com` | 沒有 `//` 也能跳轉 |
| `javascript:alert(1)` | 不是 http 開頭，但會執行 JS |
| `https://yourapp.com.evil.com` | 看起來像子網域，其實是 evil.com 的子網域 |
| `https://yourapp.com@evil.com` | `@` 前是 userinfo，真正主機是 evil.com |

> **重點**：**字串前綴判斷幾乎全部會被繞過**，必須用 URL parser + 白名單。

---

## 五、正確的防禦寫法

### 防禦原則（由嚴格到寬鬆）

1. **最佳**：完全不接受外部 URL，只接受**內部路徑代碼**
2. **次佳**：用 URL parser 解析，比對**白名單網域**
3. **退而求其次**：強制 URL 必須是「**相對路徑**」（以 `/` 開頭，且不能是 `//`）

### 正確範例 1：Java（Spring Boot）—— 白名單法

```java
import java.net.URI;
import java.util.Set;

public class SafeRedirect {

    // 允許的網域（含自己）
    private static final Set<String> ALLOWED_HOSTS = Set.of(
        "yourapp.com",
        "www.yourapp.com",
        "account.yourapp.com"
    );

    public static String sanitize(String next, String defaultPath) {
        if (next == null || next.isBlank()) {
            return defaultPath;
        }

        // 1. 拒絕 javascript: / data: 等危險協定
        String lower = next.toLowerCase().trim();
        if (lower.startsWith("javascript:") || lower.startsWith("data:")
                || lower.startsWith("vbscript:") || lower.startsWith("file:")) {
            return defaultPath;
        }

        // 2. 純相對路徑（不能是 // 或 /\ 開頭，避免 protocol-relative）
        if (next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\")) {
            return next;
        }

        // 3. 解析絕對 URL，比對白名單
        try {
            URI uri = URI.create(next);
            String host = uri.getHost();
            if (host != null && ALLOWED_HOSTS.contains(host.toLowerCase())) {
                return next;
            }
        } catch (IllegalArgumentException e) {
            // URL 格式錯誤，當作不合法
        }

        return defaultPath;
    }
}

@GetMapping("/login/success")
public void loginSuccess(@RequestParam(value = "next", required = false) String next,
                         HttpServletResponse response) throws IOException {
    String safe = SafeRedirect.sanitize(next, "/dashboard");
    response.sendRedirect(safe);
}
```

> **Java 21 提示**：可以改用 `switch` pattern matching 與 `URI.create()` 結合，
> 並用 `record` 包裝「白名單規則」，提升可測試性。

### 正確範例 2：Go —— 白名單法

```go
package security

import (
    "net/http"
    "net/url"
    "strings"
)

var allowedHosts = map[string]bool{
    "yourapp.com":         true,
    "www.yourapp.com":     true,
    "account.yourapp.com": true,
}

// SafeRedirectURL 回傳「可以安全跳轉」的目的地，否則回傳預設值
func SafeRedirectURL(next, defaultPath string) string {
    next = strings.TrimSpace(next)
    if next == "" {
        return defaultPath
    }

    // 1. 拒絕危險協定
    lower := strings.ToLower(next)
    for _, scheme := range []string{"javascript:", "data:", "vbscript:", "file:"} {
        if strings.HasPrefix(lower, scheme) {
            return defaultPath
        }
    }

    // 2. 相對路徑必須以 / 開頭，且不可為 // 或 /\
    if strings.HasPrefix(next, "/") &&
        !strings.HasPrefix(next, "//") &&
        !strings.HasPrefix(next, `/\`) {
        return next
    }

    // 3. 解析後比對白名單
    u, err := url.Parse(next)
    if err != nil || u.Host == "" {
        return defaultPath
    }
    if allowedHosts[strings.ToLower(u.Host)] {
        return next
    }

    return defaultPath
}

func loginSuccessHandler(w http.ResponseWriter, r *http.Request) {
    next := r.URL.Query().Get("next")
    target := SafeRedirectURL(next, "/dashboard")
    http.Redirect(w, r, target, http.StatusFound)
}
```

### 正確範例 3：用「跳轉代碼」徹底避免外部 URL

如果你的場景只有「站內跳轉」，**根本不需要讓使用者傳網址**。
改用一張映射表：

```java
private static final Map<String, String> REDIRECT_MAP = Map.of(
    "dashboard", "/dashboard",
    "orders",    "/orders/list",
    "profile",   "/user/profile"
);

@GetMapping("/login/success")
public void loginSuccess(@RequestParam(value = "to", required = false) String key,
                         HttpServletResponse response) throws IOException {
    String target = REDIRECT_MAP.getOrDefault(key, "/dashboard");
    response.sendRedirect(target);
}
```

URL 變成 `/login/success?to=orders`，攻擊者再怎麼改參數也不可能跳到外站。

---

## 六、OAuth `redirect_uri` 的特別注意事項

OAuth 是 Open Redirect 最危險的場景之一。**規則**：

1. **完全比對（exact match）**，不要用前綴比對
   - ❌ `redirect_uri.startsWith("https://app.com/")` → `https://app.com/.evil.com` 會通過
   - ✅ 直接 `equals` 整個 URL，或在 DB 註冊允許清單
2. **不允許 wildcards**（除非你非常確定 path 結構）
3. **拒絕 fragment（#）**、不允許 query string 控制 host
4. **保留 `state` 參數驗證**，防止 CSRF
5. 若使用 PKCE，務必驗證 `code_verifier`

---

## 七、快速自我檢查清單

在你的後端程式碼中搜尋以下關鍵字，逐一確認都有經過白名單驗證：

- Java：`response.sendRedirect(`、`RedirectView`、`"redirect:" +`
- Go：`http.Redirect(`、`c.Redirect(`（Gin）
- 通用：`Location` header 設定、`window.location` 由後端塞值

問自己 3 個問題：
1. 這個跳轉目的地是**使用者可控**的嗎？
2. 如果是，有沒有**白名單**或**內部代碼映射**？
3. 有沒有處理 `//`、`@`、`javascript:` 這些**繞過手法**？

---

## 八、加分：在前端與框架層加保險

- **CSP（Content Security Policy）**：設 `form-action` 與 `frame-ancestors`，限制表單能 submit 到哪些網域。
- **Spring Security**：使用 `RedirectStrategy` 並結合 `RequestCache`，避免自己手寫跳轉邏輯。
- **Gin / Echo**：把 `SafeRedirectURL` 包成 middleware，所有跳轉統一處理。
- **Log 警示**：當白名單被拒絕時，**記下這次嘗試**——這往往是攻擊偵測的第一個訊號。

---

## 九、今日總結

| 一句話重點 | |
|---|---|
| **核心觀念** | 任何「使用者可控的跳轉目的地」都必須白名單驗證 |
| **危險寫法** | 字串前綴比對（`startsWith("http")`）幾乎都能繞過 |
| **正確做法** | URL parser 解析 + 白名單網域，或改用「跳轉代碼映射」 |
| **常見繞過** | `//evil.com`、`https://app.com@evil.com`、`javascript:` |
| **連動風險** | 釣魚、OAuth token 竊取、繞過 Referer 檢查 |

> **明日預告**：Day 21 將介紹 **Server-Side Template Injection（SSTI）**——當你的後端模板引擎不小心把使用者輸入當成程式碼解析時，會發生什麼可怕的事，以及 Java（Thymeleaf / Freemarker）和 Go（html/template）該怎麼正確使用。

---

### 補充參考

- OWASP：Unvalidated Redirects and Forwards Cheat Sheet
- CWE-601：URL Redirection to Untrusted Site
- RFC 6749 §3.1.2（OAuth `redirect_uri` 規範）
