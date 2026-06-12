---
title: "Day 42 — Cookie 安全屬性完全指南：HttpOnly / Secure / SameSite / __Host-"
date: 2026-06-07
tags: ["Cookie", "Session", "瀏覽器安全"]
---

# Day 42 — Cookie 安全屬性完全指南：HttpOnly / Secure / SameSite / __Host-

> 適合對象：後端工程師（初學～中階）
> 主題：HTTP Cookie 的安全屬性、常見錯誤設定、以及 Java / Go 的正確寫法
> 預估閱讀時間：15 分鐘

---

## 一、為什麼要單獨講 Cookie？

過去幾天我們講過 Session（Day05、Day33）、CSRF（Day03）、JWT（Day05、Day37），這些主題的「載體」其實多半就是 Cookie。

但 Cookie 本身就有一堆安全屬性，後端工程師最常犯的錯誤是：**Set-Cookie 寫一寫就直接上線，沒設 HttpOnly、沒設 Secure、SameSite 不知道要選哪個**。結果一旦其他地方出現 XSS、CSRF、中間人攻擊，整個身份驗證就被吹走。

今天我們把 Cookie 的安全屬性一口氣講完，並用 Java（Servlet / Spring）和 Go 範例示範正確寫法。

---

## 二、一個典型的「不安全」Cookie

我們先看一個常見、但有問題的寫法：

```http
Set-Cookie: SESSIONID=abc123def456
```

這個 Cookie 缺了所有安全屬性。它的問題包括：

1. JavaScript 可以透過 `document.cookie` 讀到它 → 一旦頁面有 XSS，Session 就被偷走。
2. 在 HTTP（非 HTTPS）連線下也會被送出 → 中間人可以攔截。
3. 任何跨站請求都會自動帶這個 Cookie → CSRF 風險。
4. 沒有過期時間（雖然這樣會變成 session cookie，反而是好的，但很多人會搭配 Max-Age 設超長）。

---

## 三、四個必懂屬性

### 1. `HttpOnly` — 擋下 JavaScript 偷 Cookie

設了 `HttpOnly` 之後，**Cookie 完全無法被 `document.cookie` 讀取**，只能由瀏覽器在發 HTTP 請求時自動帶上。

```http
Set-Cookie: SESSIONID=abc123; HttpOnly
```

> 規則：**所有放身份識別資訊的 Cookie，例如 SessionID、JWT，一律要加 HttpOnly。**

唯一的例外：如果你需要前端 JS 讀取的 token（例如 CSRF token 的 double submit 模式），那一個是不能加 HttpOnly 的，但這顆 Cookie 不該放身份識別資訊。

---

### 2. `Secure` — 只在 HTTPS 連線送出

設了 `Secure` 之後，**Cookie 只會在 HTTPS 連線下被送出**，HTTP 連線一律不送。

```http
Set-Cookie: SESSIONID=abc123; HttpOnly; Secure
```

很多人會說：「我們網站本來就強制 HTTPS（HSTS），為什麼還要 Secure？」答案是：**HSTS 是『下次』才生效**。第一次造訪、或 HSTS 過期、或子網域沒包進去時，瀏覽器仍可能走 HTTP，這時候沒 `Secure` 的 Cookie 就會用明文送出。

> 規則：**production 環境一律加 Secure。** 本機開發如果用 `http://localhost` 才需要拿掉。

---

### 3. `SameSite` — 防 CSRF 的第一道防線

`SameSite` 控制「跨站請求時要不要送這個 Cookie」。它有三個值：

| 值 | 行為 | 適用情境 |
|---|---|---|
| `Strict` | 任何跨站請求都不送 | 純內部後台、金流、密碼變更 |
| `Lax` | 跨站「導航式 GET」會送（例如使用者點別人網頁上的連結進來），其他不送 | 一般網站 Session（建議預設）|
| `None` | 任何情況都送（但**必須**搭配 `Secure`） | 第三方嵌入、跨網域 SSO |

```http
Set-Cookie: SESSIONID=abc123; HttpOnly; Secure; SameSite=Lax
```

現代瀏覽器（Chrome、Edge、Firefox）如果你沒指定 SameSite，會預設套用 `Lax`，但**不要依賴預設值**，請明確寫出來。

> 注意：`SameSite=None` 一定要搭配 `Secure`，否則瀏覽器會直接拒絕。

---

### 4. `Domain` 和 `Path` — 控制 Cookie 的「範圍」

```http
Set-Cookie: SESSIONID=abc123; Domain=example.com; Path=/
```

- `Domain=example.com` → 所有 `*.example.com` 的子網域都會送這顆 Cookie。
- 不設 `Domain` → 只有「設定它的那個 host」會送（不含子網域）。

**安全建議：除非真的需要跨子網域共用，否則不要設 `Domain`。**

為什麼？因為一旦你寫了 `Domain=example.com`，連 `evil-subdomain.example.com`（例如被你忘記的舊測試環境、或被 Subdomain Takeover 的子網域，見 Day35）都會收到這顆 Cookie。

---

## 四、進階：`__Host-` 前綴（強烈推薦）

這是一個常被忽略、但威力很大的功能。Cookie 名稱以 `__Host-` 開頭時，瀏覽器會**強制**這顆 Cookie 必須同時符合：

1. 有 `Secure`
2. `Path=/`
3. **沒有** `Domain` 屬性（也就是 host-only）

```http
Set-Cookie: __Host-SESSIONID=abc123; HttpOnly; Secure; SameSite=Lax; Path=/
```

好處：這顆 Cookie **不可能**被子網域寫入或覆蓋。這擋掉了一類叫做 **Cookie Tossing** 的攻擊 — 例如攻擊者控制 `attacker.example.com`，從那邊塞一顆 `SESSIONID` 給主網域。如果你用了 `__Host-` 前綴，瀏覽器會拒絕這種子網域寫入。

> 規則：**新專案的身份 Cookie 強烈建議用 `__Host-` 前綴。**

---

## 五、實作範例

### Java 21 / Spring Boot 3.x

Spring Boot 3 內建的 Session Cookie 設定（`application.yml`）：

```yaml
server:
  servlet:
    session:
      cookie:
        name: __Host-SESSIONID
        http-only: true
        secure: true
        same-site: lax
        path: /
        # 不要設 domain！
```

如果你要自己寫 `Set-Cookie`（例如自訂 token），Servlet API 在 6.0 開始支援 `SameSite`（但 Spring 也提供 `ResponseCookie` 比較方便）：

```java
import org.springframework.http.ResponseCookie;
import org.springframework.http.HttpHeaders;

ResponseCookie cookie = ResponseCookie.from("__Host-AUTH", token)
        .httpOnly(true)
        .secure(true)
        .sameSite("Lax")
        .path("/")
        .maxAge(Duration.ofHours(2))
        // 注意：用 __Host- 就絕對不要 .domain(...)
        .build();

response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
```

### Java 1.8 / 傳統 Servlet

Java 8 的 `javax.servlet.http.Cookie` **沒有原生 SameSite 支援**，必須手動拼字串：

```java
String cookieValue = String.format(
    "__Host-SESSIONID=%s; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=7200",
    sessionId
);
response.addHeader("Set-Cookie", cookieValue);
```

> ⚠️ 寫進去前一定要驗證 `sessionId` 不含 `\r\n`，避免 CRLF Injection（見 Day34）。實務上 SessionID 應該用 `SecureRandom` 產生 base64/hex，本來就不會有控制字元，但別把使用者輸入塞進 Cookie value。

### Go 1.22+

Go 的 `net/http` 從 1.11 開始就支援 `SameSite`：

```go
import (
    "net/http"
    "time"
)

func setSessionCookie(w http.ResponseWriter, sessionID string) {
    cookie := &http.Cookie{
        Name:     "__Host-SESSIONID",
        Value:    sessionID,
        Path:     "/",
        // Domain 留空 → host-only（符合 __Host- 要求）
        MaxAge:   7200,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    }
    http.SetCookie(w, cookie)
}
```

### 清除 Cookie（登出）的正確姿勢

清 Cookie 要把**所有屬性**寫成一模一樣，只是把 `Max-Age` 設成 0（或 `Expires` 設成過去）：

```go
func clearSessionCookie(w http.ResponseWriter) {
    cookie := &http.Cookie{
        Name:     "__Host-SESSIONID",
        Value:    "",
        Path:     "/",
        MaxAge:   -1,           // 立刻過期
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    }
    http.SetCookie(w, cookie)
}
```

常見的錯誤是：設 Cookie 時用了 `Path=/api`，清 Cookie 時忘了寫 Path，導致瀏覽器其實沒清掉那顆 Cookie。

---

## 六、快速檢查表（上線前 30 秒檢查）

對著你網站的身份 Cookie，問自己這六個問題：

1. 有 `HttpOnly` 嗎？ → 沒有就是錯。
2. 有 `Secure` 嗎？（production）→ 沒有就是錯。
3. `SameSite` 寫明了嗎？預設應該是 `Lax`，第三方嵌入才用 `None`。
4. 有不必要的 `Domain` 嗎？沒理由就拿掉。
5. 名字有 `__Host-` 前綴嗎？新專案應該有。
6. 登出 endpoint 有真的把 Cookie 清掉嗎？

用 Chrome DevTools → Application → Cookies 看一眼就知道有沒有設好。

---

## 七、常見迷思

**迷思 1：「我用 JWT 不放 Cookie，所以這些都不關我的事。」**

如果你把 JWT 放 `localStorage`，那 XSS 一發生就直接被偷走（連 HttpOnly 都救不了）。比較安全的做法仍然是把 JWT 放在 HttpOnly + Secure + SameSite Cookie 裡。

**迷思 2：「SameSite=Strict 最安全，全用 Strict 就好。」**

Strict 的副作用是：從外部連結（例如別人在 Slack 貼你的網址）點進你的網站，瀏覽器**不會帶 Cookie**，使用者會看到未登入狀態，體驗很差。多數網站用 `Lax` 就夠了。

**迷思 3：「我加了 Secure 但本機開發跑不起來。」**

本機開發如果用 `http://localhost`，Secure 的 Cookie 不會送。解法：用 `mkcert` 弄一張本機憑證跑 HTTPS，或在 dev profile 把 Secure 關掉（但別把 dev 設定帶上 production）。

---

## 八、今天的功課

1. 打開你目前負責的服務，用 DevTools 看身份 Cookie，對照上面的檢查表。
2. 如果你用 Spring Boot 或 Go 標準 `net/http`，把 SessionID 改名加上 `__Host-` 前綴試試看（會強迫你拿掉 Domain、加上 Secure 跟 Path=/）。
3. 寫一個整合測試：發 `/login`，斷言回應的 `Set-Cookie` header 同時包含 `HttpOnly`、`Secure`、`SameSite=Lax`。**Cookie 安全屬性掉了就是會被忘記，用測試固化它。**

---

## 九、明日預告

Day 43 我們會講 **Prototype Pollution / Object Injection** — 雖然名字常出現在 Node.js 場景，但 Java 跟 Go 在處理 JSON 反序列化、合併物件時也有類似的攻擊面，特別是用 Jackson 的 `ObjectMapper` 或 Go 的 `mergo` 套件時。

---

> 📌 **核心一句話**：把身份 Cookie 寫成 `__Host-XXX; HttpOnly; Secure; SameSite=Lax; Path=/`，然後寫測試把它固定住。
