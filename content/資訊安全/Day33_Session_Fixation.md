---
title: "Day 33：Session Fixation（會話固定攻擊）—— 為什麼登入後一定要換一張新的 Session ID"
date: 2026-05-29
tags: ["Session", "認證"]
---

# Day 33：Session Fixation（會話固定攻擊）—— 為什麼登入後一定要換一張新的 Session ID

> 後端工程師資安系列 — Day 33
> 日期：2026-05-29

> 「使用者登入前用的是 Session A，登入後還是 Session A，
> 那這張 Session A 是誰先發給他的？如果是攻擊者塞給他的呢？」

---

## 一、前情提要

第 5 天我們聊過 JWT vs Session 的差異，第 6 天聊 Brute Force 防禦，第 27、28 天聊 MFA / Passkey。這些都是「**登入流程**」的安全性。今天要補上一個經常被忽略、但 OWASP Top 10「**A07: Identification and Authentication Failures**」明確列出的漏洞：

**Session Fixation（會話固定攻擊）**。

它的特徵是：
- 不用偷 Cookie，不用釣魚，不用拿到密碼。
- 攻擊者**自己先去拿一張合法的 Session ID**，然後想辦法讓受害者「**用這張 Session ID** 去登入」。
- 受害者一旦登入成功，這張 Session ID 就同時掛在受害者帳號上——而攻擊者一直握著同一張，立刻就是「合法登入的 Session」。

這個漏洞在「Session-based」的後端系統最常出現。如果你還在用 `JSESSIONID`、`PHPSESSID`、`connect.sid`、或自己塞進 Cookie 的 `session_id`，今天的內容請務必看完。

---

## 二、攻擊原理

### 一張圖看懂

```
攻擊者                                    伺服器                              受害者
  |                                          |                                  |
  | 1. GET /login                            |                                  |
  | -----------------------------------> 發 Session ID = ABC123                 |
  | <-- Set-Cookie: JSESSIONID=ABC123        |                                  |
  |                                          |                                  |
  | 2. 把 ABC123 想辦法塞給受害者                                                |
  |     (URL 參數、子網域 Cookie、XSS、釣魚連結都可以)                            |
  |                                          |                                  |
  |                                          |   3. 受害者帶著 ABC123 來登入       |
  |                                          | <------------------------------- |
  |                                          |       帳號 + 密碼 + JSESSIONID=ABC123|
  |                                          |                                  |
  |                                          | 4. 後端把 ABC123 標記為「已登入 = 受害者」
  |                                          |                                  |
  | 5. 攻擊者直接帶 ABC123 存取               |                                  |
  | -----------------------------------> 「你好，受害者！」                       |
```

### 攻擊成立的兩個條件

1. **後端發 Session ID 的時機點太早**：使用者還沒登入就先發一張。
2. **登入成功後沒有換新的 Session ID**：用原本那張繼續走。

只要這兩件事都成立——不管你 HTTPS 開得多漂亮、密碼 hash 用 Argon2id、MFA 開好開滿——攻擊者依舊可以把自己變成受害者。

### 那攻擊者怎麼把 Session ID 塞給受害者？

這正是 Session Fixation 容易被低估的地方——它的「Payload 投放」方式非常多元：

| 投放方式 | 範例 |
| --- | --- |
| URL 參數（最老派也最致命） | `https://bank.com/login;jsessionid=ABC123` |
| 子網域 / 同網域 Cookie 注入 | 從 `evil.bank.com` 設一個 `Domain=.bank.com` 的 cookie |
| XSS（即使只能寫 cookie 也夠） | `document.cookie="JSESSIONID=ABC123"` |
| HTTP 環境下用中間人塞 cookie | 連 HTTPS 都沒上，Wi-Fi 就能改 |
| Set-Cookie HTTP Header Injection | 上游有 CRLF Injection 漏洞時可注入 |

URL Rewriting 那一招特別惡毒，因為很多 Java 應用伺服器（早期 Tomcat、Jetty）**預設啟用 URL Rewriting**，會在 client 沒帶 cookie 時自動把 `;jsessionid=XXX` 拼到 URL 上。這就是 OWASP 一直要求「**Disable URL Rewriting**」的原因。

---

## 三、為什麼這比 Session Hijacking 更陰險

很多人會把 Session Fixation 跟 Session Hijacking 搞混，差別在哪？

| 攻擊類型 | 攻擊者怎麼拿到 Session ID |
| --- | --- |
| Session Hijacking（劫持） | 偷的（XSS 偷 cookie、抓封包、實體裝置） |
| **Session Fixation（固定）** | **自己產生的，再灌給受害者用** |

差別超級重要：

- Hijacking 必須**先有一張已登入的 Session** 才能偷。
- Fixation **不需要**——攻擊者只要拿一張匿名的、登入前的 Session，等受害者去登入「自動升級」。

所以你會看到：很多看似「我只有未登入頁面，沒在意 cookie」的網站，其實已經被 fixation 打穿了。

---

## 四、後端常見的錯誤實作

### 錯誤 1：Java Servlet — 沒有 `changeSessionId()`

```java
// ❌ 危險寫法
@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {
        String username = req.getParameter("username");
        String password = req.getParameter("password");

        User user = userService.authenticate(username, password);
        if (user == null) {
            resp.sendError(401);
            return;
        }

        // 直接把登入狀態寫進「原本那張」Session
        HttpSession session = req.getSession();      // ← 如果使用者一進來就有 session，這裡會「沿用」舊的
        session.setAttribute("user", user);          // ← 攻擊者塞的 SessionID 現在 = 受害者已登入
        resp.sendRedirect("/dashboard");
    }
}
```

上面這段是教科書級的反面教材：登入前後**Session ID 完全相同**。

### 錯誤 2：Go — 沿用 Cookie 沒換值

```go
// ❌ 危險寫法（用 gorilla/sessions）
func loginHandler(w http.ResponseWriter, r *http.Request) {
    sess, _ := store.Get(r, "sid")  // ← 如果 client 帶舊的 sid，就會還原那張

    username := r.FormValue("username")
    password := r.FormValue("password")
    user, err := authService.Authenticate(username, password)
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    sess.Values["userID"] = user.ID  // ← 用原本那張 session 存登入狀態
    sess.Save(r, w)
    http.Redirect(w, r, "/dashboard", http.StatusFound)
}
```

問題與 Java 版本一致：**從來沒換 Session ID**。

### 錯誤 3：URL Rewriting 還開著

```xml
<!-- ❌ web.xml 沒設定，Servlet 容器預設 TRACKING_MODE 可能包含 URL -->
<session-config>
    <tracking-mode>COOKIE</tracking-mode>
    <tracking-mode>URL</tracking-mode>   <!-- ← 開啟 URL Rewriting，攻擊者最愛 -->
</session-config>
```

只要這個開著，攻擊者把 `https://your-site.com/login;jsessionid=ATTACKER_CHOSEN_ID` 發給受害者就行。

---

## 五、正確的防禦方式（給後端工程師的肌肉記憶）

核心原則只有一句：

> **「使用者每跨越一個權限邊界，就換一張 Session ID。」**
>
> 至少 ——「**登入成功的那一刻**」必須換。
> 進階 ——「**權限變動（changeRole / 切換組織）**」也應該換。
> 更進階 ——「**MFA 通過**」、「**Step-up 高敏感操作前**」也應該換。

### Java 1.8 / 21 — Servlet API

從 **Servlet 3.1（Java EE 7）開始**有 `HttpServletRequest.changeSessionId()`，它會：
- 保留 session 的內容（attributes）
- 重新產生一張新的 session ID
- 把舊的廢掉

```java
// ✅ Java 8 / 21 通用寫法（Servlet 3.1+）
@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");

        User user = userService.authenticate(username, password);
        if (user == null) {
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        // 1) 如果有舊 session，先把它的 ID 換掉（推薦）
        HttpSession oldSession = req.getSession(false);
        if (oldSession != null) {
            // 最保險：先 invalidate，再開一張全新的
            oldSession.invalidate();
        }

        // 2) 開一張新的，再寫登入狀態
        HttpSession newSession = req.getSession(true);
        newSession.setAttribute("user", user);

        // 3) （可選）控制 cookie 安全屬性
        // 注意：Servlet 4.0+ 才能用 SameSite，舊版本要靠容器設定或 filter
        Cookie c = new Cookie("JSESSIONID", newSession.getId());
        c.setHttpOnly(true);
        c.setSecure(true);   // 只在 HTTPS 上送
        c.setPath("/");
        // 部分容器設定 SameSite：
        // resp.setHeader("Set-Cookie",
        //   String.format("JSESSIONID=%s; Path=/; HttpOnly; Secure; SameSite=Lax", newSession.getId()));
        resp.addCookie(c);

        resp.sendRedirect("/dashboard");
    }
}
```

> 為什麼推薦 `invalidate() + getSession(true)` 而不是 `changeSessionId()`？
> `changeSessionId()` 會**保留舊 session 的所有 attribute**。如果舊 session 是攻擊者放進來的、含有惡意的 attribute（例如 `flashMessages`、`csrfToken`、`returnUrl`），那些東西也會被帶過來。
> 用 invalidate 等於「砍掉重練」，最乾淨。
> 如果你**確定 attribute 都是自家程式寫的**（例如只在登入流程內），用 `changeSessionId()` 即可。

### Java — Spring Security 怎麼設

Spring Security 預設就會處理 Session Fixation，**但你要知道它有四個選項**：

```java
// ✅ Spring Security 6（Java 17 / 21 常見搭配）
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults())
            .sessionManagement(session -> session
                // 預設值是 changeSessionId（Servlet 3.1+）
                // 最保險的是 newSession（等同前面的 invalidate + new）
                .sessionFixation(fix -> fix.newSession())
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
            );
        return http.build();
    }
}
```

Spring Security 的 `sessionFixation()` 四個選項：

| 選項 | 行為 | 何時用 |
| --- | --- | --- |
| `migrateSession()` | 換 ID，保留所有 attribute | 預設行為（Spring Security 5 以前的預設） |
| `changeSessionId()` | 用 Servlet 3.1 的 API 換 ID，保留 attribute | Spring Security 6 預設 |
| `newSession()` | 完全新開一張，不保留 attribute | **最安全，推薦** |
| `none()` | **什麼都不做** | **千萬不要用** |

### Go — net/http + 自製 Session Store

Go 沒有像 Servlet 那樣現成的 `changeSessionId()`，要自己換：

```go
// ✅ Go 範例：登入成功後重新發 Session ID
package main

import (
    "crypto/rand"
    "encoding/base64"
    "net/http"
    "time"
)

func generateSessionID() string {
    b := make([]byte, 32)               // 256-bit entropy
    if _, err := rand.Read(b); err != nil {
        panic(err)                       // 在 production 改成 log + 5xx
    }
    return base64.RawURLEncoding.EncodeToString(b)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")
    user, err := authService.Authenticate(r.Context(), username, password)
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    // 1) 如果有舊 cookie，先把舊 session 從 store 砍掉
    if oldCookie, err := r.Cookie("sid"); err == nil {
        sessionStore.Delete(r.Context(), oldCookie.Value)
    }

    // 2) 產生新的 session ID（重點！）
    newSID := generateSessionID()
    sessionStore.Put(r.Context(), newSID, Session{
        UserID:    user.ID,
        CreatedAt: time.Now(),
    })

    // 3) 用安全屬性寫回 cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "sid",
        Value:    newSID,
        Path:     "/",
        HttpOnly: true,
        Secure:   true,                  // 只在 HTTPS 送
        SameSite: http.SameSiteLaxMode,  // 推薦至少 Lax，敏感系統用 Strict
        MaxAge:   3600,                  // 一小時，依需求調整
    })

    http.Redirect(w, r, "/dashboard", http.StatusFound)
}
```

要點：
- **`generateSessionID` 必須用 `crypto/rand`**，不能用 `math/rand`，否則 Session ID 可預測（Day 19 提過 CSPRNG 的重要性）。
- **舊的 session 一定要從 store 刪掉**，避免攻擊者繼續拿著用。

### Go — gorilla/sessions 怎麼做

`gorilla/sessions` 沒有「直接換 ID」的 API，正確做法是：

```go
// ✅ gorilla/sessions
import "github.com/gorilla/sessions"

var store = sessions.NewCookieStore([]byte(secretKey))

func loginHandler(w http.ResponseWriter, r *http.Request) {
    // 取出舊 session
    oldSess, _ := store.Get(r, "sid")

    user, err := authService.Authenticate(r.Context(),
        r.FormValue("username"), r.FormValue("password"))
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    // 1) 把舊 session 標記為刪除（MaxAge < 0 等同 Set-Cookie 立刻過期）
    oldSess.Options.MaxAge = -1
    if err := oldSess.Save(r, w); err != nil {
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }

    // 2) 因為 gorilla/sessions 用「name」對應 cookie，
    //    需要 New 一張全新的 session（記得不要再用 Get！）
    newSess, _ := store.New(r, "sid")
    newSess.Values["userID"] = user.ID
    newSess.Options = &sessions.Options{
        Path:     "/",
        MaxAge:   3600,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    }
    if err := newSess.Save(r, w); err != nil {
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }

    http.Redirect(w, r, "/dashboard", http.StatusFound)
}
```

提醒：`store.New(r, "sid")` 會明確產生一張新的（不會被 r 上的舊 cookie 還原），這就是 gorilla 推薦的「登入後換 session」做法。

---

## 六、加分題：除了換 Session ID，後端還要做什麼？

換 ID 是「**必要條件**」，不是「**充分條件**」。完整的 Session 安全還需要：

1. **Cookie 三件套（必設）**
   - `HttpOnly`：擋 XSS 偷 cookie。
   - `Secure`：只在 HTTPS 上傳。
   - `SameSite=Lax` 或 `Strict`：擋 CSRF（搭配 Day 3 的 CSRF Token 更穩）。

2. **Session ID 必須是 CSPRNG 產生的高熵字串**
   - Java：`SecureRandom`、Spring Security 預設沒問題。
   - Go：`crypto/rand`。
   - **千萬不要**用 `username + timestamp + md5` 自製 session ID。

3. **Session 有 Idle Timeout 與 Absolute Timeout**
   - Idle：閒置 N 分鐘自動失效（避免咖啡廳沒登出）。
   - Absolute：發出後最久 N 小時就必須重新登入（限制爆炸半徑）。

4. **登出時要 server-side invalidate**
   - 不能只在 client 把 cookie 刪掉，server 那張要從 store 砍掉。否則攻擊者只要留著舊值就能繼續用（這也是常見漏洞）。

5. **關閉 URL Rewriting（Servlet 容器特別重要）**
   ```xml
   <!-- ✅ web.xml -->
   <session-config>
       <tracking-mode>COOKIE</tracking-mode>
   </session-config>
   ```

6. **權限升降都換新 ID**
   - 登入、登出、改密碼、開啟 MFA、Step-up 驗證——都建議重新發 Session ID。

7. **限制 Cookie 的 Domain 範圍**
   - 不要設成 `Domain=.example.com` 後讓 `evil-tenant.example.com` 也能塞 cookie。
   - 多租戶系統尤其要小心子網域 cookie 互相污染。

---

## 七、怎麼自己測？

### 黑盒測試法（不用工具）

1. 用瀏覽器無痕模式開你的網站 → 看登入前 cookie：`JSESSIONID=AAA`。
2. 登入後再看 cookie。
3. **如果還是 `JSESSIONID=AAA`，就是漏洞**。

### Spring Security 自動化測試

```java
@SpringBootTest
@AutoConfigureMockMvc
class SessionFixationTest {

    @Autowired MockMvc mvc;

    @Test
    void session_id_should_change_after_login() throws Exception {
        // 登入前先拿一張 session
        MvcResult preLogin = mvc.perform(get("/"))
                                .andReturn();
        String sidBefore = preLogin.getResponse().getCookie("JSESSIONID").getValue();

        // 帶著這張 session 去登入
        MvcResult postLogin = mvc.perform(post("/login")
                .param("username", "alice")
                .param("password", "p@ssw0rd")
                .cookie(new jakarta.servlet.http.Cookie("JSESSIONID", sidBefore)))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String sidAfter = postLogin.getResponse().getCookie("JSESSIONID").getValue();

        // 登入前後 session ID 必須不同
        assertThat(sidAfter).isNotEqualTo(sidBefore);
    }
}
```

把這個測試丟到 CI 跑——以後就不怕學弟妹改 code 改掉了。

---

## 八、後端工程師檢查清單

### Java（1.8 / 21）

- [ ] 登入成功後呼叫 `req.getSession(false).invalidate()` 再 `req.getSession(true)`，或至少 `req.changeSessionId()`。
- [ ] Spring Security 設定 `sessionFixation().newSession()`（最保險）。
- [ ] `web.xml` 設定 `<tracking-mode>COOKIE</tracking-mode>`，**移除 URL**。
- [ ] Cookie 屬性：`HttpOnly`、`Secure`、`SameSite=Lax` 以上。
- [ ] 撰寫單元測試驗證「登入前後 SessionID 必須不同」。
- [ ] 改密碼 / 開啟 MFA / Step-up 也要換新 ID。

### Go

- [ ] 用 `crypto/rand` 產生 256-bit 以上的 session ID。
- [ ] 登入成功後：刪掉舊 session、發新 ID、Set-Cookie。
- [ ] Cookie 屬性：`HttpOnly: true`、`Secure: true`、`SameSite: SameSiteLaxMode`。
- [ ] 登出時 server-side 從 store 砍掉，不要只刪 cookie。
- [ ] 不在 URL / Query String / Referer 傳 session ID。
- [ ] gorilla/sessions：用 `store.New(r, name)` 開新的，不要重用 `Get` 回來的舊 session。

---

## 九、一句話總結

> **「凡是讓使用者的權限改變的時刻——尤其是登入——就把舊的 Session ID 砍掉，發一張全新的。」**

明天我們會聊 **CRLF Injection / HTTP Header Injection（換行字元注入）**——當使用者輸入被原樣塞進 HTTP 回應的 header（例如 `Location`、`Set-Cookie`），一個換行字元 `\r\n` 就能讓攻擊者注入自己的 header、甚至偽造整個回應內容。今天 Session Fixation 提到的「上游有 CRLF 漏洞時可注入 Set-Cookie」正是它的延伸。

> 如果這份內容對你有幫助，歡迎把它當成 Code Review checklist 的一頁；也歡迎在自家專案搜尋 `getSession`、`store.Get`、`SetCookie`，把今天提到的反例一次補好。
