---
title: "Day 36 — Clickjacking / UI Redressing（點擊劫持）"
date: 2026-06-01
tags: ["Clickjacking", "前端安全", "HTTP Header"]
---

# Day 36 — Clickjacking / UI Redressing（點擊劫持）

> 後端工程師資安教學 · Day 36
> 適合對象：剛接觸 Web 後端、Java（1.8 / 21）與 Go 開發者

---

## 一、先講一個生活化的比喻

想像有人在路邊放了一台扭蛋機，上面寫「投 10 元抽免費飲料券」。你投了硬幣、按了按鈕，扭蛋掉出來——但你不知道的是：**那台機器其實是用透明壓克力套在另一台 ATM 上**。你以為自己按的是「抽飲料」，實際按到的是 ATM 的「提款 10000 元」。

這就是 **Clickjacking**（也叫 **UI Redressing**）：
攻擊者用一個**透明的 iframe** 把你的真實網站疊在他自己的誘餌頁面底下，使用者以為自己在點「免費抽獎」，實際上點到的是你網站的「轉帳」「同意授權」「刪除帳號」按鈕。

關鍵字：**不是偷你的密碼，是借你的手點按鈕**。

---

## 二、技術上到底發生了什麼？

最簡化的攻擊頁面：

```html
<!-- 攻擊者的頁面 evil.com -->
<style>
  iframe {
    position: absolute;
    top: 0; left: 0;
    width: 100%; height: 100%;
    opacity: 0.0001;          /* 完全透明，但仍可接收點擊 */
    z-index: 9999;            /* 蓋在所有東西上面 */
  }
  .bait {
    position: absolute;
    top: 300px; left: 200px;  /* 對齊到真實網站的按鈕位置 */
  }
</style>

<button class="bait">點我抽 iPhone</button>
<iframe src="https://bank.example.com/transfer?to=ATTACKER&amount=99999"></iframe>
```

使用者邏輯流程：

1. 使用者已經登入 `bank.example.com`（瀏覽器有 Cookie）。
2. 使用者打開 `evil.com`，看到「點我抽 iPhone」按鈕。
3. 真正接收點擊的是上層**透明** iframe 裡的「確認轉帳」按鈕。
4. 因為瀏覽器自動帶 Cookie，後端認得這是合法已登入使用者的請求。
5. 轉帳完成，使用者完全不知情。

**核心三條件**：
- 受害網站允許被 iframe 嵌入（後端沒擋）。
- 受害網站的敏感動作只靠「按下按鈕」就完成，沒有二次確認。
- 瀏覽器會自動帶 Cookie（這部分要看 `SameSite`，後面講）。

---

## 三、Clickjacking 的常見變體

不是所有 Clickjacking 都長得一樣，後端工程師至少要認得這幾種：

### 1. Classic Clickjacking
就是上面範例，透明 iframe 蓋在誘餌按鈕上。

### 2. Likejacking / Sharejacking
誘導你點到「Facebook 按讚」「轉推」按鈕。社群網站常見。

### 3. Cursorjacking
用 CSS 自訂游標，讓使用者**看到的游標位置**和**真實游標位置**錯位，按鈕在 A 點但你以為要點 B 點。

### 4. Filejacking
用透明的 `<input type="file">` 蓋在誘餌按鈕上，使用者「點抽獎」變成「選擇要上傳的檔案」。

### 5. **Double Clickjacking**（2024 年後較新的攻擊向量）
利用快速雙擊：第一次點擊讓攻擊者的視窗關閉/換頁，第二次點擊正好落在 OAuth 授權的「Allow」按鈕。**X-Frame-Options 擋不住這種**，因為它不是用 iframe 嵌入，而是利用瀏覽器視窗切換的時序。

> 注意：**這篇主要講「能被 iframe 嵌入」這個面向**，Double Clickjacking 需要額外用 `Cross-Origin-Opener-Policy: same-origin` + 操作前確認對焦來緩解。

---

## 四、為什麼這是「後端工程師的問題」？

很多人以為「畫面是前端的事」。錯了。**X-Frame-Options 和 CSP `frame-ancestors` 都是 HTTP Response Header**——是後端決定要不要送、送什麼值的。前端 HTML 裡塞 `<meta>` 是**無效的**，瀏覽器不會認。

```html
<!-- ❌ 沒用！X-Frame-Options 不接受 meta 形式 -->
<meta http-equiv="X-Frame-Options" content="DENY">
```

所以這題的責任在後端 / Gateway / Reverse Proxy。

---

## 五、防禦：三層次

### 第一層：HTTP Header（最重要、最該做）

兩個選擇，**建議兩個都送**（CSP 是新標準，但舊瀏覽器只認 X-Frame-Options）：

#### (A) `X-Frame-Options`
```
X-Frame-Options: DENY              # 完全禁止被 iframe 嵌入（最嚴格）
X-Frame-Options: SAMEORIGIN        # 只允許同網域嵌入
```

注意：**`X-Frame-Options: ALLOW-FROM` 已被廢棄**，現代瀏覽器不支援。要做白名單請用 CSP。

#### (B) `Content-Security-Policy: frame-ancestors`
```
Content-Security-Policy: frame-ancestors 'none';                          # 等同 DENY
Content-Security-Policy: frame-ancestors 'self';                          # 等同 SAMEORIGIN
Content-Security-Policy: frame-ancestors 'self' https://partner.com;      # 白名單
```

**兩者衝突時，CSP `frame-ancestors` 優先**。

### 第二層：Cookie 的 `SameSite`

```
Set-Cookie: SESSIONID=...; SameSite=Lax; Secure; HttpOnly
```

`SameSite=Lax`（多數瀏覽器的預設值）會讓第三方網站發起的 POST 請求**不帶 Cookie**，這能擋掉大部分跨站 Clickjacking。但對 GET 觸發的敏感動作（例如錯誤設計的 `/delete?id=...`）仍有限。

延伸閱讀：Day 3（CSRF）、Day 33（Session Fixation）。

### 第三層：敏感動作的「二次確認」

即使前兩層失效，敏感操作（轉帳、刪除、授權）應該：
- 要求重新輸入密碼或 2FA（呼應 Day 27 MFA / TOTP）。
- 顯示驗證碼 / CAPTCHA。
- 動作前要求滑鼠在頁面內停留一定時間、或要求拖曳手勢（讓 invisible iframe 對齊變難）。

這層是「**深度防禦**」概念——當前兩層因設定錯誤失靈時，還有最後一道。

---

## 六、後端程式碼範例

### Go：用中介層統一加上 Header

```go
// pkg/middleware/clickjacking.go
package middleware

import "net/http"

// ClickjackingProtection 一律送 DENY；若有需要被嵌入的特定頁面，再個別覆寫。
func ClickjackingProtection(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // CSP（新標準，現代瀏覽器優先採用）
        w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
        // X-Frame-Options（向後相容，給較舊瀏覽器）
        w.Header().Set("X-Frame-Options", "DENY")
        next.ServeHTTP(w, r)
    })
}
```

使用：

```go
mux := http.NewServeMux()
mux.HandleFunc("/api/transfer", transferHandler)

handler := middleware.ClickjackingProtection(mux)
http.ListenAndServe(":8080", handler)
```

如果某個頁面**需要**被合作夥伴嵌入（例如 SSO 授權頁），就針對該路由用較寬的設定：

```go
func partnerEmbeddableHandler(w http.ResponseWriter, r *http.Request) {
    // 覆寫成白名單
    w.Header().Set("Content-Security-Policy",
        "frame-ancestors 'self' https://partner.example.com")
    w.Header().Del("X-Frame-Options") // 移除衝突的舊 header
    // ...render page
}
```

### Java 1.8（Spring Boot 2.x，傳統設定）

```java
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .headers()
                .frameOptions().deny() // X-Frame-Options: DENY
                .contentSecurityPolicy("frame-ancestors 'none'"); // CSP

        // ...其他設定
    }
}
```

### Java 21（Spring Boot 3.x，Lambda DSL）

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.XFrameOptionsHeaderWriter.XFrameOptionsMode;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.headers(headers -> headers
            .frameOptions(frame -> frame.mode(XFrameOptionsMode.DENY))
            .contentSecurityPolicy(csp -> csp.policyDirectives(
                "frame-ancestors 'none'"))
        );
        return http.build();
    }
}
```

> Spring Security 預設就會送 `X-Frame-Options: DENY`，你**不關掉就是安全的**。常見的錯誤是有人為了「H2 Console 看得到」就 `frameOptions().disable()`——結果整個專案都裸奔。要關只關該路由：
> ```java
> .headers(h -> h.frameOptions(f -> f
>     .mode(XFrameOptionsMode.SAMEORIGIN))) // 或對 /h2-console 局部 permit
> ```

### Nginx / Reverse Proxy 層也加一道

很多大型專案會在 LB / Gateway 統一設定，減少各 App 漏設的風險：

```nginx
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'none'" always;
```

`always` 是關鍵字，沒加的話 Nginx 在錯誤頁面（4xx/5xx）不會送這個 header。

---

## 七、怎麼檢測自家有沒有風險？

### 1. 手動測試
寫一個最小 HTML 試嵌入：

```html
<!-- test-clickjacking.html -->
<!DOCTYPE html>
<html>
<body>
  <h1>如果下方能看到內容，就代表有風險</h1>
  <iframe src="https://your-site.example.com/sensitive-page"
          width="800" height="600"></iframe>
</body>
</html>
```

開啟這個檔案，看 iframe 內容會不會被擋。如果跳出空白 / 「拒絕連線」/ Console 顯示「Refused to display ... in a frame because it set 'X-Frame-Options' to 'deny'」，那就 OK。

### 2. 用 curl 看 Response Header

```bash
curl -sI https://your-site.example.com/login \
  | grep -iE 'x-frame-options|content-security-policy'
```

### 3. 自動化掃描腳本（Go）

```go
// cmd/clickjacking-check/main.go
package main

import (
    "bufio"
    "fmt"
    "net/http"
    "os"
    "strings"
    "time"
)

func check(url string) {
    client := &http.Client{Timeout: 5 * time.Second}
    resp, err := client.Get(url)
    if err != nil {
        fmt.Printf("ERROR %s: %v\n", url, err)
        return
    }
    defer resp.Body.Close()

    xfo := resp.Header.Get("X-Frame-Options")
    csp := resp.Header.Get("Content-Security-Policy")
    hasFA := strings.Contains(strings.ToLower(csp), "frame-ancestors")

    if xfo == "" && !hasFA {
        fmt.Printf("[!] VULNERABLE %s (no X-Frame-Options, no frame-ancestors)\n", url)
    } else {
        fmt.Printf("[ok] %s  XFO=%q  FA-in-CSP=%v\n", url, xfo, hasFA)
    }
}

func main() {
    sc := bufio.NewScanner(os.Stdin)
    for sc.Scan() {
        u := strings.TrimSpace(sc.Text())
        if u != "" {
            check(u)
        }
    }
}
```

把全公司對外的 URL 清單灌進去跑一輪，就能知道哪些頁面沒設防。可以接到 Day 17（Rate Limiting / 排程）、Day 16（Logging）的監控管線。

---

## 八、自我檢查清單

1. 你的 Web App 是不是預設**所有路由**都會送 `X-Frame-Options` 或 `frame-ancestors`？
2. 如果有「需要被嵌入」的頁面，是否用**白名單**精確列舉，不用 `*` 或 `https:`？
3. 開發環境的 H2 Console / Swagger UI / Admin 面板有沒有被排除掉防護？這些反而最高風險。
4. 敏感動作（轉帳、刪除帳號、OAuth 授權同意）有沒有「再輸入密碼 / 2FA」這層？
5. Cookie 的 `SameSite` 有設嗎？是 `Lax` 還是 `Strict`？理由是什麼？
6. 你能不能用一條 curl 指令，向團隊任何成員證明「我們 production 有設這個 header」？

---

## 九、今日重點回顧（30 秒版）

- **問題本質**：攻擊者用透明 iframe 把你的網站疊在誘餌頁面下，使用者按到誘餌就等於按到你的敏感按鈕。
- **影響**：使用者不知情下完成轉帳、授權、刪除等動作。**不偷密碼，借手點按鈕**。
- **防禦三層**：
  1. **HTTP Header**：`X-Frame-Options: DENY` + `Content-Security-Policy: frame-ancestors 'none'`（後端責任，不是前端 meta）。
  2. **Cookie**：`SameSite=Lax / Strict`，擋第三方帶 Cookie。
  3. **敏感動作二次確認**：密碼 / 2FA / CAPTCHA。
- **責任歸屬**：**後端工程師必須送出正確 Response Header**，這不是前端的事。
- **記憶口訣**：**「能不能被嵌，是後端決定的。」**

---

## 十、延伸題（給自己練習）

1. 開一個 Spring Boot 3 / Gin 專案，故意把 `X-Frame-Options` 拿掉，再寫一個本機 HTML iframe 嵌入它，重現攻擊。然後加回 header，看 Console 噴的訊息。
2. 想想：如果 production 的反向代理（Nginx / Cloudflare）已經有設 `X-Frame-Options`，後端還要送嗎？兩邊衝突時誰贏？答案是「以瀏覽器看到的最後一份為準，且**多送幾乎不會壞事**，但要避免兩邊送**矛盾值**」。實驗看看。
3. 研究 **Double Clickjacking** 攻擊向量，找出為什麼 `X-Frame-Options` 擋不住，以及 `Cross-Origin-Opener-Policy: same-origin` 為何能緩解。

明天見，Day 37 預告：**JWT Algorithm Confusion（JWT 演算法混淆攻擊）**——header 裡的 `alg` 其實是「攻擊者可控的輸入」，但很多函式庫卻拿它當「驗章方式的開關」。從 `alg:none`、RS256↔HS256 混淆到 `kid` 注入，看後端怎麼一個沒注意就把整個身分驗證打穿。
