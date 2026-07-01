---
title: "Day 68：Open Redirect × CRLF（延伸篇，承 Day67）— 跳轉值過了白名單，卻在 Location 標頭裡分裂回應"
date: 2026-07-01
tags: ["Open Redirect", "CRLF", "HTTP Header Injection", "Response Splitting"]
---

# Day 68：Open Redirect × CRLF（延伸篇，承 Day67）

接續 Day67 預告:今天談 **Open Redirect 與 CRLF / HTTP Header Injection 的交會點**——當跳轉值被塞進 HTTP 回應的 `Location:` 標頭時,含有 `\r\n` 的輸入如何在標頭後面「再注入額外標頭」甚至「分裂整個回應」。

先把延伸角度講清楚:**這篇不是重新介紹 Open Redirect,也不是重講 CRLF Injection。**

- Open Redirect 的定義、釣魚故事、`?next=` 危險寫法、`//evil.com` / `@evil.com` 白名單繞過、跳轉代碼映射——**Day20** 講過入門,**Day67** 講過「白名單寫對仍被 parser differential 繞過」。
- CRLF 是什麼、`\r\n` 為什麼能把 HTTP 訊息切成兩份、response splitting 的基本原理與防禦層次——**Day34** 已完整說明。

今天只聚焦一個很多人漏掉的交叉風險:

> **就算跳轉值通過了「網域白名單」,只要它還含有 CR/LF,被寫進 `Location:` 標頭時就可能注入新標頭或分裂回應。**
>
> 網域白名單管的是「跳到哪個 host」,它**完全不管**字串裡有沒有換行。這兩道防線是正交的,少一道都不行。

如果你還沒讀過 Day20、Day34、Day67,建議先回去補;這篇預設你已經知道 Open Redirect 與 CRLF 各自是什麼。

---

## 一、為什麼「白名單通過」和「沒有 CRLF」是兩回事

回顧一個常見的跳轉端點防禦(Day67 的核心):驗證 `next` 的 host 在白名單內,才跳轉。

問題是,很多人驗證時只比對 **host**,卻把**原始字串**送進跳轉:

```java
// 反例:host 驗過了,但送進 Location 的是「原始 next」
String next = req.getParameter("next");
URI u = URI.create(next);
if (allowedHosts.contains(u.getHost())) {   // 只看 host
    resp.sendRedirect(next);                // 卻把原始字串塞回去
}
```

攻擊者送:

```text
next = https://yourapp.com/welcome%0d%0aSet-Cookie:%20session=attacker
```

- `u.getHost()` 解出 `yourapp.com` → **白名單通過**。
- 但 `next` 這個字串裡藏著 `%0d%0a`(URL 編碼的 CR/LF)。一旦某層把它解碼後直接拼進 `Location:`,回應就變成:

```http
HTTP/1.1 302 Found
Location: https://yourapp.com/welcome
Set-Cookie: session=attacker
```

多出來的 `Set-Cookie` 就是被注入的標頭。這正是 Day67 提過、留給今天展開的那一點:**「驗到的東西」和「送出的東西」必須是同一份、而且都要乾淨**。Day67 談的是 host 不一致(parser differential),今天談的是**控制字元不一致**——同一個病根的另一面。

---

## 二、現代框架幫你擋掉多少?(重要,別過度自信)

好消息是:主流容器與標準庫**大多已內建防護**,但防護方式不同,盲點也不同。你必須知道自己的那一層做了什麼。

### Java / Servlet 容器(以 Tomcat 為例)

現代 Tomcat 在寫標頭時會檢查控制字元。`response.setHeader(...)`、`addHeader(...)`、`sendRedirect(...)` 若值含裸 `\r` / `\n`,會**拒絕該標頭或丟例外**,而不是乖乖寫出去。所以在**未經解碼**的情況下,`sendRedirect(next)` 通常不會直接讓你 response splitting。

但盲點在於:

1. **你自己先解碼**。若你在驗證流程裡做了 `URLDecoder.decode(next)`,把 `%0d%0a` 變成裸 `\r\n`,再拼進其他地方(見第三節),防線就破了。
2. **舊容器 / 自製 HTTP 層 / 老舊 filter**。不是每個 runtime 都像新版 Tomcat 一樣嚴。Serverless gateway、自寫的 reverse proxy、老專案的自製 response wrapper,行為不保證。
3. **值流向的不是 `Location`,而是被你手拼的標頭**(如自訂 `X-Redirect-To`、`Refresh`、`Set-Cookie`)。

### Go / net/http

Go 標準庫的做法是「消毒」而非「拒絕」:HTTP server 在寫標頭值時,會用內建的 replacer 把 `\r` 和 `\n` **換成空白**。因此:

```go
http.Redirect(w, r, next, http.StatusFound) // 內部 w.Header().Set("Location", next)
```

即使 `next` 含裸換行,寫到線路上的 `Location` 值裡的 `\r\n` 會被替換成空白 → **不會分裂回應**。`w.Header().Set("Location", "a\r\nSet-Cookie: x")` 最終輸出大致是 `Location: a  Set-Cookie: x`(換行變空白,擠在同一行,不成為新標頭)。

Go 的盲點:

1. **`%0d%0a` 是「編碼」的,不是裸換行**。`http.Redirect` 只會 `hexEscapeNonASCII`,不會幫你解碼 `%0d%0a`;所以編碼態的 payload 對「是否分裂回應」其實無害——但如果**你自己**先 `url.QueryUnescape` / `url.Parse` 後取某欄位再拼進標頭,就把它變成裸換行了(一樣看第三節)。
2. **你繞過 `http.Redirect`,直接對底層 `bufio.Writer` 手寫標頭**,或透過 CGI/FastCGI 邊界輸出,標準庫的 replacer 就保護不到。

### 一句話結論

> 直接用 `sendRedirect` / `http.Redirect` 送**原始參數**,現代 Java/Go 大多能擋住 response splitting。真正出事的是——**你在中間自己解碼、自己拼標頭、或走了非標準輸出路徑**。CRLF 注入在 2026 年很少死在框架的預設路徑上,幾乎都死在「工程師自作聰明多做了一步」。

---

## 三、真正的破口:自己解碼 + 手拼標頭

把前兩節合起來,最容易中招的三種寫法:

### 破口 1:先解碼再驗證再跳轉

```java
// 危險:自己把 %0d%0a 解成裸 \r\n
String raw = req.getParameter("next");
String next = URLDecoder.decode(raw, StandardCharsets.UTF_8); // ← 裸換行誕生
URI u = URI.create(next);
if (allowedHosts.contains(u.getHost())) {
    // 若 next 現在是 "https://yourapp.com/x\r\nSet-Cookie: s=evil"
    resp.setHeader("Location", next); // 手拼標頭,繞過部分容器的 sendRedirect 檢查
    resp.setStatus(302);
}
```

### 破口 2:把跳轉值同時寫進「另一個」標頭

```go
// 危險:除了 Location,還把使用者值塞進自訂標頭
to := r.URL.Query().Get("next")
w.Header().Set("X-Redirect-Target", to) // 若你先 unescape 過,裸換行就注入了
http.Redirect(w, r, to, http.StatusFound)
```

`Location` 那條被標準庫保護了,但你手動 `Set("X-Redirect-Target", to)` 的那條,若 `to` 是你自己解碼過的裸換行字串,同樣會被 replacer 換成空白——**除非**你走了非標準輸出。重點是:**每多手拼一個標頭,就多一個要自己負責消毒的面。**

### 破口 3:`Refresh` / `meta refresh` / JS 導頁——完全跳出「標頭消毒」的世界

這是 Open Redirect × CRLF 最陰的交叉點。有些跳轉不是靠 `Location:` 標頭,而是:

```java
// 把跳轉值塞進 HTML body 的 meta refresh
out.println("<meta http-equiv='refresh' content='0;url=" + next + "'>");
```

或前端 `window.location = next`。這時 `next` 進的是 **HTML body**,不是 HTTP 標頭——**標頭消毒器根本管不到**。此時:

- CR/LF 不再是重點,`"` / `'` / `>` 的**跳脫**才是(這其實變成 Day02 XSS 的地盤)。
- 而且 `javascript:` scheme 可以直接升級成 XSS(呼應 Day20 提過的 `javascript:` 繞過)。

所以要記得:**跳轉值的防禦手段,取決於它最後流到哪個 sink**——流到 `Location` 標頭是「控制字元 + 網域白名單」,流到 HTML 是「輸出編碼 + scheme 白名單」,兩套完全不同。

---

## 四、正確做法:三道正交防線

把跳轉端點想成三個獨立的關卡,缺一不可:

### 防線 A:網域白名單(Day20 / Day67)——決定「能不能跳、跳到哪」

用**重建後的字串**跳轉,而不是原始輸入(Day67 的三原則:正規化、拒 userinfo、重建字串)。

### 防線 B:控制字元把關——決定「值乾不乾淨」

**在驗證階段就 reject 任何含 CR/LF(以及其他控制字元)的跳轉值**,而且是在解碼後檢查。這道防線不依賴框架,是你自己該做的最後保險。

Java:

```java
private static final Pattern CTRL = Pattern.compile("[\\x00-\\x1f\\x7f]");

static String safeRedirectTarget(String raw, Set<String> allowedHosts, String defaultPath) {
    if (raw == null) return defaultPath;

    // 1) 只解碼一次,並在「解碼後」檢查控制字元(防 %0d%0a 偷渡)
    String decoded = URLDecoder.decode(raw, StandardCharsets.UTF_8);
    if (CTRL.matcher(decoded).find()) return defaultPath;   // 含 \r \n \0 等 → 直接丟棄

    // 2) 網域白名單(Day67:用重建後字串)
    try {
        UriComponents uc = UriComponentsBuilder.fromUriString(decoded).build();
        String host = uc.getHost();
        if (host == null) {                    // 相對路徑,允許但強制站內
            return decoded.startsWith("/") && !decoded.startsWith("//") ? decoded : defaultPath;
        }
        if (uc.getUserInfo() != null) return defaultPath;      // 拒 userinfo(@)
        if (!allowedHosts.contains(host)) return defaultPath;  // equals 比對,非 endsWith
        return uc.toUriString();               // 用重建字串,不用原始 raw
    } catch (Exception e) {
        return defaultPath;
    }
}

// 使用:交給容器的 sendRedirect(它還會再幫你把關一層)
resp.sendRedirect(safeRedirectTarget(req.getParameter("next"), ALLOWED, "/home"));
```

Go:

```go
var ctrlChars = regexp.MustCompile(`[\x00-\x1f\x7f]`)

func safeRedirectTarget(raw string, allowed map[string]bool, def string) string {
	if raw == "" {
		return def
	}
	// 1) 解碼後檢查控制字元(query 參數本身已被 net/http 解碼一次)
	if ctrlChars.MatchString(raw) {
		return def // 含裸 \r \n → 丟棄
	}
	u, err := url.Parse(raw)
	if err != nil {
		return def
	}
	// 2) 相對路徑:允許但擋 protocol-relative(//evil.com)
	if u.Host == "" {
		if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
			return raw
		}
		return def
	}
	if u.User != nil { // 拒 userinfo(@)
		return def
	}
	if !allowed[u.Hostname()] { // 去 port 後精確比對
		return def
	}
	return u.String() // 重建字串
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	target := safeRedirectTarget(r.URL.Query().Get("next"), allowedHosts, "/home")
	http.Redirect(w, r, target, http.StatusFound)
}
```

> 注意:`net/http` 讀 `r.URL.Query().Get("next")` 時已解碼一次,所以此處拿到的就是解碼後的值,直接檢查控制字元即可。**不要**再自己多解碼一輪——多解一次就是多開一個 double-encoding(`%250d%250a`)的破口。

### 防線 C:sink 對號入座——決定「用哪套消毒」

- 值流向 `Location` 或任何 HTTP 標頭 → 防線 B(拒 CR/LF)+ 交給框架的標頭寫入器,**不要自己拼字串**。
- 值流向 HTML(`meta refresh` / `<a href>` / JS `location`)→ 這不是標頭問題,是 **輸出編碼 + scheme 白名單**(只允許 `http`/`https`,拒 `javascript:`/`data:`),回到 Day02 XSS 的做法。

---

## 五、和其他天的交叉風險地圖

這篇正好把 CRLF 家族串起來,幫你建立心智地圖——**同一個 `\r\n` 病根,換個 sink 就是不同的天**:

| Sink(換行流到哪) | 後果 | 對應 |
|---|---|---|
| HTTP 回應 `Location` / 任意 response header | 標頭注入 / response splitting / 快取污染 | 本篇 × Day34 |
| 請求端 `Host` 標頭 | password reset poisoning、快取污染 | Day46 |
| Email / MIME 標頭 | 偷插 Bcc/Cc、整段 MIME body(垃圾/釣魚信) | Day65 |
| Log 檔 | log injection / log forging | Day16 提及 |
| HTML body(meta refresh / JS) | 其實變成 XSS,不再是標頭問題 | Day02 |

看懂這張表,你就能在 code review 時對任何「使用者輸入 → 某種標頭/協定欄位」的地方,反射性地問:**這個 sink 的分界字元是什麼?我有沒有 reject 它?**

---

## 六、偵測、監控與 Code Review checklist

### Code Review:看到這些就要追問

```text
[ ] 跳轉值在「驗證後、送出前」有沒有可能被你自己多解碼一次(URLDecoder / QueryUnescape)?
    → 多解一次 = %0d%0a 變裸換行 + double-encoding 破口。
[ ] 驗證有沒有在「解碼後」reject 控制字元([\x00-\x1f\x7f]),而不是只比對 host?
[ ] 是否有「手拼標頭」的地方:setHeader("Location", 使用者拼字串)、
    自訂 X-* 標頭、Refresh 標頭、Set-Cookie 帶入使用者值?
[ ] 跳轉值有沒有流進 HTML(meta refresh / <a href> / window.location)?
    → 若有,改用輸出編碼 + scheme 白名單(拒 javascript:/data:),這是 XSS 面不是標頭面。
[ ] 有沒有繞過框架的標頭寫入器,直接對底層 writer / CGI 邊界輸出?
    → 這會跳過 Tomcat 拒絕 / Go replacer 的保護。
```

### 監控與回歸測試(後端可自動化)

```text
1) 把 CRLF payload 當 CI 測資,斷言「回應標頭沒有被分裂 / 沒有多出標頭」:
   - next=https://yourapp.com/x%0d%0aSet-Cookie:%20s=evil
   - next=https://yourapp.com/x%0d%0a%0d%0a<script>alert(1)</script>
   - double encoding:%250d%250a
   - 斷言:回應只有一個 Location、沒有被注入的 Set-Cookie / body。
2) 控制字元被 reject 的事件 → 記 log + 告警(呼應 Day16)。
   被拒絕的 next 值幾乎都是攻擊探測。
3) 對「所有把使用者值寫進標頭」的端點做清單盤點,不只跳轉端點。
```

把第 1 點寫進 CI,是這篇最划算的一條防線——CRLF 最容易在「有人把 sendRedirect 換成手拼 Location」或「新增一個自訂標頭」時悄悄復活。

---

## 七、一句話總結

> Open Redirect 的網域白名單和 CRLF 的控制字元把關是**兩道正交防線**:白名單管「跳到哪個 host」,完全不管字串裡有沒有 `\r\n`。現代 Tomcat(拒絕含控制字元的標頭)與 Go `net/http`(把換行換成空白)在**預設路徑**上大多能擋住 response splitting,真正出事的是工程師**自己先解碼、自己手拼標頭、或走非標準輸出**。正解三步:**解碼後 reject 控制字元 → 用重建後字串走白名單(Day67)→ 依 sink 對號入座**(流到標頭交給框架寫入器、流到 HTML 用輸出編碼 + scheme 白名單)。記住那張 sink 地圖:同一個 `\r\n`,流到 `Location` 是本篇、流到 `Host` 是 Day46、流到 Email 是 Day65、流到 HTML 就變 XSS(Day02)。

---

## 延伸閱讀

- Day20 Open Redirect——網域白名單入門。
- Day34 CRLF / HTTP Header Injection——本篇的 CRLF 入門基礎(response splitting 原理、防禦層次)。
- Day67 Open Redirect(延伸)——parser differential 與簽章式 return URL;本篇是它預告的下一步。
- Day46 Host Header Injection、Day65 Email Header Injection——CRLF 家族的另外兩個 sink。
- Day02 XSS——跳轉值流進 HTML / `javascript:` 時的正確防禦面。
- Day16 Security Logging & Monitoring——控制字元被 reject 事件的告警。

---

明天預告:**Day 69 — Reflected File Download(RFD,反射式檔案下載)入門**
(全新主題,不是延伸篇。這幾天一直在談「跳轉值流進 `Location` 標頭」,明天換到另一個回應標頭:`Content-Disposition`。RFD 是一種被低估的攻擊——攻擊者用像 `/api/user/data;setup.bat?q=...&callback=...` 這種 URL,讓你的 JSON/文字 API 把使用者可控內容原封反射回來,再誘導瀏覽器**把回應當成一個可執行檔下載並執行**,而下載的檔名與副檔名來自 URL 路徑的 matrix 參數。會用 Java(Spring `@RequestMapping` 的 path/matrix 參數與 `produces`、`Content-Disposition` 設定)與 Go(`net/http` 反射輸出與 `filename` 控制)示範:為什麼「這只是個回 JSON 的 API,不可能被下載」是錯的,以及三道防禦——強制 `Content-Disposition: attachment; filename="固定安全檔名"`、`X-Content-Type-Options: nosniff`、以及路徑不接受任意 `;filename` 後綴。)
