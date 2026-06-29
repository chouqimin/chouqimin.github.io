---
title: "Day 64：Web Cache Deception（網頁快取欺騙）— 用一個假副檔名偷走別人的私密頁面"
date: 2026-06-26
tags: ["Web Cache Deception", "CDN", "Cache-Control", "Path Normalization"]
---

# Day 64：Web Cache Deception（網頁快取欺騙）— 用一個假副檔名偷走別人的私密頁面

接續 Day63 預告：今天談 **Web Cache Deception（WCD，網頁快取欺騙）**。這是一篇**全新主題**，跟 Day30 的 Web Cache Poisoning 是**兩個相反方向**的攻擊，不要混為一談：

- **Day30 Cache Poisoning**：攻擊者**把惡意內容塞進共享快取**，讓後續所有受害者拿到被污染的回應（攻擊方向：壞東西寫進快取 → 廣播給大家）。
- **Day64 Cache Deception**：攻擊者**騙快取把「別人的私密頁面」當成靜態資源存下來**，再用一個公開、不需登入的 URL 把它讀出來（攻擊方向：把私密資料讀出快取 → 外洩）。

對後端工程師來說，WCD 最反直覺的地方是：**你的應用程式碼可能完全正確——授權判斷對、Session 對、回的內容也對給對的人**。問題出在 **origin（你的後端）和 CDN／快取層對「這個 URL 到底該不該被快取」的判斷不一致**。攻擊者就活在這個縫隙裡。

---

## 一、攻擊長什麼樣子：一行 URL 的故事

假設你的網站有個需要登入才能看的個人資料頁：

```text
https://app.example.com/account/profile
```

它回的是 HTML，帶著受害者的姓名、Email、地址，`Cache-Control` 你以為設好了（或根本沒設）。CDN 前面擋著一層快取。

攻擊者做的事只有一步——**誘導受害者（已登入狀態）點開一個被加料的連結**：

```text
https://app.example.com/account/profile/nonexistent.css
```

接下來發生的事，就是整個攻擊的精髓：

1. **瀏覽器帶著受害者的 Cookie** 對這個 URL 發請求。
2. **CDN 看到結尾是 `.css`**，心想「這是靜態資源，可以快取」，於是準備把回應存下來。它**沒有**把這個請求的 Cache hit 條件跟 Cookie 綁定（靜態資源本來就該對所有人一樣）。
3. 請求穿透到 **origin（你的後端）**。你的路由把 `/account/profile/nonexistent.css` 正規化、或用「寬鬆比對」匹配到了 `/account/profile` 這個 handler，**忽略**了後面那段 `nonexistent.css`，於是**正常地回傳了受害者的私密 HTML**（而且 HTTP 200）。
4. CDN 拿到一個 200 回應，URL 結尾是 `.css`，就**高高興興地把這份含有受害者個資的 HTML 快取起來**，key 就是那個公開 URL。
5. 攻擊者自己（**未登入、不帶任何 Cookie**）去打同一個 `https://app.example.com/account/profile/nonexistent.css`，CDN 直接 **cache hit**，把剛剛存下來的受害者個資原封不動吐給攻擊者。

整個過程攻擊者沒有碰到任何 Session、沒有 XSS、沒有 CSRF token 的問題。**是快取層替他完成了「把私密資料複製成公開檔案」這件事**。這就是 2017 年 Omer Gil 揭露、後來在多家大型網站重現的經典 WCD。

---

## 二、根因：origin 與 CDN 的「兩套世界觀」

WCD 之所以成立，需要**同時**滿足兩邊的錯誤判斷，缺一不可。後端工程師要修的也正是這兩條：

### 世界觀 A：CDN 怎麼決定「要不要快取」

CDN／反向代理通常用**很表面**的訊號決定一個回應能不能快取，常見的有：

- **副檔名**：URL 結尾是 `.css` `.js` `.png` `.jpg` `.ico` `.woff` … → 視為靜態資源，快取。
- **路徑前綴**：`/static/`、`/assets/` → 快取。
- **回應的 `Content-Type`**：有些設定會看 `text/css`、`image/*` 才快取。
- **而且**：對「靜態資源」它**故意忽略 Cookie**——因為靜態檔案本來就該對所有人相同，把 Cookie 納入 cache key 會讓命中率歸零。

關鍵風險：**CDN 是用 URL 的「長相」猜內容類型，而不是真的問 origin「這份回應屬於誰、能不能共用」**。

### 世界觀 B：origin 怎麼解析路徑

很多後端框架／路由在比對路徑時**太寬容**，導致 `/account/profile/anything.css` 還是被 `/account/profile` 接走：

- **路徑正規化**把多餘的尾段吃掉、或把 `//`、`/./`、`%2e` 折疊掉。
- **後綴/前綴比對**（`startsWith`、`pathPrefix`）只看開頭。
- **找不到路由時 fallback** 到某個 catch-all controller，而它又回了帶個資的頁面、且回 200。
- **trailing path 被當參數忽略**。

當 A（「看起來是 css，快取且不看 cookie」）和 B（「尾段我不在乎，照樣回私密頁」）**同時為真**，WCD 就成立。

> 一句話記法：**CDN 以為它在快取一張圖片，origin 卻給了它一份病歷。**

---

## 三、後端能掌握的防禦（重點，因為 CDN 不一定歸你管）

防禦要做縱深，但**最該由後端負責、也最可靠的兩道**是：**(1) 對動態／私密回應明確標記 `Cache-Control: no-store`；(2) 嚴格的路徑比對，讓帶假副檔名的 URL 直接 404 而不是回私密頁。** egress/CDN 設定是第三道，交給平台團隊兜底。

### 防禦 1：動態回應一律 `Cache-Control: no-store`（最重要）

WCD 的最後一步是「CDN 把回應存下來」。只要 origin 在私密回應上明確說「**不准存**」，遵守規範的 CDN 就不會快取，攻擊鏈直接斷。

注意用 `no-store` 而不是只用 `private` 或 `no-cache`：

- `no-store`：**完全不准寫進任何快取**（含 CDN 共享快取與瀏覽器）。這是 WCD 防禦要的。
- `private`：只是「不准**共享**快取存，瀏覽器可存」。理論上 CDN 該尊重，但**很多 CDN 對它認定的靜態副檔名會無視 `private`**，所以不要只靠它。
- `no-cache`：可以存，但每次要回 origin revalidate——對 WCD 來說「能存」本身就是風險。

**Java / Spring Boot：用一個全域預設「動態都 no-store，靜態才放行」的策略**

```java
@Configuration
public class CacheControlConfig implements WebMvcConfigurer {

    // 1) 真正的靜態資源走這條，明確允許快取
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/static/**")
                .addResourceLocations("classpath:/static/")
                .setCacheControl(CacheControl.maxAge(Duration.ofDays(30)).cachePublic());
    }
}

// 2) 其餘所有「動態」回應，預設打上 no-store
@Component
public class NoStoreByDefaultFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws ServletException, IOException {
        // 只放行真正的靜態前綴；其餘一律 no-store
        if (!req.getRequestURI().startsWith("/static/")) {
            res.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        }
        chain.doFilter(req, res);
    }
}
```

設計重點：**預設不安全的方向應該是「不快取」**。讓「可快取」成為需要明確 opt-in 的少數白名單路徑，而不是反過來。很多 WCD 的根因就是「忘了設 Cache-Control，結果 CDN 用副檔名自作主張」。

**Go：用 middleware 同樣做 default-deny 快取**

```go
// 只有白名單前綴的靜態資源可快取,其餘一律 no-store
var staticPrefixes = []string{"/static/", "/assets/"}

func cacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isStatic := false
		for _, p := range staticPrefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				isStatic = true
				break
			}
		}
		if isStatic {
			w.Header().Set("Cache-Control", "public, max-age=2592000")
		} else {
			// 動態/私密內容:絕對不准進任何共享快取
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
```

### 防禦 2：嚴格路徑比對 —— 讓 `/account/profile/x.css` 直接 404

第二道是斷掉 origin 那邊的「寬容比對」。`/account/profile/nonexistent.css` **本來就不該回 200**——它應該是個明確的 404，這樣 CDN 就算想快取，存下來的也只是一個無害的 404（而且很多 CDN 預設不快取 404，或可設定不快取）。

**反例（Spring，危險）：** 用 `@RequestMapping` 搭配萬用、或開啟了寬鬆的後綴比對。歷史上 Spring 的 `useSuffixPatternMatch` 會讓 `/account/profile.anything` 匹配到 `/account/profile`——這正是 WCD 的溫床。

```java
// 危險心智模型:以為只會匹配 /account/profile
@GetMapping("/account/profile")
public String profile() { ... }
// 但若框架開了 suffix pattern / trailing match,
// /account/profile.css、/account/profile/x.css 也可能被它接走並回 200
```

**正解：關掉寬鬆比對，要求精確路徑。** Spring Boot 新版預設 `PathPatternParser` 已不做副檔名後綴比對，但要明確確認，並關掉 trailing-slash 的寬鬆：

```java
@Configuration
public class StrictPathConfig implements WebMvcConfigurer {
    @Override
    public void configurePathMatch(PathMatchConfigurer configurer) {
        // 明確使用 PathPatternParser(預設,但顯式宣告意圖)
        configurer.setPatternParser(new PathPatternParser());
        // 不要讓 /account/profile/ 之類自動等價於 /account/profile
        // (新版預設已 strict;若用舊 AntPathMatcher,務必避免 suffix pattern match)
    }
}
```

**Go：自己拿到的 path 一定要正規化後「精確」比對，catch-all 不要回私密頁**

```go
func profileHandler(w http.ResponseWriter, r *http.Request) {
	// 1) 正規化:折疊 . / .. / 多餘斜線,看清楚「真實路徑」
	clean := path.Clean(r.URL.Path)

	// 2) 精確比對:多一個字元都不行,/account/profile/x.css 會落空 -> 404
	if clean != "/account/profile" {
		http.NotFound(w, r) // 回 404,不回私密內容
		return
	}
	// 3) 走到這裡才是真的 /account/profile,正常授權 + 回個資
	renderProfile(w, r)
}
```

兩道防線是 **AND 不是 OR**：就算路由不小心回了 200，`no-store` 也讓 CDN 不存；就算某個 CDN 不尊重 `no-store`，嚴格路徑也讓它存到的只是 404。縱深就是這樣堆出來的。

### 防禦 3（交給平台/CDN 團隊兜底）：cache key 與「以內容決定可否快取」

後端做完上面兩條，還可以推動 CDN 端：

- **不要只看副檔名決定快取**：理想上讓 CDN 以 origin 回的 `Cache-Control` 為準（origin 說 `no-store` 就不存），而不是用 URL 長相覆蓋 origin 的意圖。
- **靜態資源走獨立、隔離的路徑與網域**（如 `static.example.com`、`/static/`），動態應用網域**預設不快取**。讓「會回個資的應用」和「會被快取的靜態檔」在路由上物理分開。
- **避免危險的 path normalization 差異**：origin 與 CDN 對 `%2f`、`;`、`//`、`.css` 的處理要一致；不一致正是攻擊縫隙。

---

## 四、Code Review / 盤點 checklist

```text
[ ] 會回傳「對使用者私密、因人而異」內容的 endpoint(個資、訂單、後台),
    回應有沒有明確 Cache-Control: no-store?
    → 用 no-store,不要只靠 private;預設動態一律 no-store,靜態才白名單 opt-in。

[ ] 框架路由有沒有「寬鬆比對」把帶假副檔名/尾段的 URL 接到私密 handler?
    → 測 /account/profile/x.css、/account/profile.css、/account/profile;.css
       這些應該是 404,不能是 200 回個資。

[ ] Spring:有沒有開啟 useSuffixPatternMatch / 舊 AntPathMatcher 的後綴比對?
    → 關掉;用 PathPatternParser,精確比對。

[ ] Go:有沒有用 HasPrefix / 寬鬆 mux 把尾段忽略?path.Clean 後是否精確比對?
    → 正規化後精確比對,落空就 NotFound。

[ ] CDN 是不是「只看副檔名」決定快取、且對靜態忽略 Cookie?
    → 找平台團隊確認;讓 origin 的 Cache-Control 有最終決定權。

[ ] 靜態資源與動態應用有沒有在路徑/網域上隔離(/static/、static.example.com)?
    → 隔離;應用網域預設不快取。

[ ] origin 與 CDN 對 %2f、//、;、副檔名的 normalization 是否一致?
    → 不一致就是縫隙,要對齊或在 origin 端先 reject 異常路徑。
```

**偵測測試(可放進安全回歸測試):** 對每個會回私密內容的 endpoint,自動附加各種假副檔名與尾段,斷言「不是 200」且回應帶 `no-store`：

```text
對 /account/profile 依序送:
  /account/profile/test.css
  /account/profile.css
  /account/profile/test.js
  /account/profile;.css
  /account/profile%2ftest.css
斷言: 每一個都回 404(或至少非 200),
      且任何 2xx 回應的 Cache-Control 都含 no-store、不含 public。
```

---

## 五、一句話總結

> Web Cache Deception 的本質是:**CDN 用 URL 的「長相」(副檔名)猜這是公開靜態檔、忽略 Cookie 把它存下來;origin 卻用「寬鬆比對」把帶假副檔名的 URL 當成原本的私密頁面回了 200**——兩個錯誤判斷對上,共享快取就把一個人的個資複製成人人可讀的公開檔案。它跟 Day30 Cache Poisoning 方向相反(那是寫壞東西進快取,這是把私密讀出快取)。後端最實在的兩道防線:**(1) 動態/私密回應一律 `Cache-Control: no-store`,讓「可快取」變成靜態白名單才有的 opt-in;(2) 嚴格路徑比對,讓 `/account/profile/x.css` 直接 404 而不是回個資。** CDN 端的「以 origin 意圖決定快取、靜態與動態隔離」交給平台兜底。

---

## 延伸閱讀

- Day30 Web Cache Poisoning——同樣是共享快取,但攻擊方向相反(寫入污染 vs 讀出私密)。
- Day09 / Day58 Security Headers / CORS——`Vary` 與 cache key 隔離的共通思路。
- Day63 ESI Injection——同屬「CDN/邊緣層替你做事」造成的攻擊面,但那是邊緣執行指令,這是邊緣錯存內容。
- Day07 Broken Access Control / IDOR——個資外洩的後果相同,但 WCD 繞過的是「快取層」而非授權邏輯本身。

---

明天預告:**Day 65 — Email Header Injection（郵件標頭注入 / SMTP 注入）:全新主題,與 Day34 CRLF/HTTP Header Injection 不同 sink**
(這是全新主題,不是 Day34 的延伸。Day34 講的是把 CRLF 注進 **HTTP 回應標頭**;Day65 要講的是當後端用使用者輸入(收件人、主旨、寄件者名稱)組 email 時,攻擊者用換行字元偷插 `Bcc:`、`Cc:`、額外的 `From:` 或整段 MIME body,把你的系統變成發垃圾信/釣魚信的跳板。會用後端寄信情境示範:Java 用 JavaMail/`MimeMessage` 為什麼 `setRecipients` 安全、但手動拼 header 就中招;Go 用 `net/smtp` 直接拼 `\r\n` 的危險與 `mail.Address`/樣板化的正解,並給「收件者白名單、剝除 CR/LF、用函式庫而非字串拼接」的防禦寫法與 review 重點。)
