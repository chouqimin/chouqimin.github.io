---
title: "Day 69：Reflected File Download（RFD，反射式檔案下載）入門 — 你那支「只回 JSON」的 API，怎麼被下載成 .bat 執行"
date: 2026-07-03
tags: ["Reflected File Download", "Content-Disposition", "Download Security", "Java"]
---

# Day 69：Reflected File Download（RFD，反射式檔案下載）入門

接續 Day68 預告:這幾天一直在談「跳轉值流進 `Location` 標頭」的攻擊面,今天換到**另一個回應標頭**——`Content-Disposition`,介紹一個被嚴重低估的攻擊:**Reflected File Download(RFD,反射式檔案下載)**。

先講一句最反直覺的重點,後端工程師九成會踩:

> **「我這支 API 只是回 JSON,不會產生下載,更不可能被當成執行檔」——這句話是錯的。**

RFD 不需要你的伺服器有「檔案上傳」或「檔案下載」功能。只要滿足三個條件,一支普通的 `application/json` API 就能被瀏覽器**當成一個 `.bat` / `.cmd` / `.exe` 下載下來**,而下載的檔名、副檔名,全部來自**攻擊者控制的 URL**。使用者點下去,執行的是攻擊者的命令,但網址列顯示的卻是**你公司的可信網域**。

這篇是入門篇,會完整說明:RFD 的三個成立條件、攻擊怎麼串起來、為什麼危險(社交工程 × 可信網域)、以及後端三道防禦。用 Java(Spring)與 Go(`net/http`)示範。

---

## 一、RFD 是什麼:三個條件缺一不可

RFD 由 Google 的 Oren Hafif 在 2014 年提出。它的本質是:**攻擊者讓瀏覽器把「你的 API 回應」存成一個可執行檔,並讓內容變成一段可執行的指令。**

成立需要同時滿足三個條件:

**(1) 反射(Reflection):回應內容包含使用者可控字串。**
最常見就是 JSONP callback,或任何把 query / path 參數原封放進回應 body 的端點:

```text
GET /api/search?q=hello&callback=foo
→ 回應 body:foo({"results":["hello"]})
```

`callback` 的值 `foo` 被原封反射進 body 開頭。這一段就是攻擊者的「著陸點」。

**(2) 檔名(Filename):瀏覽器決定的下載檔名帶有危險副檔名。**
關鍵在於:**當回應沒有明確指定 `Content-Disposition: attachment; filename=...` 時,瀏覽器會拿「URL 路徑的最後一段」當檔名。** 而 URL 路徑可以塞進 matrix 參數(分號 `;`):

```text
GET /api/search;/setup.bat?q=hello&callback=cmd|'/c calc'||
```

對後端的路由來說,`;` 之後常被當成 matrix parameter 而**不影響實際對應到的 handler**(仍然打到 `/api/search`),但**瀏覽器看到的路徑結尾是 `setup.bat`** → 下載檔名就變成 `setup.bat`。

**(3) 執行(Execution):下載的內容是一段合法的指令。**
把 callback 換成一段 batch 指令:

```text
callback=cmd|'/c calc'||
```

回應 body 於是變成:

```text
cmd|'/c calc'||({"results":["hello"]})
```

存成 `setup.bat` 後,Windows 的命令直譯器讀到 `cmd|'/c calc'||` 就會執行 `calc`(示範用,真實攻擊會是下載後門、加密勒索等)。後面的 JSON 因為 `||` 短路 / 語法錯誤而被忽略,不影響前段執行。

三個條件——**可反射、可控檔名、內容可執行**——缺一不可。這也剛好對應到後面三道防禦:各打掉一個條件。

---

## 二、為什麼這比一般 XSS 更難防、也更好騙人

很多後端工程師第一次聽到會覺得「這不就是要騙使用者下載檔案嗎?跟釣魚一樣,不算我的漏洞」。這個心態正是 RFD 危險的地方:

- **網址列是你的可信網域。** 使用者滑鼠移到連結、或下載時看到來源,是 `https://你的公司.com/...`。企業內部的資安教育都在教「看網域」,而這裡網域是真的。
- **HTTPS、憑證、一切都合法。** 沒有中間人、沒有假站,就是你的正牌伺服器回的內容。
- **繞過下載信任機制。** 某些瀏覽器 / 作業系統對「從可信來源下載的檔案」信任度較高,SmartScreen / Gatekeeper 的警示也可能較弱。
- **檔案內容是你的伺服器「簽發」的。** 對事後鑑識來說,這個惡意 `.bat` 真的是從你網域下載的,責任與商譽都落在你身上。

換句話說,RFD 把「使用者對你網域的信任」武器化了。它跨在 Web 安全與社交工程之間,而**根因在後端**:是後端讓「可控內容」以「可控檔名」被下載。

---

## 三、後端到底哪裡出錯:Java / Go 反例

### Java(Spring):一支典型的 JSONP 端點

```java
@RestController
public class SearchController {

    // 反例:接受 callback、原封反射、沒有任何下載標頭控制
    @GetMapping(value = "/api/search", produces = "application/javascript")
    public String search(@RequestParam String q,
                         @RequestParam(required = false) String callback) {
        String json = "{\"results\":[\"" + escapeJson(q) + "\"]}";
        if (callback != null) {
            return callback + "(" + json + ")";   // callback 原封反射進 body 開頭
        }
        return json;
    }
}
```

問題點:

1. `callback` 原封反射 → 滿足條件(1)。
2. 沒有 `Content-Disposition` → 瀏覽器用 URL 路徑當檔名 → 攻擊者用 `;/setup.bat` 控制檔名,滿足條件(2)。
3. `produces = "application/javascript"` 之類的型別,更容易被當成可下載/可執行,且沒有 `nosniff` → 條件(3)成形。

攻擊 URL:

```text
https://yourapp.com/api/search;/setup.bat?q=x&callback=cmd|'/c calc'||
```

注意:即使你以為路由是 `/api/search`,Spring 預設會**移除 `;` 之後的 matrix 內容**再對應 handler(取決於版本與 `UrlPathHelper` 設定),所以請求仍然打到 `search()`。但**瀏覽器**看到的檔名是 `setup.bat`。這就是路由層與瀏覽器層「對同一條 URL 認知不一致」的破口。

### Go(`net/http`):同樣的坑

```go
// 反例:反射 callback、沒有 Content-Disposition、沒有 nosniff
func searchHandler(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("q")
    callback := r.URL.Query().Get("callback")

    body := fmt.Sprintf(`{"results":[%q]}`, q)
    if callback != "" {
        w.Header().Set("Content-Type", "application/javascript")
        fmt.Fprintf(w, "%s(%s)", callback, body) // callback 直接反射
        return
    }
    w.Header().Set("Content-Type", "application/json")
    fmt.Fprint(w, body)
}
```

Go 的 router(`net/http` 的 `ServeMux` 或第三方)通常會保留 `;` 在 path 裡,但實務上攻擊者也可以用結尾 path segment、或搭配 CDN / gateway 的路徑正規化差異來塞檔名。核心問題一樣:**回應沒有替瀏覽器把「這是什麼、該叫什麼名字、能不能執行」講清楚。**

---

## 四、三道防禦:一道打掉一個條件

RFD 的防禦很划算,因為三個條件是 AND,**打掉任何一個就不成立**。但正確做法是三道一起上,縱深防禦。

### 防禦一:強制 `Content-Disposition: attachment; filename="固定安全檔名"`

只要回應明確指定 attachment 與**你自己決定的固定檔名**,瀏覽器就不會拿 URL 路徑當檔名,條件(2)直接消失。

Java(Spring)——對「會回傳可下載內容」的端點固定檔名:

```java
@GetMapping(value = "/api/search", produces = MediaType.APPLICATION_JSON_VALUE)
public ResponseEntity<String> search(@RequestParam String q) {
    String json = "{\"results\":[\"" + escapeJson(q) + "\"]}";
    return ResponseEntity.ok()
        // 固定檔名,不吃 URL 路徑;attachment 讓它一律以檔案處理
        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"response.json\"")
        .header("X-Content-Type-Options", "nosniff")
        .contentType(MediaType.APPLICATION_JSON)
        .body(json);
}
```

Go:

```go
func searchHandler(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("q")
    body := fmt.Sprintf(`{"results":[%q]}`, q)

    w.Header().Set("Content-Type", "application/json; charset=utf-8")
    w.Header().Set("X-Content-Type-Options", "nosniff")
    // 固定安全檔名;若一定要下載就用 attachment
    w.Header().Set("Content-Disposition", `attachment; filename="response.json"`)
    fmt.Fprint(w, body)
}
```

補充:如果檔名裡真的需要放使用者可控的東西(例如匯出檔以使用者查詢命名),**務必白名單化**:只保留 `[A-Za-z0-9._-]`、去掉 `;`、`"`、控制字元,並自己補上安全副檔名。**永遠不要**讓副檔名由使用者決定。這一點呼應 Day34 / Day68 對「控制字元流進標頭」的把關,以及 Day11 對檔名處理的原則。

### 防禦二:`X-Content-Type-Options: nosniff`

這道標頭告訴瀏覽器**不要**用內容嗅探去猜型別,老實照 `Content-Type` 處理。它能擋掉「伺服器標了 JSON,但瀏覽器嗅探成 HTML/可執行」這類 MIME sniffing 攻擊,也削弱 RFD 內容被重新解讀的空間。搭配正確的 `Content-Type`(API 就用 `application/json`,不要用 `application/javascript` / `text/html`)。

這其實在 Day09(Security Headers)已列為基本盤——RFD 是它「為什麼重要」的一個具體案例:少了 nosniff,型別把關就漏一層。

### 防禦三:路徑不接受任意 `;filename` 後綴 + 不要無腦反射

兩個層面:

**(a) 拒絕 / 正規化可疑路徑。** 在框架或 gateway 層,關掉 matrix 參數解析、或對含 `;`、看起來像副檔名結尾(`.bat`/`.cmd`/`.exe`/`.sh` 等)的 API 路徑直接 400。Spring 可設定:

```java
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void configurePathMatch(PathMatchConfigurer configurer) {
        UrlPathHelper helper = new UrlPathHelper();
        helper.setRemoveSemicolonContent(true); // 移除 ;matrix,降低檔名注入面
        configurer.setUrlPathHelper(helper);
    }
}
```

注意:`setRemoveSemicolonContent(true)` 是讓**你的路由**忽略 `;` 後內容(這通常是預設);它讓伺服器端行為一致,但**無法改變瀏覽器如何看檔名**——真正擋下載檔名的還是防禦一。所以這條是輔助,不是主力。

**(b) 從源頭砍掉反射。** RFD 高度依賴 JSONP callback。現代前後端分離幾乎都用 CORS(Day09)取代 JSONP。若你還留著 callback 反射端點,先問:**這個 JSONP 還有人用嗎?** 沒有就下架。若必須保留,則對 `callback` 做嚴格白名單(只允許 `[A-Za-z0-9_.]`、限制長度、拒絕含 `|`、`&`、空白、括號外字元),讓它無法變成一段可執行指令,打掉條件(3)。

```java
private static final Pattern SAFE_CALLBACK =
    Pattern.compile("^[A-Za-z0-9_.]{1,64}$");

if (callback != null && !SAFE_CALLBACK.matcher(callback).matches()) {
    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid callback");
}
```

---

## 五、後端 Code Review / 測試 checklist

```text
[ ] 有沒有 JSONP / callback 反射端點?還有人在用嗎?能不能改 CORS 下架?
[ ] 若保留 callback:是否白名單化(只 [A-Za-z0-9_.]、限長、拒特殊字元)?
[ ] 會回可下載內容的端點,是否強制 Content-Disposition: attachment 且 filename 固定安全?
[ ] 檔名若含使用者輸入,是否白名單清洗 + 自己決定副檔名(不吃使用者副檔名)?
[ ] 全站是否預設帶 X-Content-Type-Options: nosniff?
[ ] API 的 Content-Type 是否正確(application/json,而非 javascript/html)?
[ ] 路由是否對含 ; 或以可執行副檔名結尾的 API 路徑做拒絕 / 正規化?
[ ] CDN / gateway 與後端對「path + matrix 參數」的解析是否一致(避免差異被利用)?
```

自動化回歸測試建議:對「會反射參數」的端點,用像 `;/setup.bat?callback=cmd|'/c calc'||` 的探測 URL 打過去,**斷言回應一定帶 `Content-Disposition: attachment; filename="固定名"` 與 `nosniff`**,並斷言 `callback` 這類參數被拒或被清洗。控制字元 / 可疑檔名被 reject 的事件記 log 告警(呼應 Day16)。

---

## 六、一句話總結

> RFD 的可怕不在於「有人被騙下載檔案」,而在於**那個惡意檔案是你的可信網域、用 HTTPS、親手簽發下來的**。它只需要三個條件:回應反射使用者輸入、下載檔名由 URL 控制、內容可被當指令執行。後端三道防禦剛好各打掉一個:**強制 `Content-Disposition: attachment` + 固定安全檔名**(打掉可控檔名)、**`X-Content-Type-Options: nosniff` + 正確 `Content-Type`**(打掉型別誤判)、**下架 / 白名單化 JSONP 反射**(打掉可執行內容)。別再說「我只是回 JSON」——`Content-Disposition` 這個標頭沒設好,你的 JSON 就是別人的 `.bat`。

---

## 延伸閱讀

- Day09 Security Headers / CORS——`X-Content-Type-Options: nosniff` 與用 CORS 取代 JSONP 的基礎。
- Day11 Path Traversal / File Upload——檔名與副檔名處理的原則,RFD 的檔名清洗可沿用。
- Day34 CRLF / HTTP Header Injection、Day68 Open Redirect × CRLF——同屬「使用者輸入流進回應標頭」家族,本篇的 sink 是 `Content-Disposition`。
- Day16 Security Logging & Monitoring——可疑檔名 / callback 被 reject 事件的告警。
- Day02 XSS——反射型輸入的另一種 sink(流進 HTML),與 RFD 的反射概念互相對照。

---

明天預告:**Day 70 — Content-Disposition 與檔案下載端點的進階防禦(延伸篇,承 Day69)**
(這篇不是重新介紹 RFD,而是聚焦在「真正需要提供檔案下載」的端點怎麼做對:`filename` 與 `filename*`(RFC 5987 / RFC 6266)如何處理非 ASCII 檔名而不引入標頭注入、`inline` vs `attachment` 的選擇與 PDF/圖片預覽的取捨、`Content-Type` 對應副檔名的白名單映射、以及大檔串流下載時 `Content-Length` / range 的正確性。會用 Java(Spring `ContentDisposition` builder、`ResponseEntity<Resource>`)與 Go(`mime.FormatMediaType`、`http.ServeContent`)示範:如何在「使用者自訂檔名」與「防止標頭注入 / RFD」之間安全落地。)
