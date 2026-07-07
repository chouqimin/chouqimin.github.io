---
title: "Day 70：Content-Disposition 與檔案下載端點的進階防禦（延伸篇，承 Day69）— filename* 非 ASCII、inline vs attachment、Content-Type 白名單與大檔串流"
date: 2026-07-07
tags: ["Content-Disposition", "Download Security", "RFC 6266", "Java"]
---

# Day 70：Content-Disposition 與檔案下載端點的進階防禦（延伸篇，承 Day69）

接續 Day69 預告：昨天談 **Reflected File Download（RFD）**，結論是「用 `Content-Disposition: attachment; filename="固定安全檔名"` 打掉可控檔名」。但那是站在「這支端點根本不該產生下載」的角度——把檔名寫死、把 JSONP 下架就沒事了。

問題是：**你有一大堆端點是「本來就要提供檔案下載」的**。使用者上傳的合約 PDF、匯出的報表 CSV、頭像圖片、發票附件……這些端點無法把檔名寫死成一個常數，而且經常需要**保留使用者原本的檔名**（含中文、日文、emoji）、需要**inline 預覽**（PDF、圖片直接在瀏覽器開）、還要能**串流大檔**。

> **這篇不是重新介紹 RFD，也不重講 Day69 的三道入門防禦。** 這篇聚焦在「真的要做下載端點」時的四個進階細節：
> 1. `filename` 與 `filename*`（RFC 5987 / RFC 6266）怎麼處理非 ASCII 檔名，又不引入標頭注入；
> 2. `inline` vs `attachment` 的選擇，以及 PDF/圖片預覽的安全取捨；
> 3. `Content-Type` ↔ 副檔名的**白名單映射**（別讓瀏覽器 sniff）；
> 4. 大檔串流下載時 `Content-Length` / `Range` 的正確性。
>
> 用 Java（Spring `ContentDisposition` builder、`ResponseEntity<Resource>`）與 Go（`mime.FormatMediaType`、`http.ServeContent`）示範。

如果你還沒讀 Day69，建議先補：本篇預設你已經知道「為什麼下載端點要強制 `attachment` + `nosniff`」。

---

## 一、先把攻擊面講清楚：合法下載端點會漏在哪

Day69 的主力防禦是「檔名寫死」。但當檔名**必須來自資料庫或使用者輸入**時，這條防線就得重新設計。合法下載端點的三個進階破口：

1. **標頭注入（承 Day34 / Day65 / Day68 家族）**：檔名裡有 `"`、`\r`、`\n`、`;` → 逸出 `filename` 引號、注入新標頭、甚至把 `attachment` 悄悄變回 `inline`。
   ```text
   原始檔名：invoice";inline;x="a.pdf
   → Content-Disposition: attachment; filename="invoice";inline;x="a.pdf"
   ```
   `filename` 在第一個 `"` 就被截斷，後面被解讀成新的 disposition 參數。

2. **非 ASCII 檔名被吃掉或亂拼**：`合約.pdf`、`請求書.pdf`、`report📎.pdf`。很多人直接把 UTF-8 bytes 塞進 `filename="..."`，結果不是亂碼就是被某些框架 reject。**正解是 RFC 5987 的 `filename*` 語法**，但這個語法本身也有逸出規則，手拼一樣會炸。

3. **Content-Type 誤判 → sniff → 型別提權**：使用者上傳一張「圖片」，內容其實是 HTML/SVG，你回 `Content-Type: image/png` 但沒帶 `nosniff`，瀏覽器 sniff 出 HTML 就變 XSS（承 Day02）。或者你依「使用者給的副檔名」決定 `Content-Type`，攻擊者就控制了瀏覽器的型別認知。

這三點的共通根因跟 Day69 一樣：**回應標頭 / 檔名帶有使用者輸入，而 sink 是 `Content-Disposition` 與 `Content-Type`。** 差別是——這次我們不能「不反射」，只能「安全地反射」。

---

## 二、filename 與 filename*：RFC 6266 / RFC 5987 的正確拼法

先講標準怎麼定的，才知道框架幫你做了什麼、哪裡要自己把關。

- **RFC 6266** 定義 HTTP 的 `Content-Disposition` 標頭：`disposition-type`（`inline` / `attachment`）加上參數，其中檔名參數有兩種：
  - `filename="..."`：只能放 **ISO-8859-1（Latin-1）可表示的字元**，且是 quoted-string，內部的 `"` 和 `\` 要跳脫。**不能放原始 UTF-8。**
  - `filename*=UTF-8''...`：這是 **RFC 5987 extended value**，格式為 `charset'lang'percent-encoded-value`，非 ASCII 一律做 **percent-encoding**（不是 URL query 那套，attr-char 以外全部 `%XX`）。
- **相容策略**：同時給 `filename`（ASCII fallback，給看不懂 `filename*` 的老 client）與 `filename*`（UTF-8，給現代瀏覽器）。現代瀏覽器**優先採用 `filename*`**。

一個正確的標頭長這樣：

```text
Content-Disposition: attachment; filename="request.pdf"; filename*=UTF-8''%E8%AB%8B%E6%B1%82%E6%9B%B8.pdf
```

`請求書.pdf` 的 UTF-8 bytes 被 percent-encode 成 `%E8%AB%8B%E6%B1%82%E6%9B%B8.pdf`，放進 `filename*`；同時 `filename` 給一個 ASCII 化的降級檔名 `request.pdf`。

**手拼這串是災難來源**（逸出規則、charset 前綴、percent-encoding 全都要對）。所以進階防禦第一原則：**用函式庫的 builder，不要自己字串相接。**

### Java：Spring `ContentDisposition` builder

Spring 從 5.x 起提供 `org.springframework.http.ContentDisposition`，會自動處理 `filename*` 的 RFC 5987 編碼與 quoted-string 逸出：

```java
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import java.nio.charset.StandardCharsets;

// 反例：手拼，會被 " 和 CRLF 注入
// headers.add("Content-Disposition",
//     "attachment; filename=\"" + userFilename + "\"");   // 危險

// 正解：先清洗，再交給 builder
String safeName = sanitizeFilename(userFilename);   // 見 §五
ContentDisposition cd = ContentDisposition.attachment()   // 明確 attachment
        .filename(safeName, StandardCharsets.UTF_8)       // 觸發 filename* UTF-8 編碼
        .build();

HttpHeaders headers = new HttpHeaders();
headers.setContentDisposition(cd);
```

`ContentDisposition.attachment().filename(name, UTF_8)` 產出的字串會**同時符合 quoted-string 逸出與 RFC 5987**，你不需要自己 percent-encode。重點是：**`sanitizeFilename` 這一步不能省**——builder 負責「格式正確」，但**不負責「語意安全」**（例如檔名裡的 `\r\n` 要不要 reject、要不要限制副檔名，是你的責任，見 §五）。

> 小地雷：`ContentDisposition.builder("attachment")` 這種舊寫法仍可用，但 disposition-type 若讓使用者控制就等於把 `attachment` / `inline` 交給攻擊者——**disposition-type 一律由伺服器常數決定**，見 §四。

### Go：`mime.FormatMediaType`

Go 標準庫 `mime` 套件的 `mime.FormatMediaType` 會依 RFC 2045/2183/2231 處理參數，**非 ASCII 值自動走 RFC 2231/5987 的 `filename*` 編碼**：

```go
import (
    "mime"
    "net/http"
)

func setDownloadHeader(w http.ResponseWriter, rawName string) {
    safe := sanitizeFilename(rawName) // 見 §五，reject CR/LF、限副檔名

    // FormatMediaType 會在含非 ASCII / 特殊字元時自動輸出 filename*
    cd := mime.FormatMediaType("attachment", map[string]string{
        "filename": safe,
    })
    // 若 safe 含不合法字元導致 FormatMediaType 回空字串，走安全降級
    if cd == "" {
        cd = `attachment; filename="download"`
    }
    w.Header().Set("Content-Disposition", cd)
}
```

注意兩點：

- `mime.FormatMediaType` 在**參數值不合法時會回傳空字串**（不是 panic、不是亂拼），所以要判斷 `cd == ""` 走降級，別直接 `Set` 一個空標頭。
- 它產出的可能只有 `filename*`（純 UTF-8 時）。若你要相容非常老的 client，可自己補一個 ASCII fallback 的 `filename`：先算好 `asciiName`，再 `mime.FormatMediaType("attachment", map[string]string{"filename": asciiName})`，然後把 `filename*` 那份接上去——但多數情況只給 `filename*` 已足夠，別為了相容性反而手拼出注入點。

---

## 三、Content-Type ↔ 副檔名：白名單映射，別讓瀏覽器 sniff

Day69 講過「回應要帶 `X-Content-Type-Options: nosniff` + 正確 `Content-Type`」。延伸篇要補的是：**「正確的 Content-Type」怎麼決定？**

三種常見錯法：

1. **依使用者給的副檔名決定 Content-Type** → 攻擊者控制型別認知。
2. **依上傳當下的 `Content-Type` header 存起來直接回** → 那個 header 是 client 給的，不可信。
3. **完全不設，讓瀏覽器 sniff** → 型別提權（image 變 HTML → XSS）。

正解是**伺服器端維護一份「允許下載的 MIME 白名單」，由你信任的來源（實際掃描過的內容 / 上傳時驗過的 magic bytes，承 Day11、Day60）決定，而不是由檔名或 client header 決定**：

```java
// 只允許這些型別對外下載；不在白名單一律 octet-stream + attachment
private static final Map<String, String> ALLOWED_CT = Map.of(
    "pdf",  "application/pdf",
    "png",  "image/png",
    "jpg",  "image/jpeg",
    "csv",  "text/csv",
    "txt",  "text/plain"
);

String contentType = ALLOWED_CT.getOrDefault(
        trustedExtension,                 // 來自 DB/掃描結果，不是使用者輸入
        "application/octet-stream");      // 白名單外：強制未知二進位

headers.setContentType(MediaType.parseMediaType(contentType));
headers.add("X-Content-Type-Options", "nosniff");   // 關鍵：禁止 sniff
```

Go 同理：

```go
var allowedCT = map[string]string{
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".csv": "text/csv",
    ".txt": "text/plain; charset=utf-8",
}

ct, ok := allowedCT[trustedExt]
if !ok {
    ct = "application/octet-stream"
}
w.Header().Set("Content-Type", ct)
w.Header().Set("X-Content-Type-Options", "nosniff")
```

> 特別小心 **SVG**：`image/svg+xml` 可含 `<script>`，以 `inline` 開啟等於 XSS。SVG 若一定要提供，**強制 `attachment` 下載，不要 `inline`**（見 §四），或轉點陣圖再回。同理 HTML、XML 這類「可執行/可解析」型別，預設就別給 inline。

---

## 四、inline vs attachment：預覽的取捨

- `attachment`：瀏覽器**下載**（可能跳存檔對話框），不在當前頁面 render。**最安全的預設值。**
- `inline`：瀏覽器**嘗試直接開**（PDF viewer、圖片、甚至 HTML render）。體驗好，但把「檔案內容」放進了你網域的 render context。

安全原則：

1. **預設一律 `attachment`。** 只有明確、白名單內的「安全可預覽型別」（PDF、常見圖片）才考慮 `inline`。
2. **要 inline 預覽的端點，最好放在獨立的「無 cookie / 隔離網域」**（例如 `usercontent.example.com`），避免 inline 內容拿到主站的 same-origin 權限。這跟 Day64（Web Cache Deception）談的「靜態/使用者內容網域隔離」是同一個思路。
3. **disposition-type 永遠是伺服器常數**，絕不從使用者輸入帶入。攻擊者若能把 `attachment` 改成 `inline`，等於把「下載」變「在你網域 render」。

```java
// 由端點語意決定，不由使用者輸入決定
ContentDisposition cd = previewSafe(trustedExtension)
        ? ContentDisposition.inline().filename(safeName, StandardCharsets.UTF_8).build()
        : ContentDisposition.attachment().filename(safeName, StandardCharsets.UTF_8).build();
```

`previewSafe()` 是一個**白名單判斷**（只有 `pdf`/`png`/`jpg` 之類回 true），不是看使用者要不要預覽。

---

## 五、檔名清洗：builder 之前的那一步（語意安全）

§二說 builder 保證「格式正確」，但**語意安全要自己做**。這是承 Day11（Path Traversal 檔名處理）與 Day65/Day68（CRLF reject）的交集，下載側的清洗規則：

```java
private static final int MAX_LEN = 100;

static String sanitizeFilename(String raw) {
    if (raw == null || raw.isBlank()) return "download";

    // 1) reject / 去除控制字元（含 CR/LF/TAB/NUL）——標頭注入防線，承 Day68
    String s = raw.replaceAll("[\\p{Cntrl}]", "");

    // 2) 去掉路徑成分，只留檔名本身——承 Day11
    s = s.replace("\\", "/");
    s = s.substring(s.lastIndexOf('/') + 1);

    // 3) 移除會逸出 quoted-string / disposition 參數的字元
    s = s.replace("\"", "").replace(";", "");

    // 4) 去頭尾點與空白（避免 . / .. / "隱藏"檔名）
    s = s.replaceAll("^[.\\s]+", "").replaceAll("[\\s]+$", "");

    // 5) 限長，避免超長標頭
    if (s.length() > MAX_LEN) s = s.substring(0, MAX_LEN);

    // 6) 副檔名不吃使用者的——由伺服器依「可信型別」決定（承 Day69）
    //    這裡只保留基底名，副檔名在外層依 ALLOWED_CT 反查後補上
    return s.isBlank() ? "download" : s;
}
```

Go 版：

```go
import (
    "strings"
    "unicode"
)

func sanitizeFilename(raw string) string {
    if strings.TrimSpace(raw) == "" {
        return "download"
    }
    // reject 控制字元（CR/LF/TAB/NUL 等）
    s := strings.Map(func(r rune) rune {
        if unicode.IsControl(r) {
            return -1
        }
        return r
    }, raw)

    s = strings.ReplaceAll(s, "\\", "/")
    if i := strings.LastIndex(s, "/"); i >= 0 {
        s = s[i+1:]
    }
    s = strings.NewReplacer(`"`, "", ";", "").Replace(s)
    s = strings.Trim(s, ". ")
    if len(s) > 100 {
        s = s[:100]
    }
    if s == "" {
        return "download"
    }
    return s
}
```

關鍵順序：**先 reject 控制字元 → 去路徑 → 去逸出字元 → 副檔名由伺服器決定**。副檔名這步呼應 Day69：**永遠不要用使用者給的副檔名**，而是依 `ALLOWED_CT` 反查出「你信任的型別」對應的副檔名，再自己接上去。

---

## 六、大檔串流：Content-Length 與 Range 的正確性

下載端點常見的效能與正確性坑：把整個檔案讀進記憶體再回（OOM）、`Content-Length` 算錯（連線 hang 或截斷）、不支援 `Range`（無法續傳、影音無法拖曳進度）。**安全與正確性在這裡合流**——`Content-Length` 若和實際 body 長度不一致，在某些代理鏈上可能造成回應邊界錯位（呼應 Day23 Request Smuggling 的「長度不一致」家族思路）。

**別自己手刻 Range 解析**（`Range: bytes=` 有多段、開放區間、`If-Range` 等一堆邊界），用框架/標準庫幫你做對。

### Go：`http.ServeContent`

`net/http` 的 `http.ServeContent` 會**自動處理 `Range`、`Content-Length`、`Last-Modified`、`If-Range`、`If-Modified-Since`**，你只要提供一個 `io.ReadSeeker`：

```go
func downloadHandler(w http.ResponseWriter, r *http.Request) {
    f, modTime, name, trustedExt, err := openTrustedFile(r) // 你的授權 + 取檔邏輯
    if err != nil {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    defer f.Close() // f 需為 io.ReadSeeker（如 *os.File）

    // 先設安全標頭（見 §二~§四）
    setDownloadHeader(w, name)                 // Content-Disposition（attachment + filename*）
    if ct, ok := allowedCT[trustedExt]; ok {
        w.Header().Set("Content-Type", ct)
    } else {
        w.Header().Set("Content-Type", "application/octet-stream")
    }
    w.Header().Set("X-Content-Type-Options", "nosniff")

    // ServeContent 負責 Range / Content-Length / 條件請求
    http.ServeContent(w, r, name, modTime, f)
}
```

注意：**不要在呼叫 `ServeContent` 前自己 `Set("Content-Length", ...)` 或 `Set("Content-Type", ...)` 又跟它打架**——`ServeContent` 會自行管理長度；`Content-Type` 若你已設它就尊重你的（所以我們刻意先設白名單型別，避免它去 sniff 副檔名）。授權檢查（這個使用者能不能下載這個檔，承 Day07 IDOR）務必放在 `openTrustedFile` 裡，別只靠檔名。

### Java：`ResponseEntity<Resource>`

Spring 用 `ResponseEntity<Resource>` 回 `Resource`（如 `FileSystemResource`、`InputStreamResource`），搭配 `contentLength()`，並可交由框架支援 range：

```java
@GetMapping("/files/{id}")
public ResponseEntity<Resource> download(@PathVariable String id, Principal user) {
    FileMeta meta = fileService.getAuthorized(id, user); // 授權在這，承 Day07

    Resource body = new FileSystemResource(meta.path());  // 可 seek，支援 range
    String safeName = sanitizeFilename(meta.originalName());
    String ct = ALLOWED_CT.getOrDefault(meta.trustedExt(), "application/octet-stream");

    ContentDisposition cd = ContentDisposition.attachment()
            .filename(safeName, StandardCharsets.UTF_8)
            .build();

    return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, cd.toString())
            .header("X-Content-Type-Options", "nosniff")
            .contentType(MediaType.parseMediaType(ct))
            .contentLength(meta.size())         // 用可信的實際大小
            .body(body);
}
```

要讓 Spring 支援 `Range`（部分下載、續傳），可註冊 `ResourceHttpRequestHandler` / 使用支援 range 的資源處理，或直接讓靜態資源走 `ResourceHttpRequestHandler`（它內建 range 支援）。重點是**用 `FileSystemResource` 這類可 `seek` 的 `Resource`**，而不是把整個檔案讀成 `byte[]`——後者既 OOM 又無法 range。`contentLength()` 一定要用**伺服器實際量到的大小**，不要相信 DB 裡可能過期的欄位。

---

## 七、後端 Code Review / 測試 checklist

```text
[ ] Content-Disposition 是否用框架 builder（Spring ContentDisposition / Go mime.FormatMediaType）而非手拼字串?
[ ] 檔名是否先過 sanitizeFilename:reject 控制字元(CR/LF)、去路徑、去 " 和 ;、限長?
[ ] 非 ASCII 檔名是否走 filename*（UTF-8''percent-encoded），而不是把原始 bytes 塞進 filename=?
[ ] disposition-type（attachment/inline）是否由伺服器常數決定,絕不由使用者輸入帶入?
[ ] 預設是否一律 attachment,只有白名單安全型別(pdf/png/jpg)才 inline?
[ ] SVG / HTML / XML 是否禁止 inline(強制 attachment 或隔離網域)?
[ ] Content-Type 是否來自伺服器白名單(依可信型別),而非使用者副檔名或 client 上傳 header?
[ ] 白名單外的型別是否降級為 application/octet-stream?
[ ] 每個下載回應是否都帶 X-Content-Type-Options: nosniff?
[ ] 大檔是否用 http.ServeContent / ResponseEntity<Resource> 串流,而非讀成整塊 byte[]?
[ ] Content-Length 是否為伺服器實際量到的大小,且與 body 一致?
[ ] Range 是否交給標準庫/框架處理,而非自己解析 bytes= ?
[ ] 下載授權(能不能下載這個檔)是否在取檔前檢查,而非只靠檔名(承 Day07 IDOR)?
```

自動化回歸測試建議：

- 對下載端點送 `originalName = 'a";inline;x="b.pdf'`、`report\r\nSet-Cookie: x=1.csv`、`請求書.pdf`、`report📎.svg` 等惡意/非 ASCII 檔名，**斷言回應標頭沒有被分裂、沒有多出標頭、`Content-Disposition` 一定是 `attachment`（該端點語意下）、且含正確的 `filename*=UTF-8''...`**。
- 斷言每個下載回應都帶 `X-Content-Type-Options: nosniff`，且 `Content-Type` 落在白名單內（SVG/HTML 不得為 inline）。
- 對大檔送 `Range: bytes=0-1023`，斷言回 `206 Partial Content`、`Content-Range` 正確、body 長度符合。
- 檔名清洗 reject 事件（含控制字元 / 路徑成分）記 log 告警（呼應 Day16）。

---

## 八、一句話總結

> Day69 教你「不該下載的端點怎麼把門關死」；Day70 教你「該下載的端點怎麼把門開對」。合法下載端點的四道進階防線各自對應一個 sink：**檔名交給 `ContentDisposition` builder / `mime.FormatMediaType`，非 ASCII 走 `filename*`，並在 builder 之前先 reject CR/LF 與路徑成分**（打掉標頭注入）；**disposition-type 由伺服器常數決定、預設 `attachment`、可執行型別禁 inline**（打掉「在你網域 render」）；**`Content-Type` 走伺服器白名單 + `nosniff`**（打掉 sniff 提權）；**大檔用 `ServeContent` / `Resource` 串流、`Content-Length` 用實際大小、`Range` 交給標準庫**（打掉 OOM 與長度不一致）。記住：**框架的 builder 保證「格式正確」，不保證「語意安全」——清洗那一步永遠是你的責任。**

---

## 延伸閱讀

- Day69 Reflected File Download——本篇的入門前傳，「不該下載的端點」的防禦。
- Day11 Path Traversal / File Upload——上傳側的檔名與副檔名處理，與本篇下載側清洗互補。
- Day60 XLSX 匯入端解析硬化——「內容真身」驗證（magic bytes），決定 Content-Type 白名單的可信來源。
- Day02 XSS——SVG/HTML inline 預覽為何危險的 sink 對照。
- Day34 / Day65 / Day68 CRLF 家族——檔名裡的 CR/LF 為何要 reject，同屬「使用者輸入流進回應標頭」。
- Day07 Broken Access Control / IDOR——下載授權必須在取檔前檢查，不能只靠檔名。
- Day64 Web Cache Deception——使用者內容網域隔離，與 inline 預覽的隔離思路相同。

---

明天預告：**Day 71 — HTTP Range 請求的安全與 DoS（新主題，承 Day70 的串流下載）**
（Day70 提到「Range 交給標準庫」，但 Range 本身也是攻擊面。這篇會介紹：`Range: bytes=` 的多段請求（multipart/byteranges）被放大成頻寬/CPU DoS（一個請求要求上萬個微小 range，讓伺服器組裝出遠大於原檔的回應，即 range amplification）、`If-Range` 與快取/CDN 交互的坑、以及後端如何限制 range 段數與總量。會用 Java（Spring resource range 設定）與 Go（`http.ServeContent` 的 range 行為與自訂上限中介層）示範怎麼在支援續傳的同時擋掉 range 濫用。）
