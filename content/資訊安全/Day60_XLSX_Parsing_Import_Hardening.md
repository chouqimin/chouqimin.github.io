---
title: "Day 60：XLSX 解析攻擊面 — 當後端「讀取」使用者上傳的試算表"
date: 2026-06-22
tags: ["XLSX", "Apache POI", "excelize", "Zip Bomb", "XXE"]
---

接續 Day59 預告：今天聊 **XLSX 匯入端（讀取端）的解析硬化**。這是一篇**延伸篇**，不是重新介紹 Day59 的 CSV / Formula Injection，也不重講 Day44 的 ZIP Slip 解壓縮基礎、或 Day13 / Day54 的 XXE 基本原理。

這篇的延伸角度只有一個：**XLSX 本質是一包 ZIP + 一堆 XML**，所以當你的後端用 Apache POI（Java）或 excelize（Go）去「解析使用者上傳的 .xlsx」時，會在同一個動作裡**同時**踩到兩條舊地雷——Day44 的解壓縮炸彈／資源耗盡，以及 Day13 / Day54 的 XML 外部實體。重點是談「讀取端」要打哪些開關，以及為什麼**匯出端逸出（Day59）跟匯入端解析硬化（今天）是完全不同的兩道防線**，做了一邊不等於另一邊安全。

---

## 一、先把昨天跟今天的防線分清楚

很多人讀完 Day59 會以為「我 XLSX 都用 `setCellValue` 不寫公式了，試算表安全搞定」。錯。那是**寫出去（匯出）**的防線，守的是「下載你檔案的人」。今天講的是**讀進來（匯入）**的防線，守的是「你自己這台後端伺服器」。

兩者方向相反、威脅對象不同：

| 維度 | Day59 匯出端逸出 | Day60 匯入端解析硬化（本篇） |
|---|---|---|
| 資料流向 | 後端 → 使用者下載 | 使用者上傳 → 後端解析 |
| 受害者 | 打開檔案的人（他的 Excel） | 你的伺服器（CPU / RAM / 磁碟 / 內網） |
| 主要威脅 | 公式注入（`=+-@`） | Zip bomb、解壓放大、XXE、entity 膨脹 |
| 防禦位置 | 輸出當下補 `'` / 結構逸出 | 解析器開關 + 資源上限 + 關外部實體 |
| 標準庫幫你嗎 | 不幫你做公式逸出 | 部分有預設保護，但**版本與設定決定一切** |

只做匯出逸出，使用者照樣可以丟一個 10KB 解壓變 10GB 的 `.xlsx` 把你 OOM。只做匯入硬化，你匯出的報表照樣可以害下載端中公式注入。**兩道都要做。**

---

## 二、XLSX 到底是什麼：拆給你看

`.xlsx`（OOXML / SpreadsheetML）不是二進位格式，它就是一個 ZIP 容器，裡面塞 XML：

```text
sample.xlsx  （其實是一個 zip）
├── [Content_Types].xml
├── _rels/.rels
├── docProps/core.xml
├── docProps/app.xml
└── xl/
    ├── workbook.xml
    ├── _rels/workbook.xml.rels
    ├── sharedStrings.xml      ← 所有字串集中在這，最容易被放大攻擊
    ├── styles.xml
    └── worksheets/
        └── sheet1.xml          ← 儲存格資料
```

你可以親手驗證（這是純讀取、無害的觀察）：

```bash
# 把 xlsx 當 zip 解開來看內容物
unzip -l sample.xlsx
# 看壓縮比：壓縮後 vs 原始大小
unzip -v sample.xlsx | awk '{print $1, $2, $7}'
```

看懂這個結構，你就會立刻明白攻擊面：

1. **它是 ZIP** → 可以做 zip bomb（高壓縮比）、巢狀放大、超大 entry。
2. **它內含 XML** → 任何一個 XML 檔（尤其 `sharedStrings.xml`、`sheet1.xml`、甚至 `[Content_Types].xml`）都可能塞 DTD / 外部實體 / billion laughs。
3. **它有 `_rels` 關聯與外部參照** → 可能誘發外連（SSRF 面，見 Day53）。

換句話說：**Day44 + Day13 的攻擊面，被打包進了一個你以為「只是試算表」的檔案。**

---

## 三、攻擊一：解壓放大 / Zip Bomb（資源耗盡）

XLSX 的 `sharedStrings.xml` 通常是純文字、可壓縮性極高。攻擊者塞一個幾 MB 的檔案，解壓後可能膨脹到數 GB，POI / excelize 在解析時把它讀進記憶體，直接 OOM 或讓你 CPU 打滿。

這不是理論。POI 內建的 zip bomb 偵測（`ZipSecureFile`）就是為了這個存在的。它用一個**最小解壓比（min inflate ratio）**判斷：當任一 entry 的「壓縮後 / 解壓後」比例好過門檻（預設 0.01，即解壓放大超過 100 倍），就拋出 zip bomb 例外。

### Java（Apache POI）：把上限調到符合你業務的真實大小

POI 5.x 的相關開關都是**全域靜態設定**，建議在服務啟動時設定一次：

```java
import org.apache.poi.openxml4j.util.ZipSecureFile;
import org.apache.poi.util.IOUtils;

public class PoiSecurityConfig {
    public static void harden() {
        // 1) 解壓放大比門檻：預設 0.01（放大 100 倍就擋）。
        //    比例「越大」越嚴格。若你的檔案合法放大頂多 ~50 倍，可調到 0.02。
        ZipSecureFile.setMinInflateRatio(0.02d);

        // 2) 單一 zip entry 解壓後最大位元組（預設 4GB = 32-bit zip 上限）。
        //    依你實際最大報表設定，例如 200 MB。
        ZipSecureFile.setMaxEntrySize(200L * 1024 * 1024);

        // 3) 抽取文字總量上限（預設 10MB）。防 sharedStrings 文字爆量。
        ZipSecureFile.setMaxTextSize(50L * 1024 * 1024);

        // 4) POI 配置的全域 byte[] 申請上限（防單次超大配置 OOM）。
        //    -1 = 不額外限制；設一個合理上限避免單筆惡意配置。
        IOUtils.setByteArrayMaxOverride(300 * 1024 * 1024);
    }
}
```

關鍵觀念：**這些值不是越大越安全，而是「越貼近你業務真實上限越安全」。** 預設 4GB entry size 等於沒防。你要先量自家最大的合法報表有多大，再往上抓一點當天花板。`setMinInflateRatio` 反過來，數字**越大越嚴格**（門檻提高），別調成 0 把保護關掉。

還有一個常被忽略的前置防線：**檔案進到 POI 之前先擋大小**。別把 multipart 整包讀進記憶體再判斷：

```java
// Spring：限制上傳大小（application.yml）
// spring.servlet.multipart.max-file-size: 20MB
// spring.servlet.multipart.max-request-size: 25MB

// 解析時用 streaming / event 模型，避免一次把整個 workbook 載進記憶體
// 大檔讀取用 SAX-based 的 XSSF event model 或 SXSSF，而不是 WorkbookFactory.create 全載
```

### Go（excelize）：用 Options 限制解壓上限

excelize（`github.com/xuri/excelize/v2`，由 qax-os 維護、活躍更新）在 `Options` 裡提供兩個上限：

```go
import (
    "fmt"
    "io"

    "github.com/xuri/excelize/v2"
)

func parseUploadedXLSX(r io.Reader) error {
    f, err := excelize.OpenReader(r, excelize.Options{
        // 整包解壓後總位元組上限（預設 16GB —— 等於沒防，務必下修）
        UnzipSizeLimit: 200 << 20, // 200 MB

        // 單一 worksheet / sharedStrings XML 進記憶體的上限（預設 16MB）。
        // 超過此值會落地到暫存目錄而非全載記憶體；可視機器調整。
        // 限制：UnzipXMLSizeLimit 必須 <= UnzipSizeLimit
        UnzipXMLSizeLimit: 32 << 20, // 32 MB
    })
    if err != nil {
        return fmt.Errorf("open xlsx: %w", err) // 超限會在這裡擋下
    }
    defer f.Close()

    rows, err := f.GetRows("Sheet1")
    if err != nil {
        return err
    }
    fmt.Printf("rows=%d\n", len(rows))
    return nil
}
```

注意預設值：`UnzipSizeLimit` 預設 **16GB**、`UnzipXMLSizeLimit` 預設 **16MB**。前者對絕大多數後端來說等於門戶大開，**一定要往下調到你業務真實需要的量級**。兩者關係是 `UnzipXMLSizeLimit <= UnzipSizeLimit`，否則回 `ErrOptionsUnzipSizeLimit`。

---

## 四、攻擊二：XLSX 內藏 XXE（外部實體）

XLSX 內含 XML，而 Day13 / Day54 講過的 XXE 在這裡照樣成立：攻擊者把外部實體塞進 `[Content_Types].xml`、`workbook.xml` 或 `sharedStrings.xml`，當你的 XML parser 預設允許 DTD / 外部實體時，就可能被讀本機檔（`file:///etc/passwd`）、打內網（SSRF，見 Day53）、或用 billion laughs 把記憶體撐爆。

好消息：**現代 POI 預設已經關掉外部實體**，它內部建 XML parser 時會套用安全 factory。壞消息：

1. **舊版 POI（特別是 3.x 早期）並非全面安全**，升級才是根本解。
2. 你若**繞過 POI、自己拿 `xl/sharedStrings.xml` 出來丟給自己的 `DocumentBuilder` / `SAXParser` 解析**（很常見，為了效能或客製欄位），那 XXE 防護就回到**你自己**身上——POI 幫不了你。

所以延伸重點不是「再教一次怎麼關 XXE」，而是：**只要是你自己直接解析從 XLSX 拆出來的 XML，就要套 Day13 的那套關閉開關。**

### Java：自己解析 XLSX 內的 XML 時的安全 parser

```java
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.XMLConstants;

DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
// 一刀切：完全禁用 DTD（最強、最簡單，XLSX 內 XML 不需要 DTD）
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
// 等價的高階保險絲
dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
```

對於走 POI 標準路徑（`WorkbookFactory` / `XSSFWorkbook` / SAX event model）的情況，把 POI 升到維護中的 5.x 並信任其預設即可；真正的風險點是「自己手動拆 XML」那條路。

### Go：`encoding/xml` 不解析外部實體，但仍要設上限

excelize 底層用 Go 的 `encoding/xml`，它**天生不解析外部 DTD / 外部實體**，所以傳統「讀 `/etc/passwd`」型 XXE 在 Go 這邊基本不成立——這是 Go 標準庫的一個安全優勢。但**實體展開造成的記憶體膨脹（billion-laughs 類）與超大 XML 仍是資源耗盡風險**，靠的是上一節的 `UnzipXMLSizeLimit` / `UnzipSizeLimit`，而不是 entity 開關。

換句話說：Go 這邊 XXE「讀檔/SSRF」面向風險低，但**資源耗盡面向不會因為用了 Go 就消失**，硬化重點回到第三節的解壓上限。

---

## 五、攻擊三：別忘了外部參照與公式回連（跨 Day53 SSRF）

XLSX 可以帶**外部連結**（external links / `externalReferences`）與某些會「回連」的函數（如 `WEBSERVICE`、`IMPORTXML`，Day59 提過）。重點分清楚兩種情境：

- **你只是解析資料、不重算公式**：POI / excelize 讀取儲存格的**快取值**或公式字串，不會主動發出網路請求，外連風險低。
- **你在伺服器端「重新計算」公式**（POI 的 `FormulaEvaluator`、或任何會 resolve 外部參照的流程）：這就可能變成 SSRF / 外部資源讀取的跳板，等於把 Day53 的攻擊面接進來。

防禦原則：**伺服器端解析使用者上傳的試算表時，預設不要重算公式、不要 resolve 外部參照。** 真的需要計算，就只算純函數、明確拒絕外部連結，並套上 Day53 的 egress 控制。

---

## 六、把防線串起來：上傳檔解析的縱深設計

對「使用者上傳 XLSX → 後端解析」這條鏈，建議的層次（從外到內）：

1. **入口先量體**：限制 multipart 大小（Day11 的上傳硬化），別把整包讀進記憶體才判斷。
2. **確認檔案真身**：不要只信副檔名／Content-Type。檢查 magic bytes（ZIP 以 `PK\x03\x04` 開頭），確認真的是 OOXML zip 容器。
3. **解壓上限**：POI `ZipSecureFile` 三項上限 + `IOUtils.setByteArrayMaxOverride`；Go excelize `UnzipSizeLimit` / `UnzipXMLSizeLimit`。全部**下修到業務真實量級**。
4. **XML 安全**：走 POI 標準路徑就升級到維護版本並信任預設；自己拆 XML 解析就套 Day13 的禁用 DTD / 外部實體。
5. **不重算公式、不 resolve 外部參照**（Day53 egress 控制）。
6. **streaming 解析**：大檔用 event / SAX 模型（POI XSSF event model；excelize 的 rows iterator `Rows()`）逐列讀，避免全載。
7. **逾時與隔離**：解析放有 timeout 的 worker，必要時隔離程序，避免單一惡意檔卡死整台。

---

## 七、自我檢查清單

- [ ] 全 codebase 搜尋解析點：`WorkbookFactory`、`XSSFWorkbook`、`OPCPackage.open`、`excelize.OpenReader`、`excelize.OpenFile`。
- [ ] 每個解析點之前，是否都有 multipart / 檔案大小上限？
- [ ] POI：服務啟動是否呼叫 `ZipSecureFile.setMaxEntrySize` / `setMaxTextSize` / `setMinInflateRatio`，且值**貼近業務真實上限**而非預設 4GB / 0.01？
- [ ] POI：是否設了 `IOUtils.setByteArrayMaxOverride` 防單筆超大配置？
- [ ] POI 版本是否為**維護中的 5.x**？有沒有殘留 3.x 舊解析路徑？
- [ ] 有沒有「自己把 `sharedStrings.xml` / `sheet1.xml` 拆出來丟給 `DocumentBuilder`」的程式？若有，是否套了 Day13 的禁用 DTD/外部實體？
- [ ] excelize：`Options.UnzipSizeLimit` / `UnzipXMLSizeLimit` 是否從預設（16GB / 16MB）**下修**到合理值？
- [ ] 是否避免在伺服器端重算公式 / resolve 外部參照？有沒有 egress 控制（Day53）？
- [ ] 大檔是否走 streaming（event model / `Rows()` iterator）而非全載？
- [ ] 解析是否有 timeout / worker 隔離？
- [ ] 自動化測試：是否有針對下列惡意樣本的測試——高壓縮比 zip bomb、巨大 `sharedStrings.xml`、含 DTD/外部實體的 `[Content_Types].xml`、超大單一 entry？

```java
// JUnit 範例：上傳一個放大比過高的 xlsx，必須被擋下
@Test
void zipBombIsRejected() {
    ZipSecureFile.setMinInflateRatio(0.02d);
    assertThrows(Exception.class, () -> {
        try (var pkg = OPCPackage.open(maliciousHighRatioXlsx())) {
            new XSSFWorkbook(pkg); // 解析時觸發 zip bomb 偵測
        }
    });
}
```

```go
// Go 範例：解壓上限過小時，惡意大檔應回錯而非 OOM
func TestUnzipLimitRejects(t *testing.T) {
    _, err := excelize.OpenReader(maliciousBigXLSX(), excelize.Options{
        UnzipSizeLimit:    8 << 20, // 8MB
        UnzipXMLSizeLimit: 4 << 20, // 4MB
    })
    if err == nil {
        t.Fatal("expected unzip size limit error, got nil")
    }
}
```

---

## 八、一句話總結

> **XLSX 不是「試算表」，它是「一包你要替使用者解壓並解析的 ZIP + XML」。** 匯出端逸出（Day59）守的是下載你檔案的人；匯入端解析硬化（今天）守的是你自己的伺服器，兩者是不同方向的兩道防線。讀取端的核心就三件事：把解壓上限（POI `ZipSecureFile` / excelize `UnzipSizeLimit`）**從天文數字預設下修到業務真實量級**、確保 XML 解析（尤其自己拆 XML 時）禁用外部實體、以及伺服器端不重算公式不 resolve 外部參照。Go 因 `encoding/xml` 不吃外部實體，XXE 讀檔面風險低，但解壓放大造成的資源耗盡照樣要靠上限擋。

---

## 延伸閱讀

- Apache POI 官方文件 — `ZipSecureFile`（`setMinInflateRatio` / `setMaxEntrySize` / `setMaxTextSize`）與 Configuration（`IOUtils.setByteArrayMaxOverride`）
- Apache POI — XSSF event model（SAX-based streaming 讀取）
- excelize 官方文件（xuri.me/excelize）— `Options` 之 `UnzipSizeLimit` / `UnzipXMLSizeLimit`、`OpenReader`、`Rows()` iterator
- 前文：Day44 ZIP Slip / Archive Extraction（解壓縮基礎與 zip bomb）、Day13 / Day54 XXE（外部實體禁用開關）、Day53 SSRF（egress 控制與外部參照回連）、Day59 CSV / Formula Injection（匯出端逸出，今天的對照面）

---

明天預告：**Day 61 — Server-Side Template Injection（SSTI）：當使用者輸入流進你的模板引擎（全新主題）**
（這是系列還沒介紹過的全新主題，承接今天「把使用者資料當成可執行內容來解析」的同一條思路，但對象從上傳檔變成模板字串。會說明 SSTI 的本質：使用者可控字串被當成「模板」而非「資料」去 render，輕則資訊洩漏、重則 RCE。後端示範會用 Java（Thymeleaf / FreeMarker / Velocity 的危險用法與安全用法）與 Go（`text/template` vs `html/template` 的關鍵差異、為什麼把使用者輸入當 template 來源是大忌），並給出「資料歸資料、模板歸模板」的防禦原則與 code review 重點。）
