---
title: "Day 65：Email Header Injection（郵件標頭注入 / SMTP 注入）— 一個換行字元，把你的系統變成釣魚信跳板"
date: 2026-06-29
tags: ["Email Header Injection", "SMTP Injection", "CRLF", "JavaMail"]
---

# Day 65：Email Header Injection（郵件標頭注入 / SMTP 注入）— 一個換行字元,把你的系統變成釣魚信跳板

接續 Day64 預告:今天談 **Email Header Injection（郵件標頭注入,也叫 SMTP 注入)**。這是一篇**全新主題**,而且要先講清楚它跟 Day34 的差別——它們長得很像,但**打的不是同一個 sink**:

- **Day34 CRLF / HTTP Header Injection**:CRLF(`\r\n`)注進的是 **HTTP 回應標頭**,後果是 response splitting、塞假 header、污染快取。
- **Day65 Email Header Injection**:同樣是 CRLF,但注進的是 **email 訊息(郵件標頭 + MIME body)**。後端在用使用者輸入(收件人、主旨、寄件者名稱)組信時,攻擊者用換行偷插 `Bcc:`、`Cc:`、額外的 `From:`,甚至整段 MIME body,把你的寄信功能變成發垃圾信/釣魚信的免費跳板。

換句話說:**同一種武器(CRLF),不同的戰場(SMTP/MIME vs HTTP)**。如果你 Day34 已經懂 CRLF 為什麼危險,今天的重點就是「換到郵件這個 sink 之後,哪些欄位會中、為什麼 `setRecipients` 安全而手拼 header 中招、以及正確的寫法長怎樣」。

---

## 一、為什麼一個換行就能注入?

郵件的格式(RFC 5322)跟 HTTP 很像:**標頭區**由一行一行的 `Name: Value` 組成,每行用 CRLF(`\r\n`)分隔,標頭區與信件內文(body)之間用**一個空行**(連續兩個 CRLF)隔開。

```text
From: noreply@example.com
To: alice@example.com
Subject: 您的訂單已出貨
                <- 這個空行之後就是內文
您好,您的訂單...
```

問題就出在:**如果後端把使用者輸入直接拼進某個標頭值,而那個輸入裡含有 `\r\n`,那麼這個換行就「結束了目前的標頭」,後面的東西會被郵件伺服器當成新的標頭(或內文)來解讀。**

假設一個「聯絡我們」表單,後端用使用者填的 email 當作 `Reply-To`:

```text
使用者填的 email 欄位:
attacker@evil.com\r\nBcc: victim1@x.com,victim2@y.com,...（一萬個收件人）
```

拼進信件後變成:

```text
Reply-To: attacker@evil.com
Bcc: victim1@x.com,victim2@y.com,...
```

你的系統就乖乖把這封信「密件副本」給了一萬個陌生人——而且寄件者是**你的網域**,通過你的 SPF/DKIM。這就是垃圾信業者最愛的跳板。

更狠的是注入完整 body。如果輸入裡塞了「兩個換行 + 任意內容」,等於提前結束標頭區、自己寫一封信:

```text
主旨欄位:
訂單確認\r\n\r\n<a href="https://phish.example">點此領取退款</a>...
```

收件人收到的就是一封**頂著你品牌、簽章合法**的釣魚信。

---

## 二、Java:為什麼 `setRecipients` 安全,手拼 header 中招

JavaMail(現 Jakarta Mail)的 `MimeMessage` API 在你**用對方法**時,會幫你做標頭的合法性檢查與 encoding。問題出在開發者繞過 API、自己拼字串。

### 反例一:用 `addHeader` 手拼收件人

```java
// 危險:把使用者輸入直接塞進 header value
String userEmail = request.getParameter("email"); // 可能含 \r\n
MimeMessage msg = new MimeMessage(session);
msg.addHeader("Reply-To", userEmail); // ← CRLF 直接被當成新 header
```

`addHeader` 對 value 不做 CRLF 防護。一旦 `userEmail` 含 `\r\nBcc: ...`,就注入成功。

### 反例二:把使用者輸入拼進 Subject 字串再硬塞

```java
String subject = "訂單 " + request.getParameter("orderNote"); // 使用者可控
msg.setHeader("Subject", subject); // 同樣不檢查 CRLF
```

### 正解:用 `InternetAddress` 解析 + `setRecipients` / `setReplyTo`

JavaMail 用「型別」幫你把關。把地址交給 `InternetAddress`(開啟 strict 解析),把主旨交給 `setSubject`:

```java
import jakarta.mail.Message;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

MimeMessage msg = new MimeMessage(session);

// 1) 地址一律用 InternetAddress 嚴格解析（strict=true）
//    非法格式（含 CRLF、多個地址混入）會丟 AddressException
InternetAddress replyTo = new InternetAddress(userEmail, /* strict */ true);
msg.setReplyTo(new InternetAddress[]{ replyTo });

// 2) 主旨用 setSubject，會做 RFC 2047 encoding，CRLF 不會逃逸成新 header
msg.setSubject(userSubject, "UTF-8");

// 3) 收件人用 setRecipients/addRecipient，搭配 InternetAddress.parse(..., true)
msg.setRecipients(Message.RecipientType.TO,
    InternetAddress.parse("fixed-recipient@example.com", true));
```

重點:**`InternetAddress` 的 strict 解析會拒絕含換行或多餘字元的「地址」**,而 `setSubject` 會做 encoded-word 處理,把非 ASCII 與控制字元安全地包起來。真正的防線是「**別自己拼 header,讓函式庫的型別系統替你檢查**」。

> 補充:JavaMail 預設也會擋掉部分含 CRLF 的 header value(系統屬性 `mail.mime.encodeparameters` / `mail.mime.foldtext` 等行為),但**不要依賴這個當唯一防線**——版本與設定會變,輸入端驗證 + 用對 API 才是穩的。

---

## 三、Go:`net/smtp` 直接拼 `\r\n` 的危險,與 `net/mail` 的正解

Go 標準庫**沒有**幫你組信件標頭的高階 API——`net/smtp.SendMail` 收的是「一坨 `[]byte` 的原始訊息」。這意味著**標頭是你自己拼的**,CRLF 防護也得你自己做,踩雷機率比 Java 高。

### 反例:把使用者輸入直接 `fmt.Sprintf` 進訊息

```go
// 危險:to / subject 含 \r\n 就直接注入
func sendDangerous(to, subject, body string) error {
    msg := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s",
        to, subject, body) // ← to/subject 的 CRLF 直接破格
    return smtp.SendMail("smtp:25", nil,
        "noreply@example.com", []string{to}, []byte(msg))
}
```

`to := "a@b.com\r\nBcc: spam@x.com"` 就會多出一個 `Bcc`,而且 `SendMail` 的信封收件人(第 4 參數)也被污染。

### 正解一:地址用 `net/mail.ParseAddress` 驗證

`mail.ParseAddress` 會嚴格解析單一地址,含 CRLF / 多地址 / 非法格式都會回 error:

```go
import "net/mail"

addr, err := mail.ParseAddress(userInput)
if err != nil {
    return fmt.Errorf("invalid recipient: %w", err)
}
// addr.Address 是清乾淨的地址；addr.Name 是顯示名稱
recipient := addr.Address
```

### 正解二:所有放進 header 的值,先剝除 / 拒絕 CR 與 LF

對「會進標頭」的欄位(主旨、寄件者顯示名稱等),最務實的是**直接拒絕含換行的輸入**(而不是默默刪掉,刪掉可能改變語意):

```go
// 任何要放進 email header 的字串都先過這關
func sanitizeHeaderValue(s string) (string, error) {
    if strings.ContainsAny(s, "\r\n") {
        return "", errors.New("header value contains CR/LF")
    }
    return s, nil
}
```

### 正解三:用樣板化的訊息建構(地址型別 + encoded 主旨)

把信件組裝集中到一個「只接受已驗證型別」的函式,主旨用 RFC 2047 編碼,收件人用 `mail.Address`:

```go
import (
    "mime"
    "net/mail"
    "net/smtp"
    "strings"
)

func sendSafe(toAddr mail.Address, subject, body string) error {
    if _, err := sanitizeHeaderValue(subject); err != nil {
        return err
    }
    from := mail.Address{Name: "Example", Address: "noreply@example.com"}

    var b strings.Builder
    b.WriteString("From: " + from.String() + "\r\n")
    b.WriteString("To: " + toAddr.String() + "\r\n")
    // 主旨做 encoded-word，控制字元/非 ASCII 都被安全包起來
    b.WriteString("Subject: " + mime.QEncoding.Encode("UTF-8", subject) + "\r\n")
    b.WriteString("MIME-Version: 1.0\r\n")
    b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
    b.WriteString("\r\n") // 標頭與內文的分界
    b.WriteString(body)

    return smtp.SendMail("smtp:25", nil,
        from.Address, []string{toAddr.Address}, []byte(b.String()))
}
```

注意這裡 `toAddr` 是**已經由 `mail.ParseAddress` 驗證過的 `mail.Address`**,`.String()` 會輸出合法格式;`subject` 額外過 `sanitizeHeaderValue` + `QEncoding`。Body 本身放在分界空行之後,即使含換行也只是內文,不會逃逸成 header。

> 如果用第三方寄信庫(如 `gomail`),它的 `SetHeader` / `SetAddressHeader` 通常會處理 encoding——但仍要對「地址欄位」先 `mail.ParseAddress`,別把原始字串塞進去。要採用前,記得確認該套件仍在維護、且你用到的方法真的存在。

---

## 四、哪些欄位最常中招(後端盤點清單)

```text
[ ] 收件人 / Cc / Bcc          ← 直接被當地址，注入額外收件人最常見
[ ] Reply-To / From 顯示名稱   ← 「聯絡我們」「邀請朋友」表單重災區
[ ] Subject 主旨               ← 常被字串拼接，可注 body 開頭
[ ] 任何寫進自訂 header 的輸入  ← X-* 自訂標頭、追蹤 ID 等
[ ] 範本變數插值點             ← 把使用者資料插進 .eml 範本字串時
```

判斷準則:**只要使用者輸入會出現在「空行之前」(標頭區),它就有 header injection 風險;出現在空行之後(body),風險降為內容類(釣魚文案/HTML 注入),但仍要處理。**

---

## 五、防禦三原則 + Code Review 重點

防禦其實只有三句話:

1. **用函式庫,不要手拼 header。** Java 用 `MimeMessage` 的 `setSubject` / `setRecipients` / `InternetAddress(strict=true)`;Go 用 `mail.ParseAddress` 取得 `mail.Address` 再組裝。
2. **所有進標頭的值,拒絕 CR/LF。** 地址欄位靠嚴格解析自動擋下;主旨、顯示名稱等自由文字欄位明確 reject 含 `\r` / `\n` 的輸入。
3. **收件人白名單 / 信封與標頭一致。** 對外只該寄給「系統決定」的收件人(例如表單通知固定寄給內部信箱),別讓使用者控制 envelope recipient。

Code Review checklist:

```text
[ ] grep 有沒有 addHeader / setHeader 直接塞使用者輸入？（Java）
[ ] grep 有沒有 fmt.Sprintf("...To: %s..." / strings 拼 header？（Go）
[ ] 地址欄位是否一律經過 InternetAddress(strict) / mail.ParseAddress？
[ ] 主旨 / 顯示名稱是否有 CR/LF reject 或 encoded-word？
[ ] 收件人是否由系統決定，而非完全由請求參數決定？
[ ] 寄信功能有沒有 rate limit？（防被當垃圾信機器，呼應 Day17）
```

偵測測試(可放進安全回歸測試):對每個會寄信的 endpoint,送入含 CRLF 的 payload,斷言「不是成功送出、且不會多出收件人」:

```text
對 email / subject / name 欄位依序送:
  a@b.com%0d%0aBcc:spam@x.com
  test%0d%0a%0d%0a<phishing body>
  名稱%0aFrom:ceo@example.com
斷言:
  - 請求被拒（4xx），或
  - 送出的信件 header 不含被注入的 Bcc/From，收件人數量 == 預期
```

---

## 六、一句話總結

> Email Header Injection 的本質跟 Day34 同源——**都是 CRLF 破格**——但 sink 換成了 SMTP/MIME:**後端用使用者輸入拼郵件標頭,一個 `\r\n` 就能讓攻擊者偷加 `Bcc`/`Cc`/`From`,甚至整段釣魚 body,把頂著你網域、過你 SPF/DKIM 的信寄給任何人。** 防線不在「努力清字串」,而在**用對函式庫的型別把關(Java `InternetAddress`/`setSubject`、Go `mail.ParseAddress`)、對標頭欄位 reject CR/LF、收件人由系統決定**。手拼 header 字串,就是把寄信權交給輸入框。

---

## 延伸閱讀

- Day34 CRLF / HTTP Header Injection——同一種武器(CRLF),不同戰場(HTTP 回應 vs 郵件)。
- Day08 / Day55 Input Validation——「拒絕含控制字元的輸入」是共通的第一道閘。
- Day17 Rate Limiting——寄信端點被濫用成垃圾信機器,rate limit 是必要的兜底。
- Day19 TLS / Cryptographic Failures——SPF/DKIM/DMARC 是「別讓別人冒用你網域」,本篇是「別讓別人透過你的系統冒用你網域」,互補。

---

明天預告:**Day 66 — DMARC / SPF / DKIM 寄件網域驗證(延伸篇,承 Day65):從「別讓系統被注入」延伸到「別讓網域被冒名」**
(這是 Day65 的延伸篇,不是重新介紹郵件注入。延伸角度:Day65 解決的是「攻擊者透過你的後端注入 header」,Day66 要往外一層,談「即使你的程式碼乾淨,攻擊者也可能直接偽造 From 冒用你的寄件網域」——會說明 SPF(信封寄件者 IP 授權)、DKIM(訊息簽章)、DMARC(對齊與處置策略)三者各擋什麼、為什麼缺一不可,並從後端角度示範:應用程式該用哪個寄件網域/子網域、`From` 與信封寄件者要如何對齊才能通過 DMARC alignment、以及寄信服務(SES/SendGrid 等)設定的常見誤區與驗證測試。)
