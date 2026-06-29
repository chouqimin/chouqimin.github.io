---
title: "Day 66：SPF / DKIM / DMARC 寄件網域驗證（延伸篇，承 Day65）— 程式碼乾淨，為什麼別人還是能冒用你的網域寄信"
date: 2026-06-30
tags: ["DMARC", "SPF", "DKIM", "Email Spoofing"]
---

# Day 66：SPF / DKIM / DMARC 寄件網域驗證（延伸篇，承 Day65）

接續 Day65 預告:今天談 **SPF / DKIM / DMARC 寄件網域驗證**。

先講清楚這篇的延伸角度:**這不是重新介紹 Email Header Injection,而是往外一層**。Day65 解決的是「攻擊者**透過你的後端**注入 header 來濫用你的寄信功能」——那是你**程式碼裡**的洞。今天要面對的是另一種威脅:**就算你的寄信程式碼一行都沒錯,攻擊者也可以完全不碰你的伺服器,直接從他自己的主機寄出一封 `From: ceo@your-company.com` 的信。** 因為 SMTP 這個 1980 年代的協定,`From` 欄位本來就是「想填什麼填什麼」,沒有任何身分驗證。

SPF / DKIM / DMARC 就是後來補上的三層「寄件網域驗證」。這篇從**後端工程師會踩到的點**切入:這三個各擋什麼、為什麼缺一不可、你的應用程式該用哪個寄件網域、`From` 與信封寄件者要怎麼對齊(alignment)才能通過 DMARC、以及用 SES / SendGrid 這類服務時最常見的設定誤區與驗證測試。

> 前置觀念對照:Day19 講的是「**別讓傳輸被竊聽/竄改**」(TLS);Day65 是「**別讓你的後端被注入**」;今天是「**別讓你的網域被冒名**」。三者互補,不能互相取代。

---

## 一、為什麼 `From` 可以隨便偽造?

寄一封信其實有**兩個**「寄件者」,這是後端最常搞混的地方:

```text
1) 信封寄件者（envelope sender / MAIL FROM / Return-Path）
   - SMTP 對話層的位址，收件伺服器用它決定「退信寄去哪」
   - 使用者通常看不到

2) 標頭寄件者（header From:）
   - 信件內容裡的 From: 欄位，收件人在郵件軟體上「看到」的寄件者
   - 跟信封寄件者可以完全不一樣
```

關鍵:**這兩個位址是各自獨立的,SMTP 不強制它們一致,也不驗證填的人有沒有資格用那個網域。** 攻擊者連到任何一台 SMTP 伺服器,就能送出:

```text
MAIL FROM: <bounce@attacker.com>      ← 信封寄件者，他自己的網域
...
From: "財務部" <finance@your-company.com>   ← 標頭，冒用你
Subject: 緊急匯款指示
```

收件人在 Outlook 裡看到的是 `finance@your-company.com`。這就是商業郵件詐騙(BEC)的根。SPF / DKIM / DMARC 的存在,就是要讓收件伺服器**有辦法判斷「這封宣稱來自 your-company.com 的信,是不是真的有 your-company.com 授權」**。

---

## 二、三層各擋什麼(後端必須分清楚)

這三個常被混為一談,但它們驗證的**對象不同**,這也是「缺一不可」的原因。

### SPF：授權「哪些 IP」可以用你的網域寄信

SPF(Sender Policy Framework)是一筆 **DNS TXT 記錄**,列出「**允許代表本網域寄信的 IP / 主機**」。收件伺服器收到信時,拿**信封寄件者(MAIL FROM)的網域**去查它的 SPF,看寄來的 IP 在不在清單裡。

```text
your-company.com.  IN  TXT  "v=spf1 include:amazonses.com include:_spf.google.com -all"
```

- `include:amazonses.com`:授權 SES 的寄件 IP。
- `-all`:**硬性失敗**——清單外的 IP 一律判 fail(`~all` 是軟性,盡量別用)。

**SPF 的兩個致命限制(後端常忽略):**

1. **SPF 驗的是「信封寄件者(Return-Path)」的網域,不是使用者看到的 `From:`。** 攻擊者把信封寄件者設成自己的網域(SPF 對他自己網域當然 pass),`From:` 照樣冒你。**單靠 SPF 擋不住 From 偽造。**
2. **轉寄會破壞 SPF。** 信經過轉發(forwarding)後,寄出 IP 變成轉發伺服器,不在你的 SPF 清單裡,SPF 就 fail 了。

### DKIM：用「簽章」證明信件沒被竄改、且確實由網域授權發出

DKIM(DomainKeys Identified Mail)讓寄件伺服器用**私鑰**對信件的部分標頭與內文做**數位簽章**,放進 `DKIM-Signature` 標頭;公鑰發佈在 DNS。收件方用公鑰驗章。

```text
DKIM-Signature: v=1; a=rsa-sha256; d=your-company.com; s=ses1;
  h=from:to:subject:date; bh=...; b=...
```

- `d=`:簽章的網域(signing domain)。
- `s=`:selector,對應到 DNS 上的公鑰 `ses1._domainkey.your-company.com`。
- `h=`:被簽進去的標頭清單(注意 `from` 有沒有被簽是重點)。

DKIM 的好處是**不怕單純轉寄**(簽章跟著信件走),而且能保證內容沒被竄改。但 DKIM 單獨也不夠:**它只證明「這封信被某個網域 `d=` 簽了」,沒規定 `d=` 一定要跟使用者看到的 `From:` 一致。** 攻擊者可以拿一個他完全掌控的網域(`d=attacker.com`)合法簽章,`From:` 還是寫你。

### DMARC：把 SPF / DKIM「綁回」到使用者看到的 `From:`，並決定怎麼處置

看出問題了嗎?SPF 驗信封寄件者、DKIM 驗 `d=`,**兩者都不直接管使用者眼睛看到的 `From:` 網域**。攻擊者就鑽這個縫:用自己的網域過 SPF / DKIM,卻在 `From:` 冒用你。

**DMARC 補的就是這道縫——它要求「對齊(alignment)」:**

> 通過 DMARC = (SPF **pass** 且 SPF 網域與 `From:` 網域**對齊**) **或** (DKIM **pass** 且 `d=` 與 `From:` 網域**對齊**)。
> 兩條至少滿足一條。

DMARC 也是一筆 DNS TXT,發佈在 `_dmarc` 子網域:

```text
_dmarc.your-company.com.  IN  TXT
  "v=DMARC1; p=reject; rua=mailto:dmarc@your-company.com; adkim=s; aspf=s; pct=100"
```

- `p=`:處置策略——`none`(只觀察)/`quarantine`(進垃圾匣)/`reject`(直接退)。
- `rua=`:彙整報告(aggregate report)寄去哪,這是你後端**唯一能看見「誰在用你網域寄信」**的眼睛。
- `adkim` / `aspf`:對齊模式,`s`=嚴格(網域要完全相同)、`r`=寬鬆(允許組織網域相同的子網域)。

**一句話總結三層分工:SPF 管 IP、DKIM 管簽章與內容完整性、DMARC 管「把前兩者綁到使用者真正看到的 `From:`,並決定通不過時怎麼辦」。少了 DMARC,前兩者擋不住 `From:` 偽造;少了 SPF/DKIM,DMARC 沒有東西可以對齊。**

---

## 三、後端最容易卡住的點:alignment（對齊）

對齊是後端寄信實作的**第一殺手**,因為它牽涉到你**程式碼裡怎麼設 `From`**。

### SPF alignment：`From:` 網域 vs 信封寄件者(Return-Path)網域

很多寄信服務(SES、SendGrid)為了處理退信,會把 **Return-Path 設成它們自己的網域**,例如:

```text
From:        noreply@your-company.com         ← 你設的
Return-Path: bounces+xxx@amazonses.com        ← 服務商預設
```

此時 SPF 對 `amazonses.com` 驗證會 pass(IP 是 SES 的),**但 SPF 的網域(amazonses.com)跟 `From:`(your-company.com)不對齊**,所以 **SPF alignment 失敗**。如果你又**沒設好 DKIM**,DMARC 就只剩 SPF 這條路,結果整封信 DMARC fail → 被 reject。

**後端解法**:在服務商設定「自訂 Return-Path / MAIL FROM 網域」,例如把 Return-Path 設為 `bounce.your-company.com`(一個你擁有、且已加好 SPF 的子網域),SPF 網域就跟 `From:` 組織網域對齊了。

### DKIM alignment：`d=` 網域 vs `From:` 網域

DKIM 對齊要求 `DKIM-Signature` 的 `d=` 跟 `From:` 同組織網域。誤區是用了服務商的**共享簽章網域**:

```text
From: noreply@your-company.com
DKIM d=us-east-1.amazonses.com     ← 服務商代簽，d= 不是你的網域 → 不對齊
```

**後端解法**:在 SES/SendGrid 啟用 **自有網域 DKIM**(俗稱 "domain authentication" / "Easy DKIM"),服務商會給你一組 CNAME(指向它們託管的公鑰),你加進 DNS 後,簽章的 `d=` 就會是 `your-company.com`,DKIM 對齊成立。**這幾乎是每個第一次接寄信服務的後端都會踩的洞:信寄得出去,但因為用的是服務商共享網域,DMARC 永遠 fail。**

---

## 四、後端程式碼:設對 `From` 與 Return-Path

驗證網域是 DNS / 服務商設定層的事,但**後端程式碼也有責任**:`From` 用哪個網域、有沒有讓使用者污染 `From`、Return-Path 有沒有對齊。

### Java：用 SES SDK(v2)指定已驗證的寄件身分

```java
import software.amazon.awssdk.services.sesv2.SesV2Client;
import software.amazon.awssdk.services.sesv2.model.*;

SesV2Client ses = SesV2Client.create();

SendEmailRequest req = SendEmailRequest.builder()
    // From 必須是「已在 SES 完成網域驗證 + DKIM」的網域
    .fromEmailAddress("noreply@your-company.com")
    // 指定自有 Return-Path 網域，讓 SPF 對齊（需先在 DNS 設好該子網域 SPF）
    .feedbackForwardingEmailAddress("bounce@bounce.your-company.com")
    .destination(Destination.builder()
        .toAddresses("alice@example.com")   // 收件人由系統決定，呼應 Day65
        .build())
    .content(EmailContent.builder()
        .simple(Message.builder()
            .subject(Content.builder().data("您的訂單已出貨").charset("UTF-8").build())
            .body(Body.builder()
                .text(Content.builder().data("您好…").charset("UTF-8").build())
                .build())
            .build())
        .build())
    .build();

ses.sendEmail(req);
```

重點:`From` 是**寫死的、已驗證的網域位址**,不是把使用者輸入拼進去。SES 在你完成 domain identity + Easy DKIM 後,會自動用 `d=your-company.com` 簽章。

> 若用 Jakarta Mail 直接走 SMTP(自架 MTA),DKIM 簽章要靠 MTA(Postfix + OpenDKIM 之類)或在程式內用 DKIM 函式庫處理。採用任何第三方 DKIM/寄信函式庫前,記得確認它仍在維護、且你要用的方法真的存在(可用 context7 之類工具核對 API)。

### Go：用 SES SDK 並避免讓使用者控制寄件網域

```go
import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
)

func sendVerified(ctx context.Context, c *sesv2.Client, to, subject, body string) error {
	const fromVerified = "noreply@your-company.com"          // 已驗證網域，寫死
	const bounceDomain = "bounce@bounce.your-company.com"     // 自有 Return-Path，對齊 SPF

	_, err := c.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress:             aws.String(fromVerified),
		FeedbackForwardingEmailAddress: aws.String(bounceDomain),
		Destination: &types.Destination{ToAddresses: []string{to}},
		Content: &types.EmailContent{
			Simple: &types.Message{
				Subject: &types.Content{Data: aws.String(subject), Charset: aws.String("UTF-8")},
				Body: &types.Body{
					Text: &types.Content{Data: aws.String(body), Charset: aws.String("UTF-8")},
				},
			},
		},
	})
	return err
}
```

`From` 由常數決定,使用者輸入只進 body / 收件人(且收件人要驗證,見 Day65)。**永遠別讓請求參數決定 `From` 的網域**——那等於把冒名權交出去。

---

## 五、SES / SendGrid 最常見的設定誤區

```text
[ ] 只做了「單一信箱驗證」就上線
    → 單一 email 驗證只能寄/收，不會自動設 DKIM、不會對齊。
      正式環境要做「網域驗證 + Easy DKIM（CNAME）」。

[ ] 用服務商共享的 Return-Path / 共享 DKIM 網域
    → SPF/DKIM pass 但「不對齊」，DMARC 照樣 fail。
      要設「自訂 MAIL FROM 子網域」+「自有網域 DKIM」。

[ ] DMARC 直接上 p=reject，沒先 p=none 觀察
    → 漏設的合法寄件來源（CRM、報表系統、第三方）全被退，
      自己把自己的信擋掉。應先 p=none 收 rua 報告，盤點乾淨再升級。

[ ] SPF 用 ~all 或 +all
    → ~all 軟性、+all 等於不設防。穩定後用 -all。

[ ] SPF 超過 10 次 DNS lookup（PermError）
    → include 串太多會 PermError，等同 SPF 失效。精簡 include / 用 flattening。

[ ] 多個寄件來源只設了其中一個的 DKIM
    → 行銷信走 SendGrid、交易信走 SES，兩邊都要各自的 DKIM selector。
```

把這份當上線前 checklist 過一遍,能擋掉九成「信進垃圾匣 / 被退」的事故。

---

## 六、驗證測試(後端可自動化)

別等收件人抱怨才知道設錯。**寄一封信給自己,看 raw header** 是最快的驗證:

```text
收信後看原始檔（"顯示原始郵件"），確認三行都 pass：
  Authentication-Results: mx.google.com;
    spf=pass   (... domain of bounce.your-company.com ...)
    dkim=pass  header.d=your-company.com           ← d= 必須是你的網域
    dmarc=pass (p=REJECT ... header.from=your-company.com)
```

三個重點:`dkim` 的 `header.d=` 要是**你的網域**(不是服務商的)、`dmarc=pass`、`header.from` 對齊。

可程式化的回歸測試:

```text
1) CI 定期對「對外寄信網域」做 DNS 斷言：
   - dig TXT your-company.com           含 v=spf1 且結尾 -all
   - dig TXT _dmarc.your-company.com     含 v=DMARC1 且 p 非 none（正式環境）
   - dig CNAME <selector>._domainkey.your-company.com  存在
2) 寄一封測試信到一個能讀 raw 的收件匣（或用 SES SNS 事件），
   斷言 Authentication-Results 三項皆 pass、dkim header.d 對齊。
3) 持續解析 rua 彙整報告，對「DMARC fail 卻宣稱你網域」的來源告警
   → 可能是被冒名，也可能是漏設的內部系統。
```

> 第 3 點的 rua 報告是後端**唯一的全域視野**:它會告訴你「全世界有哪些 IP 正用你的網域寄信、各自 SPF/DKIM 過不過」。上 `p=reject` 之前,務必靠它把合法來源盤乾淨。

---

## 七、一句話總結

> SPF / DKIM / DMARC 要一起看:**SPF 授權寄件 IP(驗信封寄件者)、DKIM 用簽章保證內容完整與網域授權(驗 `d=`)、DMARC 把前兩者「對齊」到使用者真正看到的 `From:` 並決定處置。** 後端最常死在 **alignment**——信寄得出去,卻因為用了服務商共享的 Return-Path / DKIM 網域,DMARC 永遠 fail。解法是:`From` 用已驗證網域且寫死、設自訂 MAIL FROM 子網域對齊 SPF、啟用自有網域 DKIM 對齊 `d=`、DMARC 先 `p=none` 靠 `rua` 盤點再升 `p=reject`。Day65 是「別讓你的後端被注入」,今天是「別讓你的網域被冒名」——兩道一起做,寄信功能才算真的安全。

---

## 延伸閱讀

- Day65 Email Header Injection——「別被注入」;本篇「別被冒名」,同一條 email 安全主線的兩端。
- Day19 TLS / Cryptographic Failures——傳輸層加密;本篇是寄件身分驗證,層次不同但互補。
- Day35 Subdomain Takeover——若 `bounce.` / `_domainkey.` 等子網域的 DNS 被接管,SPF/DKIM 信任鏈會被反過來利用。
- Day17 Rate Limiting——寄信端點仍要限流,避免被當垃圾信機器(即使網域驗證做滿)。

---

明天預告:**Day 67 — Open Redirect（開放重新導向）入門:從「網域被冒名」回到應用碼層,談 `?redirect=`/`?next=` 這類「信任使用者給的跳轉目標」如何被濫用成釣魚與 OAuth token 竊取的跳板**
(這是一篇**全新主題**。延續本週「冒名 / 釣魚」的氛圍,但 sink 換回你的應用程式:會用後端情境示範登入後跳轉、OAuth `redirect_uri`、簡訊/Email 內的追蹤連結如何因為「只比對開頭字串」或「allowlist 寫太鬆」而被繞過,並給 Java(Spring)與 Go 的安全跳轉白名單實作、以及為什麼 `startsWith` 比對是經典陷阱。)
