---
title: "Day 78：憑證撤銷的現實（新主題）— CRL 太大、OCSP 太慢、soft-fail 把一切歸零，以及產業為什麼決定用「短效憑證」繞過這個問題"
date: 2026-07-18
tags: ["Certificate Revocation", "OCSP", "CRL", "PKI", "TLS"]
---

接續 Day77 預告：今天你終於偵測到了——CT monitor 叫了，有人替你的網域弄到一張你沒申請過的憑證。你照著直覺做下一步：**打電話給 CA，請他們撤銷它**。

這篇要講的，就是**這個直覺為什麼幾乎不管用**。

不是「流程很慢」那種不管用，是**機制層面上，你撤銷了，攻擊者仍然可以繼續用那張憑證 MITM 你的使用者**，而且他不需要任何高明的手法——他只要**把一個查詢擋掉**就好。

這不是新主題的延伸篇，撤銷本身還沒講過。但它是 Day75（①鏈驗證 AND ②主機名驗證）、Day76（pinning）、Day77（CT/CAA）之後那塊拼圖：前面三天講的是「**這張憑證是不是有效、是不是給這個 host、是不是我授權簽的**」，今天講的是「**這張憑證本來有效，但我後悔了**」——而 PKI 對「後悔」這件事的處理，是整套體系裡設計得最失敗的部分。

---

## 一、為什麼撤銷天生就難：憑證是「離線可驗的簽章」

先把心智模型立好，後面所有的死法都是這個模型的必然結果。

一張 X.509 憑證的本質是：**CA 用私鑰簽的一句話**——「我證明 `example.com` 的公鑰是這一把，效期到 2026-09-01」。

這句話的**最大優點**就是：**驗證它不需要問任何人**。你手上有 CA 的公鑰（在 truststore 裡），拿到憑證就能自己算完驗證，不用連線、不用查詢、不用 CA 在線上。Day75 的①②兩步，全部都是**離線運算**。這正是 PKI 能撐起整個網際網路的原因——CA 不用陪著你握手。

而「撤銷」要做的是：**推翻一句已經簽出去、而且對方離線就能驗證的話。**

這在物理上就是矛盾的。憑證上寫著「效期到 2026-09-01」，這個簽章沒辦法收回，也沒辦法改。你唯一能做的是**在旁邊另外發一個公告**說「那張不算了」——然後**祈禱每個驗證者都會去看這個公告**。

於是整個撤銷機制的核心問題只有一個：

> **怎麼讓「驗證者」在離線就能完成的驗證流程裡，額外去查一個線上狀態——而且查不到的時候要怎麼辦？**

前半段（怎麼查）產生了 CRL 與 OCSP 兩代機制。後半段（查不到怎麼辦）產生了 **soft-fail**，而 soft-fail 把前面所有努力**歸零**。

---

## 二、第一代：CRL——整包下載，然後被自己的體積壓死

**CRL（Certificate Revocation List，RFC 5280）** 是最直覺的做法：CA 定期發佈一份清單，列出所有被撤銷憑證的序號，用 CA 私鑰簽名。憑證裡的 `CRLDistributionPoints` 擴充欄位寫著去哪抓。

```bash
# 看一張憑證的 CRL 發佈點
openssl x509 -in cert.pem -noout -text | grep -A 4 "CRL Distribution Points"
```

驗證流程：抓下 CRL → 驗簽 → 看目標憑證的序號在不在裡面。

概念完美。實務上三個地方死掉：

**死法一：體積是全量的，跟你要驗的那張憑證無關。**
你只想知道「這**一張**憑證有沒有被撤銷」，卻要下載這家 CA **所有**被撤銷憑證的清單。大型公開 CA 的 CRL 動輒數 MB，包含幾十萬筆序號。**你為了 20 bytes 的答案下載了 5 MB。** 而且 Heartbleed（2014）那種事件會讓 CRL 一夜之間膨脹——當時大量憑證被緊急換發並撤銷，CRL 體積直接暴漲，這反而讓依賴 CRL 的驗證者更容易選擇跳過。

**死法二：更新頻率以天計，撤銷的「生效時間」是模糊的。**
CRL 有 `nextUpdate` 欄位，中間的空窗期你手上的快取就是舊的。CA 常見的 CRL 更新週期是**幾小時到七天**。也就是說，就算一切運作正常，**撤銷生效可能要等一週**。而你撤銷憑證的場景（私鑰外洩、CT 抓到誤發）恰好都是**分秒必爭**的場景。

**死法三：抓 CRL 本身是一個對外呼叫，會失敗。**
於是——你猜對了——實作選擇 soft-fail。抓不到就當作沒撤銷。

CRL 現在幾乎不是後端該主動選的路。它在**內部 PKI**（規模小、清單短、你自己控制發佈節奏）還有意義，這一點下面會再提。

---

## 三、第二代：OCSP——把「全量下載」換成「單張查詢」，換來三個新問題

**OCSP（Online Certificate Status Protocol，RFC 6960）** 的想法是：別下載整份清單了，我**問一張**就好。憑證裡的 `Authority Information Access` 欄位寫著 OCSP responder 的 URL。

```bash
# 看 OCSP responder 位置
openssl x509 -in cert.pem -noout -ocsp_uri

# 手動查一次（需要 issuer 憑證）
openssl ocsp -issuer chain.pem -cert cert.pem \
  -url http://r11.o.lencr.org -no_nonce -text
```

回應只有三種狀態：`good` / `revoked` / `unknown`。體積從 MB 降到幾百 bytes。看起來把 CRL 的死法一二都解掉了。

但它換來三個更嚴重的問題：

**問題一：每次握手多一次對外呼叫（延遲 + 可用性）。**
你的後端要連 `api.partner.com`，握手過程中還得先去連 `ocsp.some-ca.com`。這代表：

- **延遲疊加**：一次 TLS 握手變成兩次網路往返鏈路。
- **可用性反轉**：CA 的 OCSP responder 掛掉，**你的服務就連不上你的合作夥伴**。你的可用性被綁在一個你完全不控制的第三方上。這在 2016 年 GlobalSign OCSP responder 誤發設定造成大規模「憑證被撤銷」假警報時，全球一堆網站直接被判死——**撤銷機制自己成了故障來源**。

**問題二：這是 Day74 講的握手 DoS 放大點。**
Day74 講 mTLS 握手 DoS 時提過「放大點三：握手路徑同步查 OCSP/CRL」。現在你知道細節了：**每一次握手 = 一個對外 HTTP 呼叫**。攻擊者只要對你的 mTLS 端點發起握手洪水，就能同時（a）逼你做非對稱運算、（b）逼你對 CA 發起等量的對外查詢——**你變成別人 DoS 上游 CA 的放大器**，然後 CA 對你限速，然後你的握手全掛。

**問題三（後端最該警覺的）：這是 Day10 SSRF 的教科書結構。**
仔細看這個流程：

> 你的程式收到**對方給的憑證** → 從憑證裡**讀出一個 URL** → **主動連線**過去。

**憑證是對方遞過來的資料。AIA 欄位的 URL 是憑證內容的一部分。** 這意味著「對方能影響你的後端去連哪個 URL」——這正是 Day10 SSRF 的定義。實務上這條路被幾件事收住了（AIA 通常只在鏈驗證有進展時才查；標準庫的 OCSP client 有自己的實作限制），但心智模型必須正確：**開啟撤銷檢查 = 你的 TLS 驗證路徑多了一個「連憑證裡寫的 URL」的動作**。所以 Day74 說「mTLS 別在握手路徑同步查撤銷」不只是為了效能。

**問題四：隱私。**
你每查一次 OCSP，就等於告訴 CA「我現在正在連 example.com」。CA 拿到了一份全網瀏覽紀錄。這是 Let's Encrypt 後來把 OCSP 整個關掉的**主要理由之一**。

---

## 四、壓垮一切的東西：soft-fail

前面三節都是效能與工程問題。這一節是**安全問題**，而且它讓前面所有機制的安全價值**歸零**。

問題很簡單：**查不到撤銷狀態的時候，要放行還是要擋？**

- **hard-fail（查不到就擋）**：只要 CA 的 responder 抖一下、使用者在會攔截流量的咖啡廳 Wi-Fi、公司 proxy 擋掉 OCSP 埠——**整個網站打不開**。使用者不會怪 CA，會怪你。
- **soft-fail（查不到就放行）**：一切正常運作，沒有人抱怨。

**所有主流實作都選了 soft-fail。** 瀏覽器選了，作業系統選了，Java 的預設行為實質上也是（下面會看到）。

現在看攻擊者視角。這是整篇文章最重要的一段：

> 你要防的攻擊是「攻擊者拿著一張**被撤銷的憑證**對你的使用者做 MITM」。
> 但**能做 MITM 的攻擊者，本來就在網路路徑上**。
> **在網路路徑上的攻擊者，可以直接把 OCSP 查詢丟掉**（不回應、TCP reset、DNS 給錯答案都行）。
> 於是驗證者查不到撤銷狀態 → soft-fail → **放行**。

**結論：soft-fail 下的撤銷檢查，對「唯一會用到它的那種攻擊者」完全無效。**

這不是實作 bug，是機制的邏輯死結。Adam Langley 那句著名的評語就是在講這件事：**soft-fail 的撤銷檢查像一把「只在你不需要的時候才有用」的安全帶**。平常沒事它會亮綠燈，真的出事的時候攻擊者一伸手就把它關掉了。

而**你不能因此就改用 hard-fail**——上面說了，hard-fail 會把 CA 的每一次抖動變成你的停機。這就是為什麼這個問題**卡了十幾年沒有解**，直到大家決定**繞過它**（第七節）。

---

## 五、OCSP stapling：把成本移回 server，但預設仍然是 soft-fail

**OCSP stapling**（TLS Certificate Status Request 擴充，RFC 6066）的想法很聰明：

> 既然 client 每次都要問 CA「這張憑證還有效嗎」，那**乾脆由 server 自己去問**，把 CA 簽名的回應**夾在握手裡一起送給 client**。

好處一次解掉三個問題：

- **延遲**：client 不用多一次往返，回應直接在握手裡。
- **CA 負載**：從「每個 client 每次握手」變成「每個 server 每幾小時」。
- **隱私**：CA 不再知道誰在連你。

而且 OCSP 回應是 **CA 私鑰簽的**，server 沒辦法偽造，也沒辦法竄改。回應裡有 `thisUpdate` / `nextUpdate`，所以 server 也不能拿一份三年前的 `good` 回應一直重播。

**Day77 的伏筆在這裡收**：Day77 講 SCT 的三種送達方式時，方式 C 就是「OCSP stapling 夾帶」——現在你知道那個管道長什麼樣了。

**但 stapling 沒有解掉 soft-fail。** 關鍵在這句話：

> **stapling 是 server 自願夾帶的。Server 不夾，client 預設也不會有意見。**

所以攻擊者拿著被撤銷的憑證，**只要單純不夾 stapled 回應**，client 就退回「沒有撤銷資訊」的狀態 → soft-fail → 放行。**攻擊者甚至不用擋任何東西，他只要什麼都不做。**

修補這個洞的機制叫 **OCSP Must-Staple**（RFC 7633，憑證裡的 TLS Feature 擴充）：憑證上直接寫死「**我這張憑證，握手時一定會夾 stapled 回應；沒夾就是有問題，請拒絕我**」。這把 soft-fail 變成了針對這張憑證的 hard-fail。

Must-Staple 是**技術上正確的解法**，但**實務上幾乎沒人用**——因為它把「你的 stapling 設定壞掉」直接升級成「**你的網站全站掛掉**」，而 stapling 設定壞掉是常有的事（responder 抖動、快取過期、reload 沒帶到）。**沒人願意用停機風險去換一個攻擊者本來就有很多別的辦法繞過的防護。** Let's Encrypt 甚至在 2025 年停止支援 Must-Staple 擴充。

這就是撤銷這條路的全貌：**每一代機制都在修上一代的問題，但沒有一代解得掉那個邏輯死結。**

---

## 六、後端實際上該怎麼寫：Go 與 Java 的開關到底代表什麼

理論講完，來看你真的能碰到的東西。

### 6.1 Go：`crypto/tls` 預設**完全不做**任何撤銷檢查

這句話請讀三次。**Go 的標準 TLS client 不查 CRL、不查 OCSP、不驗 stapled 回應，一個都沒有。**

`crypto/x509` 的 `Certificate.Verify()` 只做 Day75 的①鏈驗證（加上 `DNSName` 的②主機名驗證）。**沒有任何撤銷語意。** 這是 Go 團隊的明確設計選擇，理由就是第四節那個死結——既然 soft-fail 沒有安全價值，就不要假裝有。

但 Go **會把 server 夾帶的 stapled 回應交給你**，放在 `tls.ConnectionState.OCSPResponse`。要不要理它，**完全是你的事**。

這裡有一個 Day76 讀者一定會踩的坑：**`VerifyPeerCertificate` 拿不到 `OCSPResponse`**（它的簽名只有 `rawCerts` 和 `verifiedChains`）。要看 stapled 回應必須用 **`VerifyConnection`**，它收的是整個 `tls.ConnectionState`。

```go
package tlsrevoke

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// checkStapledOCSP 檢查 server 夾帶的 stapled OCSP 回應。
//
// 定位（很重要）：這是「有夾就必須是 good」的加固，不是完整的撤銷檢查。
// 對方不夾 → cs.OCSPResponse 為空 → 這裡放行（第五節說的 soft-fail 洞還在）。
// 想關掉這個洞只有 Must-Staple 一條路，而它的停機風險見第五節。
// 真正的解法是第七節的短效憑證。
func checkStapledOCSP(cs tls.ConnectionState) error {
	// 防呆：承 Day76。verifiedChains 為空代表 InsecureSkipVerify 被打開了，
	// 標準驗證根本沒跑。這種狀態下驗撤銷毫無意義，直接拒絕。
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return errors.New("tls: no verified chains (InsecureSkipVerify enabled?)")
	}

	if len(cs.OCSPResponse) == 0 {
		// 對方沒夾。這裡「放行」是刻意的選擇，不是忘了寫。
		// 若要 Must-Staple 語意就在這裡 return error，
		// 但請先確認你能承受對端 stapling 抖動 = 你的服務中斷。
		return nil
	}

	chain := cs.VerifiedChains[0]
	leaf := chain[0]

	// OCSP 回應是 issuer 簽的，要驗簽就必須有 issuer 憑證。
	// 鏈長為 1（自簽/直接是 root）時沒有 issuer 可用。
	if len(chain) < 2 {
		return errors.New("tls: stapled OCSP present but no issuer in chain")
	}
	issuer := chain[1]

	// ParseResponseForCert 會做三件事：解析、用 issuer 公鑰驗簽、
	// 確認這份回應講的就是 leaf 這張憑證（防止拿別張的 good 回應來搪塞）。
	resp, err := ocsp.ParseResponseForCert(cs.OCSPResponse, leaf, issuer)
	if err != nil {
		// 解析/驗簽失敗要當錯誤往上丟，不要 return nil 裝沒事。
		// 「有夾但夾了個爛東西」比「沒夾」更可疑。
		return fmt.Errorf("tls: parse stapled OCSP: %w", err)
	}

	// 時效檢查：沒有這段，一份三年前的 good 回應可以無限重播。
	// x/crypto/ocsp 的 ParseResponse 系列不會幫你判斷 now 是否在區間內。
	now := time.Now()
	if now.Before(resp.ThisUpdate) {
		return fmt.Errorf("tls: stapled OCSP not yet valid (thisUpdate=%s)", resp.ThisUpdate)
	}
	if !resp.NextUpdate.IsZero() && now.After(resp.NextUpdate) {
		return fmt.Errorf("tls: stapled OCSP expired (nextUpdate=%s)", resp.NextUpdate)
	}

	switch resp.Status {
	case ocsp.Good:
		return nil
	case ocsp.Revoked:
		// 這是你唯一真正想抓到的情況。
		// 記得告警（承 Day16）——對端憑證被撤銷是事件，不是雜訊。
		return fmt.Errorf("tls: peer certificate REVOKED at %s (reason=%d)",
			resp.RevokedAt, resp.RevocationReason)
	default:
		// Unknown：CA 說「這張我不認得」。對公開 CA 來說這本身就很怪。
		return fmt.Errorf("tls: stapled OCSP status unknown")
	}
}

// NewClient 組出一個「①②照做 + pin（Day76）+ stapled OCSP 加固」的 client。
// 專屬 client，不動 http.DefaultTransport（承 Day75/76）。
func NewClient(pins []string) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// 絕對不要 InsecureSkipVerify。VerifyConnection 是「疊加」不是「取代」，
		// 它在標準驗證跑完之後才被呼叫（承 Day76 的鐵律）。
		VerifyConnection: func(cs tls.ConnectionState) error {
			if err := checkStapledOCSP(cs); err != nil {
				return err
			}
			return checkPins(cs, pins) // Day76 的 SPKI pin 比對，疊在旁邊
		},
	}
	return &http.Client{
		Timeout:   10 * time.Second, // 承 Day72
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

func checkPins(cs tls.ConnectionState, pins []string) error {
	_ = cs
	_ = pins
	return nil // 實作見 Day76
}
```

想**主動**查 OCSP（不靠 stapling）？`x/crypto/ocsp` 也提供 `ocsp.CreateRequest` / `ocsp.ParseResponse` 讓你自己組請求。但請先讀第三節：這會讓你的 TLS 驗證路徑多一個「**連憑證裡寫的 URL**」的動作（Day10 SSRF 結構），而且**每次握手一個對外呼叫**（Day74 握手 DoS 放大點）。**幾乎所有情況下，正確答案都是「別做，去做第七節」。**

> 套件說明：`golang.org/x/crypto/ocsp` 是 Go 官方 `x/crypto` 子模組，目前仍在維護，提供 `CreateRequest` / `ParseResponse` / `ParseResponseForCert` 與 `Good`、`Revoked`、`Unknown` 常數。它**只負責解析與驗簽，不負責時效判斷**——`ThisUpdate` / `NextUpdate` 要自己比，這正是上面那段時效檢查存在的原因。

### 6.2 Java：三個開關，以及那個叫 `SOFT_FAIL` 的 Option

Java 走的是另一條路：JSSE **有**完整的撤銷檢查實作，但**預設關閉**，而且開關散在三個地方。

**開關一（系統屬性，最粗的那顆）：**

```bash
# 開啟 PKIX 撤銷檢查（預設 false = 完全不檢查）
-Dcom.sun.net.ssl.checkRevocation=true

# 讓 client 在握手時送出 status_request 擴充 = 要求對方 staple（Java 9+）
-Djdk.tls.client.enableStatusRequestExtension=true
```

兩個要**一起**開才有意義：`enableStatusRequestExtension` 只是「開口要」，`checkRevocation` 才是「真的檢查」。只開前者，你收到 stapled 回應但**不會拿它做任何判斷**。

> 注意 `enableStatusRequestExtension` 在 **JDK 9 起預設就是 `true`**，但 `checkRevocation` **一直預設 `false`**。所以標準情境是：**你的 Java 服務很可能已經在要 stapled 回應了，然後把它丟掉。**

**開關二（`PKIXRevocationChecker`，你真正該用的那個）：**

系統屬性是全域的、粗糙的，而且**行為是 soft-fail 還是 hard-fail 你控制不了**。要精細控制就用 `PKIXRevocationChecker`（Java 8 起提供）：

```java
import javax.net.ssl.*;
import java.security.cert.*;
import java.util.EnumSet;

public final class RevocationAwareTls {

    /**
     * 建出一個「①②照做 + 撤銷檢查行為明確」的 SSLContext。
     *
     * 定位：這裡示範的是「怎麼把 Java 的撤銷檢查設成你想要的樣子」，
     * 不是「撤銷檢查能救你」。第四節的死結對 Java 一樣成立。
     */
    public static SSLContext build(KeyStore trustStore) throws Exception {

        CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
        PKIXRevocationChecker rc = (PKIXRevocationChecker) cpv.getRevocationChecker();

        rc.setOptions(EnumSet.of(
                // 只檢查 end-entity（leaf）。中繼憑證的撤銷交給 CA 生態去處理，
                // 每張都查 = 鏈有多長就多幾個對外呼叫（Day74 放大點）。
                PKIXRevocationChecker.Option.ONLY_END_ENTITY,

                // 不要 fallback。預設行為是 OCSP 查不到就退回抓 CRL，
                // 那代表「一次握手可能觸發兩種對外呼叫」——延遲與失敗面加倍。
                PKIXRevocationChecker.Option.NO_FALLBACK

                // 刻意不加 SOFT_FAIL：不加 = hard-fail = 查不到就擋。
                // 請務必讀完下面那段再決定要不要加。
        ));

        PKIXBuilderParameters params = new PKIXBuilderParameters(
                trustStore, new X509CertSelector());
        params.setRevocationEnabled(true);      // 沒這行，addCertPathChecker 不會生效
        params.addCertPathChecker(rc);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(new CertPathTrustManagerParameters(params));

        SSLContext ctx = SSLContext.getInstance("TLS");
        // 絕不傳入全信任 TrustManager（承 Day75）
        ctx.init(null, tmf.getTrustManagers(), null);
        return ctx;
    }
}
```

**四個 Option，逐個講清楚它到底代表什麼：**

| Option | 不加（預設） | 加了 | 該不該加 |
|---|---|---|---|
| `SOFT_FAIL` | **hard-fail**：查不到撤銷狀態 → 擋 | **soft-fail**：查不到 → **放行**（例外被吞進 `getSoftFailExceptions()`） | **這是整篇文章的主角，見下方** |
| `NO_FALLBACK` | OCSP 失敗會**再退回抓 CRL** | 只用一種機制，不退回 | **建議加**。fallback = 對外呼叫與延遲加倍 |
| `ONLY_END_ENTITY` | 鏈上**每一張**都查 | 只查 leaf | **建議加**。鏈越深呼叫越多（Day74） |
| `PREFER_CRLS` | 先 OCSP 再 CRL | 順序反過來，先 CRL | 一般不加；內部 PKI 可考慮 |

**`SOFT_FAIL` 這個 Option 是整個 Java PKI API 裡最誠實的一個設計，也是最陷阱的一個。**

它誠實在：Java **強迫你自己選**，而且把選擇寫成一個名字就叫「軟性失敗」的常數。它陷阱在：

- **不加 `SOFT_FAIL` = hard-fail**，於是 CA 的 responder 抖一下，**你的服務就連不上對方**。壓測沒問題，上線第三週某天凌晨全掛。
- **加了 `SOFT_FAIL`**，你就回到了第四節那個死結：**對真正的攻擊者完全無效**，但你在架構圖上多了一個寫著「已啟用撤銷檢查」的框框。**這比不做更糟，因為它是假的安心。**

如果你真的加了 `SOFT_FAIL`，**至少要把被吞掉的例外撈出來記錄**——否則你連「我的撤銷檢查其實從來沒成功過」都不會知道（這正是 Day77 講的「偵測器自己壞掉，跟沒事長得一模一樣」）：

```java
// 握手後（或在自訂 checker 裡）把 soft-fail 吞掉的例外撈出來。
// 這些是「本來該擋、但被你放行」的清單。它不該是空的也不該是滿的——
// 它該是「幾乎是空的」，一旦持續有東西就代表撤銷檢查實質上沒在運作。
for (CertPathValidatorException e : rc.getSoftFailExceptions()) {
    log.warn("revocation check soft-failed (request was ALLOWED): {}", e.toString());
    metrics.counter("tls_revocation_soft_fail").increment();  // 承 Day16
}
```

**Java 1.8 提醒**：`PKIXRevocationChecker` 在 1.8 就有了，可以直接用。但 1.8 **沒有** `java.net.http.HttpClient`，要走 `HttpsURLConnection.setSSLSocketFactory(ctx.getSocketFactory())`；而且 raw `SSLSocket` 仍然**不會**做②主機名驗證，要自己設 `setEndpointIdentificationAlgorithm("HTTPS")`（承 Day75/76——**撤銷檢查補不了②**，這是三個不同的問題）。

---

## 七、瀏覽器怎麼做：他們早就放棄 OCSP 了，改用推播

後端工程師常有的誤解是「瀏覽器都有在查撤銷，所以這機制應該還行」。**不，主流瀏覽器基本上已經不在握手路徑上查 OCSP 了。**

他們的做法是**把方向反過來**：不要在握手時去問，而是**事先把撤銷清單推給 client**。

- **Chrome：CRLSets**——Google 自己彙整「重要的」撤銷（CA 中繼、高影響力事件），壓縮成一份小清單，**透過瀏覽器更新機制推送**。代價是**它不是全量的**，一般網站憑證的撤銷根本不在裡面。
- **Firefox：CRLite**——用 Bloom filter 串把**全量**撤銷狀態壓成幾百 KB 推送，週期性更新。技術上漂亮得多，涵蓋也完整。

這條路解掉了死結：**握手時零對外呼叫（不能被擋、無延遲、無隱私問題），因為答案已經在本機了。**

但對你來說，**這條路後端走不了**：它需要一個持續彙整全球 CT/CRL 資料並推送給幾億個 client 的基礎設施。你的 Java 服務連 `api.partner.com` 時，**沒有人在幫你維護 CRLite**。

所以請把這節記成一個**認知校正**：

> **「瀏覽器有在檢查撤銷」和「你的後端有在檢查撤銷」是完全不同的兩件事，而且前者用的方法你抄不了。**

---

## 八、產業的答案：不修撤銷，改讓憑證活得夠短

十幾年沒解掉的死結，最後的解法是——**繞過它**。

邏輯簡單得近乎粗暴：

> **撤銷之所以是問題，是因為憑證的剩餘效期很長。**
> 如果憑證只剩 3 天就過期，那「撤銷它」和「等它過期」的差別，也就 3 天。
> **把效期壓到夠短，撤銷這個問題就大部分自己消失了。**

而「過期」這件事，**不需要任何線上查詢、不會被攻擊者擋掉、不會 soft-fail**——它就寫在憑證裡，是 Day75 ①鏈驗證的一部分，**離線就驗得掉**。這正是第一節說的「離線可驗」那個優點，繞了一圈回來當解法。

這不是理論，是**已經發生的事**：

- **2025-08-06：Let's Encrypt 的 OCSP 服務正式終止。** 不是降級、不是棄用警告，是**關掉**。在那之前（2025 年 5 月起）新簽的憑證裡就已經**不再包含 OCSP URL**。全球最大的 CA 直接把第二代機制拆掉了，理由是隱私成本與營運成本都不划算，而短效憑證讓它變得沒必要。
- **2026-01-15：Let's Encrypt 的 6 天短效憑證（`shortlived` profile）正式一般可用。** 首張在 2025-02 簽出，現在是所有人都能用的選項。6 天效期的憑證，實務上建議**每 2.5 天換發一次**。
- **CA/B Forum Ballot SC-081v3（2025-04-11 通過）**把公開 TLS 憑證的最長效期排了時程表：

| 生效日 | 最長效期 | 網域驗證資料最長重用期 |
|---|---:|---:|
| 2026-03-15 | **200 天** | 200 天 |
| 2027-03-15 | **100 天** | 100 天 |
| 2029-03-15 | **47 天** | 10 天 |

**注意 2026-03-15 那一列已經生效了**——今天（2026-07-18）你新簽的公開 TLS 憑證，最長就是 200 天。

**這對後端的真正意義，是責任轉移，不是輕鬆了：**

> **撤銷從「一個你依賴 CA 提供、但其實不管用的機制」，變成「你自己的換發管線是否可靠」。**

換句話說，**你不再需要煩惱 OCSP，但你的 ACME 自動換發管線從此是生產基礎設施**——它掛掉三天，你的網站就掛了。**你把一個「假的安全機制」換成了「一個真的維運責任」。** 這是好交易，但它是**交易**，不是免費。

2026-05-08 那次 Let's Encrypt 簽發中斷就是這個新世界的預演：效期越短的憑證，**對換發管線中斷的容忍窗口越小**。用 6 天憑證、每 2.5 天換一次的服務，中斷時只剩幾小時的緩衝。（這正是明天要講的。）

---

## 九、那 CT 叫了到底該怎麼辦？

回到 Day77 結尾那個場景。CT monitor 告訴你有一張你沒申請的憑證。既然撤銷不管用，你的 runbook 是什麼？

**先做分流（這步 Day77 已經教了，別跳過）：**

1. **SPKI 已知** → 你自己的金鑰 → **營運事故**（換 CA/CA 換中繼沒更新組態），不是資安事件。**先確認這個，九成的告警到這裡就結束了。**
2. **SPKI 未知 + issuer 未知** → 疑似誤發 → 往下走。

**真的是誤發時，撤銷要不要申請？要——但要知道它的定位：**

- **申請撤銷**（向 CA 提報，走 CA 的 problem report 管道）。**它的價值不是「立刻阻止攻擊」**，而是：（a）進入 CRLSets/CRLite 這類推播機制，保護**瀏覽器使用者**；（b）**啟動 CA 的稽核程序**——CA 收到誤發報告有 BR 規定的時限要處理，這會留下紀錄，而這正是 Symantec 最後被摘掉根信任的路徑（承 Day77）。**你是在推動生態，不是在關掉那張憑證。**
- **不要把撤銷當成止血手段。** 從你提報到那張憑證對攻擊者失效，中間有 CRLSets 推送週期、有 soft-fail、有一堆根本不查撤銷的 client（**包括你自己家所有的 Go 服務**）。

**真正的止血動作在別的地方：**

| 動作 | 為什麼有效 | 承 |
|---|---|---|
| **確認自家私鑰沒外洩** | 如果是你的金鑰洩漏，撤銷是次要的，**輪替金鑰**才是主線 | Day15 |
| **更新 CAA**，把不該能簽你網域的 CA 全部關掉 | **事前**阻斷同一條路徑再來一次（對「向合法 CA 騙簽」有效） | Day77 |
| **自家 client 上 pinning** | 這是**唯一真的會擋下來**的機制，而且它**不看撤銷** | Day76 |
| **升級 CT monitor 告警等級 + 保留證據** | 誤發是要對 CA 究責的，你需要 log | Day16 |
| **縮短自己憑證效期 / 加速換發** | 降低下一次事件的曝險窗口 | 第八節 |

**注意 pinning 那一列的微妙之處**：Day76 講過「pin 是疊加不是取代——只 pin 不驗鏈，**過期或被撤銷的憑證照收**」。現在你知道那句話的後半段其實是**廢話**了——因為 Go 標準庫**本來就不查撤銷**，「被撤銷的憑證照收」是**預設行為**，跟你有沒有 pin 無關。**pinning 的價值從來不在撤銷，而在於它問的是一個不需要任何線上查詢的問題：「是不是這把金鑰」。** 這也正是它有效的原因——**攻擊者擋不掉一個不存在的查詢。**

---

## 十、常見誤區表

| 誤區 | 現實 |
|---|---|
| 「發現誤發，撤銷掉就沒事了」 | 第四節的死結：能 MITM 的攻擊者能擋掉 OCSP 查詢，soft-fail 直接放行 |
| 「我的 Go 服務會擋掉被撤銷的憑證」 | **`crypto/tls` 完全不做撤銷檢查**，一行都沒有。這是設計選擇不是 bug |
| 「Java 預設有做撤銷檢查」 | `com.sun.net.ssl.checkRevocation` **預設 false**。而 `enableStatusRequestExtension` 預設 true = **你在要 stapled 回應然後丟掉** |
| 「開 `SOFT_FAIL` 比較安全，至少有檢查」 | soft-fail 對唯一會用到它的攻擊者無效。它給你的是**假的安心**和一個架構圖上的框框 |
| 「那就用 hard-fail」 | CA 的 responder 抖一下 = 你停機。你把可用性外包給了一個第三方 |
| 「stapling 解決了 soft-fail」 | 沒有。**攻擊者不夾就好**，什麼都不用做。要補這洞只有 Must-Staple，而它把設定失誤升級成全站停機，所以幾乎沒人用 |
| 「OCSP 是現代做法，CRL 是老東西」 | 兩個都在退場。**Let's Encrypt 已於 2025-08-06 關閉 OCSP 服務**，新憑證裡連 OCSP URL 都沒有 |
| 「瀏覽器有在查 OCSP，所以機制還行」 | 主流瀏覽器早就不在握手路徑查了，改用推播（CRLSets/CRLite）。**而這條路後端抄不了** |
| 「開撤銷檢查只是多一點延遲」 | 每次握手一個對外呼叫 = Day74 握手 DoS 放大點 + Day10 SSRF 結構（**連的是憑證裡寫的 URL**）+ 把 CA 可用性接進你的可用性 |
| 「鏈上每張都查比較嚴謹」 | 鏈有多深就多幾個對外呼叫。用 `ONLY_END_ENTITY` |
| 「短效憑證只是換發頻繁一點」 | 責任轉移：**你的 ACME 管線從此是生產基礎設施**，它掛三天你就掛了 |
| 「憑證效期我還是照習慣簽一年」 | **2026-03-15 起最長 200 天**，2027 剩 100 天，2029 剩 47 天。這已經生效了 |
| 「撤銷檢查可以補主機名驗證」 | 三個不同問題：①憑證有效嗎 ②簽給這 host 嗎 ③被撤銷了嗎。少任何一個另外兩個都補不上（承 Day75/76） |

---

## 十一、Code Review / 維運 checklist

```text
【認知（比程式碼重要）】
[ ] 團隊知不知道 Go crypto/tls 預設完全不查撤銷？
[ ] 團隊知不知道 Java checkRevocation 預設 false？
[ ] 有沒有人在架構文件上寫了「已啟用撤銷檢查」但其實是 soft-fail？
[ ] 有沒有把「撤銷」當成誤發事件的止血手段？（它不是，見第九節）

【如果你決定做 stapled OCSP 加固（Go）】
[ ] 用 VerifyConnection 而非 VerifyPeerCertificate？（後者拿不到 OCSPResponse）
[ ] VerifiedChains 為空是否直接拒絕？（InsecureSkipVerify 防呆，承 Day76）
[ ] 用 ParseResponseForCert 而非 ParseResponse？（確認回應講的是這張憑證）
[ ] ThisUpdate / NextUpdate 有沒有自己比？（不比 = 舊回應可無限重播）
[ ] 「沒夾」的處理是刻意寫的、還是忘了寫？註解有沒有講清楚？
[ ] Revoked 有沒有告警？（承 Day16，這是事件不是雜訊）

【如果你決定開 Java 撤銷檢查】
[ ] checkRevocation 與 enableStatusRequestExtension 是否一起處理？
[ ] 用 PKIXRevocationChecker 明確設 Option，而非只靠系統屬性？
[ ] params.setRevocationEnabled(true) 有沒有寫？（沒寫 checker 不生效）
[ ] SOFT_FAIL 是「刻意選的」還是「預設就這樣」？決策有沒有寫下來？
[ ] 有加 SOFT_FAIL 的話，getSoftFailExceptions() 有沒有被記錄與計數？
[ ] 有沒有加 NO_FALLBACK 與 ONLY_END_ENTITY？（否則呼叫數失控，承 Day74）
[ ] 是不是在 mTLS server 的握手路徑上同步查撤銷？（Day74 明確反對）

【短效憑證與換發（真正的主線）】
[ ] 現行憑證效期是多少？有沒有超過 200 天的？（2026-03-15 起已違反 BR）
[ ] ACME 換發管線有沒有被當成生產基礎設施看待（監控/告警/on-call）？
[ ] 換發失敗有沒有告警，而且是在「還來得及」的時候叫？
[ ] 憑證 NotAfter 到期預警有沒有設？門檻有沒有跟著效期縮短調整？
[ ] 有沒有盤點「不會自動換發」的憑證？（手動簽的、內部 CA 的、埋在 image 裡的）

【內部 PKI】
[ ] 內部 CA 的撤銷怎麼做？（CT 看不到，承 Day77；規模小的話 CRL 反而可行）
[ ] 內部憑證效期能不能也壓短？（你自己是 CA，這件事你說了算）
```

**測試建議：**

- **「撤銷檢查存在證明」（最重要的一條）**：拿一張**已知被撤銷**的測試憑證（`revoked.badssl.com` 之類的公開測試點）連連看，**斷言你的 client 連不上**。**這條測不過，你的撤銷檢查就是裝飾品。** 大多數人第一次跑這個測試時會很驚訝——**Go 的預設 client 會連得上**。
- **soft-fail 行為測試**：把 OCSP responder 的網路擋掉（DNS 給錯答案或防火牆丟包），再連一次。**觀察你的 client 是放行還是拒絕。** 這個結果就是你真實的安全姿態，不是設定檔上寫的那個。
- **stapling 缺席測試**：連一個**不夾 stapled 回應**的 server，斷言你的程式走的是你**預期**的那條路（放行或拒絕），而不是意外路徑。
- **時效重播測試**：餵一份 `NextUpdate` 已經過期的 stapled 回應，斷言被拒絕。沒有這條，重播就是開放的。
- **hard-fail 爆炸半徑測試**（如果你決定用 hard-fail）：模擬 CA responder 完全不可用，**量一下你有多少功能會掛**。這個數字會幫你做決定。
- **CI 憑證效期斷言**：`openssl x509 -noout -enddate` 算出剩餘天數，超過門檻就 CI 紅（承 Day18——**讓它在 CI 紅，不要在生產紅**）。
- **換發演練**：主動讓憑證接近到期，驗證自動換發真的會動。**「從來沒失敗過」跟「從來沒被驗證過」在儀表板上長得一模一樣**（承 Day77）。

---

## 十二、一句話總結

> Day77 的 CT 讓你**看見**誤發，你的直覺下一步是「撤銷它」——**而這篇的重點是這個直覺幾乎不管用**。根因在第一節：憑證的本質是「**CA 簽的一句離線就能驗的話**」，這個優點撐起了整個 PKI，代價是**你沒辦法收回一句已經說出口的話**，只能在旁邊貼公告然後祈禱有人看。**CRL** 貼了張全量清單（為 20 bytes 的答案下載 5 MB、更新以天計、抓不到就 soft-fail）；**OCSP** 改成單張查詢，體積解了但換來**每次握手一個對外呼叫**——延遲疊加、**CA 掛你就掛**、Day74 的握手 DoS 放大點、以及一個標準的 **Day10 SSRF 結構（你的驗證路徑會去連「對方遞來的憑證裡寫的 URL」）**、外加把瀏覽紀錄送給 CA。但真正壓垮一切的是 **soft-fail**：查不到就放行，**而能 MITM 你的攻擊者本來就在網路路徑上，擋掉一個查詢對他是零成本**——所以 soft-fail 的撤銷檢查**恰好對唯一會用到它的那種攻擊者無效**，是一把只在你不需要時才扣得上的安全帶。改 hard-fail？那 CA 抖一下你就停機，你把可用性外包給了第三方。**OCSP stapling** 把查詢成本移回 server（延遲、CA 負載、隱私一次解掉，也是 Day77 SCT 的送達管道 C），但**它沒解 soft-fail**——**攻擊者不夾就好，什麼都不用做**；補這洞的 Must-Staple 技術上正確卻把「stapling 設定壞掉」升級成「全站掛掉」，所以幾乎沒人用。程式面兩句話要記牢：**Go `crypto/tls` 完全不做撤銷檢查**（要看 stapled 回應得用 **`VerifyConnection`**——`VerifyPeerCertificate` 拿不到 `OCSPResponse`，這是 Day76 讀者必踩的坑——再用 `x/crypto/ocsp` 的 `ParseResponseForCert` 驗簽並**自己比 `ThisUpdate`/`NextUpdate`** 否則舊回應可無限重播）；**Java 的 `checkRevocation` 預設 false 而 `enableStatusRequestExtension` 預設 true**——**等於你在跟對方要 stapled 回應，然後把它丟掉**，要精細控制就用 `PKIXRevocationChecker`（`NO_FALLBACK` 與 `ONLY_END_ENTITY` 該加，`SOFT_FAIL` 加不加是**你必須自己承擔的決策**：不加＝CA 抖動害你停機，加了＝回到死結還多一個假的安心，真加了至少把 `getSoftFailExceptions()` 撈出來記錄與計數）。瀏覽器早就放棄這條路，改用**推播**（Chrome CRLSets 只收重要的、Firefox CRLite 用 Bloom filter 壓全量），**握手時零查詢所以擋不掉**——但那需要一套全球基礎設施，**你的後端抄不了**。產業最後的答案不是修撤銷而是**繞過它**：**憑證只剩 3 天就過期時，「撤銷」和「等它過期」的差別也就 3 天**，而「過期」寫在憑證裡、離線就驗得掉、**不會被擋也不會 soft-fail**——繞一圈回到第一節那個「離線可驗」的優點。這已經發生了：**Let's Encrypt 2025-08-06 關閉 OCSP 服務**（新憑證裡連 URL 都沒有）、**6 天短效憑證 2026-01-15 一般可用**、**CA/B Forum SC-081v3 排定 2026-03-15 起最長 200 天 → 2027 剩 100 天 → 2029 剩 47 天（第一階段今天已經生效）**。所以真正的結論是**責任轉移而非輕鬆**：你不用再煩惱 OCSP，代價是**你的 ACME 換發管線從此是生產基礎設施**。最後回到 CT 叫了怎麼辦——**申請撤銷要做，但它的價值是進入瀏覽器推播機制與啟動 CA 稽核究責（Symantec 就是這樣被摘掉根信任的），不是止血**；真正的止血是**確認私鑰沒外洩＋輪替（Day15）、收緊 CAA 事前阻斷（Day77）、自家 client 上 pinning（Day76）**——而 pinning 有效的理由，恰恰是它問的問題（「是不是這把金鑰」）**不需要任何線上查詢，所以攻擊者擋不掉一個不存在的查詢**。

---

## 延伸閱讀

- Day77 Certificate Transparency 與 CAA——本篇的上游：CT 讓你看見誤發，這篇講看見之後為什麼撤銷救不了你；SCT 的送達管道 C 就是 OCSP stapling。
- Day76 憑證釘選落地實作——「疊加不是取代」那句話的後半段在本篇第九節被重新解讀；`VerifyPeerCertificate` vs `VerifyConnection` 的差異。
- Day75 TLS 憑證驗證失誤與 MITM——①鏈驗證 AND ②主機名驗證；撤銷是第三個獨立問題，補不了①②。
- Day74 mTLS / TLS 握手 DoS——「握手路徑同步查 OCSP/CRL」放大點的完整版說明。
- Day10 SSRF——「連憑證裡寫的 URL」為什麼是 SSRF 結構。
- Day72 Slowloris / 慢速 HTTP DoS——對外呼叫一律設 timeout，包括 OCSP 查詢。
- Day16 Security Logging / Monitoring——soft-fail 被吞掉的例外要記錄；「檢查從來沒成功過」跟「沒事」長得一樣。
- Day15 Secrets Management——私鑰外洩時輪替才是主線，撤銷是次要的。
- Day18 Supply Chain / Dependencies——CI gate 哲學：憑證效期讓它在 CI 紅。
- Day19 TLS / Cryptographic Failures——TLS 與 PKI 基礎。

---

明天預告：**Day 79 — ACME 自動換發管線：當憑證只剩 6 天，換發就是生產基礎設施（新主題）**
（Day78 的結論是「短效憑證讓撤銷問題消失」，但它同時把一件事推到了前線：**你的換發管線壞掉，就是你的服務壞掉，而且容錯窗口從「一年」縮到「幾小時」**。Day79 要講這條管線怎麼做才不會半夜叫你起床。會講 **ACME 協定的四個階段**（帳號 → order → 網域驗證 challenge → 取憑證）與 **HTTP-01 / DNS-01 / TLS-ALPN-01 三種 challenge 的安全取捨**——重點是 **DNS-01 為什麼是萬用憑證的唯一選項、又為什麼是三者中權限最危險的（你把 DNS 寫入權交給了換發程式，而 DNS 就是 Day77 CAA 這把鎖所在的地方——能改 DNS 的人可以自己把鎖拆了）**，以及 **RFC 8657 的 `accounturi` / `validationmethods` 怎麼把 CAA 從「哪家 CA 能簽」收緊成「哪個 ACME 帳號用哪種方法能簽」**。程式面示範 **Go 用 `golang.org/x/crypto/acme/autocert` 的正確姿勢與它的三個坑（`HostPolicy` 不設＝幫任何人簽到你被限速、`Cache` 用預設 `DirCache` 在多副本部署下每台各簽一份、以及它不適合放在 LB 後面）**，以及 **Java 世界沒有標準庫等價物的現實**（多數團隊靠 sidecar/cert-manager/前置 LB 換發，而不是在 JVM 裡做）。最後是**維運主線：換發要在剩餘效期的哪個時間點觸發（不是「快到期才換」而是「一開始就換」）、換發失敗的告警要在還來得及的時候叫、憑證 reload 不重啟怎麼做、以及 2026-05-08 Let's Encrypt 簽發中斷那次事故告訴我們的「單一 CA 依賴」風險與 backup CA 該不該做**。這是新主題，不重講 Day78 的撤銷機制與 Day76/77 的 pinning/CT。）
