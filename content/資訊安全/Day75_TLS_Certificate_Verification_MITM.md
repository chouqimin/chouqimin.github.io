---
title: "Day 75：TLS 憑證驗證失誤與中間人攻擊（延伸篇，承 Day19 TLS × Day74 mTLS）— 後端作為 TLS client 的驗證破口、InsecureSkipVerify / 全信任 TrustManager 與主機名驗證"
date: 2026-07-15
tags: ["TLS", "MITM", "Certificate", "TLS Client"]
---

# Day 75：TLS 憑證驗證失誤與中間人攻擊

接續 Day74 預告：Day74 談的是**你的 server 端**握手成本（別人來連你，你怎麼被握手 DoS）。今天換一個視角——**當你的後端「主動對外」發 TLS 請求時**（呼叫其他微服務、下游 API、寄 webhook、抓遠端資源），憑證驗證**關掉或做錯**會怎樣。答案是：你親手打開一條**中間人（MITM）通道**，而且最可怕的是——**「本機測得過、上線也不會噴錯」**，因為錯誤的做法正是「把會噴錯的那道防線關掉」。

> **這是一篇延伸篇。** 我**不會**重講 Day19 的 TLS 基礎（TLS 是什麼、握手怎麼走、cipher 怎麼選、敏感資料怎麼保護）——那些看 Day19。也**不會**重講 Day74 的 server 端握手成本。這篇只聚焦一個很窄但極常見的破口：**後端作為 TLS client 時，「憑證鏈驗證」與「主機名驗證」這兩件事被關掉或做錯，如何變成 MITM**，以及 Go / Java 正確的 `RootCAs` / 信任鏈 / 主機名驗證寫法與 pinning 的取捨。

為什麼這值得單獨寫？因為 Day74 講的是「別人 DoS 你」，這篇講的是「**你自己把自己交出去**」。mTLS（Day74）保護的是「誰能連進來」，但**你打出去的每一個 HTTPS 請求，安全性完全取決於你這端有沒有好好驗對方的憑證**。而現實是：這是後端最常見、最容易被 code review 放過、CI 也測不出來的高危反例之一。

---

## 一、先建立心智模型：TLS client 驗的是「兩件事」，不是一件

很多人以為「TLS 有沒有驗憑證」是一個開關。錯。**後端作為 client，握手時要驗的是兩件獨立的事，少做任何一件都等於門戶洞開：**

| 驗證項目 | 在問什麼 | 關掉它會怎樣 |
|---|---|---|
| **① 憑證鏈驗證（chain / trust）** | 這張憑證是不是由「我信任的 CA」一路簽下來、且沒過期？ | 攻擊者拿**任何自簽憑證**都能冒充對方 |
| **② 主機名驗證（hostname / identity）** | 這張（縱使合法的）憑證，是不是簽給「我正要連的那個 host」？ | 攻擊者拿**他自己合法網域的憑證**就能冒充你的目標 |

**這兩件事必須「都」成立，TLS 才真的證明「我連到的就是我想連的那台」。** 這正是很多災難的根源：

- 只做 ① 不做 ②：`attacker.com` 有一張完全合法、public CA 簽的憑證。你連 `payments.internal`，攻擊者把流量導到 `attacker.com`，鏈驗證過關（憑證是真的），但**它不是你要連的 host**。沒做主機名驗證 = 被騙。
- ① ② 都不做（例如 Go 的 `InsecureSkipVerify=true`）：**任何人**用**任何自簽憑證**都能當你的對端。這是最徹底的敞開。

記住這句話：**憑證驗證 = 鏈驗證 AND 主機名驗證。少一個，TLS 的「身分保證」就整個歸零，加密再強也只是「跟攻擊者加密通話」。**

---

## 二、為什麼「本機測得過」正好是陷阱：關驗證的動機學

幾乎所有這類漏洞都不是惡意，而是**為了解決一個開發期的摩擦**：

1. 內部服務 / 測試環境用的是**自簽憑證**或**內部 CA 簽的憑證**，不在系統信任庫裡。
2. 後端打過去 → JSSE 噴 `SSLHandshakeException: unable to find valid certification path`，Go 噴 `x509: certificate signed by unknown authority`。
3. 時間壓力下，最快「讓它動」的做法：**把驗證關掉**（`InsecureSkipVerify=true` / 全信任 `TrustManager` / `HostnameVerifier` 回傳 true）。
4. 本機通了、測試綠了、PR 過了。**因為你關掉的，正是那道「會噴錯」的防線。**
5. 上線。這條「暫時」的關閉留在生產環境，變成一條永久的 MITM 通道。

**這就是為什麼這個 bug 特別毒：正確的做法會讓程式在憑證有問題時「大聲失敗」；錯誤的做法讓它「安靜地永遠成功」——包含成功地跟攻擊者通話。** Code review 若只看「功能有沒有動」，永遠抓不到。

**正確的心態：** 自簽 / 內部 CA 憑證的問題，答案永遠是「**讓 client 多信任那張特定的 CA**」，**不是**「叫 client 什麼都信 / 什麼都不驗」。下面兩節就是把這個原則落地。

---

## 三、Go：反例與正解（`crypto/tls` + `net/http`）

### 反例：`InsecureSkipVerify: true`

```go
// 反例：為了「跳過自簽憑證」直接關掉驗證 —— 一條敞開的 MITM 通道。
// InsecureSkipVerify 會「同時」關掉①鏈驗證與②主機名驗證兩件事。
client := &http.Client{
    Transport: &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true, // ← 生產環境出現這行，等於沒有 TLS 身分保證
        },
    },
}
resp, _ := client.Get("https://payments.internal/charge") // 任何人都能冒充 payments.internal
```

`InsecureSkipVerify` 這個名字已經在跟你喊「不安全」。它**唯一**該出現的地方是「一次性本機 debug 腳本」，且**不該進版控**。

### 正解：把內部 CA 加進信任庫，其餘驗證照常

```go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// newInternalCAClient 回傳一個「額外信任內部 CA」但其餘驗證完全正常的 client。
// 關鍵：我們是「多信任一張 CA」，不是「關掉驗證」。
func newInternalCAClient(caPEM []byte) (*http.Client, error) {
	// 從系統信任庫複製一份，再「疊加」內部 CA —— 這樣既能連公開網站也能連內部服務。
	// 若你只打內部服務、想收斂信任面，也可以改用 x509.NewCertPool() 只放內部 CA。
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if ok := pool.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("append internal CA failed（PEM 格式不對？）")
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12, // 承 Day19；能收斂到 1.3 更好
		RootCAs:    pool,             // ← 只多信任這張 CA，①鏈驗證仍照常
		// 注意：ServerName「不要」手動設。留空時，http.Transport 會依請求 URL 的 host
		// 自動帶入並做②主機名驗證。手動寫死 ServerName 會讓所有請求都拿它去比對，通常是錯的。
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg},
		Timeout:   10 * time.Second, // 承 Day72，別讓對外請求無限拖
	}, nil
}

func main() {
	caPEM, err := os.ReadFile("/etc/corp/internal-ca.pem")
	if err != nil {
		panic(err)
	}
	client, err := newInternalCAClient(caPEM)
	if err != nil {
		panic(err)
	}
	resp, err := client.Get("https://payments.internal/charge")
	if err != nil {
		// 憑證有問題時「大聲失敗」正是我們要的：這代表 MITM 或設定錯，不該默默放過。
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)
}
```

### 進階：真的需要自訂驗證邏輯時，用 `VerifyConnection`「把兩件事都做回來」

有時你需要更細的控制（例如做 pinning，見第五節），但**千萬不要**把「自訂」誤解成「用 `InsecureSkipVerify` 然後只檢查一點點」。一旦設了 `InsecureSkipVerify`，**內建的①②驗證都被關掉，你必須在 `VerifyConnection` 裡「自己把①②都做完整」**，少做一件就是漏洞：

```go
cfg := &tls.Config{
	// 關掉「內建」驗證，改由下面完整重做（這不是「不驗」，是「換自己驗」）。
	InsecureSkipVerify: true,
	VerifyConnection: func(cs tls.ConnectionState) error {
		// ① 自己做鏈驗證
		opts := x509.VerifyOptions{
			Roots:         pool,
			Intermediates: x509.NewCertPool(),
			DNSName:       cs.ServerName, // ② 用 SNI/目標 host 做主機名驗證，別漏掉！
		}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
			return err
		}
		// （可在此加 pinning 等額外檢查，見第五節）
		return nil
	},
}
```

Go 專屬要點：

- **`InsecureSkipVerify` 是「①②一起關」的總開關**，不是「只關鏈驗證」。看到它 = 兩件事都沒了。
- **`RootCAs` 只影響①**；②的主機名驗證由 Transport 依 URL host 自動做，前提是你**沒有**設 `InsecureSkipVerify`、也沒把 `ServerName` 亂寫。
- **不要全域改 `http.DefaultTransport` / `http.DefaultClient`。** 用**專屬 client**，避免把「多信任內部 CA」擴散到整個 process 的所有請求（含第三方套件）。
- **`VerifyPeerCertificate` vs `VerifyConnection`**：兩者都在你需要自訂時可用；`VerifyConnection` 拿得到完整 `ConnectionState`（含 `ServerName`），做 pinning / 主機名比對更順手。

> 版本提醒：`VerifyConnection` 於 Go 1.15 加入；`tls.Config` 欄位語意隨版本演進。上線前以你實際使用的 Go 版本文件確認欄位存在與行為，別假設。

---

## 四、Java：反例與正解（JSSE / `HttpClient`）

### 反例：全信任 `TrustManager` + 停用 `HostnameVerifier`

```java
// 反例一：全信任 TrustManager（checkServerTrusted 空實作 = ①鏈驗證整個作廢）
TrustManager[] trustAll = new TrustManager[]{
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] c, String a) {}
        public void checkServerTrusted(X509Certificate[] c, String a) {} // ← 空 = 什麼都信
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }
};
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, trustAll, new SecureRandom());

// 反例二：停用主機名驗證（②整個作廢）
HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
```

這兩段是網路上「解決 SSLHandshakeException」搜尋結果的常客，也是無數 App / 後端 MITM CVE 的根因。**只要看到 `checkServerTrusted` 是空的、或 `HostnameVerifier` 直接 `return true`，就是紅燈。**

### 正解：自訂 truststore 只信任內部 CA，保留主機名驗證

```java
import javax.net.ssl.*;
import java.net.http.HttpClient;
import java.nio.file.*;
import java.security.KeyStore;
import java.time.Duration;

public final class InternalTlsClient {

    public static HttpClient build(Path trustStoreP12, char[] password) throws Exception {
        // 1) 載入「只含內部 CA」的 truststore（不是全信任，也不是關驗證）
        KeyStore trust = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(trustStoreP12)) {
            trust.load(in, password);
        }

        // 2) 用標準 TrustManagerFactory 初始化 —— ①鏈驗證邏輯照走，只是信任錨換成我們指定的
        TrustManagerFactory tmf =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trust);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);

        // 3) Java 11+ HttpClient 預設就會做 HTTPS 端點識別（②主機名驗證）——
        //    我們什麼都不用「關」，保持預設即安全。
        return HttpClient.newBuilder()
                .sslContext(ctx)
                .connectTimeout(Duration.ofSeconds(10)) // 承 Day72
                .build();
    }
}
```

> 注意：上面的 truststore **只信任內部 CA**。若同一個 client 還要打公開網站，需把內部 CA **加進系統 `cacerts` 的副本**，或用「先問系統預設 TrustManager、失敗再問內部 TrustManager」的**複合 / 委派 TrustManager**——而不是退回去用全信任。

### 特別提醒：直接用 `SSLSocket` 不會自動做主機名驗證

`HttpsURLConnection` 與 `java.net.http.HttpClient` **預設會**做主機名驗證。但如果你**手動建 `SSLSocket` / `SSLEngine`**（自寫協定、某些 gRPC/Netty 情境），**預設只做①鏈驗證、不做②主機名驗證**——這是 JSSE 一個經典的沉默陷阱，害過很多人：

```java
// 陷阱：raw SSLSocket 少了這段 = 只驗鏈不驗主機名 → 合法憑證即可 MITM
SSLParameters params = sslSocket.getSSLParameters();
params.setEndpointIdentificationAlgorithm("HTTPS"); // ← 少這行就是洞
sslSocket.setSSLParameters(params);
```

Java 專屬要點：

- **空的 `checkServerTrusted` = 關①**；**`HostnameVerifier` 回 true = 關②**。兩者都是紅燈。
- **正解是換 truststore，不是換掉驗證邏輯。** 用 `TrustManagerFactory` 走標準 PKIX 驗證，只把「信任誰」換成你的內部 CA。
- **`HttpClient` / `HttpsURLConnection` 預設安全**，別為了「相容」去清掉 endpoint identification。
- **raw `SSLSocket`/`SSLEngine` 要顯式 `setEndpointIdentificationAlgorithm("HTTPS")`**，否則②沒做。
- **別把系統屬性 `-Dcom.sun.net.ssl.checkRevocation` 之類與「憑證有效性」混為一談**——那是撤銷檢查，不是本篇的鏈/主機名驗證。

> 版本提醒：`SSLParameters` / `HttpClient` / `TrustManagerFactory` 的預設演算法與行為隨 JDK 版本演進（1.8 與 21 在預設 endpoint identification、TLS 版本協商上就有差異）。以你實際使用的 JDK 版本官方文件為準確認。

---

## 五、憑證釘選（pinning）的取捨：該不該再往上鎖一層？

做對了③④（鏈 + 主機名）之後，還有一個進階問題：**你信任的是「一整個 CA 體系」——只要任何一個被你信任的 CA 誤發（或被駭）出一張你目標網域的憑證，MITM 就能過關。** 憑證釘選（certificate pinning）就是把信任面**再收窄**到「**就是這把公鑰 / 這張憑證**」，不接受「別的 CA 也簽得出來的合法憑證」。

**pinning 的取捨（本篇只談要不要、怎麼權衡；落地實作留到 Day76）：**

- **釘什麼？** 建議釘 **SPKI（公鑰）的雜湊**，而不是整張憑證。這樣**憑證到期換發、只要沿用同一把金鑰，pin 就不會失效**；釘整張憑證則每次換發都得改 pin。
- **一定要有 backup pin。** 釘一把你**離線保管的備援金鑰**。否則主金鑰一旦要輪替（或私鑰外洩要緊急換），你會**把自己鎖死**——這正是瀏覽器端 HPKP（HTTP Public Key Pinning）被廢棄的原因：太多站台把自己 pin 到掛掉。
- **後端對後端 pinning 比瀏覽器可行。** 因為**你同時掌握兩端與輪替節奏**，可以在換金鑰時同步更新 pin。對「固定、高價值」的對端（自家微服務走內部 CA、金流供應商）特別值得。
- **什麼時候別 pinning？** 打「很多第三方、各自獨立輪替憑證」的對象時，pinning 會讓你天天追著別人的憑證更新跑，維運成本 > 安全收益。
- **pinning 不是拿來取代①②的。** 它是**疊加**在鏈 + 主機名驗證**之上**的額外一層，不是「反正我 pin 了就可以 `InsecureSkipVerify`」——那又繞回第三節的反例了。

一句話：**pinning 是「把信任面從『一堆 CA』收到『這把金鑰』」的加固，代價是把「憑證輪替」變成「可能害你停機的操作」，所以 backup pin 與輪替流程是它的命門。**

---

## 六、交叉 Day10 SSRF / Day39 DNS Rebinding：關驗證會讓 SSRF 更好打

這裡把本篇和 Day10 SSRF、Day39 DNS Rebinding 接起來，因為它們**會互相放大**：

- **SSRF 的防線常假設「TLS 能證明我連到的是對的 host」。** 你做了 egress allowlist、擋了內網 IP，但如果**憑證驗證被關掉**，攻擊者只要能把你的請求**導向他控制的端點**（on-path、或 Day39 的 DNS rebinding 把 host 解析到攻擊者 IP），你這端**照樣握手成功**，因為你「什麼憑證都信」。**TLS 本該是 SSRF 之後的最後一道「你到底連到誰」的身分確認，關掉它等於把這道確認也送給攻擊者。**
- **DNS rebinding（Day39）+ 關驗證 = 絕配。** 攻擊者先讓 host 解析到合法 IP 過你的 allowlist，握手瞬間 rebind 到內網 / 攻擊者 IP；若你有好好驗憑證，對方拿不出「那個 host」的合法憑證會**握手失敗**——這是**免費的一道防線**。一旦 `InsecureSkipVerify` / 全信任，這道防線也沒了。
- **反過來說**：**正確驗憑證，本身就是 SSRF / rebinding 的一層縱深防禦。** 這也是為什麼「為了跳過自簽憑證而全域關驗證」危害遠不只「這一條連線」——它同時削弱了你其他安全機制的地基。

**結論：憑證驗證不是孤立的 TLS 細節，它是「你連到的到底是不是你以為的那台」的最終裁決，和 egress 控制、DNS pinning 是同一套防線的不同環節。**

---

## 七、常見誤區（reject list）

| 誤區 | 為什麼錯 |
|---|---|
| 「反正有加密（HTTPS），不驗憑證也還好」 | 不驗身分 = 跟**攻擊者**加密通話。加密 ≠ 驗身分。 |
| 「內網流量不用驗，反正在防火牆內」 | 內網也有橫向移動、被入侵的鄰居、DNS rebinding。零信任的前提就是**內網也驗**。 |
| 「我 pin 了憑證，所以可以 `InsecureSkipVerify`」 | pinning 是**疊加**不是**取代**；關掉①②後你得自己把它們做回來，否則主機名 / 鏈根本沒驗。 |
| 「`HostnameVerifier return true` 只是關主機名，鏈還有驗，應該安全」 | 只做①不做② = 攻擊者用**自己合法網域**的憑證就能冒充你的目標。②不可省。 |
| 「測試環境關驗證沒差，反正不是生產」 | 關驗證的程式碼**很容易被複製 / 沿用到生產**；且測試環境也可能有真資料。用**內部 CA truststore** 而非關驗證。 |
| 「直接用 `SSLSocket` 就有 TLS 安全」 | raw `SSLSocket` **預設不做主機名驗證**，要顯式 `setEndpointIdentificationAlgorithm("HTTPS")`。 |
| 「全域把內部 CA 塞進 `http.DefaultTransport` 比較方便」 | 會擴散信任面到整個 process；用**專屬 client** 收斂範圍。 |

---

## 八、後端 Code Review / 測試 checklist

```text
[ ] 全庫 grep 過危險關驗證寫法？
    Go:   InsecureSkipVerify\s*:\s*true
    Java: checkServerTrusted 空實作、HostnameVerifier ... return true、
          setEndpointIdentificationAlgorithm(null)、setDefaultHostnameVerifier
[ ] 自簽 / 內部 CA 的正解是否為「加進 truststore / RootCAs」而非「關驗證」？
[ ] 是否確認①鏈驗證與②主機名驗證「兩者都在」？（少一個都算漏）
[ ] Go：是否用專屬 http.Client，而非全域改 DefaultTransport/DefaultClient？
[ ] Go：若用 VerifyConnection/VerifyPeerCertificate，是否把鏈驗證「與」主機名驗證都做回來？
[ ] Java：是否用 TrustManagerFactory 走標準 PKIX，而非自訂全信任 TrustManager？
[ ] Java：raw SSLSocket/SSLEngine 是否顯式 setEndpointIdentificationAlgorithm("HTTPS")？
[ ] pinning（若有）：是否為「疊加」在①②之上？是否釘 SPKI 而非整張憑證？是否備有 backup pin 與輪替流程？
[ ] 對外請求是否設連線 / 讀取 timeout（承 Day72）？
[ ] 是否理解「關驗證會放大 SSRF/DNS rebinding」（承 Day10/Day39）？
[ ] 憑證驗證失敗是否「大聲失敗 + 告警」（承 Day16），而不是被 catch 掉默默重試 / 降級？
```

測試建議：

- **反例回歸測試**：起一個**用自簽憑證**的假 server，斷言你的 client 對它**握手失敗**（`x509: unknown authority` / `SSLHandshakeException`）。若「成功」了，代表驗證被關掉——這條測試就是防止有人偷偷加 `InsecureSkipVerify` 的守門員。
- **主機名不符測試**：拿一張**簽給別的 host** 的合法憑證架 server，client 連它應**握手失敗**（驗證②有生效）。這條專門抓「只關主機名驗證」的漏網之魚。
- **正例測試**：用內部 CA 簽、且主機名正確的憑證，斷言 client **握手成功**——確認你是「多信任內部 CA」而非「什麼都信」。
- **raw socket 測試（Java）**：若專案有手建 `SSLSocket` 的路徑，加一條「主機名不符應被拒」的測試，抓 `setEndpointIdentificationAlgorithm` 漏設。
- **CI grep gate**：把上面的危險 pattern 加進 CI 靜態掃描（承 Day18 的依賴 / 程式碼治理），出現即擋 PR。

---

## 九、一句話總結

> Day74 是 server 端被握手 DoS；**本篇換視角到後端「作為 TLS client」——你打出去的每個 HTTPS 請求，安全性取決於你有沒有驗對方憑證，而驗證是「①鏈驗證 AND ②主機名驗證」兩件事，少一件 TLS 的身分保證就歸零**。最常見的高危反例是**為了跳過自簽憑證而關驗證**（Go `InsecureSkipVerify=true`、Java 空的 `checkServerTrusted` / `HostnameVerifier return true`），它之所以毒是因為**關掉的正是「會噴錯」的防線**，於是本機測得過、上線變成一條敞開的 MITM 通道。正解永遠是**「讓 client 多信任那張特定 CA」**（Go 疊加 `RootCAs`、Java 用 `TrustManagerFactory` 載入內部 CA truststore），而不是關驗證；raw `SSLSocket` 記得顯式 `setEndpointIdentificationAlgorithm("HTTPS")`。**pinning** 是疊加在①②之上、把信任收窄到「這把公鑰」的加固，命門是 backup pin 與輪替流程。最後別忘了**關驗證會放大 SSRF / DNS rebinding（Day10/Day39）**——正確驗憑證本身就是「你到底連到誰」的最後一道縱深防線。

---

## 延伸閱讀

- Day19 TLS / Cryptographic Failures——本篇的入門前傳（TLS 是什麼、加密失誤、安全 API 呼叫）。
- Day74 mTLS / TLS 握手 DoS——server 端視角；本篇是同一枚硬幣的 client 端反面。
- Day10 SSRF——關驗證會讓 SSRF 更好打；正確驗憑證是 SSRF 的一層縱深防禦。
- Day39 DNS Rebinding——rebind + 關驗證是絕配；好好驗憑證能免費擋掉一部分 rebinding。
- Day26 Webhook Security——出站 webhook 也是後端當 TLS client，同樣要驗對端憑證。
- Day15 Secrets Management——truststore / 私鑰 / pin 對應金鑰的保管與輪替。
- Day16 Security Logging / Monitoring——憑證驗證失敗要「大聲失敗 + 告警」，別被默默 catch。
- Day18 Supply Chain / Dependencies——把「關驗證」的危險 pattern 納入 CI 靜態掃描守門。

---

明天預告：**Day 76 — 憑證釘選（Certificate Pinning）落地實作（延伸篇，承 Day75）**
（Day75 只談了 pinning 的「要不要、怎麼權衡」；Day76 把它做出來：如何用 SPKI 公鑰雜湊算出一個 pin、為什麼釘公鑰而非整張憑證、backup pin 怎麼設、pin 輪替流程長怎樣。程式面會示範 **Go 在 `VerifyConnection` 裡比對 `RawSubjectPublicKeyInfo` 的 SHA-256**、**Java 用委派式 `X509TrustManager` 在標準 PKIX 驗證「之後」再加 pin 檢查**（保留①②不取代），以及為何 backend-to-backend pinning 可行、瀏覽器 HPKP 卻走向廢棄——重點放在「**pinning 最大的風險是把自己鎖死**」的營運面，這是延伸篇，不重講 Day75 的鏈 / 主機名驗證基礎。）
