---
title: "Day 76：憑證釘選（Certificate Pinning）落地實作（延伸篇，承 Day75）— SPKI pin 怎麼算、Go VerifyPeerCertificate 與 Java 委派式 TrustManager 的疊加寫法、backup pin 與輪替 SOP"
date: 2026-07-16
tags: ["TLS", "Certificate Pinning", "SPKI", "Key Rotation"]
---

# Day 76：憑證釘選（Certificate Pinning）落地實作

接續 Day75 預告：Day75 第五節只談了 pinning 的**「要不要、怎麼權衡」**——今天把它**做出來**。從「一個 pin 到底是哪串 base64、怎麼算」開始，到 Go / Java 的正確疊加寫法，最後是這整件事真正的難點：**pin 輪替 SOP**。

> **這是一篇延伸篇。** 我**不會**重講 Day75 的憑證驗證基礎（①鏈驗證 AND ②主機名驗證、`InsecureSkipVerify` 為什麼是災難、內部 CA 的正解是加 truststore），也**不會**重講 Day75 已經講完的 pinning 取捨論述（為什麼釘 SPKI 而非整張憑證、為什麼一定要 backup pin、HPKP 為什麼被廢棄、backend-to-backend 為什麼比瀏覽器可行）。那些看 Day75。這篇只聚焦**實作與營運**：**pin 的計算、程式碼怎麼寫才是「疊加」而不是「取代」、輪替流程的順序、以及怎麼避免把自己鎖死**。

為什麼「落地」值得單獨一篇？因為 pinning 是少數**「觀念聽懂了，做下去還是會出事」**的題目。它的 bug 不在理解，而在兩個地方：**一是程式碼寫成「關掉內建驗證再自己 pin」**（於是①②沒了，比不 pin 更慘）；**二是輪替順序搞反**（於是憑證換上去的那一秒，全公司的服務同時對不上 pin）。這兩個坑，下面各佔一半篇幅。

---

## 一、先講清楚：pin 到底是「什麼東西的雜湊」

Day75 說「釘 SPKI」，但 SPKI 是什麼、從哪裡拿？這是實作第一個卡點。

**SPKI = Subject Public Key Info**，是 X.509 憑證裡的一個 DER 編碼結構，內容是**演算法識別碼 + 公鑰本身**：

```text
SubjectPublicKeyInfo ::= SEQUENCE {
    algorithm         AlgorithmIdentifier,   -- 例如 rsaEncryption / id-ecPublicKey
    subjectPublicKey  BIT STRING             -- 公鑰位元組
}
```

**一個 pin = 這段 DER 位元組的 SHA-256，再 base64。** 就這樣。

重點是**它取的範圍**：不是整張憑證（不含序號、效期、簽發者、簽章），**只有「公鑰」這件事**。這正是 Day75 說「憑證到期換發、只要沿用同一把金鑰，pin 就不會失效」的機制原因——換發只改了憑證的其他欄位，SPKI 這段位元組**一字不變**。

> 這個「SHA-256(SPKI) 再 base64」的格式不是我發明的，它就是 HPKP（RFC 7469）定義的 pin 格式，也是各家工具（openssl 教學、行動端 pinning 函式庫、`Public-Key-Pins` 標頭）通用的表示法。你在網路上看到的 `pin-sha256="AAAA...="` 就是這個東西。

### 用 openssl 算：三種來源

**(A) 從線上的 server 直接抓（最常用，先確認你 pin 對了東西）**

```bash
# 注意 -servername：SNI 要帶對，否則你抓到的是預設 vhost 的憑證，pin 錯人
openssl s_client -connect payments.internal:443 -servername payments.internal < /dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64
# 輸出範例：YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=
```

**(B) 從一張憑證檔算（CI 裡驗證用）**

```bash
openssl x509 -in leaf.pem -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64
```

**(C) 從一把「還沒簽成憑證」的私鑰算 —— 這是 backup pin 的關鍵**

```bash
# backup key 只是一把離線保管的私鑰，還沒拿去簽任何憑證，
# 但它的「未來憑證」的 SPKI 已經確定了 —— 所以現在就能算出 pin。
openssl pkey -in backup.key -pubout -outform der \
  | openssl dgst -sha256 -binary \
  | base64
```

**(C) 是整個 pinning 能運作的支點，值得停一下：** backup pin 之所以做得到「先讓 client 信任、之後才啟用」，正是因為 **pin 只綁公鑰**。你今天產一把 backup key 鎖在保險庫，算出它的 pin 發佈給所有 client；三個月後緊急要換金鑰時，拿它去簽一張新憑證上線——**client 早就認得它了，不用改一行程式**。

如果你 pin 的是整張憑證的雜湊，這招**完全做不到**（憑證還沒簽出來，雜湊算不了）。這就是 Day75 說「釘 SPKI 不釘憑證」的實作層意義。

### 三個實作前必須決定的問題

| 問題 | 選項 | 建議 |
|---|---|---|
| **pin 鏈上哪一張？** | leaf / intermediate CA / root CA | 見下方 |
| **pin set 裡有幾個？** | 至少 2（現用 + backup） | **絕對不能只有 1 個** |
| **匹配規則？** | 鏈上「任一張」命中即通過 vs「只看 leaf」 | 見下方 |

**pin 哪一張的取捨：**

- **pin leaf 的 SPKI**：信任面最窄（就是這把金鑰），安全性最高，但**綁定最緊**——對端一換金鑰你就斷。適合**你自己掌握的服務**（自家微服務、內部 CA 簽的對端）。
- **pin intermediate CA 的 SPKI**：對端 leaf 憑證怎麼換發都不影響，只要它還是同一家 CA 的同一條中繼簽的。**信任面 = 那張中繼底下所有憑證**（比「全部 CA」窄得多，比「這把金鑰」寬）。適合**第三方對端**（金流供應商、你管不到輪替節奏的服務）。
- **pin root CA**：幾乎等於「自訂 truststore」（Day75 已經教過怎麼做），額外收益有限。**如果你只是想「只信任內部 CA」，那不是 pinning，那是換 truststore——用 Day75 的做法就好，別把 pinning 拿來做這件事。**

**匹配規則**：本篇範例採「**鏈上任一張憑證的 SPKI 命中 pin set 即通過**」（HPKP 也是這個語意）。它的好處是同一份 pin set 可以混放 leaf pin 與 intermediate pin，過渡期更平滑；代價是**你的信任面是 pin set 裡「最寬的那一個 pin」**——放了一張 intermediate pin，就等於接受那張中繼底下的一切。**別在 pin set 裡放一個你其實不想要的寬 pin 然後以為自己很安全。**

---

## 二、鐵律：pinning 是「疊加」，程式碼長相就該是疊加

Day75 已經講過原則（pinning 疊加在①②之上，不是取代）。這裡講**這個原則在程式碼裡長什麼樣**，因為這是實作最容易寫錯的一步。

**判斷一段 pinning 程式碼對不對，只要問一個問題：**

> **「內建的憑證驗證，還在跑嗎？」**

- 如果你**沒有**動 `InsecureSkipVerify` / 沒有換掉 TrustManager 的驗證邏輯，只是**多掛一個 callback 做 pin 比對** → **對**。①②照跑，pin 是額外一層。
- 如果你**關掉內建驗證**再自己 pin → **錯**（除非你把①②完整重做，見 Day75 第三節——但你沒有理由這樣做）。

**為什麼「關掉再 pin」特別毒？** 因為它**看起來更嚴格**（「我都 pin 死那把金鑰了，還要驗什麼鏈？」），實際上**你放棄了效期檢查、撤銷檢查、鏈完整性、主機名驗證**。舉個具體的：只 pin 不驗鏈 = **那把金鑰對應的憑證過期了、被撤銷了，你照樣接受**。pin 比對的是「公鑰位元組相同」，它**不知道**這張憑證的效期與撤銷狀態。

記住這句話：**pin 回答的是「是不是這把金鑰」，①②回答的是「這張憑證是不是有效、是不是簽給這個 host」。這是三個不同的問題，你需要全部三個答案。**

好消息是：Go 與 Java **都提供了「在標準驗證之後才被呼叫」的擴充點**——用對了，疊加是預設行為，你根本不用關任何東西。

---

## 三、Go 實作：`VerifyPeerCertificate`（不要碰 `InsecureSkipVerify`）

Day75 為了示範「自訂驗證要把①②做回來」，用了 `InsecureSkipVerify: true` + `VerifyConnection` 的組合。**做 pinning 時不要那樣寫。** 正確的做法是：**`InsecureSkipVerify` 保持 false（預設），只掛 `VerifyPeerCertificate`。**

關鍵在 `crypto/tls` 對這個 callback 的定義：

```go
// VerifyPeerCertificate 在「一般憑證驗證完成之後」被呼叫。
// 當 InsecureSkipVerify 為 false 時，verifiedChains 會是「已經通過①鏈驗證的鏈」；
// 主機名驗證②也已經由 Transport 依 URL host 做完。
// 這個 callback 回傳 error 就中止握手 —— 這正是我們要的「疊加」擴充點。
VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
```

**注意 `verifiedChains`**：它只有在**標準驗證已經跑過且通過**時才會有內容。也就是說——**如果你看到 `verifiedChains` 是空的，那代表 `InsecureSkipVerify` 被打開了**，這本身就是一個該炸掉的訊號。下面的程式碼把這件事寫成防呆。

### 完整範例

```go
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

// spkiPin 回傳一張憑證的 SPKI pin（SHA-256 → base64），
// 與 `openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64` 等價。
//
// 關鍵：RawSubjectPublicKeyInfo 就是憑證裡「SubjectPublicKeyInfo」那段原始 DER，
// 不含序號/效期/簽發者/簽章 —— 所以憑證換發、只要金鑰沿用，pin 不變。
func spkiPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// makePinVerifier 產生一個「疊加在標準驗證之上」的 pin 檢查 callback。
//
// pins：至少要兩個 —— 現用金鑰的 pin ＋ 離線保管的 backup key pin（承 Day75）。
// 只放一個 = 金鑰一輪替就把自己鎖死。
func makePinVerifier(pins map[string]struct{}) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		// 防呆：verifiedChains 為空，代表標準驗證沒跑（InsecureSkipVerify 被打開了）。
		// pinning 是疊加不是取代 —— 這種情況必須失敗，不能「反正我有 pin」就放行。
		if len(verifiedChains) == 0 {
			return fmt.Errorf("pinning: 沒有已驗證的憑證鏈（InsecureSkipVerify 被打開了？）拒絕連線")
		}

		// 掃「已通過驗證的鏈」上的每一張憑證，任一張的 SPKI 命中 pin set 即通過。
		// 只想釘 leaf 的話，把內層迴圈換成只看 chain[0]（信任面更窄，但綁定更緊）。
		for _, chain := range verifiedChains {
			for _, cert := range chain {
				if _, ok := pins[spkiPin(cert)]; ok {
					return nil // 命中：①②已過 ＋ pin 也對
				}
			}
		}

		// 沒命中：可能是對端換了金鑰（你的 pin 過期了 = 營運事故）
		// 也可能是 CA 誤發 / MITM（= 資安事件）。兩者都必須「大聲失敗 + 告警」（承 Day16）。
		return fmt.Errorf("pinning: 憑證鏈中沒有任何一張命中已知 pin（對端換金鑰？或憑證誤發？）")
	}
}

func newPinnedClient(pins []string) *http.Client {
	set := make(map[string]struct{}, len(pins))
	for _, p := range pins {
		set[p] = struct{}{}
	}

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12, // 承 Day19
		// ★ 這裡「沒有」InsecureSkipVerify —— 預設 false，①鏈驗證與②主機名驗證照常跑。
		//   pin 只是掛在後面的額外一關。這就是「疊加」在程式碼裡的長相。
		VerifyPeerCertificate: makePinVerifier(set),
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg},
		Timeout:   10 * time.Second, // 承 Day72
	}
}

func main() {
	// pin set 從「組態」來，不是硬編（見第六節：硬編 = 緊急時要重新編譯部署才能救）
	client := newPinnedClient([]string{
		"YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=", // 現用金鑰
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // backup key（離線保管，尚未啟用）
	})

	resp, err := client.Get("https://payments.internal/charge")
	if err != nil {
		panic(err) // 憑證/pin 有問題就大聲失敗，別 catch 掉默默降級
	}
	defer resp.Body.Close()
	fmt.Println(resp.Status)
}
```

### 順手寫一支「印出對端 pin」的小工具

輪替與除錯時你會一直需要它（等同上面的 openssl 一長串，但不用背）：

```go
// go run pinprint.go payments.internal:443
func printPins(addr, serverName string) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		ServerName: serverName, // SNI 要帶對，否則抓到別的 vhost 的憑證
		MinVersion: tls.VersionTLS12,
		// 這是「觀測工具」，仍然不關驗證：你想看的是「正常連線會拿到什麼」。
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	for i, cert := range conn.ConnectionState().PeerCertificates {
		role := "intermediate"
		if i == 0 {
			role = "leaf"
		}
		fmt.Printf("[%d] %-12s subject=%s\n     pin-sha256=%s\n     notAfter=%s\n",
			i, role, cert.Subject, spkiPin(cert), cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}
```

**Go 專屬要點：**

- **`VerifyPeerCertificate` 在標準驗證「之後」跑**（前提是 `InsecureSkipVerify` 為 false）。這是「疊加」的正解位置，**不需要**也**不應該**關掉內建驗證。
- **`VerifyConnection` 也可以做 pinning**（拿得到完整 `ConnectionState`），語意上同樣是「標準驗證之後」。差別是 `VerifyPeerCertificate` 直接給你 `verifiedChains`，做「鏈上任一張」比對更順手；`VerifyConnection` 給的是 `cs.PeerCertificates`（對端送來的鏈，**未必等於已驗證的鏈**）與 `cs.VerifiedChains`。**要 pin 就對 `VerifiedChains` 比對，不要對 `PeerCertificates` 比對**——後者是「對方說的」，前者是「驗過的」。
- **`RawSubjectPublicKeyInfo` 是 `x509.Certificate` 上的欄位**，直接給你那段 DER，不用自己 marshal 公鑰。（別用 `x509.MarshalPKIXPublicKey(cert.PublicKey)` 繞一圈——結果通常一樣，但多一次編碼就多一個出錯機會。）
- **pin 比對用 map / 常數時間？** pin 是**公開資訊**（任何人連上 server 都能算出來），不是秘密，所以**這裡不需要 constant-time 比較**（Day32 講的 timing attack 適用於「比對秘密」的場景，例如 HMAC 簽章）。用 map 查表即可。
- **每個對端一組 pin、一個專屬 client**。別把 pin 掛到 `http.DefaultTransport`（承 Day75）——那會讓整個 process 的所有請求都被同一組 pin 檢查，第一個打公開網站的第三方套件就會爆炸。

> 版本提醒：`VerifyPeerCertificate` 與 `VerifyConnection` 的呼叫時機與 `verifiedChains` 的填充語意由 `crypto/tls` 定義，隨版本演進。上線前以你實際使用的 Go 版本官方文件確認欄位存在與行為，別假設。

---

## 四、Java 實作：委派式 `X509ExtendedTrustManager`

Java 這邊的擴充點是 TrustManager，但**有一個必須講清楚的坑**。

### 先看正解

```java
import javax.net.ssl.*;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Set;

/**
 * PinningTrustManager：委派式 TrustManager。
 *
 * 設計要點（這就是「疊加」在 Java 的長相）：
 *   1. 先把 checkServerTrusted 「原封不動」交給 JDK 預設的 delegate → ①鏈驗證照跑
 *   2. delegate 沒丟例外，才輪到我們做 pin 比對 → pin 是額外一關
 *   3. 繼承 X509ExtendedTrustManager 並委派「全部」多載 → ②主機名驗證（endpoint identification）不會掉
 *
 * 反例對照（承 Day75）：checkServerTrusted 空實作 = 關①。這裡我們一行都不省，只在後面「加」。
 */
public final class PinningTrustManager extends X509ExtendedTrustManager {

    private final X509ExtendedTrustManager delegate;
    private final Set<String> pins; // 至少 2 個：現用 + backup

    public PinningTrustManager(X509ExtendedTrustManager delegate, Set<String> pins) {
        if (pins == null || pins.size() < 2) {
            // 防呆：只有一個 pin = 輪替時把自己鎖死（承 Day75）。直接不給你啟動。
            throw new IllegalArgumentException("pin set 至少要有現用 pin 與 backup pin");
        }
        this.delegate = delegate;
        this.pins = Set.copyOf(pins);
    }

    /**
     * spkiPin：getPublicKey().getEncoded() 對 X.509 憑證回傳的就是
     * SubjectPublicKeyInfo 的 DER 編碼 —— 與 openssl 那串管線等價。
     */
    static String spkiPin(X509Certificate cert) throws CertificateException {
        try {
            byte[] spki = cert.getPublicKey().getEncoded();
            byte[] sum = MessageDigest.getInstance("SHA-256").digest(spki);
            return Base64.getEncoder().encodeToString(sum);
        } catch (Exception e) {
            throw new CertificateException("計算 SPKI pin 失敗", e);
        }
    }

    private void checkPins(X509Certificate[] chain) throws CertificateException {
        for (X509Certificate cert : chain) {
            if (pins.contains(spkiPin(cert))) {
                return; // 命中
            }
        }
        // 不命中 = 對端換金鑰（營運事故）或誤發/MITM（資安事件），都要大聲失敗＋告警（承 Day16）
        throw new CertificateException("pinning: 憑證鏈中沒有任何一張命中已知 pin");
    }

    // ---- server 端驗證：三個多載都是「先委派、後 pin」，一個都不能漏 ----

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType); // ① 標準 PKIX 驗證，失敗直接丟出
        checkPins(chain);                            // 疊加：pin
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        delegate.checkServerTrusted(chain, authType, socket); // 這個多載才會做②端點識別
        checkPins(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        delegate.checkServerTrusted(chain, authType, engine); // 同上（NIO/Netty 路徑）
        checkPins(chain);
    }

    // ---- client 端驗證：我們不改行為，原樣委派（mTLS server 端才會用到）----

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        delegate.checkClientTrusted(chain, authType, socket);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        delegate.checkClientTrusted(chain, authType, engine);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }
}
```

### 組起來

```java
import javax.net.ssl.*;
import java.net.http.HttpClient;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Set;

public final class PinnedClientFactory {

    public static SSLContext sslContext(Set<String> pins) throws Exception {
        // 1) 取 JDK 預設 TrustManager（trust store = null 代表用系統 cacerts）
        //    要換成內部 CA truststore 的話，把 null 換成你的 KeyStore（承 Day75）
        TrustManagerFactory tmf =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((java.security.KeyStore) null);

        X509ExtendedTrustManager base = null;
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509ExtendedTrustManager x) {
                base = x;
                break;
            }
        }
        if (base == null) {
            throw new IllegalStateException("找不到 X509ExtendedTrustManager");
        }

        // 2) 用我們的委派式 TrustManager 包起來 —— 標準驗證在裡面照跑
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{ new PinningTrustManager(base, pins) }, new SecureRandom());
        return ctx;
    }

    public static HttpClient build(Set<String> pins) throws Exception {
        // Java 11+ HttpClient 預設會做 HTTPS 端點識別（②）—— 我們沒有關掉它，保持預設即安全
        return HttpClient.newBuilder()
                .sslContext(sslContext(pins))
                .connectTimeout(Duration.ofSeconds(10)) // 承 Day72
                .build();
    }
}
```

### 那個坑：`X509TrustManager` vs `X509ExtendedTrustManager`

網路上大量 pinning 範例是實作 `X509TrustManager`（只有兩個 `checkServerTrusted` 多載、沒有 `Socket` / `SSLEngine` 版本）。**問題在於：②主機名驗證（endpoint identification）是在「帶 `Socket` / `SSLEngine` 的多載」裡做的。** 你實作的若是陽春版 `X509TrustManager`，JSSE 只能拿到不帶連線資訊的多載——**它沒有辦法從你的 TrustManager 得知這次連線的目標 host**。

JDK 對這種情況會自行包一層 wrapper 來補做端點識別，所以未必真的破功。但**這是實作細節、隨版本演進，而且「我的 pinning 有沒有意外關掉主機名驗證」是你最不想賭的事**。

**結論很簡單：直接繼承 `X509ExtendedTrustManager`，把六個多載全部委派給 delegate，事情就沒有模糊空間。** 這不多寫幾行，卻省掉一整類「我明明加強了安全性，結果反而弱化了②」的災難。

**Java 專屬要點：**

- **`getPublicKey().getEncoded()` 對 X.509 憑證就是 SPKI 的 DER**，與 openssl 管線等價，不用自己拆 ASN.1。
- **一定要先 `delegate.checkServerTrusted(...)` 再比 pin。** 順序反過來（先 pin 再委派）雖然最終結果一樣，但**萬一有人日後把 delegate 那行註解掉「debug 一下」，你的程式碼看起來還是有在驗**——把標準驗證放在第一行，它被拿掉時最顯眼。
- **繼承 `X509ExtendedTrustManager`，六個多載全委派**（見上）。
- **`MessageDigest` 不是 thread-safe**，別把 instance 當欄位共用（上面每次 `getInstance` 是刻意的）。
- **Java 1.8 沒有 `java.net.http.HttpClient`**：改用 `HttpsURLConnection.setSSLSocketFactory(ctx.getSocketFactory())` 或你的 HTTP 函式庫的 SSLContext 注入點。**注意 1.8 的 `HttpsURLConnection` 預設會做主機名驗證**（別去清掉它，承 Day75）；若走 raw `SSLSocket`，一樣要顯式 `setEndpointIdentificationAlgorithm("HTTPS")`——**pinning 不會幫你補上②**。

> 版本提醒：`X509ExtendedTrustManager` 的多載呼叫時機、JSSE 對非 extended TrustManager 的包裝行為、預設端點識別設定，在 JDK 1.8 與 21 之間有差異。以你實際使用的 JDK 版本官方文件為準確認，別跨版本沿用結論。

---

## 五、真正的難點：pin 輪替 SOP（順序錯了就是停機）

程式碼寫對只是入場券。**pinning 的事故率九成來自輪替。** Day75 已經說「backup pin 是命門」——這節講**具體的順序**。

### 鐵律：pin set 先擴張，憑證後更換，最後才收縮

**pin set 與 server 憑證是兩個「分別部署」的東西，它們的更新順序決定你會不會停機。**

```text
【正確順序】（client pin set 永遠是「超集合」）

階段 0  client pins = {A, B}          server 用 A          ← 穩定態（B 是離線 backup）
        ─────────────────────────────────────────────────
階段 1  client pins = {A, B, C}       server 用 A          ← 先把「下一把 backup」C 加進去
        （產生新 backup key C，離線保管，只發佈它的 pin）
        ★ 等到「所有 client 實例」都部署完成才能往下走
        ─────────────────────────────────────────────────
階段 2  client pins = {A, B, C}       server 換用 B        ← 現在才換憑證。B 早就在 pin set 裡
        ★ 觀察：全部流量都走 B、pin 失敗率為 0
        ─────────────────────────────────────────────────
階段 3  client pins = {B, C}          server 用 B          ← 最後才把 A 移除（收縮）
        ─────────────────────────────────────────────────
        回到穩定態：現用 B、backup C。下一輪重複。
```

**反過來做會發生什麼：** 你先把 server 憑證換成 B、才要去更新 client 的 pin set——**中間那段時間，所有 client 的 pin 都對不上，全部握手失敗**。而且這是**分散式的**：你有 40 個 client 服務、跨 3 個團隊、有些一週才部署一次。**server 換憑證是「一秒生效」，client 更新 pin set 是「一週的事」——這個時間差就是你的停機時間。**

**這就是 Day75 說「pinning 最大的風險是把自己鎖死」的具體長相。** 它不是抽象風險，它是一個很好懂的**順序問題**：

> **加 pin 可以慢慢來（超集合不會壞任何東西），移除 pin 與更換憑證必須等所有 client 都準備好。**

### 三個讓 SOP 落地的實務要求

**(1) pin set 必須是「可以獨立於程式碼更新」的組態**

如果 pin 硬編在原始碼裡，那「加一個 backup pin」＝ 改 code → PR → build → 部署 → 全服務滾動更新，這條路徑可能要幾天。**緊急換金鑰（私鑰外洩）的場景你沒有幾天。**

pin set 應該放在**組態系統**（config service / K8s ConfigMap / 環境變數），能夠**不重新編譯就更新**。

**但注意：pin set 是「安全控制的組態」——能改它的人 = 能解除你的 pinning 的人。** 所以：

- 存取控制要跟 secrets 同級（承 Day15）——雖然 pin 本身是公開資訊、不是秘密，但**寫入權限是高權限**。
- pin set 變更要有 audit log 與告警（承 Day16）。**「有人把 pin set 改成空的」必須是一個會叫的事件**，因為那等於偷偷關掉 pinning。
- 程式碼要防呆：**空的 pin set 不該被解讀成「不做 pinning」**——那是一個「設定壞了」的訊號。要嘛啟動失敗，要嘛明確走「未啟用 pinning」的旗標（見下）。

**(2) 先跑 report-only，再開強制**

第一次導入 pinning、或每次改 pin set，都應該先有一段「**只記錄不阻擋**」的觀察期：

```go
// report-only：pin 不命中時「只告警不中斷」，讓你在真的鎖死自己之前先看到數據。
// 導入期與每次 pin set 變更後跑幾天，確認「不命中率 = 0」再切成強制。
func makePinVerifier(pins map[string]struct{}, enforce bool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 {
			return fmt.Errorf("pinning: 沒有已驗證的憑證鏈，拒絕連線") // 這條「永遠」強制，與 report-only 無關
		}
		for _, chain := range verifiedChains {
			for _, cert := range chain {
				if _, ok := pins[spkiPin(cert)]; ok {
					return nil
				}
			}
		}
		// 走到這裡 = pin 不命中
		metrics.PinMismatch.Inc()                       // 承 Day16：這個指標就是你的儀表板
		log.Warn("pin mismatch", "enforce", enforce)    // 別把憑證內容整包倒進 log
		if !enforce {
			return nil // report-only：放行，但你已經知道了
		}
		return fmt.Errorf("pinning: 憑證鏈中沒有任何一張命中已知 pin")
	}
}
```

**注意上面第一個檢查（`verifiedChains` 為空）不受 report-only 影響**——那不是 pin 的問題，那是「①②沒跑」，任何模式下都必須拒絕。**report-only 放寬的只有 pinning 這一層，不能連帶放寬 Day75 的基礎驗證。**

**(3) 承認 kill switch 的兩難，然後做出選擇**

「pin 不命中就中斷」在半夜出事時，你會想要一個能立刻關掉 pinning 的開關。但——**能一鍵關掉 pinning 的開關，就是攻擊者眼中「解除這道防線」的開關**。

務實的取捨：

- **有 kill switch**（切回 report-only），但**改動它需要跟改生產憑證同級的權限 + 雙人審核 + 立即告警**。
- **切 report-only ≠ 關掉 TLS 驗證**。kill switch 只能降級 pinning 這一層，**①②永遠強制**。這樣最壞情況你只是退回「一般 HTTPS」（也就是 Day75 的正解狀態），而不是退回 `InsecureSkipVerify`。
- 如果你的對端是「**你自己掌握輪替節奏**」的自家服務，其實你更需要的不是 kill switch，而是**紀律**：SOP 跑對，就不會需要半夜救火。

---

## 六、你會踩到的實務衝突：ACME 自動換發預設會換金鑰

這是 pinning 落地最常見的「怎麼上線第一天就壞了」。

**現代憑證管理已經全自動了**（ACME / Let's Encrypt / cert-manager），憑證每 60~90 天自動換發一次。問題是：

> **多數 ACME client 在 renew 時「預設會產生一把新的私鑰」。**

新私鑰 = 新 SPKI = **新 pin**。於是你的 pin 每 60 天自動失效一次，**而且沒有人通知你**——直到 client 全部連不上。

**三種處理方式：**

| 做法 | 怎麼做 | 適合 |
|---|---|---|
| **A. 讓換發沿用同一把金鑰** | ACME client 開啟 key reuse 選項（各家名稱不同，例如 certbot 的 `--reuse-key`） | 你掌握 server 端；但**削弱了「定期換金鑰」的好處**，要自己排輪替 |
| **B. 改 pin intermediate CA** | pin 那家 CA 的中繼憑證 SPKI，leaf 怎麼換都不影響 | 對端是第三方 / 你不想管 leaf 節奏；代價是信任面變寬 |
| **C. 把 pin set 更新自動化** | 換發流程「產生新 key → 先把新 pin 推進 pin set → 等 client 全部生效 → 才啟用新憑證」 | 你有成熟的組態發佈管線；**這是第五節的 SOP 自動化版** |

**A 有一個容易被忽略的副作用**：`--reuse-key` 這類選項讓你的**私鑰永遠不換**。「憑證每 60 天換發」給人一種「我有在輪替」的錯覺，但**真正該定期輪替的是金鑰**。開了 key reuse 之後，**你必須自己排一個金鑰輪替的節奏**（用第五節的 SOP），否則那把 key 就是用到天荒地老。

**還有一個很現實的提醒：如果對端在 CDN / 托管 LB 後面，憑證是「他們的」，金鑰輪替節奏你完全管不到。** 這種對端**不要 pin leaf**（隨時會斷），要嘛 pin 到穩定的中繼，要嘛**根本不要 pin**——Day75 講的取捨在這裡就是答案：**維運成本 > 安全收益，就別做。**

---

## 七、常見誤區（reject list）

| 誤區 | 為什麼錯 |
|---|---|
| 「我 pin 了，所以可以 `InsecureSkipVerify` / 空 `checkServerTrusted`」 | pin 不管效期、不管撤銷、不管主機名。關掉①②＝過期/被撤銷的憑證照收（承 Day75） |
| 「pin set 只放現用那一個就好，backup 之後再說」 | 「之後」就是輪替那天，也是停機那天。**只有一個 pin 的 pin set 是定時炸彈**（承 Day75） |
| 「先換 server 憑證，再叫大家更新 pin」 | 順序反了 = 停機。**pin set 先擴張、憑證後更換、最後才收縮** |
| 「pin 硬編在 code 裡最安全，攻擊者改不了」 | 也代表**你自己救不了**。緊急換金鑰時你需要的是分鐘級，不是「改 code → build → 全服務部署」 |
| 「pin set 是設定檔，跟其他設定一樣管就好」 | 寫入權限 = 解除 pinning 的權限。要 audit + 告警（承 Day15/Day16） |
| 「pin set 空的就當作沒啟用 pinning」 | 那是「設定壞了」的訊號，不是「不用檢查」。要嘛啟動失敗、要嘛明確旗標 |
| 「pin 比對要用 constant-time 比較」 | pin 是**公開資訊**（誰都能連上去算），不是秘密。Day32 的 timing 議題適用於比對**秘密**（HMAC），不是這裡 |
| 「上了 ACME 自動換發，pinning 就一勞永逸」 | 多數 ACME client **預設換金鑰** → pin 每 60 天自動失效。見第六節 |
| 「pin 第三方供應商的 leaf 憑證比較嚴格」 | 他們的輪替節奏你管不到，斷線只是時間問題。第三方要嘛 pin 中繼、要嘛別 pin |
| 「pin 不命中 = 一定被 MITM 了」 | 更常見的原因是**對端換了金鑰而你沒跟上**。告警要能區分「營運事故」與「資安事件」，否則會被狼來了淹沒 |
| 「Java 實作 `X509TrustManager` 做 pinning 就好」 | ②端點識別在帶 `Socket`/`SSLEngine` 的多載裡。**繼承 `X509ExtendedTrustManager` 全委派**，別賭 JSSE 的包裝細節 |
| 「pin 到 root CA 收窄了信任面」 | 那幾乎等於自訂 truststore（Day75 就能做）。pinning 的價值在收窄到「這把金鑰 / 這張中繼」 |

---

## 八、後端 Code Review / 測試 checklist

```text
【程式碼：確認是「疊加」不是「取代」】
[ ] Go：pinning 路徑「沒有」設 InsecureSkipVerify？（設了就是取代，紅燈）
[ ] Go：用 VerifyPeerCertificate/VerifyConnection，且比對的是 verifiedChains/VerifiedChains
    而非 PeerCertificates（後者是「對方說的」，未經驗證）？
[ ] Go：verifiedChains 為空時是否「拒絕連線」（代表①②沒跑）？
[ ] Java：是否繼承 X509ExtendedTrustManager 並委派「全部六個多載」？
[ ] Java：checkServerTrusted 是否「第一行」就 delegate.checkServerTrusted(...)，pin 比對在後？
[ ] Java 1.8：raw SSLSocket 是否仍顯式 setEndpointIdentificationAlgorithm("HTTPS")？
    （pinning 不會幫你補②，承 Day75）
[ ] 是否用「專屬 client」而非全域 DefaultTransport / setDefaultSSLSocketFactory？

【pin set：確認不會鎖死自己】
[ ] pin set 是否「至少 2 個」（現用 + 離線保管的 backup）？程式是否對「只有 1 個」防呆？
[ ] pin 是否從組態載入（可不重新編譯就更新），而非硬編？
[ ] pin set 的寫入權限是否受控 + 變更是否 audit/告警（承 Day15/Day16）？
[ ] 空 pin set 是否被當成「設定錯誤」而非「不檢查」？
[ ] pin 釘的是 leaf 還是 intermediate？這個選擇跟對端的輪替節奏是否相符？
[ ] 對端是否在 CDN/托管 LB 後面（憑證非其自有）？若是，是否重新評估「該不該 pin」？

【輪替 SOP：確認順序】
[ ] 是否有書面 SOP：pin set 先擴張 → 全 client 部署完成 → server 換憑證 → 最後收縮？
[ ] backup key 是否離線保管，且 pin 已「預先」發佈給所有 client？
[ ] ACME/自動換發是否會換金鑰？若會，是否已選定第六節的 A/B/C 其中一條路？
[ ] 是否有 report-only 模式，導入與每次 pin set 變更後先觀察？
[ ] kill switch（若有）是否只降級 pinning 一層、①②永遠強制？是否雙人審核 + 告警？

【監控（承 Day16）】
[ ] pin 不命中率是否有指標與告警？（0 是正常值，非 0 就是事件）
[ ] 告警是否能區分「對端換金鑰（營運）」與「誤發/MITM（資安）」？
[ ] 現用憑證的 NotAfter 是否有到期監控？（pin 對了但憑證過期，一樣斷線）
```

**測試建議：**

- **pin 命中正例**：用「pin set 裡的金鑰」簽的憑證起假 server，斷言握手**成功**。
- **pin 不命中反例（守門員）**：用**另一把金鑰**簽、但**由合法 CA 簽發、主機名也正確**的憑證起假 server，斷言 client **握手失敗**。**這條測試是 pinning 的存在證明**——它模擬的正是「CA 誤發一張你網域的合法憑證」，也就是 pinning 唯一要擋的東西。如果這條過了（連上了），你的 pinning 沒有生效。
- **backup pin 測試**：用 **backup key** 簽的憑證起 server，斷言握手**成功**——證明你的 backup pin 真的能救你，**而不是等到緊急換金鑰那天才發現算錯了**。
- **疊加性測試（最重要）**：用「**pin 命中、但憑證已過期 / 主機名不符 / 由不受信任的 CA 簽**」的憑證起 server，斷言 client **握手失敗**。**這條專門抓「有人把 pinning 寫成取代」**——若它通過了，代表①②被關掉了，你的 pinning 反而讓系統比不 pin 更弱。
- **CI pin 一致性檢查**：在 CI 加一步，對**測試環境的對端**跑第一節的 openssl 管線（或第三節的 `printPins`），斷言結果**在 pin set 裡**。憑證要換發前，這條會先在 CI 紅給你看，而不是在生產紅給使用者看。
- **憑證到期預警**：把對端憑證的 `NotAfter` 納入監控。pin 沒過期不代表憑證沒過期。

---

## 九、一句話總結

> Day75 講了 pinning 的取捨，**本篇把它做出來**：一個 pin 就是 **SHA-256(SubjectPublicKeyInfo 的 DER) 再 base64**，因為只綁公鑰，所以憑證換發沿用同金鑰時 pin 不變，也因此**能從一把「還沒簽成憑證」的 backup key 預先算出 pin**——這是 backup pin 之所以可行的支點。實作的鐵律是「**疊加不是取代**」，判準只有一句「**內建驗證還在跑嗎**」：Go **不要碰 `InsecureSkipVerify`**、只掛 `VerifyPeerCertificate` 並比對 `verifiedChains`（為空就代表①②沒跑，必須拒絕）；Java **繼承 `X509ExtendedTrustManager` 全委派六個多載**、`checkServerTrusted` 第一行就交給 delegate 再比 pin（實作陽春版 `X509TrustManager` 會讓②端點識別落入 JSSE 包裝細節的模糊地帶，別賭）。但**真正的難點不在程式碼而在輪替**：順序永遠是「**pin set 先擴張 → 等所有 client 部署完 → server 才換憑證 → 最後才收縮**」，反過來做，server「一秒生效」與 client「一週部署」的時間差就是你的停機時間。所以 pin set 要能**不重新編譯就更新**（但寫入權限要受控 + 變更告警）、導入與變更要先跑 **report-only**、kill switch 只能降級 pinning 這一層而**①②永遠強制**。最後別忘了 **ACME 自動換發預設會換金鑰 = pin 每 60 天自動失效**，你得在「key reuse + 自排輪替」「改 pin 中繼」「pin 更新自動化」之間選一條。**測試裡最關鍵的兩條：pin 不命中要失敗（證明 pinning 生效）、pin 命中但憑證過期/主機名不符也要失敗（證明你寫的是疊加不是取代）。**

---

## 延伸閱讀

- Day75 TLS 憑證驗證失誤與 MITM——本篇的前傳：①鏈驗證 AND ②主機名驗證，以及 pinning 的取捨論述。
- Day19 TLS / Cryptographic Failures——TLS 基礎與 cipher policy。
- Day74 mTLS / TLS 握手 DoS——server 端視角；mTLS client 憑證也可以被 server 端 pin。
- Day15 Secrets Management——backup key 的離線保管、pin set 組態的存取控制與輪替。
- Day16 Security Logging / Monitoring——pin 不命中率是你唯一的儀表板；要能區分營運事故與資安事件。
- Day32 Timing Attack——為什麼 pin 比對**不**需要 constant-time（pin 是公開資訊，不是秘密）。
- Day18 Supply Chain / Dependencies——把 pin 一致性檢查放進 CI 守門。

---

明天預告：**Day 77 — Certificate Transparency（CT）與憑證誤發偵測（新主題）**
（本篇 Day76 的 pinning 是「事前把信任收窄到這把金鑰」，代價是綁死自己的輪替節奏——那如果**不想 pin、或不能 pin**（第六節說的 CDN 後面的第三方對端），怎麼知道有人替你的網域弄到一張合法憑證？Day77 談另一條路：**CT log 是所有公開 CA 簽發憑證的公開帳本，你可以主動去查「誰替我的網域簽了憑證」**。會講 CT 的三方角色（log / monitor / auditor）與 SCT 怎麼被塞進憑證、**為什麼 CT 是「事後偵測」而 CAA record 是「事前預防」**（DNS 裡宣告只有哪家 CA 能簽你的網域），以及後端怎麼把它變成一個會叫的告警。程式面會示範 **Go 用 `net/http` 打 crt.sh 的 JSON API 定期拉自家網域的憑證清單、與「已知憑證的 SPKI 白名單」比對、發現未知簽發者就告警（承 Day16）**，以及 **Java 排程任務做同一件事 + 用 `dig`/DNS 查詢斷言 CAA record 存在的 CI 檢查**，並談監控結果的雜訊治理（子網域萬用憑證、CDN 廠商代簽、內部 CA 不在 CT 裡的盲區）。這是新主題，不重講 Day75/76 的驗證與 pinning。）
