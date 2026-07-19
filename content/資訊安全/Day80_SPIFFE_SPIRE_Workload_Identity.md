---
title: "Day 80：內部服務的身分與短效憑證（新主題）— SPIFFE / SPIRE、workload identity，以及為什麼「你是誰」的根從網域控制權換成 workload 證明"
date: 2026-07-20
tags: ["SPIFFE", "SPIRE", "Workload Identity", "mTLS"]
---

接續 Day79 預告：Day79 講的 ACME 是「對外服務向公開 CA 自動換發」——你的服務面對公網，向 Let's Encrypt 這種公開 CA 證明「我控制 example.com」然後拿憑證。但你的內網有幾百個微服務要互相 mTLS，它們之間怎麼辦？你不可能替每個服務手動簽憑證，也不該讓它們共用一張長效憑證。今天要接的正是 Day74（mTLS 是內部服務互相驗證身分的手段）與 Day77（內部 CA 是 CT 的盲區）這兩條線：**當「你是誰」不再能用網域控制權來證明時，內部服務的身分該怎麼發、怎麼驗、怎麼自動輪替。**

這是新主題。**不重講 Day79 的 ACME/公開 CA 換發，也不重講 Day74 的 mTLS 握手 DoS**，聚焦在一個 Day79 沒碰的問題：把換發的「信任根」從「你控制哪個網域」換成「你是不是我信任的那個 workload」。你會一直看到前面幾天回來：**SVID 短到極致讓 Day78 的撤銷問題徹底消失**、**SPIFFE ID 比對的不是主機名所以跟 Day75 的 client 端驗證是不同的一組肌肉**、**內部 PKI 用 SPIFFE 自動化正是 Day77 那個盲區的正解**。

---

## 一、先講清楚 SPIFFE 到底在解什麼問題

ACME 解的問題是「怎麼讓機器自動證明它控制某個**網域**」。這在公網很合理——網域是公開、可驗證的資源，CA 靠 HTTP-01 / DNS-01 就能確認你真的握有它。

但把同一套心智模型搬進內網會立刻卡住。你的 `payment-service` 跟 `order-service` 之間要 mTLS，`payment-service` 該用什麼身分？它沒有對外網域。你可以硬給它一個 `payment.internal` 然後跑內部 CA + ACME，但這在問一個錯的問題：**你想確認的不是「這個程序控制某個網域」，而是「這個程序真的是 payment-service，而不是同一台機器上冒充它的惡意程序」。**

SPIFFE（Secure Production Identity Framework For Everyone）解的問題只有一句話：**怎麼給每一個 workload 一個「不需要它自己填任何祕密、可被密碼學驗證、還會自動短效輪替」的身分。** 關鍵字是「不需要它自己填祕密」——傳統做法是塞一個 API key 或憑證檔進去，但那個祕密怎麼安全送進去、怎麼輪替、外洩了怎麼辦，就是 Day15 講的整套 secrets 難題。SPIFFE 的答案是：**workload 不持有任何開機祕密，它的身分是「跑起來之後由平台幫它證明出來的」。**

SPIFFE 是「規格」，SPIRE 是「參考實作」。這跟「ACME 是 RFC 8555、certbot / autocert 是實作」的關係一模一樣。今天講規格心智模型，範例用 SPIRE 當背景。

---

## 二、SPIFFE ID：身分長什麼樣，塞在憑證的哪裡

SPIFFE ID 是一個 URI，格式固定：

```text
spiffe://<trust-domain>/<workload-path>
```

例如：

```text
spiffe://example.org/ns/prod/sa/payment-service
spiffe://example.org/backend/order
```

- **trust domain**（`example.org`）：一整個信任邊界，通常一個組織 / 一個叢集一個。跨 trust domain 要另外做聯邦（federation），不在今天範圍。
- **path**（`/ns/prod/sa/payment-service`）：workload 在這個 trust domain 裡的具體身分，路徑怎麼切是你的命名規則（常見用 namespace / service account 結構）。

這個 URI 具體塞在哪？**塞進 X.509 憑證的 SAN URI 欄位（Subject Alternative Name，type = URI）。** 這件事很重要，因為它直接決定了驗證方式跟 Day75 不一樣：

- Day75 的標準 TLS client 驗證，第②步是**主機名驗證**——比對憑證 SAN 裡的 **DNS name** 跟你要連的 host 一不一致。
- SPIFFE mTLS 比對的是憑證 SAN 裡的 **URI**（也就是 SPIFFE ID），**完全不看主機名、不看 IP**。

裝著 SPIFFE ID 的這張短效憑證有個專有名詞：**SVID（SPIFFE Verifiable Identity Document）**。X.509 形式的叫 X509-SVID，還有 JWT 形式的 JWT-SVID（適合過不了 mTLS 的場景，例如經過 L7 gateway、或 workload 對雲端 API）。今天主線講 X509-SVID。

用 openssl 看一張 X509-SVID，重點在 SAN 那行是 `URI:` 而不是 `DNS:`：

```bash
openssl x509 -in svid.pem -noout -text | grep -A1 "Subject Alternative Name"
# X509v3 Subject Alternative Name:
#     URI:spiffe://example.org/backend/order
```

順帶注意 `Subject` 的 CN 通常是空的——SPIFFE 刻意不把身分放在 CN，就是要逼你別用 CN / 主機名來判斷身分，一切以 SAN URI 為準。

---

## 三、身分的根：從「網域控制權」換成「workload 證明」

這是今天最核心的觀念轉換，也是三大安全主軸的第一條。

Day79 的 ACME，CA 問你的問題是：**「你是不是控制 example.com？」** 你放個 TXT 或 HTTP 檔證明給它看。

SPIRE 問 workload 的問題完全不同：**「你是不是跑在我信任的節點上、你的程序特徵符不符合我登記過的那個 workload？」** 這個過程叫 **attestation（證明）**，分兩層，缺一不可：

**① Node attestation（節點證明）**：先確認「這台跑 SPIRE Agent 的機器」是可信的。SPIRE Agent 開機時要向 SPIRE Server 證明自己跑在哪。證明方式（node attestor）依環境而定——AWS 的 instance identity document、GCP / Azure 的 metadata、Kubernetes 的 projected service account token、或裸機的 join token。Server 驗過之後，才發給 Agent 一張代表「這個節點」的 SVID。

**② Workload attestation（workload 證明）**：節點可信之後，還要回答「來向 Agent 要憑證的**這個程序**，憑什麼相信它就是它宣稱的那個服務，而不是同一台機器上的惡意程序冒領？」這是整套設計最精妙的地方。workload 呼叫 Workload API 時**不帶任何 token、不帶任何祕密**——它只是連上那個 Unix domain socket。SPIRE Agent 反過來去**觀察這個呼叫方的核心層屬性**：透過 socket 的對端拿到呼叫方的 PID，再由 OS 查它的 UID / GID、它的 Kubernetes pod / service account、它的 binary 路徑或 selinux label 等等（這些叫 workload attestor / selector）。Agent 拿這些特徵去比對登記項（registration entry），符合才發對應的 SVID。

為什麼這比「塞一個祕密進去」強？因為**沒有祕密可偷**。傳統做法裡，那個 API key / 憑證檔一旦被同機的惡意程序讀到就完蛋（Day15）。SPIFFE 這裡，冒充者就算連上了 socket，它的 PID 對應的 UID / pod 特徵對不上登記項，Agent 就不會發憑證給它。**身分的根不是「你持有什麼祕密」，而是「你是什麼、你跑在哪」——後者偷不走。**

一句話對照：

> ACME 問「你控制哪個網域」（你出示對網域的控制權）；SPIRE 問「你是什麼、跑在哪」（平台觀察你的核心層特徵，你什麼都不用出示）。

---

## 四、Go 實作：用 go-spiffe 拿 SVID、掛進 mTLS

Go 這邊用官方的 `github.com/spiffe/go-spiffe/v2`。核心是兩個套件：`workloadapi`（跟 Agent 拿 SVID 並持續更新）與 `spiffetls/tlsconfig`（把 source 包成 `*tls.Config`）。

> 註：本文範例依 go-spiffe v2 的公開 API 撰寫。此排程環境未連上 context7，無法即時對套件版本做函式簽章核對；正式導入前請對照你鎖定的 go-spiffe 版本 godoc 再定案（尤其 `tlsconfig` 的 authorizer 名稱偶有增修）。

### 4.1 拿到一個會自動更新的 X509Source

```go
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	ctx := context.Background()

	// X509Source 會連上 Workload API socket，第一次取得 SVID，
	// 之後在背景「持續」更新——SVID 只有幾分鐘~一小時，靠它自動換新。
	// socket 位址預設讀環境變數 SPIFFE_ENDPOINT_SOCKET，
	// 也可用 workloadapi.WithClientOptions(workloadapi.WithAddr("unix:///run/spire/agent.sock")) 指定。
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		log.Fatalf("無法建立 X509Source（Agent 沒跑？socket 路徑錯？）：%v", err)
	}
	defer source.Close()

	// ... 見 4.2 / 4.3
	_ = source
}
```

兩個立刻要記牢的點：

- **`source` 要當長生命週期物件重用**，不要每次請求 new 一個。它內部維護一條到 Agent 的 stream，SVID 快到期時 Agent 主動推新的下來，`source` 自動換上。這正是「短效憑證卻不用你寫換發排程」的地方——**換發被平台接管了，你只管用**。
- **`source` 同時是 KeyManager 也是 TrustManager**：它既提供「我自己的 SVID + 私鑰」，也提供「這個 trust domain 的信任錨（bundle）」。所以下面 client / server config 兩個參數常常都傳同一個 `source`。

### 4.2 Client 端：連出去時驗對方的 SPIFFE ID

```go
// 我是 client，要連 order-service，且只接受對方的 SPIFFE ID 剛好是這個。
serverID := spiffeid.RequireFromString("spiffe://example.org/backend/order")

tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(serverID))

client := &http.Client{
	Transport: &http.Transport{TLSClientConfig: tlsCfg},
}
resp, err := client.Get("https://order.internal:8443/api/orders")
_ = resp
_ = err
```

**跟 Day75 的分水嶺就在 `AuthorizeID` 這個 authorizer。** Day75 的標準 client 驗證，第②步是拿 URL 裡的 host（`order.internal`）去比對憑證的 DNS SAN。這裡完全不是——`tlsconfig` 把標準的主機名驗證關掉，改成「鏈驗證通過 **AND** 對方 SVID 的 SPIFFE ID 符合 authorizer」。所以 `order.internal` 這個 host 只拿來建 TCP 連線，**身分裁決完全交給 SPIFFE ID**。這也是為什麼 SPIFFE 對「服務搬家、IP 換了、走 service mesh 被導到別的 pod」天生免疫——身分綁在 workload 上，不綁在網路位置上。

authorizer 有好幾種，選擇即是授權策略：

- `tlsconfig.AuthorizeID(id)`：只接受某一個確切 SPIFFE ID（最窄，點對點常用）。
- `tlsconfig.AuthorizeOneOf(id1, id2, ...)`：接受清單內任一個。
- `tlsconfig.AuthorizeMemberOf(trustDomain)`：接受同一個 trust domain 的**任何** workload（很寬——等於「只要是自己人就放行」，授權判斷得往上層再做，別當成細粒度授權）。
- `tlsconfig.AuthorizeAny()`：不看 ID 只驗鏈（幾乎不該用在 mTLS 授權）。

> 提醒：authorizer **只回答「握手層要不要接受這個身分」，不等於業務授權**。「確認對方是 payment-service」（authN）跟「payment-service 能不能呼叫這支 API」（authZ）是兩件事，後者接 Day07 的最小權限那條線，別把 `AuthorizeMemberOf` 當授權。

### 4.3 Server 端：只接受特定 caller

```go
// 我是 order-service，只接受 payment-service 打進來。
callerID := spiffeid.RequireFromString("spiffe://example.org/backend/payment")

tlsCfg := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeID(callerID))

server := &http.Server{
	Addr:      ":8443",
	TLSConfig: tlsCfg,
	Handler:   mux,
}
// 憑證與金鑰都由 source 動態提供，這裡不傳憑證檔路徑。
log.Fatal(server.ListenAndServeTLS("", ""))
```

注意 `ListenAndServeTLS("", "")` 兩個路徑參數是**空字串**——憑證不從檔案來，從 `source` 動態來，且會自動輪替。這跟 Day79 講的「reload 不重啟」是同一個訴求，只是 SPIFFE 幫你內建好了：`MTLSServerConfig` 產出的 `tls.Config` 用的是每次握手都呼叫的 `GetCertificate` / `GetConfigForClient`，永遠拿到 `source` 當下最新的 SVID，不需要你自己寫 mutex 熱替換。

---

## 五、Java 實作：java-spiffe 與 JSSE 怎麼接

Java 這邊用官方的 `java-spiffe`（Maven：`io.spiffe:java-spiffe-core` 與 `io.spiffe:java-spiffe-provider`）。心智模型跟 Go 一樣：先拿一個會自動更新的 `X509Source`，再把它接到 JSSE 的 `SSLContext`。

> 同上，本節依 java-spiffe 公開 API 撰寫；此環境未連 context7，正式導入前請對你鎖定的版本核對 `SpiffeSslContextFactory` / `X509Source` 的實際簽章。

### 5.1 X509Source + SSLContext

```java
import io.spiffe.workloadapi.DefaultX509Source;
import io.spiffe.workloadapi.X509Source;
import io.spiffe.provider.SpiffeSslContextFactory;
import io.spiffe.provider.SpiffeSslContextFactory.SslContextOptions;
import io.spiffe.spiffeid.SpiffeId;

import javax.net.ssl.SSLContext;
import java.util.Set;
import java.util.function.Supplier;

// X509Source 一樣是長生命週期物件：連 Workload API、背景自動更新 SVID。
// socket 位址讀環境變數 SPIFFE_ENDPOINT_SOCKET。
X509Source source = DefaultX509Source.newSource();

// 授權策略：只接受這些 SPIFFE ID（對應 Go 的 AuthorizeID / AuthorizeOneOf）。
Supplier<Set<SpiffeId>> accepted = () -> Set.of(
        SpiffeId.parse("spiffe://example.org/backend/order"));

SslContextOptions options = SslContextOptions.builder()
        .x509Source(source)
        .acceptedSpiffeIdsSupplier(accepted)  // ← 身分裁決在這，不是主機名
        .build();

SSLContext sslContext = SpiffeSslContextFactory.getSslContext(options);
```

拿到 `SSLContext` 之後就是標準 JSSE：`sslContext.getSocketFactory()` 給 client、或塞進你的 server（Tomcat / Netty / gRPC）。差別全在**它底層的 TrustManager 換成了 SPIFFE 版**——驗的是對方 SVID 的 SPIFFE ID 在不在 `acceptedSpiffeIds` 裡，而不是 Day75 那個主機名比對。

### 5.2 跟 Day75 的坑接起來

Day75 花了很大篇幅講 raw `SSLSocket` 預設不做主機名驗證、要 `setEndpointIdentificationAlgorithm("HTTPS")` 補回來。SPIFFE 這裡要**反過來理解**：你**不要**再去設 `"HTTPS"` 端點識別——因為 SVID 的 SAN 是 URI 不是 DNS name，硬套 HTTPS 端點識別反而會因為「找不到符合的 DNS name」而握手失敗。身分驗證的責任整個移交給了 SPIFFE TrustManager 的 `acceptedSpiffeIds` 比對。**心智轉換：Day75 是「主機名沒驗＝破口」；SPIFFE 是「主機名根本不是身分，SPIFFE ID 才是」。** 兩者不衝突，是因為驗證的「那件事」被換掉了。

同樣要守 Day75 的鐵律：**別為了讓它跑起來而自己寫一個空的 `X509TrustManager`（`checkServerTrusted` 空實作）繞過驗證。** 用 java-spiffe 的 factory 就是為了拿到「有在驗、只是驗的是 SPIFFE ID」的 TrustManager，自己塞空實作等於把整套信任根拆掉，比 InsecureSkipVerify 還糟。

Java 1.8 一樣的老提醒：沒有 `java.net.http.HttpClient`，走 `HttpsURLConnection.setSSLSocketFactory(sslContext.getSocketFactory())`；java-spiffe 對 JDK 版本有下限要求，導入前確認你的 1.8 能不能用（必要時走 sidecar 模式，見第七節）。

---

## 六、極短效 SVID：Day78 撤銷問題的終局

第二大安全主軸。Day78 的結論是「撤銷機制（CRL / OCSP / soft-fail）基本上救不了你，產業答案是讓憑證活得夠短」，Day79 把短效推到 6 天、每 2.5 天換一次。SPIFFE 把這條路走到極致：**X509-SVID 的效期常常只有幾分鐘到一小時。**

短到這個程度，Day78 整套撤銷難題**直接消失**，不是繞過是消失：

- 一張只活一小時的憑證，就算私鑰外洩，攻擊者的可用窗口最多一小時，然後它自己過期。**「等它過期」跟「撤銷它」的差別縮到幾乎為零**——而「過期」是離線可驗的（Day75 第①步的一部分），不需要 OCSP、不會被 soft-fail、不會被路徑上的攻擊者丟包。
- 所以 SPIFFE 世界裡**根本沒有撤銷這個動作**。你不撤銷 SVID，你就是等它幾分鐘後自然死掉，然後 workload 早已拿到下一張。

但天下沒有白吃的午餐——這條路把成本轉嫁到**換發頻率**，而且比 Day79 更誇張。Day79 每 2.5 天換一次你就得把換發當生產基礎設施經營；SVID 每小時（甚至更短）換一次，**換發管線只要斷幾分鐘，你的服務就開始握手失敗**。差別在於：Day79 你自己扛這條管線，SPIFFE 把它交給了 SPIRE Agent + `X509Source` 這套自動更新機制。所以 SPIFFE 世界的維運重點從 Day79 的「憑證會不會換」變成「**SPIRE 基礎設施（Server / Agent / socket）在不在**」——Agent 掛了，你的 workload 幾分鐘內就拿不到新 SVID。這是把 Day79「單一 CA 依賴」的風險，換成了「單一身分平台依賴」。

---

## 七、Day77 內部 CA 盲區的正解

第三大安全主軸，也是接 Day77 那條線。Day77 講過：**CT（Certificate Transparency）的執行力來自「瀏覽器不收沒有 SCT 的憑證」，而內部 CA 根本不在瀏覽器根計畫裡，所以內部 PKI 完全沒有 CT 保護——這是 CT 的盲區。** 內部 CA 被入侵、內部誤發，沒有公開帳本會記錄，你也不會收到 monitor 告警。

SPIFFE 是這個盲區的正解，而且比公開 CA 的 ACME 更激進——**因為你自己就是 CA，效期你說了算**：

- 公開 CA 你管不到它的簽發流程、效期下限被 CA/B Forum 綁著、被入侵你只能等它上 CT / 被摘信任。
- SPIRE 的內部 CA 是你自己的，**每一次簽發都經過 attestation（第三節）**，簽了什麼、發給哪個 workload、什麼特徵通過的，都是你自己的登記與日誌（接 Day16 的稽核那條線）。你不需要 CT 來「事後發現有人冒用」，因為**發憑證的整個決策過程都在你手上、都可稽核**。

但要誠實講清楚**它不是萬靈丹、也不取代 Day77 的工具**：

- **CT 盲區只是換了地方**：內部 CA 不上 CT 這件事本身沒變，SPIFFE 只是讓「簽發決策可控可稽核」來補償。SPIRE Server 的簽發私鑰（那個內部 CA 的 key）本身還是 Day15 的最高價值目標——它被偷，攻擊者就能簽出任何 SPIFFE ID，整個 trust domain 淪陷。**SPIRE Server 的 CA key 保護（HSM / upstream CA / 短效中繼）是這套架構的皇冠寶石。**
- **對外服務還是得走公開 CA + CT + CAA**：SPIFFE 是「內部服務對內部服務」的方案。你的邊界服務對公網那一段，Day77（CT / CAA）、Day79（ACME）一個都不能省。

**Java 服務常見的落地形態**順帶收在這裡：很多團隊不在 JVM 裡跑 java-spiffe，而是走 **sidecar / mesh 模式**——SPIRE Agent + Envoy（或 mesh sidecar）在 pod 裡幫 Java 服務終結 mTLS，Java 只講純 HTTP 給 localhost。這跟 Day79 說的「Java 常躲在 LB 後面、TLS 不在 JVM 終結」是同一個部署哲學的延伸：**把身分與 mTLS 從應用程式碼裡抽出來，交給平台**。這也是 SPIFFE 生態最主流的用法——應用甚至完全無感。

---

## 八、常見誤區表

| 誤區 | 為什麼錯 |
| --- | --- |
| SPIFFE 就是「內部版的 ACME」 | 問的問題不同。ACME 證明「你控制網域」，SPIFFE 證明「你是什麼、跑在哪」（attestation）。信任根不一樣。 |
| SPIFFE ID 拿主機名 / DNS 比對就好 | 不對。SPIFFE ID 在 SAN **URI** 欄位，驗證比對的是 URI，不看主機名、不看 IP。這正是它對搬家 / 換 IP 免疫的原因。 |
| workload 要自己持有一個 token / 憑證檔才能拿 SVID | 相反。workload 呼叫 Workload API **不帶任何祕密**，身分靠 Agent 觀察它的 PID / UID / pod 特徵（workload attestation）證出來。有祕密反而回到 Day15 的老問題。 |
| node attestation 做了就夠 | 不夠。只證明「這台機器可信」擋不住同機惡意程序冒領。一定要再做 workload attestation 確認「來要憑證的這個程序」是誰。 |
| SVID 那麼短效，一定要搭配撤銷機制 | 相反。短效正是**用來取代**撤銷的（Day78）。SPIFFE 世界沒有撤銷動作，等它幾分鐘後過期即可。 |
| 用了 SPIFFE 就不用管憑證輪替了 | 換發被平台接管，但你得管 SPIRE 基礎設施在不在。Agent 掛了幾分鐘，workload 就拿不到新 SVID＝服務開始握手失敗。 |
| `AuthorizeMemberOf(trustDomain)` 可以當授權用 | 太寬。它等於「只要是自己人就放行」，是 authN 不是 authZ。細粒度授權要另外做（Day07）。 |
| 為了讓 java-spiffe 跑起來自己寫個空 TrustManager | 等於拆掉信任根，比 Day75 的 InsecureSkipVerify 還糟。要用 factory 拿「驗 SPIFFE ID」的 TrustManager。 |
| SPIFFE mTLS 也要設 `setEndpointIdentificationAlgorithm("HTTPS")` | 不要。SVID 的 SAN 是 URI 不是 DNS，硬套 HTTPS 端點識別會找不到 DNS name 而握手失敗。身分裁決交給 SPIFFE authorizer。 |
| 內部用 SPIFFE 了，對外服務也不用 CT / CAA | 錯。SPIFFE 只管內部對內部。邊界對公網那段 Day77（CT/CAA）、Day79（ACME）一個都不能省。 |
| SPIRE Server 的 CA key 跟一般 secret 差不多 | 它是皇冠寶石。被偷＝能簽任意 SPIFFE ID＝整個 trust domain 淪陷。要 HSM / upstream CA / 短效中繼保護（Day15）。 |

---

## 九、Code Review / 維運 checklist

```text
【身分與 SVID 使用】
[ ] X509Source / DefaultX509Source 是長生命週期單例嗎？（不是每請求 new，否則失去自動輪替）
[ ] 憑證與金鑰是「動態從 source 取」還是「讀死一個檔」？（讀死檔＝SVID 過期就掛，失去短效意義）
[ ] server 端有沒有寫死憑證檔路徑？（Go 應是 ListenAndServeTLS("", "")）

【授權（authN vs authZ）】
[ ] authorizer 用的是 AuthorizeID / AuthorizeOneOf（明確身分）還是 AuthorizeMemberOf（整個 domain）？後者是否被誤當授權？
[ ] 「確認對方是誰」跟「對方能不能做這件事」有分開嗎？（後者接 Day07）
[ ] AuthorizeAny() 有沒有出現在 mTLS 路徑上？（幾乎一定是錯的）

【驗證正確性（承 Day75）】
[ ] 有沒有為了跑起來自己塞空的 X509TrustManager / InsecureSkipVerify？（拆信任根，禁止）
[ ] Java 端有沒有誤設 setEndpointIdentificationAlgorithm("HTTPS")？（SVID 是 URI 不是 DNS，會握手失敗）

【基礎設施依賴（承 Day79 單一 CA → 單一平台）】
[ ] SPIRE Agent / Workload API socket 掛掉時，workload 的失敗行為是什麼？有告警嗎？
[ ] SPIRE Server 的 CA 私鑰怎麼保管？（HSM / upstream CA？承 Day15，皇冠寶石）
[ ] registration entry（誰能拿哪個 SPIFFE ID）的變更有審核 + 稽核日誌嗎？（承 Day16）

【範圍認知】
[ ] 對外公網服務有沒有誤用 SPIFFE 取代 ACME / CT / CAA？（SPIFFE 只管內部對內部）
```

**測試建議：**

- **身分比對測試（最重要）**：拿一個「鏈驗證過、但 SPIFFE ID 不在 authorizer 允許清單」的 SVID 去連，斷言**握手被拒**。這是 SPIFFE 版的「守門員存在證明」（承 Day75/76）——測不過代表你的 authorizer 是裝飾品，任何自己人 SVID 都能進。
- **SVID 自動輪替測試**：把 SVID 效期在測試環境設到極短（例如 1 分鐘），跑超過一個效期後斷言連線仍正常、且憑證的序號 / NotBefore 真的換了新的。驗證 `source` 真的在背景換發，而不是你以為它會換。
- **Agent 中斷演練**：在 SVID 還沒過期時停掉 SPIRE Agent，斷言現有連線還能撐到 SVID 過期、且**有告警**；再讓 SVID 過期，斷言 workload 明確失敗（而非靜默降級成無驗證）。這是把 Day79「太久沒成功換發」告警搬到 SPIFFE 世界的版本。
- **attestation 冒領測試**：用一個「跑在同一節點、但特徵（UID / service account）對不上 registration entry」的程序去呼叫 Workload API，斷言 Agent **不發** SVID 給它。這是 workload attestation 的存在證明。
- **主機名無關性測試**：故意用「跟憑證 DNS SAN 不符、甚至沒有 DNS SAN」的 host 位址連線，斷言只要 SPIFFE ID 對就能連——證明你真的把身分綁在 SPIFFE ID 而非網路位置。

---

## 十、一句話總結

> Day79 說「對外服務靠 ACME 向公開 CA 證明你控制網域然後自動換發」，今天把鏡頭轉進內網：**幾百個微服務要互相 mTLS，你不能手動簽也不該共用長效憑證，而且「控制網域」這個身分根本在內網不成立**。SPIFFE（規格）／ SPIRE（實作）解的問題只有一句——**給每個 workload 一個不需自持祕密、可被密碼學驗證、還會自動短效輪替的身分**，身分寫成 `spiffe://trust-domain/workload` 這種 URI、**塞進憑證的 SAN URI 欄位**（裝著它的短效憑證叫 SVID）。整套設計的樞紐是**把信任根從「網域控制權」換成「workload 證明（attestation）」**：node attestation 先確認「這台機器可信」（AWS/GCP metadata、K8s token、join token），workload attestation 再回答「來要憑證的這個程序憑什麼是它宣稱的服務」——workload **呼叫 Workload API 不帶任何祕密**，Agent 反過來觀察它的 PID / UID / pod 特徵去比對登記項，符合才發 SVID，所以**沒有祕密可偷**（正是 Day15 難題的解法）。程式面兩邊對稱：**Go 用 `go-spiffe` 的 `workloadapi.NewX509Source` 拿一個會背景自動更新的 source，再用 `spiffetls/tlsconfig` 的 `MTLSClientConfig` / `MTLSServerConfig` 搭 `AuthorizeID` 掛進 `tls.Config`——關鍵差異是它比對的是 SVID 的 SPIFFE ID 而非 Day75 的主機名，host 只拿來建 TCP 連線**；**Java 用 `java-spiffe` 的 `DefaultX509Source` + `SpiffeSslContextFactory` 產出 `SSLContext`，底層 TrustManager 換成驗 SPIFFE ID 的版本，且千萬別再設 `setEndpointIdentificationAlgorithm("HTTPS")`（SVID 是 URI 不是 DNS 會握手失敗）、更別為了跑起來塞空 TrustManager（比 InsecureSkipVerify 還糟）**。三大安全主軸把前面幾天全接起來：**① SVID 短到幾分鐘~一小時，讓 Day78 的撤銷難題徹底消失（沒有撤銷動作，等它過期即可，而過期是離線可驗、不會被 soft-fail 的）；② 身分根從「控制網域」換成「你是什麼、跑在哪」；③ 這是 Day77 內部 CA 盲區的正解——內部 PKI 用 SPIFFE 自動化、簽發全程可稽核，比公開 CA 更激進因為你自己就是 CA 效期你說了算**。但代價與邊界要記牢：**換發被平台接管不代表沒成本，它把 Day79 的「單一 CA 依賴」換成「單一身分平台依賴」——SPIRE Agent 掛幾分鐘 workload 就拿不到新 SVID 開始握手失敗；SPIRE Server 的 CA 私鑰是皇冠寶石（偷了能簽任意身分＝整個 trust domain 淪陷，承 Day15）；而 SPIFFE 只管內部對內部，邊界對公網那段 Day77 的 CT/CAA、Day79 的 ACME 一個都不能省**。一句話：ACME 讓機器自證「我控制這個網域」，SPIFFE 讓機器被平台證明「我就是這個 workload」——內網的身分，不靠你握有什麼，靠你是什麼。

---

## 延伸閱讀

- Day79 ACME 自動換發管線——本篇的上游：對外服務向公開 CA 換發；SPIFFE 是同一件事（自動化短效憑證）在內網的激進版，信任根從網域控制權換成 workload 證明。
- Day78 憑證撤銷 / soft-fail / 短效憑證——SVID 把「憑證活得夠短」推到幾分鐘，讓撤銷問題徹底消失的終局。
- Day77 CT 與 CAA——內部 CA 是 CT 的盲區；SPIFFE 用「簽發全程可稽核」來補償，但別以為它取代了對外服務的 CT/CAA。
- Day76 憑證釘選——內部服務 pinning 的替代方案：SPIFFE ID 比對本身就是「認金鑰 / 認身分」而非認主機名。
- Day75 TLS 憑證驗證與 MITM——本篇一直在對照：Day75 驗主機名（DNS SAN），SPIFFE 驗身分（URI SAN），且 Java 端反而不能設 HTTPS 端點識別。
- Day74 mTLS / TLS 握手 DoS——mTLS 是內部服務互驗身分的手段，本篇補上「那個身分從哪來、怎麼自動發」。
- Day15 Secrets Management——「workload 不自持祕密」正是 secrets 難題的解法；但 SPIRE Server 的 CA key 變成新的皇冠寶石。
- Day16 Security Logging / Monitoring——registration entry 變更稽核、Agent 中斷告警、SVID 換發失敗告警。
- Day07 授權最小化——SPIFFE 的 authorizer 是 authN；能不能做某件事（authZ）要另外做。

---

明天預告：**Day 81 — JWT-SVID 與跨邊界的 workload 身分：當 mTLS 過不去的時候（延伸篇）**
（今天講的 X509-SVID 走 mTLS，但很多場景 mTLS 根本插不進去——請求經過 L7 API gateway / mesh ingress 被終結重打、workload 要對雲端 API 或訊息佇列出示身分、或跨過 proxy 只剩 HTTP header 能帶東西。**這是延伸篇，不重講今天的 SPIFFE ID / attestation / X509-SVID 基礎，聚焦 JWT-SVID 這個「可攜帶、能塞進 Authorization header」的身分形式，以及它獨有的一整組坑。** Day81 要講 **JWT-SVID 跟 X509-SVID 的根本差異——它是 bearer token（誰拿到誰就是你），所以少了 X509-SVID「私鑰不出 workload」的那層保護**，因此 **`aud`（audience）驗證變成生死線（承 Day31/33 JWT 那條線）：一個沒綁 audience 的 JWT-SVID 被下游服務拿去冒充你打別人，就是內部版的 token 重放**。程式面會示範 **Go 用 `go-spiffe` 的 `workloadapi.FetchJWTSVID` 拿 token、`jwtsvid.ParseAndValidate` 驗 audience 與簽章（用 bundle 裡的公鑰）**，以及 **Java 用 `java-spiffe` 的 `JwtSource` / `JwtSvid` 對應做法**。安全主軸三件事：**① bearer token 的短效與最小 audience（越窄越好，別簽一個萬用 audience 到處能用）、② 驗證方一定要驗 `aud` 是不是自己，不然就是 confused deputy、③ JWT-SVID 該用在哪、不該用在哪——能用 mTLS（X509-SVID）就別退回 bearer token**。這是延伸篇，把今天的身分從「mTLS 專用」擴展到「跨邊界可攜帶」，順帶接回 Day31/33 的 JWT 驗證肌肉。）
