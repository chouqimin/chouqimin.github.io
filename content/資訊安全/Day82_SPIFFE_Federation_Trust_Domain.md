---
title: "Day 82：SPIFFE Federation — 跨 trust domain 的信任怎麼建立、怎麼收窄（新主題）"
date: 2026-07-22
tags: ["SPIFFE", "Federation", "Trust Domain", "Bundle Endpoint"]
---

接續 Day81 預告：Day80 與 Day81 講的東西全都活在**同一個 trust domain** 裡——同一台 SPIRE Server、同一份 bundle、`spiffe://example.org` 底下大家互相認得。但真實世界會撞牆：**併購後兩個叢集各自有一套 SPIRE、多雲各跑一個控制平面、或你要跟合作夥伴的服務互相驗證身分**。這時 `spiffe://example.org` 底下的服務，要怎麼信任 `spiffe://partner.com` 底下的服務？

這是**新主題**，不重講 Day80/81 的 SVID 基礎（SPIFFE ID 格式、attestation 兩層、X509-SVID 與 mTLS 怎麼跑），那些請看前兩天。今天只聚焦一件事：**當信任邊界要跨出去，SPIFFE 用什麼機制把兩個獨立的 trust domain 接起來——答案是 bundle 交換**。而這個機制帶進來的三個安全問題，正是後端工程師最容易做錯的地方：**信任範圍開太寬、bundle endpoint 變成新的 SSRF 目標、以及 bundle refresh 失敗時的靜默全面斷線**。

---

## 一、先釐清 federation 到底在解什麼

單一 trust domain 裡，信任根很單純：所有 workload 的 SVID 都由同一台 SPIRE Server 的 CA 簽，所有人手上都有同一份 **trust bundle**（那台 Server 的 CA 公鑰集合）。A 服務驗 B 服務的 SVID，就是拿這份 bundle 去驗簽章，簽得過就是自己人。

問題出在「自己人」的邊界。trust domain 是**一整個信任邊界**，通常一個組織、一個叢集配一個。一旦你有兩個獨立的 trust domain：

- `spiffe://example.org`（你家，SPIRE Server A，bundle A）
- `spiffe://partner.com`（夥伴，SPIRE Server B，bundle B）

`example.org` 的服務手上只有 bundle A。partner 的服務出示一張由 bundle B 的 CA 簽的 SVID，你拿 bundle A 去驗——**簽不過**，因為根本不是同一個 CA 簽的。這不是 bug，這是正確行為：你本來就不該無條件相信別的 trust domain。

**federation 就是把「我這邊也拿到對方的 bundle」這件事做好的機制。** 一旦 `example.org` 也持有 bundle B，它就能驗 partner 服務出示的 SVID 的簽章了。

---

## 二、關鍵：這跟公網 PKI 是完全不同的信任模型

這裡要把 Day75 / Day77 的 PKI 心智模型**拆掉重建**，否則後面全會理解錯。

公網 PKI 的信任模型是**「大家都信同一批根 CA」**：你的瀏覽器、我的伺服器、隨便一台機器，出廠就內建同一份 root store（Mozilla / OS 那份幾百張根憑證）。任何憑證只要能鏈到那批共同的根，所有人都認。信任是**由上而下、共用一個天花板**的。

SPIFFE federation 的信任模型是**「我明確認得你的 CA，僅此一個」**：

> 信任不是靠某個共同的上級 CA，而是**兩個 trust domain 各自把對方的 bundle（公鑰集合）拿到手**。

沒有共同的根，沒有第三方 root store。是 `example.org` 主動決定「我要信任 `partner.com`，所以我去拿它的 bundle 存起來」，partner 那邊也對稱地做一次。這是**點對點、雙邊、明確列舉**的信任，不是階層式的。

這個差異的實務後果很重要：

- **公網 PKI**：新增一個可信的 CA 是全球性動作（進 root program），你個別伺服器不做決定。
- **SPIFFE federation**：新增一個可信的 trust domain 是**你這個 trust domain 自己的、明確的一筆設定**，粒度在你手上，而且只影響你。

所以 federation 的第一條鐵律就浮出來了——它是**「我認得你的 CA」，不是「我信任你的所有 workload」**。這兩件事的距離，就是接下來所有防禦的重點。

---

## 三、bundle 怎麼交換：Bundle Endpoint 與兩種驗證 profile

bundle 不是手動 copy 一次貼過去就算了（那樣對方輪替 CA 金鑰你就過期了）。SPIFFE 定義了 **Bundle Endpoint**：每個 trust domain 對外開一個 HTTPS 端點，持續提供自己**最新的** bundle（JWKS 格式），對方**定期主動來抓**。

於是配置 federation 時，你要告訴自己的 SPIRE Server：

```hcl
# SPIRE Server 設定：我要跟 partner.com federate
federation {
    bundle_endpoint {
        # 我自己對外提供 bundle 的端點
        address = "0.0.0.0"
        port    = 8443
    }

    federates_with "partner.com" {
        bundle_endpoint_url = "https://spire.partner.com:8443"
        bundle_endpoint_profile "https_spiffe" {
            endpoint_spiffe_id = "spiffe://partner.com/spire/server"
        }
    }
}
```

這裡最關鍵、也最容易被輕輕帶過的，是 **bundle endpoint 的驗證 profile**。你定期去連 `https://spire.partner.com:8443` 抓 bundle——但**你怎麼知道連上的真的是 partner、而不是被 MITM 或 DNS 劫持導到攻擊者那台**？如果這一步被騙，攻擊者就能塞一份**他自己**的 bundle 給你，之後他簽的任何假 SVID 你都會當成 partner 的來信。**bundle endpoint 的傳輸驗證，是整條 federation 信任鏈的地基。** SPIFFE 給兩種 profile：

**`https_spiffe`（用 SPIFFE 身分驗端點）**
bundle endpoint 自己也出示一張 SVID，你用**已經 bootstrap 到手的那份 partner bundle** 去驗它。這是自我閉環的：第一次要靠帶外（out-of-band）方式先拿到 partner 的初始 bundle（人工交換、CI 注入等），之後就靠這份初始 bundle 驗端點、抓到新 bundle、滾動更新。**驗的是 SPIFFE ID（`endpoint_spiffe_id`），完全不看主機名**——這跟 Day80 的 X509-SVID 驗證邏輯一致（SAN 是 URI 不是 DNS）。

**`https_web`（用公開 Web PKI 驗端點）**
bundle endpoint 用一張**公開 CA 簽發**的一般 TLS 憑證（就像普通 HTTPS 網站）。你去連的時候，走的是標準 Web PKI 驗證——**於是 Day75 那整套主機名驗證（SAN DNS 比對 host）、Day77 的 CT / CAA 全部回來了**。好處是不用帶外先交換初始 bundle（信任 bootstrap 靠公網 PKI），壞處是你把 federation 地基的安全性**外包給了公網 CA 生態**：憑證被錯發、CA 被攻陷、你自己沒開 hostname 驗證，任何一個環節破，federation 就破。

取捨一句話：**`https_spiffe` 把信任收在你和 partner 之間（更封閉、更可控，但要處理初始 bundle 帶外交換）；`https_web` 靠公網 PKI 做 bootstrap（省事，但把 Day75/77 的整包風險又背回來）。** 選 `https_web` 就必須確認你的 client 端**真的有做主機名驗證**——別為了讓它跑起來又去關掉端點識別，那等於 Day75 的破口原地重演。

---

## 四、registration entry：`federatesWith` 才是實際生效的開關

federation 在 Server 設好，只是讓兩個 domain 能交換 bundle。但**光有對方的 bundle，你的 workload 預設還是拿不到它**。真正決定「哪個 workload 可以驗哪個 domain 的身分」的，是 registration entry 上的 `federates_with` 欄位：

```bash
# 只讓 payment-service 這一個 workload 拿得到 partner.com 的 bundle
spire-server entry create \
    -spiffeID spiffe://example.org/payment-service \
    -parentID spiffe://example.org/spire/agent/... \
    -selector k8s:sa:payment \
    -federatesWith spiffe://partner.com
```

沒寫 `-federatesWith` 的 workload，它的 X509Source **不會**包含 partner 的 bundle，也就驗不了 partner 的 SVID——這是**預設拒絕**，很好。這也給了你一個天然的收窄工具：**federation 不是 trust domain 對 trust domain 整片打通，而是可以精確到「只有 payment-service 認得 partner，其他服務完全不受影響」**。能收多窄就收多窄。

---

## 五、Go 實作：go-spiffe v2 跨 domain 的 mTLS

程式面其實跟 Day80 幾乎一樣，因為 federation 的複雜度被 SPIRE Agent + Workload API 吸收掉了。**你的 `X509Source` 從 Workload API 拿到的 bundle，只要 registration entry 有 `federatesWith`，就會自動包含 partner 的 federated bundle**——你不用自己去抓、去存、去輪替 partner 的公鑰。

差異只在**授權那一步（authorizer）**：現在你要接受的對端 SPIFFE ID 是**別的 trust domain** 的。

```go
package main

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	ctx := context.Background()

	// 跟 Day80 一模一樣：長生命週期 source，背景自動更新。
	// 因為這個 workload 的 registration entry 有 federatesWith spiffe://partner.com，
	// 這個 source 內含的 bundle 會「自動」包含 partner 的 federated bundle，
	// 你完全不用自己去抓 / 存 / 輪替 partner 的公鑰。
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		panic(err)
	}
	defer source.Close()

	// 關鍵差異：authorizer 接受的是「別的 trust domain」的確切 SPIFFE ID。
	// AuthorizeID 是最窄的授權——只認 partner 的這一個服務，不是整個 partner.com。
	partnerSvc := spiffeid.RequireFromString("spiffe://partner.com/order-service")

	tlsConfig := tlsconfig.MTLSClientConfig(
		source, // 我自己的 SVID（proof-of-possession）
		source, // 驗對端用的 bundle 來源（已含 federated bundle）
		tlsconfig.AuthorizeID(partnerSvc), // ← 逐一收窄的核心
	)

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
	resp, err := client.Get("https://order.partner.com/api")
	_ = resp
	_ = err
	_ = tls.VersionTLS13
}
```

這段的所有安全重量都壓在 `AuthorizeID` 上。對照 Day80 講過的 authorizer 光譜，在 federation 場景更要命：

- `AuthorizeID(spiffe://partner.com/order-service)`：只認 partner 的**一個**服務。**這才是 federation 該有的預設。**
- `AuthorizeOneOf(...)`：partner 的少數幾個明確服務。
- `AuthorizeMemberOf(spiffeid.RequireTrustDomainFromString("partner.com"))`：**partner.com 底下的任何 workload 都放行**。在單一 domain 內這已經偏寬（Day80 講過）；在 **federation 場景這是災難**——等於你把**對方整個 trust domain** 拉進了自己的信任邊界。partner 那邊隨便一個 workload（可能是他們的測試服務、可能是被攻陷的邊角服務）都能來打你這條路徑。
- `AuthorizeAny()`：只驗簽章不看是誰。跨 domain 用這個等於自殺，別出現。

**第一條安全主軸**因此成立：**federation 是「我認得你的 CA」不是「我信任你的所有 workload」，授權必須逐一收窄，否則等於把對方整個 trust domain 拉進你的信任邊界。** `AuthorizeMemberOf` 在 federation 邊界上就是那個最常見的「開太寬」錯誤。

伺服器端對稱地做——接受來自 partner 特定服務的連線：

```go
tlsConfig := tlsconfig.MTLSServerConfig(
	source,
	source,
	tlsconfig.AuthorizeID(spiffeid.RequireFromString("spiffe://partner.com/order-service")),
)
server := &http.Server{Addr: ":8443", TLSConfig: tlsConfig}
_ = server
```

---

## 六、Java 實作：java-spiffe 跨 domain

Java 側同樣把 federated bundle 的取得交給 `DefaultX509Source`（背景更新），差異也只在**接受的 SPIFFE ID 是別的 trust domain**：

```java
import io.spiffe.provider.SpiffeSslContextFactory;
import io.spiffe.provider.SpiffeSslContextFactory.SslContextOptions;
import io.spiffe.spiffeid.SpiffeId;
import io.spiffe.workloadapi.DefaultX509Source;

import javax.net.ssl.SSLContext;
import java.util.Set;

public class FederatedClient {

    public static SSLContext buildContext() throws Exception {
        // 跟 Day80 相同：長生命週期 source，讀 SPIFFE_ENDPOINT_SOCKET。
        // registration entry 有 federatesWith 時，source 內含 partner 的 federated bundle。
        DefaultX509Source source = DefaultX509Source.newSource();

        SslContextOptions options = SslContextOptions.builder()
                .x509Source(source)
                // 接受清單放的是「別的 trust domain」的確切 SPIFFE ID，
                // 一個 partner 服務一筆，不要放整個 partner.com。
                .acceptedSpiffeIdsSupplier(() ->
                        Set.of(SpiffeId.parse("spiffe://partner.com/order-service")))
                .build();

        // 守 Day75 / Day80 鐵律：SVID 的 SAN 是 URI 不是 DNS，
        // 千萬別再設 setEndpointIdentificationAlgorithm("HTTPS")，
        // 也別為了跑起來自寫空 X509TrustManager 繞過驗證——那是拆信任根。
        return SpiffeSslContextFactory.getSslContext(options);
    }
}
```

心智重點跟 Day80 一致，只是對象換成別的 domain：**主機名根本不是身分，SPIFFE ID 才是**；`acceptedSpiffeIdsSupplier` 就是你的授權收窄點，放進去的每一個 partner ID 都是你**明確**同意信任的對象。

Java 1.8 的老限制照舊：沒有 `java.net.http.HttpClient`，要走 `HttpsURLConnection.setSSLSocketFactory(sslContext.getSocketFactory())`；`java-spiffe` 對 JDK 版本有下限，撞到就走 sidecar / mesh 模式（見第九節）讓 Java 只講純 HTTP 給 localhost，federation 與 mTLS 全交給 Envoy。JDK 21 則直接用 `HttpClient` 掛 `sslContext` 即可，這部分沒有 federation 特有的坑。

---

## 七、第二條主軸：bundle endpoint 是新的攻擊面（承 Day10 SSRF）

federation 引進了一個 Day80/81 都沒有的東西：**你的基礎設施會定期、主動地去連一個「對方給你的 URL」抓公鑰**。

```hcl
federates_with "partner.com" {
    bundle_endpoint_url = "https://spire.partner.com:8443"  # ← 你會週期性去打它
    ...
}
```

用 Day10 的眼睛看這行——這就是一個**由外部輸入（federation 設定）決定、由你內部基礎設施發起的出站請求**。這是 SSRF 的教科書觸發條件。實務要注意：

- **URL 來源要可信**：`bundle_endpoint_url` 應該是變更受審核的設定，不是某個 API 拿使用者輸入拼出來的。**絕對不要**讓「動態新增 federation」這種功能直接吃外部輸入去設 endpoint URL——那等於開放讓人指定「請你的 SPIRE Server 去連任意內網位址」。
- **出站要走 egress control**：SPIRE Server 去抓 bundle 的出站流量，應該只允許連到已知 partner 的位址，其餘 deny（承 Day10 的 egress allowlist 思路）。否則一個被污染的 endpoint URL 就能讓你的 Server 去掃內網、打 metadata endpoint。
- **拿回來的內容要當不可信資料驗**：bundle endpoint 回的是 JSON（JWKS）。SPIRE 會用 profile 指定的方式驗端點身分（`https_spiffe` 驗 SVID / `https_web` 驗 Web PKI），這步**不能省**——省了就等於誰回你 JSON 你都當成 partner 的新 bundle。
- **size / 逾時要設限**：定期主動連外的 client，順手把回應大小上限、連線逾時設好，別讓一個惡意或壞掉的端點把你的 Server 拖住（承 Day71 / Day72 的 slow / oversized 回應思路）。

**bundle endpoint 讓你的信任基礎設施從「被動被連」變成「主動連外」，多出來的這個出站行為就是新攻擊面。**

---

## 八、第三條主軸：bundle refresh 失敗＝安靜的全面斷線

這是 federation 最陰險、也最常在半夜炸掉的失敗模式，值得單獨講。

bundle 不是設一次就永久有效。partner 的 SPIRE Server 會**輪替它的 CA 金鑰**（短效正是 SPIFFE 的核心設計）。輪替時 partner 的新 SVID 改用**新 CA** 簽，而新 CA 的公鑰要透過 bundle endpoint 傳播到你這邊。正常情況下，SPIRE 會在舊金鑰還沒退場前就把新公鑰推進 bundle，你的 X509Source 背景更新拿到，無縫接軌。

但只要這條 refresh 鏈斷掉——

- partner 的 bundle endpoint 掛了 / 改了 URL 沒通知你
- 你這邊到 partner endpoint 的網路被防火牆規則擋掉（egress 規則改動的常見副作用）
- `https_spiffe` 的初始 bundle 過期、或 `https_web` 的端點憑證換了鏈你沒跟上
- 單純 refresh interval 太長，來不及在對方舊金鑰退場前更新

——結果是：**partner 開始用新 CA 簽 SVID，你手上還是舊 bundle，於是 partner 的每一個 SVID 你都驗不過，跨 domain 的連線「全部」握手失敗。** 而且它**不會報「bundle 過期」這種好懂的錯**，它報的是一般的 TLS handshake failure / bad certificate，看起來像網路問題或對方服務掛了，排查方向整個帶偏。這跟 Day79 講的「ACME 太久沒成功換發、憑證默默過期」是**同一種病的 federation 版**——問題早就發生，告警卻遲到，等到大規模斷線才發現。

防禦就是**把這條沉默鏈變吵**：

- 監控 federated bundle 的**新鮮度**：`last successfully refreshed` 距現在多久？超過門檻就告警（承 Day16）。別等握手失敗才知道。
- 監控 refresh **成功率**，不只監控最終握手——refresh 連續失敗 N 次就該有人被叫醒，即使此刻連線還正常（因為對方還沒輪替，你只是在吃老本）。
- 跨 domain 連線失敗要能**歸因到 bundle**：在錯誤處理 / log 裡把「對端 SVID 驗簽失敗（可能 bundle 過期）」跟一般網路錯誤分開，別讓它淹沒在 generic TLS error 裡。
- refresh interval 要**明顯短於**對方 CA 金鑰的重疊窗口，留足容錯。

---

## 九、落地形態：mesh federation（Istio / Envoy）

實務上 Java / 多語言團隊很少自己寫上面那些 mTLS 程式碼，而是走 **service mesh**：SPIRE Agent 把 SVID 與 federated bundle 透過 **Envoy SDS** 餵給 sidecar，Envoy 幫應用終結跨 domain 的 mTLS，應用只講純 HTTP 給 localhost。這時 federation 的授權收窄點就從程式碼移到 **mesh 的授權策略**（例如 Istio 的 `AuthorizationPolicy` 用 `principals` 比對 SPIFFE ID）。

換了地方，但三條主軸**一條都沒變**：授權策略裡別用「整個 partner.com」當 principal（第一條）、mesh 控制平面去抓 federated bundle 一樣是出站攻擊面（第二條）、SDS 沒推到新 bundle 一樣會全面斷線（第三條）。工具換了，思路照舊。

---

## 十、常見誤區表

| 誤區 | 正解 |
|---|---|
| federation 靠某個共同上級 CA | 沒有共同根，是雙邊各自拿到對方 bundle，點對點列舉信任 |
| federate 了就等於信任對方所有服務 | 只是「認得對方 CA」，能驗簽章 ≠ 授權放行；要逐一收窄 |
| 用 `AuthorizeMemberOf(partner.com)` 授權跨 domain 連線 | 太寬＝把對方整個 trust domain 拉進來；用 `AuthorizeID` 逐一列舉 |
| bundle 手動 copy 一次就好 | 對方會輪替 CA 金鑰，要靠 bundle endpoint 定期 refresh，否則會斷 |
| `https_web` 跟 `https_spiffe` 隨便選 | `https_web` 把 Day75 主機名驗證 + Day77 CT/CAA 風險背回來，選了就得確認有做 hostname 驗證 |
| bundle endpoint URL 可以吃動態輸入 | 那是 SSRF 破口；URL 要受審核設定，出站走 egress allowlist |
| refresh 失敗會有明顯的「bundle 過期」錯誤 | 它報的是一般 TLS handshake failure，會被當成網路問題；要主動監控 bundle 新鮮度 |
| federation 是 trust domain 對 trust domain 整片打通 | 用 registration entry 的 `federatesWith` 收窄到「只有某些 workload 認得對方」 |
| 為了讓跨 domain 跑起來，設 `setEndpointIdentificationAlgorithm("HTTPS")` | SVID SAN 是 URI 非 DNS，會握手失敗；身分交給 SPIFFE 授權（承 Day80） |

---

## 十一、Code Review / 維運 checklist

**信任範圍（authZ 收窄，第一條主軸）**

- [ ] 跨 domain 的 authorizer / accepted list 是 `AuthorizeID` 逐一列舉，不是 `AuthorizeMemberOf(整個 partner domain)`，更不是 `AuthorizeAny`。
- [ ] registration entry 的 `federatesWith` 只掛在**真的需要**跟對方通訊的 workload 上，不是全域打通。
- [ ] 「認得對方 CA」跟「業務授權」分開：驗過對端 SPIFFE ID 只完成 authN，「這個 partner 服務能做什麼」仍照 Day07 / Day49 在業務層做。

**bundle endpoint（出站攻擊面，第二條主軸）**

- [ ] `bundle_endpoint_url` 是變更受審核的設定，不吃任何動態 / 使用者輸入。
- [ ] SPIRE Server 去抓 bundle 的出站流量走 egress allowlist，只准連已知 partner（承 Day10）。
- [ ] profile 選擇明確：`https_spiffe` 有處理初始 bundle 帶外交換；`https_web` 有**確認做了主機名驗證**（別關掉端點識別，承 Day75）。

**refresh 失敗（沉默斷線，第三條主軸）**

- [ ] 有監控 federated bundle 的**新鮮度**與 **refresh 成功率**，不是只監控最終握手（承 Day16 / Day79）。
- [ ] refresh 連續失敗會告警，即使此刻連線還正常。
- [ ] 錯誤處理能把「對端 SVID 驗簽失敗（疑似 bundle 過期）」跟一般網路錯誤分開歸因。
- [ ] refresh interval 明顯短於對方 CA 金鑰重疊窗口。

---

## 十二、測試建議

- **跨 domain 授權收窄測試（最重要）**：拿一份**簽章完全有效、由 partner 真實 CA 簽、但 SPIFFE ID 不在你允許清單**的 SVID（例如 `spiffe://partner.com/some-other-service`）去打你的端點，斷言**被拒**。這是 federation 版的「守門員存在證明」（承 Day80 / Day81）——測不過代表你的授權其實是 `MemberOf` 甚至 `Any`，partner 隨便一個服務都能進來。
- **`MemberOf` 過寬迴歸測試**：如果你**刻意**用了 `AuthorizeMemberOf`，寫一條測試明確記錄「partner 底下任一 workload 都能連」這個事實，逼未來的人看見這個信任範圍，而不是無意識地繼承。
- **bundle refresh 斷線演練**：把到 partner bundle endpoint 的網路切斷，讓對方（或模擬）輪替 CA 金鑰，斷言你的**監控在握手大規模失敗之前就告警**（bundle 新鮮度超標）。這題直接驗證第三條主軸的告警有沒有效，別等連線全斷才發現。
- **端點身分偽造測試**：架一個假的 bundle endpoint（SPIFFE ID 或 Web 憑證不對），斷言你的 SPIRE Server **拒絕**採用它回的 bundle，而不是照單全收。這是 profile 驗證的存在證明。
- **SSRF 邊界測試**：確認 `bundle_endpoint_url` 這條路徑無法被外部輸入影響去指向內網 / metadata 位址；出站 egress 規則對非 partner 位址斷言被擋。
- **初始 bundle 過期測試（`https_spiffe`）**：把 bootstrap 用的初始 partner bundle 設成已過期，斷言 refresh **明確失敗並告警**，而不是靜默降級成「連不上就不更新繼續吃舊的」。

---

## 十三、一句話總結

> Day80 / Day81 都活在同一個 trust domain 裡，今天處理的是**信任要跨出自己這個 domain** 的場合：併購、多雲、對外夥伴，`spiffe://example.org` 的服務要驗 `spiffe://partner.com` 的 SVID，卻因為不是同一個 CA 簽的而驗不過——這不是 bug 是正確行為。**federation 的機制核心只有一句：bundle 交換**——不靠共同上級 CA，而是兩個 trust domain **各自把對方的 bundle（公鑰集合）拿到手**，這跟公網 PKI「大家都信同一批根 CA」是**完全不同的信任模型**：前者點對點、雙邊、明確列舉，後者階層式、共用天花板。交換不是手動 copy 一次，而是每個 domain 開一個 **Bundle Endpoint** 定期供最新 bundle、對方主動來抓；端點驗證有兩種 profile——**`https_spiffe`**（用 SVID 驗、要帶外先換初始 bundle、更封閉可控）與 **`https_web`**（用公開 CA 憑證驗、省事但把 **Day75 主機名驗證 + Day77 CT/CAA 的整包風險背回來**）。程式面 **Go 的 `workloadapi.NewX509Source` 拿到的 bundle 只要 registration entry 有 `federatesWith` 就自動含 partner 的 federated bundle**，你不用自己抓／存／輪替公鑰，差異只在 authorizer 換成 `tlsconfig.AuthorizeID(spiffe://partner.com/確切服務)`；**Java 的 `DefaultX509Source` + `acceptedSpiffeIdsSupplier` 放對方確切 SPIFFE ID**，且守 Day80 鐵律別設 `HTTPS` 端點識別（SAN 是 URI 非 DNS）、別自寫空 TrustManager 拆信任根。安全主軸三件事，每一件都是後端最常做錯的地方：**① federation 是「我認得你的 CA」不是「我信任你的所有 workload」，授權必須逐一收窄——`AuthorizeMemberOf(整個 partner domain)` 在 federation 邊界就是把對方整個 trust domain 拉進來的災難；② bundle endpoint 是新的攻擊面——你會週期性主動去連一個「對方給的 URL」抓公鑰，正是 Day10 SSRF 的觸發條件，URL 要受審核、出站走 egress allowlist、回應要驗端點身分；③ bundle refresh 失敗是安靜的全面斷線——對方輪替金鑰而你沒更新到，會默默變成所有跨 domain 連線握手失敗，而且報的是一般 TLS 錯誤不是「bundle 過期」，跟 Day79「太久沒換發」同款，解法是主動監控 bundle 新鮮度與 refresh 成功率，別等連線全斷才發現。** 一句話：federation 讓你「認得」另一個 trust domain 的 CA，但認得不等於放行——你必須明確寫死只放行對方的哪幾個服務，並且盯緊那條把對方公鑰持續搬進來的 refresh 鏈，因為它一斷，全部一起斷。

---

## 延伸閱讀

- Day80 SPIFFE / SPIRE workload identity——本篇的上游：trust domain、SPIFFE ID、X509-SVID、authorizer 光譜的完整基礎。
- Day81 JWT-SVID 與跨邊界身分——同樣是「身分要跨出去」，但那是跨 L7 邊界，這篇是跨 trust domain 邊界。
- Day75 TLS 憑證驗證 / MITM——`https_web` profile 一選下去，主機名驗證的整套要求就回來了。
- Day77 Certificate Transparency / CAA——`https_web` 的端點憑證同樣落在公網 CA 生態，CT / CAA 又回到桌面。
- Day79 ACME 自動換發——bundle refresh 失敗＝「太久沒成功換發默默過期」的 federation 版，同款告警思路。
- Day10 SSRF——bundle endpoint 是「主動去連對方給的 URL」，SSRF 的教科書觸發條件。
- Day16 Security Logging / Monitoring——bundle 新鮮度、refresh 成功率的告警都在這條線上。
- Day07 / Day49 授權最小化 / BFLA——驗過對端 SPIFFE ID 只是 authN，partner 服務能做什麼仍在業務層。
- Day71 / Day72 Range / Slow DoS——主動連外的 bundle client 也要設回應大小與逾時上限。

---

明天預告：**Day 83 — SPIRE Server 的信任根保管：upstream CA、CA 簽發金鑰與 HSM（延伸篇）**
（這篇是**延伸篇**，不重講 Day80 的 SPIFFE ID / attestation、也不重講今天的 federation bundle 交換，聚焦一個今天反覆點名卻沒展開的東西：**SPIRE Server 用來簽所有 SVID 的那把 CA 金鑰**。Day80 說過它是「皇冠寶石」——被偷就能簽出任意 SPIFFE ID、整個 trust domain 淪陷；今天 federation 又證明了，你的 CA 一旦被冒充，連 partner 都會信任攻擊者簽的假身分。Day83 要處理的就是「怎麼讓這把金鑰即使 SPIRE Server 主機被攻陷也偷不走」：**① upstream CA 模式**——SPIRE Server 不自己當根，而是向上游 CA（企業 PKI / Vault PKI / AWS PCA）要一張中繼憑證來簽 SVID，把根金鑰隔離在 SPIRE 之外（承 Day15 secrets management、Day19 金鑰階層）；**② 用 KMS / HSM 保管簽發金鑰**——`KeyManager` plugin 讓私鑰不落地在 Server 檔案系統，簽章動作送進 HSM 做，主機被拿下也拿不到金鑰本體；**③ 短效中繼與金鑰輪替**——upstream 給的中繼憑證也短效化，並示範 SPIRE Server 的 CA rotation 怎麼在不中斷簽發下換金鑰。程式面會示範 SPIRE Server 的 `UpstreamAuthority` plugin 設定（Vault PKI 與 AWS PCA 兩種）與 `KeyManager` 走 KMS 的組態，並用 Day16 的角度談「CA 簽了什麼」的稽核日誌怎麼接。安全主軸一句話：**federation 讓別人信任你的 CA，所以你的 CA 金鑰保管等級，決定的不只是你自己、而是所有信任你的 trust domain 的安全上限。** 這是延伸篇，只聚焦信任根金鑰的保管與輪替，不重述 SVID 發放流程。）
