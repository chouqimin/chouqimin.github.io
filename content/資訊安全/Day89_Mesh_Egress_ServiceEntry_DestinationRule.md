---
title: "Day 89：mesh egress 出站流量的身分與對外 mTLS——ServiceEntry 把外連納入認知、DestinationRule 讓 Envoy 對外 originate TLS、egress gateway 與『防止應用繞過 egress 直接對外』（延伸篇）"
date: 2026-07-29
tags: ["Istio", "egress", "mTLS", "ServiceEntry"]
---

接續 Day88 預告：Day88 整篇在收**入站**——用 `PeerAuthentication` `STRICT`、應用只綁 `127.0.0.1`、`NetworkPolicy` 預設拒絕三層，逼別人打進來的流量非走 sidecar 不可。今天翻到**出站**的鏡像面：**當你的服務主動往外打**（呼叫第三方支付 API、對接雲端服務、跨 mesh），身分怎麼跟著出站流量走、對外的 mTLS 該在哪裡終結、以及怎麼防止應用繞過受控的 egress 路徑直接對外。

**這篇是延伸篇，不重講 Day19／74／75 的 mTLS 握手與憑證驗證基礎，也不重講 Day10／53 的 SSRF 入門，更不重講 Day88 的入站三層封堵。** TLS 怎麼握、`http.Client` 怎麼設、SSRF 怎麼防打內網——前面都講過，今天不重述。這篇只聚焦一件事：**mesh 的出站流量，怎麼從『黑洞』收成『有身分、受控、防繞過』。**

延伸角度只有一條主軸：**Day88 收好了「別人怎麼打進來」，Day89 收「你怎麼打出去」——出站同樣要有身分、要受控、要防繞過，而且對外的信任邊界比內部更需要明確列舉。** 為什麼「更」需要？因為內部服務之間至少共享一個 SPIFFE trust domain 的信任根（Day80），彼此的身分是同一套 CA 簽的；但你打出去的第三方 API 完全在你控制之外，沒有共同信任根、你也決定不了對方怎麼驗你——所以「能連去哪、用什麼身分連、怎麼加密」這三件事，出站比入站更容易變成沒人管的黑洞。這篇用三個手段各收一件事：**① `ServiceEntry` + `REGISTRY_ONLY`**——把「未知外連」從預設放行收成預設拒絕，讓 mesh 對外部目標有認知；**② `DestinationRule` originate TLS/mTLS**——把「對第三方的憑證與 mTLS」從應用碼搬到 sidecar，並講清楚「該由 mesh 還是應用做」的取捨；**③ egress gateway + `NetworkPolicy` egress 預設拒絕**——對稱 Day88 的「繞過 sidecar」，把「所有出站非走受控路徑不可」釘死。

> ⚠️ 以下 Istio `ServiceEntry`／`DestinationRule`／`meshConfig.outboundTrafficPolicy`、annotation（`traffic.sidecar.istio.io/excludeOutboundPorts`…）、egress gateway 佈署與 `NetworkPolicy` egress，都會隨你的 Istio／CNI／K8s 版本與 mesh 形態（sidecar vs ambient）不同。實際請對照你那套的官方 manifest，別照抄字串與埠號。這裡示範的是**三個手段各收哪一類出站風險**的意圖，不是某一版的精確語法。

---

## 一、先定位：出站的鏡像面——三個問題對三種手段

Day88 把「入站」拆成三種繞過、三層封堵。出站也一樣有三件事要收，而且剛好是入站的鏡像：

```text
[入站，Day88]   外部 ──▶ 目標 Envoy(15006) ──loopback──▶ app     收的是「打進來的流量非走 sidecar 不可」
[出站，Day89]   app ──loopback──▶ 自己 Envoy(15001) ──▶ 外部     收的是「打出去的流量非走受控路徑不可」

出站的三個問題（對三種手段）：
① 認知     mesh 對「未知外部目標」預設是黑洞（ALLOW_ANY passthrough）  →  ServiceEntry + REGISTRY_ONLY（出站 default deny）
② 加密身分  對第三方的 TLS/mTLS 該由誰做、憑證放哪                    →  DestinationRule originate TLS/mTLS（mesh vs 應用）
③ 防繞過    就算鋪了 egress gateway，應用仍可能直連外部繞過它          →  NetworkPolicy egress 預設拒絕 + 出站攔截
```

一句話定位：**入站收的是「可達性」（誰能連到我），出站要同時收三件——「能連去哪」（認知/allowlist）、「用什麼加密與身分連」（對外 TLS/mTLS）、「有沒有別條路繞過受控出口」（防繞過）。** 這三件分屬三個層次——`ServiceEntry`/`REGISTRY_ONLY` 在 mesh registry、`DestinationRule` 在 Envoy 的 TLS origination、`NetworkPolicy` egress 在 CNI 的 L3/L4——**正因為分屬不同層，才各自擋得住另外兩層看不到的那條路。**

**和 Day10／53 SSRF 的關係一次講清楚，之後不重述。** 出站的 allowlist 這件事，看起來跟 Day10 的 egress allowlist 很像，但角度不同、而且互補：

- **Day10／53 SSRF 防的是「應用被騙去打不該打的地方」**——使用者控制了 URL，把請求導向內網 metadata、內部服務、`169.254.169.254`。防禦重點在「解析後的目的 IP 是不是內網」。
- **今天 mesh egress 防的是「連能打去哪都要事先列舉，且出站身分與加密該由誰負責」**——就算沒有 SSRF、就算 URL 是寫死的，未經宣告的外連仍是 mesh 的黑洞（看不到、管不到、沒有身分、沒有稽核）。防禦重點在「registry 裡有沒有這個目標、對它的 TLS 誰做、流量有沒有走受控出口」。

兩者是 AND：**SSRF 防「被騙去打內網」，egress allowlist 防「未經列舉的外連」；一個防輸入被污染、一個防出站範圍失控，缺一個都留一條路。**

---

## 二、手段一：認知與 allowlist——`ServiceEntry` + `outboundTrafficPolicy: REGISTRY_ONLY`

先講最根本、也最常被漏的一件事：**mesh 預設對「不認識的外部目標」是放行的。**

Istio 的 `meshConfig.outboundTrafficPolicy.mode` 常見預設是 **`ALLOW_ANY`**：Envoy 對 mesh registry 裡沒宣告過的目標**一律放行、且是 passthrough**（TLS 不終結、L7 看不到、沒有稽核、沒有 policy）。這等於出站版的「沒有預設拒絕」——你的服務可以連任何外部位址，而平台完全無感。**這正是 Day07 default deny 在出站的反面教材：預設全通。**

把它翻成 **`REGISTRY_ONLY`**，語意就變成「**只有 mesh registry 裡宣告過的外部目標才能出去，其餘一律拒**」＝出站的 default deny：

```yaml
# meshConfig（IstioOperator 或 istio configmap）—— 把出站從「未知也放行」翻成「未宣告就拒」
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  meshConfig:
    outboundTrafficPolicy:
      mode: REGISTRY_ONLY        # 預設常是 ALLOW_ANY；翻成 REGISTRY_ONLY＝出站 default deny
```

翻成 `REGISTRY_ONLY` 之後，**要能連的外部服務就得用 `ServiceEntry` 明確宣告進 registry**——這就是把外部目標「納入 mesh 認知」：

```yaml
# 明確宣告「api.partner.com:443 是一個允許的外部 HTTPS 目標」
apiVersion: networking.istio.io/v1
kind: ServiceEntry
metadata:
  name: partner-payment-api
  namespace: tenant-a
spec:
  hosts:
    - api.partner.com          # 精確主機名，別用 "*.com" 這種 wildcard（見第五節）
  location: MESH_EXTERNAL       # 明確標成 mesh 外部
  ports:
    - number: 443
      name: https
      protocol: TLS            # 端到端 TLS（應用自己做 TLS）就用 TLS/HTTPS；要 mesh originate 見第三節
  resolution: DNS              # 用 DNS 解析；別用 NONE（見第五節）
```

跟 `REGISTRY_ONLY` 搭起來，效果就是：**沒被 `ServiceEntry` 宣告的外連，在 Envoy 這一跳就被拒**——出站範圍從「無限」收斂成「一張明確列舉的清單」。這跟 Day88 層一 `STRICT`（入站拒非 mTLS）是同構的：一個收「進來的必須帶身分」，一個收「出去的必須在清單上」。

三個立刻要注意的點：

- **`REGISTRY_ONLY` 是漸進切換，不能一刀切**——直接翻，會**當場切斷所有還沒宣告 `ServiceEntry` 的外連**（第三方 API、DNS-over-HTTPS、監控上報、套件下載）。正確順序跟 Day88 收 `STRICT` 一樣：**先用 Day16 的 Envoy egress access log 盤出「目前在往哪些外部目標打」→ 逐一補 `ServiceEntry` → 確認清單齊了 → 才翻 `REGISTRY_ONLY`**。
- **`ServiceEntry` 是「認知」不是「授權」**——它讓 mesh 知道這個目標存在、能對它做路由與 TLS origination；但「哪個 workload 可以連它」還是要靠 `AuthorizationPolicy`（承 Day87）或 `Sidecar` egress host 收窄。宣告了 `ServiceEntry` ≠ 全 mesh 都能連它。
- **`ServiceEntry` 開太寬等於沒收**——`hosts: "*"`、`resolution: NONE` 配上寬鬆 endpoints，會把「明確列舉」變回「幾乎全通」。這點第五節專門講。

---

## 三、手段二：對外 TLS/mTLS——`DestinationRule` originate（該 mesh 做還是應用做）

收好了「能連去哪」，下一個問題是「**對第三方的 TLS/mTLS 由誰做、憑證放哪**」。這是後端工程師最直接會碰到的取捨。

Istio 的 `DestinationRule` 用 `trafficPolicy.tls.mode` 決定 **Envoy 對外那一跳怎麼加密**，四個值對應四種責任歸屬：

| mode | Envoy 對外做什麼 | 典型場景 |
|---|---|---|
| `DISABLE` | 不碰 TLS，原樣轉出（應用自己端到端做 TLS） | 應用自己用 HTTP client 管 TLS/pinning |
| `SIMPLE` | Envoy 對外 originate 一般（單向）TLS，驗對方憑證 | 應用送純 HTTP 給 sidecar，sidecar 幫加 TLS 出去 |
| `MUTUAL` | Envoy 對外 originate mTLS，用**指定的 client 憑證** | 對接需要 client cert 的第三方 API |
| `ISTIO_MUTUAL` | 用 **Istio 自己的 SVID** 做 mTLS | mesh 內部／跨 mesh，**不是給任意第三方** |

**先破一個常見誤解：`ISTIO_MUTUAL` 不是拿來對第三方的。** 它用的是你 mesh 內部的 SVID（Day80），第三方根本不信你的 trust domain。對外部第三方要 client cert 的情況，用的是 `MUTUAL` + 你跟對方約定好的那張 client 憑證：

```yaml
# 對接「需要 client cert」的第三方 —— Envoy 對外 originate mTLS
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: partner-mtls
  namespace: tenant-a
spec:
  host: api.partner.com
  trafficPolicy:
    tls:
      mode: MUTUAL
      clientCertificate: /etc/certs/partner-client.pem   # 給第三方看的 client 憑證
      privateKey: /etc/certs/partner-client.key
      caCertificates: /etc/certs/partner-ca.pem          # 驗第三方伺服器憑證的 CA
      sni: api.partner.com                                # 別忘了 SNI，否則對方可能握不出正確憑證
```

而「應用送純 HTTP、sidecar 幫忙 originate 一般 TLS」的模式，是 `SIMPLE`：

```yaml
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: partner-tls-origination
spec:
  host: api.partner.com
  trafficPolicy:
    tls:
      mode: SIMPLE          # Envoy 對外做單向 TLS；應用只要送 http:// 給 sidecar
      sni: api.partner.com
```

### 核心取捨：對外 mTLS，該 mesh 做還是應用做？

這題沒有唯一答案，判準跟 Day79「TLS 在哪終結，換發就在哪做」是同一把尺——**對外 TLS 該在哪終結，取決於你的憑證管理放哪、以及你要不要端到端加密**：

- **mesh 做（`DestinationRule` originate）**：把「對第三方的憑證、pinning、cipher policy」從應用碼搬到 sidecar（承 Day87「身分離開應用」的同一主軸）。應用只送純 HTTP，好處是**憑證輪替、對外 mTLS、cipher 政策集中在平台**，一次改全部生效，應用無感。
  - 代價一：**應用↔自己 sidecar 那段是 pod 內 loopback 明文**（承 Day88／Day87），pod 內其他容器共用 network namespace 就看得到——多容器 pod 別混不受信任的容器。
  - 代價二：**認知落差**——應用工程師看自己的碼是 `http://`，很容易以為「沒加密」或反過來「反正 mesh 會加密」而不去確認 `DestinationRule` 到底有沒有生效。一旦 `DestinationRule` 沒套到、或流量繞過了 sidecar（第四節），那段就真的裸奔明文出去了。
- **應用做**：應用自己用 `http.Client`／`OkHttp` 管 TLS，**端到端加密（連 loopback 那段都加密）**，client cert 也在應用手上。好處是加密邊界清楚、不依賴 mesh 攔截；代價是**憑證／pinning／cipher 散在每個應用碼裡**，正是 Day19 的老問題——輪替一張 client cert 要改 N 個服務。

一句話判準：**要「集中管理、應用無感」就讓 mesh 做，但要接受 loopback 明文與認知落差；要「端到端加密、憑證自己捏在手上」就應用做，但要接受憑證管理分散。** 高敏感的對外連線（金流、含 PII）通常傾向應用端到端做、或至少確認 mesh originate 有實測驗證過。

### Go：兩種寫法

```go
// ── 寫法 A：應用自己對外做 mTLS（端到端，連 loopback 都加密；client cert 在應用手上）
clientCert, _ := tls.LoadX509KeyPair("/etc/certs/partner-client.pem", "/etc/certs/partner-client.key")
pool := x509.NewCertPool()
caPEM, _ := os.ReadFile("/etc/certs/partner-ca.pem")
pool.AppendCertsFromPEM(caPEM)

appTLS := &http.Client{
	Timeout: 10 * time.Second,                       // 對外一定要設逾時（承 Day72 slow）
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,           // 別讓對外降級（承 Day19）
			Certificates: []tls.Certificate{clientCert}, // 送給第三方的 client cert＝mTLS
			RootCAs:      pool,
		},
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse                // 對外別亂跟跳轉（承 Day10/67/68）
	},
}
resp, err := appTLS.Get("https://api.partner.com/v1/charge")  // 注意是 https://

// ── 寫法 B：交給 mesh originate（應用只送 http:// 給 sidecar，TLS 由 DestinationRule 做）
meshClient := &http.Client{Timeout: 10 * time.Second}
resp2, err2 := meshClient.Get("http://api.partner.com/v1/charge") // 注意是 http://
// Envoy 攔截 → 依 ServiceEntry/DestinationRule 對 443 originate TLS/mTLS
// 前提：ServiceEntry 有對應的埠設定、DestinationRule tls.mode 有生效、流量真的走了 sidecar（第四節）
```

### Java：兩種寫法

```java
// ── 寫法 A：OkHttp 應用自己對外做 mTLS（Java 21）
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(keyManagers, trustManagers, null);          // keyManagers 帶 client cert；trustManagers 驗對方
OkHttpClient appClient = new OkHttpClient.Builder()
        .sslSocketFactory(ctx.getSocketFactory(), (X509TrustManager) trustManagers[0])
        .callTimeout(Duration.ofSeconds(10))          // 對外逾時（承 Day72）
        .followRedirects(false)                       // 對外別亂跟跳轉（承 Day10/67/68）
        .build();
Request req = new Request.Builder().url("https://api.partner.com/v1/charge").build();

// Spring RestClient（Spring 6.1+／Boot 3.2+）綁自訂 SSLContext 也是同理：
// RestClient.builder().requestFactory(sslRequestFactory(ctx)).build();

// ── 寫法 B：交給 mesh originate（應用只送 http:// 給 sidecar）
RestClient meshClient = RestClient.create();
String body = meshClient.get()
        .uri("http://api.partner.com/v1/charge")       // http://，TLS 由 Envoy originate
        .retrieve().body(String.class);
```

> Java 1.8 沒有 `java.net.http.HttpClient`，「應用自己做對外 TLS」走 `HttpsURLConnection.setSSLSocketFactory(ctx.getSocketFactory())` 或 Apache HttpClient；`SSLContext`／`X509TrustManager`／OkHttp 在 1.8 與 21 都可用，Spring `RestClient` 需要 Spring 6.1+（Java 17+）。無論哪版，對外都記得設逾時、關 follow redirect。**別為了跑起來自寫空的 `X509TrustManager` 繞過對第三方的憑證驗證**（承 Day75）——那比 mesh 有沒有 originate 更早就把 TLS 拆了。

---

## 四、手段三：防繞過——egress gateway + `NetworkPolicy` egress 預設拒絕

前兩節收好了「能連去哪」「怎麼加密」——但還有一類問題它們都管不到：**流量根本沒走你以為的受控出口。** 這是 Day88「繞過 sidecar」在出站的鏡像。

**egress gateway** 是所有出站集中經過的一個受控節點，價值有三：集中做 TLS origination、當對外流量的統一稽核點、給第三方一個**固定的出口 IP** 讓對方 allowlist。但它跟 sidecar 一樣，是**靠攔截把流量導過去**的——攔截前提一破，應用就直接對外了。

出站的三種繞過（對稱 Day88 入站三種）：

```text
[繞過 A：未知外連被放行]   app ──▶ 任意外部            破口：outboundTrafficPolicy 停在 ALLOW_ANY ⇒ 未宣告也放行
                          擋它的：手段一 REGISTRY_ONLY（未宣告就拒）

[繞過 B：直連外部不經 egress] app ──直連 IP──▶ 外部     破口：sidecar 有攔截但沒逼「非走 egress gateway 不可」
                          擋它的：VirtualService 把外連導去 egress gateway ＋ 只信任從 egress gateway 出去的路徑

[繞過 C：連攔截都不成立]     hostNetwork / excludeOutboundPorts / node 直連 ──▶ 外部
                          破口：sidecar iptables 出站攔截在這些情況不成立
                          擋它的：NetworkPolicy egress 預設拒絕（L3/L4 收「這個 pod 能往外開哪些連線」）
```

最關鍵、也最像 Day88 的一層是 **`NetworkPolicy` egress 預設拒絕**——它在 CNI 層收「這個 pod 能對外開哪些 TCP 連線」，**不管流量有沒有走 sidecar**，所以擋得住 `hostNetwork`、`excludeOutboundPorts`、node 直連這些「連 Envoy 都沒碰到」的出站：

```yaml
# ① 預設拒絕出站：選中 ns 內所有 pod、宣告 Egress 型別但不給任何 egress rule＝出站全拒
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: tenant-a
spec:
  podSelector: {}                    # 空 selector＝套用到 ns 內每個 pod
  policyTypes: ["Egress"]            # 宣告 Egress 且不給 egress 陣列＝出站全拒
---
# ② 明確放行：只允許出站到 DNS 與 egress gateway，其餘一律拒
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-dns-and-gateway
  namespace: tenant-a
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
    - to:                            # 放行 DNS（不放行 DNS 會整個 ns 解不了名）
        - namespaceSelector: {}
          podSelector:
            matchLabels: { k8s-app: kube-dns }
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - to:                            # 只允許出站到 egress gateway，逼所有對外非走它不可
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: istio-system }
          podSelector:
            matchLabels: { istio: egressgateway }
```

三個要點（和 Day88 層三對稱）：

- **`NetworkPolicy` egress 看不到 mesh／TLS**——它只認 selector／IP/port。所以它和 `REGISTRY_ONLY` 是 **AND、不是替代**：`REGISTRY_ONLY` 收「Envoy 那跳只准連宣告過的目標」，`NetworkPolicy` egress 收「這個 pod 在 L3/L4 只准往 egress gateway 與 DNS 開連線」。前者管走了 sidecar 的流量、後者管**沒走 sidecar 的流量**，兩層擋兩種繞過。
- **別忘了放行 DNS**——出站預設拒絕最常見的翻車，是把 UDP/TCP 53 一起擋掉，結果整個 namespace 連名字都解不了，症狀像「什麼都連不上」但其實是 DNS 被擋。放行 egress gateway 的同時一定要放行 kube-dns。
- **一樣要 CNI 支援 egress 才算數**——不是每個 CNI 都執行 `NetworkPolicy` 的 Egress 方向；用之前確認你的 CNI（Calico／Cilium 等）真的在強制它，否則你以為鋪了出站預設拒絕、其實是張廢紙。**務必用第七節的實測驗證，別假設。**

把三層疊起來，出站就從「黑洞」變成：Envoy 那跳只准連宣告過的目標（`REGISTRY_ONLY`）、對外加密集中在受控出口（egress gateway + `DestinationRule`）、L3/L4 只准往 egress gateway 開連線（`NetworkPolicy` egress）——**任何一條想繞過受控出口直接對外的路，都會撞到其中一層。**

---

## 五、「合法但打洞」的出站設定

三層鋪好之後，真正的漏水點往往是這些**合法、有正當用途、但一設就在出站上打洞**的旋鈕（對稱 Day88 第五節）：

- **`outboundTrafficPolicy: ALLOW_ANY` 殘留**：只要 mesh 還停在 `ALLOW_ANY`，前面的 `ServiceEntry` allowlist 就形同虛設——未宣告的目標一樣放行。這是出站最大的隱形破口，等於「裝了 allowlist 卻沒開」。
- **`ServiceEntry` 開太寬**：`hosts: "*"` 或 `"*.amazonaws.com"` 這種 wildcard、配上 `resolution: NONE`，會把「精確列舉」變回「幾乎全通」。`resolution: NONE` 讓 Envoy 不自己解析、直接把 client 給的位址拿去連，收斂力大幅下降。要用就用精確主機名 + `resolution: DNS`，wildcard 只在真的必要且範圍極窄時用。
- **`traffic.sidecar.istio.io/excludeOutboundPorts` / `excludeOutboundIPRanges`**：明確叫 sidecar「這些出站埠／網段**不要**攔進 Envoy」。用途是某些出站不能走 mesh，代價是**這些出站完全不經 Envoy＝沒有 `ServiceEntry` 管制、沒有 `DestinationRule` 的 TLS origination、沒有稽核**。每一個被排除的出站範圍都是一個 allowlist 管不到的洞。
- **`hostNetwork: true`**：pod 共用 node 的 network namespace，per-pod 的 sidecar 出站攔截**在這種 pod 上不成立**——應用可以直接從 node 對外，繞過整套 egress 控制。跟 Day88 一樣，應用 pod 出現 `hostNetwork: true` 幾乎都是紅旗。
- **`DestinationRule` `tls.mode: DISABLE` 用錯地方**：在「本來預期 mesh 幫忙 originate TLS」的目標上設 `DISABLE`，會讓 Envoy 原樣把明文轉出去——如果應用又沒自己做 TLS，就是明文對外。

一句話：**這些設定都合法，但每一個都在你的出站控制上開一道後門；它們不該被禁止，該被『稽核到、有人簽核、有清單』**——這正好接到第六節。

---

## 六、Day16 稽核：靜態掃「wildcard／打洞／缺出站預設拒絕」，執行期抓未知外連

出站最危險的幾個狀態——**`ServiceEntry` wildcard／`resolution: NONE`、`excludeOutboundPorts/IPRanges` 打洞、`hostNetwork` 繞過、namespace 沒有出站預設拒絕 `NetworkPolicy`**——都能靜態掃出來。把它寫成 CI／admission，就是 Day16「把偵測升級成預防」在出站的落點（承 Day87／88 第六節同一套心法：先在 chat／CI 跑一次看資料長相，再寫解析）。

先看資料長相：

```bash
kubectl get serviceentry -A -o json
kubectl get pods -A -o json
kubectl get networkpolicy -A -o json
```

**Go 版**：掃 `ServiceEntry` 抓 wildcard host 與 `resolution: NONE`，掃 pod 抓 `excludeOutboundPorts/IPRanges` 與 `hostNetwork`。

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type seList struct {
	Items []struct {
		Metadata struct{ Name, Namespace string } `json:"metadata"`
		Spec     struct {
			Hosts      []string `json:"hosts"`
			Resolution string   `json:"resolution"`
		} `json:"spec"`
	} `json:"items"`
}

type podList struct {
	Items []struct {
		Metadata struct {
			Name, Namespace string
			Annotations     map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			HostNetwork bool `json:"hostNetwork"`
		} `json:"spec"`
	} `json:"items"`
}

func kubectlJSON(v any, args ...string) {
	out, err := exec.Command("kubectl", args...).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kubectl 失敗：", err)
		os.Exit(2)
	}
	if err := json.Unmarshal(out, v); err != nil {
		fmt.Fprintln(os.Stderr, "JSON 解析失敗：", err)
		os.Exit(2)
	}
}

func main() {
	fail := false

	// ① ServiceEntry：wildcard host 或 resolution NONE 都點名（allowlist 被開太寬）
	var ses seList
	kubectlJSON(&ses, "get", "serviceentry", "-A", "-o", "json")
	for _, se := range ses.Items {
		for _, h := range se.Spec.Hosts {
			if strings.Contains(h, "*") {
				fmt.Printf("FAIL %s/%s：host=%q 含 wildcard（allowlist 開太寬）\n",
					se.Metadata.Namespace, se.Metadata.Name, h)
				fail = true
			}
		}
		if strings.EqualFold(se.Spec.Resolution, "NONE") {
			fmt.Printf("FAIL %s/%s：resolution=NONE（Envoy 不自解析、收斂力大降）\n",
				se.Metadata.Namespace, se.Metadata.Name)
			fail = true
		}
	}

	// ② Pod：excludeOutboundPorts / excludeOutboundIPRanges（打洞）與 hostNetwork（整台繞過）
	var pods podList
	kubectlJSON(&pods, "get", "pods", "-A", "-o", "json")
	for _, pod := range pods.Items {
		for _, k := range []string{
			"traffic.sidecar.istio.io/excludeOutboundPorts",
			"traffic.sidecar.istio.io/excludeOutboundIPRanges",
		} {
			if v := pod.Metadata.Annotations[k]; v != "" {
				fmt.Printf("FAIL %s/%s：%s=%q（這段出站不經 Envoy＝無 allowlist/TLS 管制）\n",
					pod.Metadata.Namespace, pod.Metadata.Name, k, v)
				fail = true
			}
		}
		if pod.Spec.HostNetwork {
			fmt.Printf("FAIL %s/%s：hostNetwork=true（共用 node netns，出站攔截失效）\n",
				pod.Metadata.Namespace, pod.Metadata.Name)
			fail = true
		}
	}

	if fail {
		os.Exit(1)
	}
	fmt.Println("OK：無 wildcard/NONE ServiceEntry、無 excludeOutbound* / hostNetwork 打洞")
}
```

**Java 版**（Jackson，對稱邏輯，跑在 CI 或維運工具裡）：

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class EgressAudit {
    static final ObjectMapper OM = new ObjectMapper();

    static JsonNode kubectl(String... args) throws Exception {
        String[] cmd = new String[args.length + 1];
        cmd[0] = "kubectl";
        System.arraycopy(args, 0, cmd, 1, args.length);
        Process p = new ProcessBuilder(cmd).redirectErrorStream(false).start();
        return OM.readTree(p.getInputStream());
    }

    public static void main(String[] args) throws Exception {
        boolean fail = false;

        // ① ServiceEntry wildcard host / resolution NONE
        for (JsonNode se : kubectl("get", "serviceentry", "-A", "-o", "json").path("items")) {
            String ns = se.path("metadata").path("namespace").asText();
            String name = se.path("metadata").path("name").asText();
            for (JsonNode h : se.path("spec").path("hosts")) {
                if (h.asText().contains("*")) {
                    System.out.printf("FAIL %s/%s：host=%s 含 wildcard%n", ns, name, h.asText());
                    fail = true;
                }
            }
            if ("NONE".equalsIgnoreCase(se.path("spec").path("resolution").asText(""))) {
                System.out.printf("FAIL %s/%s：resolution=NONE%n", ns, name);
                fail = true;
            }
        }

        // ② Pod excludeOutbound* / hostNetwork
        String[] keys = {
            "traffic.sidecar.istio.io/excludeOutboundPorts",
            "traffic.sidecar.istio.io/excludeOutboundIPRanges",
        };
        for (JsonNode pod : kubectl("get", "pods", "-A", "-o", "json").path("items")) {
            String ns = pod.path("metadata").path("namespace").asText();
            String name = pod.path("metadata").path("name").asText();
            JsonNode ann = pod.path("metadata").path("annotations");
            for (String k : keys) {
                String v = ann.path(k).asText("");
                if (!v.isEmpty()) {
                    System.out.printf("FAIL %s/%s：%s=%s（不經 Envoy）%n", ns, name, k, v);
                    fail = true;
                }
            }
            if (pod.path("spec").path("hostNetwork").asBoolean(false)) {
                System.out.printf("FAIL %s/%s：hostNetwork=true（出站攔截失效）%n", ns, name);
                fail = true;
            }
        }

        if (fail) System.exit(1);
        System.out.println("OK：無 wildcard/NONE ServiceEntry、無打洞設定");
    }
}
```

三個 CI 要補、但上面沒涵蓋的角度：

- **`outboundTrafficPolicy` 是不是還停在 `ALLOW_ANY`**：這在 `istio-system` 的 istio configmap／IstioOperator 裡，掃 `kubectl -n istio-system get configmap istio -o jsonpath=...` 的 `meshConfig`，判斷 `outboundTrafficPolicy.mode` 是否為 `REGISTRY_ONLY`；不是就判紅——這是出站 allowlist 的總開關，比任何 `ServiceEntry` 都優先。
- **「namespace 有 workload 卻沒有出站預設拒絕 `NetworkPolicy`」**：延用 Day88 第六節 `nsHasDefaultDeny` 的同構邏輯——掃 `networkpolicy`，對「`podSelector: {}` 且 `policyTypes` 含 `Egress`、且無 `egress` 陣列」記為該 ns 有出站預設拒絕，再對照有 workload 卻沒有的 ns 判紅。
- **對外流量到底走沒走 egress gateway，CI 看不到**——那是執行期才觀察得到的。補法見執行期稽核。

**執行期承 Day16**：把 Envoy 的 **egress access log** 打進 SIEM，比對「打向**有 `ServiceEntry` 的已知目標**」vs「**passthrough 的未知外連**」，對後者告警——這既是第二節「翻 `REGISTRY_ONLY` 前先盤出在往哪打」的資料來源，也是上線後「有人偷連未宣告目標／偷繞 egress」的偵測線。**因為 allowlist 與 `DestinationRule` 掃得再乾淨，都擋不住『根本沒走 sidecar／egress』的出站；那條只能靠執行期的流量稽核抓。**

---

## 七、常見誤區

| 誤區 | 為什麼錯 |
|---|---|
| 「入站收好了，出站沒什麼好收的」 | 出站要收三件：能連去哪、怎麼加密、有沒有繞過受控出口；預設 `ALLOW_ANY` 就是出站黑洞（第一、二節） |
| 「mesh 預設就會擋未知外連」 | 預設常是 `ALLOW_ANY`＝未宣告目標一律放行且 passthrough；要 `REGISTRY_ONLY` 才是出站 default deny（第二節） |
| 「egress allowlist 跟 SSRF 防禦是同一件事」 | SSRF 防「被騙去打內網」、allowlist 防「未經列舉的外連」；一個防輸入污染、一個防範圍失控，是 AND（第一節） |
| 「宣告了 `ServiceEntry` 就等於授權誰都能連」 | `ServiceEntry` 只是「認知」；哪個 workload 能連還要 `AuthorizationPolicy`／`Sidecar` egress 收窄（第二節） |
| 「對外 mTLS 用 `ISTIO_MUTUAL` 就好」 | `ISTIO_MUTUAL` 用的是內部 SVID，第三方不信你的 trust domain；對外要 `MUTUAL` + 約定的 client cert（第三節） |
| 「TLS 交給 mesh 做，應用就一定加密了」 | mesh 做的話 app↔sidecar 那段是 loopback 明文，且 `DestinationRule` 沒生效／流量繞過就裸奔（第三、四節） |
| 「應用送 `http://` 就代表沒加密、不安全」 | 若 `DestinationRule` originate 有生效，對外那段是 TLS；但你得實測確認它真的生效（第三節） |
| 「鋪了 egress gateway，出站就一定經過它」 | egress gateway 靠攔截導流，攔截前提會破；要 `NetworkPolicy` egress 逼「非走它不可」（第四節） |
| 「有 `REGISTRY_ONLY`，`NetworkPolicy` egress 是多餘的」 | `REGISTRY_ONLY` 是 Envoy（L7）、`NetworkPolicy` 是 CNI（L3/L4）；沒走 sidecar 的出站只有後者擋得到（第四節） |
| 「出站預設拒絕就把 53 也擋掉」 | 擋掉 DNS 會整個 ns 解不了名，症狀像全斷；放行 egress gateway 一定要一起放行 kube-dns（第四節） |
| 「`excludeOutboundPorts` 只是維運細節」 | 被排除的出站完全不經 Envoy＝無 allowlist／無 TLS origination／無稽核，是管不到的洞（第五節） |
| 「`ServiceEntry` 用 `hosts: "*"` 比較好管」 | wildcard + `resolution: NONE` 把精確列舉打回幾乎全通，等於沒收（第五節） |

---

## 八、Code Review / 維運 checklist

**手段一：認知與 allowlist（第二節）**

- [ ] `meshConfig.outboundTrafficPolicy.mode` 最終為 `REGISTRY_ONLY`；沒有殘留的 `ALLOW_ANY`。
- [ ] 翻 `REGISTRY_ONLY` 前已用 Day16 egress log 盤出所有外連並逐一補 `ServiceEntry`，採漸進切換（承 Day16）。
- [ ] `ServiceEntry` 用精確主機名 + `resolution: DNS`，沒有非必要的 `hosts: "*"` 與 `resolution: NONE`。
- [ ] 哪個 workload 能連哪個外部目標，有用 `AuthorizationPolicy`／`Sidecar` egress host 收窄，不是宣告了就全 mesh 可連。

**手段二：對外 TLS/mTLS（第三節）**

- [ ] 對第三方的 mTLS 用 `MUTUAL` + 約定 client cert，不是 `ISTIO_MUTUAL`；`sni` 有設。
- [ ] 「mesh 做 vs 應用做」有明確決定並記錄；高敏感對外連線傾向端到端或實測驗證過 originate。
- [ ] 應用自己做對外 TLS 時：設逾時、`MinVersion` TLS1.2+、關 follow redirect、沒有自寫空 `TrustManager`（承 Day19／75）。
- [ ] 交給 mesh 做時：確認 `DestinationRule` 真的套到、且流量沒繞過 sidecar（第四節），loopback 明文那段的 pod 內沒有不受信任容器。

**手段三：防繞過（第四節，承 Day07）**

- [ ] 每個有 workload 的 namespace 都鋪了出站預設拒絕（`podSelector: {}` + `policyTypes: ["Egress"]`、無 egress rule）。
- [ ] 放行清單只含 DNS（53）與 egress gateway；對外一律逼走 egress gateway。
- [ ] 已實測確認 CNI 真的在強制 `NetworkPolicy` 的 Egress 方向（不是鋪了沒生效）。

**打洞設定與稽核（第五、六節，承 Day16）**

- [ ] 沒有非預期的 `excludeOutboundPorts`／`excludeOutboundIPRanges`。
- [ ] 應用 pod 無 `hostNetwork: true`；`DestinationRule` 沒有在不該的地方設 `tls.mode: DISABLE`。
- [ ] CI／admission 掃「wildcard/NONE `ServiceEntry`＋`excludeOutbound*`＋`hostNetwork`＋`ALLOW_ANY`＋缺出站預設拒絕」並判紅。
- [ ] 執行期把「passthrough 未知外連」打進 SIEM 告警。

---

## 九、測試 / 演練建議

- **出站繞過測試（最重要，對稱 Day88 入站繞過）**：從應用容器直接連一個**未宣告 `ServiceEntry` 的外部位址**，斷言**連不上或被拒**。連得上＝你的 allowlist／`NetworkPolicy` egress 還有洞（`ALLOW_ANY` 殘留、或 CNI 沒強制 egress）。
- **`REGISTRY_ONLY` 生效測試（手段一）**：連一個**沒宣告**的 host 斷言**被拒**、連一個**宣告過**的 host 斷言**通**——證明出站 allowlist 真的在收，不是擺設。
- **對外 mTLS 測試（手段二）**：對一個**要求 client cert** 的測試端點發請求，斷言 `MUTUAL`（或應用端 mTLS）**握手成功**；再故意拿掉 client cert，斷言**被對方拒**——證明 client 憑證真的送出去了。
- **egress 集中測試（手段三）**：從多個服務對外打，斷言對方看到的**來源 IP 都是 egress gateway 的固定出口 IP**——證明流量真的收斂到受控出口，沒有各自直連。
- **DNS 沒被誤擋測試（手段三）**：鋪上出站預設拒絕後，斷言 ns 內服務**仍能解析名字**（放行 53 有生效），避免「什麼都連不上」其實是 DNS 被擋。
- **打洞迴歸（第五、六節）**：把某 pod 加上 `excludeOutboundPorts`／`hostNetwork`，或把 `ServiceEntry` 改成 `hosts: "*"`，斷言第六節的 CI／admission **判紅**。測不過代表你的稽核是擺設。
- **`REGISTRY_ONLY` 漸進切換演練（第二節）**：在測試叢集把 `outboundTrafficPolicy` 從 `ALLOW_ANY` 翻 `REGISTRY_ONLY`，先斷言「未宣告的外連斷、已宣告的正常」，驗證你的漸進順序與 egress log 能在切換前盤齊清單，避免正式環境一刀斷線。

---

## 十、一句話總結

> Day88 收好了「別人怎麼打進來」，Day89 收「你怎麼打出去」——出站同樣要有身分、要受控、要防繞過，而且對外的信任邊界比內部更需要明確列舉（內部至少共享 SPIFFE trust domain，第三方完全在你控制之外）。三個手段各收一件：**手段一 `ServiceEntry` + `outboundTrafficPolicy: REGISTRY_ONLY`**——mesh 預設常是 `ALLOW_ANY`＝未宣告的外連一律放行且 passthrough＝出站黑洞，翻成 `REGISTRY_ONLY` 就是出站 default deny（承 Day07），要連的外部服務用 `ServiceEntry` 精確宣告進 registry（精確主機名 + `resolution: DNS`，別 `hosts: "*"`／`resolution: NONE`），切換前先用 Day16 egress log 盤齊清單漸進切；這和 Day10／53 SSRF 是 AND 不是重複——SSRF 防「被騙去打內網」、allowlist 防「未經列舉的外連」。**手段二 `DestinationRule` originate TLS/mTLS**——對第三方的 TLS 該 mesh 做還是應用做，判準同 Day79「TLS 在哪終結就在哪管」：mesh 做（`SIMPLE`/`MUTUAL`，`MUTUAL` 才是給第三方 client cert，`ISTIO_MUTUAL` 是內部 SVID 別誤用）把憑證集中到 sidecar、應用無感，代價是 app↔sidecar loopback 明文與認知落差；應用做（Go `http.Client`+`tls.Config`、Java OkHttp/`SSLContext`）端到端加密、憑證自己捏，代價是散在各應用碼；兩種都記得設逾時、關 follow redirect、別自寫空 `TrustManager`。**手段三 egress gateway + `NetworkPolicy` egress 預設拒絕**——對稱 Day88「繞過 sidecar」，egress gateway 靠攔截導流、前提會破，所以要 `NetworkPolicy` egress（`policyTypes: ["Egress"]` 無 rule＝出站全拒，再放行 DNS 53 與 egress gateway）在 L3/L4 逼「所有出站非走受控出口不可」，它和 `REGISTRY_ONLY` 是 AND（一個 L7 一個 L3/L4，擋不同繞過），但別忘放行 DNS、且要實測 CNI 真的強制 egress。最後那些「合法但打洞」的旋鈕——`ALLOW_ANY` 殘留、wildcard `ServiceEntry`、`excludeOutboundPorts/IPRanges`、`hostNetwork`、`tls.mode: DISABLE` 用錯地方——不該被禁止，該被**稽核到**：把它們寫成 CI／admission（承 Day16），執行期再對「passthrough 未知外連」告警。一句話：**Day88 把入站可達性釘死，Day89 把出站的『能連去哪＋怎麼加密＋有沒有繞過』一起釘死——因為出站只要留一條未受控的路，你的服務就能把資料與身分送去任何你看不到的地方。**

---

## 延伸閱讀

- Day88 mesh 全域強制 mTLS 與封堵繞過 sidecar——本篇的入站鏡像：Day88 收「別人怎麼打進來非走 sidecar 不可」，今天收「你怎麼打出去非走受控出口不可」，三種繞過／三層封堵一一對稱。
- Day10 / Day53 SSRF——egress allowlist 的另一半：SSRF 防「被騙去打內網」，本篇的 `ServiceEntry` allowlist 防「未經列舉的外連」，兩者是 AND。
- Day07 Broken Access Control——預設拒絕、最小權限：`REGISTRY_ONLY` 與 `NetworkPolicy` egress 預設拒絕就是它在出站 L7／L3-L4 的落點。
- Day19 / Day75 TLS 基礎——對外 TLS/mTLS 的握手與憑證驗證；今天不重述，只講「該由 mesh 還是應用做、憑證放哪」。
- Day79 ACME——「TLS 在哪終結，換發就在哪做」的同一把尺，用來判斷對外 mTLS 該在 sidecar 還是應用終結。
- Day87 SPIRE × service mesh——「身分離開應用交給 sidecar」的同一主軸；今天把「對外的憑證與 mTLS」也交給 sidecar 是它的延伸。
- Day16 Security Logging / Monitoring——翻 `REGISTRY_ONLY` 前盤外連、上線後抓 passthrough 未知外連，都靠這裡的 egress log 與告警。

---

明天預告：**Day 90 — mesh 的 L7 細粒度授權：Envoy `ext_authz` 外接授權服務（OPA/Rego）、`AuthorizationPolicy` 的天花板、fail-open vs fail-closed 與授權服務的可用性（延伸篇）**
（這是**延伸篇**，不重講 Day07 的存取控制入門、Day49 的 BFLA、也不重講 Day87 的 `AuthorizationPolicy` 接線與 Day81 的 aud 驗證。Day87 把 mesh 的授權收到 `AuthorizationPolicy` 的 `principals`／`methods`／`paths` 層級——但那是**宣告式、無狀態**的比對，做不到「使用者只能讀自己的訂單」這種**依資料而定（data-dependent）的細粒度授權**，那正是 Day07 IDOR／Day49 BFLA 的地盤。明天整篇處理那個天花板：**當授權決策需要看請求內容、看被存取物件的擁有者、看外部政策時，怎麼用 Envoy `ext_authz` 把決策外接給一個授權服務（常見是 OPA/Rego 或你自己寫的 gRPC 服務）。** 延伸角度三條：**① `AuthorizationPolicy` 的天花板**——為什麼宣告式 L4/L7 比對表達不了 per-object／business-rule 授權，`ext_authz` 補的正是這一段（承 Day07／49／87）；**② `ext_authz` 契約**——Envoy 在轉發前先呼叫外部授權服務（gRPC `CheckRequest` 或 HTTP），拿 allow/deny 決策，政策寫在 OPA sidecar 的 Rego 或自寫服務裡，示範 Go／Java 實作一個最小 `ext_authz` 服務；**③ fail-open vs fail-closed**——授權服務掛了，Envoy 該放行還是該拒？這是可用性與安全的取捨，`ext_authz` 的 `failure_mode_allow` 一旦設成 open 就等於「授權服務一掛全部放行」＝Day07 default deny 的反面，還要談決策快取與延遲預算。程式面會示範 Envoy `ext_authz` filter 設定 + OPA Rego 政策 + Go/Java 授權服務、以及一支掃「`failure_mode_allow: true`／授權服務沒覆蓋 object-level」的稽核。安全主軸一句話：**Day87 讓 mesh 能問『你是誰』，Day90 讓 mesh 能問『這一次請求你到底能不能做』——把授權從宣告式比對升級成可帶業務規則的決策，但決策服務本身的可用性與 fail 行為，會變成新的單點。** 這是延伸篇，只聚焦 `ext_authz` 的細粒度授權與 fail 行為，不重述存取控制與 `AuthorizationPolicy` 基礎。）
