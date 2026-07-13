---
title: "Day 74：mTLS / TLS 握手 DoS（延伸篇，承 Day19 TLS × Day72/73 DoS 家族）— 重協商、握手洪水、憑證鏈驗證放大與 Go / Java 的握手成本控制"
date: 2026-07-14
tags: ["TLS", "mTLS", "DoS", "Handshake"]
---

# Day 74：mTLS / TLS 握手 DoS

接續 Day73 預告：Day71（Range 放大）、Day72（Slowloris 連線佔用）、Day73（HTTP/2 協定層）打的都是**連線建好之後**的 HTTP 層。今天往下再降一層——**連線還沒建好、還在 TLS 握手階段**，本身就是一個攻擊面。

> **這是一篇延伸篇。** 我**不會**重講 Day19 的 TLS 基礎（TLS 是什麼、憑證怎麼驗、cipher 怎麼選、怎麼保護敏感資料）——那些請看 Day19。這篇只聚焦一個很窄的角度：**TLS 握手（尤其 mTLS）本身的「運算不對稱」如何被拿來做 DoS，以及後端框架怎麼把握手成本壓下來。**

為什麼握手值得單獨寫一篇？因為它跟 Day72/73 的 DoS 是**同一個母題的不同化身**：

- Day72 Slowloris 是「**慢速佔用**」——用小封包拖住連線槽。
- Day73 Rapid Reset 是「**處理成本不對稱**」——client 送一個 `RST_STREAM`（廉價），server 已經 dispatch 了完整請求（昂貴）。
- 本篇 TLS 握手 DoS 是「**運算成本不對稱**」——client 發起一次握手（相對廉價），server 卻要做一次**非對稱金鑰運算**（RSA 私鑰解密 / ECDHE 簽章）外加（mTLS 下）**驗證整條憑證鏈**（昂貴）。

換句話說：**握手階段，攻擊者花一塊錢，你花十塊錢。** 這種不對稱一旦被高速重複，CPU 就被燒光——而且和 Day72/73 一樣，**這類攻擊流量可能不大、CPU 曲線也不一定爆表在你習慣的告警點上**，傳統流量/CPU 告警（承 Day16）容易漏掉。

---

## 一、先建立心智模型：握手為什麼「運算不對稱」

只講跟 DoS 相關的部分，其餘 TLS 握手細節略（看 Day19）。

**1. 一次完整握手（full handshake），server 一定要做一次私鑰非對稱運算。**

- RSA 金鑰交換年代：server 用**私鑰解密** client 送來的 pre-master secret。
- 現代 ECDHE：server 用**私鑰簽章** ephemeral 參數。
- 不管哪種，**server 的私鑰運算成本遠高於 client 的對應運算**。歷史上 RSA 握手 server 端成本可達 client 的近十倍。這個「一次握手就逼你做一次昂貴私鑰運算」就是所有握手 DoS 的根。

**2. 重用（resumption）可以跳過昂貴那步。** 若 client 帶著上次的 session（session ticket / TLS 1.3 PSK），server 用對稱式的 resumption 就能重建連線，**省掉非對稱私鑰運算**。所以「有沒有開 resumption」直接決定攻擊者能不能每次都逼你走 full handshake。

**3. mTLS 讓 server 多背一份成本。** 開了 client 憑證驗證（mTLS），server 在握手中**還要驗證 client 送來的整條憑證鏈**：逐張驗簽、建路徑、（可能）查撤銷。**這份成本發生在「你還不知道對方是誰、還沒授權」之前**——也就是 **pre-auth**。這點很關鍵：**mTLS 不會保護握手不被 DoS，反而讓每次握手更貴。**

記住這張對照表，下面每種攻擊都對應其中一格：

| 機制 | 廉價的一方（攻擊者） | 昂貴的一方（你的 server） |
|---|---|---|
| full handshake | 發起連線 | 私鑰非對稱運算（RSA 解密 / ECDHE 簽章） |
| renegotiation | 送一個 renegotiate 請求 | 在**同一條連線**上重跑整個握手 |
| 握手洪水 | 開大量連線各握手一次 | 每條都做一次私鑰運算 |
| mTLS 憑證鏈 | 送一條（長）憑證鏈 | 逐張驗簽 + 建路徑 + 查撤銷（pre-auth） |

---

## 二、重協商 DoS（renegotiation）：經典 THC-SSL-DOS

**攻擊流程（一句話）：** 在**一條已建立的連線**上，client 反覆要求**重新協商（renegotiation）**，強迫 server 一次又一次重跑昂貴的握手金鑰運算——一台普通機器就能壓垮一台大 server。這就是 2011 年的 **THC-SSL-DOS / CVE-2011-1473** 的思路。

**為什麼有效：** 重協商讓「一條連線」可以觸發「無限次握手」。攻擊者連頻寬都不用大，光靠運算不對稱就把 server CPU 吃乾。

三個層面的緩解，優先序由高到低：

**1. 用 TLS 1.3——從協定上根除。** TLS 1.3 **移除了 renegotiation** 這個機制（改用成本低廉的對稱式 `KeyUpdate` 與 post-handshake auth）。只要 `MinVersion` 設 TLS 1.3，重協商型 DoS **從設計上就不存在**。這是投報率最高的一招。

**2. Go server：天生免疫。** Go 的 `crypto/tls` **server 端根本不支援 renegotiation**——收到重協商就中斷連線。`tls.Config.Renegotiation` 這個欄位**只在 Go 當 client 時**才有意義。所以 Go 寫的 TLS server 對這類攻擊本來就免疫，你不用額外做事。

**3. Java / JSSE：預設可能允許，要顯式關掉。** 傳統 JSSE 若跑 TLS 1.2 且允許 client 發起重協商，就有風險。**最早期**（JVM 啟動階段）設定系統屬性關掉 client 發起的重協商：

```java
// 建議用 JVM 參數：-Djdk.tls.rejectClientInitiatedRenegotiation=true
// 或在程式最早期（TLS stack 初始化前）設定：
System.setProperty("jdk.tls.rejectClientInitiatedRenegotiation", "true");
```

> 提醒：`jdk.tls.rejectClientInitiatedRenegotiation` 這個屬性**必須在 JSSE 初始化之前**生效（用啟動參數最保險，程式內設定太晚會無效）。屬性語意與預設值隨 JDK 版本演進，請對照你實際使用的 JDK 版本文件確認。**真正一勞永逸的還是把 `MinVersion` / `protocols` 收斂到 TLS 1.3。**

---

## 三、握手洪水（handshake flood）與 resumption 的省力

就算你關了重協商、上了 TLS 1.3，攻擊者還有更笨但有效的招：**開大量新連線，每條都逼你走一次 full handshake**。每條連線一次私鑰運算，量夠大 CPU 一樣爆。

這裡沒有「一個開關關掉它」的解，要靠**組合拳**：

**1. 讓 resumption 真的生效，把 full handshake 的比例壓低。**

- full handshake 才有昂貴的非對稱運算；resumption 走對稱式，便宜非常多。
- 開啟 session ticket / session cache，讓**正常 client** 大多走 resumption，你的 CPU 預算就留給真正的新連線。
- **但 session ticket 有取捨（承 Day15 / Day19）**：ticket 加密金鑰若外洩，過去用它保護的 session 有被解密風險（傷及 forward secrecy）。所以 **ticket 金鑰要定期輪替**，別長年不換、更別把它寫死在 repo。

**2. 對「新連線建立速率」做限制——但要在對的層級。**

- 應用層限速（Day17）發生在**握手完成、請求進到 handler 之後**，對「還在握手就把你壓垮」的攻擊**來不及**。
- 握手洪水要擋在 **L4 / 前置反向代理 / 托管 LB** 這種便宜前層（承 Day72/73 的「便宜前層」哲學）：對**每 IP 的新連線 / 新握手速率**設限，把握手風暴擋在 origin 之前。TLS 卸載（TLS termination）交給有硬體加速的 LB / CDN，origin 只處理已卸載的明文或便宜的內網 mTLS。

**3. 給握手本身設 timeout。** 握手若能無限拖，就變成 Day72 Slowloris 的 TLS 版（慢速握手佔住連線）。務必替握手設上限（下面兩節 Go / Java 各給做法）。

---

## 四、mTLS 憑證鏈驗證放大：本篇 mTLS 主角

開了 mTLS（`RequireAndVerifyClientCert` / `certificateVerification=required`）之後，握手 DoS 的成本結構會**更糟**，因為 server 多了一份 **pre-auth 的憑證鏈驗證工作**：

**放大點一：長 / 深憑證鏈。** client 送來的憑證鏈越長，server 要做的**逐張驗簽**就越多。攻擊者送一條刻意加長、加深的鏈，逼你做一堆簽章驗證。**對策：限制驗證深度。**

**放大點二：pre-auth 就得驗。** 就算攻擊者根本沒有你信任的 CA 簽的憑證，**server 還是得先做完握手非對稱運算、再嘗試驗證那條（注定失敗的）鏈，才能拒絕它**。也就是說 **mTLS 把「拒絕未授權者」的成本，前移到了握手裡**——攻擊者送垃圾憑證，你照樣付出驗證成本才能說「不」。

**放大點三：同步查撤銷 = 每次握手一個對外呼叫。** 若你在握手路徑裡**同步**查 client 憑證的 OCSP / CRL，那每一次（惡意）握手都可能觸發一個**對外網路請求**：這不只慢，還把你的握手可用性綁在外部 OCSP responder 上，甚至開出一個 SSRF/可用性依賴的破口（交叉 Day10 SSRF / Day39 DNS rebinding 的「別在請求路徑同步打外部」精神）。

**mTLS DoS 的正確心態：**

- **mTLS 是「誰能連」的授權手段，不是「握手不被 DoS」的防護。** 別指望「我開了 mTLS 所以握手安全」——正好相反，你得為 mTLS 額外做成本控制。
- **把 mTLS 終結（termination）放到前面。** 讓有能力做連線速率限制的閘道 / service mesh sidecar 去扛憑證驗證與握手風暴，origin 信任內網通道（承 Day51 service mesh mTLS 的思路）。
- **限制鏈深度、避免握手路徑同步查撤銷。** 撤銷改用 **OCSP stapling**（由 server 主動附上自己憑證的 OCSP 回應，讓對端不必自己去查）或**短效憑證**取代同步 OCSP，把「每次握手一個對外呼叫」消掉。

---

## 五、Go 的握手成本控制（`tls.Config` + `http.Server` timeout）

Go 這邊的重點：**善用 TLS 1.3 免疫重協商、顯式設握手 timeout、mTLS 限鏈深、開 resumption 並輪替 ticket 金鑰。**

```go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/netutil"
)

func newTLSServer(h http.Handler, clientCAs *x509.CertPool) *http.Server {
	tlsCfg := &tls.Config{
		// TLS 1.3 從協定上移除 renegotiation → 重協商 DoS 免疫。
		MinVersion: tls.VersionTLS13,

		// mTLS：要求並驗證 client 憑證。
		// 注意：未通過驗證前，server 已為每條連線付出握手 + 憑證鏈驗證成本（pre-auth）。
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,

		// 額外把關：限制 client 送來的憑證鏈長度，壓低最壞情況的驗簽成本。
		VerifyPeerCertificate: limitChainLen(4),

		// resumption：預設會用 session ticket。金鑰要定期輪替（見下）。
		// SessionTicketsDisabled 預設 false（即啟用）；別為了省事關掉 resumption，
		// 否則每條連線都被逼走昂貴 full handshake。
	}
	// 定期輪替 session ticket 金鑰（示意；正式環境用排程 + 安全的金鑰來源，承 Day15）。
	tlsCfg.SetSessionTicketKeys(currentTicketKeys())

	srv := &http.Server{
		Addr:      ":8443",
		Handler:   h,
		TLSConfig: tlsCfg,

		// 關鍵：Go 的 http.Server 沒有獨立「握手 timeout」欄位，
		// 但它會用 ReadHeaderTimeout / ReadTimeout / WriteTimeout
		// 三者中「最小的正值」當作 TLS 握手的期限。
		// 所以承 Day72 把這些設好，順帶就替握手設了上限——
		// 別讓握手可以無限拖（那會變成 TLS 版的 Slowloris）。
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return srv
}

// limitChainLen 粗略限制 client 憑證鏈的張數。
// 注意：Go 在 RequireAndVerifyClientCert 下會「先」做完標準鏈驗證才呼叫這個 callback，
// 所以它是縱深防禦 / 政策把關，不是「在驗證前就省掉成本」的手段。
// 真正要在 pre-auth 擋住握手風暴，仍要靠前置層的連線速率限制。
func limitChainLen(max int) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) > max {
			return fmt.Errorf("client cert chain too long: %d > %d", len(rawCerts), max)
		}
		return nil
	}
}

// 用 netutil.LimitListener 限制「總連線數」→ 間接封頂「同時進行中的握手數」（承 Day72）。
// 注意：官方 x/net 這個只限總數，不分 IP；每 IP 限制要靠前置代理。
func listenLimited(addr string, maxConns int) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return netutil.LimitListener(ln, maxConns), nil
}
```

幾個 Go 專屬要點：

- **重協商**：Go server 天生免疫（見第二節），`tls.Config.Renegotiation` 只在 Go 當 client 時有效，不用管。
- **握手 timeout**：如上，靠 `ReadHeaderTimeout` / `ReadTimeout` / `WriteTimeout` 的最小正值間接設定。若你是**手動用 `tls.Conn`（不透過 `http.Server`）**，就在 `HandshakeContext` 前自己 `conn.SetDeadline(...)`，否則慢握手會一直佔著。
- **限鏈深度**：`VerifyPeerCertificate` 是縱深把關，要清楚它跑在標準驗證**之後**（如註解），別誤以為它能在驗證前省成本。
- **cipher / 曲線**：用 TLS 1.3 預設即可（它只保留高效且安全的組合）；不要為了相容硬塞昂貴或過時的參數。

> 版本提醒：`tls.Config` 欄位與 `x/net/netutil` API 隨版本演進，`SetSessionTicketKeys`、`VerifyPeerCertificate`、`GetConfigForClient` 等在不同 Go / `x/net` 版本行為可能微調。上線前以你實際使用的版本文件為準確認欄位存在與語意，別假設。

---

## 六、Java 的握手成本控制（JSSE 屬性 + Tomcat `SSLHostConfig`）

Java 這邊：**關掉 client 發起的重協商、收斂到 TLS 1.3、mTLS 限鏈深、握手交給連接器 timeout 管、resumption 靠 session cache。**

**JVM 層（最早期設定）：**

```text
# 關掉 client 發起的重協商（擋 THC-SSL-DOS 這類）
-Djdk.tls.rejectClientInitiatedRenegotiation=true
```

**Tomcat 連接器（`server.xml`）——mTLS + 握手成本控制：**

```xml
<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="200" maxConnections="10000" acceptCount="100"
           connectionTimeout="5000"
           SSLEnabled="true" scheme="https" secure="true">

    <SSLHostConfig
        protocols="TLSv1.3"
        certificateVerification="required"
        certificateVerificationDepth="4"
        sessionCacheSize="20480"
        sessionTimeout="300">

        <Certificate certificateKeystoreFile="conf/server.p12"
                     certificateKeystorePassword="${server.keystore.pass}"
                     type="RSA"/>
        <!-- client CA（信任錨），用來驗 client 憑證 -->
        <TrustStore truststoreFile="conf/client-ca.p12"
                    truststorePassword="${truststore.pass}"/>
    </SSLHostConfig>
</Connector>
```

幾個要點：

- **`protocols="TLSv1.3"`**：同樣從協定上根除 renegotiation。若因相容必須留 TLS 1.2，務必搭配上面的 `rejectClientInitiatedRenegotiation`。
- **`certificateVerification="required"`** 就是 mTLS。搭配 **`certificateVerificationDepth`**（預設 10）**把驗證深度壓低**（例如 4），封頂惡意長鏈的驗簽成本——這是本篇 mTLS 放大點一的直接對策。
- **`connectionTimeout="5000"`**：承 Day72，這個 timeout 也涵蓋**握手還沒完成**的階段——慢握手 / 卡在握手的連線會被踢掉，擋 TLS 版 Slowloris。**別為了容忍慢網路把它調很長**。
- **`maxConnections` ≫ `maxThreads`（NIO）**：承 Day72，讓少數 I/O 執行緒照顧大量連線，別讓握手風暴一次卡爆執行緒池。
- **`sessionCacheSize` / `sessionTimeout`**：讓正常 client 走 resumption，省掉 full handshake 的非對稱運算；別把 cache 設太小導致大家一直重走 full handshake。
- **撤銷檢查**：避免在握手路徑**同步** OCSP/CRL（每次握手一個對外呼叫）。優先 **OCSP stapling**（`jdk.tls.server.enableStatusRequestExtension` 家族屬性，實作依賴 OpenSSL/tc-native）或短效憑證。
- **Spring Boot**：HTTP/2 那套 `WebServerFactoryCustomizer` / `TomcatConnectorCustomizer` 一樣適用——`SSLHostConfig` 的這些屬性有時 `application.properties` 沒有對應 key，要用程式設定 connector 物件。
- **非 Tomcat（Netty 直用 `SSLEngine`）**：raw `SSLEngine` **沒有內建握手 timeout**，要自己在 pipeline 用 `SslHandler.setHandshakeTimeoutMillis(...)` 設，否則慢握手會一直掛著。

> 版本提醒：`SSLHostConfig` 屬性名稱、預設值與 OCSP stapling 的實作路徑**隨 Tomcat / JDK 版本演進**，`certificateVerificationDepth`、`rejectClientInitiatedRenegotiation` 的語意也可能微調。請對照你實際使用的版本官方文件確認。**最重要的單一動作仍是：把 JDK / Tomcat 升級到已修補相關 TLS CVE 的版本，並收斂到 TLS 1.3。**

---

## 七、後端工程師的實務決策：我到底該做什麼

握手 DoS 大多發生在 **TLS stack / 連接器 / 前置層**，不在你的業務程式碼裡，所以行動清單很集中：

1. **收斂到 TLS 1.3。** 一次解決重協商 DoS（協定移除），且握手更快。相容需求逼你留 TLS 1.2 時，務必關掉 client 發起的重協商。
2. **給握手設 timeout。** Go 靠 `ReadHeaderTimeout`/`ReadTimeout`/`WriteTimeout` 最小正值（承 Day72）；Tomcat 靠 `connectionTimeout`；Netty 靠 `SslHandler` 握手 timeout。別讓握手能無限拖。
3. **開啟並照顧 resumption。** 讓正常流量走便宜的 resumption，把昂貴的 full handshake 留給真正的新連線；**session ticket 金鑰記得輪替**（承 Day15）。
4. **mTLS 要額外做成本控制。** 限 `certificateVerificationDepth` / 鏈長；**別在握手路徑同步查撤銷**（改 stapling / 短效憑證）；把 mTLS 終結放到前置閘道 / mesh sidecar（承 Day51）。
5. **握手洪水擋在便宜前層。** 每 IP 新連線 / 新握手速率限制放 L4 / 反向代理 / 托管 LB；TLS 卸載給有硬體加速的 LB/CDN，origin 少扛非對稱運算。應用層限速（Day17）擋不到握手階段。
6. **監控看握手層指標（承 Day16）。** 握手 DoS 的特徵是「**新握手速率暴衝**」「**full handshake vs resumption 比例異常**」「**握手失敗率飆高**」「**TLS 花費的 CPU 佔比異常**」「**單 IP 連線/握手數暴衝**」「**（TLS 1.2 殘留下）renegotiation 嘗試 > 0**」——這些連線流量可能不大、一般 CPU 告警未必抓得到，要專門盯 TLS stack 匯出的握手指標。

---

## 八、後端 Code Review / 維運 checklist

```text
[ ] TLS 版本是否收斂到 TLS 1.3（MinVersion / protocols）？若留 TLS 1.2，是否關掉 client 發起的重協商？
    (Java: -Djdk.tls.rejectClientInitiatedRenegotiation=true；Go server 天生免疫)
[ ] 握手是否有 timeout？
    (Go: ReadHeaderTimeout/ReadTimeout/WriteTimeout 已設非 0，承 Day72；
     Tomcat: connectionTimeout 合理且不過長；Netty: SslHandler handshakeTimeout)
[ ] session resumption 是否啟用且 cache 夠大？full handshake 是否只發生在真正新連線？
[ ] session ticket 加密金鑰是否有輪替機制、非寫死在 repo（承 Day15）？
[ ] mTLS：certificateVerificationDepth / 鏈長是否有上限（Tomcat certificateVerificationDepth、Go VerifyPeerCertificate）？
[ ] mTLS：握手路徑是否避免「同步」OCSP/CRL 查詢？撤銷是否改用 OCSP stapling 或短效憑證？
[ ] 是否清楚 mTLS 驗證成本發生在 pre-auth（未授權者也會逼你付出）？握手風暴是否交前置層擋？
[ ] 每 IP 新連線 / 新握手速率限制是否放在 L4 / 反向代理 / 托管 LB（非應用層 Day17）？
[ ] TLS 卸載是否交給有硬體加速的 LB/CDN，讓 origin 少做非對稱運算？
[ ] 連線總數 / maxConnections 是否有上限（承 Day72，封頂同時進行中的握手數）？
[ ] 監控（承 Day16）：是否盯新握手速率、full vs resumption 比例、握手失敗率、TLS CPU 佔比、
    單 IP 連線/握手數、renegotiation 嘗試數？（而非只盯總流量/總 CPU）
[ ] JDK / Tomcat / TLS library 是否升級到已修補相關 TLS CVE 的版本？
```

測試建議：

- **重協商**：用 `testssl.sh` 檢查是否仍允許 client 發起的重協商、支援哪些 TLS 版本；用 `thc-ssl-dos` 對測試環境施壓，**斷言重協商被拒 / 連線被主動關閉**。
- **握手 timeout**：模擬「連上 TCP 但慢慢送 ClientHello / 卡在握手中途」，**斷言連線在 timeout 後被 server 主動關閉**（TLS 版 Slowloris 回歸測試）。
- **mTLS 鏈深**：送一條超過 `certificateVerificationDepth` / `VerifyPeerCertificate` 上限的長鏈，**斷言握手在達到深度上限即被拒**，而非默默把 CPU 吃爆。
- **resumption 生效**：連兩次，斷言第二次走 resumption（省掉 full handshake），確認 session cache / ticket 有效。
- **回歸**：把「升級 JDK/Tomcat/TLS library」納入 CI 依賴掃描（承 Day18），避免因 pin 舊版把 TLS 修補倒退。

---

## 九、一句話總結

> Day72/73 打的是「連線建好之後」的 HTTP 層；**本篇再降一層到 TLS 握手——它的「運算不對稱」（client 發起廉價、server 私鑰運算 + mTLS 憑證鏈驗證昂貴）本身就是 DoS 攻擊面**，和 Day73 Rapid Reset 的「處理成本不對稱」是表兄弟。三類攻擊：**重協商 DoS（THC-SSL-DOS/CVE-2011-1473）**——一條連線逼你無限重跑握手，**上 TLS 1.3 從協定根除**（Go server 天生免疫，Java 用 `rejectClientInitiatedRenegotiation`）；**握手洪水**——大量新連線各走一次 full handshake，靠**resumption 省非對稱運算 + 前置層每 IP 連線速率限制 + 握手 timeout**壓制；**mTLS 憑證鏈驗證放大**——長鏈驗簽 + pre-auth 成本 + 同步查撤銷，靠**限 `certificateVerificationDepth`/鏈長 + OCSP stapling/短效憑證取代同步撤銷查詢 + 把 mTLS 終結放前置閘道**收斂。記住：**mTLS 是授權手段，不是握手防 DoS 的護身符，反而讓每次握手更貴。** 監控要盯握手層指標（新握手速率、full vs resumption 比例、握手失敗率），因為這類攻擊流量/CPU 未必爆在你習慣的告警點（承 Day16）。

---

## 延伸閱讀

- Day19 TLS / Cryptographic Failures——本篇的入門前傳（TLS 是什麼、憑證怎麼驗、cipher 怎麼選）。
- Day72 Slowloris / 慢速 HTTP DoS——本篇「握手 timeout」的思路來源；慢握手就是 TLS 版 Slowloris。
- Day73 HTTP/2 協定層 DoS——Rapid Reset 的「處理成本不對稱」與本篇「運算成本不對稱」是表兄弟。
- Day51 gRPC / Protobuf Security——service mesh mTLS 與把 mTLS 終結放 sidecar 的落地。
- Day17 Rate Limiting——為何應用層限速擋不到握手階段，握手風暴要靠前置層/L4。
- Day15 Secrets Management——session ticket 金鑰、私鑰的保管與輪替。
- Day10 SSRF / Day39 DNS Rebinding——「別在請求（握手）路徑同步打外部」的精神，對應 mTLS 同步查撤銷的破口。
- Day16 Security Logging / Monitoring——握手 DoS 流量/CPU 不一定爆表，必須靠握手層指標告警。
- Day18 Supply Chain / Dependencies——升級 TLS library / JDK / Tomcat 拿 CVE 修補要靠依賴治理落地。

---

明天預告：**Day 75 — TLS 憑證驗證失誤與中間人攻擊（延伸篇，承 Day19 TLS × Day74 mTLS，聚焦「後端作為 TLS client」的驗證破口）**
（Day74 談的是 server 端的握手成本；Day75 換一個視角：當**你的後端主動對外發 TLS 請求**（呼叫其他服務、webhook、下游 API）時，把憑證驗證**關掉或做錯**會怎樣。經典災難是 Go 的 `InsecureSkipVerify=true`、Java 自訂 `X509TrustManager` 全部信任 / 停用 `HostnameVerifier`——「本機測得過」正好因為信任鏈被關掉，上線就是一條敞開的 MITM 通道。這是延伸篇，不重講 Day19 的 TLS 基礎，聚焦後端當 client 時**正確的 `RootCAs` / 信任鏈 / 主機名驗證**寫法、憑證釘選（pinning）的取捨，以及為何「為了跳過自簽憑證」而全域關驗證是最常見的高危反例——並交叉 Day10 SSRF：關掉憑證驗證會讓 SSRF 更好打。）
