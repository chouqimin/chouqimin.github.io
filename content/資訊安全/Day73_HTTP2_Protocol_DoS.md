---
title: "Day 73：HTTP/2 協定層 DoS（延伸篇，承 Day71/72 DoS 家族）— Rapid Reset、HPACK bomb、SETTINGS/PING/CONTINUATION flood 與 Go / Tomcat 的設限"
date: 2026-07-10
tags: ["HTTP2", "DoS", "Rapid Reset", "Go", "Tomcat"]
---

# Day 73：HTTP/2 協定層 DoS

接續 Day72 預告：Day71（Range 放大型）與 Day72（Slowloris 連線佔用型）談的都是 **HTTP/1.1 世界**的 DoS。今天換到 HTTP/2。

> **這是一篇延伸篇。** 我**不會**重講「什麼是 DoS」「放大型 vs 連線佔用型」「為什麼要設 timeout / 連線上限」——那些請看 Day71 / Day72。這篇聚焦一個更窄的問題：**HTTP/2 的協定機制（多工 multiplexing、stream、HPACK 標頭壓縮、flow control）本身帶來哪些 HTTP/1.1 沒有的新攻擊面，以及後端框架怎麼設限。**

為什麼值得單獨寫一篇？因為 HTTP/2 的很多防禦直覺在 HTTP/1.1 是對的，到了 HTTP/2 卻**失效或不夠**：

- Day72 教你「限制**連線數**」。但 HTTP/2 一條 TCP 連線可以承載成百上千個並行 stream——**限連線數擋不住單連線內的 stream 濫用**。
- HTTP/1.1 你靠「限制**同時併發請求**」。HTTP/2 的 **Rapid Reset（CVE-2023-44487）**專門繞過這條：開了 stream 立刻取消，讓「同時存在的 stream 數」永遠不超標，但後端已經在幹活了。
- HTTP/1.1 的標頭是純文字，大小一眼可估。HTTP/2 用 **HPACK 壓縮**，一個幾 KB 的壓縮標頭可以解壓成幾十 MB（**HPACK bomb**，思路呼應 Day60 的 zip bomb）。

換句話說：**HTTP/2 把「請求」從「一條連線一個請求」變成「一條連線多路複用」，資源計量的單位全變了。** 舊的以「連線」為單位的防禦，必須補上以「stream / frame / 解壓後標頭大小」為單位的新防禦。

---

## 一、先建立心智模型：HTTP/2 在一條 TCP 連線裡發生什麼

只講跟 DoS 相關的三件事，其餘 HTTP/2 細節略。

**1. 多工（multiplexing）與 stream。** HTTP/1.1 一條 TCP 連線同時只能處理一個請求（或 pipeline 但實務不用）。HTTP/2 把一條連線切成很多 **stream**，每個 stream 是一次請求/回應，彼此交錯（interleave）傳輸。伺服器用 `SETTINGS_MAX_CONCURRENT_STREAMS` 告訴 client「你最多可以同時開幾個 stream」（常見預設 100）。

**2. 每個 stream 都是狀態機。** 開一個 stream（送 `HEADERS` frame）→ 伺服器**開始配置資源、路由、可能已經丟給 worker 執行**。client 可以隨時送 `RST_STREAM` 取消這個 stream。關鍵在於：**取消 stream 對 client 幾乎零成本（送一個小 frame），對伺服器卻可能已經付出了完整的請求處理成本。** 這個「取消成本不對稱」就是 Rapid Reset 的根。

**3. HPACK 標頭壓縮 + flow control。** 標頭用 HPACK 壓縮（含一張跨請求共用的動態表 dynamic table），還有連線層與 stream 層兩級 **flow control 視窗**控制資料流速。這兩個機制各自都能被武器化（HPACK bomb、視窗操縱）。

記住這張對照表，下面每種攻擊都對應到其中一格：

| 機制 | HTTP/1.1 對應 | HTTP/2 新攻擊面 |
|---|---|---|
| 多工 stream | 一連線一請求 | Rapid Reset、stream 建立 flood |
| stream 取消 | 關 TCP 連線（貴） | `RST_STREAM`（極廉價、不對稱） |
| HPACK 壓縮 | 純文字標頭 | HPACK bomb（解壓放大） |
| 控制 frame | 無對應 | `SETTINGS` / `PING` / `WINDOW_UPDATE` flood |
| 標頭分片 | 一次送完 | `CONTINUATION` flood |

---

## 二、Rapid Reset（CVE-2023-44487）：本篇主角

2023 年 8 月被大規模利用、10 月公開的 **HTTP/2 Rapid Reset**，是近年打破多個「史上最大 DDoS」紀錄的手法。它不需要巨大頻寬，一台普通機器就能打爆設計不良的 HTTP/2 伺服器。

**攻擊流程（一句話）：** 在一條連線上，**開一個 stream（`HEADERS`）→ 立刻送 `RST_STREAM` 取消 → 再開一個 → 再取消**，如此高速循環。

**為什麼有效——繞過「併發 stream 上限」這條防線：**

- 傳統想法：「我設了 `MAX_CONCURRENT_STREAMS=100`，同一時間最多 100 個 stream 在跑，資源可控。」
- Rapid Reset 的詭計：被取消（reset）的 stream **不計入「當前併發數」**。所以攻擊者可以「開了就砍、開了就砍」，讓「當前併發 stream」永遠停在很低的數字，卻在**單位時間內讓伺服器路由/開始處理了成千上萬個請求**。
- 更糟的是，很多伺服器實作**收到 `HEADERS` 就已經把請求 dispatch 給後端 worker / handler goroutine 開始執行**，`RST_STREAM` 到達時工作可能已經在跑或排進佇列。取消的是「回應要不要送回去」，**不是「工作要不要做」**。攻擊者付出「一開一砍」兩個小 frame，伺服器付出「完整請求處理」。這就是**成本不對稱放大**。

**它和 Slowloris（Day72）恰好相反：** Slowloris 是「**慢**」——連線開著不放、拖住資源；Rapid Reset 是「**快**」——瘋狂開了又砍。但兩者的目標一致：用極小的攻擊端成本，耗盡伺服器有限的處理資源。

### Go 的緩解（對應 Go 專屬 CVE-2023-39325）

Go 的 `net/http` / `golang.org/x/net/http2` 在 Go 1.21.3 / 1.20.10 修補了 Rapid Reset（Go 的 CVE 編號是 **CVE-2023-39325**，同一個攻擊）。**升級 runtime 是第一優先**——這類協定層防禦大多內建在 HTTP/2 stack 裡，你自己在 handler 寫再多防禦也擋不住「請求根本還沒進到 handler」的攻擊。

修補後的核心緩解是：**限制「同時處理中（正在執行 handler）的 stream 數量」**，而不只是限制「協定層當前併發 stream」。當已經 reset 但 handler 仍在跑的數量過多時，伺服器會拒絕新工作或直接關閉這條連線。

你能主動調的旋鈕（透過 `http2.Server`）：

```go
import (
    "net/http"
    "time"

    "golang.org/x/net/http2"
)

func newServer(h http.Handler) *http.Server {
    srv := &http.Server{
        Addr:    ":8443",
        Handler: h,

        // 承 Day72：連線生命週期 timeout 一樣要設，HTTP/2 不例外。
        ReadHeaderTimeout: 5 * time.Second,
        ReadTimeout:       30 * time.Second,
        WriteTimeout:      30 * time.Second,
        IdleTimeout:       60 * time.Second,
    }

    // 顯式設定 HTTP/2 參數，別只吃預設。
    _ = http2.ConfigureServer(srv, &http2.Server{
        // 單連線同時併發 stream 上限：不是設越大越好。
        // 越大 = 攻擊者單連線能同時壓越多工作。多數 API 100~250 已足夠。
        MaxConcurrentStreams: 100,

        // 單一 frame 最大讀取尺寸，壓低巨型 frame 的記憶體壓力。
        MaxReadFrameSize: 1 << 20, // 1 MiB

        // 閒置連線回收（呼應 Day72 IdleTimeout 思維）。
        IdleTimeout: 60 * time.Second,

        // 連線層 / stream 層 flow control 視窗上限，
        // 壓低單連線可佔用的緩衝記憶體。
        MaxUploadBufferPerConnection: 1 << 20,
        MaxUploadBufferPerStream:     1 << 18,
    })
    return srv
}
```

> 注意：`http2.Server` 各欄位在不同 `x/net` 版本會增修，且 Go 1.24 起 `http.Server` 也逐步收斂 HTTP/2 設定（`Protocols` / 內建 http2）。**上線前請以你實際使用的 Go 與 `x/net` 版本文件為準確認欄位存在與語意**——不要假設某個欄位一定在。Rapid Reset 的主力緩解來自升級後的 stack 內建邏輯，這些欄位是把攻擊面進一步收窄的輔助。

### Tomcat / Java 的緩解:overhead 保護

Tomcat 的 HTTP/2 連接器（`Http2Protocol` upgrade）用一套 **overhead 記帳**來抓 Rapid Reset 這類「低價值 frame 洪水」。核心是 `overheadCountFactor`:

- 每個連線維護一個 **overhead count**。
- 收到「浪費型」frame（例如很快被 reset 的 stream、過小的 `DATA` frame、過多的 `WINDOW_UPDATE`）會**增加** overhead count(乘上對應 threshold factor)。
- 收到「有進展」的 frame(正常送完的 stream / 正常大小的 `DATA`)會**降低** overhead count。
- 當 overhead count 超過門檻，Tomcat 判定這條連線在「用大量無用 frame 消耗你」，**直接關閉連線**。

Rapid Reset 的「開了又砍」正好是典型的高 overhead 行為,會被這套機制快速累積到門檻而斷線。

```xml
<!-- server.xml：HTTP/2 UpgradeProtocol 掛在既有 Connector 上 -->
<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
           SSLEnabled="true" maxThreads="200">
    <UpgradeProtocol className="org.apache.coyote.http2.Http2Protocol"
        maxConcurrentStreams="100"
        maxConcurrentStreamExecution="100"
        overheadCountFactor="10"
        overheadContinuationThreshold="1024"
        overheadDataThreshold="1024"
        overheadWindowUpdateThreshold="1024"
        readTimeout="5000"
        writeTimeout="5000"
        keepAliveTimeout="15000"
        maxHeaderCount="100"
        maxHeaderSize="8192" />
</Connector>
```

幾個要點:

- `maxConcurrentStreams`(協定廣播給 client 的上限,預設 100)與 `maxConcurrentStreamExecution`(**真正同時丟給執行緒池跑的 stream 數**)是兩件事。後者才是限制「同時吃 worker」的關鍵——把它壓在合理值,避免單連線的一堆 stream 一次佔滿 `maxThreads`(承 Day72 執行緒池耗盡)。
- `overheadCountFactor` **不要關掉**(設 0 等於放棄這道防線)。預設值就是為了擋 Rapid Reset 這類攻擊而存在的。
- Spring Boot 使用者:HTTP/2 開關是 `server.http2.enabled=true`,而上面這些 Tomcat 專屬屬性要透過 `WebServerFactoryCustomizer` / `TomcatConnectorCustomizer` 以程式設定 `Http2Protocol` 物件,`application.properties` 不一定每個都有對應 key。

> 同樣提醒:上述屬性名稱與預設值**隨 Tomcat 版本演進**(overhead 家族屬性是 9.0.x 之後陸續加入/調整的),請對照你實際使用的 Tomcat 版本官方文件確認。**最重要的單一動作仍是:把 Tomcat / JDK 升級到已修補 CVE-2023-44487 的版本。**

---

## 三、HPACK bomb:壓縮放大的標頭炸彈

呼應 Day60 的 zip bomb、Day13 的 Billion Laughs——**只要有「解壓/展開」步驟,就有放大攻擊面。** HTTP/2 的標頭用 HPACK 壓縮,自然也不例外。

**機制:** HPACK 有一張**動態表(dynamic table)**,client 可以先塞一個很長的標頭值進表裡(佔一個索引),之後用**極短的參照**重複引用它成百上千次。壓縮後在線上只有幾 KB,伺服器解壓後卻要在記憶體裡展開成幾十 MB 的標頭集合。若伺服器**先完整解壓才檢查大小**,記憶體就爆了。

**防禦(通常框架已內建,你要做的是別把上限調掉):**

- **限制 HPACK 動態表大小**:透過 `SETTINGS_HEADER_TABLE_SIZE` 告訴對端你的解碼表上限(Go `http2.Server.MaxDecoderHeaderTableSize`)。
- **限制解壓後標頭總大小 / 數量**:Go 有 `http2.Server.MaxHeaderListSize`(對應 `SETTINGS_MAX_HEADER_LIST_SIZE`);Tomcat 有 `maxHeaderSize` / `maxHeaderCount`。這是**在解壓過程中就累計、超標即中止**,而不是解壓完再算。
- 這條和 Day71 的 `MaxHeaderBytes`(HTTP/1.1 巨型標頭)是**同一種防禦哲學在不同協定的化身**:標頭大小一定要有硬上限,差別只在 HTTP/2 要管的是「**解壓後**」的大小。

```go
_ = http2.ConfigureServer(srv, &http2.Server{
    MaxConcurrentStreams:      100,
    MaxDecoderHeaderTableSize: 4096,   // HPACK 解碼動態表上限
    MaxHeaderListSize:         1 << 20, // 解壓後標頭總大小上限 1 MiB
})
```

---

## 四、控制 frame flood:SETTINGS / PING / WINDOW_UPDATE / CONTINUATION

HTTP/2 有一批「控制用」frame,正常情況下量很少。攻擊者可以**狂送這些 frame**,強迫伺服器不斷處理/回應,消耗 CPU 與頻寬——這類統稱 control-frame flood。

- **SETTINGS flood**:每個 `SETTINGS` frame 伺服器都要處理並回 `SETTINGS ACK`。狂送 = 逼你不斷做無用功。
- **PING flood**:每個 `PING` 伺服器要回 `PING ACK`。同理。
- **WINDOW_UPDATE flood / 空 frame flood**:大量 flow-control 更新或零長度 `DATA`/`HEADERS`,每個都要進狀態機處理,累積起來就是 CPU 消耗。
- **CONTINUATION flood(2024 揭露)**:HTTP/2 標頭若太大會拆成 `HEADERS` + 多個 `CONTINUATION` frame。某些實作**在標頭組裝完成前不強制上限**,攻擊者送一長串永不結束的 `CONTINUATION`,伺服器持續配置記憶體累積標頭——是 HPACK bomb 的近親變體。

**防禦要點(絕大多數落在 HTTP/2 stack / 連接器層,不是你的 handler):**

1. **升級 runtime / 伺服器**。CONTINUATION flood、Rapid Reset 這類都是靠**升級到已修補版本**拿到內建緩解——這點怎麼強調都不過分。
2. Tomcat 的 **overhead 記帳**(上一節)同時涵蓋這些 flood:過量的 `WINDOW_UPDATE`、過小的 `DATA`、失控的 stream 都會拉高 overhead count 而觸發斷線;`overheadContinuationThreshold` / `overheadWindowUpdateThreshold` / `overheadDataThreshold` 就是分別為這幾類設的。Go 修補版也對這幾類 frame 設了速率/數量上限。
3. **前面擺一層有 HTTP/2 感知的反向代理 / 托管 LB**(承 Day72 的「便宜前層」哲學):Nginx、Cloudflare、ALB 這類多半已內建對 Rapid Reset 與 control-frame flood 的緩解,把這場消耗戰擋在 origin 之前。

---

## 五、後端工程師的實務決策:我到底該做什麼

這篇的攻擊大多發生在**協定 stack 層**,不在你的業務程式碼裡。所以你的行動清單其實很集中:

1. **升級,升級,升級。** Go runtime、JDK/Tomcat、任何 HTTP/2 代理(Nginx/Envoy)——Rapid Reset(CVE-2023-44487 / Go CVE-2023-39325)與 CONTINUATION flood 的主力緩解全靠這個。這是投報率最高的一件事。
2. **顯式設定 HTTP/2 上限,別吃預設或設無限大。** `MaxConcurrentStreams` / `maxConcurrentStreamExecution`、標頭大小上限、flow-control 視窗上限、Tomcat overhead 家族**不要關掉**。
3. **HTTP/1.1 的 timeout / 連線上限一樣要設(承 Day72)。** HTTP/2 不是取代,是疊加——連線層 timeout、`MaxHeaderBytes`/`maxHeaderSize`、每 IP 連線數在 HTTP/2 世界依然需要。
4. **前面擺一層有 HTTP/2 感知的 buffering 代理 / 托管 LB。**
5. **監控看的指標和 Day72 不同。** Rapid Reset 的特徵是「**RST_STREAM 速率異常高**」「**單連線 stream 建立/取消次數暴衝**」「**已 reset 但 handler 仍在跑的數量**」——這些連線 CPU 可能不高、頻寬不大,傳統 CPU/流量告警(承 Day16)一樣抓不到,要專門盯 HTTP/2 stack 匯出的 stream 層指標。

---

## 六、後端 Code Review / 維運 checklist

```text
[ ] Runtime/伺服器是否已升級到修補 CVE-2023-44487 / Go CVE-2023-39325 的版本?
    (Go ≥ 1.21.3 或 1.20.10;Tomcat/JDK 對應修補版;Nginx/Envoy 修補版)
[ ] 是否確認過 CONTINUATION flood(2024)相關修補也在?
[ ] Go:是否透過 http2.ConfigureServer 顯式設定 MaxConcurrentStreams(非無限)?
[ ] Go:是否設 MaxReadFrameSize / MaxHeaderListSize / MaxDecoderHeaderTableSize(擋 HPACK bomb)?
[ ] Go:是否設 MaxUploadBufferPerConnection / PerStream 壓低單連線緩衝記憶體?
[ ] Go:HTTP/1.1 的 ReadHeaderTimeout/ReadTimeout/WriteTimeout/IdleTimeout 是否仍有設(承 Day72)?
[ ] Tomcat:maxConcurrentStreams 與 maxConcurrentStreamExecution 是否都設合理值(後者限同時吃 worker)?
[ ] Tomcat:overheadCountFactor 是否維持啟用(非 0)?overhead*Threshold 是否為預設或更嚴?
[ ] Tomcat:maxHeaderSize / maxHeaderCount 是否設上限(擋 HPACK bomb / CONTINUATION flood)?
[ ] Spring Boot:HTTP/2 屬性是否確實透過 TomcatConnectorCustomizer 生效(不是誤以為 properties 有 key)?
[ ] 前面是否有 HTTP/2 感知的反向代理 / 托管 LB 內建 Rapid Reset / flood 緩解?
[ ] 監控(承 Day16):是否盯 RST_STREAM 速率、單連線 stream 建立/取消次數、
    「已 reset 但仍在執行的 stream 數」?(而非只盯 CPU/流量——這類攻擊 CPU 可能不高)
[ ] 是否確認過 handler 的成本:一個「開了立刻被砍」的請求,你的路由/DB/下游呼叫
    會不會在 RST 到達前就已經開跑?(成本不對稱越大,Rapid Reset 越痛)
```

測試建議:

- 用 `h2load`(nghttp2 附帶)或 `h2spec` 對測試環境施壓,模擬高速開 stream + `RST_STREAM`,斷言**連線在 overhead 門檻後被伺服器主動關閉**、`maxConcurrentStreamExecution` 確實限制了同時執行數。
- 對標頭端點送逼近 `MaxHeaderListSize` / `maxHeaderSize` 的壓縮標頭,斷言**在解壓過程即被拒**(回 `RST_STREAM` / 431 / 連線關閉),而非把記憶體吃爆。
- **回歸測試**:把「升級 runtime」納入 CI 依賴掃描(承 Day18),確保不會因為 pin 舊版而把 Rapid Reset 修補倒退。

---

## 七、一句話總結

> Day72 的 Slowloris 是 HTTP/1.1「一連線一請求」世界的慢速佔用;**HTTP/2 把資源計量單位從「連線」換成「stream / frame / 解壓後標頭」,舊防禦全要補新的一層。** 本篇三類新攻擊面:**Rapid Reset(CVE-2023-44487)**——開 stream 立刻 `RST_STREAM` 取消,繞過「併發 stream 上限」用成本不對稱把後端打爆;**HPACK bomb**——壓縮標頭解壓放大(呼應 Day60 zip bomb);**control-frame flood(SETTINGS/PING/WINDOW_UPDATE/CONTINUATION)**——狂送控制 frame 逼伺服器做無用功。防禦主線很集中:**升級到已修補版本(投報率最高)**、**顯式設 HTTP/2 上限別吃預設**(Go `MaxConcurrentStreams`/`MaxHeaderListSize`;Tomcat `maxConcurrentStreamExecution`/`overheadCountFactor` 別關)、**HTTP/1.1 的 timeout/連線上限照舊要設(承 Day72)**、**前面擺 HTTP/2 感知的代理**,並用**stream 層指標監控**(RST_STREAM 速率、已 reset 仍執行的 stream 數)——因為這類攻擊 CPU 可能不高,傳統告警抓不到(承 Day16)。

---

## 延伸閱讀

- Day72 Slowloris / 慢速 HTTP DoS——本篇的 HTTP/1.1 對照組(慢速佔用 vs 高速開砍)。
- Day71 HTTP Range 請求 DoS——DoS 家族「放大型」,與本篇 HPACK bomb 同屬「解壓/展開放大」思路。
- Day60 XLSX 匯入解析硬化 / Day13 XXE Billion Laughs——同為「解壓/展開放大」家族,HPACK bomb 的近親。
- Day23 HTTP Request Smuggling——同樣涉及 HTTP/2 與 HTTP/1.1 邊界差異(H2 downgrade),協定層攻擊面的另一面。
- Day16 Security Logging / Monitoring——Rapid Reset CPU/流量不一定爆表,必須靠 stream 層指標告警。
- Day18 Supply Chain / Dependencies——本篇最重要的防禦「升級 runtime」要靠依賴掃描與版本治理落地。

---

明天預告:**Day 74 — mTLS / TLS handshake DoS(延伸篇,承 Day19 TLS × Day72/73 DoS 家族,聚焦連線建立階段的運算不對稱)**
(Day72/73 打的是「連線建好之後」的 HTTP 層。往下一層看:**TLS handshake 本身**就是攻擊面——伺服器在握手階段要做非對稱金鑰運算(RSA 解密 / ECDHE),成本遠高於 client。攻擊者可以發起大量握手、或在 **client 憑證驗證(mTLS)** 階段送畸形/超大憑證鏈逼伺服器做昂貴驗證,把 CPU 打爆——這是「運算不對稱」型 DoS,和本篇 Rapid Reset 的「處理成本不對稱」是表兄弟。這是延伸篇,不重講 Day19 的 TLS 基礎,聚焦握手階段的 DoS 攻擊面與 Java(`SSLEngine`/連接器 SSL 參數、session resumption、OCSP stapling)與 Go(`tls.Config` 的 `ClientAuth`、憑證鏈長度/大小限制、握手 timeout)如何限制握手成本。)
