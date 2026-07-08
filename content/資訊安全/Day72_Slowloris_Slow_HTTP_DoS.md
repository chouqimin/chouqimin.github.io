---
title: "Day 72：Slowloris 與慢速 HTTP DoS（新主題，承 Day71 的 DoS 家族）— 連線佔用型攻擊、thread-per-connection 為何脆弱、用 timeout 與連線上限守門"
date: 2026-07-09
tags: ["Slowloris", "DoS", "Timeout", "Go", "Tomcat"]
---

# Day 72：Slowloris 與慢速 HTTP DoS

接續 Day71 預告：昨天講的是「**放大型** DoS」——一個 `Range` 請求撐大回應，用少量請求換取大量伺服器工作。今天換到光譜的另一端：「**連線佔用型** DoS」。

Slowloris、Slow POST（R.U.D.Y.）、Slow Read 這一家，特色是**頻寬需求極低、封包極小、流量看起來完全正常**。它們不打你的 CPU、不放大回應，而是用**極慢的速度**送標頭、送 body、或讀回應，把伺服器有限的**連線槽 / 執行緒**一個一個佔住不放。當所有槽都被慢速連線卡死，合法使用者就連不進來——伺服器 CPU 可能還在 5%，但服務已經掛了。

> **這是一篇新主題。** 我們會談：
> 1. 三種慢速攻擊（慢送標頭 / 慢送 body / 慢讀回應）分別卡住連線生命週期的哪一段；
> 2. 為什麼 **thread-per-connection**（傳統 Tomcat BIO 思維）特別脆弱，而**非阻塞式**（Go `net/http`、Netty/Tomcat NIO）較耐打**但仍會被拖垮**；
> 3. 防禦主線：用 **timeout 把連線生命週期的每一段都設上限**，加上**連線數 / 每 IP 上限**；
> 4. Go（`ReadHeaderTimeout`、`ReadTimeout`、`WriteTimeout`、`IdleTimeout`、`http.TimeoutHandler`）與 Java（Tomcat `connectionTimeout`、`maxConnections`、`maxSwallowSize`、`keepAliveTimeout`）怎麼設；
> 5. 為什麼「應用層 timeout 不夠，前面還要一層反向代理」。

---

## 一、慢速攻擊卡住的是「連線」，不是「運算」

先把一個 HTTP 請求的生命週期拆開，你就能看出每種慢速攻擊各卡在哪：

```text
[建立 TCP/TLS]
  → [收 request line + 標頭]     ← Slowloris 卡這裡
    → [收 request body]           ← Slow POST / R.U.D.Y. 卡這裡
      → [server 處理]
        → [送 response body]      ← Slow Read 卡這裡
          → [keep-alive 等下個請求] ← 閒置連線也能被拿來佔槽
```

每一段只要伺服器「願意一直等」，攻擊者就能把連線凍在那一段。三種手法本質相同——**用慢換佔用**——只是卡的階段不同。

### 1-1 Slowloris：永遠送不完的標頭

Slowloris 開很多條連線，每條都送出請求行與部分標頭，然後**故意不送結束標頭區的空行**（`\r\n\r\n`），改成每隔幾十秒補送一個無關緊要的標頭，把連線「續命」：

```text
GET / HTTP/1.1\r\n
Host: victim.example\r\n
X-a: 1\r\n
（等 15 秒）
X-b: 2\r\n
（等 15 秒）
X-c: 3\r\n
...永遠不送最後的空行，標頭區永遠「還沒收完」
```

伺服器只要沒設「收完整個標頭區的時限」，就會為每條連線癡癡地等下去。幾百條這種連線就能吃光連線池。**關鍵字：讀標頭階段沒有超時。**

### 1-2 Slow POST（R.U.D.Y.）：宣告很大，body 一滴一滴送

攻擊者送一個合法的 `POST`，`Content-Length` 宣告一個很大的值（例如 `Content-Length: 10000000`），但 body **每隔幾秒才送 1 byte**：

```text
POST /login HTTP/1.1\r\n
Host: victim.example\r\n
Content-Length: 10000000\r\n
\r\n
a       （等 10 秒）
a       （等 10 秒）
a       ...要送 10MB，這樣可以拖幾小時
```

伺服器認為「client 還在傳 body」，就一直等。這招對**任何接受 POST body 的端點**都有效（登入、上傳、表單）。**關鍵字：讀 body 階段沒有超時、或沒有整體請求時限。**

### 1-3 Slow Read：慢慢讀回應，把 server 的送出緩衝塞住

反過來，攻擊者正常送完請求，但**把 TCP 接收視窗開得極小、極慢地讀回應**。伺服器有一大包回應要送（例如大檔），但對方一次只收幾 bytes，伺服器的 socket 送出緩衝被塞滿、寫入阻塞，連線與相關資源被卡住。**關鍵字：寫回應階段沒有超時。**

---

## 二、為什麼 thread-per-connection 特別脆弱

這是理解防禦的核心。差別在於**「一條被卡住的連線」會凍結多少伺服器資源**。

### 2-1 thread-per-connection（傳統阻塞式）

經典的 Tomcat BIO 模型（以及很多同步阻塞式伺服器）是**一條連線綁一個工作執行緒**，執行緒在 `read()` 上阻塞等資料。慢速攻擊下：

- 每條慢連線 = 佔用**一整個執行緒**，卡在 `read()` 動不了。
- 執行緒池大小有限（Tomcat 預設 `maxThreads=200`）。
- **只要幾百條 Slowloris 連線，就能把 200 條執行緒全部卡在讀標頭 / 讀 body**，池子耗盡，合法請求排不進來 → 服務癱瘓。

一條慢連線的成本是「一個執行緒」，而執行緒是稀缺又昂貴的資源，這就是脆弱的根源。

### 2-2 非阻塞式（Go net/http、Netty、Tomcat NIO）

現代預設多是**非阻塞 / event-loop**：少數 I/O 執行緒用 epoll/kqueue 同時照顧上萬條連線，連線在等資料時**不綁定執行緒**。

- Go 的 `net/http` 是**一條 goroutine 對一條連線**，但 goroutine 極輕量（初始 ~2KB stack），且阻塞的 goroutine 會被 runtime 調度器讓出，不佔 OS 執行緒。
- Netty / Tomcat NIO 用 event loop，慢連線只是 selector 上一個閒置的 channel。

所以非阻塞式**對「執行緒耗盡」這件事免疫得多**。但——

> **非阻塞式不是免疫，只是把瓶頸從「執行緒數」換成「連線數 / 記憶體 / fd」。**

慢連線再輕，也還是：

- 佔一個**檔案描述符（fd）**——`ulimit -n` 有上限。
- 佔一份**每連線的緩衝與 goroutine/channel 記憶體**——連線開到幾十萬條，記憶體一樣會炸。
- 若你在 handler 裡把 body 讀進來做事，慢 body 一樣拖住那個 goroutine 對應的下游資源（DB 連線、鎖）。

**結論：架構選型能提高門檻，但不能取代「設 timeout 與連線上限」。無論同步或非阻塞，都必須主動限制連線生命週期。**

---

## 三、防禦主線：給連線生命週期的每一段設上限

防禦哲學一句話：**永遠不要無限期等待一個 client。** 把第一節那張生命週期圖的每一段都配一個 timeout，再加上「連線總數 / 每 IP 上限」，慢速攻擊就無處落腳。

要設的上限有四類：

1. **讀標頭超時**：收完整個標頭區的時限（擋 Slowloris）。
2. **讀 body / 整體請求超時**：收完 body 或整個請求處理的時限（擋 Slow POST）。
3. **寫回應超時**：把回應送出去的時限（擋 Slow Read）。
4. **閒置（keep-alive）超時 + 連線數上限**：閒置連線多久回收、同時最多幾條、每 IP 幾條。

---

## 四、Go：用 `http.Server` 的 timeout 欄位守門

Go 標準庫把這些 timeout 直接做成 `http.Server` 的欄位。**預設值全部是 0（永不逾時）**——這是最危險的預設，等於對 Slowloris 門戶大開。你必須顯式設定：

```go
package main

import (
	"context"
	"net/http"
	"time"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,

		// 擋 Slowloris：收完「整個標頭區」的時限。
		// 這是最關鍵的一條，預設 0 = 永不逾時。
		ReadHeaderTimeout: 5 * time.Second,

		// 擋 Slow POST：收完「標頭 + 整個 body」的時限。
		// 注意這涵蓋 body，會限制慢速上傳的合法使用者，
		// 大檔上傳端點要另外用 http.TimeoutHandler 或串流處理，別把 ReadTimeout 設太短。
		ReadTimeout: 15 * time.Second,

		// 擋 Slow Read：從標頭讀完到寫完回應的時限。
		WriteTimeout: 15 * time.Second,

		// keep-alive 閒置連線多久回收，避免閒置連線長期佔 fd。
		IdleTimeout: 60 * time.Second,

		// 承 Day71：擋塞滿逗號的巨型標頭，同時限制標頭區大小。
		MaxHeaderBytes: 16 << 10, // 16KB
	}

	_ = srv.ListenAndServe()
	_ = context.Background()
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
```

幾個容易踩雷的細節：

**`ReadHeaderTimeout` 是擋 Slowloris 的主角。** 它單獨計「讀完整個標頭區」的時間，就算你為了支援大上傳把 `ReadTimeout` 放寬，`ReadHeaderTimeout` 也要維持很短（幾秒）。**只設 `ReadTimeout` 不設 `ReadHeaderTimeout` 是常見漏洞**——因為大上傳端點會把 `ReadTimeout` 調大甚至設 0，Slowloris 就從標頭階段鑽進來。

**`ReadTimeout` 涵蓋 body，會誤傷慢速的合法上傳。** 如果端點要接大檔或慢網路上傳，別用全域 `ReadTimeout` 壓死它。做法是全域 `ReadHeaderTimeout` 設短（擋 Slowloris），body 的時限改用 per-handler 控制：

```go
// per-handler 控制整體處理時限（擋 Slow POST / 慢 handler），
// 只掛在特定端點，不影響需要長時間串流的上傳端點。
slowHandler := http.TimeoutHandler(
	http.HandlerFunc(loginHandler),
	10*time.Second,
	"request timeout",
)
mux.Handle("/login", slowHandler)
```

**`http.TimeoutHandler` 管的是「handler 執行 + 寫回應」的時限，不管讀 body 的慢速。** 它包住 handler，逾時就回 `503` 並中止。它是「handler 跑太久」與「Slow Read（寫太久）」的防線，但**擋不住 Slow POST 在 handler 之前就慢慢送 body**——那要靠 `ReadTimeout`。兩者互補，別混淆。

**針對 body 的更精細控制：`http.MaxBytesReader` + 逐段讀。** 限制 body 大小本身（承 Day71 的「設上限」哲學），避免 `Content-Length` 宣告很大：

```go
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	// 限制實際讀取的 body 上限，超過就報錯（連 Content-Length 說謊也擋）。
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB
	// ... 讀取與處理
}
```

> Go 版重點：**四個 timeout 欄位預設全是 0（永不逾時），必須顯式設定。`ReadHeaderTimeout` 短、擋 Slowloris；`ReadTimeout`/`TimeoutHandler` 擋 Slow POST 與慢 handler；`WriteTimeout` 擋 Slow Read；`IdleTimeout` 回收閒置連線。**

至於「連線總數上限」，Go 標準庫沒有內建欄位，常見做法是用 `netutil.LimitListener` 包住 listener：

```go
import "golang.org/x/net/netutil"

ln, _ := net.Listen("tcp", ":8080")
ln = netutil.LimitListener(ln, 10000) // 同時最多 10000 條連線
srv.Serve(ln)
```

`golang.org/x/net/netutil.LimitListener` 是官方擴充套件，長期維護中，用 semaphore 限制同時 `Accept` 的連線數。但**它只限「總數」不分 IP**——每 IP 上限通常交給前面的反向代理或 firewall 做（見第六節）。

---

## 五、Java / Tomcat：連接器層的 timeout 與連線上限

Spring Boot 內嵌 Tomcat，這些防線設在**連接器（Connector）層**，不是 filter 層——因為慢速攻擊在請求「還沒被 Tomcat 交給你的 servlet」之前就發生了，filter 根本還沒被呼叫。所以要靠 Tomcat 連接器參數。

現代 Spring Boot 預設用 **NIO 連接器**（非阻塞），已經比古早的 BIO 耐打，但一樣要設上限：

```yaml
# application.yml
server:
  tomcat:
    # 擋 Slowloris / Slow POST：連線上一次讀取的最長等待（毫秒）。
    # 這是慢速攻擊最重要的一條——別讓連線無限期等資料。
    connection-timeout: 5s

    # keep-alive 閒置連線的存活時限；不設會沿用 connection-timeout。
    keep-alive-timeout: 15s
    # 一條 keep-alive 連線最多服務幾個請求，避免單連線長佔。
    max-keep-alive-requests: 100

    # 同時最大連線數（NIO 下可遠大於 maxThreads）。達到後新連線進 accept 佇列。
    max-connections: 10000
    # accept 佇列長度（OS backlog）；滿了就拒絕新連線。
    accept-count: 100

    threads:
      max: 200        # 工作執行緒上限（處理階段）
      min-spare: 10

    # 擋 Slow POST 的「棄置未讀 body」放大：當要中止請求時，
    # Tomcat 為了讓連線能重用會先「吞掉」剩餘 request body，
    # maxSwallowSize 限制最多吞多少 bytes，超過就直接關連線而非慢慢吞。
    # 設一個合理上限（例如 2MB），-1 表示無限吞（危險）。
    max-swallow-size: 2MB
```

對應的原生 Tomcat `server.xml`（若不是 Spring Boot）：

```xml
<Connector port="8080" protocol="org.apache.coyote.http11.Http11NioProtocol"
           connectionTimeout="5000"
           keepAliveTimeout="15000"
           maxKeepAliveRequests="100"
           maxConnections="10000"
           acceptCount="100"
           maxThreads="200"
           maxSwallowSize="2097152" />
```

幾個要點：

**`connectionTimeout` 是 Tomcat 版的主力防線。** 它限制「連線在讀取階段等待資料的時間」，直接掐住 Slowloris（慢送標頭）與 Slow POST（慢送 body）。Tomcat 對這個值的語意涵蓋標頭讀取等待，是擋慢速攻擊最關鍵的一條。

**`maxConnections` vs `maxThreads` 在 NIO 下是兩件事。** NIO 連接器下一條連線不綁一個執行緒，所以 `maxConnections`（可到上萬）通常遠大於 `maxThreads`（處理階段的執行緒，預設 200）。這正是 NIO 比 BIO 耐 Slowloris 的原因——慢連線只佔連線槽不佔執行緒。但 `maxConnections` 一樣是硬上限，攻擊者堆到這個數字，合法連線就進不來，所以**還是要靠 `connectionTimeout` 讓慢連線盡快被踢掉、把槽讓出來**。

**`maxSwallowSize` 擋的是中止請求時的「吞 body」成本。** 當伺服器決定要回錯誤並中止一個帶大 body 的請求時，為了讓 keep-alive 連線能重用，Tomcat 會嘗試讀完（吞掉）剩下的 request body。攻擊者可以宣告超大 body 讓這個「吞」的動作變成負擔——`maxSwallowSize` 限制吞的上限，超過就直接關連線，不陪玩。

**別把 `connectionTimeout` 設太長。** 常見錯誤是為了「容忍慢網路的手機使用者」把它設成 60 秒甚至更長——這等於把 Slowloris 的門開大。合理值是幾秒到十幾秒；真正需要長時間的（大上傳、long polling）用專屬端點與專屬連接器 / 非同步處理，別放寬全域值。

> Java 版重點：**慢速防線在連接器層（`connection-timeout`），不在 filter 層。NIO 連接器讓 `maxConnections ≫ maxThreads`、對 Slowloris 較耐打，但 `connectionTimeout` 仍是把慢連線踢出去的主力；`maxSwallowSize` 限制中止請求時吞 body 的成本。**

---

## 六、為什麼應用層 timeout 不夠：前面要一層反向代理

即使 Go / Tomcat 都設好 timeout，**單靠應用伺服器擋慢速攻擊仍不理想**，原因有三：

1. **應用伺服器的連線槽 / fd 仍會先被打滿。** timeout 能讓慢連線「幾秒後被踢掉」，但攻擊者可以持續補新連線維持飽和。你希望這場消耗戰發生在**便宜、專門、可水平擴充的前層**，而不是你昂貴的應用實例上。
2. **每 IP 連線數上限、連線速率限制**，這類防禦在反向代理 / WAF / LB 做遠比在應用碼做乾淨。
3. **buffering 反向代理天生免疫多數慢速攻擊。** Nginx 這類代理預設會**先把完整請求 buffer 起來**才轉給後端——它自己用非阻塞架構扛住慢速連線，等收完整個請求才用一條快速連線打你的 origin。Slowloris 打在 Nginx 上，打不到後面的 Tomcat。

實務上的縱深配置：

- **邊緣 / 反向代理層**：Nginx（`client_header_timeout`、`client_body_timeout`、`send_timeout`、`limit_conn` 每 IP 連線數）、Cloudflare / ALB 這類托管 LB 通常內建慢速攻擊防護與請求 buffering。
- **應用層（本篇重點）**：Go / Tomcat 的 timeout 與連線上限作為**第二道防線**——因為你不一定總是在代理後面（內部服務、直連場景），而且縱深防禦不該假設前層永遠在。
- **監控（承 Day16）**：對「連線數逼近上限」「大量請求因 `connectionTimeout` 被中止」「單一 IP 連線數異常」告警——慢速攻擊流量小、CPU 低，靠傳統「CPU / 流量爆表」的告警**抓不到**，要專門盯連線層指標。

---

## 七、後端 Code Review / 測試 checklist

```text
[ ] Go：http.Server 是否顯式設定 ReadHeaderTimeout（預設 0 = 永不逾時，擋 Slowloris 的主力）?
[ ] Go：是否設定 ReadTimeout / WriteTimeout / IdleTimeout（別留 0）?
[ ] Go：大上傳端點是否用 per-handler(http.TimeoutHandler / 串流)而非把全域 ReadTimeout 放大/設 0?
[ ] Go：body 是否用 http.MaxBytesReader 限制大小(擋 Content-Length 說謊)?
[ ] Go：是否用 netutil.LimitListener 限制同時連線總數?
[ ] Tomcat：connection-timeout 是否設合理短值(幾秒~十幾秒),沒被為了容忍慢網路調到很長?
[ ] Tomcat：keep-alive-timeout / max-keep-alive-requests 是否限制閒置與單連線請求數?
[ ] Tomcat：max-connections / accept-count 是否設上限?maxSwallowSize 是否設(非 -1)?
[ ] 是否理解 NIO 讓 maxConnections≫maxThreads 提高門檻,但仍需 connectionTimeout 踢慢連線?
[ ] 前面是否有 buffering 反向代理(Nginx client_*_timeout / limit_conn / 每 IP 上限)?
[ ] 監控(承 Day16)：是否盯「連線數逼近上限」「connectionTimeout 中止數」「單 IP 連線數」,
    而非只盯 CPU / 流量(慢速攻擊 CPU 低、流量小,傳統告警抓不到)?
[ ] 大檔下載端點(承 Day70/Day71)是否設 WriteTimeout,避免 Slow Read 塞住送出緩衝?
```

自動化 / 手動測試建議：

- 用 `slowhttptest`（經典工具）跑三種模式：`-c 500 -H`（Slowloris 慢標頭）、`-c 500 -B`（Slow POST）、`-c 500 -X`（Slow Read），觀察在你設好 timeout 前後「服務是否還能被合法請求存取」。
- 壓測時斷言：慢連線在 `ReadHeaderTimeout` / `connectionTimeout` 後**確實被伺服器主動關閉**（收到 `408 Request Timeout` 或連線 RST），而非無限期存活。
- 對大上傳端點單獨驗證：合法的慢速上傳（例如手機弱網）**不會**被過短的全域 timeout 誤殺，確認你走的是 per-endpoint 放寬而非全域放寬。
- 驗證 `MaxBytesReader` / `maxSwallowSize`：送 `Content-Length` 遠大於實際、或宣告超大 body，斷言被上限擋下而非慢慢吞。

---

## 八、一句話總結

> Day71 是「放大型」DoS（一個請求撐大回應）；Day72 是相反的「連線佔用型」DoS——**Slowloris 慢送標頭、Slow POST/R.U.D.Y. 慢送 body、Slow Read 慢讀回應，用極小流量與極慢速度把有限的連線槽 / 執行緒卡死**。**thread-per-connection（BIO）一條慢連線佔一個執行緒，最脆弱；非阻塞式（Go net/http、Tomcat NIO、Netty）把瓶頸從執行緒換成連線數 / fd / 記憶體，門檻高但不免疫。** 防禦主線是**給連線生命週期的每一段設 timeout**：Go 顯式設 `ReadHeaderTimeout`（擋 Slowloris，預設 0 最危險）/ `ReadTimeout` / `WriteTimeout` / `IdleTimeout` + `MaxBytesReader` + `LimitListener`；Tomcat 設 `connection-timeout`（主力）/ `keep-alive-timeout` / `max-connections` / `maxSwallowSize`。再加上**前面一層 buffering 反向代理（Nginx / 托管 LB）扛住慢速連線與每 IP 上限**，並用**連線層指標監控**（承 Day16）——因為慢速攻擊 CPU 低、流量小，傳統 CPU / 流量告警抓不到。記住：**永遠不要無限期等待一個 client。**

---

## 延伸閱讀

- Day71 HTTP Range 請求 DoS——本篇的姊妹篇，DoS 家族的「放大型」對照組（一個請求撐大回應 vs 一堆慢連線佔用資源）。
- Day17 Rate Limiting——限制「請求速率」，與本篇限制「連線生命週期 / 連線數」互補，一起構成資源濫用防線。
- Day51 gRPC / Protobuf Security——`MaxRecvMsgSize`、連線與訊息上限，同屬「設上限」防禦哲學。
- Day31 ReDoS——同為 DoS 但打的是 CPU（regex 回溯放大），與本篇「打連線」正好對照 DoS 的兩種資源目標。
- Day16 Security Logging / Monitoring——慢速攻擊流量小、CPU 低，必須靠連線層指標告警，不能只盯 CPU / 流量。
- Day70 Content-Disposition 下載端點進階防禦——大檔下載端點是 Slow Read 的天然目標，`WriteTimeout` 要設好。

---

明天預告：**Day 73 — HTTP/2 特有的 DoS（延伸篇，承 Day71/Day72 的 DoS 家族，聚焦協定層新攻擊面）**
（Day71/72 談的都是 HTTP/1.1 世界的 DoS。HTTP/2 的多工（multiplexing）、stream、HPACK 標頭壓縮與 flow control 帶來一批**協定層特有**的新攻擊面：2023 的 **HTTP/2 Rapid Reset（CVE-2023-44487）**——快速開 stream 又立刻送 `RST_STREAM` 取消，繞過「同時併發 stream 上限」把後端打爆；以及 HPACK bomb（壓縮炸彈放大解壓成本，呼應 Day60 zip bomb 思路）、`SETTINGS`/`PING` flood、CONTINUATION flood。這是延伸篇——不重講 DoS 基本觀念，聚焦 HTTP/2 協定機制怎麼被武器化，以及 Go（`http2.Server` 的 `MaxConcurrentStreams`、`MaxReadFrameSize`、Rapid Reset 的緩解）與 Java（Tomcat HTTP/2 連接器的 `maxConcurrentStreams`、`maxConcurrentStreamExecution`、`overheadCountFactor`）如何設限。）
