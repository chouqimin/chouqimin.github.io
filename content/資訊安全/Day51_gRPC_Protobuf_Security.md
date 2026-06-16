---
title: "Day 51：gRPC 與 Protobuf 安全 — 反序列化、訊息大小限制與 TLS/mTLS"
date: 2026-06-16
tags: ["gRPC", "Protobuf", "mTLS", "DoS"]
---

# Day 51：gRPC 與 Protobuf 安全 — 反序列化、訊息大小限制與 TLS/mTLS

> 「gRPC 是內部服務在用的，跑在內網，不用太擔心安全吧？」
> —— 「內網 = 安全」是最危險的假設之一。內部服務一旦被攻進來（透過某個對外的 API），gRPC 就是橫向移動的高速公路。

（接續 Day50 預告：講完 HTTP 系的 REST 與 GraphQL，今天轉向內部服務常用的 gRPC。重點放三個面向——protobuf 反序列化的資源耗盡風險、`MaxRecvMsgSize` 訊息大小上限、以及 service-to-service 一定要做的 mTLS。會用 Java（grpc-java）與 Go（grpc-go）示範 server 端的安全預設值，並串回 Day48 HMAC 簽章與 Day49 微服務間授權。）

---

## 一、gRPC 的攻擊面跟 REST / GraphQL 有什麼不同？

gRPC 跑在 HTTP/2 上、用 Protobuf 做二進位序列化、通常是 service-to-service 的內部通訊。它和前幾天講的 HTTP API 有幾個關鍵差異：

1. **二進位協定，不是純文字**：你沒辦法用 WAF 規則去掃 `' OR 1=1`，因為 payload 是壓縮過的二進位。傳統字串型的防禦在這裡幾乎失效，安全要靠**結構性限制**（大小、深度、型別）。
2. **常被當成「內網就安全」**：很多團隊 REST 端做足了驗證授權，gRPC 卻是裸奔的 plaintext，沒有 TLS、沒有身份驗證——因為「反正在內網」。這正是 Day49 講的微服務間授權盲點。
3. **streaming 是一等公民**：gRPC 支援 client streaming / server streaming / bidirectional streaming，一條連線可以持續灌資料，DoS 的形態跟「一次性請求」不同。

下面我們聚焦三個最該先做的防禦。

---

## 二、Protobuf 反序列化：小 payload、大代價

Protobuf 解析本身比 JSON 安全（沒有 JSON 那種任意型別、原型污染問題），但它**不是免疫 DoS**。攻擊者可以送出「壓縮後很小、解開後很大」的訊息，本質和 Day31 ReDoS、Day50 的深度查詢一樣——**輸入小、運算 / 記憶體代價大**。

常見手法：

- **超大欄位 / 超長 repeated**：一個 `repeated` 欄位塞進數百萬個元素，server 在反序列化時就把記憶體吃光。
- **深層巢狀 message**：message 互相巢狀很多層，遞迴解析爆 stack 或 CPU。
- **解壓縮放大（decompression bomb）**：gRPC 支援 gzip 壓縮。一個幾 KB 的壓縮 payload 解開後可能是幾百 MB。

防禦的核心是**在解析之前就設上限**，不要等資料都讀進記憶體才檢查。

---

## 三、訊息大小限制：`MaxRecvMsgSize`（最該先設的一個）

gRPC 預設的接收訊息上限是 **4 MB**（`grpc-java` 與 `grpc-go` 都是這個預設值）。很多人為了「方便傳大檔」直接把它調超大甚至設成 `MaxInt`——這等於把反序列化 DoS 的大門打開。

原則：**訊息大小上限要設成「業務真正需要的最小值」**，大檔案改用 streaming 分塊傳，而不是放寬單一訊息上限。

### ✅ Java：grpc-java 設定接收訊息上限

`grpc-java` 在 server 建立時用 `maxInboundMessageSize` 設定：

```java
import io.grpc.Server;
import io.grpc.ServerBuilder;

Server server = ServerBuilder.forPort(9090)
        // 接收訊息上限設為 1 MB（依業務調整，不要無上限）
        .maxInboundMessageSize(1 * 1024 * 1024)
        // 單一 metadata（header）大小上限，預設 8 KB，避免 header 灌爆
        .maxInboundMetadataSize(8 * 1024)
        .addService(new MyServiceImpl())
        .build()
        .start();
```

> `maxInboundMessageSize(int)` 是 `io.grpc.ServerBuilder` 長期提供的官方方法；client 端對應的是 `ManagedChannelBuilder.maxInboundMessageSize(int)`。若超過上限，gRPC 會直接以 `RESOURCE_EXHAUSTED` 狀態拒絕，不會把整包讀進來。

### ✅ Go：grpc-go 設定接收訊息上限

`grpc-go` 用 server option 設定：

```go
import (
    "google.golang.org/grpc"
    "google.golang.org/grpc/keepalive"
    "time"
)

server := grpc.NewServer(
    // 接收訊息上限 1 MB（預設 4 MB，視業務調小）
    grpc.MaxRecvMsgSize(1*1024*1024),
    // 同時限制並發 stream 數，避免單一連線開太多 stream 耗資源
    grpc.MaxConcurrentStreams(100),
    // header 大小上限
    grpc.MaxHeaderListSize(8*1024),
)
```

> `grpc.MaxRecvMsgSize` 與 `grpc.MaxConcurrentStreams` 都是 `google.golang.org/grpc` 提供的標準 `ServerOption`。超過上限同樣回 `codes.ResourceExhausted`。

### 別忘了 streaming 的累積量

訊息大小上限是「每一則訊息」的上限。對於 client streaming，攻擊者可以送出**無限多則合法大小的訊息**來累積資源消耗。所以還要：

- 設定**連線 / stream 的 keepalive 與 idle timeout**，閒置或異常連線及早關閉。
- 在 streaming handler 內**自行累計收到的訊息數 / 總 bytes**，超過業務上限就主動中止。
- 用 `MaxConcurrentStreams` 限制單連線並發 stream 數。

---

## 四、TLS 與 mTLS：service-to-service 的身份基礎

這是 gRPC 安全最常被忽略、卻最重要的一塊。預設情況下你很容易就建了一個 **plaintext（h2c）** 的 server——資料明文在內網跑，任何能進到網段的人都能竊聽或竄改。

兩個層次：

- **TLS**：加密傳輸 + 驗證 server 身份（client 確認「我連到的真的是對的服務」）。
- **mTLS（雙向 TLS）**：再加上 server 驗證 client 身份（每個呼叫方都要出示憑證）。微服務之間應該用 mTLS，讓「誰能呼叫我」有密碼學等級的保證——這正是 Day49 微服務間授權的傳輸層基礎，也和 Day48 用 HMAC 簽章驗證請求來源是同一個目標的不同手段。

### ✅ Java：grpc-java 啟用 mTLS

```java
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.ClientAuth;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContextBuilder;
import java.io.File;

SslContextBuilder sslBuilder = SslContextBuilder.forServer(
        new File("server.crt"), new File("server.key"))
        // 用我們信任的 CA 來驗證 client 憑證
        .trustManager(new File("ca.crt"))
        // REQUIRE = 強制 client 出示憑證（mTLS），不接受無憑證連線
        .clientAuth(ClientAuth.REQUIRE);

Server server = NettyServerBuilder.forPort(9090)
        .sslContext(GrpcSslContexts.configure(sslBuilder).build())
        .maxInboundMessageSize(1 * 1024 * 1024)
        .addService(new MyServiceImpl())
        .build()
        .start();
```

> `ClientAuth.REQUIRE` 是關鍵：它讓 server **強制**驗證 client 憑證。若設成 `OPTIONAL` 或不設，等於 mTLS 形同虛設。`GrpcSslContexts` 是 grpc-java 官方提供、針對 HTTP/2 ALPN 設定好的 SSL context 建構器。

### ✅ Go：grpc-go 啟用 mTLS

```go
import (
    "crypto/tls"
    "crypto/x509"
    "os"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

// 載入 server 憑證
cert, _ := tls.LoadX509KeyPair("server.crt", "server.key")

// 載入用來驗證 client 的 CA
caPem, _ := os.ReadFile("ca.crt")
caPool := x509.NewCertPool()
caPool.AppendCertsFromPEM(caPem)

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    ClientCAs:    caPool,
    // RequireAndVerifyClientCert = 強制驗證 client 憑證（mTLS）
    ClientAuth: tls.RequireAndVerifyClientCert,
    MinVersion: tls.VersionTLS13, // 至少 TLS 1.2，能用 1.3 更好
}

server := grpc.NewServer(
    grpc.Creds(credentials.NewTLS(tlsConfig)),
    grpc.MaxRecvMsgSize(1*1024*1024),
)
```

> `tls.RequireAndVerifyClientCert` 對應 Java 的 `ClientAuth.REQUIRE`——這一行決定了你是「真 mTLS」還是「只是加密但任何人都能連」。`credentials.NewTLS` 是 grpc-go 官方的 TLS 憑證封裝。

### 拿到 client 身份後做授權（串回 Day49）

mTLS 只解決「你是誰」（authentication），不解決「你能做什麼」（authorization）。在 interceptor 中從 client 憑證取出身份（如 CN / SAN），再對照白名單決定能不能呼叫某個 method——這就是 Day49「預設拒絕」在 gRPC 的落地：

```go
// 在 UnaryInterceptor 內從 peer 取出 client 憑證的 CN，
// 比對「哪個服務允許呼叫哪些 method」的白名單，不在白名單就回 codes.PermissionDenied
```

---

## 五、容易被忽略的細節

1. **預設 plaintext 太容易**：`grpc.NewServer()` 不帶 `Creds` 就是明文；`ServerBuilder.forPort()` 不設 sslContext 也是明文。一定要在 code review 與啟動檢查中強制要求 TLS。
2. **reflection 服務別在 production 開**：gRPC server reflection 會把所有 service / method 定義吐出來，等於 Day50 GraphQL introspection 的翻版——方便除錯，但也把 API 藍圖送給攻擊者。production 關閉。
3. **錯誤訊息洩漏**：別把內部 exception / stack trace 塞進 gRPC `Status` 的 message。包裝成通用錯誤（串回 Day25、Day50 的資訊洩漏）。
4. **逾時與 deadline**：server 端對每個呼叫設處理逾時，避免單一慢請求佔住資源；client 端設 deadline，避免雪崩式等待。
5. **壓縮放大**：若啟用 gzip，務必搭配訊息大小上限（解壓後仍受 `MaxRecvMsgSize` 限制），避免 decompression bomb。

---

## 六、後端工程師的 Checklist

- [ ] 設定 **`maxInboundMessageSize` / `MaxRecvMsgSize`** 為業務最小值，不要無上限（預設 4 MB，多數情況可調小）。
- [ ] 限制 **metadata / header 大小**、**並發 stream 數**、**streaming 累積 bytes**。
- [ ] **強制 TLS**，service-to-service 用 **mTLS**（Java `ClientAuth.REQUIRE`、Go `RequireAndVerifyClientCert`）。
- [ ] 從 client 憑證取身份後，在 interceptor 做**授權白名單**（Day49 預設拒絕）。
- [ ] production **關閉 server reflection**。
- [ ] 每個呼叫設 **deadline / timeout**，錯誤訊息包裝成通用錯誤。
- [ ] 啟用壓縮時，確認解壓後仍受訊息大小上限保護。

---

## 七、一句話總結

> **gRPC 的二進位協定擋不掉「結構性攻擊」——大小、深度、連線數要靠後端硬性設上限；而「內網就安全」是幻覺，service-to-service 一定要 mTLS。**
> 訊息大小控反序列化 DoS、mTLS 控身份、interceptor 控授權，三者一起做才算完整。

---

## 延伸閱讀

- gRPC Documentation — Security / Authentication（TLS、ALTS）
- grpc-java — `ServerBuilder.maxInboundMessageSize`、`GrpcSslContexts`
- grpc-go — `grpc.MaxRecvMsgSize`、`credentials.NewTLS`
- 前文：Day25 過度暴露、Day31 ReDoS、Day48 HMAC API 簽章、Day49 BFLA / 微服務授權、Day50 GraphQL 安全

---

明天預告：**Day 52 — 不安全的反序列化（Insecure Deserialization）：從 Java 原生序列化到 JSON/YAML 的 RCE**
（今天 gRPC 講的是「結構性」反序列化 DoS；明天升級到更危險的反序列化漏洞——攻擊者控制序列化資料直接觸發 RCE。會講 Java 原生 `ObjectInputStream` 的 gadget chain 風險、Jackson `enableDefaultTyping` 的雷、YAML `SnakeYAML` 的危險建構子，並用 Java 與 Go 示範「白名單型別」與「只用資料型 DTO」的安全做法。）
