---
title: "Day 71：HTTP Range 請求的安全與 DoS（新主題，承 Day70 串流下載）— range amplification、multipart/byteranges 放大、If-Range 與段數上限"
date: 2026-07-08
tags: ["HTTP Range", "DoS", "Range Amplification", "Go"]
---

# Day 71：HTTP Range 請求的安全與 DoS

接續 Day70 預告：昨天談大檔下載時「**把 `Range` 交給標準庫**」（Go `http.ServeContent`、Java `ResponseEntity<Resource>` / `ResourceHttpRequestHandler`），讓續傳、部分下載自動運作。今天要補上一件昨天故意沒展開的事——**`Range` 本身就是一個攻擊面**。

一個看起來人畜無害的續傳功能，可能被一個請求放大成頻寬與 CPU 的 DoS。這篇不重講「怎麼支援續傳」，而是聚焦：

> **這是一篇聚焦 DoS 防禦的文章，不是 Range 教學。** 我們會談：
> 1. 為什麼「多段小 range」能把回應體積放大到遠超原檔（**range amplification**）；
> 2. `multipart/byteranges` 每段的 boundary + 標頭 overhead 怎麼變成 CPU/記憶體攻擊；
> 3. 標準庫（Go `http.ServeContent`、Tomcat/Spring）**幫你擋掉了哪一半、沒擋哪一半**；
> 4. `If-Range` 與 CDN/快取交互的坑；
> 5. 後端如何自訂**段數上限、總量上限**中介層。

如果你還不熟 `Range: bytes=` 的基本語意，先花 30 秒看第一節；重點在第三節之後。

---

## 一、30 秒複習：Range 請求長什麼樣

Range 讓 client 只要檔案的一部分（續傳、影片 seek、分塊下載）。流程是：

```text
# client 先看伺服器支不支援
GET /files/movie.mp4
→ 200 OK
  Accept-Ranges: bytes
  Content-Length: 104857600

# client 要第 0~1023 bytes
GET /files/movie.mp4
  Range: bytes=0-1023
→ 206 Partial Content
  Content-Range: bytes 0-1023/104857600
  Content-Length: 1024
```

單段很單純。問題出在 **HTTP 允許一次要「多段」**：

```text
Range: bytes=0-99,200-299,400-499
```

伺服器回的是一個 `multipart/byteranges` 文件，每段前面都要放一段 MIME 標頭：

```text
206 Partial Content
Content-Type: multipart/byteranges; boundary=SEP

--SEP
Content-Type: video/mp4
Content-Range: bytes 0-99/104857600

<100 bytes>
--SEP
Content-Type: video/mp4
Content-Range: bytes 200-299/104857600

<100 bytes>
--SEP--
```

看到問題了嗎？**每一段真正的資料可能只有 100 bytes，但外層的 boundary + `Content-Type` + `Content-Range` 標頭就佔了上百 bytes。** 段數一多，overhead 就開始輾壓資料本身。

---

## 二、range amplification：一個請求打爆頻寬與 CPU

### 2-1 重疊 range 的體積放大（經典 Apache Killer）

2011 年的 **CVE-2011-3192（Apache Killer）** 是這類攻擊的教科書。攻擊者送一個含**大量重疊 range** 的請求：

```text
Range: bytes=0-,0-1,0-2,0-3,0-4, ... （幾百到上千段，全部從 0 開始）
```

天真的伺服器實作會**為每一段各自複製一份資料**。一個 100KB 的檔案，被要求 1000 段幾乎整檔的重疊 range，就要組出接近 **100MB** 的回應——同時吃記憶體、吃 CPU（組 multipart）、吃出向頻寬。幾十個這種請求就能讓伺服器記憶體爆掉。

**放大來源有兩個，要分開看：**

1. **資料放大**：重疊 range 讓同一段 bytes 被複製多次（sum of ranges 遠大於檔案大小）。
2. **overhead 放大**：大量微小 range（即使不重疊、不超過檔案大小），每段的 MIME 標頭累積成龐大 overhead，且伺服器要做上萬次字串組裝。

### 2-2 現代標準庫擋掉了「資料放大」，但沒擋「overhead 放大」

這是本篇最重要的認知。**主流標準庫在 Apache Killer 之後都補了「sum of ranges 超過檔案大小就別玩了」的檢查**——但那只堵住第 1 種放大，第 2 種（段數過多的 overhead 與 CPU）通常**還開著**。

以 **Go `net/http`** 為例，`http.ServeContent` 解析完 range 後有這段邏輯（觀念示意）：

```go
// net/http 內部：若所有 range 的長度總和 > 檔案大小，
// 代表 range 覆蓋了整個檔案（或重疊放大），乾脆送整檔、忽略 range。
if sumRangesSize(ranges) > size {
    ranges = nil // 直接回 200 整檔，不做 multipart 放大
}
```

所以 **Go 幫你擋掉了 Apache Killer 式的「重疊資料放大」**：你送 `bytes=0-,0-1,0-2,...` 時，總和超過檔案大小，Go 會回整檔而不是複製 N 份。這是好事。

但 Go **不會限制 range 的「段數」**。攻擊者只要送**大量不重疊的微小 range**（總和 ≤ 檔案大小，躲過上面那個檢查）：

```text
Range: bytes=0-0,2-2,4-4,6-6, ... （上萬段，每段 1 byte，彼此不重疊）
```

此時 `sumRangesSize` 很小（就幾 KB），檢查放行 → Go 老實地產生一個含**上萬個 part** 的 `multipart/byteranges`，每個 part 幾百 bytes 的標頭。**回應體積被 overhead 放大幾百倍，而且 server 要做上萬次 boundary/標頭的字串組裝與 buffer 操作**——CPU 才是這裡的主要受害者。

Java 這邊（Tomcat 的 `DefaultServlet`、Spring 的 `ResourceHttpRequestHandler` / `ResourceRegion` 機制）在歷史上也有過對應的 range DoS 修補，行為隨版本演進，但同樣的道理成立：**別假設框架幫你把「段數」也管好了。你要自己設上限。**

> 一句話：**標準庫堵的是「同一段被複製到超過檔案大小」，你要自己堵的是「段數多到 overhead 與 CPU 爆掉」。**

---

## 三、防禦主線：在進 handler 之前，攔截惡意 Range 標頭

最乾淨的做法是一個**前置中介層 / Filter**：在請求碰到下載邏輯之前，解析 `Range` 標頭，套用三條規則：

1. **段數上限**：`Range` 內的區段數量超過門檻（例如 > 16）→ 直接**拒絕**（回 `416 Range Not Satisfiable`）或**丟棄 Range**（當成整檔請求，回 200）。合法的續傳/播放器幾乎不會一次要幾十段。
2. **總量上限**：所有區段長度總和若超過檔案大小（或某個倍數）→ 丟棄 Range 回整檔（把 Go 那條檢查明確化，並套用到 Java）。
3. **語法防禦**：無法解析、負值、`start > end`、超過檔案界線的畸形 range → 依 RFC 回 `416` 並帶 `Content-Range: bytes */<size>`。

### 3-1 Go：自訂 range 段數上限中介層

Go 的策略很直接：**在呼叫 `http.ServeContent` 之前，先檢查 `Range` 標頭的段數，超標就把整個 `Range` header 拔掉**，讓 `ServeContent` 回整檔（`200`）而不是產生巨大的 multipart。

```go
package rangeguard

import (
	"net/http"
	"strconv"
	"strings"
)

const (
	maxRangeSegments = 16 // 一次最多允許幾段；播放器/續傳綽綽有餘
)

// Middleware：檢查 Range 段數，超標就丟棄 Range（降級為整檔請求）。
// 放在 http.ServeContent / http.FileServer 之前。
func LimitRanges(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get("Range"); h != "" {
			n, ok := countRangeSegments(h)
			if !ok || n > maxRangeSegments {
				// 惡意或無意義的多段 range：直接拔掉 Range，
				// 讓下游回 200 整檔，不做 multipart 放大。
				r.Header.Del("Range")
				// 若寧可明確拒絕，也可改成：
				// http.Error(w, "too many ranges", http.StatusRequestedRangeNotSatisfiable)
				// return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// countRangeSegments 只數逗號分隔的段數，不做完整解析（那交給標準庫）。
func countRangeSegments(header string) (int, bool) {
	const prefix = "bytes="
	if !strings.HasPrefix(header, prefix) {
		return 0, false // 非 bytes 單位，一律視為不支援
	}
	spec := strings.TrimPrefix(header, prefix)
	if spec == "" {
		return 0, false
	}
	count := 0
	for _, part := range strings.Split(spec, ",") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		count++
		if count > maxRangeSegments {
			// 提早短路，避免對超長 header 本身做無謂的工
			return count, true
		}
	}
	return count, true
}

// 為避免超長 Range 標頭本身就是攻擊，另外在 Server 設定限制標頭大小：
//   srv := &http.Server{
//       Addr:              ":8080",
//       Handler:           LimitRanges(fileHandler),
//       MaxHeaderBytes:    16 << 10, // 16KB，擋掉塞滿逗號的巨大 Range 標頭
//       ReadHeaderTimeout: 5 * time.Second,
//   }
```

重點細節：

- **`MaxHeaderBytes` 是第一道閘**。上萬段的 `Range` 標頭本身可能好幾 MB——在解析段數前，`http.Server` 的 `MaxHeaderBytes`（預設 1MB）就會先擋下巨型標頭。把它調到合理值（例如 16KB）能讓攻擊連進不來。
- `countRangeSegments` 故意**只數逗號、提早短路**，不做完整區間解析，避免「為了擋 DoS 反而自己做了大量解析工」。
- 降級策略選 **「拔掉 Range 回 200」** 通常比 `416` 友善：正常 client 頂多退化成整檔下載，不會壞掉；但若你的檔案很大、整檔下載本身就昂貴，改回 `416` 明確拒絕更安全。

### 3-2 Java / Spring：在 Filter 層限制 Range 段數

Spring 的 `ResourceHttpRequestHandler` 會處理 range，但**段數上限最好在 handler 之前的 `OncePerRequestFilter` 就把關**，邏輯與 Go 版一致：數段數、超標就移除或改寫 `Range`。由於 `HttpServletRequest` 的標頭唯讀，用 `HttpServletRequestWrapper` 蓋掉 `Range`。

```java
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class RangeLimitFilter extends OncePerRequestFilter {

    private static final int MAX_RANGE_SEGMENTS = 16;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        String range = request.getHeader("Range");
        if (range != null && !range.isBlank()) {
            int segments = countSegments(range);
            // segments < 0 代表非 bytes 單位或格式異常
            if (segments < 0 || segments > MAX_RANGE_SEGMENTS) {
                // 選項 A：明確拒絕（大檔建議這個）
                response.setHeader("Content-Range", "bytes */*");
                response.sendError(HttpServletResponse.SC_REQUESTED_RANGE_NOT_SATISFIABLE);
                return;

                // 選項 B（較友善）：把 Range 拿掉、降級為整檔
                // request = new NoRangeRequestWrapper(request);
            }
        }
        chain.doFilter(request, response);
    }

    /** 只數段數，超過上限就提早短路；非 bytes 單位回 -1。 */
    private int countSegments(String header) {
        final String prefix = "bytes=";
        if (!header.startsWith(prefix)) {
            return -1;
        }
        String spec = header.substring(prefix.length());
        if (spec.isBlank()) {
            return -1;
        }
        int count = 0;
        for (String part : spec.split(",")) {
            if (part.isBlank()) {
                continue;
            }
            count++;
            if (count > MAX_RANGE_SEGMENTS) {
                return count; // 提早短路
            }
        }
        return count;
    }

    /** 需要「降級為整檔」時，用這個 wrapper 隱藏 Range 標頭。 */
    static class NoRangeRequestWrapper extends HttpServletRequestWrapper {
        NoRangeRequestWrapper(HttpServletRequest req) { super(req); }

        @Override
        public String getHeader(String name) {
            if ("Range".equalsIgnoreCase(name)) return null;
            return super.getHeader(name);
        }
    }
}
```

搭配 Spring Boot 註冊，並**限制請求標頭大小**（等同 Go 的 `MaxHeaderBytes`）：

```java
@Bean
FilterRegistrationBean<RangeLimitFilter> rangeLimit() {
    var reg = new FilterRegistrationBean<>(new RangeLimitFilter());
    reg.addUrlPatterns("/files/*", "/download/*"); // 只掛在會下載的路徑
    reg.setOrder(Ordered.HIGHEST_PRECEDENCE);       // 越早越好
    return reg;
}
```

```yaml
# application.yml：把巨型 Range 標頭擋在容器層
server:
  max-http-request-header-size: 16KB   # Tomcat 標頭上限，別讓上萬段 Range 進來
  tomcat:
    connection-timeout: 5s
```

> Tomcat / Spring 各版本對 range DoS 的內建處理不盡相同，且會演進。**不要靠「猜測某版本會擋」**——用上面這種明確的 Filter，把段數與標頭大小上限寫成你自己的、可測試的規則。

---

## 四、`If-Range` 與快取/CDN 的坑

`If-Range` 是續傳的一致性保險：client 說「如果檔案還是我上次拿到的那個版本（用 ETag 或 Last-Modified 比對），就給我 range；否則給我整個新檔」。

```text
GET /files/report.pdf
Range: bytes=1000-2000
If-Range: "v3-etag"        # 或 If-Range: <Last-Modified date>
```

- ETag **相符** → `206` 給那一段。
- ETag **不符**（檔案已更新）→ 忽略 Range，回 `200` 整個新檔（避免把新舊檔案的 bytes 拼在一起 → 檔案損毀）。

後端與 CDN 交互時要注意幾點：

1. **ETag 必須真的能代表內容版本**。如果你用弱 ETag 或用會變動的值（例如 inode、每次啟動就變的 hash），`If-Range` 會頻繁失效，把本該 206 的續傳全部退化成 200 整檔——**等於把續傳優化變成頻寬放大**（每次都傳整檔）。
2. **`Accept-Ranges: bytes` 與 `Vary`**。若回應會依 `Range`／授權而不同，快取層必須把 `Range` 納入 cache key 或設對 `Vary`，否則可能把某使用者的 partial 回應快取後回給別人（承 Day30 / Day64 的快取污染/欺騙家族）。多數成熟 CDN 會自行處理 range 與 cache，但**自建反向代理要特別確認**。
3. **授權要在給 range 之前檢查**（承 Day07）。別因為「只是一小段」就跳過授權——partial content 一樣是內容洩漏。

---

## 五、後端 Code Review / 測試 checklist

```text
[ ] 下載端點是否有「Range 段數上限」（例如 <= 16）? 超標拒絕或降級為整檔?
[ ] 是否限制請求標頭大小(Go MaxHeaderBytes / Tomcat max-http-request-header-size)
    以擋掉塞滿逗號的巨型 Range 標頭?
[ ] 是否確認標準庫會擋「sum of ranges > 檔案大小」的重疊放大(Go 會;Java 依版本自行加固)?
[ ] 大檔是否走串流(http.ServeContent / ResponseEntity<Resource>)而非讀成 byte[]?
    (承 Day70;整檔讀進記憶體時 range DoS 更致命)
[ ] Range 段數/標頭大小拒絕事件是否記 log 告警(承 Day16)?
[ ] ETag 是否穩定代表內容版本,避免 If-Range 頻繁失效把 206 退化成 200 整檔放大頻寬?
[ ] CDN / 反向代理是否正確處理 Range 與 cache key / Vary(承 Day30 / Day64)?
[ ] 取 range 前是否已做下載授權(承 Day07),不因「只是一小段」跳過?
[ ] 畸形 range(負值、start>end、超界)是否回 416 + Content-Range: bytes */<size>?
[ ] ReadTimeout / connection-timeout 是否設定,避免 range 請求配合慢速讀取拖住連線?
```

自動化回歸測試建議：

- 送 `Range: bytes=0-0,2-2,4-4,...`（上萬段微小不重疊 range），**斷言伺服器回 416 或 200 整檔，而非產生巨大的 `multipart/byteranges`**；量測回應體積與處理時間有上限。
- 送 Apache Killer 式重疊 range（`bytes=0-,0-1,0-2,...`），斷言回應體積不超過原檔大小（沒有資料放大）。
- 送超大的 `Range` 標頭（數 MB 的逗號串），斷言被標頭大小上限擋下（`431` / 連線關閉），不進 handler。
- 送畸形 range（`bytes=abc`、`bytes=100-50`、`bytes=999999999-`），斷言回 `416` 且帶正確 `Content-Range`。
- 更新檔案內容後，用舊 `If-Range` ETag 送 range，斷言回 `200` 整個新檔（不是拼接損毀的檔案）。

---

## 六、一句話總結

> Day70 教你「把 Range 交給標準庫」讓續傳自動運作；Day71 補上「Range 本身是攻擊面」。**放大有兩種：重疊 range 的「資料放大」(Apache Killer)——主流標準庫(如 Go http.ServeContent 的 `sumRangesSize > size` 檢查)已幫你擋掉；以及大量微小 range 的「overhead / CPU 放大」——標準庫通常不管段數,要你自己擋。** 防禦主線是一個前置中介層/Filter:**限制 Range 段數(例如 ≤16,超標拒絕或降級整檔)、限制請求標頭大小(Go MaxHeaderBytes / Tomcat max-http-request-header-size)擋掉巨型 Range 標頭、畸形 range 回 416**；再確認 **ETag 穩定避免 If-Range 退化成整檔放大、CDN 正確處理 Range 與 cache key(承 Day30/Day64)、授權在取 range 前(承 Day07)**。記住:**標準庫堵「同一段複製到超過檔案大小」,你堵「段數多到 CPU 爆掉」。**

---

## 延伸閱讀

- Day70 Content-Disposition 下載端點進階防禦——本篇的前傳，串流下載與 `Range` 交給標準庫的起點。
- Day31 ReDoS——同屬「一個小輸入放大成 CPU DoS」的思路對照（那邊是 regex 回溯，這邊是 range 組裝）。
- Day51 gRPC / Protobuf Security——`MaxRecvMsgSize` 限制訊息大小，與本篇限制 range 段數/標頭大小同一種「設上限」防禦哲學。
- Day30 Web Cache Poisoning / Day64 Web Cache Deception——Range 與 CDN cache key / Vary 的交互風險來源。
- Day16 Security Logging / Monitoring——range/標頭上限的拒絕事件要記 log 告警。
- Day07 Broken Access Control / IDOR——partial content 一樣是內容，授權要在取 range 前檢查。

---

明天預告：**Day 72 — Slowloris 與慢速 HTTP DoS（新主題，承 Day71 的 DoS 家族）**
（Day71 談的是「放大型」DoS——一個請求撐大回應；明天換到相反的「連線佔用型」DoS：Slowloris、Slow POST（R.U.D.Y.）、slow read 用**極慢的速度**送標頭/body 或讀回應，用極少頻寬就把伺服器的連線池/執行緒佔滿。會介紹為什麼同步阻塞式伺服器（傳統 Tomcat thread-per-connection）特別脆弱、非阻塞式（Netty / Go net/http）為何較耐打但仍需設限，並示範 Java（Tomcat `connectionTimeout`、`maxConnections`、`maxSwallowSize`）與 Go（`ReadHeaderTimeout`、`ReadTimeout`、`WriteTimeout`、`http.TimeoutHandler`）怎麼用 timeout 與連線上限把慢速攻擊擋在門外。）
