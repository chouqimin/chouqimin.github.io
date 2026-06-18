---
title: "Day 53：SSRF（Server-Side Request Forgery）— 當你的伺服器變成攻擊者的跳板"
date: 2026-06-18
tags: ["SSRF", "Cloud Metadata", "DNS Rebinding", "Java", "Go"]
---

# Day 53：SSRF（Server-Side Request Forgery）— 當你的伺服器變成攻擊者的跳板

接續 Day52 預告：昨天反序列化講的是「攻擊者控制資料**內容**」，今天換成「攻擊者控制伺服器發出的**請求**」。SSRF 讓你的後端代替攻擊者去打它不該打的地方——內網服務、雲端 metadata endpoint——而這一切都用著你伺服器的身分與網路位置。

---

## 一、SSRF 到底在攻擊什麼？

SSRF 的本質很單純：**你的後端會根據使用者提供的 URL（或 URL 的一部分）發出 HTTP 請求**。攻擊者只要能左右那個 URL，就能借用你伺服器的「網路視角」去存取它原本碰不到的資源。

從外部看，你的伺服器在 DMZ、能連內網、能存取雲端 metadata；從攻擊者看，這正是一個完美的跳板。常見的危險入口：

- 「給我一個圖片網址，我幫你抓下來做縮圖」
- 「填入你的 Webhook URL，事件發生時我們會 POST 過去」
- 「匯入這個 RSS / OpenGraph 連結的內容」
- 「PDF 產生器幫你把這個網頁轉成 PDF」
- 「health check：輸入要監控的 endpoint」

這些功能都有一個共通點：**使用者輸入直接變成伺服器發出請求的目標**。

---

## 二、最致命的目標：雲端 Metadata Endpoint

如果你的服務跑在 AWS / GCP / Azure，最該擔心的不是內網，而是 metadata endpoint：

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
```

這個 link-local IP（169.254.169.254）只有機器本身能存取，回傳的卻是**臨時的 IAM 憑證**。一旦攻擊者透過 SSRF 讓你的伺服器去打它，再把回應內容拿回來，等同直接拿到你雲端角色的 access key——接下來就是橫向移動、讀 S3、提權。

> 著名的 2019 Capital One 事件，核心就是一個 SSRF 打到 EC2 metadata 偷走憑證，外洩上億筆資料。

AWS 的 IMDSv2 改用「需先 PUT 拿 token，再帶 token GET」來緩解，務必強制啟用；但**應用層的白名單防禦才是根本**，不能只靠雲端設定。

---

## 三、後端情境：一個會被 SSRF 的縮圖服務

以一個「使用者給圖片 URL，伺服器下載後產縮圖」的 Java 範例示範漏洞：

```java
// ❌ 危險：直接拿使用者的 URL 發請求
@PostMapping("/thumbnail")
public ResponseEntity<byte[]> thumbnail(@RequestBody ThumbReq req) throws Exception {
    URL url = new URL(req.getImageUrl());          // 使用者完全控制
    try (InputStream in = url.openStream()) {       // 伺服器代為發送請求
        byte[] data = in.readAllBytes();
        return ResponseEntity.ok(makeThumbnail(data));
    }
}
```

攻擊者只要送：

```json
{ "imageUrl": "http://169.254.169.254/latest/meta-data/iam/security-credentials/" }
```

你的伺服器就乖乖把 IAM 憑證抓回來塞進回應。內網也一樣：`http://10.0.0.5:6379/`（Redis）、`http://localhost:8080/actuator/env`（Spring 內部端點）全都暴露。

---

## 四、為什麼「黑名單 IP 過濾」擋不住？

很多人第一直覺是：那我把 `127.0.0.1`、`169.254.169.254`、`10.x` 之類列黑名單擋掉不就好了？**不行**，黑名單在 SSRF 面前漏洞百出：

**1. IP 表示法千變萬化**——同一個 `127.0.0.1` 可以寫成：

```
http://0x7f.0.0.1/        十六進位
http://0177.0.0.1/        八進位
http://2130706433/        十進位整數
http://127.1/             省略寫法
http://[::ffff:127.0.0.1] IPv6 對映
http://0/                 等同 0.0.0.0
```

字串比對黑名單根本列不完。

**2. 用域名繞過**——攻擊者註冊一個解析到 `169.254.169.254` 的網域，你的字串黑名單看到的是普通 domain，照樣放行。

**3. HTTP redirect**——你檢查的初始 URL 是 `https://evil.com/img.png`（看起來無害），但對方回 `302 Location: http://169.254.169.254/...`，HTTP client 預設會乖乖跟著跳轉到內網。

**4. 最陰險的 DNS Rebinding（呼應 Day39）**——這是 TOCTOU（檢查與使用之間的時間差）攻擊：

```
你做安全檢查時：  evil.com → 解析成 1.2.3.4（公網，通過檢查）
你實際發請求時：  evil.com → 解析成 169.254.169.254（TTL 設極短，已換掉）
```

你「先解析驗證、再用 URL 發請求」中間 DNS 結果被掉包，驗證等於白做。

**結論：SSRF 的防禦核心不是黑名單，而是「解析成實際 IP → 用白名單比對 → 鎖定該 IP 直接連線、禁止 redirect」。**

---

## 五、Java：安全的 HTTP Client 寫法

關鍵三招：(1) 先 resolve 成 IP 並用**白名單 / 私網黑名單**比對實際 IP；(2) **禁用自動 redirect**，每跳一次都重新驗證；(3) 用驗證過的 IP 建立連線，避免「驗證後 DNS 又被換」。

```java
import java.net.*;
import java.net.http.*;
import java.util.List;

public class SafeHttpFetcher {

    // 阻擋的網段：loopback、link-local（含 metadata）、私網、保留位址
    private static boolean isBlockedAddress(InetAddress addr) {
        return addr.isLoopbackAddress()      // 127.0.0.0/8, ::1
            || addr.isLinkLocalAddress()     // 169.254.0.0/16, fe80::/10
            || addr.isSiteLocalAddress()     // 10/8, 172.16/12, 192.168/16
            || addr.isAnyLocalAddress()      // 0.0.0.0
            || addr.isMulticastAddress();
    }

    // 只允許走 http/https，且最終 IP 必須是公網
    private static void validate(URI uri) throws Exception {
        String scheme = uri.getScheme();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            throw new SecurityException("只允許 http/https，拒絕 " + scheme); // 擋 file://, gopher:// 等
        }
        // 解析「所有」回傳的 IP，任何一個落在私網就拒絕
        InetAddress[] addrs = InetAddress.getAllByName(uri.getHost());
        for (InetAddress a : addrs) {
            if (isBlockedAddress(a)) {
                throw new SecurityException("目標解析到內網位址：" + a.getHostAddress());
            }
        }
    }

    public byte[] fetch(String userUrl) throws Exception {
        // 關鍵：NEVER 自動跟隨 redirect，自己一跳一跳地驗證
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(java.time.Duration.ofSeconds(3))
                .build();

        URI uri = URI.create(userUrl);
        int maxHops = 5;
        for (int i = 0; i < maxHops; i++) {
            validate(uri);   // 每一跳都重新驗證實際 IP

            HttpRequest req = HttpRequest.newBuilder(uri)
                    .timeout(java.time.Duration.ofSeconds(5))
                    .GET().build();
            HttpResponse<byte[]> resp =
                    client.send(req, HttpResponse.BodyHandlers.ofByteArray());

            int code = resp.statusCode();
            if (code >= 300 && code < 400) {
                String loc = resp.headers().firstValue("Location")
                        .orElseThrow(() -> new SecurityException("redirect 缺 Location"));
                uri = uri.resolve(loc);   // 解析新目標，回圈頂端再次 validate
                continue;
            }
            return resp.body();
        }
        throw new SecurityException("redirect 次數過多");
    }
}
```

> 補強：Java 標準 client 仍有 resolve→connect 的微小時間差（DNS rebinding 殘餘風險）。要徹底封死，可改用「自訂 `connect` 時直接用驗證過的 `InetAddress` 而非重新解析 host」的低階寫法，或在出口架一台只允許白名單的 forward proxy，讓應用一律走它。

---

## 六、Go：安全的 HTTP Client 寫法

Go 的 `net/http` 很適合做這件事，因為 `Transport.DialContext` 讓你在**真正建立 TCP 連線的那一刻**攔截、驗證即將連的 IP——這正好把 DNS rebinding 的時間差關掉：在 dial 當下解析、驗證、然後就用那個 IP 連，不留空檔。

```go
package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// 阻擋的網段：loopback、link-local（含 169.254.169.254）、私網
func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	// 額外明確擋雲端 metadata
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}
	return false
}

func safeHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 3 * time.Second}

	return &http.Client{
		Timeout: 8 * time.Second,
		// 關鍵：禁止自動 redirect，避免被導去內網
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("redirect 已停用")
		},
		Transport: &http.Transport{
			// DialContext 在真正連線那刻驗證 IP，封死 DNS rebinding 時間差
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, err
				}
				for _, ipAddr := range ips {
					if isBlockedIP(ipAddr.IP) {
						return nil, errors.New("目標為內網位址，拒絕連線：" + ipAddr.IP.String())
					}
				}
				// 用驗證過的 IP 直接連，不再重新解析 host
				return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
			},
		},
	}
}

func fetch(userURL string) ([]byte, error) {
	// 也要擋掉 file:// gopher:// 等非 http(s) scheme（略，先檢查 scheme）
	client := safeHTTPClient()
	resp, err := client.Get(userURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// 限制讀取大小，避免大檔 DoS（呼應 Day51 訊息大小限制）
	return readLimited(resp.Body, 5<<20) // 5MB 上限
}
```

兩語言的共同原則一模一樣：**禁用 redirect、解析成實際 IP、用網段判斷（而非字串比對）擋掉私網與 metadata、限制大小與逾時**。

---

## 七、容易被忽略的細節

1. **不只擋 IP，scheme 也要白名單**：`file:///etc/passwd`、`gopher://`、`dict://` 都能被 SSRF 利用（尤其 curl-based client）。只允許 `http` / `https`。
2. **回應內容別原樣回傳**：就算你擋了大部分，也別把抓回來的 body / error 訊息原封回給使用者——這會變成「blind SSRF」探測內網的回饋管道。錯誤訊息統一、模糊化。
3. **IPv6 與雙重編碼**：`[::ffff:169.254.169.254]`、URL 編碼後的 host 都要正規化後再驗證。用語言內建的 `InetAddress` / `net.IP` 解析，不要自己拆字串。
4. **DNS rebinding 要在「連線當下」驗證**：先 resolve 再發請求的兩段式寫法仍有時間差，務必像 Go 那樣在 dial 時鎖 IP，或走只認白名單的 egress proxy。
5. **強制 IMDSv2 + 限制出網**：雲端層用 IMDSv2、把 metadata 的 hop limit 設 1、用 security group / NACL 限制應用伺服器的對外連線——多層防禦。
6. **SSRF 常與其他洞串接**：搭配 Day46 Host Header Injection、Day34 CRLF 可放大影響；它也是打進內網後續攻擊的起點，別當小洞看。

---

## 八、後端工程師的 Checklist

- [ ] 凡是「使用者輸入變成伺服器發出的請求」都視為 SSRF 風險點（縮圖、webhook、匯入、PDF、health check）。
- [ ] **scheme 白名單**：只允許 http / https，拒絕 file / gopher / dict 等。
- [ ] **用網段判斷擋私網**：loopback、link-local（含 169.254.169.254）、私網、保留位址一律拒絕——**不要用字串黑名單**。
- [ ] **禁用自動 redirect**，或每一跳都重新驗證目標 IP。
- [ ] 在**連線當下**解析並鎖定 IP，封死 DNS rebinding 時間差（Go `DialContext` / 自訂 socket factory / egress proxy）。
- [ ] 設定 connect / read **逾時**與**回應大小上限**，避免 SSRF 兼 DoS。
- [ ] 回應與錯誤訊息**模糊化**，不要洩漏內網探測結果（防 blind SSRF）。
- [ ] 雲端強制 **IMDSv2**、限制 metadata hop limit、用 security group 收斂出網。

---

## 九、一句話總結

> **SSRF 的本質是「使用者控制了伺服器要去連誰」。防禦的關鍵不是列黑名單（IP 寫法千變萬化、DNS 會被掉包），而是「解析成實際 IP → 用網段白名單判斷 → 禁用 redirect → 在連線當下鎖定 IP」。**
> 最該優先封死的目標是雲端 metadata（169.254.169.254）——那裡藏著你的 IAM 憑證。

---

## 延伸閱讀

- OWASP — A10:2021 Server-Side Request Forgery (SSRF)、SSRF Prevention Cheat Sheet
- AWS — IMDSv2 與 metadata hop limit 設定
- 2019 Capital One 事件分析（SSRF → EC2 metadata → IAM 憑證外洩）
- 前文：Day39 DNS Rebinding、Day46 Host Header Injection、Day34 CRLF Injection、Day51 gRPC 訊息大小限制

---

明天預告：**Day 54 — XXE（XML External Entity Injection）：當 XML 解析器幫攻擊者讀檔與打內網**
（今天 SSRF 是攻擊者控制「伺服器要連誰」；明天看一個經典的「藉由解析格式而觸發」的洞——XXE。攻擊者在 XML 裡塞入外部實體（`<!ENTITY xxe SYSTEM "file:///etc/passwd">`），讓解析器幫他讀本機檔案、甚至發出 SSRF 請求。會講外部實體與 DTD 的危險、為何預設設定就會中招，並用 Java（`DocumentBuilderFactory` / SAX 的安全 feature 設定）與 Go（為何標準 `encoding/xml` 不擴展外部實體、以及第三方解析器要注意什麼）示範如何安全關閉 DTD 與外部實體。）
