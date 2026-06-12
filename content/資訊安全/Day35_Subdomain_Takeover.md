---
title: "Day 35 — Subdomain Takeover（子網域接管）"
date: 2026-05-31
tags: ["DNS", "Subdomain Takeover"]
---

# Day 35 — Subdomain Takeover（子網域接管）

> 後端工程師資安教學 · Day 35
> 適合對象：剛接觸 Web 後端、Java（1.8 / 21）與 Go 開發者

---

## 一、先講一個生活化的比喻

想像你公司在 A 商辦租了一間辦公室，門口掛著「**bigcorp-promo.example.com → A 商辦 301 號房**」這塊牌子（這牌子就是 DNS）。

後來行銷活動結束、退租了，可是**門口的牌子忘了拆**。

過幾個月，A 商辦把 301 號房租給別人——只要那個人去櫃台說「我要 301 號房」，他就拿到了。他在那間房間放什麼，外人從牌子走進來，都以為那是「bigcorp」的東西。

這就是 **Subdomain Takeover**：你的 DNS 還指著一個你已經不再擁有的雲端服務資源，**任何人去那個雲端服務「申請同一個名字」，就接管了你的子網域**。

---

## 二、技術上到底發生了什麼？

典型流程：

1. 你曾經建立 `promo.bigcorp.com` 的 DNS：CNAME → `bigcorp-promo.herokuapp.com`
2. 行銷活動結束，你把 Heroku app 刪了。
3. **但 DNS 的 CNAME 沒刪。** 此時 `bigcorp-promo.herokuapp.com` 變成「沒人擁有的可申請名字」。
4. 攻擊者去 Heroku 申請一個新 app，名字剛好叫 `bigcorp-promo`。
5. 從現在起，使用者打開 `https://promo.bigcorp.com` → DNS 解析 → 走到 Heroku 上**攻擊者的** app → 攻擊者的內容。

關鍵點：**問題不是雲服務商有漏洞**，而是 **DNS 指向了一個「外部可申請」的識別字 (identifier)，而你已經不再持有那個識別字**。

---

## 三、常見會被接管的服務

只要該服務「允許任意人申請特定子網域名稱、且該名稱會出現在 CNAME 裡」，就有風險。常見的有：

- **AWS S3**：`bucket-name.s3.amazonaws.com`
- **AWS CloudFront / Elastic Beanstalk**
- **GitHub Pages**：`username.github.io`
- **Heroku**：`*.herokuapp.com`
- **Azure**：`*.azurewebsites.net` / `*.cloudapp.net` / `*.trafficmanager.net`
- **Fastly / Netlify / Vercel / Surge / Shopify / Zendesk / Tumblr**
- **Mailgun / Sendgrid 的 verification 紀錄**

每家服務的「指紋」不一樣：S3 會回 `NoSuchBucket`，GitHub Pages 會回 `There isn't a GitHub Pages site here.`，Heroku 會回 `no-such-app.herokuapp.com`。這些固定字串就是偵測腳本的依據。

---

## 四、被接管後攻擊者可以做什麼？

很多人會覺得「不就是一個閒置子網域嗎，又沒重要的東西」。但因為瀏覽器把 `*.bigcorp.com` 視為**同一個註冊網域底下**，攻擊者可以：

1. **Cookie 偷竊 / 偽造**：如果主站把 Cookie 設成 `Domain=.bigcorp.com`，攻擊者可以從子網域讀取（或設定覆蓋）這些 Cookie，繞過 Session 隔離。
2. **CORS / postMessage 信任濫用**：很多主站把自家 `*.bigcorp.com` 加入 `Access-Control-Allow-Origin` 白名單。
3. **CSP `script-src` 白名單**：很多主站的 CSP 寫 `script-src 'self' *.bigcorp.com`，攻擊者就能從接管的子網域載入惡意 JS，繞過 CSP。
4. **OAuth Redirect 白名單**：若 redirect_uri 設成 `*.bigcorp.com`，攻擊者能竊取授權碼。
5. **釣魚**：在自家網域底下放釣魚頁面，使用者完全看不出異常，TLS 也是綠色（因為攻擊者可在那家雲服務上申請 Let's Encrypt 憑證）。
6. **品牌損害 / SEO 污染**。

簡單說：**它幾乎等於攻擊者拿到了你網域內的「自己人身分」**。

---

## 五、怎麼偵測自家有沒有 dangling DNS？

### 思路

對你所有 `*.bigcorp.com` 子網域：

1. 解析 DNS，看是否有 CNAME。
2. 若 CNAME 指向已知的雲服務商網域，**檢查那個目標是不是真的存在、由你擁有**。
3. 拿 HTTP 回應的指紋字串去比對「已知的 takeover 指紋」。

### Go 範例：簡單的 CNAME 巡檢工具

```go
// cmd/dangling-check/main.go
// Go 1.22+
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// 一些常見 takeover 指紋（節錄，實務上請維護自家清單）
var fingerprints = []struct {
	CNAMEContains string
	BodyContains  string
	Service       string
}{
	{"s3.amazonaws.com", "NoSuchBucket", "AWS S3"},
	{"github.io", "There isn't a GitHub Pages site here.", "GitHub Pages"},
	{"herokuapp.com", "No such app", "Heroku"},
	{"azurewebsites.net", "404 Web Site not found", "Azure Web App"},
	{"cloudfront.net", "Bad request", "CloudFront"}, // 需配合 CNAME 額外判斷
}

type Finding struct {
	Subdomain string
	CNAME     string
	Service   string
	Evidence  string
}

func check(ctx context.Context, sub string) (*Finding, error) {
	cname, err := net.DefaultResolver.LookupCNAME(ctx, sub)
	if err != nil || cname == "" {
		return nil, nil // 沒 CNAME 就跳過
	}
	cname = strings.TrimSuffix(cname, ".")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + sub)
	if err != nil {
		// 連不上也可能是 dangling，視情況納入告警
		return nil, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyStr := string(body)

	for _, f := range fingerprints {
		if strings.Contains(cname, f.CNAMEContains) &&
			strings.Contains(bodyStr, f.BodyContains) {
			return &Finding{
				Subdomain: sub,
				CNAME:     cname,
				Service:   f.Service,
				Evidence:  f.BodyContains,
			}, nil
		}
	}
	return nil, nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	scanner := bufio.NewScanner(os.Stdin) // 注意：實際使用要 import bufio
	for scanner.Scan() {
		sub := strings.TrimSpace(scanner.Text())
		if sub == "" {
			continue
		}
		if f, _ := check(ctx, sub); f != nil {
			fmt.Printf("[!] %s -> %s (%s): %s\n",
				f.Subdomain, f.CNAME, f.Service, f.Evidence)
		}
	}
}
```

用法：

```bash
cat all-subdomains.txt | go run ./cmd/dangling-check
```

### Java 21 版本（搭配排程跑）

```java
// SubdomainTakeoverChecker.java
// 需要 jdk.naming.dns 模組做 DNS 查詢，或改用 dnsjava 套件
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import javax.naming.directory.*;

public class SubdomainTakeoverChecker {

    private record Fingerprint(String cnameHint, String bodyHint, String service) {}

    private static final List<Fingerprint> FPS = List.of(
        new Fingerprint("s3.amazonaws.com", "NoSuchBucket", "AWS S3"),
        new Fingerprint("github.io", "There isn't a GitHub Pages site here.", "GitHub Pages"),
        new Fingerprint("herokuapp.com", "No such app", "Heroku")
    );

    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();

    public static Optional<String> check(String subdomain) throws Exception {
        String cname = lookupCNAME(subdomain);
        if (cname == null) return Optional.empty();

        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create("https://" + subdomain))
            .timeout(Duration.ofSeconds(5))
            .GET().build();

        HttpResponse<String> resp;
        try {
            resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) {
            return Optional.empty();
        }

        String body = resp.body();
        for (Fingerprint f : FPS) {
            if (cname.contains(f.cnameHint()) && body.contains(f.bodyHint())) {
                return Optional.of(
                    "[!] " + subdomain + " -> " + cname + " (" + f.service() + ")");
            }
        }
        return Optional.empty();
    }

    private static String lookupCNAME(String name) throws Exception {
        var env = new Hashtable<String, String>();
        env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
        var ctx = new InitialDirContext(env);
        Attributes attrs = ctx.getAttributes(name, new String[]{"CNAME"});
        Attribute cname = attrs.get("CNAME");
        return cname == null ? null : cname.get().toString();
    }
}
```

> 提醒：Java 內建 `com.sun.jndi.dns.DnsContextFactory` 屬於非穩定 API。實務上建議用 [dnsjava](https://github.com/dnsjava/dnsjava)（有持續維護，至今仍在更新），會更穩定也支援 EDNS、DoH、DNSSEC。

---

## 六、防禦：流程比工具更重要

### ✅ 1. DNS 紀錄要有 owner、有生命週期

每筆 DNS 紀錄至少標記：

- 建立的服務 / 用途
- 對應的雲端資源 ID（例如 S3 bucket 名）
- 負責人 / 團隊
- TTL 之外的「審視期限」

把 DNS 當成 IaC（Infrastructure as Code）管理：Terraform 的 `aws_route53_record`、`cloudflare_record` 都有清楚的資源關聯，可以做相依分析。

### ✅ 2. **拆服務的順序：先拆 DNS，再拆雲端資源**

最常踩雷的就是順序顛倒。正確順序：

1. 從 DNS 把 CNAME / A record 移除（或改指向 sinkhole）。
2. **等 TTL 過期 + 一段觀察期（24~72 小時）**。
3. 才刪除雲端的 S3 bucket / Heroku app / Azure 站台。

反過來做的話，從你刪掉 bucket 那一刻到 DNS 移除之間，會有一個「dangling 視窗」。

### ✅ 3. 雲服務商的「網域驗證」機制要用上

很多服務（CloudFront、App Service、Heroku Custom Domain、GitHub Pages 都已支援）現在會要求你加一筆 **TXT 驗證紀錄**才能把網域綁定到該帳號的資源。對攻擊者來說，即使他申請到同名 app，沒辦法通過驗證就無法綁網域。

- AWS：使用 ACM 憑證 + CloudFront 的 alternate domain name 驗證流程。
- GitHub Pages：在 repo 設定 custom domain 時會要求驗證 TXT。
- Azure：custom domain 需 `asuid.<your-domain>` TXT。

### ✅ 4. 限制 Cookie / CSP / CORS 的「同網域信任」

退一步想：就算真的被接管，能不能讓**爆炸半徑變小**？

- Cookie 不要設 `Domain=.bigcorp.com`，能不設就不設（讓它預設只對發 cookie 的主機有效）。
- CSP 不要寫 `*.bigcorp.com`，列舉真正需要的子網域。
- CORS / OAuth redirect 白名單一律寫**精確主機名**，不接受萬用字元。

這幾招呼應 Day 9（Security Headers / CORS）、Day 24（OAuth2 Pitfalls）。

### ✅ 5. 持續巡檢（CI / 排程）

把上面那支 Go 工具加進每日排程，輸出告警到 Slack / Email。對外的子網域清單可以從：

- 內部 DNS Zone export
- Certificate Transparency 日誌（`crt.sh`，可程式化查詢）
- 自家 CDN / WAF 的紀錄

---

## 七、最小化偵測腳本（可直接放排程）

```go
// cmd/daily-takeover-scan/main.go
package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var risky = []string{
	"s3.amazonaws.com", "cloudfront.net", "herokuapp.com",
	"github.io", "azurewebsites.net", "trafficmanager.net",
	"netlify.app", "vercel.app",
}

func looksRisky(cname string) (string, bool) {
	for _, r := range risky {
		if strings.Contains(cname, r) {
			return r, true
		}
	}
	return "", false
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // 並發限制

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		sub := strings.TrimSpace(sc.Text())
		if sub == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(s string) {
			defer wg.Done()
			defer func() { <-sem }()
			cname, err := net.DefaultResolver.LookupCNAME(ctx, s)
			if err != nil || cname == "" {
				return
			}
			if svc, ok := looksRisky(cname); ok {
				fmt.Printf("REVIEW %s -> %s [%s]\n", s, strings.TrimSuffix(cname, "."), svc)
			}
		}(sub)
	}
	wg.Wait()
}
```

這只做「**值得人工複核**」的清單，不做自動斷言「已被接管」——因為誤判成本高（可能把正常服務當成漏洞通報）。實務做法是：機器列清單，人工 + 指紋驗證再判斷。

---

## 八、自我檢查清單

在你的環境裡，逐項問自己：

1. 公司是否有**完整**的子網域清單？怎麼維護？
2. 退場流程文件裡，是否有寫「**先 DNS 後資源**」？
3. 有沒有 Cookie 設成 `Domain=.公司主網域`？真的需要嗎？
4. CSP / CORS / OAuth redirect 白名單裡有沒有 `*.bigcorp.com`？
5. 有沒有用 Certificate Transparency 監控你網域底下新冒出來的憑證？
6. 收購 / 併購進來的網域，有沒有納入巡檢？（最常出事的就是這類「歷史包袱」網域。）

---

## 九、今日重點回顧（30 秒版）

- **問題本質**：DNS 指向「外部可申請」的雲端識別字，但你已經不擁有它。
- **影響**：攻擊者拿到「自家網域底下」的合法位置，可竊取 Cookie、繞過 CSP / CORS、做釣魚與 OAuth 攻擊。
- **預防三招**：
  1. DNS 當 IaC 管理、加 owner。
  2. 拆服務先拆 DNS、等 TTL 過了再拆雲端資源。
  3. 用網域驗證 TXT，不讓「申請到同名」就能綁網域。
- **偵測一招**：每日掃描所有子網域的 CNAME，遇到指向高風險服務商的就人工複核。
- **記憶口訣**：**「DNS 不能比資源活得久。」**

---

## 十、延伸題（給自己練習）

1. 用 `crt.sh` 抓你網域過去半年所有出現過的子網域，過濾出仍然有 DNS 紀錄、但你已經不認得用途的。
2. 把上面那支 Go 腳本接上 Slack webhook，每天 09:00 發報告（呼應 Day 17 排程 / Day 16 日誌監控）。
3. 想想：如果你公司用的是 AWS Route53 + ACM，被接管的人能不能也申請到 `*.bigcorp.com` 的 TLS 憑證？答案是什麼？為什麼？

明天見，Day 36 預告：**Clickjacking / UI Redressing**——「我以為我點的是按鈕，結果按到了授權」。
