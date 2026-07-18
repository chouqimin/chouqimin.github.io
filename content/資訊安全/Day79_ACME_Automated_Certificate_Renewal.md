---
title: "Day 79：ACME 自動換發管線（新主題）— 四階段協定、三種 challenge 的安全取捨、DNS-01 為什麼最強也最危險，以及當換發管線變成生產基礎設施之後你要扛的事"
date: 2026-07-19
tags: ["ACME", "Certificate Renewal", "PKI", "TLS", "autocert"]
---

接續 Day78 預告：Day78 的結論是「短效憑證讓撤銷問題消失」，但它同時把一件事推到最前線——**你的換發管線壞掉，就是你的服務壞掉，而且容錯窗口從「一年」縮到「幾小時」**。以前憑證簽一年，換發失敗你有好幾週可以慢慢處理；現在 6 天短效憑證每 2.5 天換一次，換發掛掉幾小時你就開始掉服務。今天要講的就是這條管線：**ACME 協定怎麼運作、三種網域驗證 challenge 各自的安全代價、autocert 的三個坑、以及當「拿憑證」從一年一次的手動作業變成每天自動跑的生產系統之後，維運上你必須重新看待的東西。**

這是新主題。不重講 Day78 的撤銷機制、也不重講 Day76/77 的 pinning 與 CT。但你會一直看到它們回來：**換發程式要有 DNS 寫入權，而 DNS 就是 Day77 CAA 那把鎖所在的地方**；**換發預設會換金鑰，而那正是 Day76 pinning 每 60 天自動失效的原因**；**換發管線是偵測型控制的近親——「從來沒失敗過」跟「從來沒被驗證過」在儀表板上長得一模一樣**（承 Day77）。

---

## 一、先講清楚 ACME 到底在解什麼問題

ACME（Automatic Certificate Management Environment，RFC 8555）解的問題只有一句話：**怎麼讓一台機器自動證明「我控制這個網域」，然後自動拿到一張憑證，全程沒有人。**

在 ACME 之前，拿憑證是這樣的：你到 CA 網站填表、貼上 CSR、CA 寄一封驗證信到 `admin@yourdomain.com`、你點連結、CA 用 email 或電話確認你是誰、幾天後寄憑證檔給你、你手動裝上去。這整套流程**假設有一個人**在每個環節做決定。一年一次，還撐得住。

短效憑證把這個假設打碎了。**每 2.5 天換一次憑證，一年 146 次，你不可能派人去點 146 次驗證信。** 所以整套流程必須自動化，而自動化的前提是：**「證明你控制網域」這件事要能被機器做、被機器驗。** 這就是 ACME。

Let's Encrypt 2015 上線 ACME，把「拿一張公開信任的 DV 憑證」從一件要花錢、要等幾天、要有人操作的事，變成一行指令幾秒鐘的事。這是 HTTPS 從「大站才有」變成「到處都是」的直接原因。**但天下沒有白吃的午餐**：你把「證明控制網域」自動化了，代價是——那套能自動證明控制權的憑據（DNS API token、web server 的寫入權、TLS 監聽埠的控制權），現在握在一支自動跑的程式手裡。**誰能驅動那支程式，誰就能替你的網域弄到憑證。** 這是本篇後半的主軸。

---

## 二、ACME 的四個階段（心智模型）

不管你用 certbot、autocert、acme4j 還是 cert-manager，底層都是同一套四階段流程。把這四階段記在腦子裡，後面所有的坑你才知道發生在哪一格。

**階段一：帳號（Account）。** 你先在 CA 註冊一個 ACME 帳號，用一對你自己產生的金鑰。**注意這對「帳號金鑰」跟「憑證金鑰」是兩回事**——帳號金鑰是你跟 CA 之間的身分（你所有的請求都用它簽名），憑證金鑰是實際放進憑證裡、用來跑 TLS 握手的那把。這個區分待會在 RFC 8657 那節會變得很重要（CAA 可以綁「哪個帳號」而不是「哪把憑證金鑰」）。

**階段二：下單（Order）。** 你告訴 CA「我要一張涵蓋 `api.example.com` 跟 `*.example.com` 的憑證」。CA 回你一張 order，裡面列出**你必須先完成哪些網域的授權（authorization）**，每個 authorization 底下給你**一組可選的 challenge**（HTTP-01 / DNS-01 / TLS-ALPN-01）。

**階段三：網域驗證（Challenge）。** 這是整個協定的核心。CA 說「你選一種 challenge，照做，我來驗你是不是真的控制這個網域」。三種 challenge 的差別就是本篇第三節，也是安全取捨全部發生的地方。你完成 challenge、通知 CA、CA 去驗、驗過了這個 authorization 就變 valid。

**階段四：取憑證（Finalize + Download）。** 所有 authorization 都 valid 之後，你送出 CSR（憑證簽署請求，裡面帶你的**憑證金鑰**公鑰），CA 簽出憑證，你下載回來裝上去。

**換發（Renewal）不是特殊流程——它就是把階段二到四再跑一次。** 這點很多人沒意識到：ACME 沒有「續約」這個動作，換發＝重新下單、重新驗證、重新簽一張新的。所以**每一次換發，你的網域驗證能力都要能重新證明一次**。如果你當初是靠「暫時開一個埠」或「暫時寫一筆 DNS」來驗證，那每 2.5 天你都得再做一次——這件事能不能穩定自動化，就是短效憑證時代的成敗點。

---

## 三、三種 challenge：安全取捨全在這裡

CA 要驗「你控制這個網域」，方法就是**要你去改一個只有網域控制者才改得動的東西**。改什麼？三種選擇。

### HTTP-01：在網站根目錄放一個檔案

CA 給你一個 token，你要在 `http://<你的網域>/.well-known/acme-challenge/<token>` 放一個特定內容的檔案。CA 用 HTTP（**故意用明文 80 埠，因為此時你可能還沒有憑證**）去抓那個 URL，抓到對的內容就算你控制這個網域。

**安全性質：**

- **需要你的網站在 80 埠對公網開放。** CA 的驗證伺服器要連得到你。內網服務、防火牆後的服務用不了 HTTP-01。
- **不能簽萬用憑證（wildcard）。** `*.example.com` 沒有一個具體的 host 讓 CA 去抓檔案，所以 HTTP-01 天生不支援 wildcard。這是硬限制。
- **驗證流量走明文 HTTP，且 CA 會跟隨跳轉。** 這裡藏了一個跟 Day10 SSRF、Day20/67 Open Redirect 有關的細節：如果你的 80 埠 handler 對 `.well-known/acme-challenge/` 以外的路徑有奇怪的跳轉行為，理論上是個要注意的面。實務上 CA 的驗證器有自己的限制，但**心智模型要對：你在 80 埠上放了一個「CA 會主動來連、且會跟跳轉」的端點**。
- **權限範圍相對窄。** 執行換發的程式只需要能在 web root 的 `.well-known/acme-challenge/` 寫檔案（或攔截那個路徑的請求）。它拿不到你的 DNS、也拿不到別的東西。**這是 HTTP-01 最大的優點：爆炸半徑小。**

### TLS-ALPN-01：在 443 埠的 TLS 握手裡回應

CA 跟你的 443 埠發起一個 TLS 握手，用一個特殊的 ALPN 協定值 `acme-tls/1`。你要在握手時回一張**自簽的臨時憑證**，裡面帶一個特定的 extension（把 token 編進去）。CA 看到對的 extension 就算你控制這個網域。

**安全性質：**

- **完全走 443 埠，不需要開 80 埠。** 對「只想開一個埠」的部署很乾淨。
- **一樣不能簽 wildcard。**
- **需要你的 TLS 終端能在握手層動態回應 ACME 專用憑證。** 這對「TLS 由應用程式自己終結」的架構（例如 Go 服務直接跑 `tls.Config`）很自然；但如果你 TLS 是由前置的 LB / CDN 終結，你就得讓那一層支援 TLS-ALPN-01，而很多托管 LB 不讓你插手握手。
- **權限範圍窄，跟 HTTP-01 差不多。** 只需要控制 TLS 握手，拿不到 DNS。

### DNS-01：在 DNS 放一筆 TXT 記錄

CA 給你一個 token，你要在 `_acme-challenge.<你的網域>` 放一筆 TXT 記錄，內容是 token 的雜湊。CA 去查 DNS，查到對的 TXT 就算你控制這個網域。

**安全性質——這裡是本篇最重要的一段：**

- **DNS-01 是萬用憑證（wildcard）的唯一選項。** 要簽 `*.example.com`，CA 沒辦法用 HTTP/TLS 去連一個具體 host（wildcard 沒有具體 host），只能查 `_acme-challenge.example.com` 這筆 DNS。所以**只要你要 wildcard，你就被迫用 DNS-01**。
- **不需要你的服務對公網開任何埠。** CA 只查 DNS，不連你的服務。**這是內網服務、防火牆後服務唯一能自動換發的方式**——你的服務可以完全不對公網開放，只要你的 DNS 供應商 API 打得到就行。
- **但它的權限範圍最大、最危險。** 要自動完成 DNS-01，換發程式必須有**寫入你 DNS zone 的權限**（一把 DNS API token）。而——**DNS 正是 Day77 CAA 那把鎖所在的地方**。CAA 記錄（`example.com. CAA 0 issue "letsencrypt.org"`）是一筆 DNS 記錄。**誰能寫你的 DNS，誰就能改掉 CAA、把鎖拆了，然後叫任何一家 CA 幫他簽你的網域。** 你為了自動換發，把一把「能拆掉你所有憑證防線」的鑰匙交給了一支自動跑的程式。

把這三者的取捨列成表：

| 面向 | HTTP-01 | TLS-ALPN-01 | DNS-01 |
|---|---|---|---|
| 需要對公網開的埠 | 80 | 443 | 無（只需 DNS API 可達） |
| 能簽 wildcard | 否 | 否 | **是（唯一選項）** |
| 內網 / 防火牆後服務 | 不行 | 不行 | **可行** |
| 換發程式需要的權限 | 寫 web root 一個路徑 | 控制 TLS 握手 | **寫整個 DNS zone** |
| 爆炸半徑 | 小 | 小 | **大（含 CAA）** |
| 適合誰 | 對外 web 服務 | 自己終結 TLS 的服務 | wildcard、內網服務、多主機 |

**選擇原則：能用 HTTP-01 或 TLS-ALPN-01 就別用 DNS-01。** DNS-01 的權限太大，只有在「需要 wildcard」或「服務不對公網開放」時才用，而且用的時候要把那把 DNS token 當成**最高等級的機密**來管（承 Day15：短生命週期、最小權限、輪替、寫入即 audit）。

### DNS-01 的權限問題有沒有解？有——委派子網域

如果你被迫用 DNS-01（例如要 wildcard），但不想把「整個 zone 的寫入權」交給換發程式，標準做法是 **CNAME 委派**：把 `_acme-challenge.example.com` 用 CNAME 指到另一個你專門開來、權限隔離的 zone（例如 `example.com.acme-delegation.net`），換發程式只拿到那個小 zone 的寫入權。這樣即使 token 外洩，攻擊者能改的也只有那個委派用的 zone，改不了你正式 zone 裡的 CAA、MX、A 記錄。**用最小權限把 DNS-01 的爆炸半徑收回來**——這是承 Day07 授權最小化在 PKI 管線上的體現。

---

## 四、RFC 8657：把 CAA 從「哪家 CA」收緊成「哪個帳號、用哪種方法」

Day77 講 CAA 時，`issue "letsencrypt.org"` 的意思是「只有 Let's Encrypt 這家 CA 能簽我的網域」。但這個粒度其實不夠細——**Let's Encrypt 幫全世界簽憑證，「是 Let's Encrypt 簽的」不代表「是我這個帳號叫它簽的」**。如果攻擊者也能在 Let's Encrypt 開一個帳號、且能通過某個 challenge（例如他短暫控制了你某台機器的 80 埠），CAA `issue "letsencrypt.org"` 是擋不住他的——因為他也是走 Let's Encrypt。

RFC 8657 給 CAA 加了兩個參數，把鎖收得更緊：

```
example.com. CAA 0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/12345678; validationmethods=dns-01"
```

- **`accounturi`**：只有「這個特定的 ACME 帳號」能替我簽。不是「Let's Encrypt 能簽」，是「Let's Encrypt 底下**我這個帳號 12345678**能簽」。攻擊者就算也用 Let's Encrypt，他的帳號 URI 不一樣，簽不出來。
- **`validationmethods`**：只允許用**指定的 challenge 方法**驗證。例如你全部走 DNS-01，就寫 `validationmethods=dns-01`，那麼即使攻擊者短暫拿到你的 80 埠想走 HTTP-01，CA 也會拒絕——因為 CAA 說「這個網域只接受 dns-01 驗證」。

**這是 Day77「CAA 是門鎖」的升級版：從「哪家 CA 能進門」細化到「哪個人、用哪把鑰匙、走哪個門」。** 對後端的意義是：如果你的換發管線是固定的（固定帳號、固定 challenge 方法），你就**應該**把 `accounturi` 和 `validationmethods` 寫進 CAA，把鎖收到最緊。這幾乎沒有代價（你本來就只用一個帳號一種方法），卻能擋掉「攻擊者用同一家 CA 開別的帳號」和「攻擊者切換到你沒在用的 challenge 方法」這兩條路。

**CI 檢查**（承 Day77 的 CAA 斷言 script，這裡補上 8657 參數）：

```bash
# 斷言 CAA 有綁定 accounturi 與 validationmethods，而非只寫 CA 名
dig +short CAA example.com | grep -q 'accounturi=' \
  || { echo "CAA 未綁定 accounturi，鎖沒收緊"; exit 1; }
dig +short CAA example.com | grep -q 'validationmethods=' \
  || { echo "CAA 未限制 validationmethods"; exit 1; }
```

承 Day18：讓它在 CI 紅，不要在生產紅。**DNS 記錄很容易在某次調整時被誤刪或被覆蓋**，CAA 尤其——它平常不影響任何東西，壞掉了你也不會馬上發現，直到有人利用那個缺口。

---

## 五、Go：`autocert` 的正確姿勢與三個坑

Go 生態裡最常見的自動換發方案是 `golang.org/x/crypto/acme/autocert`。它把整套 ACME 流程包成「你在 `tls.Config` 掛一個 `GetCertificate`，第一次有人連進來且沒有憑證時，它自動去 Let's Encrypt 走一次 TLS-ALPN-01 / HTTP-01，拿到憑證、快取、之後自動換發」。對「單台 Go 服務自己終結 TLS」的場景，它幾乎是零設定。

**但它有三個坑，每一個都足以把你搞掛。**

### 正確的基本用法

```go
package main

import (
    "crypto/tls"
    "log"
    "net/http"

    "golang.org/x/crypto/acme/autocert"
)

func main() {
    m := &autocert.Manager{
        Prompt: autocert.AcceptTOS,
        // 坑一的解法：一定要設 HostPolicy
        HostPolicy: autocert.HostWhitelist("api.example.com", "www.example.com"),
        // 坑二的解法：Cache 不能用預設，要用共享儲存
        Cache: autocert.DirCache("/var/lib/acme-cache"),
        Email: "ops@example.com", // 換發失敗 / 即將到期時 CA 會寄信通知
    }

    srv := &http.Server{
        Addr:      ":443",
        Handler:   yourHandler(),
        TLSConfig: m.TLSConfig(), // 內含 GetCertificate + acme-tls/1 ALPN 支援
    }

    // HTTP-01 與 80 埠跳轉：autocert 提供 HTTPHandler
    go func() {
        h := m.HTTPHandler(nil) // 處理 /.well-known/acme-challenge/ 並把其餘跳轉到 https
        log.Fatal(http.ListenAndServe(":80", h))
    }()

    log.Fatal(srv.ListenAndServeTLS("", "")) // 憑證由 autocert 動態提供
}
```

### 坑一：`HostPolicy` 不設 = 幫任何人簽到你被限速

`autocert.Manager` 如果 `HostPolicy` 留空（`nil`），它的行為是——**任何連進來、在 SNI 裡帶了任意網域的請求，它都會去 Let's Encrypt 幫那個網域申請憑證**。攻擊者只要對你的 IP 連一堆 `SNI: random-<n>.attacker.com`，你的服務就會傻傻地對 Let's Encrypt 發一堆申請，直到**觸發 Let's Encrypt 的速率限制**（每個帳號、每個 IP 都有上限），然後你**連自己真正需要的憑證都申請不到了**——這是一個自我 DoS。

`HostPolicy` 不是選配，是**必填**。用 `autocert.HostWhitelist(...)` 明確列出你要服務的網域，或自己實作 `HostPolicy` 函式做更精細的判斷。**沒設 HostPolicy 的 autocert 是一顆定時炸彈。**

### 坑二：預設 `Cache` = 每個副本各簽一份，然後一起被限速

`autocert.Manager` 如果不設 `Cache`，它**根本不快取到磁碟**，每次重啟都重新申請。就算你設了 `autocert.DirCache("...")` 指到本機磁碟，在**多副本部署**下問題還在：三個 pod 各自有各自的本機磁碟快取，於是**每個副本各自去申請一份 `api.example.com` 的憑證**。三個副本 = 三倍申請量，很快撞上 Let's Encrypt「每個註冊網域每週最多幾張」的限制，然後全體換發失敗。

解法：**多副本部署必須共享 Cache。** 自己實作 `autocert.Cache` 介面（`Get`/`Put`/`Delete` 三個方法）接到共享儲存——Redis、資料庫、S3、或 Kubernetes Secret。讓所有副本讀寫同一份憑證快取，只有一個副本會真的去申請，其他的讀快取。

### 坑三：它不適合放在 LB 後面

autocert 的 TLS-ALPN-01 / HTTP-01 都需要**CA 的驗證流量能直接打到「持有這個申請狀態的那台機器」**。但你把服務放在 LB 後面時：

- CA 來驗 TLS-ALPN-01，LB 會把握手**分流到任意一台後端**——但發起申請、握著那個 challenge 狀態的可能是另一台，於是握手回不出對的 ACME 憑證，驗證失敗。
- 更根本的是，**LB 通常自己終結 TLS**，握手根本到不了你的 Go 服務，autocert 的 ALPN 機制完全插不上手。

autocert 的設計假設是「**這台 Go 服務自己直接面對公網、自己終結 TLS**」。一旦前面有 LB / CDN 終結 TLS，autocert 就不是對的工具了——這時憑證應該由**前置那一層**（LB / CDN / ingress controller）自己管，或用獨立的換發元件（見下一節）。

---

## 六、Java：沒有標準庫等價物，這是現實

Go 有 `x/crypto/acme/autocert` 這種近乎官方的方案。**Java 沒有。** JDK 標準庫裡沒有任何 ACME client。這不是疏漏，是生態選擇的結果，而且它反映了一個更大的架構事實。

Java 世界要自動換發，實務上有三條路：

**路徑 A：用第三方函式庫 acme4j。** `org.shredzone.acme4j` 是 Java 生態最成熟的 ACME client，能在 JVM 裡直接跑完四階段。適合「我就是想在 Java 程式裡自己管憑證」的場景。但你要自己處理：帳號金鑰保管（承 Day15）、challenge 的落地（DNS-01 要接你的 DNS 供應商 API、HTTP-01 要能在 web root 寫檔）、憑證的儲存與 reload。**這是可行的，但你等於自己重寫了一遍 certbot 的骨架**，要維護的東西不少。

**路徑 B（最常見）：把換發移出 JVM，交給旁邊的元件。** 這是大多數 Java 團隊實際在做的：

- **Sidecar / cert-manager**：在 Kubernetes 裡，用 `cert-manager` 這個 controller 統一管所有服務的憑證。它負責跟 ACME 打交道、完成 challenge、把簽好的憑證塞進 Kubernetes Secret，你的 Java 服務只管**讀那個 Secret**。JVM 完全不碰 ACME 協定。
- **前置 LB / ingress 換發**：由 Nginx ingress、Traefik、雲端 LB 這一層去終結 TLS 並自動換發（很多都內建 ACME 支援），Java 服務在後面跑純 HTTP。**這也是為什麼「Java 沒有 autocert」不是問題**——因為在這種架構下，TLS 根本不在 JVM 裡終結。

**路徑 C：certbot + 部署鉤子。** 傳統 VM 部署，用 certbot 排程換發，換發成功後用 deploy hook 通知 Java 服務 reload 憑證（見第七節）。

**架構判斷：TLS 在哪裡終結，換發就該在哪裡做。** 如果 TLS 由前置 LB 終結，就別在 Java 裡折騰 ACME；如果是 Java 自己終結 TLS（例如內嵌 Tomcat 直接跑 HTTPS），才考慮 acme4j 或 certbot + reload。**Go 的 autocert 好用，恰恰是因為 Go 服務常常自己直接終結 TLS；Java 服務更常躲在 LB 後面，所以它不需要 autocert。** 這不是語言的優劣，是部署形態的差異。

---

## 七、維運主線：換發從「一年一次的手動作業」變成「生產基礎設施」

這是本篇真正的重點。**協定和函式庫都是細節，難的是把換發當成一個會半夜掛掉的生產系統來經營。** 承 Day78：效期越短，容錯窗口越小；6 天憑證每 2.5 天換一次，換發掛掉你只有幾小時緩衝。

### 觸發時機：不是「快到期才換」，是「一開始就換」

最常見、也最致命的錯誤是**把換發排在「憑證快到期時」**——例如「剩 3 天才換」。這在短效憑證時代是自殺：

假設憑證效期 6 天，你設「剩 2 天換」。那你的**緩衝只有 2 天**。如果換發那天 CA 出問題（見下面 2026-05-08 那場事故）、或你的 DNS API 掛了、或 challenge 驗證失敗，你有 2 天可以修。修不完，憑證過期，服務掛。

**正確的做法：一拿到憑證就開始嘗試換，把緩衝拉到最大。** 業界慣例是**在效期過了 1/3 ~ 1/2 時就開始換**，而且**換發失敗要能一直重試到還剩很多時間**。certbot 預設是「效期過三分之二才換」，但那是為 90 天憑證設計的；短效憑證要更激進。核心原則是：**換發的緩衝時間 = 你能容忍換發連續失敗多久而服務不掛，這個數字要盡可能大。**

### 換發失敗的告警：要在「還來得及」的時候叫

換發是**偵測型控制的近親**，它有跟 Day77 CT monitor 一模一樣的病：**「換發從來沒失敗過」跟「換發程式根本沒在跑」，在儀表板上長得一模一樣。**

所以告警要分兩種，缺一不可：

1. **換發失敗告警（有 error）**：換發程式跑了、失敗了、發告警。這個大家都會做。
2. **「太久沒成功換發」告警（沒有 success）**：換發程式如果因為排程沒被觸發、容器沒起來、cron 壞了而**根本沒跑**，那它連 error 都不會產生。你要對「距離上次成功換發已經超過 N 小時」這件事本身告警。承 Day77：`renewal_success` 要是一個指標，並設「N 小時內沒有成功」的告警——因為「沒有成功」跟「有失敗」是兩件不同的事。

而且——**告警的門檻要跟著效期縮短調整**。以前 90 天憑證，「剩 7 天沒換到」告警很合理；6 天憑證，「剩 7 天」這個門檻根本不會觸發（憑證總共才 6 天）。**憑證 NotAfter 到期預警的門檻，要用「剩餘效期的比例」而不是「固定天數」。**

```bash
# CI / 監控：憑證剩餘效期斷言（承 Day18/78）
# 用比例而非固定天數，適應短效憑證
enddate=$(openssl x509 -enddate -noout -in /etc/tls/live.crt | cut -d= -f2)
end_epoch=$(date -d "$enddate" +%s)
now=$(date +%s)
remaining_hours=$(( (end_epoch - now) / 3600 ))
if [ "$remaining_hours" -lt 24 ]; then
  echo "憑證剩不到 24 小時且尚未換發成功，緊急告警"; exit 1
fi
```

### 憑證 reload：不重啟換上新憑證

換發成功之後，新憑證躺在磁碟上，但你的服務**還握著舊憑證的記憶體副本**。你需要讓服務在**不重啟、不中斷連線**的情況下換上新憑證。重啟服務來換憑證在短效憑證時代是不可接受的——每 2.5 天重啟一次會累死你，也會製造不必要的服務中斷。

**Go**：`tls.Config` 的 `GetCertificate` 回呼是關鍵。**每次握手都會呼叫它**，所以只要你讓它去讀一個「會被換發程式更新的憑證來源」，新握手就自動用新憑證，完全不用重啟。autocert 內建做到這件事；自己管憑證的話，用一個受 mutex 保護、可被換發流程替換的 `*tls.Certificate`：

```go
type certReloader struct {
    mu   sync.RWMutex
    cert *tls.Certificate
}

func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    return r.cert, nil // 每次握手取當前憑證，換發後 reload 即生效
}

func (r *certReloader) reload(certPath, keyPath string) error {
    c, err := tls.LoadX509KeyPair(certPath, keyPath)
    if err != nil {
        return err // 換發後檔案損毀 / 讀不到，保留舊憑證別讓服務裸奔
    }
    r.mu.Lock()
    r.cert = &c
    r.mu.Unlock()
    return nil
}

// tls.Config{ GetCertificate: reloader.GetCertificate }
// 收到 SIGHUP 或 fsnotify 檔案變更事件時呼叫 reloader.reload(...)
```

**Java**：JSSE 的 `KeyManager` 一旦初始化就抓死憑證，沒有「每次握手重讀」的內建鉤子。實務上有幾條路：用**可換底層的自訂 `X509KeyManager` 包裝**（把真正的 KeyManager 放在一個 volatile 參照後面，reload 時整包換掉），或**重建 `SSLContext` 並替換連接器引用的 factory**，或——最常見——**讓前置 LB / cert-manager 去處理 reload，JVM 完全不管**（呼應第六節：躲在 LB 後面的 Java 服務，連 reload 都不用自己做）。核心心法：**reload 失敗時要保留舊憑證繼續服務，而不是換上一個壞檔案然後握手全掛。**

### 單一 CA 依賴：2026-05-08 那場事故告訴我們的事

**2026-05-08，Let's Encrypt 發生簽發中斷。** 對還在用「一年憑證、剩幾週才換」的人來說，這種中斷幾乎無感——他們的憑證還有好幾週，等 Let's Encrypt 恢復再換就好。**但對短效憑證使用者，這是一場預演**：效期越短，你對「CA 隨時可用」的依賴就越硬。6 天憑證每 2.5 天換一次，如果你唯一的 CA 中斷超過那個緩衝，你的憑證就會開始成批過期。

這把一個以前不太需要想的問題推到檯面上：**你的整個 TLS 可用性，外包給了單一一家 CA。** Day78 講 OCSP 時我們嫌「CA 掛你就連不上」，那時是講對方的憑證；現在是講你自己的憑證能不能續命，依賴反轉了但單點還是那個單點。

**backup CA 該不該做？** 這是個要權衡的決策，不是無腦「要」：

- **論據（支持做）**：短效憑證讓 CA 中斷的爆炸半徑變大，多一家備援 CA（例如同時能向 Let's Encrypt 和 ZeroSSL / Google Trust Services 換發）能在主 CA 中斷時切換，把單點消掉。
- **論據（反對／需注意）**：多一家 CA = 多一套帳號金鑰要管（承 Day15）、多一組 CAA 授權要維護（你的 CAA 得同時 `issue` 兩家，這又稍微放寬了 Day77 那把鎖）、多一條要測試的換發路徑（沒測過的 backup 路徑 = Day77「從來沒被驗證過」）。**一個沒演練過的 backup CA，跟沒有 backup 一樣沒用**，甚至更糟，因為它給你虛假的安心。

**務實建議**：對大多數服務，把力氣先花在「**換發緩衝拉大 + 換發失敗告警 + reload 不重啟**」上——這三件事能扛住絕大多數 CA 短暫抖動。只有當你的可用性要求高到「連幾小時的 CA 中斷都不能忍」時，才投資 backup CA，而且**投資了就要定期演練切換**，否則那筆投資是負的。

---

## 八、常見誤區

| 誤區 | 為什麼錯 |
|---|---|
| 「ACME 有續約動作」 | 沒有。換發＝把 order→challenge→finalize 重跑一次，每次都要重新證明控制網域 |
| 「三種 challenge 差不多，隨便選一種」 | 差很多。DNS-01 是 wildcard 唯一選項也是唯一能用於內網服務的，但權限最大（含 CAA） |
| 「DNS-01 比較方便就都用它」 | 它要整個 zone 的寫入權，等於把「能拆掉你 CAA 這把鎖」的鑰匙交出去。能用 HTTP-01/TLS-ALPN-01 就別用 DNS-01 |
| 「CAA 寫了 CA 名就安全了」 | 不夠。攻擊者也能用同一家 CA 開別的帳號。用 RFC 8657 `accounturi`/`validationmethods` 收緊到帳號與方法層級 |
| 「autocert 掛上去就好」 | 不設 `HostPolicy` = 幫任何 SNI 申請憑證直到被限速自我 DoS；預設 `Cache` 在多副本下每台各簽一份撞限制；放 LB 後面 challenge 到不了它 |
| 「Java 沒 autocert 是缺陷」 | 不是。Java 服務更常躲在 LB 後面，TLS 不在 JVM 終結，換發本來就該由 LB/cert-manager 做 |
| 「快到期才換省事」 | 短效憑證時代這是自殺。緩衝＝你能容忍連續換發失敗多久，要盡量大，一拿到就開始換 |
| 「換發沒告警＝一切正常」 | 「從來沒失敗」跟「根本沒在跑」長得一樣。要對「太久沒成功換發」本身告警（承 Day77 偵測器自壞） |
| 「到期預警設固定天數」 | 6 天憑證設「剩 7 天告警」永遠不會觸發。門檻要用剩餘效期比例 |
| 「換憑證重啟一下就好」 | 每 2.5 天重啟一次會累死也造成中斷。要 reload 不重啟，且 reload 失敗保留舊憑證 |
| 「用一家 CA 就夠了」 | 短效憑證讓你對單一 CA 可用性的依賴變硬（2026-05-08 Let's Encrypt 中斷）。但沒演練過的 backup CA 等於沒有 |

---

## 九、Code Review / 維運 checklist

```text
【challenge 選擇與權限】
[ ] 用了哪種 challenge？為什麼？（能 HTTP-01/TLS-ALPN-01 就別 DNS-01）
[ ] 如果用 DNS-01：DNS token 是最小權限嗎？有沒有用 CNAME 委派把爆炸半徑收窄？
[ ] DNS token 的儲存、輪替、寫入 audit 有沒有比照最高機密（承 Day15）？
[ ] 帳號金鑰跟憑證金鑰有沒有分清楚？帳號金鑰有沒有妥善保管？

【CAA（承 Day77）】
[ ] CAA 有沒有設？有沒有綁 accounturi（RFC 8657）到你的實際帳號？
[ ] 有沒有用 validationmethods 限制成你實際在用的那種 challenge？
[ ] CI 有沒有斷言 CAA 存在且參數正確？（DNS 記錄容易在調整時被誤刪）

【autocert / Go（如適用）】
[ ] HostPolicy 有沒有設？（沒設＝幫任何 SNI 申請＝自我 DoS）
[ ] 多副本部署 Cache 有沒有共享？（預設本機 Cache＝每台各簽一份撞限制）
[ ] 服務是自己終結 TLS 還是躲在 LB 後面？（LB 後面 autocert 不適用）

【觸發時機與緩衝】
[ ] 換發是「一拿到就開始嘗試」還是「快到期才換」？
[ ] 換發緩衝（能容忍連續失敗多久）有多大？跟憑證效期是否匹配？
[ ] 到期預警門檻是固定天數還是剩餘效期比例？（短效憑證要用比例）

【告警（承 Day16/77）】
[ ] 換發失敗有告警嗎？（有 error）
[ ] 「太久沒成功換發」有告警嗎？（沒 success——排程沒跑連 error 都沒有）
[ ] renewal_success 有沒有當成指標並設「N 小時沒成功」告警？

【reload 與 CA 依賴】
[ ] 憑證換發後能不重啟 reload 嗎？reload 失敗會不會保留舊憑證？
[ ] 只依賴單一 CA 嗎？可用性要求撐得住一次 CA 中斷（如 2026-05-08）嗎？
[ ] 如果做了 backup CA：有沒有定期演練切換？（沒演練＝沒有）
```

**測試建議：**

- **換發演練（最重要）**：主動把測試環境的憑證逼近到期，驗證自動換發真的會觸發、會成功、會 reload。**「從來沒失敗過」跟「從來沒被驗證過」在儀表板上長得一模一樣**（承 Day77/78）——你必須主動證明它會動。
- **challenge 失敗演練**：故意讓 DNS API 回錯 / 擋掉 80 埠，斷言換發**失敗且告警**，而不是靜默卡住。
- **「太久沒換」告警測試**：故意讓換發排程不觸發（停掉 cron / 刪掉排程），斷言「太久沒成功換發」告警真的會叫。這是換發版的「偵測器存在證明」（承 Day77）。
- **reload 不重啟測試**：換發成功後，斷言**服務沒有重啟**（PID 不變 / 連線沒斷）就換上了新憑證；再故意放一個壞憑證檔，斷言 reload 失敗時**保留舊憑證繼續服務**而非握手全掛。
- **CAA CI 斷言**：`dig +short CAA` 檢查 `accounturi` 與 `validationmethods` 都在（承 Day77/本篇第四節）。
- **限速防呆測試（autocert）**：在測試環境用假 SNI 打服務，斷言 `HostPolicy` 擋掉了不在白名單的網域，而不是傻傻去申請。

---

## 十、一句話總結

> Day78 說「短效憑證讓撤銷問題消失」，代價寫在今天：**拿憑證從一年一次的手動作業，變成每 2.5 天自動跑一次的生產基礎設施，掛幾小時你就掉服務**。ACME（RFC 8555）解的問題只有一句——**讓機器自動證明「我控制這個網域」然後自動拿到憑證**，靠四階段（帳號 → order → challenge → finalize）完成，而且**沒有「續約」這動作，換發就是把後三階段重跑一次，每次都要重新證明控制權**。全部的安全取捨集中在 challenge：**HTTP-01（放檔案，權限窄爆炸半徑小但不能簽 wildcard）、TLS-ALPN-01（443 握手回應，一樣不能 wildcard）、DNS-01（放 TXT，是 wildcard 的唯一選項、也是內網服務唯一能用的，但它要整個 zone 的寫入權——而 DNS 正是 Day77 CAA 那把鎖所在的地方，誰能寫 DNS 誰就能拆掉你的憑證防線）**，所以原則是**能不用 DNS-01 就不用，非用不可就 CNAME 委派把權限收窄**。CAA 本身也該從 Day77 的「哪家 CA」升級到 **RFC 8657 的 `accounturi`＋`validationmethods`——鎖到「哪個帳號、走哪種 challenge」**，幾乎零成本卻擋掉「攻擊者用同一家 CA 開別帳號」。工具面兩件事要記牢：**Go 的 `autocert` 好用但三個坑會把你搞掛（`HostPolicy` 不設＝幫任何 SNI 申請到被限速自我 DoS／預設 `Cache` 在多副本下每台各簽一份撞限制／放 LB 後面 challenge 根本到不了它）；Java 沒有標準庫等價物且這不是缺陷——Java 服務更常躲在 LB 後面 TLS 不在 JVM 終結，換發本來就該交給 cert-manager / 前置 LB，硬要在 JVM 裡做才用 acme4j**。但協定和函式庫都是細節，真正難的是把換發當生產系統經營：**觸發時機要「一拿到就開始換」而非「快到期才換」把緩衝拉到最大；告警要分兩種——換發失敗（有 error）與太久沒成功換發（沒 success，因為排程沒跑連 error 都不會有，這是 Day77 偵測器自壞的老病）；到期預警門檻要用剩餘效期比例而非固定天數（6 天憑證設「剩 7 天告警」永不觸發）；憑證要能 reload 不重啟（Go 靠每次握手都呼叫的 `GetCertificate`，Java 靠可換的 KeyManager 或乾脆交給 LB，且 reload 失敗要保留舊憑證別裸奔）；最後 2026-05-08 Let's Encrypt 簽發中斷是一場預演——效期越短你對單一 CA 可用性的依賴越硬，backup CA 值不值得做取決於你的可用性要求，但沒演練過的 backup 跟沒有一樣**。一句話：撤銷的煩惱沒了，換來的是**你自己的換發管線變成了必須有 on-call 的生產基礎設施**。

---

## 延伸閱讀

- Day78 憑證撤銷：CRL / OCSP / soft-fail / 短效憑證——本篇的上游：短效憑證讓撤銷問題消失，代價就是本篇的換發管線。
- Day77 Certificate Transparency 與 CAA——CAA 這把鎖；本篇用 RFC 8657 把它從「哪家 CA」收緊到「哪個帳號、哪種 challenge」；DNS-01 的權限危險正因為 CAA 也住在 DNS。
- Day76 憑證釘選落地實作——ACME 預設換金鑰＝pin 每次換發失效，第五節「實務衝突」的完整背景在本篇。
- Day75 TLS 憑證驗證與 MITM——reload 錯憑證 / 保留舊憑證的判斷，跟「握手到底信不信對方」是同一組肌肉。
- Day74 mTLS / TLS 握手 DoS——內部服務的 client 憑證換發是下一篇的主場（短效 workload 憑證）。
- Day18 Supply Chain / CI gate——CAA 斷言、憑證效期斷言「讓它在 CI 紅不要在生產紅」。
- Day16 Security Logging / Monitoring——換發失敗告警與「太久沒成功換發」告警；偵測器自壞。
- Day15 Secrets Management——帳號金鑰、DNS API token 的保管與輪替；backup CA 多一套金鑰。
- Day10 SSRF / Day20/67 Open Redirect——HTTP-01 在 80 埠放一個「CA 會主動來連且跟跳轉」的端點的心智模型。
- Day07 授權最小化——CNAME 委派把 DNS-01 的爆炸半徑收窄。

---

明天預告：**Day 80 — 內部服務的身分與短效憑證：SPIFFE / SPIRE 與 workload identity（新主題）**
（今天講的 ACME 是「對外服務向公開 CA 自動換發」，但你的內網服務之間怎麼辦？Day74 講過 mTLS 是內部服務互相驗證身分的手段，Day77 講過內部 CA 是 CT 的盲區——把這兩條線接起來，就是明天的主題：**當你有幾百個微服務要互相 mTLS，你不可能替每個服務手動簽憑證，也不該讓它們共用一張長效憑證**。Day80 要講 **SPIFFE（Secure Production Identity Framework For Everyone）怎麼給每個 workload 一個可驗證的身分（SPIFFE ID＝`spiffe://trust-domain/workload` 這種 URI，塞進憑證的 SAN URI 欄位）**，以及 **SPIRE 這個實作怎麼做「workload 證明」（node attestation＋workload attestation：憑什麼相信「來要憑證的這個程序真的是它宣稱的那個服務」，而不是同一台機器上的惡意程序冒領）**。程式面會示範 **Go 用 `go-spiffe` 的 `workloadapi` 拿 SVID（SPIFFE Verifiable Identity Document）並掛進 `tls.Config` 做雙向驗證，重點是它跟 Day75 標準 TLS client 驗證的差異——比對的不是主機名而是 SPIFFE ID**，以及 **Java 用 `java-spiffe` 的對應做法與它跟 JSSE `TrustManager` 怎麼接**。安全主軸是三件事：**① 短效到極致的憑證（SVID 常常只有幾分鐘到一小時，把 Day78 的撤銷問題徹底變成非問題——短到根本不需要撤銷）、② 身分的根從「網域控制權」換成「workload 證明」（你不再問「你是不是控制 example.com」而是問「你是不是跑在我信任的節點上、你的程序特徵符不符合」）、③ 這是 Day77 內部 CA 盲區的正解——內部 PKI 用 SPIFFE 自動化，比公開 CA 的 ACME 更激進因為你自己就是 CA、效期你說了算**。這是新主題，不重講今天的 ACME/公開 CA 換發，也不重講 Day74 的 mTLS 握手 DoS。）
