---
title: "Day 77：Certificate Transparency 與憑證誤發偵測（新主題）— CT log 三方角色、SCT 怎麼進到憑證裡、CAA 事前預防 vs CT 事後偵測，與後端怎麼把它變成一個會叫的告警"
date: 2026-07-17
tags: ["Certificate Transparency", "CAA", "PKI", "Monitoring"]
---

# Day 77：Certificate Transparency 與憑證誤發偵測

接續 Day76 預告：Day76 的 pinning 是「**事前**把信任收窄到這把金鑰」，代價是綁死自己的輪替節奏——而且 Day76 第六節已經承認，**CDN / 托管 LB 後面的第三方對端，你根本不該 pin**。那問題就來了：

> **不想 pin、或不能 pin 的時候，你怎麼知道有人替你的網域弄到了一張合法憑證？**

今天談另一條路，而且是**完全不同的思路**：不是「收窄我信任誰」，而是「**去查有誰替我簽了憑證**」。

這是新主題。我不會重講 Day75 的憑證驗證（①鏈驗證 AND ②主機名驗證）與 Day76 的 pinning 實作——那兩篇談的是「**我這個 client 連出去時要不要信對方**」；今天談的是「**我這個網域的擁有者，怎麼知道全世界有誰在冒用我**」。**視角從 client 換成網域擁有者**，這是理解今天內容的關鍵。

---

## 一、先講清楚問題：CA 是 PKI 的單點失效

Day75 說「①鏈驗證」就是「這張憑證是不是由我信任的 CA 簽的」。但你的作業系統 / 瀏覽器信任的 CA 有**幾十到上百家**（cacerts 裡那一大包）。這件事的殘酷推論是：

> **任何一家你信任的 CA，都可以簽出一張「你的網域」的合法憑證，而 Day75 的①②會完整通過。**

不是理論。真實事故：

- **DigiNotar（2011）**：荷蘭 CA 被入侵，攻擊者簽出 `*.google.com` 等 500 多張假憑證，被用於伊朗的大規模 MITM。事後 DigiNotar 被所有瀏覽器移除信任並破產。
- **Symantec（2015–2017）**：陸續被發現誤發（含未經網域擁有者同意的測試憑證，例如 google.com 的憑證）。最終 Chrome / Firefox 分階段撤銷對 Symantec 舊根的信任——這件事的推動力，正是 **CT log 讓大家「看得到」誤發到底有多少張**。

**注意這裡的關鍵**：DigiNotar 簽出的假 `*.google.com`，對當時的 client 而言是**完全合法**的憑證。①鏈驗證過（DigiNotar 在信任清單裡）、②主機名驗證過（憑證就是簽給 google.com 的）。**Day75 的兩道驗證，一道都擋不住。**

**Day76 的 pinning 能擋這個**——這正是 Day76 說「pin 不命中反例是 pinning 的存在證明」時模擬的場景。但 pinning 的代價 Day76 也講完了：你得掌握兩端、得跑輪替 SOP、第三方對端還不能 pin。

**CT 是另一個答案，而且方向相反：**

| | Day76 pinning | Day77 CT |
|---|---|---|
| **誰在做這件事** | TLS **client**（連出去的那一端） | **網域擁有者**（你，離線地查） |
| **時機** | 握手當下 | 事後（分鐘～小時級） |
| **效果** | **阻擋**這次連線 | **知道**有這張憑證存在 |
| **代價** | 綁死輪替節奏、可能鎖死自己 | 幾乎為零（只是一個排程查詢） |
| **涵蓋範圍** | 只有「你控制的 client」 | **全世界所有人**看到的憑證 |

最後一列是重點：**pinning 只保護「裝了你的 pin 的那些 client」。** 如果攻擊者拿假憑證去 MITM 你的**使用者**（他們用瀏覽器，不會裝你的 pin），pinning 一點忙都幫不上。**CT 是你唯一能看到那件事的方法。**

---

## 二、CT 的機制：三方角色與「公開帳本」

**Certificate Transparency（RFC 6962）的核心想法只有一句：**

> **讓「CA 簽發了哪些憑證」變成一件公開、可驗證、且**無法事後抹除**的事。**

它不阻止誤發。它**讓誤發藏不住**。

### 三方角色

```text
┌──────────────┐   1. 簽發前把 precertificate 送去 log
│      CA      │ ─────────────────────────────────────┐
└──────────────┘                                      ▼
                                        ┌──────────────────────────┐
                                        │       CT Log Server      │
       2. log 回傳 SCT ◄────────────────│  append-only Merkle Tree │
       （「我收下了，保證 24h 內公開」） │  （只能加，不能改/刪）   │
                                        └──────────────────────────┘
                                                ▲            ▲
                                                │            │
                    3. Monitor 定期拉全部條目   │            │  4. Auditor 驗證 log
                       找「我的網域」            │            │     沒有偷改歷史
                    ┌───────────────────────────┘            └────────────┐
                    │                                                      │
        ┌───────────────────────┐                            ┌─────────────────────────┐
        │       Monitor         │                            │        Auditor          │
        │  ← 這是「你」要扮演的 │                            │ 瀏覽器/研究者/log 之間  │
        │    crt.sh/Cert Spotter│                            │ 用 Merkle proof 交叉稽核│
        └───────────────────────┘                            └─────────────────────────┘
```

- **Log**：一個 **append-only 的 Merkle Tree**。憑證只能加進去，**不能修改、不能刪除**。「append-only」不是靠承諾，是靠密碼學——任何人都能用 Merkle proof 驗證「你現在給我看的樹，包含了你上次給我看的樹」。log 想偷偷抽掉一筆，數學上會被抓到。
- **Monitor**：定期拉 log 的內容，找出「跟我有關」的憑證。**這就是你今天要做的事。**
- **Auditor**：驗證 log 沒有食言（送出 SCT 卻沒公開、或偷改歷史）。這件事通常由瀏覽器與研究者做，**後端工程師一般不需要自己扮演 auditor**。

### SCT：憑證怎麼「證明自己被 log 過」

**SCT（Signed Certificate Timestamp）= log 給 CA 的一張收據**，內容是「我在時間 T 收下了這張憑證，並承諾在 MMD（Maximum Merge Delay，通常 24 小時）內把它公開」，由 log 的私鑰簽名。

**Chrome 與 Apple 平台都要求**：公開信任 CA 簽發的憑證必須附上足夠數量的 SCT（來自不同 log 營運者），否則**直接拒絕連線**。這就是 CT 的執行力來源——**不是規定 CA 要 log，而是「沒 log 的憑證瀏覽器不收」**。

SCT 有三種送達 client 的方式：

| 方式 | 怎麼運作 | 特點 |
|---|---|---|
| **A. 嵌在憑證裡**（X.509 extension，OID `1.3.6.1.4.1.11129.2.4.2`） | CA 簽發時就把 SCT 寫進憑證 | **最常見**。server 端**零設定**（憑證裡本來就有） |
| **B. TLS 握手擴充** | server 在握手時另外送 SCT | server 要支援；憑證不必改 |
| **C. OCSP stapling** | SCT 夾在 stapled OCSP response 裡 | server 要開 stapling |

**A 有一個「先有雞還是先有蛋」的問題，值得停一下**：SCT 要嵌進憑證裡，但 SCT 是 log 對「憑證內容」的簽名——**憑證還沒簽出來，怎麼送去 log？**

解法是 **precertificate（預憑證）**：CA 先簽一張「內容跟正式憑證一樣、但多帶一個 **poison extension**（critical，OID `1.3.6.1.4.1.11129.2.4.3`）」的東西送去 log。這個 poison extension 是 **critical 且沒有任何 client 認得**——所以**任何 TLS client 拿到它都必定拒絕**（critical extension 不認得就必須 reject，這是 X.509 的規則）。它進得了 log，卻**永遠不能拿來當憑證用**。log 回傳 SCT 後，CA 把 SCT 塞進正式憑證再簽一次。

> **這個設計細節對你的實務有直接影響**：CT log 裡**同一張憑證會出現兩次**（precert 一次、正式憑證一次）。你寫 monitor 時**必須去重**，否則每張憑證都告警兩次。第四節的程式碼會處理這件事。

**後端工程師的實務結論**：SCT 這一整套是 **CA 與瀏覽器之間的事**，你**幾乎不用做任何事**——你的憑證（只要來自公開 CA）裡本來就有 SCT。**你要做的只有一件事：當 monitor，去查 log。** 這節的機制講到這裡就夠了，下面全部是你真的要動手的部分。

---

## 三、CT 是事後偵測，CAA 是事前預防 —— 兩件事都要做

這是今天最重要的一組對照。**很多人把 CT 當成「防誤發」的方案，那是誤解。**

> **CT 不阻止任何事。它只讓你「知道」。**

如果你想**事前**降低誤發機率，那是另一個機制：**CAA record**。

### CAA：在 DNS 裡宣告「只有這幾家 CA 能簽我的網域」

**CAA（Certification Authority Authorization，RFC 8659）是一種 DNS 記錄**，語意是：

```dns
; 只有 Let's Encrypt 能簽 example.com
example.com.    IN  CAA 0 issue "letsencrypt.org"

; 只有 Amazon 能簽萬用字元憑證（issuewild 覆蓋 issue 對萬用字元的效果）
example.com.    IN  CAA 0 issuewild "amazon.com"

; 有 CA 收到不符 CAA 的請求時，通報這個信箱
example.com.    IN  CAA 0 iodef "mailto:security@example.com"

; 明確禁止任何人簽（沒有任何 CA 被授權）
example.com.    IN  CAA 0 issue ";"
```

- **flag `0`**：非 critical。`128` 代表 critical（CA 不認得這個 tag 就必須拒絕簽發）。
- **`issue`**：授權某家 CA 簽發一般憑證。
- **`issuewild`**：授權某家 CA 簽發萬用字元憑證。**注意：只要存在任何 `issuewild`，它就完全接管萬用字元的授權，`issue` 對萬用字元不再有效。**
- **`iodef`**：CA 發現違規請求時的通報管道。
- **值 `;`**：代表「**沒有任何 CA 被授權**」。

**執行力來源**：CA/Browser Forum 從 2017 年 9 月起**強制要求所有公開信任的 CA 在簽發前檢查 CAA**。不檢查 = 違反 Baseline Requirements = 有被踢出根憑證計畫的風險。

**查詢方式（你的 CI 就用這個）：**

```bash
dig CAA example.com +short
# 0 issue "letsencrypt.org"
# 0 iodef "mailto:security@example.com"
```

**CAA 的樹狀爬升**：CA 要簽 `api.staging.example.com` 時，會依序查 `api.staging.example.com` → `staging.example.com` → `example.com`，**取第一個「找得到 CAA 記錄」的層級為準**，找到就停。這代表：

> **你只要在 apex（`example.com`）設一組 CAA，整棵子網域樹都受保護**——除非某個子網域自己設了 CAA 把它蓋掉。

**這個「蓋掉」是最常見的自我 DoS**：某團隊在 `staging.example.com` 設了 `0 issue "letsencrypt.org"`，結果 `api.staging.example.com` 要用另一家 CA 的自動換發**全部簽不出來**——而且錯誤訊息通常只說「CAA 檢查失敗」，查半天。**設 CAA 前先想清楚你的子網域有幾條簽發管線。**

### 兩者的界線在哪裡：CAA 只約束「守規矩的 CA」

**這是關鍵，也是為什麼兩個都要做：**

```text
攻擊者拿到你網域憑證的兩條路：

路徑 A：向合法 CA 提出簽發請求（騙過網域驗證 / 走社交工程 / 內部人員）
        → CAA 擋得住（CA 會查 CAA，不在授權名單就拒簽）   ← 事前預防有效
        → 但如果他選的正好是你 CAA 授權的那家 CA，還是簽得出來

路徑 B：CA 本身被入侵 / 內部作惡 / 流程出包（DigiNotar 模式）
        → CAA 完全無效（CAA 是「請 CA 自己檢查自己」，
                        一個被入侵的 CA 不會為難自己）      ← 事前預防失效
        → 但憑證仍必須進 CT log（否則 Chrome/Apple 不收）
        → CT 抓得到                                          ← 事後偵測是唯一防線
```

**一句話總結兩者的分工：**

> **CAA 靠的是「CA 願意遵守規則」；CT 靠的是「憑證想被瀏覽器接受，就必須公開」。前者防君子，後者防小人——所以兩個都要。**

再說直白一點：**CAA 是門鎖，CT 是監視器。** 門鎖擋掉大部分隨手推門的人，但對付撬鎖的人，你需要的是「知道有人進來過」。**沒有人會因為裝了門鎖就拆掉監視器。**

---

## 四、Go 實作：定期拉 crt.sh，比對白名單，發現未知簽發者就告警

現在做正事。**你要當 monitor。**

### 選擇資料來源

自己跑一個 CT log monitor（直接對接 RFC 6962 的 `get-entries` API 拉全世界所有憑證）是**大工程**——每天數百萬筆，你要自己存、自己索引。**絕大多數後端團隊不該這樣做。**

務實的選項：

| 方式 | 說明 | 適合 |
|---|---|---|
| **crt.sh 的 JSON 介面** | Sectigo 營運的公開 CT 搜尋服務，有非官方 JSON 輸出 | **快速起步**、內部工具。但**它是免費公共服務**：無 SLA、會限速、格式可能變 |
| **Cert Spotter API**（SSLMate） | 有正式文件的 API，免費額度 + 付費方案 | 要穩定性與正式支援時 |
| **商用 CT 監控 / CA 附帶的監控** | 各家安全廠商、部分 CA 提供 | 有預算、要 SLA |
| **自建 monitor**（`get-entries`） | 直接對接 log | 有規模、有專職團隊 |

**下面用 crt.sh 示範**，因為它最容易起步、能讓你今天就跑起來。但請把它當**起點**：

> **crt.sh 是別人的免費服務，不是你的 SLA。** 上生產前務必：加 timeout、加 rate limit、失敗時**告警而非靜默**（見下方程式碼），並認真評估換成有 SLA 的來源。而且——**「monitor 掛了」跟「沒有誤發」在你的儀表板上長得一模一樣**，這是本節最後會回頭處理的坑。

crt.sh 的查詢長這樣：

```bash
# %25 是 % 的 URL 編碼，%.example.com 代表所有子網域
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | head -c 500
```

回傳是一個 JSON 陣列，每筆大致是：

```json
{
  "issuer_ca_id": 183267,
  "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
  "common_name": "api.example.com",
  "name_value": "api.example.com\nexample.com",
  "id": 9876543210,
  "entry_timestamp": "2026-07-16T03:12:45.123",
  "not_before": "2026-07-16T02:12:44",
  "not_after": "2026-10-14T02:12:43",
  "serial_number": "03a1b2c3..."
}
```

> **這個 JSON 輸出是 crt.sh 的非官方便利介面，欄位可能隨時變動。** 你的程式必須對「欄位不存在 / 型別不同 / 回傳不是 JSON」有防禦，並且**解析失敗要告警**（那代表你的 monitor 瞎了）。

### 完整範例

```go
package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// crtShEntry：只宣告我們用得到的欄位。
// 刻意不全部映射 —— crt.sh 的 JSON 是非官方介面，多映射一個欄位就多一個會壞的地方。
type crtShEntry struct {
	ID           int64  `json:"id"`
	IssuerCAID   int64  `json:"issuer_ca_id"`
	IssuerName   string `json:"issuer_name"`
	CommonName   string `json:"common_name"`
	NameValue    string `json:"name_value"` // 多個 SAN 用 \n 分隔
	SerialNumber string `json:"serial_number"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
}

// Policy：什麼是「預期中的憑證」。從組態載入，不硬編（同 Day76 pin set 的理由）。
type Policy struct {
	Domain string
	// AllowedIssuers：允許的簽發者比對片段（對 issuer_name 做子字串比對）。
	// 用「片段」而非完整字串，因為 CA 的中繼名稱會換（R3 → R10 → R11...），
	// 綁死完整字串等於每次 CA 換中繼你就誤報一輪。
	AllowedIssuers []string
	// KnownSPKIPins：已知憑證的 SPKI pin（Day76 的格式，可直接沿用同一份組態）。
	KnownSPKIPins map[string]struct{}
}

// fetchCrtSh 拉取某網域近期的 CT 憑證條目。
func fetchCrtSh(ctx context.Context, client *http.Client, domain string) ([]crtShEntry, error) {
	// %.<domain> 涵蓋所有子網域；URL 編碼交給 url.Values，別自己拼（承 Day67/68：手拼 URL 是破口）
	q := url.Values{}
	q.Set("q", "%."+domain)
	q.Set("output", "json")
	endpoint := "https://crt.sh/?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	// 對公共服務要有基本禮貌：表明身分，方便對方在你打爆他們時聯絡你而不是直接封鎖
	req.Header.Set("User-Agent", "example-ct-monitor/1.0 (security@example.com)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ct monitor: 查詢 crt.sh 失敗: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ct monitor: crt.sh 回應 %d（限速？服務異常？）", resp.StatusCode)
	}

	// 限制讀取大小：對方回什麼你不能假設（承 Day71 的哲學：外部輸入永遠要有上限）
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // 32MB
	if err != nil {
		return nil, err
	}

	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		// 解析失敗 = 你的 monitor 瞎了，這本身就是一個事件，不能靜默
		return nil, fmt.Errorf("ct monitor: 解析 crt.sh JSON 失敗（介面變了？）: %w", err)
	}
	return entries, nil
}

// spkiPinFromCert：與 Day76 完全相同的計算方式，讓兩邊的白名單可以共用同一份組態。
func spkiPinFromCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// fetchSPKIPin：crt.sh 的 JSON 不含公鑰，要另外抓 PEM（?d=<id>）才能算 SPKI。
// 只對「issuer 白名單沒過」的少數條目做，別對每一筆都打一次（會被限速）。
func fetchSPKIPin(ctx context.Context, client *http.Client, id int64) (string, error) {
	endpoint := fmt.Sprintf("https://crt.sh/?d=%d", id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "example-ct-monitor/1.0 (security@example.com)")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", fmt.Errorf("ct monitor: crt.sh 回傳的不是 PEM（id=%d）", id)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return spkiPinFromCert(cert), nil
}

func issuerAllowed(issuerName string, allowed []string) bool {
	for _, frag := range allowed {
		if strings.Contains(issuerName, frag) {
			return true
		}
	}
	return false
}

// Finding：一筆需要人看的發現。
type Finding struct {
	Entry  crtShEntry
	Reason string
}

// Audit：核心邏輯。回傳「需要人看」的條目。
func Audit(ctx context.Context, client *http.Client, p Policy) ([]Finding, error) {
	entries, err := fetchCrtSh(ctx, client, p.Domain)
	if err != nil {
		return nil, err // 上層要把這個當事件告警，不是當「沒事」
	}

	// ★ 去重：同一張憑證在 CT log 裡會有 precertificate 與正式憑證兩筆（見第二節）。
	//   不去重 = 每張憑證告警兩次 = 兩倍雜訊 = 大家開始無視告警。
	//   serial + issuer 是同一張憑證的穩定識別（單一 CA 內 serial 不重複）。
	seen := make(map[string]struct{}, len(entries))
	var findings []Finding

	for _, e := range entries {
		key := e.IssuerName + "|" + e.SerialNumber
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		// 第一關（便宜）：issuer 是不是我們認識的 CA？
		// 絕大多數條目會在這裡通過，不必再打一次 crt.sh。
		if issuerAllowed(e.IssuerName, p.AllowedIssuers) {
			continue
		}

		// 第二關（貴）：issuer 不認識，才去抓 PEM 算 SPKI。
		// 為什麼還要這關？因為「你自己換了 CA 但忘了更新白名單」跟「有人誤發」在第一關長得一樣。
		// SPKI 命中 = 這是你自己的金鑰簽出來的憑證 = 白名單過期，不是資安事件。
		pin, perr := fetchSPKIPin(ctx, client, e.ID)
		if perr != nil {
			// 抓不到 PEM 不能當「沒事」，要當「查不出來」報出去
			findings = append(findings, Finding{Entry: e, Reason: "未知簽發者，且無法取得憑證內容驗證: " + perr.Error()})
			continue
		}
		if _, known := p.KnownSPKIPins[pin]; known {
			// 金鑰是我們的，但 issuer 不在名單 —— 通常是「換了 CA / CA 換了中繼但沒更新組態」
			findings = append(findings, Finding{
				Entry:  e,
				Reason: "SPKI 是已知金鑰，但簽發者不在白名單（換 CA 沒更新組態？）→ 營運事故，非資安事件",
			})
			continue
		}

		// 未知 issuer + 未知金鑰 = 你完全不認得這張憑證 = 資安事件，立刻升級
		findings = append(findings, Finding{
			Entry:  e,
			Reason: "未知簽發者且 SPKI 不在已知金鑰清單 —— 疑似憑證誤發，立即人工調查",
		})
	}
	return findings, nil
}

func main() {
	client := &http.Client{Timeout: 30 * time.Second} // 承 Day72：對外呼叫一律設 timeout

	p := Policy{
		Domain:         "example.com",
		AllowedIssuers: []string{"Let's Encrypt", "Amazon"}, // 從組態來
		KnownSPKIPins: map[string]struct{}{
			"YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=": {}, // 可與 Day76 的 pin set 共用同一份組態
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	findings, err := Audit(ctx, client, p)
	if err != nil {
		// ★ 最重要的一行：monitor 自己失敗，必須告警（承 Day16）。
		//   「查詢失敗」與「沒有誤發」在儀表板上長得一樣 —— 這是 CT 監控最大的坑，見第六節。
		fmt.Println("ALERT ct_monitor_error:", err)
		return
	}
	for _, f := range findings {
		// 告警內容夠人判斷即可，別把整張憑證倒進 log（承 Day16）
		fmt.Printf("ALERT ct_unexpected_cert domain=%s cn=%s issuer=%q serial=%s notAfter=%s reason=%s\n",
			p.Domain, f.Entry.CommonName, f.Entry.IssuerName, f.Entry.SerialNumber, f.Entry.NotAfter, f.Reason)
	}
	fmt.Printf("ct_monitor_ok domain=%s findings=%d\n", p.Domain, len(findings))
}
```

**這段程式碼的幾個設計決策值得講：**

- **兩關式比對（issuer 便宜、SPKI 貴）**：99% 的條目是你自己的 ACME 換發，第一關就過了。只有少數異常才付「抓 PEM」的成本。**這不只是效能——它也是對 crt.sh 這個免費服務的基本尊重。**
- **issuer 用「片段包含」而非完整字串比對**：CA 的中繼憑證名稱會換（Let's Encrypt 的 `R3` → `R10` → `R11`…）。比對完整 issuer name = **每次 CA 換中繼你就收到一輪假警報**，兩次之後大家就會開始無視這個告警。
- **SPKI 那一關把「營運事故」與「資安事件」分開**——這正是 Day76 說 pin 不命中告警要能區分的同一件事。**分不開的告警 = 會被無視的告警。**
- **`fetchSPKIPin` 用的是 Day76 完全相同的 `RawSubjectPublicKeyInfo` 計算**，所以 pin set 那份組態可以直接共用。**兩套機制共用一份「我認得的金鑰」清單**是很划算的整合。
- **查詢失敗必須告警**，不能 `return nil, nil` 混過去（見第六節）。

---

## 五、Java 實作：排程任務 + CI 的 CAA 斷言

### Java 排程 monitor

```java
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

/**
 * CtMonitor：定期查 CT log，找出「不是我們簽的」憑證。
 *
 * 定位（承 Day76）：這不是 client 端防禦，pinning 才是。
 * 這是「網域擁有者」的偵測面 —— 它不擋任何連線，它只讓你知道。
 */
public final class CtMonitor {

    private final HttpClient http;
    private final String domain;
    private final List<String> allowedIssuerFragments; // 片段比對，理由同 Go 版
    private final Set<String> knownSpkiPins;           // 可與 Day76 pin set 共用組態

    public CtMonitor(String domain, List<String> allowedIssuerFragments, Set<String> knownSpkiPins) {
        this.domain = Objects.requireNonNull(domain);
        this.allowedIssuerFragments = List.copyOf(allowedIssuerFragments);
        this.knownSpkiPins = Set.copyOf(knownSpkiPins);
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10)) // 承 Day72
                .followRedirects(HttpClient.Redirect.NEVER) // 承 Day10：對外呼叫別自動跟 redirect
                .build();
    }

    /** 拉 crt.sh JSON。用你既有的 JSON 函式庫解析（Jackson/Gson 皆可，此處只示意流程）。 */
    private String fetchCrtShJson() throws Exception {
        String q = URLEncoder.encode("%." + domain, StandardCharsets.UTF_8);
        URI uri = URI.create("https://crt.sh/?q=" + q + "&output=json");

        HttpRequest req = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(30))
                .header("User-Agent", "example-ct-monitor/1.0 (security@example.com)")
                .GET()
                .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            // 失敗要往上丟 → 上層告警。絕不能 catch 掉當作「今天沒事」
            throw new IllegalStateException("crt.sh 回應 " + resp.statusCode() + "（限速？）");
        }
        return resp.body();
    }

    /**
     * audit：核心流程（與 Go 版相同的三步）。
     *   1. 去重（precert + 正式憑證會各一筆，見第二節）
     *   2. issuer 片段白名單 → 便宜的第一關
     *   3. issuer 沒過才抓 PEM 算 SPKI → 區分「換 CA 沒更新組態」與「真的誤發」
     */
    public List<String> audit() throws Exception {
        String json = fetchCrtShJson();
        List<Entry> entries = parseEntries(json); // 用 Jackson: mapper.readValue(json, new TypeReference<List<Entry>>(){})

        Set<String> seen = new HashSet<>();
        List<String> findings = new ArrayList<>();

        for (Entry e : entries) {
            String key = e.issuerName + "|" + e.serialNumber;
            if (!seen.add(key)) {
                continue; // 去重
            }
            if (issuerAllowed(e.issuerName)) {
                continue;
            }
            String pin = fetchSpkiPin(e.id); // GET https://crt.sh/?d=<id> → PEM → CertificateFactory → SPKI
            if (knownSpkiPins.contains(pin)) {
                findings.add("營運事故：SPKI 已知但簽發者不在白名單（換 CA 沒更新組態？）cn=" + e.commonName
                        + " issuer=" + e.issuerName);
            } else {
                findings.add("資安事件：未知簽發者且未知金鑰，疑似誤發 cn=" + e.commonName
                        + " issuer=" + e.issuerName + " serial=" + e.serialNumber);
            }
        }
        return findings;
    }

    private boolean issuerAllowed(String issuerName) {
        for (String frag : allowedIssuerFragments) {
            if (issuerName.contains(frag)) return true;
        }
        return false;
    }

    /** 從 crt.sh 抓 PEM 算 SPKI pin —— 與 Day76 的 getPublicKey().getEncoded() 完全相同的計算。 */
    private String fetchSpkiPin(long id) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create("https://crt.sh/?d=" + id))
                .timeout(Duration.ofSeconds(20))
                .header("User-Agent", "example-ct-monitor/1.0 (security@example.com)")
                .GET().build();
        String pem = http.send(req, HttpResponse.BodyHandlers.ofString()).body();

        var cf = java.security.cert.CertificateFactory.getInstance("X.509");
        var cert = (java.security.cert.X509Certificate) cf.generateCertificate(
                new java.io.ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));

        byte[] spki = cert.getPublicKey().getEncoded(); // 對 X.509 就是 SubjectPublicKeyInfo 的 DER（承 Day76）
        byte[] sum = java.security.MessageDigest.getInstance("SHA-256").digest(spki);
        return Base64.getEncoder().encodeToString(sum);
    }

    record Entry(long id, String issuerName, String commonName, String serialNumber, String notAfter) {}

    private List<Entry> parseEntries(String json) { /* Jackson/Gson 映射，欄位名見第四節 */ return List.of(); }
}
```

**排程起來（Spring 或純 JDK 皆可）：**

```java
// Spring：@Scheduled(cron = "0 0 * * * *")  每小時
// 純 JDK：
ScheduledExecutorService ses = Executors.newSingleThreadScheduledExecutor();
ses.scheduleAtFixedRate(() -> {
    try {
        List<String> findings = monitor.audit();
        for (String f : findings) {
            log.error("ct_unexpected_cert {}", f); // 承 Day16：這條要進告警規則
        }
        metrics.counter("ct_monitor_success").increment(); // ★ 見第六節：成功也要記
    } catch (Exception e) {
        // ★ monitor 自己壞掉，是一個必須告警的事件，不是一個可以吞掉的例外
        log.error("ct_monitor_error", e);
        metrics.counter("ct_monitor_error").increment();
    }
}, 0, 1, TimeUnit.HOURS);
```

> **Java 1.8 提醒**：`java.net.http.HttpClient` 是 Java 11+。1.8 請改用 `HttpsURLConnection` 或你既有的 HTTP 函式庫（**記得 Day75：別關掉憑證驗證**——你是在查誰誤發憑證，結果自己連 crt.sh 時 `InsecureSkipVerify` 掉了，那就太諷刺了）。`record` 是 16+，1.8 用普通 class。
>
> **版本提醒**：`java.net.http.HttpClient` 的 API 與行為、`CertificateFactory` 的 provider 細節隨 JDK 版本演進，上線前以你實際使用的 JDK 版本官方文件確認。crt.sh 的 JSON 介面則是**非官方**的，隨時可能改。

### CI 的 CAA 斷言（這才是第三節的落地）

**CT monitor 是偵測。CAA 是預防。預防的東西要有人守著它不被拿掉**——DNS 記錄是很容易在某次「調整 DNS」時被誤刪的。

```bash
#!/usr/bin/env bash
# ci/check-caa.sh —— 斷言 CAA 存在且內容符合預期。
# 放進 CI 定期跑（承 Day18 的 CI gate 哲學：讓它在 CI 紅，而不是在生產紅）。
set -euo pipefail

DOMAIN="example.com"
EXPECTED_ISSUERS=("letsencrypt.org" "amazon.com")

CAA_OUT="$(dig +short CAA "$DOMAIN")"

if [[ -z "$CAA_OUT" ]]; then
  echo "FAIL: $DOMAIN 沒有 CAA 記錄 —— 任何 CA 都能簽發你的網域"
  exit 1
fi

echo "$DOMAIN CAA:"
echo "$CAA_OUT"

# 1) 每一個預期的 CA 都在
for issuer in "${EXPECTED_ISSUERS[@]}"; do
  if ! grep -q "issue.*\"$issuer\"" <<<"$CAA_OUT"; then
    echo "FAIL: CAA 缺少預期的簽發者 $issuer —— 這家 CA 的自動換發會失敗"
    exit 1
  fi
done

# 2) 沒有預期外的 CA 被授權（有人偷加？誤加？）
while read -r _flag tag value; do
  [[ "$tag" == "issue" || "$tag" == "issuewild" ]] || continue
  clean="${value//\"/}"
  [[ "$clean" == ";" ]] && continue  # ";" = 不授權任何人，合法
  # 去掉 RFC 8657 的參數（例如 letsencrypt.org;accounturi=...）
  ca="${clean%%;*}"
  found=0
  for issuer in "${EXPECTED_ISSUERS[@]}"; do
    [[ "$ca" == "$issuer" ]] && found=1
  done
  if [[ $found -eq 0 ]]; then
    echo "FAIL: CAA 授權了預期外的 CA: $ca"
    exit 1
  fi
done <<<"$CAA_OUT"

# 3) iodef 存在（CA 發現違規請求時才知道要通報誰）
if ! grep -q "iodef" <<<"$CAA_OUT"; then
  echo "WARN: 沒有設 iodef —— CA 擋下違規簽發請求時，沒有管道通知你"
fi

echo "OK: $DOMAIN 的 CAA 符合預期"
```

**注意這個 script 檢查的是「雙向」：既要有你要的 CA，也不能有你沒預期的 CA。** 只檢查前者的話，別人偷偷加一行 `0 issue "some-other-ca.example"` 你不會知道——**而那正好是把 CAA 這道鎖打開的方法**。

---

## 六、雜訊治理：這是 CT 監控成敗的關鍵

**技術上，CT monitor 只是一個排程 HTTP 查詢。真正的難點跟 Day76 一樣不在程式碼——是「這個告警會不會被無視」。**

**你的網域每 60 天就會有一批新憑證（ACME 自動換發），CT log 裡全都看得到。如果你 naive 地「有新憑證就告警」，第一週你就會關掉它。**

### 五個雜訊來源與處理

| 雜訊來源 | 為什麼會叫 | 怎麼治 |
|---|---|---|
| **自家 ACME 自動換發** | 每 60~90 天每個網域一批，量最大 | issuer 白名單（第一關就過濾掉）+ SPKI 已知金鑰清單 |
| **precert + 正式憑證雙筆** | CT 機制使然（第二節） | **用 serial + issuer 去重**。不做的話**雜訊直接乘二** |
| **子網域萬用憑證** | `*.example.com` 會在 `%.example.com` 的查詢裡出現，且涵蓋你沒列舉的子網域 | 白名單以 **issuer + SPKI** 為主，別用「網域字串精確比對」——萬用憑證的 CN 跟你的子網域清單本來就對不起來 |
| **CDN / 托管服務代簽** | 你放 Cloudflare/AWS/Fastly 後面，**他們會用自己的帳號幫你簽憑證**，issuer 是他們選的 CA，換發節奏你管不到 | 把服務商用的 CA 加進 issuer 白名單。**這正是 Day76 說「CDN 後面的對端別 pin」的同一個現象**——你不掌握那些憑證 |
| **內部 CA 的憑證不在 CT 裡** | **這是盲區，不是雜訊** | 見下 |

### 最重要的盲區：CT 看不到內部 CA

> **CT 只涵蓋「公開信任 CA」簽發的憑證。你自己的內部 CA（Day75 教你加進 truststore 的那個）簽的東西，一張都不會出現在 CT log 裡。**

原因很單純：CT 的執行力來自「Chrome/Apple 不收沒有 SCT 的憑證」，而**內部 CA 本來就不在瀏覽器的根憑證計畫裡**，這個壓力對它不存在。它想簽什麼就簽什麼，沒有人會知道。

**這代表：**

- **你的內部 PKI 完全沒有 CT 這層保護。** 內部 CA 被入侵 = 內部所有服務可被 MITM，而且**沒有任何公開帳本會記錄這件事**。
- **內部 PKI 的對應解法是 Day76 的 pinning**（你掌握兩端、你控制輪替節奏——這正是 Day76 說 backend-to-backend pinning 可行的場景），加上內部 CA 自己的簽發稽核日誌（承 Day16）。
- **不要把「CT 沒告警」讀成「沒有人在冒充我的服務」。** CT 的涵蓋範圍是「公開 CA」，不是「全世界」。

**這是 CT 與 pinning 真正的分工**，也是為什麼 Day76 與 Day77 是一組而不是二選一：

```text
              對外服務（公開 CA 簽）      內部服務（內部 CA 簽）
              ─────────────────────      ─────────────────────
  事前預防      CAA（限制哪家 CA）         內部 CA 簽發流程管控
  事後偵測      CT monitor  ← 今天         ✗ CT 看不到（盲區）
  連線阻擋      pinning（若可行）          pinning ← Day76 的主場
```

### 「monitor 掛了」跟「沒有誤發」長得一模一樣

**這是所有偵測型控制的通病，也是本篇最容易被跳過的一節。** 你的 CT monitor 因為 crt.sh 限速而連續失敗三個月，儀表板上跟「這三個月很平安」**完全一樣安靜**。

**所以：**

- **`ct_monitor_error` 要有指標與告警**（第四、五節的程式碼都刻意把「查詢失敗」當事件往上報）。
- **`ct_monitor_success` 也要有指標**，並且設定「**N 小時內沒有成功執行**」的告警。**「沒有成功」跟「有失敗」是兩件事**——process 沒被排到、容器沒起來，連 error 都不會有。
- **定期做一次「陽性測試」**：讓 monitor 對一個**你知道一定有憑證、但不在你白名單裡**的網域跑一次，斷言它**確實會告警**。**這是 monitor 的存在證明**——完全等同於 Day76 說的「pin 不命中反例是 pinning 的存在證明」。沒有這條，你不知道你的 monitor 是在守夜還是在睡覺。

---

## 七、常見誤區（reject list）

| 誤區 | 為什麼錯 |
|---|---|
| 「上了 CT，誤發就不會發生」 | **CT 不阻止任何事**，它只讓誤發藏不住。它是監視器不是門鎖 |
| 「設了 CAA 就不會被誤發」 | CAA 只約束**願意遵守規則的 CA**。CA 被入侵（DigiNotar 模式）時 CAA 完全無效 |
| 「CT 和 CAA 二選一就好」 | 一個是事後偵測、一個是事前預防，**擋的是不同路徑**（第三節）。門鎖跟監視器沒有人只裝一個 |
| 「pinning 做了就不用 CT」 | pinning 只保護「裝了你 pin 的 client」。攻擊者拿假憑證 MITM 你的**使用者**（他們用瀏覽器），pinning 看不到也擋不到 |
| 「CT 沒告警 = 沒人冒充我」 | **內部 CA 簽的憑證不在 CT 裡**。CT 的涵蓋範圍是「公開 CA」不是「全世界」 |
| 「有新憑證就告警」 | 你自己的 ACME 每 60 天換一批，第一週你就會關掉這個告警。**雜訊治理是主線工作不是加分題** |
| 「crt.sh 查得到就好，寫個 cron 打就行」 | 那是別人的免費服務：無 SLA、會限速、格式會變。要有 timeout、要限速、**失敗要告警** |
| 「issuer 用完整字串比對最精確」 | CA 會換中繼（R3→R10→R11…），比完整字串 = 每次換中繼就一輪假警報 → 大家開始無視 |
| 「查詢失敗就 skip，下次再查」 | 「monitor 掛了」跟「沒有誤發」在儀表板上長得一樣。**要有 success 指標 + 「N 小時沒成功」的告警** |
| 「CT log 一筆一張憑證」 | **precert 與正式憑證各一筆**。不去重 = 雜訊乘二 |
| 「SCT 要我 server 端設定」 | 公開 CA 簽發時就把 SCT 嵌進憑證了（方式 A），**你什麼都不用做**。你要做的是當 monitor |
| 「在每個子網域都設一組 CAA 比較安全」 | CAA 是**取第一個找得到的層級就停**。子網域設了會**蓋掉** apex 的設定，最常見的自我 DoS 是子網域的 CA 簽不出來 |
| 「發現誤發憑證，撤銷掉就沒事了」 | 撤銷這件事本身遠比你想的不可靠——**這是明天的主題** |

---

## 八、後端 Code Review / 維運 checklist

```text
【CAA：事前預防】
[ ] apex 網域是否有 CAA 記錄？（沒有 = 任何公開 CA 都能簽你的網域）
[ ] CAA 是否涵蓋「所有你實際在用的簽發管線」？（含 CDN/托管服務代簽的那家 CA）
[ ] 是否有子網域自己設了 CAA 而蓋掉 apex？該子網域的簽發管線是否仍可運作？
[ ] 萬用字元憑證是否需要 issuewild？（有 issuewild 就完全接管萬用字元授權）
[ ] 是否設了 iodef？（CA 擋下違規請求時的通知管道）
[ ] CI 是否有 dig CAA 斷言？是否同時檢查「該有的在」與「不該有的不在」？

【CT monitor：事後偵測】
[ ] 是否有排程任務定期查自家網域（含子網域 %.example.com）？
[ ] 資料來源是否評估過 SLA？（crt.sh 是免費公共服務，適合起步不適合當唯一依賴）
[ ] 對外查詢是否有 timeout（承 Day72）、是否有 User-Agent、是否自我限速？
[ ] 是否對 precert + 正式憑證去重（serial + issuer）？
[ ] issuer 白名單是否用「片段比對」而非完整字串？（CA 會換中繼）
[ ] 是否有第二關 SPKI 比對，把「換 CA 沒更新組態」與「真的誤發」分開？
[ ] 白名單/組態是否可不重新編譯就更新（同 Day76 pin set），且寫入權限受控 + 變更告警？

【告警品質（承 Day16）】
[ ] 告警是否能區分「營運事故（換 CA/中繼）」與「資安事件（未知金鑰）」？
[ ] ct_monitor_error 是否有指標與告警？（查詢失敗 = monitor 瞎了）
[ ] ct_monitor_success 是否有指標，且設了「N 小時內沒有成功執行」的告警？
[ ] 是否定期做陽性測試（對已知會命中的目標跑一次，斷言真的會叫）？
[ ] 告警內容是否足以人工判斷（CN/issuer/serial/notAfter）且不倒整張憑證進 log？

【範圍認知】
[ ] 團隊是否知道「內部 CA 簽的憑證不在 CT 裡」＝ CT 的盲區？
[ ] 內部 PKI 是否有對應的偵測（簽發稽核日誌）與阻擋（Day76 pinning）？
[ ] 是否知道 CT 只偵測不阻擋 —— 有沒有想過「真的告警了，下一步做什麼」？
```

**測試建議：**

- **陽性測試（monitor 的存在證明）**：對一個「一定有憑證、但 issuer 不在你白名單」的目標跑一次 audit，斷言 **findings 非空**。**這條不過，你的 monitor 就是在睡覺。**
- **去重測試**：餵一份包含「同 serial 的 precert + 正式憑證」的假 JSON，斷言只產生**一筆** finding。
- **issuer 片段比對測試**：餵一筆 issuer 從 `CN=R3` 換成 `CN=R11` 的條目，斷言**不告警**（否則你每次 CA 換中繼就吃一輪假警報）。
- **SPKI 分流測試**：餵一筆「未知 issuer + 已知 SPKI」的條目，斷言它被歸類為**營運事故**而非資安事件。
- **失敗路徑測試**：讓 crt.sh 回 429 / 回非 JSON，斷言程式**丟出錯誤並告警**，而不是回傳空清單假裝沒事。
- **CI CAA 斷言**：把第五節的 script 排進 CI 定期跑。**DNS 記錄被誤刪要在 CI 紅，不是在憑證簽不出來的那天才發現。**

---

## 九、一句話總結

> Day76 的 pinning 是「**client 端事前收窄信任**」，但它只保護裝了你 pin 的 client、且 CDN 後面的第三方對端根本不能 pin——**Certificate Transparency 是完全相反的思路：不收窄信任，而是讓「誰替我簽了憑證」變成一件查得到的事**。CT 的執行力不是規定 CA 要 log，而是「**沒有 SCT 的憑證 Chrome/Apple 不收**」；SCT 是 log 給 CA 的收據，靠 **precertificate + poison extension**（critical 且無人認得，所以進得了 log 卻永遠不能當憑證用）解掉「憑證還沒簽出來怎麼送 log」的雞蛋問題——**副作用是同一張憑證在 log 裡有兩筆，你的 monitor 必須去重，否則雜訊直接乘二**。三方角色裡你只需要扮演 **monitor**：排程查 crt.sh（或有 SLA 的來源），**兩關式比對**——第一關比 issuer 片段（別比完整字串，CA 會換中繼 R3→R11，比死了每次都假警報），過不了才抓 PEM 算 **SPKI（與 Day76 完全同一份計算與組態）**，**SPKI 已知 = 換 CA 沒更新組態的營運事故，SPKI 未知 = 疑似誤發的資安事件**，這兩者分不開的告警就是會被無視的告警。但**CT 只偵測不阻擋**，想事前預防要靠 **CAA**（DNS 裡宣告只有哪幾家 CA 能簽，2017 年起 CA 強制檢查）——**兩者不是二選一：CAA 防的是「向合法 CA 騙簽」，CT 抓的是「CA 自己被入侵」（DigiNotar 模式下 CAA 完全無效，因為被入侵的 CA 不會為難自己）。CAA 是門鎖，CT 是監視器。** CAA 記得注意子網域會**蓋掉** apex 設定（最常見的自我 DoS）、CI 要**雙向斷言**（該有的在、不該有的不在）。最後兩個認知比程式碼重要：**CT 的盲區是內部 CA**（不在瀏覽器根計畫裡就沒有 log 壓力，一張都不會出現，那塊只能靠 Day76 的 pinning 與簽發稽核）；以及**「monitor 掛了」跟「沒有誤發」在儀表板上長得一模一樣**——所以 `ct_monitor_error` 要告警、`ct_monitor_success` 要有「N 小時沒成功」的告警、還要定期跑**陽性測試**證明它真的會叫。

---

## 延伸閱讀

- Day76 憑證釘選落地實作——本篇的對照組：client 端事前阻擋 vs 網域擁有者事後偵測；SPKI pin 的計算兩篇完全共用。
- Day75 TLS 憑證驗證失誤與 MITM——為什麼「①②都過」的合法憑證仍可能是誤發的；內部 CA truststore。
- Day16 Security Logging / Monitoring——告警要能區分營運事故與資安事件；「偵測器自己壞掉」也是事件。
- Day18 Supply Chain / Dependencies——CI gate 的哲學：讓它在 CI 紅，不要在生產紅。
- Day15 Secrets Management——白名單/組態的存取控制與變更稽核。
- Day72 Slowloris / 慢速 HTTP DoS——對外呼叫一律設 timeout。
- Day10 SSRF——對外呼叫別自動跟 redirect。
- Day19 TLS / Cryptographic Failures——TLS 與 PKI 基礎。

---

明天預告：**Day 78 — 憑證撤銷（Revocation）的現實：CRL、OCSP soft-fail 與短效憑證（新主題）**
（今天你終於偵測到了：CT monitor 叫了，有人替你的網域弄到一張憑證。**然後呢？** 直覺答案是「請 CA 撤銷它」——Day78 要講的是**這個直覺為什麼幾乎不管用**。會講撤銷的三代機制與各自的死法：**CRL**（整包下載、動輒數 MB、更新頻率以天計）、**OCSP**（每次握手多一次對外查詢——這正是 Day74 說的握手 DoS 放大點，而且**交叉 Day10 SSRF**：你的驗證路徑會主動連一個憑證裡寫的 URL）、以及**壓垮一切的 soft-fail**：查不到撤銷狀態時所有主流實作都選擇**放行**，於是攻擊者只要**擋掉 OCSP 查詢**，撤銷就等於沒發生。程式面會示範 **Go `crypto/tls` 預設完全不做撤銷檢查（`ConnectionState.OCSPResponse` 要自己在 `VerifyPeerCertificate` 裡處理，疊加在 Day76 的 pin 檢查旁邊）**，以及 **Java 的 `-Dcom.sun.net.ssl.checkRevocation` / `-Djdk.tls.client.enableStatusRequestExtension` 與 `PKIXRevocationChecker` 的 `SOFT_FAIL` / `NO_FALLBACK` / `PREFER_CRLS` 選項到底各自代表什麼**，最後談產業的收斂方向：**OCSP stapling（把查詢成本移回 server）與「短效憑證」——當憑證只有 6 天效期，撤銷這個問題就大部分消失了**。這是新主題，不重講 Day75/76/77 的驗證、pinning 與 CT。）
