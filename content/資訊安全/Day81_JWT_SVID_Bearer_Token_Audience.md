---
title: "Day 81：JWT-SVID 與跨邊界的 workload 身分（延伸篇）— 當 mTLS 過不去的時候，bearer token、audience 生死線與 confused deputy"
date: 2026-07-21
tags: ["SPIFFE", "JWT-SVID", "Audience", "Bearer Token"]
---

接續 Day80 預告：Day80 講的 X509-SVID 走 mTLS，但很多場景 mTLS 根本插不進去——請求經過 L7 API gateway / mesh ingress 被終結重打、workload 要對雲端 API 或訊息佇列出示身分、或跨過 proxy 之後只剩 HTTP header 能帶東西。這時候 SPIFFE 給你的另一種身分形式就登場了：**JWT-SVID**。

**這是延伸篇，不重新介紹 SPIFFE ID 格式、attestation 兩層機制、X509-SVID 與 mTLS 的基礎**（那些請看 Day80）。今天只聚焦一件事：**當同一個 SPIFFE ID 從「憑證裡的 SAN URI」換成「可攜帶的 JWT」，它的安全性質整個變了**——從 proof-of-possession 掉回 bearer token，於是 `aud` 驗證從「一個好習慣」升級成「唯一撐住整套機制的那根柱子」。這條線會直接接回 Day05 / Day37 / Day57 的 JWT 驗證肌肉，而且你會發現那些老坑一個都沒少，只是換了個更容易讓人鬆懈的外衣。

---

## 一、先講清楚：為什麼需要第二種 SVID

Day80 的結論很乾脆——**能用 mTLS（X509-SVID）就用 mTLS**。今天不推翻這句話，今天只回答「不能用的時候怎麼辦」。

mTLS 插不進去的場景，實務上大致這幾類：

| 場景 | 為什麼 X509-SVID 過不去 |
|---|---|
| L7 API gateway / mesh ingress 終結 TLS 再重打 | client 憑證在 gateway 就被吃掉了，後端拿到的是 gateway 的連線，不是原始 workload 的 |
| CDN / 托管 LB 在前面 | 同上，你根本無法讓 TLS 連線一路貫穿到目標服務 |
| 對雲端 API / 第三方 SaaS 出示身分 | 對方不吃你的內部 CA，也不會為你做 SPIFFE ID 比對 |
| 訊息佇列、非同步任務 | 根本沒有「連線」這個東西——訊息躺在 queue 裡，身分必須跟著訊息走 |
| 跨語言 / 跨執行環境的 hop | 中間某一段是你動不了的元件，只剩 HTTP header 能帶資訊 |

共同點只有一句話：**身分必須離開連線，變成一份可以被複製、被轉交、被存進 queue 的資料。**

而「可以被複製」這五個字，就是今天所有麻煩的根源。

---

## 二、核心差異：proof-of-possession vs bearer token

這是本篇最重要的一段，其他都是它的推論。

**X509-SVID 是 proof-of-possession。** workload 手上有 SVID 的私鑰，那把私鑰**從來不離開 workload**。TLS 握手時對方拿到的是憑證（公開資訊）＋一個用私鑰做的簽章。中間任何人抄走憑證都沒有用——他沒有私鑰，簽不出那個握手。**「拿到憑證」不等於「能冒充你」。**

**JWT-SVID 是 bearer token。** 它是一串字串，簽章是 SPIRE Server 用 bundle 私鑰簽的，用來證明「這個 SPIFFE ID 是我發的」。但**驗證方只會驗簽章，不會驗『拿著這串字串的人是不是原本那個 workload』**。所以：

> **誰拿到這串 token，誰就是你。**

把這兩句話並排看，Day80 那套「workload 不持有任何祕密、沒有祕密可偷」的漂亮性質，在 JWT-SVID 上**部分失效了**——X509-SVID 的私鑰偷不走（在 workload 記憶體裡、且短效），但 JWT-SVID 本身就是一個可以被抄走的祕密，而且它會被你**主動塞進 HTTP header 送給別人**。

送給誰？送給下游服務。下游服務會不會拿去用？這就是第四節的 confused deputy。

---

## 三、JWT-SVID 長什麼樣：claims 與 audience

JWT-SVID 是一個標準 JWT，但 SPIFFE 規格把幾個 claim 的語意鎖死了：

```text
{
  "sub": "spiffe://example.org/ns/prod/sa/order-service",   ← SPIFFE ID 放在 sub，不是 SAN URI
  "aud": ["spiffe://example.org/ns/prod/sa/payment-service"], ← 這份 token 只能給誰用
  "exp": 1753084800,
  "iat": 1753084500
}
```

跟 Day80 對照，兩個關鍵位移：

1. **SPIFFE ID 從憑證的 `SAN URI` 搬到 JWT 的 `sub`**。所以你的驗證邏輯不是比對憑證欄位，而是比對 claim。
2. **多了一個 `aud`，而且它是必填的**。X509-SVID 沒有這個東西——因為 mTLS 的「對象」是連線本身，你連到誰就是給誰看。JWT-SVID 離開了連線，所以「這份身分是要給誰看的」必須寫在 token 裡面。

**`aud` 是 X509-SVID 世界不存在、JWT-SVID 世界不能省的那一欄。** 它存在的唯一理由，就是補回「離開連線」所失去的那個綁定。

簽章驗證用的公鑰在 **JWT bundle**（一組 JWKS，由 Workload API 提供、會隨 SPIRE Server 金鑰輪替自動更新）。這裡有個 Day37 讀者要立刻警覺的點：**JWT-SVID 的公鑰來源是 Workload API 的 bundle，不是 token 裡的 `jku` 或任何 header 欄位**。SPIFFE 的函式庫替你把這個決定寫死了，這是好事——Day37 的 kid 注入 / JWKS 指向攻擊者，在正確使用函式庫的前提下，在這裡沒有施力點。**但前提是你用函式庫的 `ParseAndValidate`，不是自己撿一個泛用 JWT library 隨手驗。**

---

## 四、生死線：audience 驗證與 confused deputy

先講攻擊，再講防禦。

假設 `order-service` 要呼叫 `payment-service`，它拿了一份 JWT-SVID 放進 `Authorization` header。現在問一個問題：

> 如果這份 token 的 `aud` 是 `spiffe://example.org`（整個 trust domain）或乾脆是 `"internal"` 這種萬用值，會怎樣？

會這樣：`payment-service` 收到 token、驗簽章通過、看到 `sub` 是 order-service。然後 `payment-service`（可能只是有個 SSRF、可能是被入侵、也可能只是寫得爛）**把這份 token 原封不動轉發給 `ledger-service`**。`ledger-service` 驗簽章——通過；看 `aud`——`"internal"`，我也是 internal，通過；看 `sub`——order-service，喔那是我信任的上游。

**於是 payment-service 成功冒充 order-service 去操作 ledger-service。** 這就是 **confused deputy**：一個有權限的中介，被誘導著用自己拿到的憑據去做不該做的事。這也是 Day33 session fixation / token 重放那條線的內部版——**只是這次被重放的不是使用者的 session，是服務的身分**。

X509-SVID 為什麼沒這個問題？因為 payment-service 拿不到 order-service 的私鑰，它**物理上無法**重現那個 mTLS 握手。bearer token 把這道物理屏障換成了一個純粹的約定，而約定只有在雙方都遵守時才有效。

**防禦只有一句話：audience 要窄到「一份 token 只能對一個接收方使用」，而接收方一定要驗 `aud` 是不是自己。**

兩邊各有一半責任，缺一不可：

- **簽發端（呼叫方）**：向 Workload API 要 token 時，`audience` 填**目標服務的 SPIFFE ID**，不要填 trust domain、不要填 `"internal"`、不要一份 token 到處用。要呼叫三個下游就拿三份 token。
- **驗證端（被呼叫方）**：`ParseAndValidate` 時把**自己的 SPIFFE ID** 當 expected audience 傳進去。**不是傳「任意」，不是不傳。**

我看過最常見的錯誤寫法，是驗證端為了「先跑起來」把 audience 參數填成上游的 ID（因為報錯訊息裡看到上游的名字，就照抄），這等於完全沒驗——**`aud` 說的是「這份 token 要給誰」，所以驗證端要拿自己去比對，不是拿對方。**

---

## 五、Go 實作：go-spiffe v2

兩件事：**拿 token**（呼叫方）與 **驗 token**（被呼叫方）。

### 5.1 呼叫方：拿一份綁定目標的 JWT-SVID

```go
package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// jwtSource 跟 Day80 的 X509Source 一樣：長生命週期單例，內部維持到 Agent 的 stream，
// 並且會快取 / 自動更新。千萬不要每個請求 new 一個。
var jwtSource *workloadapi.JWTSource

func initJWTSource(ctx context.Context) error {
	src, err := workloadapi.NewJWTSource(ctx,
		workloadapi.WithClientOptions(
			workloadapi.WithAddr("unix:///run/spire/agent.sock"),
		),
	)
	if err != nil {
		return fmt.Errorf("建立 JWTSource 失敗: %w", err)
	}
	jwtSource = src
	return nil
}

// callPayment 示範：每一個下游，拿一份「只給那個下游」的 token。
func callPayment(ctx context.Context, body []byte) error {
	// 關鍵：Audience 是「目標服務的 SPIFFE ID」，不是 trust domain、不是萬用字串。
	svid, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: "spiffe://example.org/ns/prod/sa/payment-service",
	})
	if err != nil {
		// 拿不到身分要大聲失敗，不要退回「不帶 token 打打看」（承 Day75 的鐵律）。
		return fmt.Errorf("取得 JWT-SVID 失敗: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://payment.internal/charge", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+svid.Marshal())

	// 專屬 client，設 Timeout（承 Day72），不要動 DefaultTransport（承 Day75/76）。
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
```

幾個要點：

- `FetchJWTSVID` 的 `Audience` 是**必填**。go-spiffe 不會給你一個「沒有 audience 的 token」——這是規格層級的防呆，很好。
- `jwtsvid.Params` 還有 `ExtraAudiences`（多個接收方）。**能不用就不用**——每多一個 audience，就多一個「這份 token 被那個服務拿去重放」的可能。要呼叫三個下游，寧可拿三份 token（`JWTSource` 有快取，成本沒你想的高）。
- `svid.Marshal()` 才是那串 token 字串。
- **JWT-SVID 有效期很短（SPIRE 預設 5 分鐘等級）**。這是刻意的——bearer token 唯一的補救就是活得夠短，讓被抄走的窗口小到不值得。所以**不要自己快取 token 一小時**，讓 `JWTSource` 管。

### 5.2 被呼叫方：驗 token（audience 傳自己）

```go
package main

import (
	"context"
	"net/http"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// bundleSource 提供驗簽章要用的公鑰（JWKS），一樣是長生命週期單例、會自動更新。
var bundleSource *workloadapi.BundleSource

// myID：我自己的 SPIFFE ID。驗 aud 就是拿這個去比。
const myID = "spiffe://example.org/ns/prod/sa/payment-service"

// 允許呼叫我的上游（authN 之後的第一層粗篩；細粒度授權仍然要做，承 Day07）。
var allowedCallers = map[string]bool{
	"spiffe://example.org/ns/prod/sa/order-service": true,
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if raw == "" || raw == r.Header.Get("Authorization") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// 核心：expected audience 傳「我自己」。
		// ParseAndValidate 會一次做完：驗簽章（用 bundle 公鑰）、驗 exp、驗 aud 包含 myID。
		svid, err := jwtsvid.ParseAndValidate(raw, bundleSource, []string{myID})
		if err != nil {
			// 驗證失敗要記錄並告警（承 Day16），不要靜默放行。
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if !allowedCallers[svid.ID.String()] {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), callerKey{}, svid.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type callerKey struct{}

var _ = spiffeid.ID{} // 型別提示：svid.ID 是 spiffeid.ID
```

**絕對不要用的函式**：go-spiffe 有一個 `jwtsvid.ParseInsecure`。它**不驗簽章**，只解析內容，存在的目的是給 debug / log 用。它在 code review 裡出現在請求處理路徑上，等同 Day57 的 `decode without verify`——**攻擊者可以自己捏一個 `sub` 是任何 SPIFFE ID 的 token**。這是本篇最該 grep 的字串。

---

## 六、Java 實作：java-spiffe

對稱的兩件事。

### 6.1 呼叫方

```java
import io.spiffe.workloadapi.DefaultJwtSource;
import io.spiffe.workloadapi.JwtSource;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.spiffeid.SpiffeId;

public class PaymentClient {

    // 跟 Day80 的 DefaultX509Source 一樣：長生命週期單例，背景自動更新。
    private static final JwtSource JWT_SOURCE;

    static {
        try {
            // socket 位址由 SPIFFE_ENDPOINT_SOCKET 環境變數提供
            JWT_SOURCE = DefaultJwtSource.newSource();
        } catch (Exception e) {
            throw new IllegalStateException("初始化 JwtSource 失敗", e);
        }
    }

    private static final SpiffeId PAYMENT_ID =
            SpiffeId.parse("spiffe://example.org/ns/prod/sa/payment-service");

    public String fetchTokenForPayment() throws Exception {
        // audience 就是目標服務的 SPIFFE ID
        JwtSvid svid = JWT_SOURCE.fetchJwtSvid(PAYMENT_ID);
        return svid.getToken();
    }
}
```

拿到 token 之後放進 `Authorization: Bearer <token>`。Java 11+ 用 `java.net.http.HttpClient`（記得 `connectTimeout`、`followRedirects(NEVER)` 承 Day10/72）；**Java 1.8 沒有 `java.net.http.HttpClient`**，走 `HttpURLConnection` 或 Apache HttpClient，一樣要設 timeout、一樣不要跟跳轉（跟著跳轉＝把你的 token 送去攻擊者控制的位址，這是 Day67/68 那條線在 bearer token 上的具體災難）。

### 6.2 被呼叫方

```java
import io.spiffe.workloadapi.DefaultJwtSource;
import io.spiffe.workloadapi.JwtSource;
import io.spiffe.svid.jwtsvid.JwtSvid;
import io.spiffe.spiffeid.SpiffeId;

import java.util.Set;

public class SvidAuthenticator {

    private static final JwtSource JWT_SOURCE;

    static {
        try {
            JWT_SOURCE = DefaultJwtSource.newSource();
        } catch (Exception e) {
            throw new IllegalStateException("初始化 JwtSource 失敗", e);
        }
    }

    // 我自己的 SPIFFE ID —— 驗 aud 就是拿這個去比
    private static final SpiffeId MY_ID =
            SpiffeId.parse("spiffe://example.org/ns/prod/sa/payment-service");

    private static final Set<SpiffeId> ALLOWED_CALLERS = Set.of(
            SpiffeId.parse("spiffe://example.org/ns/prod/sa/order-service"));

    public SpiffeId authenticate(String bearerToken) {
        JwtSvid svid;
        try {
            // JWT_SOURCE 同時是 JwtBundleSource，提供驗簽章的公鑰。
            // 第三個參數是 expected audience —— 傳「我自己」。
            svid = JwtSvid.parseAndValidate(bearerToken, JWT_SOURCE, Set.of(MY_ID.toString()));
        } catch (Exception e) {
            // 驗證失敗大聲失敗 + 告警（承 Day16）；絕不 catch 掉當今天沒事
            throw new SecurityException("JWT-SVID 驗證失敗", e);
        }

        SpiffeId caller = svid.getSpiffeId();
        if (!ALLOWED_CALLERS.contains(caller)) {
            throw new SecurityException("不允許的呼叫方: " + caller);
        }
        return caller;
    }
}
```

Java 端的對應地雷是 **`JwtSvid.parseInsecure(...)`**——同樣不驗簽章，同樣只該出現在 debug 工具裡。另外一個更隱蔽的：**不要用專案裡現成的泛用 JWT library（jjwt、nimbus-jose-jwt）自己驗 JWT-SVID**。不是那些函式庫不好，是你自己接的話，公鑰從哪來、`kid` 怎麼選、要不要信 header 裡的欄位，全部變成你的責任——而那正是 Day37 演算法混淆與 kid 注入的整片雷區。**`parseAndValidate` 的價值就在於它把這些決定寫死了。**

---

## 七、JWT-SVID 該用在哪、不該用在哪

這節是決策，不是技術。

**該用：**

- 請求要穿過你控制不了的 L7 元件（gateway、mesh ingress、CDN），mTLS 貫穿不了。
- 身分要跟著**資料**走而不是跟著**連線**走：訊息佇列、非同步任務、批次工作。
- 對接不吃你內部 CA 的外部系統（部分雲端 API 支援 OIDC federation 吃 JWT）。

**不該用：**

- **服務對服務、你兩端都控制、網路上打得通**——用 X509-SVID + mTLS。用 JWT-SVID 是把 proof-of-possession 主動降級成 bearer token，沒有任何好處。
- **當成「比較簡單的內部 auth」**。JWT-SVID 看起來簡單（塞個 header 就好），這正是它危險的地方：mTLS 設錯通常握手就失敗、當場就知道；JWT-SVID 設錯（audience 太寬、驗證端沒驗 aud）**一切照常運作**，直到有人重放。

**最重要的一條，也是最容易被跳過的：`aud` 不是授權。** 驗過 `aud` 只代表「這份 token 是給我的」，驗過 `sub` 只代表「發話的是誰」。**「order-service 能不能對這筆訂單發起扣款」是完全獨立的一題，要照 Day07 / Day49 的方式在業務層做。** JWT-SVID 只是把 Day80 的 authN 換了一種傳輸方式，authZ 那一半一點都沒替你做。

---

## 八、常見誤區

| 誤區 | 實際情況 |
|---|---|
| 「JWT-SVID 跟 X509-SVID 差不多，只是格式不同」 | 差在 bearer vs proof-of-possession。前者誰拿到誰就是你，後者私鑰不出 workload |
| 「反正有 SPIRE 簽章，重放不了」 | 簽章證明「是 SPIRE 發的」，不證明「拿著它的人是原主」。這正是重放成立的原因 |
| 「audience 填 trust domain 比較好管」 | 那等於作廢 audience：任何內部服務都能拿去對任何內部服務用＝confused deputy 開門 |
| 「驗證端 audience 填上游的 ID」 | 方向反了。`aud` 說的是「給誰用」，驗證端必須拿**自己**比對 |
| 「驗證端不驗 aud，反正驗了簽章跟 sub」 | 這是最致命的單一疏漏。沒驗 aud＝任何下游都能重放你的 token 冒充你 |
| 「用 `ParseInsecure` / `parseInsecure` 先跑起來再說」 | 完全不驗簽章，攻擊者可任意捏造 `sub`。等同 Day57 的 decode without verify |
| 「自己用 jjwt / nimbus 驗比較好控制」 | 你會接手公鑰來源與 kid 選擇＝Day37 整片雷區。用函式庫的 parseAndValidate |
| 「token 快取久一點省呼叫」 | JWT-SVID 短效是唯一的補救。自己拉長效期＝把被抄走的窗口自己撐大 |
| 「有 JWT-SVID 就不用 mTLS 了，比較簡單」 | 反了。能 mTLS 就 mTLS，JWT-SVID 是妥協方案不是升級 |
| 「gateway 幫我驗過了，後端不用再驗」 | 那後端就對「繞過 gateway 直接連內網」完全無防禦（承 Day38 X-Forwarded-For 那條線） |
| 「驗過 aud 跟 sub 就等於授權完成」 | authN ≠ authZ。業務授權要另外做（Day07 / Day49） |
| 「client 端跟著 3xx 跳轉沒關係」 | 跟著跳轉＝把 Bearer token 送去攻擊者位址（承 Day10 / Day67 / Day68） |

---

## 九、Code Review / 維運 checklist

```text
【Source 生命週期】
[ ] JWTSource / JwtSource 是長生命週期單例嗎？（不是每請求 new，否則失去快取與自動更新）
[ ] 有沒有自己實作 token 快取並拉長效期？（該讓 source 管，短效是安全性質不是效能問題）

【簽發端（呼叫方）】
[ ] Audience 填的是「目標服務的 SPIFFE ID」還是 trust domain / 萬用字串？
[ ] ExtraAudiences 有沒有被拿來偷懶做「一份 token 打天下」？
[ ] 拿不到 SVID 時的行為是「大聲失敗」還是「不帶 token 打打看」？
[ ] 帶 token 的 HTTP client 有沒有關掉 follow redirect？（跟跳轉＝送 token 給攻擊者，承 Day67/68）
[ ] token 有沒有被寫進 log / trace / error message？（bearer token 進 log 就是外洩，承 Day16）

【驗證端（被呼叫方）】
[ ] ParseAndValidate / parseAndValidate 的 expected audience 傳的是「自己的 SPIFFE ID」嗎？
[ ] 有沒有 ParseInsecure / parseInsecure 出現在請求處理路徑上？（最該 grep 的字串）
[ ] 有沒有繞過 SPIFFE 函式庫，改用泛用 JWT library 自行驗簽？（Day37 雷區）
[ ] 驗證失敗有沒有記錄 + 告警，還是靜默回 401 就算了？（承 Day16）
[ ] 有沒有假設「gateway 驗過了」而後端不驗？（繞過 gateway 直連內網就全裸）

【邊界與定位】
[ ] 這條路徑真的 mTLS 過不去嗎？還是只是覺得 JWT 比較好接？
[ ] 有沒有把「驗過 sub / aud」當成業務授權？（authN vs authZ，承 Day07 / Day49）
[ ] token 會不會被下游服務原封不動轉發出去？（confused deputy 的具體形態）
```

**測試建議：**

- **audience 不符測試（最重要）**：拿一份 `aud` 是**別的服務**、但簽章完全有效、未過期的 JWT-SVID 去打你的端點，斷言**被拒**。這是 audience 驗證的存在證明——測不過代表你的 `aud` 檢查是裝飾品，任何服務的 token 都能進來。這是本篇版本的「守門員存在證明」（承 Day75 / 76 / 80）。
- **重放 / confused deputy 測試**：模擬「payment-service 把收到的 token 原封不動轉給 ledger-service」，斷言 ledger-service **拒絕**（因為 `aud` 不是它）。這一題會直接暴露你 audience 開太寬。
- **簽章偽造測試**：自己捏一個 `sub` 是高權限 SPIFFE ID、但用別的金鑰簽（或 `alg: none`）的 token，斷言被拒。這同時是「有沒有人偷用 ParseInsecure」的偵測器。
- **過期測試**：把一份已過期的 JWT-SVID 送進去，斷言被拒。順便驗證你的時鐘容忍設定沒有被放大到失去意義。
- **失敗行為測試**：讓 Workload API socket 不可用，斷言呼叫方**明確失敗**而不是靜默降級成「不帶 Authorization header 送出去」——後者是最糟的失敗模式，因為下游如果剛好有條沒驗的路徑，它就過了。
- **log 洩漏檢查**：CI 加一條 grep，斷言不會有人把整個 Authorization header 或 token 寫進 log（承 Day16 / Day18）。

---

## 十、一句話總結

> Day80 說「內網服務靠 X509-SVID 走 mTLS 互相證明身分」，今天處理的是那句話撐不住的場合：**請求要穿過 L7 gateway / mesh ingress 被終結重打、身分要跟著訊息躺進佇列、或要對不吃你內部 CA 的雲端 API 出示身分——這時身分必須離開連線，變成一份可攜帶的資料，那就是 JWT-SVID**。核心差異只有一句、其餘全是推論：**X509-SVID 是 proof-of-possession（私鑰不出 workload，抄走憑證也冒充不了你），JWT-SVID 是 bearer token（誰拿到那串字串誰就是你）**——Day80 那個「沒有祕密可偷」的漂亮性質在這裡部分失效，因為 token 本身就是祕密，而且你會主動把它塞進 header 送給別人。格式上兩個位移要記牢：**SPIFFE ID 從憑證的 SAN URI 搬到 JWT 的 `sub`，而且多了一個 X509-SVID 世界不存在、這裡不能省的 `aud`**——它存在的唯一理由就是補回「離開連線」所失去的那個綁定。**`aud` 因此是生死線**：audience 開成 trust domain 或 `"internal"`，等於下游服務可以把你的 token 原封不動轉發去冒充你打第三方，這就是 **confused deputy**（Day33 token 重放的服務版）；防禦必須兩端各做一半——**簽發端 audience 填目標服務的確切 SPIFFE ID，一個下游一份 token；驗證端 `ParseAndValidate` 的 expected audience 傳「自己的 SPIFFE ID」，不是傳對方、更不是不傳**。程式面 **Go 用 `workloadapi.NewJWTSource` 拿長生命週期 source、`FetchJWTSVID(ctx, jwtsvid.Params{Audience: 目標ID})` 取 token、`jwtsvid.ParseAndValidate(raw, bundleSource, []string{myID})` 驗**；**Java 用 `DefaultJwtSource.newSource()` + `fetchJwtSvid(目標ID)` 與 `JwtSvid.parseAndValidate(token, jwtSource, Set.of(myID))`**；兩邊都有同一個必須 grep 的地雷——**`ParseInsecure` / `parseInsecure` 不驗簽章，出現在請求處理路徑上就等同 Day57 的 decode without verify，攻擊者可任意捏造 `sub`**；也都別繞過函式庫改用泛用 JWT library 自行驗簽，那會把公鑰來源與 kid 選擇的責任接回自己身上＝Day37 整片雷區。最後是定位：**JWT-SVID 是妥協方案不是升級，能走 mTLS 就別退回 bearer token**；它短效（分鐘級）是唯一的補救所以別自己快取拉長；而**驗過 `sub` 與 `aud` 只完成 authN，「這個服務能不能做這件事」仍然要照 Day07 / Day49 在業務層做**。一句話：X509-SVID 讓你證明「我握有這個身分」，JWT-SVID 只讓你出示「有人說我是這個身分」——差別在於後者可以被轉交，所以你必須事先寫死它只能交給誰。

---

## 延伸閱讀

- Day80 SPIFFE / SPIRE workload identity——本篇的上游：SPIFFE ID、attestation 兩層、X509-SVID 與 mTLS 的完整基礎。
- Day57 JWT 常見陷阱——`ParseInsecure` 就是這篇「decode without verify」在 SPIFFE 世界的化身。
- Day37 JWT 演算法混淆——為什麼不要自己接泛用 JWT library 驗 JWT-SVID：公鑰來源與 kid 選擇的整片雷區。
- Day33 Session Fixation / token 重放——confused deputy 是這條線的服務對服務版本。
- Day49 BFLA / Day07 授權最小化——驗過 `aud` 與 `sub` 只是 authN，業務授權在這裡。
- Day38 X-Forwarded-For 偽造——「gateway 幫我驗過了」的同款錯誤：繞過邊界直連內網就全裸。
- Day67 / Day68 Open Redirect 與 Location header——帶著 Bearer token 跟隨跳轉＝把身分送給攻擊者。
- Day16 Security Logging / Monitoring——驗證失敗告警，以及「token 千萬別進 log」。
- Day10 SSRF——下游服務的 SSRF 加上過寬的 audience，就是 confused deputy 最現實的觸發路徑。

---

明天預告：**Day 82 — SPIFFE Federation：跨 trust domain 的信任怎麼建立、怎麼收窄（新主題）**
（Day80 / Day81 都活在**同一個 trust domain**裡——同一個 SPIRE Server、同一組 bundle、`spiffe://example.org` 底下大家互相認得。但真實世界會撞牆：**併購後兩個叢集各有自己的 SPIRE、多雲各跑一套控制平面、或你要跟合作夥伴的服務互相驗證身分**，這時 `spiffe://example.org` 的服務要怎麼信任 `spiffe://partner.com` 的服務？Day82 要講 **federation 的機制核心＝bundle 交換**：信任不是靠某個共同上級 CA，而是**兩個 trust domain 互相拿到對方的 bundle（公鑰集合）**，這跟公網 PKI「大家都信同一批根 CA」是完全不同的信任模型。程式面會示範 **Go 用 `go-spiffe` 的 `tlsconfig` 搭 federated bundle source 與 `AuthorizeID` 跨 domain 授權**，以及 **SPIFFE Bundle Endpoint（`https_web` 與 `https_spiffe` 兩種驗證方式）的取捨——前者靠公開 CA 憑證，於是 Day75 的主機名驗證與 Day77 的 CT/CAA 整套又回來了**。安全主軸三件事：**① federation 是「我認得你的 CA」不是「我信任你的所有 workload」，授權必須逐一收窄否則等於把對方整個 trust domain 拉進你的信任邊界；② bundle endpoint 是新的攻擊面（承 Day10 SSRF：你會定期主動去連一個對方給的 URL 抓公鑰）；③ bundle refresh 失敗的失敗模式——對方輪替金鑰而你沒更新到，會安靜地變成全面握手失敗**。這是新主題，不重講 Day80/81 的 SVID 基礎，聚焦「信任邊界跨出去之後」的機制與收窄。）
