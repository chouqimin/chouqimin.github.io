---
title: "Day 26：Webhook 安全性 — HMAC 簽章驗證、重放攻擊與 SSRF 風險"
date: 2026-05-22
tags: ["Webhook", "API 安全", "HMAC"]
---

# Day 26：Webhook 安全性 — HMAC 簽章驗證、重放攻擊與 SSRF 風險

> 後端工程師資安系列 — Day 26
> 日期：2026-05-22

## 一、前情提要

過去 25 天我們講過 SQL Injection、XSS、CSRF、JWT、Rate Limiting、SSRF、OAuth2、BOPLA 等議題，這些大多是「使用者打進來」或「我們打出去」的標準 HTTP 流量。

但現代後端系統有另一條經常被忽略的入口 — **Webhook（Web 回呼）**。

> 「Webhook」就是第三方服務在某個事件發生時，主動 HTTP POST 到你提供的 URL，把事件資料推給你。

常見場景：
- **Stripe / 綠界 / Line Pay**：付款成功、退款、訂閱續訂通知
- **GitHub / GitLab**：push、PR、issue 事件
- **Slack / Discord**：slash command、interactive button
- **SendGrid / Mailgun**：信件送達、退信、開信事件
- **Shopify / 蝦皮 / 露天**：訂單建立、出貨狀態

對攻擊者來說，這是一個超棒的攻擊面：
1. **URL 通常是公開的**（要讓第三方打得到）
2. **付款 / 訂單 / 權限變更**等高價值動作經常掛在 webhook handler 後面
3. 後端工程師對「打進來的請求是否真的來自 Stripe」往往沒做嚴格驗證

今天我們就把 webhook 安全該注意的事一次講清楚。

---

## 二、Webhook 常見的三大漏洞

| 漏洞 | 一句話描述 | 後果 |
| --- | --- | --- |
| 缺少／錯誤的簽章驗證 | 任何人都能假冒成 Stripe 打你的 endpoint | 偽造付款成功、偽造訂單狀態、權限提升 |
| 缺少重放保護 | 攻擊者攔截到一次合法請求後可無限重播 | 同一筆退款被執行多次、訊息洗版、配額暴衝 |
| SSRF / 出站 webhook 設定外洩 | 使用者自訂的 webhook URL 沒做驗證 | 內網掃描、雲端 metadata 服務洩漏（同 Day 10） |

下面逐一拆解。

---

## 三、漏洞範例：缺少簽章驗證

### 反例（Java 21，Spring Boot）

```java
// ❌ 反例：直接相信 body 內容
@RestController
public class StripeWebhookController {

    private final OrderService orderService;

    @PostMapping("/webhooks/stripe")
    public ResponseEntity<String> handle(@RequestBody String payload) {
        // 直接解析 JSON，沒驗證來源
        var event = objectMapper.readValue(payload, StripeEvent.class);

        if ("payment_intent.succeeded".equals(event.type())) {
            // 危險：任何人 curl 一下就能讓任意訂單變成「已付款」
            orderService.markAsPaid(event.data().orderId());
        }
        return ResponseEntity.ok("ok");
    }
}
```

攻擊者只要知道你的 webhook 路徑（或從前端 JS、GitHub 公開 repo 撈到），就能直接：

```bash
curl -X POST https://yourapp.com/webhooks/stripe \
  -H 'Content-Type: application/json' \
  -d '{"type":"payment_intent.succeeded","data":{"orderId":"12345"}}'
```

訂單 12345 立刻變成「已付款」。這不是假設，這是 2022 年某個東南亞電商真的被攻擊的手法。

---

## 四、正確做法：HMAC 簽章驗證

### 原理

第三方服務在送 webhook 時，會用「你跟它共享的 secret key」對 **原始 request body** 做 HMAC-SHA256，把結果放在 header（例如 `Stripe-Signature`、`X-Hub-Signature-256`）。

你的後端要做的事：
1. **拿到原始 body**（不是反序列化後再序列化的版本，**順序、空白都不能差**）
2. 用相同 secret 對 body 做 HMAC-SHA256
3. 用 **常數時間比較（constant-time compare）** 對照 header 中的簽章
4. 比對失敗 → 直接 401，不要洩漏任何細節

> 「常數時間比較」很重要：用 `==` 或 `String.equals` 比較 hash，會因為前幾個字元就 short-circuit，攻擊者可以藉由量測響應時間逐字猜出正確簽章（Timing Attack）。

### Java 21 範例（含 Stripe-style header）

```java
@RestController
public class StripeWebhookController {

    @Value("${stripe.webhook.secret}")
    private String secret;  // whsec_xxxxxxxxxxxxxxxxxx

    private static final long TOLERANCE_SECONDS = 300; // 5 分鐘

    @PostMapping(value = "/webhooks/stripe",
                 consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> handle(
            @RequestHeader("Stripe-Signature") String sigHeader,
            @RequestBody byte[] rawBody) {   // ✅ 用 byte[] 拿原始 bytes

        try {
            verifySignature(rawBody, sigHeader, secret);
        } catch (SecurityException e) {
            return ResponseEntity.status(401).body("invalid signature");
        }

        var event = objectMapper.readValue(rawBody, StripeEvent.class);
        // ... 後續處理
        return ResponseEntity.ok("ok");
    }

    private void verifySignature(byte[] payload, String header, String secret) {
        // Stripe-Signature: t=1614000000,v1=abcdef...
        Map<String, String> parts = Arrays.stream(header.split(","))
            .map(s -> s.split("=", 2))
            .collect(Collectors.toMap(a -> a[0], a -> a[1]));

        long timestamp = Long.parseLong(parts.get("t"));
        String expectedSig = parts.get("v1");

        // (1) 時間戳檢查：防重放
        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - timestamp) > TOLERANCE_SECONDS) {
            throw new SecurityException("timestamp out of tolerance");
        }

        // (2) 計算 HMAC：簽的是 "timestamp.payload"
        String signedPayload = timestamp + "." + new String(payload, StandardCharsets.UTF_8);
        String computed = hmacSha256Hex(secret, signedPayload);

        // (3) 常數時間比較
        if (!MessageDigest.isEqual(
                computed.getBytes(StandardCharsets.UTF_8),
                expectedSig.getBytes(StandardCharsets.UTF_8))) {
            throw new SecurityException("signature mismatch");
        }
    }

    private String hmacSha256Hex(String secret, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] raw = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(raw);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
```

幾個容易出錯的點：

- **必須收原始 bytes**：若你用 `@RequestBody Map<String, Object>`，Jackson 反序列化後再 toString 出來的 JSON 跟原始 body 不一樣（空白、欄位順序、Unicode escape 全都會變），HMAC 一定算不過。所以一律用 `byte[]`、`InputStream`，或設定 filter 把 raw body 存下來。
- **`MessageDigest.isEqual` 是常數時間比較**：在 JDK 1.6+ 就是 timing-safe 實作，不要用 `Arrays.equals` 或 `String.equals`。
- **時間戳一定要檢查**：HMAC 只能保證「這個 body 是有 secret 的人簽的」，無法防止別人把「以前簽過的合法請求」再播一次。

### Java 8 版本（語法相容）

```java
// Java 8 沒有 var、records、HexFormat，改寫如下
String signedPayload = timestamp + "." + new String(payload, StandardCharsets.UTF_8);

Mac mac = Mac.getInstance("HmacSHA256");
mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
byte[] raw = mac.doFinal(signedPayload.getBytes(StandardCharsets.UTF_8));

// Java 8 沒有 HexFormat，用 Apache Commons Codec 或自己寫
StringBuilder sb = new StringBuilder(raw.length * 2);
for (byte b : raw) {
    sb.append(String.format("%02x", b));
}
String computed = sb.toString();

if (!MessageDigest.isEqual(
        computed.getBytes(StandardCharsets.UTF_8),
        expectedSig.getBytes(StandardCharsets.UTF_8))) {
    throw new SecurityException("signature mismatch");
}
```

### Go 範例（GitHub-style header）

GitHub webhook 的 header 長這樣：`X-Hub-Signature-256: sha256=abcdef...`

```go
package webhook

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "io"
    "net/http"
    "strings"
    "time"
)

const tolerance = 5 * time.Minute

func GitHubWebhookHandler(secret []byte) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // (1) 讀取原始 bytes
        body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20)) // 限制 1MB
        if err != nil {
            http.Error(w, "bad request", http.StatusBadRequest)
            return
        }

        // (2) 取出 signature
        sig := r.Header.Get("X-Hub-Signature-256")
        if !strings.HasPrefix(sig, "sha256=") {
            http.Error(w, "missing signature", http.StatusUnauthorized)
            return
        }
        gotMAC, err := hex.DecodeString(strings.TrimPrefix(sig, "sha256="))
        if err != nil {
            http.Error(w, "invalid signature format", http.StatusUnauthorized)
            return
        }

        // (3) 計算期望的 HMAC
        mac := hmac.New(sha256.New, secret)
        mac.Write(body)
        expectedMAC := mac.Sum(nil)

        // (4) 常數時間比較
        if !hmac.Equal(gotMAC, expectedMAC) {
            http.Error(w, "signature mismatch", http.StatusUnauthorized)
            return
        }

        // (GitHub webhook 沒帶 timestamp，要靠 X-GitHub-Delivery 去重；
        //  Stripe / Slack 等服務則有 timestamp，務必檢查)

        // (5) 安全處理 event
        eventType := r.Header.Get("X-GitHub-Event")
        deliveryID := r.Header.Get("X-GitHub-Delivery")
        if err := handleEvent(eventType, deliveryID, body); err != nil {
            http.Error(w, "internal", http.StatusInternalServerError)
            return
        }
        w.WriteHeader(http.StatusOK)
    }
}

func handleEvent(eventType, deliveryID string, body []byte) error {
    // 用 deliveryID 做冪等性檢查（見下節）
    if alreadyProcessed(deliveryID) {
        return nil
    }
    markProcessed(deliveryID)
    // ... 業務邏輯
    return nil
}

var (
    ErrReplay = errors.New("replay detected")
)
```

重點：
- **`hmac.Equal`** 才是常數時間比較，**不要**用 `bytes.Equal` 來比 HMAC。
- **`http.MaxBytesReader`** 限制 body 大小，避免攻擊者送 10GB 來把你 OOM。
- 讀完 body 後若還要繼續用，記得 `r.Body = io.NopCloser(bytes.NewReader(body))` 重新塞回去。

---

## 五、重放攻擊（Replay Attack）與冪等性

即使 HMAC 驗過，攻擊者若能拿到一份合法的 webhook（例如從 log、從中間人代理），他可以無限次發送同一份 payload + signature。

### 防禦三層

**(1) 時間戳 + 容忍視窗**

要求簽章內含 timestamp，後端只接受 ±5 分鐘內的請求。Stripe、Slack、Shopify 都是這樣做。

**(2) Delivery ID 去重（冪等性）**

每個 webhook event 通常有唯一 ID（`Stripe-Signature` 帶的 `evt_xxx`、GitHub 的 `X-GitHub-Delivery`）。把處理過的 ID 存起來：

```java
// 用 Redis SETNX，5 分鐘內同一個 event 只處理一次
String key = "webhook:processed:" + eventId;
Boolean firstTime = redis.opsForValue().setIfAbsent(key, "1", Duration.ofMinutes(10));
if (Boolean.FALSE.equals(firstTime)) {
    // 已處理過，回 200 就好（不要回 4xx，否則 Stripe 會一直重試）
    return ResponseEntity.ok("duplicate, ignored");
}
```

**(3) 業務面冪等**

最重要的一層：**業務邏輯本身要冪等**。
- 「把訂單 12345 標記為已付款」要先檢查狀態，已付過就跳過。
- 「給用戶加 100 點」要記錄 transaction_id，同一個 transaction 加過就跳過。

> 為什麼三層都要做？因為第三方服務（特別是 Stripe）**本來就會故意重送**：你回 5xx、或你 timeout，他下一分鐘就再打一次。你的 handler 必須假設「同一個 event 會收到很多次」。

---

## 六、出站 Webhook 的 SSRF 風險

另一個常被忽略的場景：**你的系統允許使用者填一個 URL，事件發生時你打過去**（例如 Zapier、IFTTT、自家 SaaS 的「Outgoing Webhook」設定）。

### 反例

```go
// ❌ 反例：直接打使用者填的 URL
func sendWebhook(userURL string, payload []byte) error {
    resp, err := http.Post(userURL, "application/json", bytes.NewReader(payload))
    // ...
}
```

使用者可以填 `http://169.254.169.254/latest/meta-data/iam/security-credentials/` 偷你的 AWS IAM credentials；或填 `http://internal-admin.local/users/promote?id=1` 打你的內網管理介面。這就是 Day 10 講的 **SSRF**。

### 防禦

```go
import "net"

var blockedCIDRs = []string{
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", // AWS / GCP metadata
    "::1/128", "fc00::/7", "fe80::/10",
}

func validateWebhookURL(rawURL string) error {
    u, err := url.Parse(rawURL)
    if err != nil { return err }
    if u.Scheme != "https" {
        return errors.New("only https allowed")
    }
    // (1) DNS 解析後再判 IP，避免 DNS rebinding 部分情境
    ips, err := net.LookupIP(u.Hostname())
    if err != nil { return err }
    for _, ip := range ips {
        for _, cidr := range blockedCIDRs {
            _, ipnet, _ := net.ParseCIDR(cidr)
            if ipnet.Contains(ip) {
                return fmt.Errorf("blocked IP: %s", ip)
            }
        }
    }
    return nil
}
```

更完整的做法：
- 強制只允許 `https://`
- 限制 port（443、特定 allowlist）
- 用獨立的 egress proxy（例如 [smokescreen](https://github.com/stripe/smokescreen)）統一過濾
- 不要 follow redirect 到內網（`http.Client.CheckRedirect` 自訂）
- **DNS rebinding 防禦**：要在「實際建立連線時」再次驗證 IP，不是只在 URL 解析時做一次

---

## 七、Checklist：今天就可以審視自家系統

入站 Webhook（別人打進來）：
- [ ] 每個 endpoint 都有驗 HMAC 簽章（不只是 IP 白名單）
- [ ] 簽章驗的是「原始 bytes」，不是反序列化後再 toString
- [ ] 用 **常數時間比較**（`MessageDigest.isEqual` / `hmac.Equal`）
- [ ] 有檢查 timestamp 容忍視窗（建議 5 分鐘）
- [ ] 有用 delivery ID 做冪等性檢查
- [ ] 業務邏輯本身也冪等（不依賴上一層）
- [ ] 失敗時回 4xx / 5xx 不要洩漏 secret 或 hash 細節
- [ ] webhook secret 跟一般 API token 一樣放在 Secret Manager（Day 15）
- [ ] 限制 body 大小（避免 OOM 攻擊）

出站 Webhook（你打去別人那）：
- [ ] 強制 HTTPS
- [ ] URL 經過 IP / CIDR 白名單／黑名單過濾（防 SSRF）
- [ ] 不 follow redirect 到內網
- [ ] 連線時設定 timeout 與 max body size
- [ ] 不要在 webhook payload 中夾帶過多敏感資料（最小化原則）

---

## 八、總結

Webhook 是後端系統的「第二個前門」，但它的安全性常常被視為「第三方的事」。實際上每個 webhook handler 都應該被當作 **未認證的公開 endpoint** 來設計，因為它本來就接受任何來源的 HTTP POST。

三個記憶要點：
1. **驗簽章（HMAC + 常數時間比較）**：證明 body 真的來自合法來源。
2. **防重放（timestamp + delivery ID + 業務冪等）**：證明這是「新的、第一次處理」的請求。
3. **過濾 URL（SSRF 防禦）**：使用者填的 webhook URL 一律當成不可信。

明天 Day 27 我們會接著聊 **多因素驗證（MFA / TOTP）的後端實作** — 從 RFC 6238 的 TOTP 演算法、為什麼驗證碼一定要防重放、到備援碼（backup codes）該怎麼安全地產生與儲存。

---

## 延伸閱讀

- [Stripe — Verifying webhook signatures](https://stripe.com/docs/webhooks/signatures)
- [GitHub — Securing your webhooks](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- [OWASP — Server Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Stripe smokescreen — egress proxy](https://github.com/stripe/smokescreen)
