---
title: "Day 48：HMAC 簽章驗證與 API Request Signing"
date: 2026-06-12
tags: ["HMAC", "API 安全", "Webhook", "密碼學"]
---

# Day 48：HMAC 簽章驗證與 API Request Signing

> 「我的 webhook 有驗 signature 啊，我用 `signature.equals(expected)` 比對的。」
> —— 恭喜，你同時踩中了 Day32 的 Timing Attack，而且可能連簽什麼內容都簽錯了。

（接續 Day47 預告：今天把 **Day47 的 CSPRNG**、**Day32 的固定時間比較**、**Day26 的 Webhook 安全**組合成一條完整防線。）

---

## 一、為什麼需要 Request Signing？

HTTPS 已經保證「傳輸過程」不被竄改，但它**無法回答這兩個問題**：

1. **這個請求真的是「他」發的嗎？**（來源驗證）
   Webhook 的 endpoint 是公開 URL，任何人都能對它 POST 假資料。
2. **內容在「應用層」有沒有被動過？**（完整性）
   經過 proxy、API gateway、訊息佇列重送之後，你拿到的還是原始內容嗎？

HMAC (Hash-based Message Authentication Code) 就是解這兩題的標準工具：
發送方與接收方共享一把密鑰，發送方對「訊息內容」計算 `HMAC-SHA256(secret, message)` 附在 header；接收方用同一把密鑰重算一次，比對是否一致。

> 攻擊者沒有密鑰 → 改了內容就算不出正確簽章 → 偽造與竄改同時被擋下。

業界實例：Stripe 的 `Stripe-Signature`、GitHub 的 `X-Hub-Signature-256`、AWS 的 SigV4，核心都是 HMAC。

---

## 二、HMAC 不是「把 secret 接在字串後面再 hash」

常見錯誤：

```java
// ❌ 千萬不要這樣自製簽章
String sig = sha256(secret + payload);
```

這種寫法會被 **Length Extension Attack** 打穿：SHA-256 屬於 Merkle–Damgård 結構，攻擊者拿到 `sha256(secret + payload)` 後，**不需要知道 secret** 就能算出 `sha256(secret + payload + 惡意附加內容)` 的合法雜湊。

HMAC 的內部結構（`H(K⊕opad ‖ H(K⊕ipad ‖ m))`）專門設計來免疫這個攻擊。
**結論：永遠用標準函式庫的 HMAC，不要自己拼接。**

---

## 三、完整實作：簽什麼、怎麼簽

一個健全的簽章方案要簽的不只是 body：

```
待簽字串 = HTTP方法 + "\n" + 路徑 + "\n" + 時間戳 + "\n" + body
```

- **時間戳**：防重放攻擊 (Replay Attack)。沒有它，攻擊者側錄一個合法請求後可以無限重送。
- **方法與路徑**：防止把「對 A 資源的合法請求」重放到 B 資源上。

### Java 範例（Java 8 / 21 通用，零外部依賴）

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class HmacSigner {

    private static final long MAX_CLOCK_SKEW_SECONDS = 300; // 5 分鐘

    /** 發送方：計算簽章 */
    public static String sign(byte[] secret, String method, String path,
                              long timestamp, String body) throws Exception {
        String message = method + "\n" + path + "\n" + timestamp + "\n" + body;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        byte[] raw = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return toHex(raw); // 約定用小寫 hex，雙方要一致
    }

    /** 接收方：驗證簽章 */
    public static boolean verify(byte[] secret, String method, String path,
                                 long timestamp, String body,
                                 String receivedSig) throws Exception {
        // 1. 先檢查時間戳，過期直接拒絕（防 Replay）
        long now = System.currentTimeMillis() / 1000;
        if (Math.abs(now - timestamp) > MAX_CLOCK_SKEW_SECONDS) {
            return false;
        }
        // 2. 重算簽章
        String expected = sign(secret, method, path, timestamp, body);
        // 3. ✅ 固定時間比較（Day32），絕對不要用 equals()
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                receivedSig.getBytes(StandardCharsets.UTF_8));
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
```

> Java 17+ 可以用 `HexFormat.of().formatHex(raw)` 取代手寫 `toHex`；上面寫法是為了 Java 8 也能直接用。

### Go 範例

```go
package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"time"
)

const maxClockSkew = 300 // 秒

// Sign 發送方：計算簽章
func Sign(secret []byte, method, path string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "%s\n%s\n%d\n%s", method, path, ts, body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify 接收方：驗證簽章
func Verify(secret []byte, method, path string, ts int64, body []byte, receivedSig string) bool {
	// 1. 時間戳檢查（防 Replay）
	if math.Abs(float64(time.Now().Unix()-ts)) > maxClockSkew {
		return false
	}
	// 2. 重算簽章
	expected := Sign(secret, method, path, ts, body)
	// 3. ✅ hmac.Equal 是固定時間比較（內部就是 subtle.ConstantTimeCompare）
	return hmac.Equal([]byte(expected), []byte(receivedSig))
}
```

---

## 四、接收端的三大地雷

### 地雷 1：用一般字串比較驗簽（Day32 復習）

```java
// ❌ equals() 會在第一個不同字元就提早 return
if (expected.equals(receivedSig)) { ... }

// ✅ Java：MessageDigest.isEqual()
// ✅ Go：hmac.Equal()
```

攻擊者可以靠回應時間差，一個字元一個字元「猜」出正確簽章。這就是 Day47 結尾問的「為什麼 webhook 驗章不能用 `equals()`」的答案。

### 地雷 2：用「解析後再序列化」的 body 驗簽

```java
// ❌ 框架把 JSON 轉成物件再轉回字串，欄位順序/空白/Unicode 跳脫都可能變
String body = objectMapper.writeValueAsString(parsedDto);

// ✅ 必須拿「原始 raw bytes」驗簽
```

Spring 裡用 `ContentCachingRequestWrapper` 或在 Filter 層先讀出 raw body；Go 裡在 middleware 用 `io.ReadAll(r.Body)` 後以 `io.NopCloser(bytes.NewReader(raw))` 塞回去。**驗簽永遠發生在解析之前**——驗不過的請求連 JSON parser 都不該碰（順便降低 Day14 反序列化、Day31 ReDoS 的攻擊面）。

### 地雷 3：忘記防 Replay

簽章正確 ≠ 請求新鮮。完整防線：

1. 時間戳容差 ±5 分鐘（上面範例已做）。
2. 更嚴格的場景（如扣款 API）：再加一個 **nonce**——用 **Day47 的 CSPRNG** 產生，接收方存進 Redis `SETNX nonce 1 EX 600`，重複出現即拒絕。

---

## 五、密鑰管理（串回 Day15 / Day47）

- 簽章密鑰用 CSPRNG 產生，**至少 32 bytes**（`SecureRandom` / `crypto/rand`，見 Day47）。
- 存放在環境變數或 KMS / Secrets Manager（見 Day15），不要進 git。
- 支援**多把密鑰並存**（key rotation）：header 帶 `key_id`，驗證時查表取對應密鑰。Stripe / GitHub 都這樣設計，輪替時新舊密鑰可短暫共存。
- 每個對接方一把獨立密鑰，洩漏時影響範圍最小。

---

## 六、後端工程師的 Checklist

- [ ] Webhook / 內部 API 簽章一律用標準 HMAC-SHA256，不自製 `hash(secret + msg)`。
- [ ] 簽章內容包含：HTTP 方法、路徑、時間戳、raw body。
- [ ] 驗簽用固定時間比較：Java `MessageDigest.isEqual()`、Go `hmac.Equal()`。
- [ ] 用 raw bytes 驗簽，且在 JSON 解析「之前」驗。
- [ ] 時間戳容差 ≤ 5 分鐘；高風險操作加 nonce + Redis 去重。
- [ ] 密鑰 ≥ 32 bytes、CSPRNG 產生、存 KMS、支援 key rotation（header 帶 key_id）。
- [ ] 驗簽失敗回 401，**不要在錯誤訊息透露期望簽章或失敗原因細節**。

---

## 七、一句話總結

> **HTTPS 保護「路上」，HMAC 保護「來源與內容」。**
> 簽要簽 raw body + 時間戳，驗要用固定時間比較，密鑰要用 CSPRNG 並可輪替。

---

## 延伸閱讀

- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication
- Stripe Docs — Checking Webhook Signatures
- GitHub Docs — Validating Webhook Deliveries (`X-Hub-Signature-256`)
- AWS Signature Version 4 簽章流程
- 前文：Day15 Secrets Management、Day26 Webhook Security、Day32 Timing Attack、Day47 Insecure Randomness

---

明天預告：**Day 49 — Mass Assignment 之外的 API 授權陷阱：BFLA（Broken Function Level Authorization）**
（Day07 講過 IDOR 是「物件層級」授權失效，明天講「功能層級」：一般使用者直接打 `/admin/users` 這類管理 API 為什麼常常成功？我們會用 Spring Security 與 Go middleware 示範如何以「預設拒絕」設計路由授權。）
