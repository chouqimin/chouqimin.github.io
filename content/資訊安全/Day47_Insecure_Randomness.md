---
title: "Day 47：不安全的隨機性 (Insecure Randomness / CWE-330)"
date: 2026-06-12
tags: ["密碼學", "CSPRNG", "Randomness"]
---

# Day 47：不安全的隨機性 (Insecure Randomness / CWE-330)

> 「我的 session token 是用 `Math.random()` 產生的，怎麼會出事？」
> —— 出事了，而且通常你不會發現，直到帳號被批次盜走。

---

## 一、為什麼這篇要單獨講？

在前 46 天裡，我們聊過密碼雜湊 (Day04)、JWT (Day05/Day37)、CSRF token (Day03)、MFA (Day27)、WebAuthn (Day28)、Session Fixation (Day33)、Timing Attack (Day32)…
這些防禦機制有一個**共同的基礎假設**：

> 「攻擊者無法猜到我們產生的隨機值。」

只要這個假設崩了，上面所有機制就跟著崩。
而最常見的崩法，就是工程師用了「看起來隨機、其實可預測」的 API。

---

## 二、PRNG 與 CSPRNG 的差別（一張表看懂）

| 項目 | 一般隨機 (PRNG) | 密碼學安全隨機 (CSPRNG) |
|---|---|---|
| 種子 (seed) | 通常是系統時間 | 作業系統 entropy pool（如 `/dev/urandom`） |
| 可預測性 | 只要拿到夠多輸出就能反推狀態 | 即使拿到大量輸出也無法推未來值 |
| 用途 | 遊戲擲骰、A/B 測試分桶、洗牌動畫 | Token、Session ID、Nonce、IV、Salt、密碼重設連結 |
| Java 代表 | `java.util.Random`、`ThreadLocalRandom`、`Math.random()` | `java.security.SecureRandom` |
| Go 代表 | `math/rand`（含 `math/rand/v2`） | `crypto/rand` |

**口訣**：只要這個值「被猜到會造成資安後果」，就一定要用 CSPRNG。

---

## 三、後端常見的災難情境

### 情境 A：密碼重設連結 token

```
GET /reset-password?token=4f9c2a0b... 
```

如果 token 是用 `new Random(System.currentTimeMillis())` 產生的：
攻擊者只要先呼叫「忘記密碼」，記下自己拿到的 token 跟當時的時間，
就能反推 PRNG 內部狀態，**列舉未來幾秒內所有受害者會拿到的 token**。

這不是理論——CVE 史上至少出現過十次以上類似案例。

### 情境 B：Session ID / API Key

可預測的 session ID 等於「免登入大門」。
Tomcat、Jetty 預設都用 `SecureRandom`，**但只要你自己改寫 session 機制，幾乎都會踩雷**。

### 情境 C：JWT 簽章金鑰

很多範例教學寫成 `Keys.secretKeyFor(SignatureAlgorithm.HS256)` 或 `"my-secret-key"`。
正確做法是「從環境變數讀 32 bytes 以上的 CSPRNG 產出值」，且開發機與正式機必須不同。

### 情境 D：UUID

- `UUID.randomUUID()` (Java) → ✅ 內部使用 `SecureRandom`，安全。
- `uuid.NewV4()`（多數 Go 套件如 `google/uuid`） → ✅ 安全。
- **但**：UUID v1 (時間+MAC)、UUID v7 (時間排序) **不是密碼學安全**，不要拿來當 token。

---

## 四、程式碼範例

### ❌ 錯誤示範（Java 1.8 / 21）

```java
import java.util.Random;

public class TokenGenerator {
    // 災難寫法 1：可預測
    public String badToken() {
        Random r = new Random(); // 種子是 System.nanoTime()
        byte[] bytes = new byte[32];
        r.nextBytes(bytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    // 災難寫法 2：更慘，種子寫死
    public String worseToken(long userId) {
        Random r = new Random(userId); // 同一個 user 永遠拿到同一個 token
        return Long.toHexString(r.nextLong());
    }

    // 災難寫法 3：拿來當「亂數」其實是均勻分布而已
    public String mathRandom() {
        return String.valueOf(Math.random()); // 內部也是 java.util.Random
    }
}
```

### ✅ 正確示範（Java 1.8 / 21 通用）

```java
import java.security.SecureRandom;
import java.util.Base64;

public class SecureTokenGenerator {

    // 重用同一個 instance，避免每次 new 都重新 seed（會慢）
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER =
            Base64.getUrlEncoder().withoutPadding();

    /**
     * 產生 URL 安全的 token。
     * 32 bytes = 256 bits 熵，足以對抗暴力枚舉與生日攻擊。
     */
    public static String generateToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }

    /**
     * 產生 16 bytes (128 bits) 的密碼 salt。
     * salt 不必太長，重點是「每筆都不一樣」。
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }
}
```

### ✅ 正確示範（Go）

```go
package token

import (
	"crypto/rand"
	"encoding/base64"
)

// GenerateToken 回傳 URL-safe、長度 32 bytes 的隨機 token。
// 注意是 crypto/rand，不是 math/rand。
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// rand.Read 在現代 OS 上幾乎不會失敗，但仍要回傳錯誤
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
```

### ❌ Go 的反面教材

```go
import (
	"math/rand"
	"time"
)

func badToken() string {
	rand.Seed(time.Now().UnixNano()) // Go 1.20+ 已不需要 Seed，但這寫法本身就錯
	b := make([]byte, 32)
	rand.Read(b) // math/rand.Read 不是密碼學安全的
	return string(b)
}
```

> Go 1.20 之後，`math/rand` 全域 source 已改為自動 seed，但**仍然不是 CSPRNG**。
> 任何安全相關的隨機值，一律改用 `crypto/rand`。

---

## 五、`SecureRandom` 在 Java 上的常見地雷

1. **不要呼叫 `setSeed(long)`**
   ```java
   SecureRandom sr = new SecureRandom();
   sr.setSeed(123L); // ❌ 這只會「補充」熵，但若是用 SHA1PRNG 會被完全控制
   ```
   想要可重現的測試，請用一般 `Random`，不要在 production 加 seed。

2. **`SecureRandom.getInstance("SHA1PRNG")` 不要再用**
   舊版 Android 與部分 JDK 上，`SHA1PRNG` 有歷史漏洞（CVE-2013-7372）。
   直接用 `new SecureRandom()`，會自動選擇平台最佳實作（Linux 上是 NativePRNG → `/dev/urandom`）。

3. **首次呼叫可能會阻塞**
   `/dev/random` 在 entropy 不足時會 block；container/雲端機在剛開機時最容易出事。
   解法：JVM 加參數 `-Djava.security.egd=file:/dev/./urandom`（注意中間的 `.`，避免被 JDK 自動覆寫）。

---

## 六、後端工程師的 Checklist

抄一份貼到團隊 wiki：

- [ ] Session ID、CSRF token、密碼重設連結 → 用 CSPRNG，至少 128 bits 熵。
- [ ] Password salt → 用 CSPRNG，每筆獨立，至少 128 bits。
- [ ] JWT 簽章金鑰 (HS256/HS512) → CSPRNG 產 32 bytes 以上，存環境變數或 KMS（見 Day15）。
- [ ] API key → CSPRNG，且顯示時加 prefix（如 `sk_live_`）方便偵測誤外洩。
- [ ] 不要把 `Random`、`math/rand`、`Math.random()` 用在任何「猜到會出事」的場合。
- [ ] UUID 當 token 時，只用 v4；v1/v7 用來排序可以，但不要當機密。
- [ ] 程式碼掃描 (SAST) 規則：偵測 `java.util.Random`、`Math.random()`、`math/rand` 出現在 security 相關檔案的呼叫。

---

## 七、一句話總結

> **「隨機」不等於「安全」。**
> 凡是被猜到會造成資安後果的值，請務必使用 `SecureRandom` (Java) 或 `crypto/rand` (Go)。

---

## 延伸閱讀

- CWE-330: Use of Insufficiently Random Values
- OWASP ASVS V6 — Cryptography Requirements
- RFC 4086 — Randomness Requirements for Security
- 前文：Day04 密碼雜湊、Day05 JWT、Day32 Timing Attack、Day37 JWT Algorithm Confusion

---

明天預告：**Day 48 — HMAC 簽章驗證與 API Request Signing**
（為什麼 webhook 驗章不能用 `equals()`？我們會在範例裡看到怎麼把今天的 CSPRNG、Day32 的固定時間比較、以及 Day26 的 webhook 安全，組合成一條完整防線。）
