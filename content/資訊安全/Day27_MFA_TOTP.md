---
title: "Day 27：多因素驗證 MFA／TOTP 後端實作 — 從 RFC 6238 到防重放、備援碼"
date: 2026-05-23
tags: ["MFA", "TOTP", "認證"]
---

# Day 27：多因素驗證 MFA／TOTP 後端實作 — 從 RFC 6238 到防重放、備援碼

> 後端工程師資安系列 — Day 27
> 日期：2026-05-23

## 一、前情提要

在 Day 04 我們學會了正確雜湊密碼（Argon2id／bcrypt），Day 05 比較了 Session 與 JWT，Day 06 加上了暴力破解保護（rate limit、帳號鎖定），Day 24 講了 OAuth2／OIDC 的常見地雷。

但這些都還停留在「**一個東西**」的驗證 — 也就是「你知道的東西」（密碼）。

> 只要密碼洩漏，攻擊者就能登入。

而密碼洩漏的方式多到數不清：撞庫（credential stuffing）、釣魚、鍵盤側錄、瀏覽器外掛偷取、第三方網站 DB 外洩、員工社交工程⋯⋯。根據 Microsoft 的研究，**啟用 MFA 可以擋下 99.2% 的帳號攻擊**。

今天我們就站在後端工程師的角度，把 **MFA（Multi-Factor Authentication，多因素驗證）** 講清楚 — 特別是最常見、最容易自己實作的 **TOTP（Time-based One-Time Password）**。

---

## 二、什麼是 MFA？三大要素

MFA 的核心觀念是「需要兩個以上不同類別的證據」才能登入：

| 類別 | 英文 | 例子 |
| --- | --- | --- |
| 你知道的 | Something you know | 密碼、PIN、安全問題 |
| 你擁有的 | Something you have | 手機（TOTP App、簡訊）、實體 Key（YubiKey、FIDO2） |
| 你本身的 | Something you are | 指紋、Face ID、虹膜 |

注意：**密碼 + 安全問題 ≠ MFA**，因為都是「你知道的」。
**密碼 + 手機 TOTP = MFA**，因為跨了兩個類別。

### MFA 常見實作的安全度比較

| 方式 | 安全度 | 缺點 |
| --- | --- | --- |
| SMS 簡訊 OTP | ⭐⭐ | 容易被 SIM swap、SS7 攻擊、釣魚轉發；NIST 已不建議用於高安全場景 |
| Email OTP | ⭐⭐ | 信箱被盜就一起淪陷；延遲不可控 |
| TOTP（Google Authenticator、Authy） | ⭐⭐⭐⭐ | 仍可被釣魚（即時轉發），但離線、無 SIM 風險 |
| Push 通知（Duo、Microsoft Authenticator） | ⭐⭐⭐⭐ | 防釣魚較好，但有「MFA Fatigue」攻擊 |
| FIDO2／WebAuthn（YubiKey、Passkey） | ⭐⭐⭐⭐⭐ | 體驗最好、最防釣魚，但實作較複雜、舊瀏覽器支援有限 |

對大多數產品來說，**TOTP 是性價比最高的入門選擇** — 不需付費簡訊閘道、沒有 SIM 卡風險、使用者用 Google Authenticator／1Password／Authy 都能掃。

---

## 三、TOTP 怎麼運作？（RFC 6238 一頁懂）

TOTP 是建立在 HOTP（RFC 4226，HMAC-based OTP）之上的：

```
TOTP(K, T) = HOTP(K, T)
其中 T = floor((Now - T0) / X)
```

- **K**：伺服器與使用者裝置共享的密鑰（一般 20 bytes，Base32 編碼後給使用者掃 QR code）
- **T0**：起算時間，通常用 Unix epoch（0）
- **X**：時間窗，標準是 30 秒
- **HOTP**：把計數器 T 用 HMAC-SHA1 與 K 算出 hash，再用「Dynamic Truncation」抽出 6 位數字

關鍵點：

1. **K 只在第一次綁定時雙方共享一次**（透過 QR code 或手動輸入），之後不會再傳。
2. 每 30 秒雙方根據同一個 K 算出同一組 6 位數。
3. 攻擊者沒有 K，就算看到歷史的 OTP 也無法預測下一組。

換句話說：**TOTP 不需要連網**，手機關飛航模式也能產生正確的 6 位數，因為它只依賴 K 跟「時間」。

QR code 內容是一個 URI，叫 `otpauth://`：

```
otpauth://totp/MyApp:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp&algorithm=SHA1&digits=6&period=30
```

---

## 四、後端要做哪些事？整體流程圖

```
[綁定階段]
   使用者點「啟用 MFA」
        │
        ▼
   後端產生 secret（20 bytes random）
        │
        ▼
   存「pending_secret」到 user 表（**加密儲存**）
        │
        ▼
   回傳 otpauth:// URI／QR code 給前端
        │
        ▼
   使用者用 Google Authenticator 掃描
        │
        ▼
   使用者輸入當下 6 位數驗證
        │
        ▼
   後端驗證通過 → 把 pending_secret 移到 confirmed_secret
                  → 產生 8~10 組備援碼（單次使用、雜湊存）
                  → 回傳備援碼給使用者抄下來

[登入階段]
   帳密驗證通過 (Day 04)
        │
        ▼
   檢查使用者是否啟用 MFA
        │
        ▼
   要求輸入 6 位 TOTP（或備援碼）
        │
        ▼
   驗證通過 → 發 session/JWT
   驗證失敗 → rate limit + 記錄 audit log (Day 06, Day 16)
```

---

## 五、Java 21（Spring Boot 3）實作範例

我們用 [`com.eatthepath:java-otp`](https://github.com/jchambers/java-otp) 這個輕量函式庫 — 它由 RFC 標準實作，零依賴，且 2024 年仍有維護。

> 注意：請務必到 [Maven Central](https://central.sonatype.com/artifact/com.eatthepath/java-otp) 確認最新版本，避免使用已棄用的舊版 `aerogear-otp-java`。

### Maven

```xml
<dependency>
    <groupId>com.eatthepath</groupId>
    <artifactId>java-otp</artifactId>
    <version>0.4.0</version>
</dependency>
```

### 5.1 產生 secret 與 QR code URI

```java
import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

public class TotpService {

    private static final String ISSUER = "MyApp";
    private static final Duration TIME_STEP = Duration.ofSeconds(30);

    /** 產生 20 bytes 的 HMAC-SHA1 key（標準 TOTP）。 */
    public SecretKey generateSecret() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("HmacSHA1");
        kg.init(160); // 160 bits = 20 bytes
        return kg.generateKey();
    }

    /** 把 secret 轉成 Base32 給 Authenticator app 掃。 */
    public String toBase32(SecretKey key) {
        // Authenticator 認的是 Base32（不是 Base64）。可用 commons-codec 的 Base32：
        return new org.apache.commons.codec.binary.Base32()
                .encodeToString(key.getEncoded())
                .replace("=", ""); // 去掉 padding，提升 UX
    }

    /** 產生 otpauth:// URI，前端用 qrcode.js 或後端用 ZXing 轉成 QR code。 */
    public String buildOtpAuthUri(String userEmail, SecretKey key) {
        String secret = toBase32(key);
        String label = URLEncoder.encode(ISSUER + ":" + userEmail, StandardCharsets.UTF_8);
        return "otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30"
                .formatted(label, secret, URLEncoder.encode(ISSUER, StandardCharsets.UTF_8));
    }
}
```

### 5.2 驗證 OTP（含時間窗容錯與重放保護）

```java
import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;

public class TotpVerifier {

    private static final Duration TIME_STEP = Duration.ofSeconds(30);
    private static final int WINDOW = 1; // 容許前後各 1 個時間步（共 ±30 秒）

    private final TimeBasedOneTimePasswordGenerator generator;
    private final UsedCodeRepository usedCodeRepo;

    public TotpVerifier(UsedCodeRepository usedCodeRepo) throws Exception {
        this.generator = new TimeBasedOneTimePasswordGenerator(TIME_STEP);
        this.usedCodeRepo = usedCodeRepo;
    }

    public boolean verify(long userId, SecretKey key, String inputCode) throws Exception {
        // 1. 格式檢查（防注入、防 timing attack）
        if (inputCode == null || !inputCode.matches("\\d{6}")) {
            return false;
        }

        Instant now = Instant.now();

        // 2. 允許前後 WINDOW 個時間步，解決使用者手機與伺服器時間誤差
        for (int i = -WINDOW; i <= WINDOW; i++) {
            Instant checkTime = now.plus(TIME_STEP.multipliedBy(i));
            int expected = generator.generateOneTimePassword(key, checkTime);
            String expectedStr = "%06d".formatted(expected);

            // 3. 用常數時間比較，防 timing attack
            if (MessageDigest.isEqual(
                    expectedStr.getBytes(StandardCharsets.UTF_8),
                    inputCode.getBytes(StandardCharsets.UTF_8))) {

                // 4. 防重放：同一個 (userId, timeStep) 只能用一次
                long timeStep = checkTime.getEpochSecond() / 30;
                if (usedCodeRepo.markUsedIfAbsent(userId, timeStep)) {
                    return true;
                } else {
                    // 已經用過了 — 攔下來
                    return false;
                }
            }
        }
        return false;
    }
}
```

`UsedCodeRepository.markUsedIfAbsent` 用 Redis 的 `SET NX EX 90` 實作最簡單：

```java
public boolean markUsedIfAbsent(long userId, long timeStep) {
    String key = "totp:used:" + userId + ":" + timeStep;
    Boolean ok = redisTemplate.opsForValue().setIfAbsent(key, "1", Duration.ofSeconds(90));
    return Boolean.TRUE.equals(ok);
}
```

---

## 六、Go 實作範例

Go 推薦使用 [`github.com/pquerna/otp`](https://github.com/pquerna/otp)，這是 Go 生態最主流的 TOTP／HOTP 套件，截至 2025 仍持續維護（v1.4.0）。

```bash
go get github.com/pquerna/otp/totp
```

### 6.1 產生 secret 與 QR code

```go
package mfa

import (
	"bytes"
	"crypto/subtle"
	"image/png"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const issuer = "MyApp"

// GenerateSecret 為使用者建立新的 TOTP secret。
func GenerateSecret(userEmail string) (*otp.Key, []byte, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: userEmail,
		Period:      30,
		SecretSize:  20, // 20 bytes = 160 bits
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      otp.DigitsSix,
	})
	if err != nil {
		return nil, nil, err
	}

	// 直接產生 QR code PNG（200x200）
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, nil, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, nil, err
	}
	return key, buf.Bytes(), nil
}
```

`key.Secret()` 已經是 Base32 字串，可以直接存進 DB（記得加密 — 見第七章）。
`key.URL()` 則是 `otpauth://...` 字串，給前端自己畫 QR 也行。

### 6.2 驗證 OTP（含時間窗與重放）

```go
package mfa

import (
	"context"
	"errors"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
)

var ErrInvalidCode = errors.New("invalid totp code")
var ErrReplay = errors.New("totp code already used")

type Verifier struct {
	rdb *redis.Client
}

func NewVerifier(rdb *redis.Client) *Verifier {
	return &Verifier{rdb: rdb}
}

func (v *Verifier) Verify(ctx context.Context, userID int64, secret, code string) error {
	// 1. 格式檢查
	if len(code) != 6 {
		return ErrInvalidCode
	}

	now := time.Now()

	// 2. 帶時間窗的驗證（前後各 30 秒，共 ±1 step）
	valid, err := totp.ValidateCustom(code, secret, now, totp.ValidateOpts{
		Period:    30,
		Skew:      1, // 容忍 1 個時間步
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !valid {
		return ErrInvalidCode
	}

	// 3. 防重放：把這次成功的 timeStep 記到 Redis，存活 90 秒
	timeStep := now.Unix() / 30
	key := fmt.Sprintf("totp:used:%d:%d", userID, timeStep)
	set, err := v.rdb.SetNX(ctx, key, 1, 90*time.Second).Result()
	if err != nil {
		return err
	}
	if !set {
		return ErrReplay
	}
	return nil
}
```

注意 `totp.ValidateCustom` 內部已經用 `subtle.ConstantTimeCompare`，不會有 timing attack 風險，這是選擇成熟函式庫的好處。

---

## 七、後端必做的 8 項安全要點（最容易被漏掉）

### ⚠️ 1. secret **絕對不能明文存在資料庫**

如果 DB 外洩，所有人的 TOTP secret 都裸奔。應該用 KMS／Vault 加密：

```java
// Java（用 AWS KMS 或 envelope encryption）
byte[] encrypted = kmsClient.encrypt(secret.getEncoded());
user.setTotpSecretEncrypted(encrypted);
```

```go
// Go
encrypted, err := kms.Encrypt(ctx, secretBytes)
```

### ⚠️ 2. 重放保護（同一個 6 位數不能用兩次）

如第五、六章範例所示，用 Redis `SETNX` 把 `(userId, timeStep)` 記下來。
**沒做這個的話**，攻擊者在 30 秒內看到使用者輸入過的 OTP（網管、釣魚轉發），就能也跟著用一次。

### ⚠️ 3. 時間窗（skew）不要設太大

很多人為了「體驗好」設 `skew=5`（容忍 ±2.5 分鐘），這等於把暴力破解的空間從 10⁶ 變成 10⁶ / 11，安全性下降一個量級。
**建議 skew = 1（±30 秒）足夠了**，伺服器自己跑 NTP 同步比較重要。

### ⚠️ 4. MFA 驗證也要 rate limit

別讓人慢慢爆 6 位數。建議：每使用者每分鐘最多 5 次失敗，超過鎖 15 分鐘。
參考 Day 06 的暴力破解防護。

```go
if attempts, _ := rdb.Incr(ctx, "mfa:fail:"+userID).Result(); attempts > 5 {
    rdb.Expire(ctx, "mfa:fail:"+userID, 15*time.Minute)
    return ErrTooManyAttempts
}
```

### ⚠️ 5. 備援碼（Recovery Codes）必須雜湊儲存

使用者手機掉了怎麼辦？要在綁定時產生 8~10 組單次使用的備援碼（例如 `4f3a-9c2d`），**用 Argon2id／bcrypt 雜湊後存進 DB**（同 Day 04 的密碼處理方式），不要明文。

```go
codes := make([]string, 10)
for i := range codes {
    codes[i] = randomCode() // e.g. "a3f2-9c4e"
    hashed, _ := argon2id.CreateHash(codes[i], argon2id.DefaultParams)
    db.Insert("INSERT INTO recovery_codes(user_id, hash) VALUES (?, ?)", userID, hashed)
}
// 把 codes 一次性顯示給使用者，警告：離開頁面就看不到了
```

### ⚠️ 6. 綁定時要先「驗證一次」才能正式啟用

很多新手寫法：使用者按「啟用」就直接把 secret 設成已啟用 — 結果使用者其實沒掃成功，下次登入就被鎖死。
**正確流程**：先存到 `pending_secret`，使用者輸入第一組 6 位數驗證通過後才搬到 `confirmed_secret`。

### ⚠️ 7. 關閉 MFA 也要再驗證一次

別讓「取得 session cookie」=「能關 MFA」。
**關閉 MFA 前要求重新輸入密碼 + 一次 TOTP**，否則 XSS 或 session hijack 就直接繞過 MFA 了。

### ⚠️ 8. 不要在錯誤訊息洩漏「帳號是否存在」或「MFA 是否啟用」

```
❌ 不好："此帳號未啟用 MFA"     ← 洩漏使用者狀態
❌ 不好："密碼錯誤"             ← 洩漏帳號存在
✅ 較好："帳號或驗證資訊不正確"
```

否則攻擊者可以用這個訊息列舉哪些帳號還沒啟用 MFA，當作優先攻擊目標。

---

## 八、常見的真實案例

| 案例 | 漏洞 | 對策 |
| --- | --- | --- |
| Reddit 2018 員工帳號被入侵 | SMS OTP 被 SIM swap | 改用 TOTP／硬體 Key |
| 2022 Uber 員工被 MFA Fatigue 攻擊 | Push 通知瘋狂連發 | 改用 number matching、限制每分鐘 push 次數 |
| 某電商 MFA 驗證 endpoint 沒 rate limit | 攻擊者枚舉 10⁶ 可能性，平均 50 萬次就破 | 加上 5 次失敗鎖定 |
| 某 SaaS 「重設 MFA」只需要 email 連結 | 信箱被盜 = MFA 形同虛設 | 改用「需要原本的密碼 + 客服人工驗證」 |

---

## 九、測試與驗收清單（Checklist）

實作完上線前，請逐項打勾：

- [ ] secret 在 DB 是**加密**儲存（不是明文 Base32）
- [ ] 綁定流程需要使用者輸入一次 OTP 才會正式啟用（`pending_secret` → `confirmed_secret`）
- [ ] 同一個 6 位數**不能在時間窗內被用兩次**（Redis SETNX 已驗證）
- [ ] OTP 驗證的字串比較用**常數時間**（`MessageDigest.isEqual` / `subtle.ConstantTimeCompare`）
- [ ] 時間窗 `skew ≤ 1`，伺服器有跑 NTP
- [ ] MFA 驗證 endpoint 有**rate limit**（建議 5 次／分鐘）
- [ ] 提供 **8~10 組備援碼**，且**雜湊儲存**
- [ ] 關閉 MFA、變更 secret 前要求**重新驗證密碼 + OTP**
- [ ] 登入失敗訊息**不洩漏帳號是否存在、是否啟用 MFA**
- [ ] 所有 MFA 啟用／關閉／驗證失敗事件都寫入 audit log（Day 16）

---

## 十、明日預告

明天我們會講 **Day 28：FIDO2 / WebAuthn — Passkey 是怎麼把 MFA 變成「無密碼」？**
TOTP 雖然好，但仍會被即時釣魚（如 evilginx2）攔截。FIDO2 透過「綁定 origin」的密碼學機制，是目前唯一能擋下進階釣魚的方案，現在 Apple／Google／Microsoft 也都已支援 Passkey。我們會手把手帶後端工程師走完 WebAuthn 的 `attestation` 與 `assertion` 流程。

---

## 參考資料

- RFC 6238 — TOTP: Time-Based One-Time Password Algorithm: https://datatracker.ietf.org/doc/html/rfc6238
- RFC 4226 — HOTP: An HMAC-Based One-Time Password Algorithm: https://datatracker.ietf.org/doc/html/rfc4226
- NIST SP 800-63B — Digital Identity Guidelines（已不建議 SMS OTP）
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- `pquerna/otp` (Go): https://github.com/pquerna/otp
- `eatthepath/java-otp` (Java): https://github.com/jchambers/java-otp
