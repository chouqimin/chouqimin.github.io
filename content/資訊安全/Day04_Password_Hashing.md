---
title: "Day 04 — 密碼安全與雜湊儲存（Password Hashing）"
date: 2026-04-24
tags: ["密碼學", "認證", "Password"]
---

# Day 04 — 密碼安全與雜湊儲存（Password Hashing）

> 日期：2026-04-24
> 適合對象：後端工程師初學者
> 主題難度：★★★☆☆（身份驗證的第一道防線）

---

## 一、為什麼這個主題這麼重要？

前三天我們介紹了 SQL Injection、XSS、CSRF，這些都是「攻擊者從外面打進來」的漏洞。但即使這三種攻擊全部被你擋下來，**只要你的密碼欄位沒存好，一次資料庫外洩，所有使用者就全完了**。

近年最知名的幾次事件：

- 2012 年 LinkedIn 外洩約 650 萬筆密碼雜湊（2016 年更揭露完整規模達約 1.17 億筆），因為只用 **SHA-1** 而且**沒加鹽**，幾天內絕大多數就被破解。
- 2013 年 Adobe 外洩 1.5 億筆，更糟——他們用的是**可逆的對稱加密**，而且密碼提示欄位是明碼。
- 即使到今天，還是常常在 code review 看到 `MD5(password)` 就寫入資料庫的程式碼。

身為後端工程師，你幾乎一定會碰到「使用者註冊、登入」這種功能，**密碼怎麼存**是第一個必須答對的問題。

一句話先記住：

> **密碼絕對不要加密（encrypt），請用「雜湊 + 鹽」（hash + salt），並且用為密碼設計的慢演算法（bcrypt / Argon2 / scrypt）。**

---

## 二、三個最常見的錯誤做法

### 錯誤 1：明文儲存

```sql
INSERT INTO users(email, password) VALUES ('alice@x.com', 'p@ssw0rd');
```

只要資料庫一被 dump，全部帳號都洩露。而且許多人會在多個網站用相同密碼，受害範圍會波及其他服務。**這是職業生涯絕對不能犯的錯。**

### 錯誤 2：用「加密」存密碼（可逆）

```java
// 絕對不要這樣做
String encrypted = AES.encrypt(password, SECRET_KEY);
```

加密是**可逆**的，這代表：

- 你的程式必須持有一把「解密金鑰」。
- 只要攻擊者入侵到能讀程式設定（例如 server），連同金鑰一起拿走，就能把所有密碼還原成明文。
- 這正是 2013 Adobe 事件重蹈的覆轍。

**密碼驗證本來就不需要還原，所以也就不該用加密。**

### 錯誤 3：用「通用雜湊」（MD5 / SHA-1 / SHA-256）

```java
String hash = sha256(password); // ← 很多人第一直覺會這樣寫
```

這比前兩者好，但仍然不安全，原因：

1. **彩虹表（Rainbow Table）攻擊**：網路上有預先算好 TB 級的「常見密碼 → SHA256」對照表，一查即破。
2. **GPU 爆破太快**：一張中階顯卡一秒可以算**上百億次** SHA-256。使用者的密碼若是 8 碼英文小寫＋數字，幾小時就能窮舉。
3. **相同密碼產生相同雜湊**：資料庫一看就知道誰跟誰用相同密碼。

MD5 / SHA-1 / SHA-256 是**為了「快」而設計**的雜湊，但「快」對密碼儲存來說正好是缺點——我們要的是讓攻擊者算得非常慢。

---

## 三、正確觀念：Salt + 慢雜湊

### 3.1 Salt（鹽）

Salt 是**每個使用者都不同的一串隨機值**，在雜湊前和密碼一起混進去。

```
stored_hash = slow_hash(password + salt)
資料庫儲存：{ salt, stored_hash }
```

Salt 的作用：

- **破解彩虹表**：每個使用者的 salt 不同，攻擊者必須為每個帳號單獨計算，預先算好的表沒用了。
- **隱藏「相同密碼」的事實**：即使兩個使用者都用 `123456`，因為 salt 不同，資料庫裡的 hash 也會完全不同。

⚠️ Salt **不是秘密**，和 hash 一起存進資料庫沒關係。重點是「每人不同 + 夠隨機（建議至少 16 bytes）」。

### 3.2 為什麼要「慢」？

密碼驗證只在「使用者登入」的那一下執行一次，花 100ms 使用者根本感覺不到。但對攻擊者來說，他要窮舉上億次密碼，**每次慢 100ms**意味著他的破解時間從幾小時變成幾百年。

這就是 **bcrypt / scrypt / Argon2** 的核心設計哲學：**刻意把雜湊做得很慢，而且成本可調。**

| 演算法 | 設計年代 | 特點 |
| :-- | :-- | :-- |
| **bcrypt** | 1999 | 最成熟、函式庫最齊全，**目前絕大多數後端的第一選擇** |
| **scrypt** | 2009 | 額外要求大量記憶體，對抗 GPU/ASIC 更好 |
| **Argon2** | 2015 | 密碼雜湊競賽 (PHC) 冠軍，**目前最推薦**的新專案選擇 |

**懶人結論**：
- 既有專案已經用 **bcrypt**：繼續用，沒問題。
- 新專案：優先用 **Argon2id**，次選 **bcrypt**。
- **絕對不要**自己發明或只用 MD5/SHA-x 存密碼。

---

## 四、Java 實作範例

### 4.1 使用 Spring Security 的 BCryptPasswordEncoder（最常見）

```java
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class PasswordService {

    // cost factor = 12，大約每次雜湊 ~250ms（2024 年的機器）
    // 之後硬體變快時可以調高，bcrypt 會把 cost 記在 hash 字串裡
    private final PasswordEncoder encoder = new BCryptPasswordEncoder(12);

    /** 註冊時：把使用者輸入的密碼 hash 後存進資料庫 */
    public String hashForStorage(String rawPassword) {
        return encoder.encode(rawPassword);
        // 回傳值長這樣：$2a$12$N9qo8uLOickgx2ZMRZo...
        // 已包含 algorithm / cost / salt / hash，不需要另外存 salt 欄位
    }

    /** 登入時：驗證密碼是否正確 */
    public boolean verify(String rawPassword, String storedHash) {
        return encoder.matches(rawPassword, storedHash);
    }
}
```

重點：

1. **不要自己生 salt**，BCryptPasswordEncoder 會自動用安全的亂數產生器（`SecureRandom`）產生。
2. **只存 `encode()` 的回傳值**即可（那串 `$2a$12$...` 已經把演算法、cost、salt、hash 全包在一起）。
3. **驗證一定用 `encoder.matches()`**，它內部做的是 constant-time 比對，避免 timing attack（下面會講）。

### 4.2 使用 Argon2（新專案推薦）

Spring Security 也內建 `Argon2PasswordEncoder`：

```java
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

// 參數參考 OWASP 2024 建議：saltLen=16, hashLen=32,
// parallelism=1, memory=19456 KiB (~19MB), iterations=2
PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 1, 19456, 2);

String hash = encoder.encode("p@ssw0rd");
boolean ok  = encoder.matches("p@ssw0rd", hash);
```

> 提示：Argon2PasswordEncoder 需要額外引入 `bouncycastle` 相關依賴。Spring Security 文件都有列出。

### 4.3 不用 Spring 的場景（Java 21 + jBCrypt）

```java
// Maven: <dependency>org.mindrot:jbcrypt:0.4</dependency>
import org.mindrot.jbcrypt.BCrypt;

String hash = BCrypt.hashpw("p@ssw0rd", BCrypt.gensalt(12));
boolean ok  = BCrypt.checkpw("p@ssw0rd", hash);
```

---

## 五、Go 實作範例

Go 標準「擴充」套件 `golang.org/x/crypto` 同時提供 bcrypt、scrypt、argon2，是 Go 後端最常用的選擇。

### 5.1 bcrypt

```go
package auth

import "golang.org/x/crypto/bcrypt"

// cost 預設 10，建議生產環境用 12。注意 bcrypt 有 72 bytes 密碼長度上限。
const bcryptCost = 12

func HashPassword(raw string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(raw), bcryptCost)
    if err != nil {
        return "", err
    }
    return string(hash), nil
}

func VerifyPassword(raw, storedHash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(raw))
    return err == nil
}
```

### 5.2 Argon2id（推薦新專案）

Argon2 在 Go 裡沒那麼多糖衣，通常自己包一層，把 salt 和參數一起序列化：

```go
package auth

import (
    "crypto/rand"
    "crypto/subtle"
    "encoding/base64"
    "errors"
    "fmt"
    "strings"

    "golang.org/x/crypto/argon2"
)

// OWASP 2024 建議 Argon2id 參數
const (
    argonTime    = 2         // iterations
    argonMemory  = 19 * 1024 // 19 MiB
    argonThreads = 1
    argonKeyLen  = 32
    argonSaltLen = 16
)

func HashPassword(raw string) (string, error) {
    salt := make([]byte, argonSaltLen)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }
    hash := argon2.IDKey([]byte(raw), salt,
        argonTime, argonMemory, argonThreads, argonKeyLen)

    // 用 OWASP 推薦的編碼格式把參數 / salt / hash 串成一字串存 DB
    return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
        argonMemory, argonTime, argonThreads,
        base64.RawStdEncoding.EncodeToString(salt),
        base64.RawStdEncoding.EncodeToString(hash)), nil
}

func VerifyPassword(raw, encoded string) (bool, error) {
    parts := strings.Split(encoded, "$")
    if len(parts) != 6 || parts[1] != "argon2id" {
        return false, errors.New("invalid hash format")
    }
    var m, t uint32
    var p uint8
    if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
        return false, err
    }
    salt, err := base64.RawStdEncoding.DecodeString(parts[4])
    if err != nil {
        return false, err
    }
    want, err := base64.RawStdEncoding.DecodeString(parts[5])
    if err != nil {
        return false, err
    }

    got := argon2.IDKey([]byte(raw), salt, t, m, p, uint32(len(want)))
    // ✅ constant-time 比對，避免 timing attack
    return subtle.ConstantTimeCompare(got, want) == 1, nil
}
```

注意最後那行 `subtle.ConstantTimeCompare`——這是為了防止下一節要講的 **timing attack**。

---

## 六、進階但常考：Timing Attack（時序攻擊）

很多人比對兩個字串時會這樣寫：

```go
if got == want {       // ❌ 危險：提早中斷
```

或 Java：

```java
if (computed.equals(stored)) {   // ❌ 危險：equals 遇到不同 byte 就 return
```

`==` 和 `equals` 會「遇到第一個不同的 byte 就回傳 false」。雖然只差幾奈秒，但**攻擊者如果能發大量請求量測回應時間**，就能一個 byte、一個 byte 地試出正確值。對 API token、HMAC、password hash 比對尤其危險。

正確寫法：

- Go：`crypto/subtle.ConstantTimeCompare(a, b)`
- Java：`java.security.MessageDigest.isEqual(a, b)`（JDK 6u17 後已是 constant-time）
- 或直接用你的雜湊函式庫提供的 `matches()` / `CompareHashAndPassword()`，它們內部已經處理好了。

---

## 七、其他常被忽略的細節

### 7.1 Pepper（胡椒）是什麼？要不要用？

Pepper 是一段**全站共用的秘密**，寫在 server 設定（如 HSM、環境變數），**不存資料庫**，雜湊時額外混入。

常見且正確的做法是「先用 pepper 當 key 做一次 HMAC，再丟進 bcrypt/Argon2」（bcrypt 本身沒有 key 參數，不能寫成 `bcrypt(password, key=pepper)`）：

```
pre  = HMAC-SHA256(password, key = pepper)   // pepper 當 HMAC 金鑰
hash = bcrypt(pre, salt)                      // salt 仍由雜湊函式庫自動產生
```

（注意：先 HMAC 可順便避開 bcrypt 的 72 bytes 上限，因為 HMAC 輸出是固定長度。）

好處：就算資料庫整個外洩，攻擊者沒有 pepper，也爆破不了。
代價：要管理這個 pepper 的安全、不能寫死在 repo、rotate 很麻煩。

> 對一般專案：**先把 bcrypt/Argon2 + salt 做對，已經夠強**。有高安全需求再加 pepper。

### 7.2 要不要限制密碼長度上限？

- **bcrypt 有一個硬限制：輸入超過 72 bytes 的部分會被忽略**。如果允許使用者貼 200 字元的 passphrase，最好先告知或改用 Argon2。
- 除此之外，**不要訂過嚴的規則**（例如「必須包含符號、不能超過 16 字元」）。NIST SP 800-63B 現在建議：至少 8 字元、不設過期強迫換、不強制特殊字元、但要比對常見密碼黑名單。

### 7.3 Cost / 參數要不要調？

- bcrypt 的 cost 每加 1，時間變**兩倍**。目標是「單次驗證約 250–500ms」，硬體愈新，cost 要愈高。
- 實務做法：使用者**登入成功**後，如果發現他的 hash 是舊的（較低 cost 或演算法），**用他剛剛輸入的明文重新 hash 一份並更新**，這樣能無痛升級強度。

### 7.4 錯誤訊息不要洩露

```
❌ 「帳號不存在」 / 「密碼錯誤」  ← 會幫攻擊者確認哪些帳號存在
✅ 統一回「帳號或密碼錯誤」
```

同理，忘記密碼功能、註冊功能也不要暗示「這個 email 已註冊」。

### 7.5 搭配登入節流（Rate Limiting）

即使雜湊做對，也要在登入端加：

- 同 IP / 同帳號失敗 N 次後**指數退避**或短暫鎖定。
- CAPTCHA / MFA / 登入異常通知。

這些會在後續章節單獨介紹。

---

## 八、今天的 Checklist

後端工程師在做「註冊 / 登入」功能前，先問自己：

1. [ ] 我是不是用 **bcrypt / Argon2 / scrypt** 其中之一，而不是 MD5 / SHA-x？
2. [ ] 我是不是**讓函式庫自動產生 salt**，而不是自己發明？
3. [ ] 我驗證時是不是用 `matches()` / `CompareHashAndPassword()` 這類 constant-time API？
4. [ ] 我的錯誤訊息是否**沒有洩露「帳號是否存在」**？
5. [ ] 我是不是**沒有**在 log、錯誤訊息、監控裡印出使用者的明文密碼？
6. [ ] 我有沒有保留「未來升級 cost / 換演算法」的彈性（登入時動態 rehash）？

六題全部答得出「Yes」，恭喜你，今天的防線就站穩了。

---

## 九、小結

| 錯誤做法 | 為什麼不行 | 正確做法 |
| :-- | :-- | :-- |
| 明文儲存 | DB 一洩全漏 | hash 後存 |
| AES/對稱加密 | 可逆、key 被偷就全開 | hash 是單向，驗證不需要還原 |
| MD5 / SHA-256 | 太快 + 沒 salt，彩虹表可破 | bcrypt / Argon2 + 自動 salt |
| 自己寫字串比較 | 有 timing attack 風險 | 用 constant-time 比對 API |

**明天預告（Day 05）**：JWT 與 Session 的身份驗證設計 — 登入之後，你要怎麼「記得」這個使用者是誰？兩種機制的取捨、常見實作錯誤（例如 `alg: none`、簽章驗證漏掉），一次說清楚。

---

> 參考資料：
> - OWASP Password Storage Cheat Sheet（2024 版）
> - NIST SP 800-63B Digital Identity Guidelines
> - Spring Security Reference — PasswordEncoder
> - `golang.org/x/crypto/bcrypt`、`golang.org/x/crypto/argon2` 官方文件
