---
title: "Day 28：FIDO2／WebAuthn／Passkey — 後端怎麼實作「無密碼登入」？"
date: 2026-05-24
tags: ["WebAuthn", "Passkey", "認證"]
---

# Day 28：FIDO2／WebAuthn／Passkey — 後端怎麼實作「無密碼登入」？

> 後端工程師資安系列 — Day 28
> 日期：2026-05-24

## 一、前情提要

過去四週我們從密碼雜湊（Day 04）、Session vs JWT（Day 05）、暴力破解（Day 06）一路講到昨天的 **TOTP（Day 27）**。TOTP 已經能擋下 99% 以上的「撞庫」攻擊，但仍然有兩個致命弱點：

1. **即時釣魚（real-time phishing）**：攻擊者架一個假站（例如 `bankofamerica-login.com`），把使用者輸入的密碼跟 6 位數 OTP 即時轉發到真網站登入 — 工具如 `evilginx2`、`Modlishka` 已經把這做成「點兩下就能用」。TOTP 對此完全無能為力。
2. **使用者體驗差**：要打開 App、找帳號、唸 6 位數、輸入 — 平均 8 秒以上，常常還要在 30 秒過期前手忙腳亂。

> 有沒有一種方案，既能擋掉即時釣魚，又能比輸入密碼還快？

答案是 **FIDO2／WebAuthn**，搭配 2022 年後三大廠（Apple／Google／Microsoft）力推的 **Passkey**。今天我們站在後端工程師的角度，把這個被稱為「**密碼的終結者**」的標準講清楚。

---

## 二、FIDO2、WebAuthn、Passkey 到底是什麼關係？

新手最常被這三個名詞搞混，先一頁說清楚：

| 名詞 | 是什麼 | 由誰定 |
| --- | --- | --- |
| **FIDO2** | 一整套規範的「品牌名」，包含底下兩個協定 | FIDO Alliance |
| **WebAuthn** | 瀏覽器 ↔ 網站伺服器 的 JavaScript API（你後端要對接的就是這個） | W3C |
| **CTAP2** | 瀏覽器 ↔ Authenticator（YubiKey、Touch ID、Windows Hello）的傳輸協定 | FIDO Alliance |
| **Passkey** | 「**可同步、可跨裝置**」的 FIDO2 credential 的行銷名稱 | Apple／Google／Microsoft |

換句話說：
- 你後端對接的是 **WebAuthn**。
- 使用者拿的可能是 YubiKey、手機 Touch ID、Windows Hello、或 iCloud／Google Password Manager 同步的 Passkey。
- 對伺服器來說都一樣 — 你看到的就是一把公鑰，加上每次登入帶回來的簽章。

---

## 三、它憑什麼防得了即時釣魚？

WebAuthn 的關鍵設計只有一句話：

> **每一把私鑰，都是「綁定在 origin 上」的。**

當使用者在 `https://your-bank.com` 註冊一把 Passkey，瀏覽器（不是伺服器、不是 JS）會把 `your-bank.com` 這個 origin 寫進簽章的 `clientDataJSON`。攻擊者就算把使用者騙到 `your-b4nk.com`，瀏覽器產的簽章上面也會寫 `your-b4nk.com`，後端一比 `RP ID` 對不上，立刻拒絕。

這跟密碼／OTP 的根本差別：
- 密碼／OTP：**使用者**負責判斷網址對不對（人是最弱的環節）
- WebAuthn：**瀏覽器**負責判斷網址對不對（瀏覽器不會被「網址長得很像」騙到）

這也是為什麼 Google 內部全面導入 Security Key 後，**員工帳號被釣魚成功的事件 = 0**。

---

## 四、密碼學機制（一頁懂）

```
[註冊 Registration / Attestation]
   伺服器產生 challenge（隨機 nonce）
        │
        ▼
   前端呼叫 navigator.credentials.create({...})
        │
        ▼
   Authenticator（YubiKey／TouchID）做三件事：
     1. 產生「這個網站專屬」的 keypair（ECDSA P-256 為主）
     2. 把 publicKey + credentialId 回傳給瀏覽器
     3. 用 attestation key 簽 challenge（證明是真的硬體產的）
        │
        ▼
   後端驗證簽章 → 把 publicKey、credentialId、signCount 存到 DB

[登入 Authentication / Assertion]
   伺服器產生 challenge
        │
        ▼
   前端呼叫 navigator.credentials.get({...})
        │
        ▼
   Authenticator：
     用「網站專屬」的私鑰 簽 challenge + origin + RP ID
        │
        ▼
   後端用 DB 裡的 publicKey 驗章 + 檢查 origin/RP ID
     → 通過 → 發 session
```

幾個關鍵欄位後端一定要懂：

| 欄位 | 意義 | 後端要怎麼處理 |
| --- | --- | --- |
| `rpId` | Relying Party ID，就是你的網域，例如 `example.com` | 要跟你 server config 寫的一致；子網域共用要用「**最高可掛載**」的網域 |
| `challenge` | 16+ bytes 隨機值 | 存到 session／Redis，**單次使用**，5 分鐘逾期 |
| `origin` | 瀏覽器看到的 origin，例如 `https://example.com:443` | 後端要白名單比對 |
| `credentialId` | 這把 credential 的 ID | 註冊時存進 DB（跟 user_id 綁定）|
| `publicKey` | COSE 格式的公鑰 | 註冊時存進 DB；登入時拿來驗簽 |
| `signCount` | 簽章計數器（防 cloning）| 每次登入要 > 上次（Passkey 可能恆為 0，需特別處理）|
| `userHandle` | 你給使用者的 opaque ID | 不要放 email／使用者名稱（會曝光）|

---

## 五、Java 21（Spring Boot 3）實作範例

Java 生態最成熟的函式庫是 Yubico 官方的 **`java-webauthn-server`**，2024 年仍有 active 維護。

> 在使用任何第三方套件之前，建議先到 Maven Central／官方 repo 確認版本與最後更新時間 — 用 `context7` 之類的工具也能查到套件健康度。

### Maven

```xml
<dependency>
    <groupId>com.yubico</groupId>
    <artifactId>webauthn-server-core</artifactId>
    <version>2.6.0</version>
</dependency>
```

### 5.1 設定 RelyingParty

```java
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;

@Configuration
public class WebAuthnConfig {

    @Bean
    public RelyingParty relyingParty(CredentialRepository repo) {
        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
                .id("example.com")              // RP ID，必須是 origin 的可註冊網域
                .name("My App")                 // 顯示給使用者看
                .build();

        return RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(repo)     // 你要實作這個，介接 DB
                .origins(Set.of("https://example.com"))
                .allowOriginPort(false)
                .allowOriginSubdomain(false)    // 大多數情境關閉，避免子網域污染
                .build();
    }
}
```

### 5.2 註冊（Attestation）流程

```java
// Step 1：產生 challenge，回傳給前端
@PostMapping("/webauthn/register/start")
public PublicKeyCredentialCreationOptions startRegistration(@AuthUser User user) {
    UserIdentity userIdentity = UserIdentity.builder()
            .name(user.getEmail())
            .displayName(user.getDisplayName())
            .id(new ByteArray(user.getOpaqueId()))   // ⚠️ 不要用 email，要不可逆 ID
            .build();

    PublicKeyCredentialCreationOptions options = relyingParty.startRegistration(
            StartRegistrationOptions.builder()
                    .user(userIdentity)
                    .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                            .residentKey(ResidentKeyRequirement.REQUIRED)   // 想做 Passkey 要 REQUIRED
                            .userVerification(UserVerificationRequirement.REQUIRED)
                            .build())
                    .build()
    );

    // 把 options 整個物件存到 session／Redis，等 finish 階段拿出來比對
    challengeStore.save(user.getId(), options);
    return options;
}

// Step 2：使用者掃過指紋／按 YubiKey 後，前端把結果回傳
@PostMapping("/webauthn/register/finish")
public void finishRegistration(@AuthUser User user,
                               @RequestBody PublicKeyCredential<AuthenticatorAttestationResponse,
                                                                ClientRegistrationExtensionOutputs> pkc)
        throws RegistrationFailedException {
    PublicKeyCredentialCreationOptions request = challengeStore.consume(user.getId()); // 取出 & 刪除
    if (request == null) throw new BadRequestException("challenge expired");

    RegistrationResult result = relyingParty.finishRegistration(
            FinishRegistrationOptions.builder()
                    .request(request)
                    .response(pkc)
                    .build()
    );

    credentialRepo.save(new StoredCredential(
            user.getId(),
            result.getKeyId().getId(),       // credentialId
            result.getPublicKeyCose(),       // 公鑰，COSE 格式
            result.getSignatureCount(),
            result.isBackupEligible(),
            result.isBackupState()
    ));
}
```

### 5.3 登入（Assertion）流程

```java
@PostMapping("/webauthn/login/start")
public AssertionRequest startLogin(@RequestBody LoginRequest req) {
    AssertionRequest request = relyingParty.startAssertion(
            StartAssertionOptions.builder()
                    .username(Optional.ofNullable(req.username()))   // 也可不填，做 usernameless
                    .userVerification(UserVerificationRequirement.REQUIRED)
                    .build()
    );
    challengeStore.save("login:" + req.sessionId(), request);
    return request;
}

@PostMapping("/webauthn/login/finish")
public LoginResponse finishLogin(@RequestBody PublicKeyCredential<AuthenticatorAssertionResponse,
                                                                   ClientAssertionExtensionOutputs> pkc,
                                 @RequestParam String sessionId)
        throws AssertionFailedException {
    AssertionRequest request = challengeStore.consume("login:" + sessionId);

    AssertionResult result = relyingParty.finishAssertion(
            FinishAssertionOptions.builder()
                    .request(request)
                    .response(pkc)
                    .build()
    );

    if (!result.isSuccess()) throw new UnauthorizedException();

    // ⚠️ 更新 signCount（Passkey 可能恆為 0，要先判斷）
    long newCount = result.getSignatureCount();
    credentialRepo.updateSignCount(result.getCredential().getCredentialId(), newCount);

    return new LoginResponse(sessionService.create(result.getUsername()));
}
```

---

## 六、Go 實作範例（`go-webauthn/webauthn`）

Go 這邊用社群維護最積極的 `github.com/go-webauthn/webauthn`（fork 自 duo-labs，目前由 go-webauthn 組織接手）。

```go
package main

import (
    "github.com/go-webauthn/webauthn/webauthn"
)

var web *webauthn.WebAuthn

func init() {
    var err error
    web, err = webauthn.New(&webauthn.Config{
        RPDisplayName: "My App",
        RPID:          "example.com",
        RPOrigins:     []string{"https://example.com"},
    })
    if err != nil { panic(err) }
}

// 註冊：產 challenge
func BeginRegister(w http.ResponseWriter, r *http.Request) {
    user := currentUser(r) // 需實作 webauthn.User interface
    options, sessionData, err := web.BeginRegistration(user,
        webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
            ResidentKey:      protocol.ResidentKeyRequirementRequired,
            UserVerification: protocol.VerificationRequired,
        }),
    )
    if err != nil { http.Error(w, err.Error(), 500); return }

    saveSession(r, sessionData) // 存到 Redis / session
    json.NewEncoder(w).Encode(options)
}

// 註冊：finish
func FinishRegister(w http.ResponseWriter, r *http.Request) {
    user := currentUser(r)
    sessionData := loadSession(r)

    credential, err := web.FinishRegistration(user, *sessionData, r)
    if err != nil { http.Error(w, "register failed", 400); return }

    saveCredential(user.ID, credential)  // 存 publicKey、credentialID、signCount
    w.WriteHeader(204)
}

// 登入：產 challenge
func BeginLogin(w http.ResponseWriter, r *http.Request) {
    user := currentUser(r)
    options, sessionData, err := web.BeginLogin(user)
    if err != nil { http.Error(w, err.Error(), 500); return }
    saveSession(r, sessionData)
    json.NewEncoder(w).Encode(options)
}

// 登入：finish
func FinishLogin(w http.ResponseWriter, r *http.Request) {
    user := currentUser(r)
    sessionData := loadSession(r)

    credential, err := web.FinishLogin(user, *sessionData, r)
    if err != nil { http.Error(w, "login failed", 401); return }

    // 更新 signCount，注意 Passkey 同步的情境
    updateSignCount(credential.ID, credential.Authenticator.SignCount)

    issueSession(w, user.ID)
}
```

---

## 七、最容易踩的 8 個地雷

### ⚠️ 1. RP ID 設錯，整個系統不能用

`rpId` 必須是 origin 的「**可註冊網域或其上層**」。

```
origin = https://app.example.com
✅ rpId = "example.com"      （可登入整個 example.com 底下所有子網域）
✅ rpId = "app.example.com"  （只能用在這個子網域）
❌ rpId = "example.org"      （完全不同網域 → 瀏覽器直接拒絕）
❌ rpId = "https://example.com"  （只能是 host，不能有 scheme）
```

### ⚠️ 2. challenge 沒驗單次使用

challenge 是抵擋 replay attack 的唯一防線。每次發出去都要：

```
1. 至少 16 bytes 隨機（用 crypto/rand）
2. 存到 server-side session 或 Redis（不要存 cookie！）
3. finish 階段必須「比對 + 立刻刪除」
4. 5 分鐘自動逾期
```

不要把 challenge 放 client cookie 再讀回來 — 那等於沒驗。

### ⚠️ 3. 用 email／username 當 `user.id`

`userHandle` 會被裝置端記錄、甚至顯示給使用者看。請用：

```
user.id = HMAC(系統 secret, user_internal_id)  // 或是 random UUID 永久綁定
```

不要用 email、手機、姓名 — 個資外洩風險。

### ⚠️ 4. 不檢查 origin

很多新手以為 RP ID 對了就好，但你要同時 enforce `origin` 白名單：

```
allowed_origins = ["https://example.com", "https://www.example.com"]
```

否則攻擊者開一個 `evil.com` 嵌 iframe 也可能繞過（雖然瀏覽器多半會擋，但伺服器也要再驗一次）。

### ⚠️ 5. signCount 處理錯誤

| 情境 | signCount 行為 | 處理 |
| --- | --- | --- |
| 實體 Key（YubiKey） | 每次 +1，必定遞增 | 收到 ≤ 舊值 → 拒絕（可能被 clone） |
| 同步式 Passkey（iCloud／Google） | **可能恆為 0** | 收到 0 → 不要當錯誤，但也不要更新 |

很多教學沒講第二點，導致 Passkey 使用者第二次登入就被拒。

### ⚠️ 6. 不要強迫只能 WebAuthn，要有 fallback

剛上線時建議：

```
密碼 + TOTP    → 一般帳號
密碼 + Passkey → 推薦升級
只有 Passkey   → 部分使用者（最後才開放，要先確定 recovery 流程）
```

「**沒有第二把備用 credential**」就把使用者鎖死，是 WebAuthn 上線最常見的災難。

### ⚠️ 7. 註冊時要記錄裝置 metadata

```
{
  "credentialId": "...",
  "transports": ["internal", "hybrid"],   // 用 hybrid 可判斷是不是 Passkey
  "backupEligible": true,                  // 是否可被同步
  "backupState": true,                     // 是否目前已同步
  "aaguid": "...",                         // 認證器型號
  "createdAt": "...",
  "lastUsedAt": "...",
  "deviceName": "Edison's iPhone"          // 讓使用者自己命名
}
```

提供一個「**已綁定裝置列表**」頁面，使用者可以看到、可以撤銷 — 這是基本盤。

### ⚠️ 8. 別忘記「帳號復原」這個攻擊面

WebAuthn 把帳號安全拉到天花板，但「忘記密碼／裝置遺失」的 recovery 流程仍可能是最弱的一環：

```
❌ 重設只需要 email link → 等於把 WebAuthn 降級成 email 安全度
✅ 至少兩種 recovery factor：另一把 Passkey + 備援碼，或 + 人工驗證
```

---

## 八、Passkey vs 傳統 FIDO2 — 後端要注意什麼？

| 比較項 | 傳統 FIDO2（YubiKey） | Passkey（同步式） |
| --- | --- | --- |
| 私鑰位置 | **只在裝置內**（永遠不離開） | iCloud／Google／1Password 雲端同步 |
| 遺失裝置怎辦 | 全部完蛋，要備用 key | 換新手機登入雲端就回來 |
| signCount | 每次 +1 | 可能恆為 0 |
| `backupEligible` | false | true |
| `transports` | usb, nfc, ble | internal, hybrid |
| 安全度 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐（取決於雲端帳號安全） |
| UX | 要插 key | 指紋／臉部，極快 |

對後端來說，**兩者程式碼一樣**，只差在你要不要在 admin 介面區分。建議在 UI 標示「☁️ 同步」或「🔒 僅此裝置」讓使用者自己決定要不要再加一把硬體 Key。

---

## 九、最簡單的後端資料表設計

```sql
CREATE TABLE webauthn_credentials (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id),
    credential_id   BYTEA NOT NULL UNIQUE,         -- 來自 Authenticator
    public_key      BYTEA NOT NULL,                -- COSE 格式
    sign_count      BIGINT NOT NULL DEFAULT 0,
    transports      TEXT[],                        -- ["internal", "hybrid"]
    aaguid          UUID,
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state    BOOLEAN NOT NULL DEFAULT FALSE,
    device_name     TEXT,                          -- 使用者自訂
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ
);

CREATE INDEX idx_webauthn_cred_user ON webauthn_credentials(user_id);
```

---

## 十、測試與驗收清單（Checklist）

上線前請逐項打勾：

- [ ] `rpId` 設定正確（是 host 不含 scheme，且涵蓋所有要支援的子網域）
- [ ] origin 白名單明確列出，沒有 `*` wildcard
- [ ] challenge ≥ 16 bytes、單次使用、5 分鐘逾期、存在 server side
- [ ] `userVerification` 設為 `REQUIRED`（強迫驗證使用者本人）
- [ ] `user.id` 是不可逆的 opaque ID，不是 email
- [ ] 註冊成功會把 `credentialId`、`publicKey`、`signCount`、`transports`、`aaguid` 都存進 DB
- [ ] signCount 驗證有處理「Passkey 恆為 0」的情境
- [ ] 提供「已綁定裝置」列表頁，使用者可命名、可撤銷
- [ ] 至少有一種備援機制（另一把 Passkey、備援碼、或結合 TOTP）
- [ ] 註冊／登入／撤銷 都寫入 audit log（Day 16）
- [ ] 註冊 endpoint 跟登入 endpoint 都有 rate limit（Day 17）
- [ ] 重設密碼／復原流程**不能比 WebAuthn 弱**

---

## 十一、明日預告

明天我們會講 **Day 29：NoSQL Injection（NoSQL 注入攻擊）**——大家都知道要防 SQL Injection，但換成 MongoDB / Elasticsearch / Redis 就一定安全嗎？我們會看為什麼 `{"$gt": ""}` 這種 operator injection 能繞過登入，以及 Java（Spring Data MongoDB）和 Go（mongo-driver）裡常見的注入手法與防禦。

---

## 參考資料

- W3C Web Authentication Level 3: https://www.w3.org/TR/webauthn-3/
- FIDO Alliance 規範總覽: https://fidoalliance.org/specifications/
- Yubico `java-webauthn-server`: https://github.com/Yubico/java-webauthn-server
- `go-webauthn/webauthn`: https://github.com/go-webauthn/webauthn
- OWASP WebAuthn Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#webauthn
- Passkeys.dev（Apple／Google／Microsoft 合作的入門站）: https://passkeys.dev/
- WebAuthn.io（線上測試各種設定的 demo）: https://webauthn.io/
