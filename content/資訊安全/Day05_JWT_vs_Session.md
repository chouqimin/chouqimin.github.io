---
title: "Day 05 — 身份驗證機制：Session vs JWT（誰才是登入後的「記憶體」？）"
date: 2026-04-26
tags: ["JWT", "Session", "認證"]
---

# Day 05 — 身份驗證機制：Session vs JWT（誰才是登入後的「記憶體」？）

> 日期：2026-04-26
> 適合對象：後端工程師初學者
> 主題難度：★★★☆☆（理解兩種主流設計與常見實作陷阱）

---

## 一、為什麼這個主題這麼重要？

昨天（Day 04）我們把「使用者註冊、密碼怎麼存」做對了。但有一個更根本的問題還沒解決：

> HTTP 是**無狀態（stateless）**的，伺服器不會自己記得「這個請求是 Alice 發的」。

那麼，當使用者登入成功後，要怎麼讓接下來幾百個 API 請求都還能「認得」這個使用者？

答案就是兩大主流機制：**Session（伺服器端記憶）**與 **JWT（自帶身分證的 Token）**。

選錯了不只架構難擴展，**選對了但實作錯**反而是更常見的災難來源——例如名留青史的 `alg: none` 漏洞、忘記驗簽、Token 永不過期……都會把整個系統的身份驗證打穿。今天把兩者的本質、取捨、與雷區一次講清楚。

---

## 二、先區分兩個常被混淆的詞

| 詞 | 意思 | 例子 |
| :-- | :-- | :-- |
| **Authentication（驗證 / 認證，AuthN）** | 「你是誰？」 | 輸入帳密、驗證 OTP |
| **Authorization（授權，AuthZ）** | 「你能做什麼？」 | 你是會員，可以看自己的訂單；你是管理員，可以刪別人的帳號 |

**Session 與 JWT 主要解決的是「登入後怎麼持續驗證『你還是你』」這件事**，屬於 AuthN 的延伸。Authorization 是另一條路（會在後續章節介紹 RBAC / ABAC）。

---

## 三、機制一：Session（伺服器端會話）

### 3.1 流程

```
[使用者]                    [後端]                [Session Store]
   |   POST /login           |                         |
   |  (帳密)                 |                         |
   |------------------------>|                         |
   |                         | 1. 驗證密碼              |
   |                         | 2. 產生 Session ID       |
   |                         |  (隨機 128bit 以上)      |
   |                         |------ SET key=user ---->|
   |   Set-Cookie:           |                         |
   |   session_id=abc123     |                         |
   |<------------------------|                         |
   |                         |                         |
   |   GET /api/orders       |                         |
   |   Cookie: session_id=.. |                         |
   |------------------------>|                         |
   |                         |---- GET key ---------->|
   |                         |<--- userId=42 ---------|
   |                         | 認得 user 42，回資料     |
   |<------------------------|                         |
```

關鍵：**真正的身份資料留在後端**（Redis / DB / 記憶體），瀏覽器只拿到一張「鑰匙」（Session ID），通常放在 Cookie。

### 3.2 優點

- **可立即登出 / 強制下線**：刪掉 Session Store 裡那筆紀錄就好。
- **Session ID 本身沒有資訊**，外洩了至少不會直接暴露 user 內容。
- 改權限即時生效（下一次請求就讀到新狀態）。

### 3.3 缺點

- 需要伺服器端儲存。**水平擴展時**多台機器要共用 Session Store（通常上 Redis）。
- 微服務、跨網域場景比較麻煩（Cookie 有 SameSite / Domain 限制）。
- 行動 App、原生 Client 不一定方便處理 Cookie。

### 3.4 實作範例（Java + Spring Boot）

```java
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginReq req,
                               HttpServletRequest httpReq) {
    User user = userService.verify(req.email(), req.password());

    // 建立 Session（Spring 預設用 JSESSIONID Cookie，可換成 Redis）
    HttpSession session = httpReq.getSession(true);
    session.setAttribute("userId", user.getId());
    session.setMaxInactiveInterval(30 * 60); // 30 分鐘未活動失效

    return ResponseEntity.ok().build();
}
```

Cookie 的安全屬性務必設好：

```java
ResponseCookie cookie = ResponseCookie.from("SESSIONID", sid)
    .httpOnly(true)        // JS 讀不到，避免 XSS 偷走
    .secure(true)          // 只在 HTTPS 下傳
    .sameSite("Lax")       // 防 CSRF（Day 03 講過）
    .path("/")
    .maxAge(Duration.ofMinutes(30))
    .build();
```

### 3.5 常見實作錯誤

1. **Session ID 太短或可預測**——一定要用 `SecureRandom`（Java）或 `crypto/rand`（Go），至少 128 bit 隨機性。
2. **Cookie 沒設 `HttpOnly` / `Secure` / `SameSite`**（連帶 XSS 與 CSRF 風險）。
3. **登入後沒換新 Session ID**（Session Fixation 攻擊）。Spring 預設會幫你做，但如果是自己手刻的中介層要小心。
4. **登出時只刪 Cookie，後端紀錄還在**——攻擊者搶到 Session ID 還是能用。

---

## 四、機制二：JWT（JSON Web Token）

### 4.1 結構：Header.Payload.Signature

```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiIsImV4cCI6MTcxNX0.kQ1...rT
└──── Header ────┘ └──── Payload ────┘ └── Signature ──┘
```

三段都是 **Base64URL 編碼**（注意：是「編碼」不是「加密」，內容可被肉眼讀出來）。

- **Header**：演算法（如 `HS256`、`RS256`）。
- **Payload (Claims)**：宣告，例如：

  ```json
  {
    "sub": "42",          // user id
    "iat": 1715000000,    // 發行時間
    "exp": 1715003600,    // 過期時間
    "role": "admin"
  }
  ```

- **Signature**：用 secret（HS256）或 private key（RS256）對前兩段做的簽章，用來「證明這個 Token 沒被竄改」。

### 4.2 流程

```
[Client]                              [後端]
   POST /login (帳密)
   ─────────────────────────────────▶
                                       驗證密碼
                                       產生 JWT（用 secret 簽章）
   ◀───────────────────────────────── Authorization: Bearer eyJ...
   下次請求帶 Header
   Authorization: Bearer eyJ...
   ─────────────────────────────────▶
                                       1) 拆三段
                                       2) 用 secret 重算簽章 → 比對
                                       3) 檢查 exp / iss / aud
                                       4) 從 sub 拿到 user id
   ◀───────────────────────────────── 回資料
```

關鍵：**後端不需要存 Session**。只要簽章驗得過、時間沒過期，就承認你是 sub 裡那位 user。

### 4.3 優點

- **無狀態（stateless）**：後端不必查資料庫就能驗 Token，水平擴展容易。
- 跨服務、跨網域好用，前端 SPA / 行動 App 都能直接帶 Header。
- 適合微服務之間互相證明身份。

### 4.4 缺點 ── 也是常被低估的部分

- **不能立即撤銷**：一旦簽出去，在 `exp` 之前都有效。要強制登出就只能再做黑名單（這時又有 server state 了，反而失去無狀態的優勢）。
- Token 一變大（多塞 claims）每次請求都要重傳，浪費頻寬。
- **資訊放在 Payload 等於明碼**——千萬不要塞密碼、信用卡、可識別敏感欄位。
- 改權限不會即時生效（要等舊 Token 過期）。

### 4.5 實作範例（Go + `jwt-go` 後繼者 `golang-jwt/jwt/v5`）

> 套件目前由 `github.com/golang-jwt/jwt` 維護，原 `dgrijalva/jwt-go` 已 deprecated。實際使用前請自行確認最新版本。

```go
import (
    "time"
    "github.com/golang-jwt/jwt/v5"
)

var secret = []byte(os.Getenv("JWT_SECRET")) // 至少 32 bytes 隨機字串

// 簽 Token
func IssueToken(userID string) (string, error) {
    claims := jwt.MapClaims{
        "sub": userID,
        "iat": time.Now().Unix(),
        "exp": time.Now().Add(15 * time.Minute).Unix(), // 短一點！
        "iss": "my-service",
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(secret)
}

// 驗 Token
func ParseToken(raw string) (string, error) {
    token, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
        // ★ 一定要檢查演算法，避免 algorithm confusion
        if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
        }
        return secret, nil
    })
    if err != nil || !token.Valid {
        return "", errors.New("invalid token")
    }
    claims := token.Claims.(jwt.MapClaims)
    return claims["sub"].(string), nil
}
```

Java（Spring Security + `jjwt`）：

```java
String token = Jwts.builder()
    .subject(user.getId().toString())
    .issuedAt(new Date())
    .expiration(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
    .signWith(secretKey, Jwts.SIG.HS256)   // 明確指定演算法
    .compact();

// 驗證
Jws<Claims> jws = Jwts.parser()
    .verifyWith(secretKey)                 // 明確指定 key
    .build()
    .parseSignedClaims(token);             // 自動驗簽 + 檢查過期
```

---

## 五、JWT 五大經典實作漏洞（請逐條對照你的程式碼）

### 5.1 `alg: none` 漏洞 ── 早期 JWT 函式庫的恥辱柱

JWT 標準允許 `alg: "none"`（即「沒有簽章」）。早期一些函式庫如果你只呼叫 `decode()`，會**信以為真**，直接把 Header / Payload 回傳，等於攻擊者自己編 Payload 就能冒充任何人。

```
攻擊者送的 Token：
{"alg":"none","typ":"JWT"}.{"sub":"admin"}.
                                           └ 簽章是空字串
```

**防禦：**
- 永遠呼叫 **verify()** 而不是 decode()。
- 在 verify 時**白名單指定允許的演算法**（例如 `HS256` 或 `RS256`），拒絕一切其他選項。

### 5.2 Algorithm Confusion（HS256 vs RS256 混淆）

伺服器以為 Token 是用 RS256（非對稱）簽的，但攻擊者把 Header 改成 `HS256`（對稱），然後**用「公開的 public key」當作 HMAC 的 secret 去簽**。如果驗證程式只是「拿 public key 給 verify」，就會通過——因為演算法被換掉了。

**防禦：**
- 程式中**寫死「我只接受 RS256」**，不要相信 Header 裡的 `alg`。

### 5.3 完全沒驗簽

```javascript
// ❌ 災難級寫法
const payload = JSON.parse(atob(token.split('.')[1]));
if (payload.role === 'admin') { ... }
```

只解碼 Payload，跳過驗簽，等於把後端鑰匙交給使用者。看起來離譜，但在許多前端「樂觀解析」的程式裡偷渡進後端 middleware 的案例不少。

### 5.4 沒檢查 `exp` / `iss` / `aud`

- `exp`：過期時間。沒檢查＝Token 永遠有效。
- `iss`：簽發者。沒檢查可能會接受其他系統簽出來的 Token。
- `aud`：受眾。同一把 key 簽給 A 服務的 Token，被拿去 B 服務也通過。

主流函式庫只要你呼對 `parseSignedClaims()` / `Parse()`，會幫你驗 `exp`，但 `iss` / `aud` 通常要自己加一行。

### 5.5 把敏感資料塞進 Payload

```json
{ "sub": "42", "ssn": "A123456789", "creditCard": "4111-..." }
```

JWT Payload 是**Base64**，不是加密。任何拿到 Token 的人都能看內容。除非你用 **JWE（JSON Web Encryption）**，否則只放「不怕被看到」的資料：user id、role、過期時間。

---

## 六、什麼時候用 Session？什麼時候用 JWT？

| 情境 | 推薦 |
| :-- | :-- |
| 傳統 server-rendered 網站，瀏覽器為主 | **Session + Cookie**（簡單、可即時登出、安全屬性成熟） |
| 單機或小規模、可以接受 Redis 共用 Session | **Session** |
| 微服務之間互相驗證身份 | **JWT**（短效、由 Auth Service 簽發） |
| 行動 App / 第三方 OAuth 客戶端 | **JWT / OAuth Access Token** |
| 需要「後台一鍵下線所有人」 | **Session**（或 JWT + 黑名單，但會犧牲無狀態） |

實務上**最常見的混合模式**：
- 用一張**短效（15 分鐘）的 JWT Access Token** 做 API 驗證（無狀態、好擴展）。
- 配一張**長效（7~30 天）的 Refresh Token** 存在後端（DB / Redis），可隨時撤銷。
- Access Token 過期時，用 Refresh Token 換一張新的。
- 如此兼具「無狀態的高效」與「可即時登出」。

Refresh Token 的設計細節（rotation、reuse detection）日後會再單獨講。

---

## 七、今天的 Checklist

設計或 review 一段「登入 / 驗證」程式碼前，先問自己：

1. [ ] 我是用 **Session 還是 JWT**？是否清楚每種的取捨？
2. [ ] **Session ID** 是否用 `SecureRandom` 等密碼學等級的亂數？
3. [ ] Cookie 是否設了 **HttpOnly + Secure + SameSite**？
4. [ ] 登入成功後是否**重發 Session ID**（防 Session Fixation）？
5. [ ] JWT 是否**只接受白名單演算法**（拒絕 `none`）？
6. [ ] JWT 驗證是否**真的驗簽**，並且檢查 `exp` / `iss` / `aud`？
7. [ ] JWT Payload 是否**不含敏感資訊**？
8. [ ] JWT Access Token **時效是否夠短**（建議 5–15 分鐘）？是否搭配 Refresh Token？
9. [ ] 簽章用的 **secret / private key 是否從環境變數或 KMS 讀取**，沒寫死在 repo？

九題全答 Yes，你今天的身份驗證設計就站穩了。

---

## 八、小結

| 主題 | Session | JWT |
| :-- | :-- | :-- |
| 狀態 | 有狀態（後端存） | 無狀態（自帶身份） |
| 撤銷 | 立即 | 需等過期或加黑名單 |
| 擴展 | 多機需共用 store | 天生水平擴展友善 |
| 跨域 / Mobile | 較麻煩 | 直接 Header 帶 |
| 內容外露 | Session ID 沒意義 | Payload 是明碼 |
| 常見漏洞 | Fixation、Cookie 屬性沒設 | `alg: none`、不驗簽、無過期 |

**沒有絕對的對錯，只有適不適合你的場景。**選擇之後，把上面那 9 條 Checklist 真的執行到位，遠比選哪一種更重要。

**明天預告（Day 06）**：登入暴力破解與帳號保護 — Rate Limiting、漸進式延遲、帳號鎖定、CAPTCHA、登入異常通知。「擋不住別人偷帳密、但能讓他試 100 萬次」也是非常重要的最後一道防線。

---

> 參考資料：
> - OWASP Authentication Cheat Sheet（2024）
> - OWASP JWT for Java Cheat Sheet
> - RFC 7519（JSON Web Token）/ RFC 8725（JWT Best Current Practices）
> - Spring Security Reference — Session Management / OAuth2 Resource Server
> - `github.com/golang-jwt/jwt/v5` 官方文件
