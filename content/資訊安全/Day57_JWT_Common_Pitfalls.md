---
title: "Day 57：JWT 常見誤用 — `alg: none`、簽章未驗證與弱密鑰（當「無狀態驗證」變成「無防線驗證」）"
date: 2026-06-22
tags: ["JWT", "Authentication", "Java", "Go"]
---

# Day 57：JWT 常見誤用 — `alg: none`、簽章未驗證與弱密鑰（當「無狀態驗證」變成「無防線驗證」）

接續 Day56 預告：昨天 Race Condition 是並發時間軸上的洞，問題藏在請求**交錯執行**的縫隙裡；今天回到**身份驗證**主題，看 JSON Web Token 最容易踩的幾個雷。JWT 的賣點是「無狀態驗證」——伺服器不必存 session，只憑 token 自身的簽章就能確認「這是我發的、沒被竄改」。但只要你在「驗證」這一步偷懶，無狀態驗證就會變成**無防線驗證**：攻擊者把 header 的 `alg` 改成 `none` 讓你「不驗章」、用演算法混淆讓 RS256 被當成 HS256 驗、或乾脆暴力破解你那個太短的 secret。這三個雷，每一個都能讓攻擊者**自己簽發一張「我是 admin」的 token**。

---

## 一、先複習：JWT 到底靠什麼保證安全？

一個 JWT 長這樣，三段以 `.` 分隔：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9.<簽章>
   └────────── Header ──────────┘ └────────── Payload ──────────┘ └ Signature ┘
```

- **Header**：描述 token 用什麼演算法簽，例如 `{"alg":"HS256","typ":"JWT"}`
- **Payload**：實際的聲明（claims），例如 `{"sub":"123","role":"user","exp":...}`
- **Signature**：用 Header 指定的演算法 + 你的密鑰，對「Header.Payload」算出來的簽章

關鍵觀念一句話：**Header 和 Payload 都只是 Base64URL 編碼，任何人都能讀、都能改。JWT 唯一的安全保證，來自伺服器用「自己的密鑰」重新驗證簽章是否吻合。** 一旦驗章這步出問題，整個 token 就形同一張可任意偽造的明信片。

下面三個雷，本質都是「**讓伺服器以為簽章是對的，但其實沒真正驗**」。

---

## 二、雷一：`alg: none` —— 攻擊者叫你「別驗了」

JWT 規格裡有一個 `none` 演算法，意思是「這個 token 不簽章」（原本設計給已透過其他方式確保安全的場景）。災難在於：如果你的驗證程式**信任 token header 裡寫的 `alg`**，攻擊者只要：

1. 把 payload 改成 `{"sub":"123","role":"admin"}`
2. 把 header 改成 `{"alg":"none"}`
3. 簽章段直接留空

送出 `<header>.<payload>.`（第三段空白），一個會「照 header 指示」的函式庫就會說：「喔，`alg` 是 `none`，那不用驗章，通過！」攻擊者就這樣把自己變成了 admin，**完全不需要任何密鑰**。

核心錯誤：**把「該用什麼演算法驗證」的決定權交給了不可信的 token 本身。** 正確做法是由**伺服器端**寫死「我只接受 HS256（或 RS256）」，token header 說什麼都不算數。

---

## 三、雷二：簽章「未驗證」—— 只 decode 不 verify

這是最常見、也最隱晦的一種。很多函式庫同時提供「decode（只解碼，不驗章）」和「verify（解碼並驗章）」兩種 API，名字又很像。工程師趕進度時很容易呼叫到只解碼的那個：

```
parse(token)          // 只把 Base64 解出來，payload 我照單全收
verify(token, key)    // 用 key 驗章，不對就拋例外 ← 你要的是這個
```

只 decode 的後果跟 `alg: none` 一樣致命：攻擊者隨便改 payload，你都當真。**「能成功取出 payload」不等於「token 是合法的」**——前者只代表它是合法的 Base64，後者才代表它真的是你簽的。

---

## 四、雷三：演算法混淆（RS256 → HS256）與弱密鑰

### 4-1 演算法混淆（key confusion）

這個比較進階，發生在你用**非對稱**演算法（RS256：私鑰簽、公鑰驗）時。RS256 的公鑰本來就是公開的，不是秘密。攻擊者的伎倆：

1. 把 token header 的 `alg` 從 `RS256` 改成 `HS256`（對稱：同一把 key 簽與驗）
2. 用你那把**公開的公鑰當作 HS256 的 secret**，去簽一張偽造 token
3. 如果你的驗證程式「照 header 的 alg 走」，它就會拿你的公鑰當 HMAC secret 去驗——而攻擊者剛好就是用這把公鑰簽的，**驗章通過**

根因還是同一個：**信任了 token header 指定的演算法**。防禦方法也一樣——伺服器明確指定「我只接受 RS256」，拒絕一切 HMAC 類演算法。

### 4-2 弱密鑰（weak secret）

用 HS256 時，安全性完全押在那個 secret 字串上。如果你用 `secret`、`123456`、`password` 這種短又好猜的字串，攻擊者拿一張你發的 token（token 本來就會給使用者），用 `hashcat` 或 `jwt_tool` 配字典檔，幾秒鐘就能爆破出你的 secret——然後他就能簽任何 token。HS256 的 secret 應該是**至少 256 bits（32 bytes）的高熵隨機值**，從環境變數或密鑰管理服務注入，不寫死在程式碼裡。

---

## 五、Java：用 jjwt 把驗證做對

以下用常見的 `io.jsonwebtoken:jjwt`（0.12.x）示範。

### 反例：只 parse 不驗章 / 信任 header 的 alg

```java
// ❌ 反例一：用 unsecured / 不帶 key 解析，等於不驗章
Jws<Claims> jws = Jwts.parser()
        .build()
        .parseSignedClaims(token);   // 沒有 .verifyWith(key)，無法驗章
// 攻擊者改 payload、改 alg:none，你照單全收
```

### 正解：明確指定 key，並限定允許的演算法

```java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;

public class JwtVerifier {

    // ✅ secret 至少 256 bits，從環境變數/KMS 注入，不寫死
    private final SecretKey key = Keys.hmacShaKeyFor(
            System.getenv("JWT_SECRET").getBytes(StandardCharsets.UTF_8));

    public Claims verify(String token) {
        try {
            Jws<Claims> jws = Jwts.parser()
                    .verifyWith(key)        // 用「伺服器的 key」驗章
                    // jjwt 0.12.x 會依 key 型別自動拒絕不相符的演算法；
                    // 對 SecretKey 只接受 HMAC，alg:none / RS256 偽造都會被擋下
                    .build()
                    .parseSignedClaims(token);   // 驗章失敗 → 直接拋例外
            return jws.getPayload();
        } catch (JwtException e) {
            // 簽章不符、過期、alg 不對、格式錯誤……一律視為驗證失敗
            throw new SecurityException("JWT 驗證失敗", e);
        }
    }
}
```

兩個重點：

1. **`verifyWith(key)`**：明確要求用伺服器自己的 key 驗章。jjwt 不提供「照 header 的 alg 自動選 key」這種危險行為——key 是你給的，演算法由 key 的型別決定（`SecretKey` → HMAC、`PublicKey` → RSA/EC）。因此 `alg:none` 與 RS256↔HS256 混淆都會在驗證階段被拒。
2. **catch `JwtException`**：jjwt 把「驗章失敗」設計成丟例外，而不是回傳 `null` 讓你忘記檢查。任何例外都代表「這張 token 不可信」，一律當失敗處理。

> 注意 jjwt 早已移除對 `none` 的隱性支援；`parseSignedClaims` 本來就要求 token 有合法簽章。真正要小心的是別誤用 `parse`/`parseUnsecuredClaims` 之類「不驗章」的入口。

如果是 RS256（非對稱），驗證時改用**公鑰**並維持同樣的紀律：

```java
// 用公鑰驗 RS256；因為傳的是 PublicKey，jjwt 只會接受 RSA 簽章，
// 擋掉「把公鑰當 HMAC secret」的混淆攻擊
Jws<Claims> jws = Jwts.parser()
        .verifyWith(rsaPublicKey)
        .build()
        .parseSignedClaims(token);
```

---

## 六、Go：用 golang-jwt 明確指定允許的演算法

以下用 `github.com/golang-jwt/jwt/v5` 示範。golang-jwt 的核心防線是 `jwt.WithValidMethods(...)`——**白名單**你接受的演算法。

### 反例：keyFunc 裡不檢查 alg

```go
// ❌ 反例：keyFunc 直接回傳 secret，不檢查 token.Method
token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
    return secret, nil // 攻擊者改成 alg:none 或 RS256 混淆都可能繞過
})
```

`Parse` 的 keyFunc 會把解析到的 `*jwt.Token` 交給你，如果你不檢查 `t.Method` 就直接回傳 key，等於信任了 token header 宣稱的演算法。

### 正解：用 `WithValidMethods` 白名單演算法，並在 keyFunc 內再次確認

```go
package auth

import (
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

// ✅ secret 至少 32 bytes 的高熵隨機值，從環境變數/KMS 注入
var secret = []byte(os.Getenv("JWT_SECRET"))

func Verify(tokenString string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(t *jwt.Token) (interface{}, error) {
			// 第二道防線：在 keyFunc 內再次確認演算法是 HMAC
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("非預期的簽章演算法：%v", t.Header["alg"])
			}
			return secret, nil
		},
		// 第一道防線（首選）：白名單只允許 HS256，
		// alg:none、RS256 混淆全部在這關被拒
		jwt.WithValidMethods([]string{"HS256"}),
	)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("token 無效")
	}
	return claims, nil
}
```

兩道防線缺一不可的理由：

1. **`jwt.WithValidMethods([]string{"HS256"})`**：解析時若 token 的 `alg` 不在白名單（包含 `none`、`RS256`），直接驗證失敗。這是最乾淨、首選的擋法。
2. **keyFunc 內 `t.Method.(*jwt.SigningMethodHMAC)` 型別斷言**：縱深防禦，再次確認拿到的是 HMAC 類演算法，避免把 secret 餵給錯誤的演算法路徑。

RS256 的場景就把白名單與型別斷言換成 RSA，並回傳**公鑰**：

```go
jwt.WithValidMethods([]string{"RS256"}) // 只接受 RS256
// keyFunc 內：
if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
    return nil, fmt.Errorf("非預期演算法：%v", t.Header["alg"])
}
return rsaPublicKey, nil
```

---

## 七、容易被忽略的細節

1. **永遠由伺服器決定演算法，不要相信 token header 的 `alg`**：這是三個雷共同的根因。白名單（Go 的 `WithValidMethods`）或以 key 型別綁定演算法（Java jjwt）。
2. **「decode 成功」≠「token 合法」**：能取出 payload 只代表它是合法 Base64。一定要走「驗章」的 API，並把驗章失敗當成硬性錯誤。
3. **HS256 的 secret 要夠長夠隨機**：至少 256 bits，從環境變數/KMS 注入，絕不寫死在 code 或 commit 進 git。
4. **務必驗 `exp`（過期）與必要的 `iss`/`aud`**：jjwt 與 golang-jwt 預設會驗 `exp`，但 `iss`（簽發者）、`aud`（受眾）要自己明確比對，避免別的系統發的 token 被你接受。
5. **敏感資料別放 payload**：payload 只是 Base64，人人可讀。別放密碼、完整身分證號這類東西。
6. **token 失效是 JWT 的天生弱點**：無狀態代表你很難「立刻撤銷」一張還沒過期的 token。需要強制登出/封禁時，搭配短 `exp` + refresh token，或維護一份伺服器端黑名單。
7. **時鐘偏移（clock skew）**：分散式環境多台機器時間略有差異，驗 `exp`/`nbf` 時可設定少量容許偏移（如 30~60 秒），避免邊界誤判。

---

## 八、後端工程師的 Checklist

- [ ] 驗證時**白名單**允許的演算法（Go `WithValidMethods`；Java 以 key 型別綁定），明確拒絕 `none`。
- [ ] 一律使用「驗章」API（jjwt `verifyWith` + `parseSignedClaims`；golang-jwt `ParseWithClaims` + keyFunc 型別斷言），不要只 decode。
- [ ] 把驗章失敗當成硬性錯誤（拋例外 / 回 401），不要 fallback 放行。
- [ ] HS256 secret ≥ 256 bits 隨機值，從環境變數/KMS 注入，不進版控。
- [ ] 用 RS256 時，keyFunc/parser 明確只接受 RSA，回傳公鑰，防 key confusion。
- [ ] 驗 `exp`，並依需求驗 `iss`、`aud`；設定合理 clock skew。
- [ ] payload 不放敏感資料；設計 token 撤銷機制（短 exp + refresh，或黑名單）。

---

## 九、一句話總結

> **JWT 的安全 100% 取決於「驗章」這一步，而驗章的演算法必須由伺服器說了算，不是由 token 自己宣稱。** 守住三件事：白名單演算法（擋 `alg:none` 與 RS256↔HS256 混淆）、真的驗章（別只 decode）、夠強的密鑰（擋暴力破解）。任何一件偷懶，攻擊者就能自簽一張「我是 admin」。

---

## 延伸閱讀

- OWASP — JSON Web Token (JWT) Cheat Sheet
- RFC 7519（JWT）、RFC 7515（JWS）、RFC 8725（JWT Best Current Practices）
- CWE-347：Improper Verification of Cryptographic Signature
- jjwt（io.jsonwebtoken）官方文件 — `verifyWith` / `parseSignedClaims`
- golang-jwt/jwt/v5 官方文件 — `ParseWithClaims`、`WithValidMethods`、`SigningMethodHMAC`/`SigningMethodRSA`
- 前文：Day56 Race Condition（時間維度的洞）；今天回到身份驗證的信任邊界

---

明天預告：**Day 58 — CORS 設定踩雷：`Access-Control-Allow-Origin: *` 配上 `Allow-Credentials`、反射 Origin 與萬用字元的危險（當「跨域放行」變成「全世界都能帶著你的 cookie 來」）**
（今天 JWT 是「token 自身的驗證」被繞過；明天看瀏覽器同源政策的另一面——CORS。會拆解後端最容易設錯的幾個 header：把 `Allow-Origin` 設成 `*` 卻又開 `Allow-Credentials`、或為了方便直接「反射」請求帶來的 Origin 等於對所有網站開門、以及 `null` origin 的坑。會用 Java（Spring 的 `CorsConfiguration` 正確白名單寫法 vs. 反射 Origin 的反例）與 Go（`net/http` middleware 明確比對允許清單）示範如何把 CORS 設定收緊。）
