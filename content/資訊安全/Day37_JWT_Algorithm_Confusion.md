---
title: "Day 37 — JWT Algorithm Confusion（JWT 演算法混淆攻擊）"
date: 2026-06-02
tags: ["JWT", "密碼學", "認證"]
---

# Day 37 — JWT Algorithm Confusion（JWT 演算法混淆攻擊）

> 後端工程師資安教學 · Day 37
> 適合對象：剛接觸 Web 後端、Java（1.8 / 21）與 Go 開發者
> 前情提要：Day 5 我們講過 JWT vs Session，這篇要講「就算你用了 JWT，也可能被一行 header 改寫整個身份」

---

## 一、先講一個生活化的比喻

想像你開了一家銀行，門口有個保全。保全的規則是：

> 「客戶拿來的支票，**支票上自己寫**用什麼方式驗證——
> 如果寫『請打電話跟分行確認』，我就打電話；
> 如果寫『不用驗證』，那我就直接放行。」

聽起來很荒謬，但**這就是早期 JWT 函式庫的真實行為**。

JWT 的 header 裡有一個欄位叫 `alg`（algorithm），它**讓 token 自己宣告**要用什麼演算法驗章。攻擊者只要把這欄改掉，就可能讓你用錯誤的方式驗證——甚至完全跳過驗證。

關鍵字：**讓攻擊者選驗證方式，就跟讓小偷自己選鎖一樣**。

---

## 二、JWT 結構快速複習

一個 JWT 長這樣（用 `.` 分成三段）：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9.SflKxw...
└──────── header ────────┘.└──── payload ────┘.└── signature ──┘
```

Base64URL 解碼後：

```json
// header
{"alg": "HS256", "typ": "JWT"}

// payload
{"sub": "123", "role": "user"}

// signature = HMAC-SHA256( header + "." + payload, SECRET_KEY )
```

驗章的流程概念上是：

1. 取出 `alg`。
2. 用對應演算法 + 你的金鑰，去重新計算 signature。
3. 跟 token 帶來的 signature 比對。

**問題就出在第 1 步：`alg` 是 token 自己宣告的。**

---

## 三、三種常見的演算法混淆攻擊

### 攻擊 1：`alg: none`（最經典）

JWT 的演算法清單定義在 RFC 7518（JWA），裡面真的有一種「不簽章」的 `none` 演算法（JWT 本身的結構定義在 RFC 7519）。當初是給某些「已經透過 TLS 保護、不需要 JWT 自己再簽章的場景」使用，但許多函式庫的預設行為是：**只要 `alg=none`，就跳過簽章驗證，直接信 payload**。

攻擊者把 token 改成：

```json
// header
{"alg": "none", "typ": "JWT"}

// payload
{"sub": "1", "role": "admin"}

// signature 留空
```

最後組成：

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.
```

只要後端傻傻照 `alg` 走，這個 token 就**沒有簽章但被當成有效**。一鍵變 admin。

---

### 攻擊 2：RS256 → HS256（金鑰類型混淆）

這個更陰險。情境是：

- 你用 **RS256**（非對稱）簽 JWT：私鑰簽、公鑰驗。
- 公鑰是「公開的」，可能放在 `/.well-known/jwks.json`、GitHub、API 文件裡。

攻擊者做什麼？

1. 抓到你的**公鑰**（反正是公開的）。
2. 把 token header 改成 `{"alg": "HS256"}`。
3. **用你的公鑰當作 HMAC 的 secret**，自己算一個 HMAC-SHA256 簽章。
4. 把這個 token 丟給你。

後端如果寫成這樣（簡化版）：

```python
key = load_my_key()           # 載入「我的金鑰」（其實是公鑰）
verify(token, key)            # 函式庫看 alg=HS256，把 key 當成 HMAC secret
```

函式庫會用「公鑰當 HMAC secret」去算，跟攻擊者算的**完全一致**——驗章通過。

> 為什麼會這樣？因為函式庫的 API 常常只收一個 `key` 參數，不知道你**原本期待**哪種演算法。它信任 token 的 `alg`，所以「公鑰」被誤用成「HMAC 對稱金鑰」。

這是 2015 年 Auth0 公開的經典攻擊（CVE-2015-9235 等系列），到現在仍不斷出現。

---

### 攻擊 3：`kid`（Key ID）注入

`kid` 是 header 裡用來指定「我這個 token 用哪把鑰匙簽」的欄位。有些後端會寫成：

```python
kid = header["kid"]
key = open(f"/etc/keys/{kid}").read()   # 危險！Path Traversal
```

攻擊者把 `kid` 設成 `../../../../dev/null`，於是 key 變成空字串。再把 `alg` 設成 HMAC，用「空字串」當 secret 自己簽，token 就驗章通過。

變形：`kid` 被當 SQL 查詢、被當 URL 載入（變 SSRF）……全都是同一類「`kid` 是使用者輸入」的問題。

---

## 四、Java 範例：脆弱寫法 vs 安全寫法

> 用 `jjwt`（io.jsonwebtoken）為例，這是 Java 圈最常見的 JWT 函式庫之一。

### 脆弱寫法（請勿模仿）

```java
// Java 1.8 / 21 皆可編譯
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;

public class VulnerableJwt {

    // 危險點 1：用 parser().setSigningKey(...) 而不指定演算法
    // 危險點 2：金鑰是字串，沒分對稱/非對稱意圖
    public Claims parse(String token, String key) {
        return Jwts.parser()
                   .setSigningKey(key.getBytes())   // 函式庫會根據 token 的 alg 自己決定怎麼用 key
                   .parseClaimsJws(token)
                   .getBody();
    }
}
```

如果 `key` 是 RSA 公鑰、token 卻宣稱 `HS256`，舊版 jjwt 會把公鑰 bytes 當 HMAC secret——攻擊成立。

### 安全寫法

```java
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.PublicKey;

public class SecureJwt {

    private final PublicKey publicKey;            // 啟動時載入，固定型別

    public SecureJwt(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public Claims parse(String token) {
        return Jwts.parserBuilder()
                   // 1) 明確指定接受的演算法
                   //    （新版 jjwt 0.11+ 在 verifyWith / setSigningKey(Key) 已會檢查型別）
                   .verifyWith(publicKey)         // 明確告訴函式庫：用「公鑰」驗，且只接受非對稱
                   .build()
                   .parseSignedClaims(token)
                   .getPayload();
        // 若 token 宣稱 alg=none 或 alg=HS256，會直接拋 SignatureException
    }
}
```

關鍵原則：

- **白名單演算法**：後端應該預先決定「我只用 RS256」，凡是 token 宣稱別的演算法一律拒絕。
- **金鑰型別嚴格化**：把 key 包成 `RSAPublicKey` / `SecretKey`，函式庫就無法把它當成另一種用途。
- 升級到 `io.jsonwebtoken:jjwt-api` **0.11.0 以上**（更建議 0.12.x），舊版的 parser API 在這點不夠嚴格。

### Spring Security 的寫法

如果你用 Spring Security 的 OAuth2 Resource Server：

```java
@Bean
JwtDecoder jwtDecoder() {
    NimbusJwtDecoder decoder = NimbusJwtDecoder
            .withPublicKey(rsaPublicKey)
            .signatureAlgorithm(SignatureAlgorithm.RS256)   // 明確白名單
            .build();
    return decoder;
}
```

`signatureAlgorithm(RS256)` 寫了之後，Spring 收到 `alg=HS256` 或 `alg=none` 的 token 會直接 reject。

---

## 五、Go 範例：脆弱寫法 vs 安全寫法

> 用 `github.com/golang-jwt/jwt/v5`（前身是 `dgrijalva/jwt-go`，已停止維護，請改用 golang-jwt 社群版）。

### 脆弱寫法

```go
import "github.com/golang-jwt/jwt/v5"

func parseVulnerable(tokenStr string, keyBytes []byte) (*jwt.Token, error) {
    return jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
        // 危險：沒檢查 t.Method 是什麼，無論 alg 是什麼都回傳同一把 key
        return keyBytes, nil
    })
}
```

如果 `keyBytes` 是 RSA 公鑰的 PEM，而攻擊者送來 `alg=HS256` 的 token，這段程式會把公鑰 bytes 交給 HMAC 去算——驗章通過。

`alg=none` 在 golang-jwt v5 預設已禁止（會直接拒絕），但**演算法混淆**這點仍需自己擋。

### 安全寫法

```go
import (
    "crypto/rsa"
    "errors"
    "fmt"
    "github.com/golang-jwt/jwt/v5"
)

func parseSecure(tokenStr string, pubKey *rsa.PublicKey) (*jwt.Token, error) {
    return jwt.Parse(
        tokenStr,
        func(t *jwt.Token) (interface{}, error) {
            // 1) 明確檢查 alg 是 RS256（白名單）
            if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
            }
            return pubKey, nil
        },
        // 2) 再用 ParserOption 強化：只接受 RS256
        jwt.WithValidMethods([]string{"RS256"}),
    )
}
```

兩道防線：

1. callback 裡用 type switch 檢查 `t.Method` 型別，不對就拒絕。
2. `jwt.WithValidMethods([]string{"RS256"})` 是 v5 提供的 ParserOption，在解析階段就會比對 `alg`，這個寫法是**最推薦**的。

> 順手提：如果你還在用 `dgrijalva/jwt-go`，請務必遷移到 `golang-jwt/jwt/v5`。前者已經 archived，許多 CVE 都修在新版。

---

## 六、`kid` 注入怎麼擋？

如果你真的要用 `kid` 來選 key（例如多租戶、輪替金鑰），**永遠把 `kid` 當不可信輸入**：

```go
// 危險：把 kid 直接拿去查檔案
key := os.ReadFile("/keys/" + token.Header["kid"].(string))

// 安全：用 map 白名單
var keys = map[string]*rsa.PublicKey{
    "2024-q4": pubKey1,
    "2025-q1": pubKey2,
}

func keyFunc(t *jwt.Token) (interface{}, error) {
    kid, ok := t.Header["kid"].(string)
    if !ok {
        return nil, errors.New("missing kid")
    }
    k, ok := keys[kid]                   // 白名單查表，找不到就拒絕
    if !ok {
        return nil, errors.New("unknown kid")
    }
    return k, nil
}
```

原則：**`kid` 只能拿來查白名單，不能拿來拼接路徑、SQL、URL**。

---

## 七、實戰檢核清單

部署前自己問這幾題：

1. 我有沒有**明確指定**接受的演算法？（不要讓 token 自選）
2. 我用的 JWT 函式庫是不是最新穩定版？（jjwt 0.11+ / golang-jwt v5）
3. 我有沒有把 `alg=none` 列為不接受？
4. 我的「公鑰」會不會被誤當「HMAC secret」？（型別分開、API 分開）
5. `kid` / `jku` / `x5u` 等 header 有沒有被當成可信輸入？（這幾個欄位常被忽略，但都是攻擊面）
6. 我有沒有驗 `exp`、`iat`、`nbf`、`iss`、`aud`？（白名單發行者）
7. 我的金鑰多長？HS256 至少 256-bit（32 bytes）random，不要用 `"secret"`。
8. Token 有沒有方法**撤銷**？（純 JWT 不能改、不能撤，敏感場景請搭配短 TTL + Refresh Token，或回到 Session）

---

## 八、現實世界的 CVE 案例

- **CVE-2015-9235**：Auth0 公開的 RS256/HS256 混淆，影響多個 JS 函式庫。
- **CVE-2022-21449**（Java ECDSA）：OpenJDK 在驗 ECDSA 簽章時，沒檢查 `r`、`s` 是否為 0，導致**全 0 簽章**也能通過——任何用 ES256/ES384/ES512 的 JWT 都能偽造。影響 JDK 15–18，Java 8 不受影響但 Java 21 已修復。
- **CVE-2018-1000531**（inversoft `prime-jwt` 1.3.0 以前）：`JWTDecoder.decode` 未擋 `alg=none`，可把 HMAC 簽章的 token 演算法改成 `none` 繞過驗章。
- 各種 `kid` Path Traversal / SQL Injection 在 HackerOne 上層出不窮。

---

## 九、TL;DR

> JWT 的本質：**header 裡的 `alg` 是「不可信的輸入」**，但歷史上很多函式庫把它當「行為開關」。
>
> 三條鐵律：
>
> 1. **白名單演算法**，不要讓 token 自選。
> 2. **金鑰用對型別**，公鑰是 `PublicKey`，HMAC secret 是 `SecretKey`，永遠不要混用。
> 3. **`kid` 等 header 欄位視為使用者輸入**，只能查白名單，不能拼接路徑。

做到這三點，今天介紹的攻擊基本都會在「解 token」那一步就被擋掉。

---

明天 Day 38 預告：**X-Forwarded-For 偽造 / 反向代理標頭信任問題**——當你用 `X-Forwarded-For` 之類的標頭判斷「來源 IP」做風控、限流或白名單時，攻擊者只要自己塞一個 header 就能偽裝成任何 IP。我們看看反向代理後面到底該怎麼取得真實來源 IP。
