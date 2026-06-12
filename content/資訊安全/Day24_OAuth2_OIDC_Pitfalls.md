---
title: "Day 24：OAuth 2.0 / OpenID Connect 的常見實作陷阱"
date: 2026-05-20
tags: ["OAuth2", "OIDC", "認證"]
---

# Day 24：OAuth 2.0 / OpenID Connect 的常見實作陷阱

> 後端工程師資安系列 — Day 24
> 日期：2026-05-20

## 一、前情提要

Day 04 我們聊過密碼雜湊、Day 05 比較了 JWT 與 Session、Day 06 處理過暴力破解。今天要進入更現代、也更容易踩雷的領域 —— **OAuth 2.0 與 OpenID Connect (OIDC)**。

只要你的服務有「用 Google 登入」「用 LINE 登入」「串接第三方 API（GitHub、Slack、Stripe…）」「把你自家的服務拆成多個微服務並透過 Authorization Server 發 Token」，這套協定就會出現在你的程式碼裡。

OAuth 2.0 本身是一份規格（RFC 6749 + 後續一連串補充 RFC），看起來「不過就是換個 Token」，但魔鬼藏在細節。下面這些坑，**沒踩過真的看不到**：

- Redirect URI 沒驗證好 → 任何使用者帳號都能被接管。
- 沒帶 State → 又一個 CSRF 漏洞。
- 沒用 PKCE → Authorization Code 被攔截就完蛋。
- ID Token 沒驗 issuer/audience/signature → 你以為登入了 A，其實是 B。

今天把這些一次講清楚，並附上 Java (Spring Security 6) 與 Go (golang.org/x/oauth2 + go-oidc) 的程式碼示範。

---

## 二、五分鐘複習：Authorization Code Flow

OAuth 2.0 有多種 grant type，**對網站 / API 後端唯一推薦的是 Authorization Code Flow（加上 PKCE）**。Implicit Flow 已於 OAuth 2.1 草案中正式淘汰，Password Grant 也不該再用。

流程（簡化版）：

```
[User] ──①點「用 Google 登入」──▶ [Your App (Client)]
                                  │
                                  ② 302 轉址到 IdP，附 client_id, redirect_uri,
                                     scope, state, code_challenge
                                  ▼
                              [Google (Authorization Server)]
                                  │
                                  ③ 使用者登入 / 同意授權
                                  │
                                  ④ 302 轉回 redirect_uri，附上 code、state
                                  ▼
[User] ──⑤瀏覽器送 code 回 App──▶ [Your App]
                                  │
                                  ⑥ App 用 code + client_secret + code_verifier
                                     向 IdP 的 /token 取 access_token、id_token
                                  ▼
                              [Google] ──⑦ 回 token ──▶ [Your App]
```

每個箭頭都至少有一個常見陷阱。下面逐一拆解。

---

## 三、陷阱 1：Redirect URI 驗證不嚴格

`redirect_uri` 是 Authorization Server 把 `code` 送回來的地方。如果這個值可以被攻擊者操控，**整個流程就崩了**。

### 攻擊情境

假設你註冊在 Google 的 redirect_uri 是 `https://app.example.com/oauth/callback`。
你的後端「方便起見」只用 `startsWith` 驗證：

```java
// 反例：危險
if (redirectUri.startsWith("https://app.example.com")) {
    // 視為合法
}
```

攻擊者建立網域 `https://app.example.com.attacker.tw/callback`，誘騙受害者點下這個 OAuth 連結。Google 看到 `redirect_uri` 是攻擊者控制的網域、但 Google 是用「**完全字串比對**」，所以這個攻擊在 IdP 端通常會擋下來。

真正常見的失誤是 **Client 端自己**做轉址：

```java
// 反例：Open Redirect + OAuth Code 竊取
@GetMapping("/oauth/callback")
public String callback(@RequestParam String code,
                       @RequestParam String returnTo) {
    sessionService.exchangeCode(code);
    return "redirect:" + returnTo;   // 沒驗證！
}
```

攻擊者把 `returnTo=https://evil.example` 塞進去，使用者登入完後被導去攻擊者站，連同 `code`、`state` 一起以 `Referer` header 洩漏出去。

### 正確做法

1. **Authorization Server 端**：註冊 redirect_uri 必須是完整 URL，且用 **完全字串比對**（exact match）。不要用萬用字元或前綴比對。
2. **Client 端**：所有「登入完跳回原頁」的 `returnTo` 參數都必須是白名單比對 —— 與 Day 20 的 Open Redirect 同源。
3. **不要把 access_token / code 放在 query string 裡轉發**。需要傳遞用 server-side session 暫存。

---

## 四、陷阱 2：Authorization Code Injection（沒用 PKCE）

這是 OAuth 史上最經典的攻擊之一。

### 攻擊情境

1. 攻擊者自己跑一遍 OAuth：從 Google 拿到一個合法的 `code_A`（這個 code 是要交換攻擊者帳號的 token 的）。
2. 攻擊者誘騙受害者打開一個惡意連結，把 `code_A` 直接塞進受害者的瀏覽器，例如：
   ```
   https://app.example.com/oauth/callback?code=code_A&state=...
   ```
3. 受害者的瀏覽器把 `code_A` 帶回 App。App 用自己的 `client_secret` 去交換 token，拿到的是**攻擊者帳號的 token**。
4. App 把這個 token 與「受害者的 session」綁定。**受害者從此用的是攻擊者的 Google 帳號**，他存的資料、行為紀錄、檔案都會被攻擊者讀到 / 接管。

這個攻擊不需要竊聽，只要受害者點下一個連結。

### 解法：PKCE (RFC 7636)

PKCE（Proof Key for Code Exchange）讓 Client 在第 ② 步隨機產生：

- `code_verifier`：43–128 字元的高熵字串，**只存在 Client 端 session 裡**。
- `code_challenge` = `BASE64URL(SHA256(code_verifier))`，傳給 IdP。

到了第 ⑥ 步交換 token 時，Client 必須把 `code_verifier` 一起送上。Authorization Server 會用同樣的雜湊驗證：「這個 verifier 真的是當初換 challenge 的人嗎？」

只要攻擊者沒拿到 `code_verifier`，他就算偷到 `code` 也換不出 token。**PKCE 現在是強制建議（OAuth 2.1 草案直接列為必要），所有公開或機密 Client 都應該用。**

---

## 五、陷阱 3：忘記驗證 `state`

`state` 是 Client 在 ② 步隨機產生並存在 session 的字串，會跟著 ④ 一起回來。

它的作用是 **防 CSRF**：避免攻擊者透過事先準備的 callback URL，誘騙受害者「以攻擊者的身分」登入到攻擊者的應用。

很多教學文章為了簡化都會省略 state，但**真實環境一定要做**：

```go
// Go 範例：產生並儲存 state
func login(w http.ResponseWriter, r *http.Request) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        http.Error(w, "internal", http.StatusInternalServerError)
        return
    }
    state := base64.RawURLEncoding.EncodeToString(b)

    // 寫入 session（範例用 cookie；正式環境應放在 server-side store）
    http.SetCookie(w, &http.Cookie{
        Name:     "oauth_state",
        Value:    state,
        Path:     "/",
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   600,
    })

    http.Redirect(w, r, oauthCfg.AuthCodeURL(state,
        oauth2.SetAuthURLParam("code_challenge", challenge),
        oauth2.SetAuthURLParam("code_challenge_method", "S256"),
    ), http.StatusFound)
}

func callback(w http.ResponseWriter, r *http.Request) {
    c, err := r.Cookie("oauth_state")
    if err != nil {
        http.Error(w, "missing state", http.StatusBadRequest)
        return
    }
    if subtle.ConstantTimeCompare([]byte(c.Value),
                                  []byte(r.URL.Query().Get("state"))) != 1 {
        http.Error(w, "state mismatch", http.StatusBadRequest)
        return
    }
    // ...交換 token
}
```

`state` 必須：

- 有足夠熵（≥ 128 bit）。
- **與當前 user session 綁定**（單純把 state 寫進 cookie 還不夠，要在 server 端確認這個 state 是這個 session 發出去的）。
- 使用 `constant-time compare`（如 Java 的 `MessageDigest.isEqual`、Go 的 `subtle.ConstantTimeCompare`），避免時序攻擊。

---

## 六、陷阱 4：ID Token 沒驗對（OpenID Connect）

OpenID Connect (OIDC) 在 OAuth 2.0 之上加了一個 `id_token`（一個簽過名的 JWT），告訴你「使用者是誰」。

如果你只是 `Base64Url decode` 就拿 `sub` 來當使用者 ID，那就跟 Day 05 講的「不驗證 JWT」一樣慘。

**必驗欄位：**

1. `iss` 必須等於你信任的 IdP（例如 `https://accounts.google.com`）。
2. `aud` 必須包含你自己的 `client_id`。
3. `exp` 還沒過期，`iat` / `nbf` 合理。
4. 簽章用 IdP 公佈的 JWK Set 驗證，演算法必須是 RS256 / ES256 之類的非對稱演算法。**絕對不要接受 `alg: none`，也不要把 RS256 公鑰當 HS256 secret 用**（CVE-2015-9235 經典案例）。
5. 如果你有送 `nonce`，回來的 `id_token.nonce` 必須等於送出的 nonce（與 state 同樣是 CSRF 防護，但是綁在 token 本身）。
6. `at_hash`（若有）要符合 access_token 的雜湊，避免 Token Substitution。

### Java 範例：用 Nimbus + Spring Security 6 驗證 ID Token

```java
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.URL;
import java.time.Instant;
import java.util.Set;

public class IdTokenValidator {

    private final DefaultJWTProcessor<?> processor;
    private final String expectedIssuer;
    private final String expectedAudience;

    public IdTokenValidator(String issuer, String audience, URL jwksUrl) throws Exception {
        this.expectedIssuer = issuer;
        this.expectedAudience = audience;
        var jwkSource = JWKSourceBuilder.create(jwksUrl).retrying(true).build();
        var keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwkSource);

        this.processor = new DefaultJWTProcessor<>();
        this.processor.setJWSKeySelector(keySelector);
    }

    public JWTClaimsSet validate(String idToken, String expectedNonce) throws Exception {
        SignedJWT jwt = SignedJWT.parse(idToken);

        // 1) 演算法白名單：拒絕 none / HS*
        if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())) {
            throw new SecurityException("alg not allowed");
        }

        JWTClaimsSet claims = processor.process(jwt, null); // 驗簽章

        // 2) issuer
        if (!expectedIssuer.equals(claims.getIssuer())) {
            throw new SecurityException("bad iss");
        }

        // 3) audience
        if (claims.getAudience() == null
                || !Set.copyOf(claims.getAudience()).contains(expectedAudience)) {
            throw new SecurityException("bad aud");
        }

        // 4) exp / nbf
        Instant now = Instant.now();
        if (claims.getExpirationTime() == null
                || claims.getExpirationTime().toInstant().isBefore(now)) {
            throw new SecurityException("expired");
        }

        // 5) nonce
        if (expectedNonce != null
                && !expectedNonce.equals(claims.getStringClaim("nonce"))) {
            throw new SecurityException("nonce mismatch");
        }

        return claims;
    }
}
```

> 實務上若用 Spring Security 6 的 `spring-boot-starter-oauth2-client`，框架已經幫你做完上面所有步驟，**只要你不要去覆寫成「跳過驗證」的版本**。Day 23 提到的「不要自己 parse HTTP」這條規則，這裡同樣適用：**不要自己 parse JWT**，用成熟函式庫。

### Go 範例：使用 coreos/go-oidc

```go
import (
    "context"
    "github.com/coreos/go-oidc/v3/oidc"
    "golang.org/x/oauth2"
)

func newVerifier(ctx context.Context, issuer, clientID string) (*oidc.IDTokenVerifier, error) {
    provider, err := oidc.NewProvider(ctx, issuer) // 自動抓 /.well-known/openid-configuration + JWKS
    if err != nil {
        return nil, err
    }
    return provider.Verifier(&oidc.Config{ClientID: clientID}), nil
}

func handleCallback(verifier *oidc.IDTokenVerifier, cfg *oauth2.Config,
                    expectedNonce string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // ... 驗 state、取得 code ...
        token, err := cfg.Exchange(r.Context(), r.URL.Query().Get("code"),
            oauth2.SetAuthURLParam("code_verifier", loadVerifier(r)))
        if err != nil {
            http.Error(w, "exchange", http.StatusBadRequest); return
        }

        raw, ok := token.Extra("id_token").(string)
        if !ok { http.Error(w, "no id_token", http.StatusBadRequest); return }

        idTok, err := verifier.Verify(r.Context(), raw) // 簽章 + iss + aud + exp
        if err != nil { http.Error(w, "bad id_token", http.StatusUnauthorized); return }

        var claims struct {
            Sub   string `json:"sub"`
            Email string `json:"email"`
            Nonce string `json:"nonce"`
        }
        if err := idTok.Claims(&claims); err != nil {
            http.Error(w, "claims", http.StatusBadRequest); return
        }
        if claims.Nonce != expectedNonce {
            http.Error(w, "nonce", http.StatusUnauthorized); return
        }
        // ✅ 信任 claims.Sub 作為使用者識別碼
    }
}
```

---

## 七、陷阱 5：用錯 Grant Type

幾個容易誤用的 grant type：

- **Implicit Flow（`response_type=token`）**：直接把 access_token 放在 URL fragment，token 會出現在瀏覽器歷史紀錄、Referer header、JS 之中。**已淘汰，不要用。**
- **Resource Owner Password Credentials（ROPC）**：讓使用者直接把帳號密碼交給你的 App。這違反 OAuth 的初衷（讓使用者「不必」把密碼交給第三方）。**僅限於遷移舊系統時短暫使用，且必須要有 MFA / Rate Limit。**
- **Client Credentials**：服務對服務（M2M）。沒有「使用者」這個概念，**不要用來代表終端使用者登入**。

對 Web App，唯一推薦：**Authorization Code + PKCE**。

---

## 八、防禦清單（Cheat Sheet）

1. **Authorization Server 註冊 redirect_uri 用完全字串比對**；Client 端所有 `returnTo` 等轉址參數走白名單。
2. **強制使用 PKCE**（即使你有 `client_secret` 也加，OAuth 2.1 預設）。
3. **State 與 session 綁定，constant-time compare**。
4. **OIDC ID Token 驗 iss / aud / exp / sig / nonce / alg 白名單**；不要自己 parse JWT。
5. **使用最新版 OAuth 函式庫**：Spring Security 6.x、`golang.org/x/oauth2` 最新版、`coreos/go-oidc v3`。
6. **不要把 access_token 放在 URL**，只能放 `Authorization: Bearer` header。
7. **Refresh Token Rotation**：每次用 refresh token 後立刻作廢舊的，並偵測重複使用 → 視為被盜，強制登出。
8. **Token 儲存**：後端 server-side session 或 HttpOnly + Secure + SameSite=Lax 的 cookie。前端用 `localStorage` 存 token 是常見錯誤（XSS 一中就完蛋，回 Day 02）。
9. **Logout 要呼 IdP 的 `end_session_endpoint`**，並廢除自家 session。
10. **記得 Log + 監控**（Day 16）：login、token 交換失敗、refresh rotation 偵測異常，都應該打 log + 告警。

---

## 九、一句話帶走

> OAuth 2.0 的安全是「**每個 step 都要驗回來的對應物**」：state 驗 CSRF、PKCE 驗 code、nonce 驗 ID Token、JWK 驗簽章。
> 跳過任何一個，整條鏈就斷了。**用框架預設值、不要自己重寫，是後端工程師的最佳防線。**

---

## 十、延伸閱讀

- RFC 6749 — *The OAuth 2.0 Authorization Framework*
- RFC 7636 — *PKCE for OAuth Public Clients*
- RFC 8252 — *OAuth 2.0 for Native Apps*（強制 PKCE）
- OAuth 2.1 Draft — 整合最佳實務的下一版規格
- OpenID Connect Core 1.0 — `id_token` 必驗欄位與 nonce 規範
- OWASP — *OAuth 2.0 Cheat Sheet* / *JWT Cheat Sheet*
- CVE-2015-9235 — JWT `alg=none` 與 RS256↔HS256 攻擊
- Daniel Fett, *OAuth 2.0 Security Best Current Practice* (RFC 9700)

明天 Day 25 我們會把這個系列繼續推進到 **API 安全的下一層：Broken Object Property Level Authorization (BOPLA) 與 GraphQL 過度資料暴露**，看看為什麼「即使有登入、也驗了權限」，仍然可能漏資料。
