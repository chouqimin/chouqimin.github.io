---
title: "Day 19：TLS/HTTPS 與加密失誤（Cryptographic Failures）"
date: 2026-05-15
tags: ["TLS", "密碼學", "OWASP Top 10"]
---

# Day 19：TLS/HTTPS 與加密失誤（Cryptographic Failures）

> **適合對象**：後端工程師初學者
> **語言範例**：Java（1.8 / 21）、Go
> **OWASP 對應**：A02:2021 - Cryptographic Failures（前身為 Sensitive Data Exposure）

---

## 一、開場故事：一杯咖啡換來一個帳號

阿明在咖啡廳用筆電登入公司的內部系統，連的是免費 Wi-Fi。
他輸入帳號密碼，順利登入，開始工作。

然而坐在隔壁桌的，是一位拿著筆電的攻擊者。他用 Wireshark 攔截了 Wi-Fi 流量，發現阿明連的內部系統用的是 `http://internal.company.com`——**沒有 HTTPS**。

於是攻擊者在封包中看到了這樣的內容：

```
POST /login HTTP/1.1
Host: internal.company.com
Content-Type: application/x-www-form-urlencoded

username=ming&password=Abc12345!
```

帳號密碼**明文**就這樣被攔下來了。

> **教訓**：在 2026 年的今天，**沒有 HTTPS 就等於把資料寫在明信片上**，任何中間人（咖啡廳的路由器、ISP、駭客）都看得到。
> 但 HTTPS 不只是「裝個憑證」這麼簡單——加密用錯方式，跟沒加密一樣慘。

---

## 二、什麼是 Cryptographic Failures？

OWASP 把這類問題定義為：**沒有正確保護敏感資料**，導致資料外洩或被竄改。

常見的「加密失誤」包括：

1. **資料明文傳輸**：HTTP 而不是 HTTPS、明文連資料庫
2. **用了已被破解的演算法**：MD5、SHA-1、DES、RC4
3. **加密模式選錯**：AES-ECB（會洩漏資料結構）
4. **金鑰寫死在程式碼**：硬編碼 secret key
5. **隨機數不夠隨機**：用 `Math.random()` 產生 token
6. **TLS 設定錯誤**：允許 TLS 1.0/1.1、停用憑證驗證
7. **敏感資料記在 log 裡**：把信用卡號、密碼寫到日誌

我們今天聚焦在 **TLS/HTTPS** 與**對稱/雜湊加密選擇**這兩大塊。

---

## 三、TLS/HTTPS 是怎麼運作的？

簡化版的 TLS 1.3 握手：

```
Client                                   Server
  |                                        |
  |---- ClientHello (支援的加密套件) ----->|
  |                                        |
  |<--- ServerHello + 憑證 + 公鑰 ---------|
  |                                        |
  |---- (用公鑰加密的對稱金鑰) ----------->|
  |                                        |
  |<==== 之後都用對稱金鑰加密通訊 ========>|
```

關鍵幾件事：

- **憑證（Certificate）**：證明「我真的是 example.com」，由 CA（憑證授權單位，如 Let's Encrypt、DigiCert）簽發
- **對稱金鑰**：握手後雙方共用，用來加密實際資料（AES-GCM 是主流）
- **完整性驗證**：每個封包都有 MAC，被竄改會被發現

> **重點**：HTTPS 保證了 **機密性 + 完整性 + 身份驗證**。少一個都不安全。

---

## 四、後端常見的 5 個加密失誤

### 失誤 1：用 MD5 / SHA-1 雜湊密碼

```java
// ❌ 錯誤：MD5 已經被破解，撞庫攻擊（rainbow table）秒殺
String hash = DigestUtils.md5Hex(password);
```

`md5("123456")` 是 `e10adc3949ba59abbe56e057f20f883e`——這個值早就被 Google 收錄。

✅ **正解（已在 Day 4 介紹）**：用 **bcrypt / Argon2 / scrypt**。

```java
// Java：使用 BCrypt
String hash = BCrypt.hashpw(password, BCrypt.gensalt(12));
```

```go
// Go：使用 bcrypt
import "golang.org/x/crypto/bcrypt"

hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
```

> ⚠️ MD5、SHA-1、SHA-256 都**不該用來雜湊密碼**。它們算太快，攻擊者一秒可以試幾億次。

---

### 失誤 2：AES 用 ECB 模式

ECB（Electronic Codebook）是 AES 最簡單的模式，但**相同明文會產生相同密文**，會洩漏資料結構。

經典的「ECB 企鵝」就是把企鵝圖用 ECB 加密後，輪廓還清晰可見。

```java
// ❌ 錯誤：ECB 模式
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
```

✅ **正解**：用 **AES-GCM**（帶認證的加密模式）：

```java
// Java 21：AES-GCM
SecureRandom random = new SecureRandom();
byte[] iv = new byte[12];
random.nextBytes(iv);

Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
GCMParameterSpec spec = new GCMParameterSpec(128, iv);
cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
// 別忘了把 iv 跟 ciphertext 一起存（iv 不需要保密，但要唯一）
```

```go
// Go：AES-GCM
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
)

block, _ := aes.NewCipher(key)
gcm, _ := cipher.NewGCM(block)

nonce := make([]byte, gcm.NonceSize())
rand.Read(nonce)

ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
// gcm.Seal 會把 nonce 接在前面，方便之後解密
```

> ⚠️ 黃金原則：**永遠不要用 ECB**。預設選 GCM。

---

### 失誤 3：隨機數用錯 API

產生 token、session ID、CSRF token 都需要**密碼學等級的隨機數**。

```java
// ❌ 錯誤：Math.random() 不是密碼學安全的
String token = String.valueOf(Math.random() * 1000000);

// ❌ 錯誤：Random 也不安全（可預測）
Random r = new Random();
byte[] bytes = new byte[16];
r.nextBytes(bytes);
```

✅ **正解**：用 `SecureRandom`：

```java
// Java
SecureRandom random = new SecureRandom();
byte[] tokenBytes = new byte[32];
random.nextBytes(tokenBytes);
String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
```

```go
// Go：crypto/rand（不是 math/rand!）
import (
    "crypto/rand"
    "encoding/base64"
)

bytes := make([]byte, 32)
rand.Read(bytes)
token := base64.RawURLEncoding.EncodeToString(bytes)
```

> ⚠️ Go 的 `math/rand` **絕對不能**用來產生 token，要用 `crypto/rand`。Java 同理：別用 `java.util.Random`。

---

### 失誤 4：TLS 客戶端關掉憑證驗證

後端服務常常需要呼叫其他 API（外部金流、簡訊閘道、第三方服務）。新手最常踩的雷：

```java
// ❌ 災難級錯誤：信任所有憑證
TrustManager[] trustAll = new TrustManager[]{
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }
};
SSLContext sc = SSLContext.getInstance("TLS");
sc.init(null, trustAll, new SecureRandom());
```

```go
// ❌ 災難級錯誤
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
client := &http.Client{Transport: tr}
```

這等於**自願讓中間人攻擊（MITM）成功**——攻擊者可以偽造憑證，你的後端會傻傻地接受。

✅ **正解**：使用預設驗證行為，遇到自簽憑證就把 CA 加到 trust store，**不要關閉驗證**。

```java
// Java：預設就會驗證，什麼都不用做
HttpClient client = HttpClient.newHttpClient();
```

```go
// Go：預設就會驗證
client := &http.Client{}
```

> ⚠️ 如果搜尋程式碼出現 `InsecureSkipVerify: true` 或 `trustAll`，那是**紅燈警報**。

---

### 失誤 5：TLS 版本太舊、加密套件太弱

伺服器端如果允許 TLS 1.0 / 1.1、SSLv3，會被攻擊者降級攻擊（POODLE、BEAST、CRIME 等）。

✅ **正解**：

- **最低限度允許 TLS 1.2**，最好強制 TLS 1.3
- 禁用弱加密套件（RC4、3DES、DES、export ciphers）
- 啟用 HSTS（Day 9 介紹過）

**Nginx 範例**：

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
ssl_prefer_server_ciphers on;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

**Go 設定 server**：

```go
server := &http.Server{
    Addr: ":443",
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
        },
    },
}
```

> 💡 用 **SSL Labs Test**（https://www.ssllabs.com/ssltest/）檢查你的 HTTPS 設定，目標是 A 或 A+。

---

## 五、敏感資料還會從哪裡漏出來？

除了傳輸層，後端工程師還容易在這些地方洩密：

| 洩密管道 | 例子 | 解法 |
|---|---|---|
| Log 檔案 | `log.info("user logged in: " + password)` | 過濾敏感欄位，密碼/卡號/token 不入 log |
| 錯誤訊息 | `500: SQL error: SELECT * FROM users WHERE password='xxx'` | production 模式關閉 stack trace 對外 |
| URL 參數 | `GET /reset?token=abc123` | 用 POST + body，或 token 一次性即失效 |
| 備份檔 | 整個 DB dump 放在 S3 public bucket | 備份要加密 + 嚴格的 IAM |
| Cache | Redis 存了未加密的信用卡號 | 敏感資料盡量別 cache；要 cache 就加密 |

---

## 六、實戰：寫一個「對外 API 呼叫」的安全版本

情境：你的後端需要呼叫外部金流 API `https://payment.example.com/charge`。

**Java 21 版本**：

```java
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public class SecurePaymentClient {
    // 預設使用系統 trust store，TLS 1.3 優先
    private final HttpClient client = HttpClient.newBuilder()
        .version(HttpClient.Version.HTTP_2)
        .connectTimeout(Duration.ofSeconds(5))
        .build();

    public String charge(String token, double amount) throws Exception {
        // 1. URL 寫死成 HTTPS，不接受外部傳入的 URL
        // 2. token 從金鑰管理服務取得，不寫死
        // 3. 不 log 完整 token，只 log 後 4 碼
        String body = String.format("{\"amount\":%.2f}", amount);

        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create("https://payment.example.com/charge"))
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(10))
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();

        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
        // 失敗時也不要把完整 response body 寫進 log
        return resp.body();
    }
}
```

**Go 版本**：

```go
package payment

import (
    "bytes"
    "crypto/tls"
    "fmt"
    "io"
    "net/http"
    "time"
)

type Client struct {
    http  *http.Client
    token string
}

func New(token string) *Client {
    return &Client{
        http: &http.Client{
            Timeout: 10 * time.Second,
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{
                    MinVersion: tls.VersionTLS12,
                    // 注意：不要設定 InsecureSkipVerify
                },
            },
        },
        token: token,
    }
}

func (c *Client) Charge(amount float64) (string, error) {
    body := fmt.Sprintf(`{"amount":%.2f}`, amount)
    req, err := http.NewRequest("POST",
        "https://payment.example.com/charge",
        bytes.NewBufferString(body))
    if err != nil {
        return "", err
    }
    req.Header.Set("Authorization", "Bearer "+c.token)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.http.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    b, _ := io.ReadAll(resp.Body)
    return string(b), nil
}
```

---

## 七、總結：加密失誤防禦清單

對後端工程師而言，請把以下清單貼在 Code Review 旁邊：

**傳輸層（TLS）**

- ☐ 所有對外、對內 API 都用 HTTPS
- ☐ 最低支援 TLS 1.2，建議 TLS 1.3
- ☐ 禁用 SSLv3 / TLS 1.0 / TLS 1.1
- ☐ 永遠不要 `InsecureSkipVerify` 或 `trustAll`
- ☐ 啟用 HSTS（`Strict-Transport-Security`）
- ☐ 用 SSL Labs 測試，目標 A+

**演算法選擇**

- ☐ 密碼用 bcrypt / Argon2，不用 MD5 / SHA-1 / SHA-256
- ☐ 對稱加密用 **AES-GCM**，不用 ECB
- ☐ 雜湊用 SHA-256 或 SHA-3（如果不是密碼用途）
- ☐ 簽章用 Ed25519 / ECDSA / RSA-2048+
- ☐ Token 產生用 `SecureRandom`（Java）或 `crypto/rand`（Go）

**金鑰與資料**

- ☐ Secret 不寫死在程式碼裡（Day 15 介紹）
- ☐ 敏感資料不入 log、不放 URL
- ☐ 錯誤訊息不洩露內部細節
- ☐ 備份檔案要加密

---

## 八、明天預告

Day 20 我們會介紹另一個經典攻擊：**Open Redirect（開放重新導向）**。當你的網站把使用者導向一個「由參數決定的網址」（例如登入後的 `?redirect=...`），攻擊者就能把這個跳轉拿去做釣魚，或串接成 OAuth token 竊取。

> 💬 **今日思考題**：
> 你目前服務的程式碼裡，有沒有 `Math.random()`、`new Random()`、`md5(`、`InsecureSkipVerify`、`AES/ECB` 這幾個關鍵字？
> 用 IDE 全域搜尋一次，把它們改掉，今天的功課就完成了。

---

*Day 19 of 365 — 持續學習，每天進步一點點 🔐*
