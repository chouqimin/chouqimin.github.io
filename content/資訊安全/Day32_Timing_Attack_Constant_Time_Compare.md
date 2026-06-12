---
title: "Day 32：Timing Attack（時序攻擊）—— 為什麼 `String.equals` 不能拿來比對密碼或 Token"
date: 2026-05-28
tags: ["Timing Attack", "密碼學", "側信道"]
---

# Day 32：Timing Attack（時序攻擊）—— 為什麼 `String.equals` 不能拿來比對密碼或 Token

> 後端工程師資安系列 — Day 32
> 日期：2026-05-28

> 「你以為 `if (token.equals(expected))` 是世界上最無害的一行 code，
> 但它可能正在用『回應時間』把你的 Secret Key 一個 byte 一個 byte 洩漏給攻擊者。」

---

## 一、前情提要

前 31 天我們已經談過許多「會明顯噴錯／回傳資料」的漏洞：SQL Injection、XSS、CSRF、SSRF、ReDoS……。這些攻擊的共通點是：**有明顯的 response 變化**（噴錯訊息、回傳不同內容、回傳 5xx）。

但今天的主題不一樣——**Timing Attack** 是一種「側信道（side channel）攻擊」：

> 不靠 response body、不靠 status code，而是靠「server 回應的時間差」，把秘密資料一點一點還原出來。

對後端工程師而言，這是一個「**code 看起來完全正確、邏輯也沒漏，但仍然不安全**」的隱性漏洞。它最常出現在：

- 密碼 / API Token / Session ID 的字串比對
- HMAC、JWT 簽章驗證
- CSRF Token 比對
- 一次性密碼（OTP / TOTP）比對
- Webhook signature 驗證（這也是 Day 26 提過的）

---

## 二、什麼是 Timing Attack？

### 攻擊核心：比對字串時，多數語言會「越早發現不同、越早回傳」

```java
// Java String.equals 的內部實作（簡化版）
public boolean equals(Object anObject) {
    if (this == anObject) return true;
    if (anObject instanceof String) {
        String anotherString = (String) anObject;
        int n = value.length;
        if (n == anotherString.value.length) {
            for (int i = 0; i < n; i++) {
                if (value[i] != anotherString.value[i])
                    return false;   // ← 一發現不同就回傳！
            }
            return true;
        }
    }
    return false;
}
```

這是非常合理的效能最佳化——但對攻擊者來說，這意味著：

> **「正確猜中前 N 個字元」的比對，會比「第 1 個字元就錯」多花一點點時間。**

那一點點時間就是攻擊者要的「資訊」。

### 簡化情境

假設正確 Token 是 `"abcdef"`，攻擊者完全不知道：

| 攻擊者試的 Token | 比對到第幾個 byte 才失敗 | 耗時 |
| --- | --- | --- |
| `"zzzzzz"` | 第 1 個就失敗 | 100 ns |
| `"azzzzz"` | 第 2 個才失敗 | 110 ns |
| `"abzzzz"` | 第 3 個才失敗 | 120 ns |
| `"abczzz"` | 第 4 個才失敗 | 130 ns |

差距只有 10 ns，看起來很小對吧？但攻擊者可以：

1. 把每個猜測值送 10000 次取平均，把網路抖動洗掉。
2. 透過統計學上的 t-test、Welch's test 找出「哪個前綴是對的」。
3. 一旦鎖定某個 byte，再猜下一個 byte。
4. 從 256^N 的暴力搜尋空間，降為 256 × N 的線性搜尋。

### 真實案例

- **Keyczar（2009）**：Google 的加密函式庫，HMAC 驗證使用 byte 陣列比較，被 Nate Lawson 發表的 paper 證明可遠端攻擊。
- **Django**：早期 `django.contrib.auth` 的密碼驗證會因「帳號是否存在」而有明顯回應時間差，可被用來枚舉使用者（Django ticket #20760，1.6 版修正）；Django 也提供 `constant_time_compare` 工具函式供 token／簽章比對使用。
- **Java JDK（CVE-2009-3875）**：`MessageDigest.isEqual()` 早期版本是 short-circuit 的，使得 HMAC 簽章可被 timing attack 偽造，後來在 JDK 6u17 才改為常數時間。
- **OAuth2 / OIDC 函式庫**：很多自寫的 JWT 簽章驗證沒用 constant-time compare，被多次 CVE 點名。
- **WiFi WPA2 PMK 比對**、**SSH MAC 驗證** 在歷史上都出現過 timing attack。

> 教訓：**不要相信「網路抖動會把訊號掩蓋掉」**。雲端內網的 latency jitter 已經低到 µs 等級，PoC 工具（如 `timing_attack_lab`、`racepwn`）能在實務中跑出 1 ns 等級的差異。

---

## 三、Java 範例：你以為很安全的 API Token 驗證

### 反例（會被 timing attack 攻陷）

```java
@RestController
public class ApiController {

    private static final String API_TOKEN = System.getenv("API_TOKEN");
    // 假設 API_TOKEN = "sk_live_{隨機32字元}"（範例，非真實金鑰）

    @GetMapping("/api/secret-data")
    public ResponseEntity<?> getSecret(@RequestHeader("X-Api-Token") String token) {
        // ❌ String.equals 是 short-circuit 的
        if (!API_TOKEN.equals(token)) {
            return ResponseEntity.status(401).body("Unauthorized");
        }
        return ResponseEntity.ok(loadSecret());
    }
}
```

在公司內網或同一 AZ 的雲端機器上，攻擊者只要送幾萬個請求就能還原 token 的前幾個字元。

### 正確寫法 1：用 `MessageDigest.isEqual`（JDK 6u17+ 為常數時間）

```java
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;

public class TokenComparator {
    public static boolean safeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        // MessageDigest.isEqual 自 JDK 6u17 起為 constant-time
        return MessageDigest.isEqual(aBytes, bBytes);
    }
}
```

> 注意：`Arrays.equals(byte[], byte[])` 在 JDK 17 之前是 short-circuit 的，**不要拿來比對 secret**。JDK 21 仍然不保證常數時間，請固定使用 `MessageDigest.isEqual`。

### 正確寫法 2：手寫 constant-time compare（推薦理解原理）

```java
public static boolean constantTimeEquals(byte[] a, byte[] b) {
    if (a == null || b == null) return false;
    // 注意：長度比較本身會洩漏「長度資訊」，但這通常不是 secret
    if (a.length != b.length) return false;

    int result = 0;
    for (int i = 0; i < a.length; i++) {
        // XOR：相同得 0，不同得非 0；用 |= 累積，全部跑完才能知道結果
        result |= a[i] ^ b[i];
    }
    return result == 0;
}
```

關鍵在於：**無論前面差幾個 byte，迴圈都會跑完整個陣列**，沒有 short-circuit、沒有 `break`、沒有 `return false`。

### Spring Security 內建工具

如果你用 Spring Security 5.6+，可以直接用：

```java
import java.security.MessageDigest;
// Spring 沒有獨立的工具，最佳做法仍是 MessageDigest.isEqual
boolean ok = MessageDigest.isEqual(
    expected.getBytes(StandardCharsets.UTF_8),
    received.getBytes(StandardCharsets.UTF_8)
);
```

> 提醒：Apache Commons Lang3 的 `StringUtils.equals()` **不是** constant-time，別誤用。

---

## 四、Go 範例：標準庫已經準備好了

Go 的標準庫 `crypto/subtle` 就是專門解這個問題的，後端工程師應該把它寫進肌肉記憶。

### 反例

```go
func validateToken(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("X-Api-Token")
    // ❌ == 對 string 是 short-circuit 的
    if token != expectedToken {
        http.Error(w, "Unauthorized", 401)
        return
    }
    serveSecret(w, r)
}
```

### 正解：`crypto/subtle.ConstantTimeCompare`

```go
import (
    "crypto/subtle"
    "net/http"
)

func validateToken(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("X-Api-Token")

    // ConstantTimeCompare 在「長度相同」時為常數時間
    // 長度不同會回傳 0，但長度比較本身會洩漏長度
    if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
        http.Error(w, "Unauthorized", 401)
        return
    }
    serveSecret(w, r)
}
```

### 進階：避免洩漏長度

如果連「token 長度」都想藏（極少見，但對某些可變長 secret 有用），可以先把雙方都過一輪 HMAC：

```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "crypto/subtle"
)

func safeCompareWithHmac(a, b, key []byte) bool {
    h1 := hmac.New(sha256.New, key); h1.Write(a)
    h2 := hmac.New(sha256.New, key); h2.Write(b)
    // 經過 HMAC 後兩邊都會是固定 32 bytes
    return subtle.ConstantTimeCompare(h1.Sum(nil), h2.Sum(nil)) == 1
}
```

這同時也是 HMAC signature 驗證的標準寫法（如 Day 26 的 Webhook signature 驗證）。

### Webhook signature 驗證的完整正確示範

```go
func verifyWebhook(payload, signatureHeader []byte, secret []byte) bool {
    mac := hmac.New(sha256.New, secret)
    mac.Write(payload)
    expected := mac.Sum(nil)

    // 假設 signatureHeader 是 hex
    received, err := hex.DecodeString(string(signatureHeader))
    if err != nil {
        return false
    }
    // 一定要用 hmac.Equal（內部就是呼叫 subtle.ConstantTimeCompare）
    return hmac.Equal(expected, received)
}
```

> `hmac.Equal` 是 Go 為了「永遠用 constant-time 比對 HMAC」特地包的一層糖，比起寫 `subtle.ConstantTimeCompare` 還更明確語意。

---

## 五、不只字串比對——其他常見的時序洩漏點

Timing attack 不只發生在 `equals` 上，下列情境也常見：

### 1. **使用者帳號是否存在（user enumeration）**

```java
// 反例
User u = userRepo.findByEmail(email);
if (u == null) {
    return "User not found";                      // 不論 timing：訊息就洩漏了
}
if (!bcrypt.matches(password, u.passwordHash)) {
    return "Wrong password";
}
```

不只「不同回應訊息」會洩漏，更糟的是：**找不到 user 時不會跑 bcrypt，而 bcrypt 故意慢（~100 ms）**。

攻擊者用 timing 就能分：

- 回應 < 5 ms → user 不存在
- 回應 ~ 100 ms → user 存在但密碼錯誤

**正解**：找不到 user 時，也要跑一次「假 bcrypt」維持時間恆定，並統一錯誤訊息。

```java
private static final String DUMMY_HASH = BCrypt.hashpw("dummy", BCrypt.gensalt(10));

User u = userRepo.findByEmail(email);
String hash = (u != null) ? u.passwordHash : DUMMY_HASH;
boolean ok = BCrypt.checkpw(password, hash) && u != null;
if (!ok) {
    return ResponseEntity.status(401).body("Invalid credentials"); // 統一訊息
}
```

### 2. **JWT 簽章驗證**

自己拼湊 JWT verifier 時，最後一步 `signatureBytes == calculatedBytes` **務必**用 constant-time compare。

主流庫（auth0/java-jwt、jjwt、golang-jwt/jwt v5）內部都已經用 constant-time compare，但若你自己依著 RFC 寫一遍就要注意。

### 3. **快取命中與否**

如果你的 endpoint 從快取拿資料只要 1 ms、從 DB 拿要 50 ms，攻擊者就能用 timing 探測「某筆資料是不是熱資料」、推測使用者活動。這是進階的「快取側信道」議題，這次先打住。

### 4. **業務邏輯分支**

```go
if isPremiumUser(uid) {
    // 跑複雜的 premium 邏輯，慢
} else {
    // 直接回 403，快
}
```

→ 攻擊者透過 timing 知道某 UID 是否 premium 用戶。若這是 secret 屬性，要設法讓兩條分支耗時相近，或者一律先過完權限檢查再決定回應。

---

## 六、攻擊者怎麼實作？

簡化版的 PoC 概念，幫助你理解威脅有多真：

```python
import requests, time, statistics

URL = "https://api.example.com/secret"
prefix = ""
charset = "abcdefghijklmnopqrstuvwxyz0123456789_-"

for _ in range(32):  # 假設 token 32 字元
    timings = {}
    for c in charset:
        guess = (prefix + c).ljust(32, "0")
        samples = []
        for _ in range(2000):  # 取 2000 次平均
            t0 = time.perf_counter_ns()
            requests.get(URL, headers={"X-Api-Token": guess})
            samples.append(time.perf_counter_ns() - t0)
        timings[c] = statistics.median(samples)
    best = max(timings, key=timings.get)  # 耗時最長的，是「比對到比較後面才失敗」的那個
    prefix += best
    print(f"目前猜到：{prefix}")
```

實務上會加上：
- 同時並發發多個 worker 取平均
- 用 t-test 而非 mean 來判斷顯著差異
- 排除掉異常高的樣本（GC、context switch）

> 別小看這種攻擊：研究論文 "Remote Timing Attacks Are Practical"（Brumley & Boneh, 2003）證明跨網路也能跑出 ns 等級的差異。雲端內網更不用說。

---

## 七、防禦清單（給後端工程師的肌肉記憶）

### Java（1.8 / 21）

- [ ] 比對 token / signature / OTP，**永遠用 `MessageDigest.isEqual`**。
- [ ] 避免 `String.equals`、`Arrays.equals(byte[], byte[])`、`StringUtils.equals` 用於 secret。
- [ ] HMAC 驗證後再比，不直接比 raw token。
- [ ] 找不到 user 時跑 dummy hash 維持時間恆定。
- [ ] 統一錯誤訊息（不要分「user 不存在」/「密碼錯」）。

### Go

- [ ] 比對 token / OTP，用 `crypto/subtle.ConstantTimeCompare`。
- [ ] 比對 HMAC，用 `hmac.Equal`。
- [ ] 注意：`bytes.Equal` 是 short-circuit 的，**不要拿來比 secret**。
- [ ] cookie / session id 比對也是。

### 通用

- [ ] 把 secret hashing 後再比（這層 hash 同時讓 timing 與長度都不再洩漏）。
- [ ] 對外 API 加 rate limit + 異常流量偵測（搭配 Day 17）。
- [ ] 把驗證邏輯獨立成函式並寫單元測試：故意餵不同長度 / 不同前綴的字串，確認回應時間沒有顯著差異（用 `JMH` 或 Go 的 `testing.B`）。
- [ ] code review 時把「比對 secret」當作一個 checklist 項目強制檢查。

---

## 八、快速自我檢查

把下面這幾個問題拿來檢查你的服務：

- [ ] 全 codebase grep `\.equals\(.*token`、`token.*\.equals`、`== expectedToken`、`bytes\.Equal\(.*signature`，看有沒有遺漏的點？
- [ ] 是否有自己手寫的 JWT / HMAC 驗證？最後一步是不是 constant-time？
- [ ] 登入失敗的回應時間，「user 存在 vs 不存在」是否差很多？
- [ ] 業務邏輯是否會因為「使用者屬性（是否 VIP、是否在黑名單）」造成顯著的時間差？
- [ ] 你的 secret 比對是否寫成「集中式工具函式」，避免每個 controller 各寫一個？
- [ ] CI 是否有靜態分析（Semgrep、CodeQL）規則：「禁止對 secret-like 變數用 == / equals」？

---

## 九、總結

Timing Attack 是「程式邏輯 100% 正確、但仍然不安全」的經典範例。它教會我們：

> **「安全寫法」與「正確寫法」不是同一件事。**

回到後端工程師的肌肉記憶，記住四句口訣：

> **「比 secret 不用 `equals`、HMAC 完再比、單一錯誤訊息、回應時間恆定。」**

明天我們會聊 **Day 33：Session Fixation（會話固定攻擊）**——為什麼使用者「登入之後」一定要換一張新的 Session ID？如果沿用登入前就已存在的 session，攻擊者只要事先把一個 session 塞給受害者，等他登入就能直接接管帳號。

---

*Edison 的後端資安日記 · Day 32 · 2026/05/28*
