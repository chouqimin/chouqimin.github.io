---
title: "Day 06 — 暴力破解防禦：Rate Limiting、帳號鎖定、CAPTCHA 與異常通知"
date: 2026-04-28
tags: ["認證", "Rate Limiting", "Brute Force"]
---

# Day 06 — 暴力破解防禦：Rate Limiting、帳號鎖定、CAPTCHA 與異常通知

> 日期：2026-04-28
> 適合對象：後端工程師初學者
> 主題難度：★★★☆☆（多層防禦的取捨設計）

---

## 一、為什麼這個主題這麼重要？

過去五天我們做了不少功課：
- Day 04：密碼用 bcrypt/argon2 好好雜湊。
- Day 05：登入後用 Session 或 JWT 維持身份。

但有一個前提沒被守住——**「使用者根本還沒登入成功」的那個 `/login` 端點本身**。如果攻擊者可以無限次嘗試，那不管你密碼怎麼存、Session 多安全都沒意義：他總有一天會猜中，或是用別人外洩的帳密直接打進來。

這在實務上有三種常見攻擊：

| 攻擊類型 | 說明 | 特徵 |
| :-- | :-- | :-- |
| **Brute Force（暴力破解）** | 對單一帳號嘗試大量密碼 | 同一帳號、密碼狂變 |
| **Credential Stuffing（撞庫）** | 拿別站外洩的帳密來這裡試 | 帳號密碼都變、命中率高 |
| **Password Spraying（密碼噴灑）** | 用幾個熱門密碼去試大量帳號 | 帳號狂變、密碼固定（如 `Password2025!`） |

OWASP 把這類問題歸類在 **A07:2021 — Identification and Authentication Failures**，幾乎所有公開過的大型帳號外洩事件都跟「沒做好登入限流」脫不了關係。

> 一句話：**你不一定擋得住攻擊者偷帳密，但你絕對擋得住他試 100 萬次。**

---

## 二、防禦層級總覽

沒有單一機制能解決全部問題，要疊起來：

```
   [入口]
     │
     ▼
  ┌──────────────────────────┐
  │ 1. IP / 全域速率限制       │  擋住自動化掃描器
  ├──────────────────────────┤
  │ 2. 每帳號速率限制          │  擋住針對單帳號的暴力破解
  ├──────────────────────────┤
  │ 3. 漸進式延遲（Backoff）    │  讓自動化嘗試成本越來越高
  ├──────────────────────────┤
  │ 4. CAPTCHA（可疑時才觸發）  │  區分人 vs 機器
  ├──────────────────────────┤
  │ 5. 帳號臨時凍結           │  最後一道防線（小心別變 DoS）
  ├──────────────────────────┤
  │ 6. 異常登入偵測 + 通知      │  即使被打進來也能被使用者發現
  ├──────────────────────────┤
  │ 7. MFA / 2FA             │  即使帳密對了也擋得住（Day 後續再講）│
  └──────────────────────────┘
```

下面逐層展開。

---

## 三、第一層：Rate Limiting（速率限制）

### 3.1 兩個維度同時做

| 維度 | 目的 | 缺點（單獨用時） |
| :-- | :-- | :-- |
| **依 IP 限制** | 擋住來自單一機器的暴力嘗試 | NAT/Proxy 會誤傷（一棟大樓共用 IP）；殭屍網路繞過 |
| **依帳號限制** | 擋住針對單一帳號的攻擊 | 會被惡意人用來鎖死別人帳號 |

**正確做法是兩者都做，閾值不同**：
- IP：1 分鐘內 30 次失敗 → 暫停。
- 帳號：5 分鐘內 5 次失敗 → 進入下一層（延遲 / CAPTCHA）。

### 3.2 演算法選擇

最常見三種：

```
Token Bucket    ：固定速率補 token，允許短暫爆量。最常用。
Leaky Bucket    ：固定速率漏水，平滑流量。適合下游有處理能力上限。
Sliding Window  ：精確計算最近 N 秒的次數。準但稍貴。
```

對「登入失敗計數」這種低頻場景，三種都行；通常選 **Sliding Window** 或 **固定視窗 + Redis** 就夠用。

### 3.3 Java（Spring Boot + Bucket4j + Redis）

Bucket4j 是 Java 生態最成熟的限流套件，支援 Redis、Hazelcast 做分散式限流。

```java
// build.gradle
// implementation 'com.bucket4j:bucket4j-core:8.10.1'
// implementation 'com.bucket4j:bucket4j-redis:8.10.1'

@Service
public class LoginRateLimiter {

    private final ProxyManager<String> proxyManager; // Redis-backed

    public LoginRateLimiter(ProxyManager<String> proxyManager) {
        this.proxyManager = proxyManager;
    }

    /** 每個帳號：5 分鐘 5 次失敗 */
    public boolean tryAcquireForAccount(String email) {
        BucketConfiguration config = BucketConfiguration.builder()
            .addLimit(Bandwidth.simple(5, Duration.ofMinutes(5)))
            .build();
        Bucket bucket = proxyManager.builder()
            .build("login:account:" + email.toLowerCase(), () -> config);
        return bucket.tryConsume(1);
    }

    /** 每個 IP：1 分鐘 30 次失敗 */
    public boolean tryAcquireForIp(String ip) {
        BucketConfiguration config = BucketConfiguration.builder()
            .addLimit(Bandwidth.simple(30, Duration.ofMinutes(1)))
            .build();
        Bucket bucket = proxyManager.builder()
            .build("login:ip:" + ip, () -> config);
        return bucket.tryConsume(1);
    }
}

@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginReq req,
                               HttpServletRequest http) {
    String ip = ClientIpResolver.resolve(http);

    if (!rateLimiter.tryAcquireForIp(ip)) {
        return ResponseEntity.status(429).body("Too Many Requests");
    }
    if (!rateLimiter.tryAcquireForAccount(req.email())) {
        // 注意：訊息要曖昧，不要洩漏「這個帳號被鎖了」 vs 「密碼錯誤」
        return ResponseEntity.status(429).body("請稍後再試");
    }

    boolean ok = userService.verify(req.email(), req.password());
    if (!ok) {
        return ResponseEntity.status(401).body("帳號或密碼錯誤");
    }
    // ... 發 Session / JWT
    return ResponseEntity.ok(...);
}
```

> ⚠️ `ClientIpResolver` 別只看 `request.getRemoteAddr()`。在 Nginx / ALB 後面要讀 `X-Forwarded-For` 的**最左可信位**——而且要先把這個 header 設成「只接受可信代理寫入」，否則攻擊者自己塞一個假 IP 就能繞過限流。

### 3.4 Go（`golang.org/x/time/rate` + Redis）

單機可以用標準的 `rate.Limiter`；分散式環境推薦 Redis-backed 套件如 `github.com/go-redis/redis_rate/v10`。

```go
import (
    "context"
    "net/http"
    "time"

    "github.com/go-redis/redis_rate/v10"
    "github.com/redis/go-redis/v9"
)

type LoginLimiter struct {
    rdb *redis.Client
    rl  *redis_rate.Limiter
}

func NewLoginLimiter(rdb *redis.Client) *LoginLimiter {
    return &LoginLimiter{rdb: rdb, rl: redis_rate.NewLimiter(rdb)}
}

func (l *LoginLimiter) AllowIP(ctx context.Context, ip string) (bool, error) {
    res, err := l.rl.Allow(ctx, "login:ip:"+ip,
        redis_rate.PerMinute(30))
    if err != nil {
        return false, err
    }
    return res.Allowed > 0, nil
}

func (l *LoginLimiter) AllowAccount(ctx context.Context, email string) (bool, error) {
    res, err := l.rl.Allow(ctx, "login:acct:"+email,
        // 5 分鐘 5 次
        redis_rate.Limit{Rate: 5, Period: 5 * time.Minute, Burst: 5})
    if err != nil {
        return false, err
    }
    return res.Allowed > 0, nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    ip := clientIP(r) // 同樣注意 X-Forwarded-For 的可信來源
    var body struct {
        Email, Password string
    }
    _ = json.NewDecoder(r.Body).Decode(&body)

    if ok, _ := limiter.AllowIP(r.Context(), ip); !ok {
        http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
        return
    }
    if ok, _ := limiter.AllowAccount(r.Context(), body.Email); !ok {
        http.Error(w, "請稍後再試", http.StatusTooManyRequests)
        return
    }
    // ... 驗證密碼、發 token
}
```

---

## 四、第二層：漸進式延遲（Progressive Backoff）

「直接擋下」對使用者體驗很差，**慢慢拖時間**反而更聰明：

```
失敗次數     延遲
   1         0 秒
   2         1 秒
   3         2 秒
   4         4 秒
   5         8 秒
   6        16 秒
   ...      指數退避（最大上限例如 30 秒）
```

對真人來說：偶爾打錯密碼根本沒感覺。
對自動化腳本來說：本來 1 秒可以試 100 次，現在每次都要等——一天試的次數從幾百萬掉到幾千。

實作要點：
- 延遲要在**伺服器端**做（用 `Thread.sleep` / `time.Sleep`），而不是回 4xx 讓 client 自己等。
- 但要小心執行緒被吃光：`Thread.sleep` 會整條佔住一個 servlet 容器執行緒，登入流量一大就可能把執行緒池塞滿。真正能避開的是非阻塞模型（例如 Spring WebFlux 用 reactor 的延遲算子，連線在等待時不佔執行緒）；Go 的 goroutine 很輕量，比較沒這個問題。
- 失敗計數用 Redis 存 `attempts:{email}`，TTL 跟著最後一次失敗滑動。

```java
int attempts = redis.incr("login:fail:" + email);
redis.expire("login:fail:" + email, Duration.ofMinutes(15));

if (attempts > 1) {
    long delayMs = Math.min(30_000L, (long) Math.pow(2, attempts - 2) * 1000);
    Thread.sleep(delayMs);
}
```

```go
attempts, _ := rdb.Incr(ctx, "login:fail:"+email).Result()
rdb.Expire(ctx, "login:fail:"+email, 15*time.Minute)

if attempts > 1 {
    delay := time.Duration(math.Min(30, math.Pow(2, float64(attempts-2)))) * time.Second
    time.Sleep(delay)
}
```

登入**成功**後，要把這個計數器清掉：`redis.del("login:fail:" + email)`。

---

## 五、第三層：CAPTCHA（最後再用）

CAPTCHA 是雙面刃：
- 優點：對自動化腳本最有效。
- 缺點：拖累所有合法使用者體驗，無障礙友善度差。

**準則：不要一開始就放，等可疑了再觸發。**

觸發條件範例：
- 該 IP / 帳號失敗次數 ≥ 3。
- IP 來自高風險地區或已知 Tor 出口節點。
- User-Agent 看起來像 bot。

主流選擇：
- **reCAPTCHA v3**（評分制，0.0–1.0，越低越像 bot）— 對使用者最不打擾，但要送資料給 Google。
- **hCaptcha** — Google 替代品，注重隱私。
- **Cloudflare Turnstile** — 不用解圖，主要做 challenge，免費。

後端只需驗證 token：

```java
// reCAPTCHA v3 驗證
RestTemplate rt = new RestTemplate();
MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
form.add("secret", recaptchaSecret);
form.add("response", req.recaptchaToken());
form.add("remoteip", ip);
Map resp = rt.postForObject(
    "https://www.google.com/recaptcha/api/siteverify", form, Map.class);
boolean success = (Boolean) resp.get("success");
double score = ((Number) resp.get("score")).doubleValue();
if (!success || score < 0.5) {
    return ResponseEntity.status(403).body("可疑流量");
}
```

---

## 六、第四層：帳號臨時凍結

「鎖定帳號」聽起來很安全，但**直接做永久鎖定就變成 DoS 攻擊載具**——攻擊者只要去你登入頁狂打別人帳號的錯密碼，就能讓全公司每個人都登不進來。

正確做法：

| 觸發 | 行為 | 解除方式 |
| :-- | :-- | :-- |
| 連續 5 次失敗 | **暫時凍結 15 分鐘** | 自動解除 |
| 連續 10 次失敗 | 凍結 1 小時 + 寄信通知本人 | 自動解除 / 信中連結確認本人 |
| 偵測到撞庫模式（同 IP 試多帳號） | 該 IP 全域封鎖 | 人工 / 24 小時自動解除 |

**訊息一律曖昧**：對「正確帳號 + 錯密碼」「不存在的帳號」「帳號被鎖」回應同一句「帳號或密碼錯誤，請稍後再試」，避免攻擊者用回應差異去枚舉哪些 email 真的有註冊（這叫 **Account Enumeration**）。

---

## 七、第五層：異常登入偵測與通知

即使前四層全被繞過，最後還有一招：**讓使用者自己發現**。

### 7.1 怎麼判斷「異常」？

最常用的訊號：
- **新裝置**：發一個 device cookie（不是 session cookie，是長效的識別票），第一次登入時記下來；下次沒帶這張票就視為新裝置。
- **新地點 / 新國家**：用 IP 查 GeoIP，跨國登入直接通知。
- **奇怪時間**：使用者一向台灣時區白天用，突然凌晨三點從巴西登入。
- **不可能的旅程（Impossible Travel）**：5 分鐘前在台北，現在在莫斯科。

### 7.2 通知策略

- 新裝置 / 新國家成功登入 → **立即寄 email**：「您的帳號剛從 [位置 / 裝置] 登入。如不是您本人，請點此修改密碼並登出所有裝置。」
- 多次失敗 → 寄通知（讓使用者知道有人在試）。
- 密碼變更 / Email 變更 → 寄到**舊** email 也通知一次。

這幾乎是 0 成本但 ROI 最高的安全措施。

---

## 八、放在一起：完整流程

```
POST /login
  │
  ├─ [1] 檢查 IP 限流 ─── 超過 → 429
  │
  ├─ [2] 檢查帳號限流 ── 超過 → 429（曖昧訊息）
  │
  ├─ [3] 漸進式延遲（依此帳號失敗次數）
  │
  ├─ [4] 失敗 ≥ 3 次 → 要求 CAPTCHA token
  │
  ├─ 驗證密碼
  │     ├─ 錯：失敗計數 +1 → 401
  │     │      └─ 失敗 ≥ 5 → 帳號暫凍 15 分
  │     └─ 對：清空失敗計數
  │
  ├─ [5] 比對 device cookie / GeoIP
  │     └─ 異常 → 寄通知 email
  │
  └─ 發 Session / JWT，回 200
```

---

## 九、今天的 Checklist

設計或 review 一個登入端點時，逐條確認：

1. [ ] 我有對 **IP** 做速率限制嗎？
2. [ ] 我有對 **帳號** 做速率限制嗎？
3. [ ] 失敗訊息是否**曖昧**（不洩漏帳號是否存在、是否被鎖）？
4. [ ] 連續失敗有**漸進式延遲**或 CAPTCHA 嗎？
5. [ ] 帳號鎖定是否是**臨時**的（不是永久）？
6. [ ] 是否避免「攻擊者打你登入頁就能鎖死合法用戶」這個 DoS 缺口？
7. [ ] 失敗次數計數的 key 是否有 **TTL**（避免無限累積）？
8. [ ] 登入成功後是否會寄**新裝置 / 新地點通知信**？
9. [ ] `X-Forwarded-For` 是否只信任你自己的 reverse proxy（避免被偽造 IP 繞過限流）？
10. [ ] 重要帳號（管理員、金融）是否強制 **MFA**？

---

## 十、小結

| 層級 | 防的是 | 主要工具 |
| :-- | :-- | :-- |
| IP 限流 | 自動化掃描 | Bucket4j / redis_rate |
| 帳號限流 | 針對性暴力破解 | Redis 計數器 |
| 漸進式延遲 | 拖慢自動化成本 | 指數退避 |
| CAPTCHA | 區分人/機器 | Turnstile / reCAPTCHA |
| 帳號臨時凍結 | 最後一道防線 | TTL 鎖 |
| 異常通知 | 已被打進來時被發現 | GeoIP + email |

**沒有銀彈，只有層層疊加。** 任何單一機制都能被繞過或都會誤傷使用者，但這六層加起來，**讓攻擊成本指數上升、同時保留正常使用者順暢的體驗**。

從這六層的設計也可以看出一個重要的資安設計哲學：

> **預設 deny，例外才 allow；同時要讓誤傷可被自我恢復。**

明天我們會換一個視角，從「身份驗證」走到「授權」——談**Broken Access Control / IDOR**：使用者已經登入了，但他能存取別人的資料嗎？這是 OWASP 2021 排名第一的風險，也是各種「改網址 ID 就看到別人帳單」新聞的本質。

---

> 參考資料：
> - OWASP Authentication Cheat Sheet — Account Lockout / Login Throttling
> - OWASP Credential Stuffing Prevention Cheat Sheet
> - NIST SP 800-63B §5.2.2（Throttling）
> - Bucket4j 8.x 官方文件
> - `github.com/go-redis/redis_rate` v10 文件
> - Cloudflare Turnstile / Google reCAPTCHA v3 文件
