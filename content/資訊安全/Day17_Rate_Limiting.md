---
title: "Day 17：Rate Limiting & API Throttling（速率限制與 API 流量管控）"
date: 2026-05-12
tags: ["Rate Limiting", "API 安全"]
---

# Day 17：Rate Limiting & API Throttling（速率限制與 API 流量管控）

> 「沒有速率限制的 API，就像沒有閘門的水庫——一場大雨就能讓系統崩潰，或讓駭客拿到所有資料。」

哈囉，今天我們要來聊一個**每個後端工程師都應該設計**，但常常被忽略的防禦機制：**Rate Limiting（速率限制）**。

---

## 一、什麼是 Rate Limiting？

**Rate Limiting** 指的是限制「**某個客戶端（IP、使用者、API Key）在一段時間內**」可以呼叫 API 的次數。

舉個生活化的例子：
- 銀行 ATM 不會讓你 1 秒內按 1000 次「查詢餘額」
- 餐廳不會讓單一顧客同時點 500 份餐
- 高速公路收費站會限制每秒通過的車輛數

API 也一樣，如果不限制呼叫頻率，就會出現以下問題。

---

## 二、為什麼後端工程師一定要做？

### 1. 防止暴力破解（Brute Force）
回想 Day 6，我們提到登入端點如果不限制嘗試次數，駭客可以用字典檔暴力測試密碼。

### 2. 防止 API 濫用 / 爬蟲
有人可能寫腳本爬取你網站的所有商品、文章、使用者資料。

### 3. 防止 DoS / DDoS
單一 IP 大量呼叫昂貴 API（例如報表查詢、AI 推論），會把伺服器資源吃光。

### 4. 控制成本
如果你的後端會呼叫**收費的第三方 API**（OpenAI、簡訊、雲端服務），沒有 Rate Limit 就等於把信用卡交給駭客。

### 5. 公平分配資源
SaaS 服務常依方案分級，免費用戶限制較嚴格，付費用戶較寬鬆。

---

## 三、常見的 Rate Limiting 演算法

理解演算法，才能選對工具。

### 演算法一：Fixed Window（固定窗口）

**做法**：每分鐘最多 100 次。當分鐘切換時，計數歸零。

```
[00:00-00:59]  ████████  80 次
[01:00-01:59]  ██░░░░░░  20 次
```

**優點**：實作最簡單，記憶體用量小。
**缺點**：**邊界突刺問題**——使用者可以在 00:59 打 100 次、01:00 又打 100 次，等於 1 秒內打 200 次。

### 演算法二：Sliding Window（滑動窗口）

**做法**：以「當下時間往前推 60 秒」作為計算範圍。

**優點**：平滑，不會有邊界突刺。
**缺點**：需要儲存每次請求的時間戳，較吃記憶體。

### 演算法三：Token Bucket（令牌桶）

**做法**：想像有個桶子，每秒丟 10 個令牌進去（最多 100 個）。每次請求要消耗 1 個令牌；沒令牌就拒絕。

**優點**：允許**短時間突發流量**（burst），但長期平均流量受控。最常用於 API 閘道（AWS API Gateway、Cloudflare）。

### 演算法四：Leaky Bucket（漏桶）

**做法**：請求像水滴進桶子，桶底以固定速率漏水。桶滿就拒絕新請求。

**特性**：輸出速率固定，**平滑流量**。適合保護下游昂貴的服務。

---

## 四、Java 21 範例：用 Bucket4j 實作

[Bucket4j](https://github.com/bucket4j/bucket4j) 是 Java 圈最主流的 Rate Limiting 函式庫（目前仍有維護，2024 年釋出 8.x，支援 Java 8+）。

### 1. Maven 相依套件

```xml
<dependency>
    <groupId>com.bucket4j</groupId>
    <artifactId>bucket4j_jdk17-core</artifactId>
    <version>8.10.1</version>
</dependency>
```

### 2. 單機版（記憶體型）Rate Limiter

```java
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Refill;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimitService {

    // 每個 IP 一個 Bucket
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    private Bucket createBucket() {
        // 每分鐘 100 次，允許短時間突發
        Bandwidth limit = Bandwidth.classic(
            100,
            Refill.greedy(100, Duration.ofMinutes(1))
        );
        return Bucket.builder().addLimit(limit).build();
    }

    public boolean tryConsume(String clientKey) {
        Bucket bucket = buckets.computeIfAbsent(clientKey, k -> createBucket());
        return bucket.tryConsume(1);
    }
}
```

### 3. Spring Boot Filter 整合

```java
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class RateLimitFilter implements Filter {

    private final RateLimitService rateLimitService;

    public RateLimitFilter(RateLimitService rateLimitService) {
        this.rateLimitService = rateLimitService;
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpReq = (HttpServletRequest) req;
        HttpServletResponse httpRes = (HttpServletResponse) res;

        // 用 IP 當 key（實務上請小心 X-Forwarded-For 偽造，見後文）
        String clientIp = httpReq.getRemoteAddr();

        if (!rateLimitService.tryConsume(clientIp)) {
            httpRes.setStatus(429);  // Too Many Requests
            httpRes.setHeader("Retry-After", "60");
            httpRes.getWriter().write("Rate limit exceeded. Please try again later.");
            return;
        }

        chain.doFilter(req, res);
    }
}
```

> **注意**：上面的單機版只在「**單一 JVM**」內有效。如果你的服務有多台機器，使用者請求被負載均衡分散到不同節點，計數會不準。**正式環境必須用分散式儲存**（見下節）。

---

## 五、分散式 Rate Limiting：Redis + Lua

多節點環境最常見的做法是用 **Redis 集中計數**。

### Java 範例：Bucket4j + Redis (Lettuce)

```java
import io.github.bucket4j.Bucket;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.RedisClient;
import io.lettuce.core.api.StatefulRedisConnection;

import java.time.Duration;

public class DistributedRateLimit {

    private final ProxyManager<byte[]> proxyManager;

    public DistributedRateLimit(RedisClient client) {
        StatefulRedisConnection<String, byte[]> connection =
            client.connect(new io.lettuce.core.codec.RedisCodec<String, byte[]>() { /* ... */ });

        this.proxyManager = LettuceBasedProxyManager
            .builderFor(connection)
            .withExpirationStrategy(/* ... */)
            .build();
    }

    public boolean tryConsume(String userId) {
        Bucket bucket = proxyManager.builder()
            .build(userId.getBytes(), () ->
                io.github.bucket4j.BucketConfiguration.builder()
                    .addLimit(io.github.bucket4j.Bandwidth.classic(
                        100,
                        io.github.bucket4j.Refill.greedy(100, Duration.ofMinutes(1))
                    ))
                    .build()
            );
        return bucket.tryConsume(1);
    }
}
```

---

## 六、Go 範例：用 `golang.org/x/time/rate`

Go 標準函式庫的衍生套件 `x/time/rate` 提供了 Token Bucket 實作，是最常用的方案之一。

### 1. 安裝

```bash
go get golang.org/x/time/rate
```

### 2. 單機版 Middleware

```go
package main

import (
    "net/http"
    "sync"

    "golang.org/x/time/rate"
)

type IPRateLimiter struct {
    limiters map[string]*rate.Limiter
    mu       sync.Mutex
    r        rate.Limit
    b        int
}

func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
    return &IPRateLimiter{
        limiters: make(map[string]*rate.Limiter),
        r:        r,
        b:        b,
    }
}

func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
    i.mu.Lock()
    defer i.mu.Unlock()

    limiter, exists := i.limiters[ip]
    if !exists {
        limiter = rate.NewLimiter(i.r, i.b)
        i.limiters[ip] = limiter
    }
    return limiter
}

// Middleware：每秒 10 個請求，桶子大小 20（允許短時間突發）
var limiter = NewIPRateLimiter(10, 20)

func RateLimitMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        ip := r.RemoteAddr // 實務上要解析 X-Forwarded-For
        if !limiter.GetLimiter(ip).Allow() {
            w.Header().Set("Retry-After", "1")
            http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("OK"))
    })
    http.ListenAndServe(":8080", RateLimitMiddleware(mux))
}
```

### 3. 分散式版本：用 Redis + 滑動窗口

```go
package main

import (
    "context"
    "time"

    "github.com/redis/go-redis/v9"
)

// 用 Redis 原子操作實作 Sliding Window
// Lua 腳本確保「讀取-判斷-寫入」是原子的
const slidingWindowLua = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])

-- 移除過期請求
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)

-- 計算當前數量
local count = redis.call('ZCARD', key)
if count >= limit then
    return 0
end

-- 加入當前請求
redis.call('ZADD', key, now, now)
redis.call('EXPIRE', key, math.ceil(window / 1000))
return 1
`

type RedisRateLimiter struct {
    rdb    *redis.Client
    script *redis.Script
}

func NewRedisRateLimiter(rdb *redis.Client) *RedisRateLimiter {
    return &RedisRateLimiter{
        rdb:    rdb,
        script: redis.NewScript(slidingWindowLua),
    }
}

// Allow 回傳是否允許請求
// key: 客戶端識別（IP or userID）
// windowMs: 時間窗口（毫秒）
// limit: 窗口內最多次數
func (r *RedisRateLimiter) Allow(ctx context.Context, key string, windowMs int64, limit int) (bool, error) {
    now := time.Now().UnixMilli()
    result, err := r.script.Run(ctx, r.rdb, []string{key}, now, windowMs, limit).Int()
    if err != nil {
        return false, err
    }
    return result == 1, nil
}
```

---

## 七、實務上常踩的坑

### 坑 1：用 `request.getRemoteAddr()` 鎖到的是反向代理 IP

在 Nginx / Cloudflare / AWS ALB 後面，`getRemoteAddr()` 拿到的會是**代理的 IP**，不是真實使用者 IP。

**正確做法**：
1. 讀取 `X-Forwarded-For` 或 `X-Real-IP`
2. **白名單你信任的代理 IP**，不可無條件相信標頭（駭客會偽造）

```java
// 偽 code，僅示意原則
private String getClientIp(HttpServletRequest req) {
    String forwarded = req.getHeader("X-Forwarded-For");
    if (forwarded != null && isFromTrustedProxy(req.getRemoteAddr())) {
        // 只取第一個 IP（最左邊是原始 client）
        return forwarded.split(",")[0].trim();
    }
    return req.getRemoteAddr();
}
```

### 坑 2：只用 IP 鎖很容易誤殺

- 企業 NAT 後可能有上百人共用一個 IP
- 大學宿舍、機場 Wi-Fi 也是同一個出口 IP

**建議分層**：
- **未登入**：用 IP（限制較鬆）
- **已登入**：用 user ID（限制較嚴）
- **昂貴 API**：再加上 endpoint 維度

### 坑 3：忘了 429 要回 `Retry-After` 標頭

```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1715600000
```

這些標頭可以幫助前端 / SDK 自動退避（exponential backoff）。

### 坑 4：限流邏輯本身會放大攻擊

如果你在「計數時」就讀寫資料庫，駭客只要丟超快的流量，就會把資料庫拖垮——**還沒擋到攻擊，自己先死了**。

**解法**：
- 限流檢查放在**最上層**（Nginx、CDN、API Gateway）
- 應用程式內部用記憶體 / Redis，不要碰主資料庫

### 坑 5：登入 API 應該用「**帳號**」鎖，不是用 IP

如果只鎖 IP，駭客換 IP 就能繼續暴力破解。
如果只鎖帳號，攻擊者可以拿你的帳號當「DoS 武器」，讓你登不進去。

**標準做法**：兩者都鎖，**且 IP 鎖比較鬆，帳號鎖比較嚴**，並考慮 CAPTCHA 機制。

---

## 八、不同層級的 Rate Limiting 部署

| 層級 | 範例 | 適合擋什麼 |
|------|------|-----------|
| **CDN / WAF** | Cloudflare, AWS WAF | 大規模 DDoS、明顯惡意流量 |
| **API Gateway** | Kong, AWS API Gateway, Nginx | 每個 API、每個 API Key 的配額 |
| **應用程式內** | Bucket4j, x/time/rate | 業務邏輯（單一帳號的特定行為） |
| **下游服務保護** | Resilience4j, sentinel | 保護自己呼叫第三方時不超量 |

**核心觀念**：**多層防禦**。CDN 擋 90% 流量，閘道擋 9%，應用層擋 1% 精細的攻擊。

---

## 九、今日小檢核 ✅

回頭看看你負責的服務，問自己：

- [ ] 登入 / 註冊 / 忘記密碼端點有 Rate Limit 嗎？
- [ ] 對外公開的 API 有設定每分鐘 / 每小時上限嗎？
- [ ] 有區分「未登入 IP 級」和「已登入 user 級」嗎？
- [ ] 回傳 429 時有附 `Retry-After` 嗎？
- [ ] 如果有多台機器，計數是用 Redis 等分散式儲存嗎？
- [ ] 限流檢查在資料庫查詢「之前」就執行嗎？
- [ ] 有監控 429 的觸發頻率嗎？（接續 Day 16 的監控）

---

## 十、明日預告

明天我們會聊 **軟體供應鏈安全（Supply Chain Security）**——你的專案有很高比例的程式碼其實是別人寫的（第三方相依套件）。當某個套件被植入後門、或爆出已知漏洞時你怎麼辦？我們會談相依套件漏洞掃描、SBOM（軟體物料清單）與 lock file 的重要性。

掰掰，明天見！🔐

---

### 參考資源

- OWASP API Security Top 10：[API4:2023 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- Bucket4j 官方文件：https://bucket4j.com/
- Go `x/time/rate` 套件：https://pkg.go.dev/golang.org/x/time/rate
- Cloudflare 對 Rate Limiting 的科普文章
