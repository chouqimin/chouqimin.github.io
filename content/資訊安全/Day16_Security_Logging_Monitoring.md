---
title: "Day 16：安全日誌與監控（Security Logging & Monitoring）"
date: 2026-05-11
tags: ["日誌與監控", "DevSecOps", "OWASP Top 10"]
---

# Day 16：安全日誌與監控（Security Logging & Monitoring）

> **適合對象**：後端工程師初學者
> **語言範例**：Java（1.8 / 21）、Go
> **OWASP 對應**：A09:2021 - Security Logging and Monitoring Failures

---

## 一、為什麼日誌跟資安有關？

很多新手會覺得：「日誌不就是為了 debug 嗎？跟資安有什麼關係？」

讓我說一個真實的故事。

某電商公司被駭了，攻擊者偷走了 50 萬筆會員資料。事後檢討時，資安團隊翻 log 發現：

- 同一個 IP 在凌晨 3 點對 `/api/login` 發出 **18 萬次** 請求
- 在攻擊發生前一週，這個 IP 就已經在掃描 `/admin/*`、`/.env`、`/wp-login.php`
- 攻擊者最後是透過某個帳號的密碼破解登入，然後在系統中潛伏了 **6 個月**

問題不是「沒有 log」——log 都在。

**真正的問題是：沒有人在看 log，也沒有警報。**

這就是 OWASP 把「Logging & Monitoring Failures」列入 Top 10 的原因：你能不能在攻擊「發生中」就察覺，決定了損失是 1 個帳號還是 50 萬筆資料。

---

## 二、安全日誌應該記什麼？

把日誌分成兩種：

1. **應用日誌（Application Log）**：debug 用，記 request、response、stack trace。
2. **安全日誌（Audit Log / Security Log）**：給資安團隊看，記「誰在什麼時候做了什麼敏感操作」。

後者最容易被忽略。下面這些事件，**一定要進安全日誌**：

| 類別 | 事件範例 |
|---|---|
| 認證 | 登入成功、登入失敗、登出、密碼錯誤、帳號被鎖 |
| 授權 | 存取被拒絕（403）、權限提升、角色變更 |
| 帳號管理 | 註冊、刪除帳號、修改 email、修改密碼、啟用 / 停用 2FA |
| 敏感操作 | 轉帳、下單、刪除資料、匯出資料、API key 建立 / 刪除 |
| 系統 | 設定變更、伺服器重啟、密鑰輪替、資料庫連線失敗 |
| 異常 | 大量 4xx / 5xx、輸入驗證失敗、可疑 payload（SQLi / XSS 特徵） |

每一筆事件至少要記：

- **誰**（user id、IP、user agent）
- **什麼時候**（精確到毫秒，UTC 時區）
- **做了什麼**（事件類型、目標資源）
- **結果**（成功 / 失敗，失敗原因）
- **關聯 ID**（trace id / request id，方便串起一連串請求）

---

## 三、絕對不能寫進日誌的東西

剛接觸日誌的工程師最常踩的雷，就是「為了好 debug，把整包 request 印出來」。

```java
// 反面教材
logger.info("Login request: {}", request);   // request.password 也跟著進 log 了
logger.debug("HTTP headers: {}", headers);   // Authorization header 也跟著進 log 了
```

**Log 通常會被收集到中央日誌系統**（ELK、Splunk、Datadog、CloudWatch），權限通常比資料庫還寬。一旦密碼、token 進 log，等同已洩漏。

下面這些，絕對不要寫進日誌：

- 密碼（即使是雜湊後的也最好不要）
- API key、token、JWT、refresh token
- 信用卡號、CVV
- 身分證字號、護照號碼、健保卡號
- 完整的 cookie / Authorization header
- 個人健康資料、生物特徵

如果一定要記，做「遮罩（masking）」：

- email：`a***@gmail.com`
- 信用卡：`**** **** **** 1234`
- 手機：`0912-***-678`
- token：只記前 6 碼 + 後 4 碼

---

## 四、Java 實作：用 SLF4J + MDC 做結構化安全日誌

### 4.1 為什麼要「結構化日誌」？

純文字 log 很難搜尋：

```
2026-05-12 03:21:11 INFO  Login failed for user
```

結構化 log（JSON）容易被機器解析、聚合、做警報：

```json
{"ts":"2026-05-12T03:21:11.123Z","level":"WARN","event":"LOGIN_FAILED","user":"a***@gmail.com","ip":"1.2.3.4","reason":"BAD_PASSWORD","trace_id":"abc-123"}
```

### 4.2 Java 21 + Spring Boot 範例

定義一個安全日誌的工具類，集中所有寫法，避免每個工程師各寫各的：

```java
// SecurityAuditLogger.java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

public final class SecurityAuditLogger {

    // 用獨立的 logger name，可以在 logback 中單獨輸出到 audit.log
    private static final Logger AUDIT = LoggerFactory.getLogger("SECURITY_AUDIT");

    private SecurityAuditLogger() {}

    public static void loginSuccess(String userId, String ip) {
        try (var ignored = MDC.putCloseable("event", "LOGIN_SUCCESS")) {
            MDC.put("user_id", userId);
            MDC.put("ip", ip);
            AUDIT.info("Login success");
        } finally {
            MDC.clear();
        }
    }

    public static void loginFailed(String maskedUser, String ip, String reason) {
        try (var ignored = MDC.putCloseable("event", "LOGIN_FAILED")) {
            MDC.put("user", maskedUser);
            MDC.put("ip", ip);
            MDC.put("reason", reason);
            AUDIT.warn("Login failed");
        } finally {
            MDC.clear();
        }
    }

    public static void accessDenied(String userId, String resource) {
        try (var ignored = MDC.putCloseable("event", "ACCESS_DENIED")) {
            MDC.put("user_id", userId);
            MDC.put("resource", resource);
            AUDIT.warn("Access denied");
        } finally {
            MDC.clear();
        }
    }
}
```

在登入流程裡呼叫：

```java
// AuthService.java
public LoginResult login(LoginRequest req, String clientIp) {
    User user = userRepo.findByEmail(req.email()).orElse(null);

    if (user == null) {
        // 注意：不要在 log 印完整 email，做遮罩
        SecurityAuditLogger.loginFailed(mask(req.email()), clientIp, "USER_NOT_FOUND");
        return LoginResult.fail();
    }
    if (!passwordHasher.matches(req.password(), user.passwordHash())) {
        SecurityAuditLogger.loginFailed(mask(req.email()), clientIp, "BAD_PASSWORD");
        return LoginResult.fail();
    }

    SecurityAuditLogger.loginSuccess(user.id(), clientIp);
    return LoginResult.success(user);
}

private static String mask(String email) {
    if (email == null || !email.contains("@")) return "***";
    int at = email.indexOf('@');
    return email.charAt(0) + "***" + email.substring(at);
}
```

### 4.3 logback-spring.xml 設定 JSON 輸出（額外加分）

```xml
<configuration>
    <!-- 一般 app log 維持原狀 -->
    <appender name="APP" class="ch.qos.logback.core.ConsoleAppender">
        <encoder><pattern>%d{ISO8601} %-5level [%thread] %logger - %msg%n</pattern></encoder>
    </appender>

    <!-- audit log 單獨寫到 audit.log，JSON 格式 -->
    <appender name="AUDIT" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/audit.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>logs/audit-%d{yyyy-MM-dd}.log.gz</fileNamePattern>
            <maxHistory>365</maxHistory>
        </rollingPolicy>
        <encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
    </appender>

    <logger name="SECURITY_AUDIT" level="INFO" additivity="false">
        <appender-ref ref="AUDIT"/>
    </logger>

    <root level="INFO"><appender-ref ref="APP"/></root>
</configuration>
```

關鍵：**audit log 跟一般 log 分開檔案、分開保存週期**。一般 log 可能 30 天就清掉，audit log 通常依法規要保 1 年以上。

---

## 五、Go 實作：用 slog 做安全日誌

Go 1.21+ 內建的 `log/slog` 是現代結構化日誌的標準作法。

```go
// security_audit.go
package audit

import (
    "context"
    "log/slog"
    "os"
    "strings"
)

var auditLogger *slog.Logger

func init() {
    // audit log 寫到獨立檔案
    f, err := os.OpenFile("logs/audit.log",
        os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
    if err != nil {
        panic(err)
    }
    auditLogger = slog.New(slog.NewJSONHandler(f, &slog.HandlerOptions{
        Level: slog.LevelInfo,
    }))
}

func LoginSuccess(ctx context.Context, userID, ip string) {
    auditLogger.InfoContext(ctx, "login_success",
        slog.String("event", "LOGIN_SUCCESS"),
        slog.String("user_id", userID),
        slog.String("ip", ip),
    )
}

func LoginFailed(ctx context.Context, maskedUser, ip, reason string) {
    auditLogger.WarnContext(ctx, "login_failed",
        slog.String("event", "LOGIN_FAILED"),
        slog.String("user", maskedUser),
        slog.String("ip", ip),
        slog.String("reason", reason),
    )
}

func MaskEmail(email string) string {
    at := strings.Index(email, "@")
    if at < 1 {
        return "***"
    }
    return string(email[0]) + "***" + email[at:]
}
```

呼叫端：

```go
func (s *AuthService) Login(ctx context.Context, req LoginReq, ip string) error {
    user, err := s.repo.FindByEmail(ctx, req.Email)
    if err != nil {
        audit.LoginFailed(ctx, audit.MaskEmail(req.Email), ip, "USER_NOT_FOUND")
        return ErrInvalidCredentials
    }
    if !s.hasher.Matches(req.Password, user.PasswordHash) {
        audit.LoginFailed(ctx, audit.MaskEmail(req.Email), ip, "BAD_PASSWORD")
        return ErrInvalidCredentials
    }
    audit.LoginSuccess(ctx, user.ID, ip)
    return nil
}
```

實際輸出的 audit.log（每行一個 JSON）：

```json
{"time":"2026-05-12T03:21:11.123Z","level":"WARN","msg":"login_failed","event":"LOGIN_FAILED","user":"a***@gmail.com","ip":"1.2.3.4","reason":"BAD_PASSWORD"}
```

---

## 六、Trace ID：把一連串請求串起來

一次完整的攻擊通常會打很多 endpoint。如果每個 log 沒有共同的識別碼，事後追查時根本不知道誰是誰。

作法：在最外層（filter / middleware）產一個 `trace_id`，整個請求生命週期內都帶著。

### Java（Spring Boot Filter）

```java
@Component
public class TraceIdFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {
        String traceId = req.getHeader("X-Trace-Id");
        if (traceId == null || traceId.isBlank()) {
            traceId = UUID.randomUUID().toString();
        }
        MDC.put("trace_id", traceId);
        res.setHeader("X-Trace-Id", traceId);
        try {
            chain.doFilter(req, res);
        } finally {
            MDC.remove("trace_id");
        }
    }
}
```

只要在 logback pattern 中加上 `%X{trace_id}`，所有 log 都會自動帶這個 ID。

### Go（middleware）

```go
func TraceMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        traceID := r.Header.Get("X-Trace-Id")
        if traceID == "" {
            traceID = uuid.NewString()
        }
        ctx := context.WithValue(r.Context(), "trace_id", traceID)
        w.Header().Set("X-Trace-Id", traceID)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

---

## 七、不只是寫——還要「監控」與「警報」

寫了 log 卻沒人看，等於沒寫。最少要設定以下警報：

| 警報條件 | 觸發門檻範例 |
|---|---|
| 單一 IP 大量登入失敗 | 5 分鐘內 > 20 次 |
| 同一帳號從多個國家登入 | 同一帳號 1 小時內出現 ≥ 2 個國家 |
| 403 / 401 量暴增 | 與前 7 天同時段相比 > 5 倍 |
| 5xx 突增 | 1 分鐘內 > 50 個 |
| 敏感 API 異常 | `/admin/*`、`/export/*` 被非管理員存取 |
| 新建立 API key 後立刻大量呼叫 | 5 分鐘內新 key 呼叫 > 1000 次 |

實務上會把 audit log 灌到 ELK / Loki / Datadog，搭配 Grafana / Kibana 做 dashboard，再用 Alertmanager / PagerDuty 發警報。

---

## 八、檢查清單（給後端工程師的 self-check）

- [ ] 認證、授權、敏感操作都有寫安全日誌
- [ ] 密碼、token、信用卡號、PII 都做了遮罩
- [ ] 安全日誌跟一般 app log 分檔案、分保存週期
- [ ] 日誌是結構化（JSON）格式，方便搜尋與聚合
- [ ] 每個請求都有 trace_id，可以串起整個請求鏈
- [ ] 時間戳用 UTC + ISO 8601，精確到毫秒
- [ ] 日誌檔案權限設好（其他使用者讀不到）
- [ ] 中央化日誌系統有設定基本警報規則
- [ ] 日誌本身有做「防止刪除 / 修改」的保護（write once / 雜湊鏈）

---

## 九、今日重點 TL;DR

1. **沒有 log = 出事後死在沙灘上**，但 log 沒人看 = 也是一樣。
2. 區分「應用日誌」與「安全日誌」，後者要單獨輸出、長期保存。
3. 永遠不要把密碼、token、PII 寫進日誌；要記也要做遮罩。
4. 用結構化（JSON）格式 + trace_id，事後才追得起來。
5. 不只是寫——還要監控與警報。出事的當下就要知道，不是 6 個月後才發現。

明天我們會聊 **Day 17：速率限制與 DoS 防護（Rate Limiting）**，這也是「監控」之後最自然的下一步——光知道有人在打你還不夠，你要能擋住他。

---

> 📚 **延伸閱讀**
> - OWASP Top 10 - A09:2021 Security Logging and Monitoring Failures
> - OWASP Logging Cheat Sheet
> - NIST SP 800-92: Guide to Computer Security Log Management
