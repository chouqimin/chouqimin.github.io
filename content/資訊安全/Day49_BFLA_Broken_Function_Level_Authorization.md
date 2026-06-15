---
title: "Day 49：BFLA — Broken Function Level Authorization（功能層級授權失效）"
date: 2026-06-14
tags: ["BFLA", "存取控制", "授權", "API 安全"]
---

# Day 49：BFLA — Broken Function Level Authorization（功能層級授權失效）

> 「我們的 admin 後台有做權限控管啊，前端會把管理選單藏起來。」
> —— 藏選單不是授權。攻擊者不用你的前端，他直接 `curl /admin/users`。

（接續 Day48 預告：Day07 講過 IDOR 是「**物件層級**」授權失效——A 使用者讀到 B 使用者的資料；今天講「**功能層級**」——一般使用者直接呼叫管理員才能用的 API。我們會用 Spring Security 與 Go middleware 示範「預設拒絕」的路由授權設計。）

---

## 一、什麼是 BFLA？

BFLA 是 OWASP API Security Top 10 的 **API5:2023 — Broken Function Level Authorization**。

定義很簡單：**API 只檢查了「你是誰（認證）」，卻沒檢查「你能不能用這個功能（授權）」。**

三種典型樣貌：

1. **垂直越權**：一般使用者呼叫管理員功能。
   `GET /api/admin/users`、`POST /api/users/{id}/ban` —— 只要登入就能打，伺服器沒驗角色。
2. **隱藏端點**：以為「沒寫在文件、前端沒連結」就安全。
   攻擊者掃 `/admin`、`/internal`、`/debug`、`/actuator`，或從 JS bundle 裡翻出 API 路徑。
3. **HTTP 方法繞過**：`GET /api/users/1` 有擋，但 `DELETE /api/users/1` 沒設定授權規則，直接放行。

### 和 IDOR（Day07）、BOPLA（Day25）的關係

| | 層級 | 問題 | 範例 |
|---|---|---|---|
| **IDOR** (Day07) | 物件 | 能用這功能，但碰到了**別人的資料** | 改 URL 的 `id` 看到別人訂單 |
| **BFLA** (今天) | 功能 | 根本**不該用這個功能** | 一般用戶呼叫 `/admin/users` |
| **BOPLA** (Day25) | 屬性 | 能碰這物件，但讀/寫了**不該碰的欄位** | 註冊時送 `"role":"admin"` |

三層要分開檢查，缺一不可。

---

## 二、漏洞長什麼樣？

### ❌ 錯誤示範 1：只驗登入，不驗角色（Java / Spring）

```java
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    // 只要通過 JWT filter（有登入）就能進來，沒檢查角色！
    @GetMapping("/users")
    public List<UserDto> listAllUsers() {
        return userService.findAll();
    }

    @PostMapping("/users/{id}/ban")
    public void banUser(@PathVariable Long id) {
        userService.ban(id);
    }
}
```

```java
// SecurityConfig：致命的「預設放行」
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/login", "/api/register").permitAll()
    .anyRequest().authenticated()   // ← 任何登入者都能打 /api/admin/**
);
```

攻擊只需要一行：

```bash
# 用「一般使用者」的 token 直接打管理 API
curl -H "Authorization: Bearer $NORMAL_USER_TOKEN" https://api.example.com/api/admin/users
```

### ❌ 錯誤示範 2：把授權做在前端（Go）

```go
// 前端：if user.role === 'admin' 才顯示「刪除使用者」按鈕
// 後端：
r.HandleFunc("/api/admin/users/{id}", deleteUserHandler).Methods("DELETE")
// deleteUserHandler 裡只解析 JWT 拿 userID，從沒看過 role
```

前端的角色判斷只是 UI 體驗，**不是安全邊界**。

### ❌ 錯誤示範 3：規則用「列舉拒絕」而不是「預設拒絕」

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/admin/users").hasRole("ADMIN")  // 只擋了這條
    .anyRequest().authenticated()
);
// 後來同事新增了 /api/admin/reports → 忘了加規則 → 直接對所有登入者開放
```

每加一個端點都要「記得」加規則的設計，遲早會漏。

---

## 三、正確做法：預設拒絕（Deny by Default）

核心原則只有一條：**授權規則應該寫成「沒有明確允許的，一律拒絕」**，而不是「沒有明確拒絕的，一律允許」。

### ✅ Java 21 + Spring Security 6

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity   // 啟用 @PreAuthorize
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable) // 純 API + JWT，見 Day03 的討論
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                // 1. 白名單：明確列出公開端點
                .requestMatchers("/api/auth/login", "/api/auth/register").permitAll()
                // 2. 管理區：整個 /api/admin/** 綁定角色，新端點自動套用
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                // 3. 一般 API
                .requestMatchers("/api/**").authenticated()
                // 4. 預設拒絕：沒被上面規則命中的，全部擋掉（而非 authenticated）
                .anyRequest().denyAll()
            );
        return http.build();
    }
}
```

再加上**方法層級的第二道防線**（defense in depth，路由規則改壞時還有保險）：

```java
@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {

    @PreAuthorize("hasRole('ADMIN')")   // 就算路由規則被改壞，這裡還會擋
    @PostMapping("/{id}/ban")
    public void banUser(@PathVariable Long id) {
        userService.ban(id);
    }
}
```

**Java 8 / Spring Security 4~5（舊版語法）：**

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        .antMatchers("/api/auth/**").permitAll()
        .antMatchers("/api/admin/**").hasRole("ADMIN")
        .antMatchers("/api/**").authenticated()
        .anyRequest().denyAll();   // 同樣的預設拒絕
}
```

> 注意：`hasRole("ADMIN")` 比對的是 authority `ROLE_ADMIN`（Spring 自動加 `ROLE_` 前綴）。角色要從**伺服器端的資料來源**（DB / token 簽發時寫入的 claim）取得，而且 JWT 必須驗簽（Day37 講過 algorithm confusion），否則攻擊者自己改 claim 就升權了。

### ✅ Go：以 middleware 實作「預設拒絕」的路由群組

Go 標準庫沒有內建授權框架，慣用做法是**把授權做成 middleware，綁在路由群組上**，讓「新端點自動繼承規則」：

```go
package main

import (
    "context"
    "net/http"
)

type ctxKey string

const roleKey ctxKey = "role"

// 認證 middleware：解析並驗證 JWT，把 role 放進 context
func authenticate(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims, err := verifyJWT(r.Header.Get("Authorization")) // 必須驗簽！
        if err != nil {
            http.Error(w, "unauthorized", http.StatusUnauthorized)
            return
        }
        ctx := context.WithValue(r.Context(), roleKey, claims.Role)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// 授權 middleware：要求特定角色
func requireRole(role string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        got, _ := r.Context().Value(roleKey).(string)
        if got != role {
            // 回 403（已認證但無權限）；資源是否存在不想透露時可回 404
            http.Error(w, "forbidden", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func main() {
    // 公開區
    public := http.NewServeMux()
    public.HandleFunc("POST /api/auth/login", loginHandler)

    // 一般使用者區（須登入）
    user := http.NewServeMux()
    user.HandleFunc("GET /api/orders", listMyOrdersHandler)

    // 管理區：整個 mux 包在 requireRole 裡，
    // 之後在 admin 上新增任何路由，都「自動」需要 ADMIN —— 這就是預設拒絕
    admin := http.NewServeMux()
    admin.HandleFunc("GET /api/admin/users", listUsersHandler)
    admin.HandleFunc("DELETE /api/admin/users/{id}", deleteUserHandler)

    root := http.NewServeMux()
    root.Handle("/api/auth/", public)
    root.Handle("/api/admin/", authenticate(requireRole("ADMIN", admin)))
    root.Handle("/api/", authenticate(user))
    // 沒被命中的路徑：ServeMux 預設 404，等同拒絕

    http.ListenAndServe(":8080", root)
}
```

（用 Gin / Echo 的話同理：`adminGroup := r.Group("/api/admin", AuthMiddleware(), RequireRole("ADMIN"))`，授權綁在 group，不要逐條 handler 各自實作。）

---

## 四、容易被忽略的細節

1. **HTTP 方法也要涵蓋**：規則寫 `requestMatchers("/api/admin/**")` 是「所有方法」；若你逐條指定 `GET /admin/users`，別忘了 `POST`/`DELETE`/`PATCH` 也要規則覆蓋——這正是「預設拒絕」能救你的地方。
2. **內部/維運端點**：Spring Boot Actuator（`/actuator/env`、`/actuator/heapdump`）、pprof（`/debug/pprof/`）、GraphQL introspection 都是常見 BFLA 受災戶。要嘛關掉，要嘛綁管理權限或只開放內網。
3. **角色不要信任 client 給的任何欄位**：`X-Role: admin` header、body 裡的 `isAdmin`、未驗簽的 JWT claim，全都不可信（串回 Day08 Mass Assignment、Day38 header 偽造）。
4. **403 vs 404**：403 會洩漏「這個管理端點存在」。對外部攻擊面，回 404 可以減少資訊洩漏；內部 API 用 403 方便除錯，二選一但要一致。
5. **微服務間也要授權**：別假設「打得到內部服務的都是自己人」（Day10 SSRF 就是反例）。service-to-service 也要帶身分（mTLS / 簽章，見 Day48）。

---

## 五、怎麼測試自己的 API？

最簡單的自查法——**拿低權限 token 重放高權限請求**：

```bash
# 1. 用 admin 帳號操作一次後台，從瀏覽器 DevTools 抄下請求
# 2. 把 Authorization 換成一般使用者的 token 重放
curl -X DELETE https://api.example.com/api/admin/users/42 \
     -H "Authorization: Bearer $NORMAL_USER_TOKEN"
# 期望：403/404。若回 200 → BFLA
```

進一步可以在 CI 寫自動化測試：對每個標記為 admin-only 的路由，用一般使用者 token 打一輪，斷言全部非 2xx。

```java
// Spring Boot 整合測試範例
@Test
void normalUserCannotAccessAdminApi() throws Exception {
    mockMvc.perform(get("/api/admin/users")
            .header("Authorization", "Bearer " + normalUserToken))
        .andExpect(status().isForbidden());
}
```

---

## 六、後端工程師的 Checklist

- [ ] 路由授權採**預設拒絕**：Spring 用 `anyRequest().denyAll()` 收尾；Go 把授權 middleware 綁在路由群組上。
- [ ] 管理功能除了路由規則，方法上再加 `@PreAuthorize`（雙重防線）。
- [ ] 角色來自伺服器端資料或已驗簽的 token claim，絕不信任 client 傳的角色欄位。
- [ ] 授權規則涵蓋**所有 HTTP 方法**，不要只擋 GET。
- [ ] Actuator / pprof / debug / internal 端點：關閉、綁權限、或限內網。
- [ ] CI 中加入「低權限 token 打高權限端點」的自動化測試。
- [ ] 前端隱藏按鈕只是 UX，所有授權判斷必須在後端重做一次。

---

## 七、一句話總結

> **認證回答「你是誰」，授權回答「你能做什麼」——BFLA 就是只做了前者。**
> 解法是把授權規則設計成「預設拒絕」，讓新端點忘了設定時是「打不通」而不是「全開放」。

---

## 延伸閱讀

- OWASP API Security Top 10 (2023) — API5: Broken Function Level Authorization
- Spring Security Reference — Authorize HttpServletRequests
- OWASP Cheat Sheet — Authorization Cheat Sheet
- 前文：Day07 IDOR（物件層級）、Day25 BOPLA（屬性層級）、Day08 Mass Assignment、Day37 JWT Algorithm Confusion

---

明天預告：**Day 50 — GraphQL 安全專題：Introspection、深度攻擊與 Batching 濫用**
（Day25 提過 GraphQL 容易過度暴露資料，明天完整講 GraphQL 特有的攻擊面：introspection 洩漏 schema、巢狀查詢打爆資料庫（query depth/complexity 限制）、alias batching 繞過 rate limit（串回 Day17），並用 Java graphql-java 與 Go gqlgen 示範防禦設定。）
