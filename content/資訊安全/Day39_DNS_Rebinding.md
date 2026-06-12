---
title: "Day 39 — DNS Rebinding：把瀏覽器變成內網跳板"
date: 2026-06-04
tags: ["DNS", "SSRF", "瀏覽器安全"]
---

# Day 39 — DNS Rebinding：把瀏覽器變成內網跳板

> 後端工程師資安教學 · Day 39
> 適合對象：剛接觸 Web 後端、Java（1.8 / 21）與 Go 開發者
> 前情提要：Day 10 我們講過 SSRF（伺服器自己被騙去打內網），今天我們講一個更陰險的版本——攻擊者騙的不是你的後端，而是「使用者的瀏覽器」，再用瀏覽器當跳板去打你內網的服務。

---

## 一、先講一個生活化的比喻

想像你公司有一棟辦公大樓，門禁是用「臉部辨識」。

某天有一位「外送員」要來送便當：

1. 外送員走到大門口，攝影機掃描他的臉，警衛確認「沒問題，是外送員」，幫他開門。
2. 一進門，外送員立刻拿出面具戴上，變成一個「公司 CEO 的臉」。
3. 他走到內部電梯前，電梯感應器又掃了一次臉——「喔，是 CEO」，直接送他到頂樓機密辦公室。

問題出在哪？**第一次驗證跟第二次驗證之間，身分換掉了**，但內部系統以為「人還是同一個」。

DNS Rebinding 就是這招的網路版：
- 瀏覽器去解析網域 `evil.com` → 第一次拿到攻擊者外部 IP `1.2.3.4`，正常拜訪一個網頁。
- 同一個分頁過幾秒後，又解析一次 `evil.com` → 這次 DNS 回的是 `127.0.0.1` 或 `192.168.0.1`。
- 瀏覽器的「同源政策（Same-Origin Policy）」只看**網域字串**，不看 IP，所以它以為「還是同一個源」，乖乖把請求送去 `127.0.0.1`，而且 JavaScript 還可以讀取回應。

於是攻擊者用網頁，**透過受害者的瀏覽器去打受害者的內網或本機服務**。

---

## 二、為什麼後端工程師要在意？

很多後端工程師會說：「我有開發環境跑在 `localhost:8080`，反正沒對外，安全。」

錯。只要受害者的瀏覽器一打開攻擊者的網站，那個網站就能：

1. 掃描受害者電腦上的 `localhost:1`～`localhost:65535`，看哪些 port 開著。
2. 對你的 Spring Boot Actuator、Go pprof、Redis HTTP 介面、Elasticsearch、Kibana、Jenkins、Hadoop YARN 發 HTTP 請求。
3. 讀取回應內容，傳回給攻擊者。

你以為很安全的「只綁 localhost 的開發服務」、「公司內網的管理介面」、「家用路由器 192.168.1.1」、「IoT 裝置」——通通是攻擊面。

**真實案例**：
- 2018 年 Geth、Parity 等以太坊節點預設綁 `127.0.0.1:8545`，攻擊者用 DNS Rebinding 偷加密貨幣。
- 2019 年 Logitech Harmony Hub、多款 Smart TV 被研究員證實可遠端控制。
- Kubernetes Dashboard、Docker daemon 過去都中過。

---

## 三、攻擊流程詳解

```
受害者瀏覽器                  DNS 伺服器（攻擊者擁有）         目標服務
                              evil.com                          
   │                              │                                
   │ 1) DNS query evil.com        │                                
   │─────────────────────────────>│                                
   │                              │                                
   │ 2) 回答 A=1.2.3.4 TTL=1秒    │                                
   │<─────────────────────────────│                                
   │                              │                                
   │ 3) GET http://evil.com/      │                                
   │  載入攻擊者的 JS              │                                
   │                              │                                
   │ 4) JS 等 2 秒，再 fetch       │                                
   │    http://evil.com/secret    │                                
   │                              │                                
   │ 5) DNS query evil.com        │                                
   │─────────────────────────────>│                                
   │                              │                                
   │ 6) 這次回答 A=127.0.0.1      │                                
   │   （rebind！）               │                                
   │<─────────────────────────────│                                
   │                              │                                
   │ 7) 瀏覽器以為「還在 evil.com」                                  
   │    把請求送到 127.0.0.1      │                                
   │──────────────────────────────────────────────────────────────>│
   │                              │                                │
   │ 8) 內部服務回應機敏資料        │                                │
   │<──────────────────────────────────────────────────────────────│
   │                              │                                
   │ 9) JS 讀到回應，POST 回攻擊者 │                                
```

關鍵：**步驟 7 沒有跨域，因為網域字串還是 `evil.com`**。瀏覽器的同源政策被繞過。

---

## 四、為什麼這跟 SSRF 不一樣？

| 比較 | SSRF | DNS Rebinding |
|------|------|---------------|
| 攻擊發起者 | 後端伺服器自己 | 受害者的瀏覽器 |
| 利用對象 | 後端的網路位置 | 使用者的網路位置（本機 / 內網） |
| 防禦點 | 後端要做 IP 黑名單、URL 驗證 | 後端要做 Host header 驗證、CORS 嚴格化 |
| 攻擊管道 | 任何接收 URL 的 API | 任何不檢查 Host header 的內網服務 |

簡單說：**SSRF 打的是你伺服器的內網，DNS Rebinding 打的是使用者的內網**。但對你身為「內網服務的開發者」來說，兩個都會把你的服務暴露出去。

---

## 五、後端要做的四道防線

### 防線 1：Host header 白名單（最重要）

DNS Rebinding 攻擊時，請求的 `Host:` header 會是攻擊者的網域（例如 `Host: evil.com`），不是 `localhost`。**你的服務只要拒絕非預期的 Host，攻擊就失敗了**。

#### Java（Spring Boot）範例

```java
// ✅ 在 Filter 層攔截非法 Host
@Component
public class HostHeaderValidationFilter extends OncePerRequestFilter {

    private static final Set<String> ALLOWED_HOSTS = Set.of(
        "localhost",
        "localhost:8080",
        "127.0.0.1",
        "127.0.0.1:8080",
        "admin.mycompany.com"
    );

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse resp,
                                    FilterChain chain)
            throws ServletException, IOException {

        String host = req.getHeader("Host");
        if (host == null || !ALLOWED_HOSTS.contains(host.toLowerCase())) {
            resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
            resp.getWriter().write("Invalid Host header");
            return;
        }
        chain.doFilter(req, resp);
    }
}
```

注意三點：
1. 比對要**完全相等**，不要用 `contains` 或 `endsWith`，否則 `evil.com.localhost` 之類的會繞過。
2. 比對前**轉小寫**，因為 Host header 不分大小寫。
3. 連 port 都要比對清楚（很多時候 `Host: localhost` 跟 `Host: localhost:8080` 是不同的）。

#### Go（net/http）範例

```go
package main

import (
    "net/http"
    "strings"
)

var allowedHosts = map[string]bool{
    "localhost":         true,
    "localhost:8080":    true,
    "127.0.0.1":         true,
    "127.0.0.1:8080":    true,
    "admin.mycompany.com": true,
}

func hostHeaderGuard(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        host := strings.ToLower(r.Host) // r.Host 已經是 Host header 的值
        if !allowedHosts[host] {
            http.Error(w, "Invalid Host header", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/api/admin", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("admin data"))
    })
    http.ListenAndServe("127.0.0.1:8080", hostHeaderGuard(mux))
}
```

### 防線 2：強制要求認證

很多本機服務、Docker Daemon、開發工具預設「綁 localhost 就不用認證」。錯。**只要綁網路 socket，就要假設可能被打到**，認證一定要有。

最簡單的做法：要求 `Authorization: Bearer <token>` 或 client cert。Rebinding 出去的 JS 拿不到 token，攻擊就斷了。

### 防線 3：CORS 不要設成 wildcard

```java
// ❌ 危險
response.setHeader("Access-Control-Allow-Origin", "*");
response.setHeader("Access-Control-Allow-Credentials", "true"); // 而且這兩個一起會被瀏覽器拒絕，但有些人會手動配對來繞過
```

如果你的 API 需要回 CORS header，請列**明確的白名單來源**。DNS Rebinding 雖然是同源，但若是 cross-origin preflight 攻擊，嚴格的 CORS 也能擋下一部分變形攻擊。

### 防線 4：DNS 層面拒絕「rebind 到內網 IP」

這通常是 OS / 路由器層做的，但你身為後端可以提醒運維：

- 公司內部 DNS 解析器設定**「禁止外部網域解析回內網 IP」**（dnsmasq 有 `stop-dns-rebind` 選項；Unbound 有 `private-address` 設定）。
- 瀏覽器層：Chrome / Firefox 已對部分常見私網 IP 做防護，但不要全靠它。

---

## 六、Spring Boot Actuator 的真實陷阱

Spring Boot Actuator 的 `/actuator/env`、`/actuator/heapdump`、`/actuator/jolokia` 都可能洩漏機敏資訊。很多人以為「我把 actuator 綁在 management port、只開內網」就安全。

但只要開發者的瀏覽器中了 DNS Rebinding，攻擊者的 JS 可以從受害者瀏覽器直接打 `http://internal-admin:9090/actuator/env`，因為瀏覽器以為「還是 evil.com」。

**正確做法**：
1. Actuator 一律要求認證（Spring Security 保護 `/actuator/**`）。
2. 啟用上面那個 `HostHeaderValidationFilter`。
3. 敏感 endpoint 直接關掉：`management.endpoint.env.enabled=false`。

---

## 七、檢查清單

每次當你開發一個「綁在 localhost 或內網」的服務時，問自己：

1. 這個服務有沒有檢查 `Host` header 白名單？
2. 就算只綁 127.0.0.1，有沒有強制認證？（特別是 admin、debug、metrics endpoint）
3. CORS 設定是不是寫死的白名單，而不是 `*`？
4. 我有沒有把「不必要的 admin endpoint」直接關掉？
5. 公司 DNS 解析器有沒有開啟 anti-rebind 防護？
6. 開發環境的工具（Jenkins、Grafana、pgAdmin、Redis Commander 等）有沒有預設密碼？

---

## 八、延伸閱讀的關鍵字

- RFC 6761（特殊用途網域）
- `dnsmasq --stop-dns-rebind`、Unbound `private-address`
- Chrome 的 [Private Network Access](https://developer.chrome.com/blog/private-network-access-update) 草案
- Tavis Ormandy 2018 年對 Blizzard Update Agent 的 rebinding 攻擊
- Spring Boot Actuator security best practice、Spring `WebSecurityConfig` 對 `/actuator/**` 的鎖定

---

## 一句話總結

> **瀏覽器的「同源」是用網域字串判斷的，但 IP 可以被攻擊者偷偷換掉；唯一可靠的防線，是後端自己驗 `Host` header、強制認證、不要假設「綁 localhost = 安全」。**

明天 Day 40，我們會講「HTTP Parameter Pollution（HPP）」——當同一個參數在 query string 裡出現兩次（例如 `?role=user&role=admin`），不同框架、不同層（WAF、後端、ORM）對「到底該採用哪一個」的解讀不一致時，攻擊者就能鑽這個縫隙繞過驗證。
