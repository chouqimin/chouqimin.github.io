---
title: "Day 38 — X-Forwarded-For 偽造 / 反向代理標頭信任問題"
date: 2026-06-03
tags: ["HTTP Header", "Proxy", "Rate Limiting"]
---

# Day 38 — X-Forwarded-For 偽造 / 反向代理標頭信任問題

> 後端工程師資安教學 · Day 38
> 適合對象：剛接觸 Web 後端、Java（1.8 / 21）與 Go 開發者
> 前情提要：Day 17 我們講過 Rate Limiting，但如果攻擊者可以「偽造自己的 IP」，那速率限制、IP 白名單、稽核日誌全都失效

---

## 一、先講一個生活化的比喻

想像你在一棟大樓裡開了一家便利商店，但你的店面沒有對外窗戶，所有客人都是先經過一樓大廳，再被警衛帶上來。

警衛會在客人手上蓋一個章，寫著：

> 「這個客人來自門口，身分證上的地址是台北市信義區。」

你信任這個章，因為**只有警衛能蓋**。

但今天，警衛偷懶，改成「每個進來的人，自己拿筆寫上自己從哪裡來」。攻擊者立刻在自己手上寫：

> 「我來自 127.0.0.1，是公司內網的人，請放行。」

這就是 `X-Forwarded-For`、`X-Real-IP`、`X-Forwarded-Host` 等代理標頭被濫用的核心問題：**這些 header 是 HTTP 客戶端可以自由填寫的**，只有當你「真的有反向代理在前面、而且代理會覆寫它們」的時候，才能信任。

---

## 二、為什麼後端會錯誤信任這些 header？

典型的部署架構：

```
使用者 (1.2.3.4)
    │
    ▼
Cloudflare / ALB / Nginx (代理)
    │  加上 X-Forwarded-For: 1.2.3.4
    ▼
後端應用 (你的 Spring Boot / Go 服務)
```

後端從 TCP 層拿到的 `remoteAddr` 是「代理的 IP」（例如 10.0.0.5），不是真正的客戶端 IP。所以工程師會去讀 `X-Forwarded-For` 來取得「真實 IP」。

問題是：

1. **如果服務直接暴露在網路上**（沒有代理），攻擊者可以自己塞 `X-Forwarded-For`。
2. **就算有代理**，代理預設可能是「附加」而不是「覆寫」，攻擊者塞的 IP 會留在最前面。
3. **多層代理**之下，到底哪一個位置才是真的客戶端 IP？

---

## 三、X-Forwarded-For 的正確讀法

`X-Forwarded-For` 是一個逗號分隔的清單，**越前面越接近原始客戶端**：

```
X-Forwarded-For: <client>, <proxy1>, <proxy2>
```

舉例：

```
X-Forwarded-For: 1.2.3.4, 10.0.0.5, 10.0.0.6
```

如果你的架構是「使用者 → Cloudflare → ALB → 後端」，那後端收到的清單應該是：

```
X-Forwarded-For: 1.2.3.4(真實), <Cloudflare IP>, <ALB IP>
```

**正確的讀法**是：從最右邊往左數，跳過「你信任的代理 IP」，第一個不是你代理的 IP 就是客戶端。

**錯誤但常見的讀法**是：直接抓最左邊那個。攻擊者只要送：

```
X-Forwarded-For: 127.0.0.1
```

後端就以為這是 localhost 過來的請求，可能就跳過驗證、或視為內網管理員。

---

## 四、實戰：四種常見災難情境

### 情境 1：Rate Limiting 被繞過

```java
// ❌ 危險寫法
String clientIp = request.getHeader("X-Forwarded-For");
if (clientIp == null) clientIp = request.getRemoteAddr();
rateLimiter.check(clientIp);
```

攻擊者每次請求都帶不同的 `X-Forwarded-For`，每次都是「新 IP」，rate limit 永遠不會觸發。登入頁面可以無限暴力破解。

### 情境 2：管理介面 IP 白名單被破

```go
// ❌ 危險寫法
clientIP := r.Header.Get("X-Forwarded-For")
if clientIP == "10.0.0.0/8" || strings.HasPrefix(clientIP, "127.") {
    // 視為內網，跳過登入
}
```

攻擊者：

```
GET /admin HTTP/1.1
X-Forwarded-For: 127.0.0.1
```

直接進後台。這是真實發生過的事件，包括 Apache Airflow、某些舊版 Kibana、許多自研後台。

### 情境 3：稽核日誌被污染

```
[2026-06-02 10:23:45] user=admin action=delete_user ip=1.1.1.1
```

攻擊者把 `X-Forwarded-For` 塞成受害者的 IP，稽核日誌就指向別人。鑑識時找錯人。

### 情境 4：地理區塊（Geo-blocking）失效

如果你用 IP 判斷國家來決定 GDPR、稅率、內容版權，攻擊者改 header 就可以切換國籍。

---

## 五、Spring Boot 正確處理範例

Spring 提供 `ForwardedHeaderFilter`，會根據 `Forwarded` / `X-Forwarded-*` 改寫 `HttpServletRequest`，但**只有在你的應用真的在受信任的代理後面時才能啟用**。

### 步驟 1：設定 Tomcat 的可信任代理（最重要）

`application.yml`：

```yaml
server:
  # 只信任這些來源 IP 的代理標頭
  tomcat:
    remoteip:
      remote-ip-header: X-Forwarded-For
      protocol-header: X-Forwarded-Proto
      # 信任的內部代理 IP（CIDR 寫法）
      internal-proxies: "10\\.0\\.0\\.\\d{1,3}|172\\.16\\.\\d{1,3}\\.\\d{1,3}"
  forward-headers-strategy: native
```

`internal-proxies` 就是白名單。如果請求來源 IP 不在這個範圍，Tomcat 會**忽略 `X-Forwarded-For`**，避免被偽造。

### 步驟 2：在程式碼安全取得客戶端 IP

```java
// ✅ 經過 Tomcat RemoteIpValve 處理後
@GetMapping("/whoami")
public String whoami(HttpServletRequest request) {
    // 這時 getRemoteAddr() 已經是真實客戶端 IP
    // 前提是你的 internal-proxies 設定正確
    return "Your IP: " + request.getRemoteAddr();
}
```

### 步驟 3：絕對不要這樣寫

```java
// ❌ 永遠錯
String ip = request.getHeader("X-Forwarded-For");
String firstIp = ip.split(",")[0].trim();  // 取最左邊？不對！
```

如果你一定要手動解析，要從**最右邊**開始往前跳過所有你信任的代理 IP。

---

## 六、Go 的正確處理範例

### 錯誤示範

```go
// ❌ 危險：直接讀 header
func getClientIP(r *http.Request) string {
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        return strings.Split(xff, ",")[0]
    }
    return r.RemoteAddr
}
```

### 正確示範：使用 net/netip + 信任清單

```go
package main

import (
    "net"
    "net/http"
    "net/netip"
    "strings"
)

// 你信任的代理 CIDR
var trustedProxies = []netip.Prefix{
    netip.MustParsePrefix("10.0.0.0/8"),
    netip.MustParsePrefix("172.16.0.0/12"),
    netip.MustParsePrefix("192.168.0.0/16"),
}

func isTrustedProxy(ipStr string) bool {
    addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
    if err != nil {
        return false
    }
    for _, prefix := range trustedProxies {
        if prefix.Contains(addr) {
            return true
        }
    }
    return false
}

// 從 X-Forwarded-For 取得真實客戶端 IP
// 規則：從最右邊往左，跳過所有信任的代理，第一個不是代理的就是客戶端
func getRealClientIP(r *http.Request) string {
    // 1. 先確認 TCP 來源確實是受信任的代理
    host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        return r.RemoteAddr
    }
    if !isTrustedProxy(host) {
        // TCP 連線來源不是代理，X-Forwarded-For 不可信，直接用 RemoteAddr
        return host
    }

    // 2. TCP 來源是代理，才解析 XFF
    xff := r.Header.Get("X-Forwarded-For")
    if xff == "" {
        return host
    }

    ips := strings.Split(xff, ",")
    // 從最右邊往左
    for i := len(ips) - 1; i >= 0; i-- {
        candidate := strings.TrimSpace(ips[i])
        if !isTrustedProxy(candidate) {
            return candidate // 第一個非代理 IP
        }
    }
    return host
}

func handler(w http.ResponseWriter, r *http.Request) {
    ip := getRealClientIP(r)
    w.Write([]byte("Your IP: " + ip))
}
```

關鍵在那個雙重檢查：

1. **TCP 連線來源**要在信任清單裡（代表你真的在代理後面）
2. **解析 XFF 時要從右往左**跳過代理，第一個陌生 IP 才是客戶端

---

## 七、Cloudflare / CDN 場景

如果你用 Cloudflare，標準作法是用 `CF-Connecting-IP`，這個欄位 Cloudflare **保證會覆寫**，不是附加。但前提是：

1. 你的伺服器**只接受**來自 Cloudflare IP 範圍的連線（要在防火牆鎖死）
2. 否則攻擊者繞過 Cloudflare 直連你的 origin，自己塞 `CF-Connecting-IP`，一樣破功

```nginx
# nginx 例子：只允許 Cloudflare IP 進來，並用 CF-Connecting-IP 還原
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
# ... 完整 CF IP 清單
real_ip_header CF-Connecting-IP;
```

---

## 八、檢查清單（給後端工程師）

每次當你寫到「取得客戶端 IP」這段程式碼時，問自己：

1. 這個服務有沒有反向代理在前面？沒有 → **直接用 `RemoteAddr`**，**不准**讀 `X-Forwarded-For`。
2. 有代理 → 我有沒有限制只信任「特定 IP 範圍」的代理？
3. 我的解析方式是從右往左嗎？還是傻傻抓最左邊？
4. 防火牆有沒有鎖死「只接受代理過來的連線」？
5. Rate limit、IP 白名單、稽核日誌，是否都用同一個「可信任的真實 IP 函式」？避免一處正確、一處錯誤。
6. 預設拒絕：拿不到可信 IP 時，要選**最不利於攻擊者**的選項（例如套用最嚴格的 rate limit，而不是放行）。

---

## 九、延伸閱讀的關鍵字

- RFC 7239 `Forwarded` header（XFF 的正規版，但採用率低）
- Spring `ForwardedHeaderFilter`、Tomcat `RemoteIpValve`
- OWASP「Trusting HTTP Permission Headers」
- CVE-2022-31813（Apache HTTP Server 因未正確傳遞 `X-Forwarded-*` 標頭，導致後端基於 IP 的認證被繞過）
- Cloudflare `CF-Connecting-IP`、AWS ALB `X-Forwarded-For`

---

## 一句話總結

> **HTTP header 是客戶端可以亂寫的便條紙；只有當你能證明這張便條紙來自你信任的代理時，你才能相信上面寫的 IP。**

明天 Day 39，我們會接著講「DNS Rebinding」——攻擊者怎麼用 DNS 的時間差，把瀏覽器當成跳板打你的內網服務。
