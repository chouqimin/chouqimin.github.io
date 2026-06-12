---
title: "Day 23：HTTP Request Smuggling（HTTP 請求走私）"
date: 2026-05-19
tags: ["HTTP", "Request Smuggling", "網路"]
---

# Day 23：HTTP Request Smuggling（HTTP 請求走私）

> 後端工程師資安系列 — Day 23
> 日期：2026-05-19

## 一、前情提要

前幾天我們談過 SQL Injection、XSS、SSRF、Path Traversal 等較常見的漏洞，今天要介紹一個聽起來很神祕、實際上又非常「後端」的漏洞 —— **HTTP Request Smuggling（HTTP 請求走私）**。

這個漏洞的成因不在你的程式碼，而在「**前端代理 / 負載平衡器**」與「**後端應用伺服器**」之間對 HTTP 訊息的解讀不一致。它能讓攻擊者把自己的請求「藏在」別人的請求裡，繞過身分驗證、竊取 Session、毒化快取，甚至偷別人的請求 Body。

只要你的服務前面有 Nginx / HAProxy / AWS ALB / Cloudflare / Akamai 之類的反向代理，這個觀念就一定要懂。

---

## 二、攻擊的核心原理：兩個前後端對 Request 長度的看法不一致

HTTP/1.1 規格允許「一條 TCP 連線」上連續送多個請求（Keep-Alive / Pipelining）。要切出第二個請求從哪裡開始，伺服器必須知道**第一個請求的 Body 在哪裡結束**。HTTP 規格提供兩種方式來描述 Body 的長度：

1. `Content-Length: 數字` — 直接告訴你 Body 有幾個 byte。
2. `Transfer-Encoding: chunked` — 用分塊編碼，每塊前面寫該塊大小（16 進位），最後以 `0\r\n\r\n` 結束。

依 RFC 7230 規定：當這兩個 header **同時出現**時，必須以 `Transfer-Encoding` 為準，並忽略 `Content-Length`（或乾脆拒絕請求）。但實務上各家伺服器實作不完全一致，於是攻擊者就有了發揮空間。

走私的三個經典變體：

- **CL.TE**：前端代理用 `Content-Length`，後端用 `Transfer-Encoding`
- **TE.CL**：前端代理用 `Transfer-Encoding`，後端用 `Content-Length`
- **TE.TE**：兩端都看 `Transfer-Encoding`，但用某種「混淆寫法」（如 `Transfer-Encoding: xchunked`）只能騙過其中一邊

---

## 三、CL.TE 案例直擊

假設前端 (Nginx) 用 `Content-Length`、後端 (Tomcat / Gin) 用 `Transfer-Encoding`。攻擊者送出這樣一個請求：

```
POST /search HTTP/1.1
Host: vulnerable.example.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

前端代理看到 `Content-Length: 13`，於是把整個 Body（13 byte = `0\r\n\r\nSMUGGLED`）轉送給後端。

後端讀到 `Transfer-Encoding: chunked`，遇到 `0\r\n\r\n` 就認為第一個請求已經結束。剩下的 `SMUGGLED` 字串，後端會把它當成「**下一個請求的開頭**」，接到下一個合法使用者的請求前面。

換句話說：受害者下一個請求變成 `SMUGGLEDGET /account HTTP/1.1 ...`，可能讓他被導向 404，也可能被改寫成攻擊者指定的請求。

### 真實會造成什麼後果？

- **繞過前端的安全控管**：前端 WAF 已經看過了「合法」的請求，惡意的尾巴卻直接到後端。
- **竊取 Session / Cookie**：把惡意請求改成 `POST /log`，附上 `Content-Length` 很大的數字，後端會把下一個受害者請求的 header（含 Cookie）當作 Body 接收下來，攻擊者再去讀 log 就能拿到。
- **快取毒化（Cache Poisoning）**：把惡意 response 綁定到熱門 URL，所有使用者都會拿到攻擊者的內容。
- **內部端點越權存取**：原本只允許內網存取的 `/admin` 也可能被走私進去。

---

## 四、後端情境：Go (net/http) 與 Java (Servlet) 是否安全？

好消息是，**現代的標準函式庫對這類攻擊有相對嚴謹的處理**，但你仍然必須注意：你引入的中介層、反向代理或自己寫的 HTTP parser。

### Go 範例：標準庫的防護

Go `net/http` 從 1.x 起就明確規定：當 `Content-Length` 與 `Transfer-Encoding: chunked` 同時存在時，會移除 `Content-Length` 並以 chunked 處理，符合 RFC 7230。

```go
// Go 1.21+：net/http/server.go 行為示意
// 若同時帶 CL 與 TE: chunked，net/http 會優先使用 TE，並刪除 CL header
func handler(w http.ResponseWriter, r *http.Request) {
    // 比較安全的寫法：明確拒絕雙重長度宣告
    if r.Header.Get("Transfer-Encoding") != "" && r.Header.Get("Content-Length") != "" {
        http.Error(w, "ambiguous request", http.StatusBadRequest)
        return
    }

    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "bad body", http.StatusBadRequest)
        return
    }
    log.Printf("收到 %d bytes", len(body))
}
```

要注意的是：**若你把 Go 服務放在另一個自己寫的或舊版的 reverse proxy 後面**，雙方對 header 的處理不同步，仍然可能被走私。

### Java 範例：Tomcat / Servlet

Tomcat 9.0.31+、10.x、11.x 都已強化此類解析，但若使用舊版本（或 Jetty 9 早期版本），可能存在已知的走私風險。建議在程式碼層做最後一道防線：

```java
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AntiSmugglingFilter implements Filter {

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpReq = (HttpServletRequest) req;
        HttpServletResponse httpRes = (HttpServletResponse) res;

        String cl = httpReq.getHeader("Content-Length");
        String te = httpReq.getHeader("Transfer-Encoding");

        // 雙重宣告 -> 拒絕
        if (cl != null && te != null) {
            httpRes.sendError(HttpServletResponse.SC_BAD_REQUEST, "Ambiguous request");
            return;
        }

        // 非標準的 TE 值（例如 "xchunked", " chunked"）-> 拒絕
        if (te != null && !te.trim().equalsIgnoreCase("chunked")
                       && !te.trim().equalsIgnoreCase("identity")) {
            httpRes.sendError(HttpServletResponse.SC_BAD_REQUEST, "Bad TE");
            return;
        }

        chain.doFilter(req, res);
    }
}
```

這支 Filter 不能取代升級伺服器版本，但能擋掉最常見的混淆形態。

---

## 五、HTTP/2 也別大意：H2.CL / H2.TE Downgrade

很多人以為「升上 HTTP/2 就沒事了」，但事實上：

- 雲端與 CDN 前端通常是 HTTP/2，後端往往降回 HTTP/1.1。
- 在「降級」的過程中，前端會把 HTTP/2 的 `:content-length`、pseudo-headers 翻譯成 HTTP/1.1 headers。
- 若前端沒驗證 HTTP/2 的 body 是否真的符合 `content-length` 的長度，就會把多出來的 byte 寫進 HTTP/1.1 連線，造成走私。

實務上 2021 之後爆出的多起大案（Netflix、AWS ALB、某些 Akamai/Cloudflare 設定）都屬於這一類。修補的關鍵是：**前端必須嚴格驗證 HTTP/2 訊息**，不能讓 client 任意覆寫 `Content-Length`、`Transfer-Encoding`。

---

## 六、防禦清單（給後端工程師）

1. **第一道防線：升級**
   - Nginx ≥ 1.21、HAProxy ≥ 2.4、Tomcat 9.0.31+ / 10.x、Jetty 11+、Go ≥ 1.17、Spring Boot 與 Apache HTTPClient 用最新版本。
   - 雲服務 ALB / CloudFront / Cloudflare 也都已修補大部分已知變體，但仍要持續追新 CVE。
2. **強制使用 HTTP/2 端到端**：減少 H2 → H1.1 的降級空間。如果無法做到，務必在前端設定「拒絕同時帶有 CL 和 TE」的請求。
3. **拒絕模糊請求**：兩端對 Body 長度只認一種編碼。如上 Java/Go 範例。
4. **關閉前後端的 TCP 連線重用**（治標）：在 reverse proxy 上設定 `proxy_http_version 1.1` 並對每個請求建立新連線（如 `proxy_set_header Connection "close"`）。這是效能與安全的取捨。
5. **不要在 application 層自己 parse HTTP**：除非你真的知道自己在做什麼。例如不要用 `bufio.Reader` 手刻 HTTP server，這類客製 parser 是漏洞溫床。
6. **監控異常 HTTP**：在前端 log 裡找「雙重長度」、「奇怪的 chunked 編碼」、「同一個連線上的不對稱 request/response 數量」。Day 16 的 logging 內容剛好派上用場。
7. **PortSwigger 的 Smuggler 工具**：在測試環境跑一下，確認自己的 stack 不會中招。

---

## 七、一句話帶走

> HTTP Request Smuggling 不是「你的程式碼有 bug」，而是「前端和後端對同一段 bytes 的解讀不一致」。
> 把雙重長度的請求一律拒絕，並讓整條鏈路（CDN → LB → App）的 HTTP parser 版本統一，是後端工程師最重要的責任。

---

## 八、延伸閱讀

- PortSwigger Web Security Academy — *HTTP request smuggling* 系列實驗（CL.TE / TE.CL / TE.TE / H2.CL / H2.TE）。
- James Kettle, *HTTP Desync Attacks: Request Smuggling Reborn*（Black Hat USA 2019）。
- James Kettle, *HTTP/2: The Sequel is Always Worse*（Black Hat USA 2021）。
- RFC 7230 §3.3.3 — Message Body Length 的權威定義。
- CVE 範例：CVE-2019-18277 (HAProxy)、CVE-2022-1271 (gzip+TE)、CVE-2023-25690 (Apache mod_proxy)。

明天 Day 24 預計討論 **OAuth 2.0 / OpenID Connect 的常見實作陷阱（Authorization Code Injection、PKCE、Redirect URI 驗證）**，這也是後端工程師最容易踩雷的身分驗證主題之一。
