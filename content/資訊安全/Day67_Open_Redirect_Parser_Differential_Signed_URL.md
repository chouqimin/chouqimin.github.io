---
title: "Day 67：Open Redirect（延伸篇，承 Day66）— 白名單寫對了還是被繞過：parser 解析差異與簽章式 return URL"
date: 2026-07-01
tags: ["Open Redirect", "URL Parsing", "OAuth", "HMAC"]
---

# Day 67：Open Redirect（延伸篇，承 Day66）

接續 Day66 預告:今天回到應用碼層,談 **Open Redirect（開放重新導向）**。

先把這篇的延伸角度講清楚:**這不是重新介紹 Open Redirect。** 基本定義、釣魚故事、`?next=` 危險寫法、`//evil.com` / `@evil.com` / `javascript:` 這些常見繞過、白名單與「跳轉代碼映射」的正確寫法,Day20 已經完整講過了。如果你還沒讀過,請先回去看 Day20。

今天這篇要面對一個更尷尬的處境:**你照 Day20 做了白名單,用 URL parser 解析、比對 host、也擋了字串前綴比對,結果還是被繞過。** 原因是後端工程師最容易忽略的一層:**驗證 URL 用的 parser,和真正拿去跳轉的 parser,對同一個字串的解析結果可能不一樣。** 攻擊者鑽的就是這道「解析差異(parser differential)」的縫。

這篇聚焦三件 Day20 沒深入的事:

1. **Parser differential**:Java `URI` / `URL` / Spring `UriComponentsBuilder` 與 Go `net/url` 對同一個畸形 URL 的 host 解析差異,以及它如何讓白名單失效。
2. **簽章式 return URL**:當跳轉目標必須是動態外站(行銷追蹤、跨站 SSO)時,白名單擋不住,改用 HMAC 簽章從根本解決(接 Day48)。
3. **Open Redirect 串成 OAuth token 竊取的進階鏈**,以及偵測 / Code Review checklist。

> 前置觀念對照:Day20 是「**别無條件信任跳轉參數**」(白名單入門);Day48 是「**用 HMAC 簽章保證參數沒被竄改**」;今天把這兩條接起來,處理 Day20 白名單擋不住的那些情境。

---

## 一、核心問題:驗證的 parser 和跳轉的 parser 不是同一個

Day20 的防禦長這樣:用 parser 解析 `next`,取出 `host`,比對白名單,通過才跳轉。邏輯沒錯。問題出在一個隱藏假設:

> **「我驗證時解析出來的 host」== 「瀏覽器/HTTP 客戶端最後真正連去的 host」。**

這個假設**經常不成立**。URL 規格其實有兩套:老的 RFC 3986 和瀏覽器用的 WHATWG URL Standard,兩者對畸形輸入的容錯不同。各語言的 parser 又各自實作了其中一套的某個子集,對「奇怪但瀏覽器吃得下」的 URL 解出來的 host 五花八門。

舉個經典例子,這個字串:

```text
https://yourapp.com\@evil.com/
```

- 某些 parser 把 `\` 當路徑的一部分,解析出 `host = yourapp.com`(因為 `\@evil.com/` 被當成 path)→ **通過白名單**。
- 瀏覽器依 WHATWG 把 `\` 正規化成 `/`,於是 `yourapp.com/@evil.com` → host 其實是 `yourapp.com`... 但換個 payload:

```text
https://evil.com\.yourapp.com/    →  瀏覽器看到 host = evil.com（\ 變 /，後面全是 path）
https://yourapp.com:@evil.com/    →  userinfo 是 yourapp.com:，真正 host = evil.com
http://yourapp.com#@evil.com/     →  parser 對 fragment 與 userinfo 處理不一致時會分歧
```

**重點不是背這些 payload**(Day20 已列過一批),而是理解:**只要「做白名單判斷的 parser」跟「執行跳轉的 client」對同一字串解出不同 host,白名單就形同虛設。** 攻擊者的工作就是找到一個能讓兩者分歧的輸入。

---

## 二、Java:`URI`、`URL`、`UriComponentsBuilder` 解出來的 host 不一樣

很多 Spring 後端的白名單是隨手抓一個 parser 來用,沒意識到它們行為不同。

```java
String s = "https://yourapp.com\\@evil.com/";   // 注意 Java 字串裡 \\ 是一個反斜線

// (1) java.net.URI —— 嚴格 RFC 3986，遇到不合法字元可能直接丟例外或 host=null
URI u1 = URI.create(s);
System.out.println(u1.getHost());   // 可能是 null（因為含不合法字元，無法判定 host）

// (2) java.net.URL —— 較寬鬆，行為又不同
URL u2 = new URL(s);
System.out.println(u2.getHost());   // 可能解出 yourapp.com，與 (1) 不一致

// (3) Spring UriComponentsBuilder —— 又是另一套解析
String h3 = UriComponentsBuilder.fromUriString(s).build().getHost();
```

這三者對畸形輸入很可能給你**三個不同的 host**。如果你的白名單用 `URI.getHost()` 判斷(得到 null 或 yourapp.com),但實際跳轉是把**原始字串**塞進 `response.sendRedirect(s)` 交給瀏覽器,瀏覽器解析的結果跟你驗證的不同,就被繞過了。

> 採用任何 URL 處理函式庫或某個 `getHost()` 行為前,建議用 context7 之類工具核對該方法在你的 JDK / Spring 版本是否仍維護、行為是否如你假設——不同版本對畸形 URL 的容錯曾有變動,別憑印象寫白名單。

### Java 的穩健做法:正規化 → 用同一個解析結果做「驗證」與「跳轉」

不要驗證一個字串、卻跳轉另一個(原始)字串。**驗證通過後,跳轉用的必須是你「解析重組後」的那個 URL,而不是使用者的原始輸入。**

```java
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriComponents;
import java.util.Set;

public final class SafeRedirect2 {

    private static final Set<String> ALLOWED_HOSTS = Set.of(
        "yourapp.com", "www.yourapp.com", "account.yourapp.com");

    /** 回傳「可安全跳轉的目標字串」，不合法則回 defaultPath。 */
    public static String resolve(String next, String defaultPath) {
        if (next == null || next.isBlank()) return defaultPath;

        // 0. 先把反斜線正規化成斜線（瀏覽器會這樣做，我們也要這樣判斷）
        String normalized = next.replace('\\', '/').strip();

        // 1. 相對路徑：必須單一斜線開頭，且不得是 // 開頭（protocol-relative）
        if (normalized.startsWith("/") && !normalized.startsWith("//")) {
            return normalized;   // 站內相對路徑，安全
        }

        // 2. 絕對 URL：解析後「用解析結果重建」，並嚴格比對 host
        try {
            UriComponents uc = UriComponentsBuilder.fromUriString(normalized).build();
            String scheme = uc.getScheme();
            String host = uc.getHost();
            // 只允許 http/https，拒絕 javascript:/data: 等
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return defaultPath;
            }
            // 含 userinfo（@ 前的內容）一律拒絕，這是冒名 host 的主要手段
            if (uc.getUserInfo() != null) {
                return defaultPath;
            }
            if (host != null && ALLOWED_HOSTS.contains(host.toLowerCase())) {
                // 關鍵：回傳「重建後」的 URL，而非原始 next
                return uc.toUriString();
            }
        } catch (RuntimeException e) {
            // 解析失敗 → 不合法
        }
        return defaultPath;
    }
}
```

三個關鍵改進:**先正規化 `\`、明確拒絕含 userinfo(`@`)的 URL、跳轉用「重建後的字串」而非原始輸入**。這樣「驗證看到的 host」就等於「跳轉送出的 host」,parser differential 的縫被補起來。

---

## 三、Go:`net/url` 的陷阱與 host 一致性

Go 的 `net/url.Parse` 同樣寬鬆。常見的踩雷:

```go
u, _ := url.Parse("https://yourapp.com\\@evil.com/")
// u.Host 在某些情況下不是你以為的值；\ 不會被自動正規化成 /
```

`net/url` **不會**幫你把 `\` 正規化成 `/`(那是瀏覽器 WHATWG 的行為),所以你驗證時看到的 host 和瀏覽器跳轉時的 host 可能不同。另外 `url.Parse` 對 `//evil.com`(protocol-relative)會解出 `Host = evil.com`、`Scheme = ""`,要特別處理。

### Go 的穩健做法

```go
package security

import (
	"net/url"
	"strings"
)

var allowedHosts = map[string]bool{
	"yourapp.com":         true,
	"www.yourapp.com":     true,
	"account.yourapp.com": true,
}

// ResolveRedirect 回傳可安全跳轉的目標；不合法回 defaultPath。
func ResolveRedirect(next, defaultPath string) string {
	next = strings.TrimSpace(next)
	if next == "" {
		return defaultPath
	}

	// 0. 反斜線正規化（對齊瀏覽器行為）
	next = strings.ReplaceAll(next, `\`, "/")

	// 1. 站內相對路徑：單斜線開頭、且非 //
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") {
		return next
	}

	// 2. 絕對 URL：解析後嚴格檢查
	u, err := url.Parse(next)
	if err != nil {
		return defaultPath
	}
	// 只允許 http/https
	if u.Scheme != "http" && u.Scheme != "https" {
		return defaultPath
	}
	// 拒絕 userinfo（u.User != nil 代表有 @ 前段）
	if u.User != nil {
		return defaultPath
	}
	// u.Hostname() 去掉 port，做小寫比對
	if allowedHosts[strings.ToLower(u.Hostname())] {
		return u.String() // 回傳重新序列化後的字串
	}
	return defaultPath
}
```

同樣三原則:**正規化 `\`、拒絕 `u.User != nil`(userinfo)、回傳 `u.String()`(重序列化)而非原始輸入**。`u.Hostname()` 而不是 `u.Host`,後者含 port 會讓比對出錯。

---

## 四、白名單擋不住的情境:簽章式 return URL(接 Day48)

有些場景**本來就要跳去動態的外站**,白名單列不完:

- 行銷 / Email 追蹤連結:`/click?target=<合作夥伴任意網址>`
- 跨產品 SSO:登入後要跳回「使用者來時的那個外部產品頁」
- 多租戶系統:每個租戶有自己的 callback 網域

這時候白名單會變成「要嘛太鬆(等於沒擋)、要嘛常常漏掉合法網址」。正解是換個思路:**不驗證 URL 內容,而是驗證「這個 URL 是不是我自己之前簽發的」。** 這就是 Day48 HMAC 簽章的應用。

### 概念

跳轉目標在**產生連結的當下**就由後端決定並簽章,使用者只能拿到「URL + 簽章」,改一個字元簽章就對不上:

```text
/redirect?to=https%3A%2F%2Fpartner.com%2Fpage&sig=<HMAC-SHA256(to, secret)>
```

跳轉端驗章通過才跳,簽章是後端用密鑰算的,攻擊者偽造不出來,所以 `to` 可以是任意網址也不怕被當跳板——因為任意網址**進不了**這個流程(沒有合法簽章)。

### Java 範例(沿用 Day48 的 HMAC 風格)

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

public final class SignedRedirect {

    private final byte[] key; // 從 secrets 來，見 Day15

    public SignedRedirect(byte[] key) { this.key = key; }

    /** 產生連結時呼叫：把目標 URL 簽章。 */
    public String sign(String target) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] h = mac.doFinal(target.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(h);
    }

    /** 跳轉時呼叫：驗章。用 constant-time 比較（見 Day32）。 */
    public boolean verify(String target, String sig) throws Exception {
        String expected = sign(target);
        // 不要用 String.equals！用 MessageDigest.isEqual 做定長時間比較
        return MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.UTF_8),
            sig.getBytes(StandardCharsets.UTF_8));
    }
}
```

注意兩個跨主題連動:**密鑰管理走 Day15(Secrets Management)、驗章比較用 Day32 的 constant-time compare(`MessageDigest.isEqual`)而非 `equals`,避免 timing attack 洩漏簽章。**

### Go 範例

```go
package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func signTarget(key []byte, target string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(target))
	return hex.EncodeToString(m.Sum(nil))
}

// VerifyRedirect 用 hmac.Equal 做 constant-time 比較
func VerifyRedirect(key []byte, target, sig string) bool {
	expected := signTarget(key, target)
	return hmac.Equal([]byte(expected), []byte(sig))
}
```

Go 的 `hmac.Equal` 就是 constant-time,別用 `==` 比字串。

**進階保險**:簽章的 payload 除了 `to`,可以再加上**過期時間**與**綁定使用者/session id**,讓簽出來的連結不能被別人重放、也不會永久有效。這跟 Day48 的 API 簽章設計同一套思路。

---

## 五、進階串接:Open Redirect → OAuth token 竊取(比 Day20 更深一層)

Day20 提過 Open Redirect 可以偷 OAuth token,這裡補上**為什麼即使 OAuth provider 對 `redirect_uri` 做了 exact match,你的應用內 Open Redirect 還是能把它打穿**。

關鍵在 OAuth 的 `redirect_uri` 通常只允許註冊好的、你自己的網域(例如 `https://yourapp.com/oauth/callback`)。攻擊者**沒辦法**把 `redirect_uri` 直接改成 `evil.com`(exact match 擋住了)。但如果 `https://yourapp.com` 上**有一個 Open Redirect**:

```text
1. 攻擊者構造授權連結，redirect_uri = https://yourapp.com/oauth/callback
   （完全合法，通過 exact match）
2. callback 處理完後，你的 app 依 ?next= 參數做跳轉……而這個 next 沒做白名單
3. 於是流程變成：provider → yourapp.com/callback（帶 code/token）
   → 你的 Open Redirect → evil.com（token 在 URL fragment / referer 裡跟著被帶出去）
```

**Open Redirect 在這裡扮演「合法網域內的跳板」**,讓 token 從你的網域「合法地」流到攻擊者手上,繞過了 provider 端嚴格的 `redirect_uri` 比對。這也是為什麼:**就算 OAuth 設定做滿,只要應用內任何一個端點有 Open Redirect,整條 OAuth 鏈就有破口。** 防禦回到本篇與 Day20 的核心:**所有跳轉端點一律白名單或簽章,沒有例外**——尤其是 callback 之後的二次跳轉。

> 對照:Day24(OAuth2/OIDC Pitfalls)講 `redirect_uri`、PKCE、state 的入門驗證;本篇補的是「provider 端做對了,但被你自家 Open Redirect 反咬」這個跨主題交叉風險。

---

## 六、偵測、監控與 Code Review checklist

延伸篇的價值在於「上線後怎麼持續抓」。

### Code Review:看到這些就要追問

```text
[ ] 驗證 URL 用的 parser，和最後跳轉送出的字串，是不是「同一份解析結果」？
    （驗證 A 字串、跳轉 B 字串 = 必繞過）
[ ] 白名單比對前，有沒有把 \ 正規化成 /、有沒有拒絕 userinfo(@)？
[ ] host 比對是用 equals/map，還是用 endsWith / startsWith / contains？
    （endsWith("yourapp.com") 會被 evil-yourapp.com 或 ...@x.yourapp.com 之類繞過）
[ ] 跳轉值有沒有可能流到前端 window.location / <a href>（會多出 javascript: 風險）？
[ ] callback / 登入成功後的「二次跳轉」有沒有納入白名單？（OAuth 串接破口）
[ ] 動態外站跳轉，是不是改用簽章式 return URL 而不是放寬白名單？
```

### 監控訊號(後端可自動化)

```text
1) 白名單拒絕事件 → 記 log + 告警
   被拒絕的 next 值往往是攻擊探測的第一個訊號（呼應 Day16 Logging）。
2) 對「跳轉端點」做回歸測試：把已知繞過 payload 當測資跑
   - //evil.com、/\evil.com、https://yourapp.com\@evil.com、
     https://yourapp.com@evil.com、https://yourapp.com.evil.com、javascript:...
   - 斷言：全部都回到 defaultPath，沒有一個跳出站。
3) 簽章式 return URL：監控「簽章驗證失敗率」
   突然飆高 = 有人在嘗試偽造跳轉連結。
4) referrer / proxy log 比對：是否有「從本網域跳往未知外站」的異常流量。
```

把第 2 點寫成單元測試,加進 CI,是最划算的防線——Open Redirect 最容易在「改版時不小心放寬白名單」復發,測試能幫你卡住。

---

## 七、一句話總結

> Open Redirect 的進階風險不在「忘了做白名單」,而在「白名單做了卻被 **parser differential** 繞過」:驗證用的 parser 與跳轉用的 client 對畸形 URL 解出不同 host。修法三原則——**正規化 `\`、拒絕 userinfo(`@`)、跳轉用「重建後的字串」而非原始輸入**,讓「驗到的 host」== 「跳出的 host」。白名單列不完的動態外站,改用 **HMAC 簽章式 return URL**(接 Day48,搭 Day32 constant-time 比較、Day15 密鑰管理)從根本擋掉偽造。最後別忘了:**就算 OAuth `redirect_uri` 做了 exact match,應用內任何一個 Open Redirect 都能當合法網域內的跳板把 token 帶出去**——所有跳轉端點,包含 callback 後的二次跳轉,一律白名單或簽章,沒有例外。

---

## 延伸閱讀

- Day20 Open Redirect——本篇的入門基礎(定義、釣魚、基本白名單、常見繞過 payload),今天是它的進階延伸。
- Day48 HMAC / API Request Signing——簽章式 return URL 的技術底層。
- Day32 Timing Attack / Constant-Time Compare——驗章一定要用定長時間比較。
- Day24 OAuth2 / OIDC Pitfalls——`redirect_uri` 入門;本篇補「被自家 Open Redirect 反咬」的交叉風險。
- Day15 Secrets Management——簽章密鑰的存放。
- Day16 Security Logging & Monitoring——白名單拒絕事件的告警。

---

明天預告:**Day 68 — Open Redirect 延伸:CRLF / Header Injection 與 `Location` 標頭注入的交叉風險（延伸篇）**
(延伸角度明確:這**不是**重新介紹 Open Redirect,也不是重講 Day34 的 CRLF 入門,而是聚焦兩者的**交會點**——當跳轉值被塞進 HTTP `Location` 回應標頭時,攻擊者如何用 `%0d%0a` 在 `Location:` 後面再注入額外標頭或分裂回應。會用 Java(Servlet `sendRedirect` 的編碼行為)與 Go(`http.Redirect` 對控制字元的處理)示範:為什麼「跳轉值就算過了網域白名單,只要含 CR/LF 還是能注入標頭」,以及正確的 header 值消毒與 response splitting 防禦。)
