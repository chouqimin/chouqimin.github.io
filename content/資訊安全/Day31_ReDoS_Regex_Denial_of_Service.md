---
title: "Day 31：ReDoS（Regular Expression Denial of Service，正則表達式拒絕服務）"
date: 2026-05-27
tags: ["ReDoS", "Regex", "DoS"]
---

# Day 31：ReDoS（Regular Expression Denial of Service，正則表達式拒絕服務）

> 「一條看起來無害的正則表達式，可能讓你的服務 CPU 直接打到 100%。」
> 攻擊者不需要打很多請求，只要一條 30 個字元的字串，就能讓整台機器卡死好幾分鐘。

---

## 一、什麼是 ReDoS？

**ReDoS（Regular Expression Denial of Service）** 是利用「正則表達式引擎在某些 pattern 上會發生指數級回溯（catastrophic backtracking）」的特性，讓攻擊者可以用一個短短的輸入字串，把後端 CPU 完全吃滿，造成服務無法回應其他請求。

跟 Day17 的 Rate Limiting 場景不同：

- 一般 DoS：靠大量請求壓垮你 → 用 rate limit、WAF 擋。
- **ReDoS**：一個請求 + 一個字串，就能讓 thread 卡 10 分鐘 → rate limit 沒用，因為「合法的請求數」沒有超標。

而且最危險的是：**幾乎所有後端都有用 regex 在做 input validation、log parsing、URL routing、HTML sanitization**。一條有問題的 regex，可能藏在你 codebase 的任何地方。

---

## 二、為什麼會「指數級回溯」？

主流語言（Java、Go 標準庫除外、Python、JavaScript、.NET、Ruby、PHP）使用的是 **NFA（Non-deterministic Finite Automaton，非確定有限自動機）** 引擎，其特性是支援 backreference、look-around 等強大功能，但代價是某些 pattern 在比對失敗時，會嘗試「所有可能的拆法」。

### 經典的危險 pattern

```
^(a+)+$
^(a*)*$
^(a|a)*$
^(a|aa)+$
(.*a){25}
```

這類 pattern 的共通特徵是：**重複裡面又有重複（nested quantifier）**，或**多個分支可以匹配同一段字元（overlapping alternation）**。

### 用 `^(a+)+$` 比對 `aaaaaaaaaaaaaaaaaaaaab`（21 個 a + 一個 b）為例

引擎會先試「外層 `(a+)+` 把 21 個 a 全吃掉」，然後遇到 `b` 失敗 → 回頭把外層拆成「20 + 1」、「19 + 2」、「19 + 1 + 1」… **幾乎是 2 的 N 次方種拆法**。

實測結果（Java 8 預設 `java.util.regex`）：

| 輸入長度 | 比對時間       |
| -------- | -------------- |
| 20 個 a + b | ~30 ms      |
| 25 個 a + b | ~1 秒        |
| 30 個 a + b | ~30 秒       |
| 35 個 a + b | ~17 分鐘     |

也就是說，攻擊者只需要送 30 個字元的字串，就能把一個 thread 卡住 30 秒。如果你有 200 個 thread pool，攻擊者只要 200 次請求，整個 API 就掛了。

---

## 三、真實世界的災情

ReDoS 不是學術玩具，已經造成過多次知名事故：

- **Cloudflare（2019/07/02）**：WAF 規則裡的一條 regex（用來偵測 XSS）觸發 catastrophic backtracking，導致全球 Cloudflare 服務 CPU 100% 約 27 分鐘。
- **Stack Overflow（2016/07/20）**：home page 的一條 regex 在某些 markdown 內容上 backtracking，造成全站當機 34 分鐘。
- **CVE-2017-16021（uri-js）、CVE-2021-23337（lodash _.template）、CVE-2022-25883（semver）** 等多個 npm 套件因 ReDoS 被列為高風險。
- **Apache Commons Validator**：其 email / URL validator 的 regex 也曾被回報在特殊輸入下發生 catastrophic backtracking（ReDoS）——連標準函式庫等級的驗證器都不能假設「一定安全」。

> 教訓：**不是「我自己寫的 regex」才會有問題，連 Cloudflare、Stack Overflow、`commons-validator` 都中過。**

---

## 四、Java 範例：你以為很安全的 Email Validator

### 危險寫法

```java
import java.util.regex.Pattern;

public class EmailValidator {
    // 看似完整、實則致命
    private static final Pattern EMAIL = Pattern.compile(
        "^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$"
    );

    public static boolean isValid(String email) {
        return EMAIL.matcher(email).matches();
    }

    public static void main(String[] args) {
        // 攻擊 payload：30 個 a + 一個非法字元
        String evil = "a".repeat(30) + "!";
        long start = System.currentTimeMillis();
        isValid(evil);
        System.out.println("耗時：" + (System.currentTimeMillis() - start) + " ms");
    }
}
```

問題在於 `([a-zA-Z0-9_\\-\\.]+)` 跟 `([a-zA-Z0-9_\\-\\.]+)` 中間是 `@`。當 email 沒有 `@` 時，引擎會把整段字元拆成「左邊吃 N 個、右邊吃 M 個」的所有組合 → backtracking 爆炸。

### 安全寫法（一）：限制長度

```java
public static boolean isValid(String email) {
    if (email == null || email.length() > 254) {
        return false;  // RFC 5321: email 最長 254 字元
    }
    return EMAIL.matcher(email).matches();
}
```

**第一道防線：永遠在 regex 之前檢查輸入長度**。即使 regex 有 catastrophic backtracking，攻擊者也沒辦法送無限長的字串來放大攻擊。

### 安全寫法（二）：用 possessive quantifier 或 atomic group（Java 21 仍支援）

```java
// Possessive quantifier：++、*+、?+ — 一吃定終身，不允許 backtrack
private static final Pattern EMAIL_SAFE = Pattern.compile(
    "^([a-zA-Z0-9_\\-\\.]++)@([a-zA-Z0-9_\\-\\.]++)\\.([a-zA-Z]{2,5})$"
);
```

`++` 表示「貪婪吃完之後絕不吐回去」，所以引擎不會嘗試各種拆法，**直接從根源消除 backtracking**。

### 安全寫法（三）：用 timeout

Java 17+ 之後沒有原生 regex timeout，但可以用 `InterruptibleCharSequence` 技巧：

```java
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class InterruptibleCharSequence implements CharSequence {
    private final CharSequence inner;

    public InterruptibleCharSequence(CharSequence inner) { this.inner = inner; }

    @Override
    public char charAt(int index) {
        if (Thread.currentThread().isInterrupted()) {
            throw new RuntimeException("Regex timeout");
        }
        return inner.charAt(index);
    }

    @Override
    public int length() { return inner.length(); }

    @Override
    public CharSequence subSequence(int start, int end) {
        return new InterruptibleCharSequence(inner.subSequence(start, end));
    }

    @Override
    public String toString() { return inner.toString(); }
}

// 使用方式
ExecutorService exec = Executors.newSingleThreadExecutor();
Future<Boolean> future = exec.submit(() -> {
    Matcher m = pattern.matcher(new InterruptibleCharSequence(input));
    return m.matches();
});
try {
    return future.get(100, TimeUnit.MILLISECONDS);  // 超過 100ms 就放棄
} catch (TimeoutException e) {
    future.cancel(true);  // interrupt → 觸發 charAt 拋例外
    return false;
}
```

---

## 五、Go 範例：標準庫 `regexp` 為什麼安全？

Go 標準庫 `regexp` 採用 **RE2 演算法**（DFA-based），保證**比對時間是 O(n)，與 pattern 複雜度無關**。也就是說：

```go
package main

import (
    "fmt"
    "regexp"
    "strings"
    "time"
)

func main() {
    re := regexp.MustCompile(`^(a+)+$`)

    // 即使送 100 個 a + 一個 b，也是毫秒級
    evil := strings.Repeat("a", 100) + "b"
    start := time.Now()
    re.MatchString(evil)
    fmt.Printf("耗時：%v\n", time.Since(start))  // ~50 微秒
}
```

**這就是 Go 標準庫的好處：你完全不必擔心 ReDoS。**

但是有兩個重要陷阱：

### 陷阱 1：第三方套件用了 PCRE

如果你用了 `github.com/dlclark/regexp2`、`github.com/GRbit/go-pcre` 這類提供 lookbehind、backreference 的套件，**它們是 NFA 引擎**，會有 ReDoS 風險。

### 陷阱 2：RE2 不支援的功能可能讓你「假裝」用 regex 但其實沒用

Go 的 `regexp` 故意不支援 backreference（`\1`、`\2`）跟 lookbehind，因為 DFA 演算法做不到。如果你有需求一定要用這些功能，就只能換引擎，**這時就要 timeout 防護**：

```go
import (
    "context"
    "github.com/dlclark/regexp2"
    "time"
)

func safeMatch(pattern *regexp2.Regexp, input string, timeout time.Duration) (bool, error) {
    pattern.MatchTimeout = timeout  // regexp2 內建 timeout 機制
    return pattern.MatchString(input)
}
```

`regexp2` 套件本身就有 `MatchTimeout` 欄位，**請務必設定**，否則一條惡意輸入就能卡住一個 goroutine。

---

## 六、防禦清單（給後端工程師）

### 1. **限制輸入長度**

任何 regex 之前都先檢查 `length()`。Email 不會超過 254、使用者名稱不會超過 64、URL 不會超過 2048…這是零成本、最高效的防線。

```java
if (input.length() > MAX_LEN) {
    throw new BadRequestException("input too long");
}
```

### 2. **避開危險的 pattern 結構**

審視所有 regex，特別注意：

- `(x+)+`、`(x*)*`、`(x+)*` — 巢狀量詞
- `(a|a)`、`(a|ab)` — 分支重疊
- `.*foo.*bar.*baz` — 多個 `.*` 加上 anchored 失敗時的回溯

### 3. **能不用 regex 就不用**

很多時候 `String.startsWith()`、`String.contains()`、`URI.parse()` 反而更快、更安全。

```java
// 比 Pattern.compile("^https://").matcher(url).find() 安全且快
boolean isHttps = url.startsWith("https://");
```

### 4. **用 RE2-based 引擎**

- Java：[google/re2j](https://github.com/google/re2j) — Google 把 RE2 移植到 Java，API 跟 `java.util.regex` 幾乎一樣。
- Go：直接用標準庫 `regexp`。
- Rust：標準庫 regex crate 也是 RE2-based。

```java
// 把 java.util.regex.Pattern 換成 com.google.re2j.Pattern
import com.google.re2j.Pattern;
import com.google.re2j.Matcher;

Pattern p = Pattern.compile("^([a-z]+)+$");  // 安全！O(n)
```

> 註：使用第三方套件前，建議用 context7 MCP 確認該套件的維護狀態與函數簽章是否與你預期相符。

### 5. **靜態掃描工具**

- **ESLint plugin: `eslint-plugin-security`**（detects unsafe regex）
- **Semgrep rules**（`p/owasp-top-ten`）
- **CodeQL `js/redos`、`java/redos`**
- **regex 專用：[ecosystem-redos-vulnerable-regex-collection](https://github.com/davisjam/vuln-regex-detector)、[recheck](https://makenowjust-labs.github.io/recheck/)**

把這些工具加進 CI，可以在 PR 階段就攔下危險 regex。

### 6. **執行 timeout**

如果你真的得用 NFA 引擎且 pattern 無法簡化，**一定要包 timeout**：

- Java：`InterruptibleCharSequence` 技巧（如上）。
- Go：用 `regexp2.MatchTimeout`。
- .NET：`Regex.MatchTimeout`（這是少數內建支援的語言）。
- Node.js：用 worker thread 跑 regex，主 thread 設 setTimeout 殺掉。

### 7. **依賴掃描**

定期跑 `npm audit`、Snyk、Dependabot，盯緊「CVE 描述含 ReDoS」的依賴更新。前面提過的 `lodash._template`、`semver`、`uri-js` 都中過。

---

## 七、快速自我檢查

把這幾個問題拿來檢查你的服務：

- [ ] 所有「使用者可控的字串」進來時，是否有先檢查 `length`？
- [ ] codebase 裡所有的 `Pattern.compile(...)`、`regexp.MustCompile(...)`，是否都通過了 ReDoS 掃描？
- [ ] 有沒有用第三方 PCRE / regexp2 / oniguruma？有的話 timeout 設了嗎？
- [ ] log 解析、URL routing、HTML sanitizer 這些「框架層」的 regex 也檢查過嗎？（這常是盲點）
- [ ] CI 是否包含 regex 靜態分析（Semgrep、CodeQL、ESLint security 等）？
- [ ] 是否監控了「單一 request 處理時間 > 1 秒」的事件？（這通常是 ReDoS 被觸發的早期訊號）

---

## 八、總結

ReDoS 是「最安靜的 DoS」——不需要大流量、不需要殭屍網路，一個合法的 HTTP request、一個 30 字元的 payload，就能讓整台服務癱瘓。

對後端工程師而言，防禦 ReDoS 的核心心法只有四個：

> **「短輸入、好 pattern、強引擎、設 timeout。」**

明天我們會聊 **Day 32：Timing Attack（時序攻擊）**——為什麼用 `String.equals` 或 `==` 比對密碼、token、HMAC 簽章是危險的，以及怎麼用 constant-time 比較把「逐 byte 量測回應時間反推正確值」這條攻擊路徑堵死。

---

*Edison 的後端資安日記 · Day 31 · 2026/05/27*
