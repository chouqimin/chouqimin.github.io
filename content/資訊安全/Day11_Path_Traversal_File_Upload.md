---
title: "Day 11 — Path Traversal & 檔案上傳安全：當使用者輸入的「檔名」能讀到你的 `/etc/passwd`"
date: 2026-05-06
tags: ["Path Traversal", "檔案上傳", "輸入驗證"]
---

# Day 11 — Path Traversal & 檔案上傳安全：當使用者輸入的「檔名」能讀到你的 `/etc/passwd`

> 日期：2026-05-06
> 適合對象：後端工程師初學者
> 主題難度：★★★☆☆（觀念非常簡單，但魔鬼都藏在細節裡——尤其是「我以為已經擋掉了」的時候）

---

## 一、開場白：你以為的「檔案名稱」，駭客眼中的「自由通行證」

幾乎每個後端服務都會碰檔案：

- 使用者下載發票：`GET /invoices/2026-04.pdf`
- 使用者讀附件：`GET /files?name=report.docx`
- 使用者匯出資料：把產生好的 CSV 暫存到 `/tmp/exports/{user}/{filename}`，再讓他抓回來
- 上傳大頭貼：把使用者送上來的圖片存到 `uploads/{filename}`

這些功能聽起來都人畜無害——只是「用一個字串當作檔名去開檔」嘛？

問題在於：**作業系統的檔案路徑規則裡，藏著兩個你可能忘記的字元——`..` 和 `/`。**

當你寫 `Files.readAllBytes(Paths.get("/var/app/files/" + filename))`，你以為使用者只能讀 `/var/app/files/` 底下的東西。但如果他傳的 `filename` 是 `../../../../etc/passwd`，那組合起來就是：

```
/var/app/files/../../../../etc/passwd
```

作業系統會老老實實地往上爬，最後讀到 `/etc/passwd`。這就是 **Path Traversal（路徑遍歷）**，又叫 **Directory Traversal**，也叫 **Dot-Dot-Slash Attack**。

> **真實案例：** 2021 年的 [CVE-2021-41773](https://nvd.nist.gov/vuln/detail/CVE-2021-41773)，Apache HTTP Server 2.4.49 的路徑正規化有 bug，攻擊者用 `.%2e/` 就能繞過保護讀任意檔案。一行 curl 就能拖回伺服器上的 CGI 腳本原始碼，再升級成 RCE（遠端命令執行）。Apache 是全世界用最多的 web server——光這個漏洞就讓無數公司熬夜打補丁。

---

## 二、最小化的 Path Traversal 範例

### Java 版

```java
@GetMapping("/download")
public ResponseEntity<byte[]> download(@RequestParam String name) throws IOException {
    // ❌ 危險：直接拼接使用者輸入
    Path file = Paths.get("/var/app/files/", name);
    byte[] content = Files.readAllBytes(file);
    return ResponseEntity.ok()
            .header("Content-Disposition", "attachment; filename=" + name)
            .body(content);
}
```

正常使用者：`GET /download?name=invoice.pdf` → 拿到 `/var/app/files/invoice.pdf`。
攻擊者：`GET /download?name=../../../../etc/passwd` → 拿到系統使用者列表。
更壞：`GET /download?name=../../app/application.yml` → 拿到你的設定檔，連同資料庫密碼、API Key 一起送他。

### Go 版

```go
// ❌ 危險
func DownloadHandler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    path := filepath.Join("/var/app/files", name)
    data, err := os.ReadFile(path)
    if err != nil {
        http.Error(w, err.Error(), 404)
        return
    }
    w.Write(data)
}
```

注意這裡有個陷阱：**`filepath.Join` 不會幫你阻擋 `..`！** 它只負責把分隔符接起來、做最基本的清理。`filepath.Join("/var/app/files", "../../etc/passwd")` 的結果是 `/var/etc/passwd`——`..` 會被照常解析。新手最容易在這裡誤會：「我有用 Join 啊，怎麼還會出事？」

---

## 三、Path Traversal 能搞出什麼花樣？

### 1. 讀任意檔案（最常見）

```
?name=../../../../etc/passwd
?name=../../../../etc/shadow              ← 通常 root 才能讀，但有時候 app 跑 root
?name=../../app/application.properties    ← Spring 設定檔
?name=../../config/database.yml           ← Rails 設定檔
?name=../../.env                          ← .env 檔（最甜美的目標）
?name=../../.aws/credentials              ← AWS 金鑰
?name=../../.ssh/id_rsa                   ← SSH 私鑰
?name=../../proc/self/environ             ← Linux：當前 process 的環境變數，常含密碼
```

**`.env` 跟 `.aws/credentials` 是駭客的最愛，因為一旦拿到，整個帳號就是他的。**

### 2. 寫任意檔案（如果是上傳功能）

如果是「上傳檔案」而不是讀檔，攻擊者改成：

```
filename=../../../../var/www/html/shell.jsp
filename=../../../../etc/cron.d/backdoor
filename=../../../../home/app/.ssh/authorized_keys
```

**寫進 `authorized_keys` → 攻擊者就能 ssh 進來。** 寫進 `cron.d` → 直接拿到排程執行權限。寫進 web root → JSP / PHP shell。

### 3. 各種編碼繞過（這就是地獄的開始）

如果你只擋 `..`，攻擊者會試：

| Payload | 說明 |
| :-- | :-- |
| `..%2f..%2fetc/passwd` | URL encode 一次的 `/` |
| `..%252f..%252fetc/passwd` | **URL encode 兩次**——常常打中「外層 web server 解一次、後端再解一次」的雙重解碼 |
| `..%c0%af..%c0%afetc/passwd` | UTF-8 過長編碼（IIS 經典） |
| `..\..\etc\passwd` | Windows 反斜線 |
| `....//....//etc/passwd` | 把 `..` 拆開：你 replace 完一次 `..` 之後，剩下的字符可能又組成 `..` |
| `\\?\C:\Windows\System32\config\SAM` | Windows UNC / 長路徑 |
| `/var/app/files/../etc/passwd` | 用「絕對路徑」開頭，即使你前面 prefix 過了，後面 `..` 還是能逃 |

### 4. 軟連結（symlink）攻擊

某些系統允許使用者上傳「資料夾」或從 zip 解壓——zip 裡面藏一個 symlink 指向 `/etc/passwd`，解壓完之後讀那個 symlink 就讀到任意系統檔案。**`ZipSlip`**（[CVE-2018-1002200](https://nvd.nist.gov/vuln/detail/CVE-2018-1002200)）就是這類問題的代表，影響超過 20 萬個專案。

---

## 四、為什麼「黑名單」永遠擋不完

新手常見的第一個防禦：

```java
if (name.contains("..")) {
    throw new IllegalArgumentException("invalid filename");
}
```

這個檢查會被以下任何一種繞過：

- `..%2f` → URL decode 才會變 `..`，你 String 比對時還是 `..%2f`，沒中。
- `....//` → 你 replace 一次 `..` 變 `//`，剩下兩個 `..` 接在一起變 `..`。哎呀。
- `..\` → 你只擋 `/`，沒擋 `\`，Windows 會解析這個。
- 把使用者輸入 base64 encode、解出來是 `..` → 你看到的是 base64，沒中。

**黑名單的根本問題是：你必須猜光所有可能的編碼、所有可能的字元組合。猜不完。**

正確的做法是 **白名單 + 路徑正規化（canonicalization）+ prefix 驗證**——做完後才用，下面會詳細看。

---

## 五、正確的防禦：三層防線

### 防線一：能用白名單就用白名單

很多時候，使用者根本不需要任意輸入「檔名」。你可以：

- 用 ID 替代檔名：`GET /invoices/12345` → 後端查表得到 `invoice_2026-04.pdf`，使用者根本看不到內部的檔案路徑。
- 提供下拉選單：列出該使用者可下載的檔案，使用者選一個。
- 用 UUID 命名儲存的檔案：使用者上傳的 `report.pdf` 存成 `f47ac10b-58cc-4372.pdf`。**這樣即使有 path traversal，他也不知道別人的檔案叫什麼。**

> **能不接觸使用者輸入的字串，就不要接觸。** 這是 SSRF、SQLi、Path Traversal 共用的最強原則。

### 防線二：路徑正規化後驗證 prefix

如果真的需要讓使用者指定檔名，正確的流程是：

1. **拼接**完整路徑
2. **正規化**（resolve `..`、`.`、symlink、編碼）
3. **驗證**正規化後的路徑仍然在允許的目錄底下

#### Java 版（安全）

```java
import java.nio.file.*;

private static final Path BASE_DIR = Paths.get("/var/app/files").toAbsolutePath().normalize();

@GetMapping("/download")
public ResponseEntity<byte[]> download(@RequestParam String name) throws IOException {
    // 1. 拼接 + 正規化 + 解析 symlink
    Path requested = BASE_DIR.resolve(name).normalize();

    // 2. 驗證仍在允許目錄底下
    if (!requested.startsWith(BASE_DIR)) {
        throw new IllegalArgumentException("invalid path");
    }

    // 3. 進一步：解析 symlink 後再檢查一次（防 symlink 攻擊）
    Path real;
    try {
        real = requested.toRealPath();   // 會解開所有 symlink
    } catch (NoSuchFileException e) {
        return ResponseEntity.notFound().build();
    }
    if (!real.startsWith(BASE_DIR)) {
        throw new IllegalArgumentException("invalid path");
    }

    return ResponseEntity.ok()
            .header("Content-Disposition", "attachment; filename=\"" + sanitizeForHeader(name) + "\"")
            .body(Files.readAllBytes(real));
}
```

關鍵點：
- `resolve` + `normalize`：把 `..` 折疊掉。
- `toRealPath()`：把 symlink 也展開——這是擋 symlink 攻擊的關鍵。
- `startsWith(BASE_DIR)` **而不是** `String.startsWith(BASE_DIR.toString())`：用 `Path.startsWith` 是按路徑分隔符比對，不會被 `/var/app/files-evil/` 這種「前綴像但其實是別的目錄」騙到。**用字串比對會被打。**

#### Go 版（安全）

```go
package handler

import (
    "errors"
    "net/http"
    "os"
    "path/filepath"
    "strings"
)

var baseDir string

func init() {
    abs, err := filepath.Abs("/var/app/files")
    if err != nil {
        panic(err)
    }
    // EvalSymlinks 把 base dir 自己也展開，後面比較才公平
    real, err := filepath.EvalSymlinks(abs)
    if err != nil {
        panic(err)
    }
    baseDir = real
}

func resolveSafe(name string) (string, error) {
    // 1. 拼接 + Clean（折疊 ..）
    joined := filepath.Join(baseDir, name)
    cleaned := filepath.Clean(joined)

    // 2. 第一層：clean 後仍在 baseDir 底下
    rel, err := filepath.Rel(baseDir, cleaned)
    if err != nil || strings.HasPrefix(rel, "..") || rel == ".." {
        return "", errors.New("invalid path")
    }

    // 3. 第二層：解開 symlink 再檢查一次
    real, err := filepath.EvalSymlinks(cleaned)
    if err != nil {
        return "", err
    }
    rel2, err := filepath.Rel(baseDir, real)
    if err != nil || strings.HasPrefix(rel2, "..") {
        return "", errors.New("invalid path (symlink escape)")
    }

    return real, nil
}

func DownloadHandler(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    path, err := resolveSafe(name)
    if err != nil {
        http.Error(w, "bad request", 400)
        return
    }
    data, err := os.ReadFile(path)
    if err != nil {
        http.Error(w, "not found", 404)
        return
    }
    w.Write(data)
}
```

> **為什麼用 `filepath.Rel` 比 `strings.HasPrefix(real, baseDir)` 安全？**
> 假設 baseDir 是 `/var/app/files`，攻擊者建一個檔案叫 `/var/app/files-evil/secret.txt`。`strings.HasPrefix("/var/app/files-evil/secret.txt", "/var/app/files")` 是 `true`——但其實已經逃出去了。`filepath.Rel` 會回傳 `../files-evil/secret.txt`，馬上就抓到 `..`。

> **Go 1.24+ 還可以用 `os.Root`：** Go 標準庫從 1.24 加入了 `os.Root`，能直接把後續所有檔案操作鎖在某個目錄下，超出範圍會直接報錯。如果你的 Go 版本夠新，這是最乾淨的方案。

### 防線三：權限與沙箱

即使程式碼有 bug，也讓它「拿不到」敏感檔案：

1. **用最小權限的使用者跑 app**——不要用 root。讓 app process 連 `/etc/shadow` 都讀不到。
2. **chroot / 容器**——把 app 塞進 container 裡，`/etc/passwd` 只是 container 內的，沒什麼價值。
3. **掛載成 read-only**——如果功能只需要讀，就把資料夾以 read-only 掛上去，連寫都寫不進。
4. **SELinux / AppArmor**——額外限制 process 能碰到的檔案。
5. **不要把 secrets 放成檔案**——用 secret manager（Vault、AWS Secrets Manager），別放 `.env`。

**程式碼防禦 + 權限隔離 = 縱深防禦。**

---

## 六、檔案上傳的安全：Path Traversal 只是其中一塊

檔案上傳結合了好幾種風險，這裡一次講清楚。

### 1. 檔名要重新生成，**不要用使用者送的**

```java
// ❌ 危險：使用者送什麼，就存什麼
Files.copy(file.getInputStream(), Paths.get("/var/uploads/" + file.getOriginalFilename()));
```

正確做法：

```java
// ✅ 安全：自己決定檔名
String ext = sanitizeExtension(file.getOriginalFilename()); // 白名單檢查副檔名
String storedName = UUID.randomUUID() + "." + ext;
Path target = uploadDir.resolve(storedName).normalize();
if (!target.startsWith(uploadDir)) {
    throw new IllegalArgumentException("invalid path");
}
Files.copy(file.getInputStream(), target, StandardCopyOption.REPLACE_EXISTING);

// 把「原始檔名」存進資料庫的某個欄位，下載時當 Content-Disposition 用就好
saveToDatabase(userId, storedName, file.getOriginalFilename());
```

**儲存用 UUID，原始檔名只在 DB / Header 用——這同時擋掉了 Path Traversal、檔名衝突、以及檔名注入問題。**

### 2. 副檔名檢查是**必要但不充分**

```java
// 不可少，但不能只靠這個
List<String> ALLOWED = List.of("png", "jpg", "jpeg", "pdf");
if (!ALLOWED.contains(ext.toLowerCase())) reject();
```

副檔名只是「請求」，內容可能完全是別的東西。把 `shell.php` 改名 `shell.jpg` 上傳，存進 `/var/www/html/`——只要 web server 設定有 bug、或是你又把那個目錄當 PHP 解析了，就 RCE 了。

### 3. 檢查「真實檔案類型」(Magic Number)

```java
// 讀前 8 bytes 看 magic number
byte[] header = new byte[8];
try (InputStream in = file.getInputStream()) {
    in.read(header);
}
boolean isPng = header[0] == (byte)0x89 && header[1] == 'P' && header[2] == 'N' && header[3] == 'G';
boolean isJpg = header[0] == (byte)0xFF && header[1] == (byte)0xD8;
boolean isPdf = header[0] == '%' && header[1] == 'P' && header[2] == 'D' && header[3] == 'F';
```

或用函式庫，例如 [Apache Tika](https://tika.apache.org/) 偵測 MIME type。Go 可以用 `http.DetectContentType`。

### 4. **絕對不要把上傳目錄放在 web root 底下**

```
❌  /var/www/html/uploads/        ← 直接被 web server 當靜態資源服務
✅  /var/data/uploads/             ← 後端用程式讀出來、自己 stream 給 client
```

放 web root 底下 = 駭客上傳的 `.html`、`.svg`（含 JS）、`.php`、`.jsp` 都可能直接被執行 / 渲染。

如果一定要對外 serve：放到 **另一個 domain / subdomain**（例如 `usercontent.example.com`），這樣即使裡面有惡意 JS，跟你主站的 cookie / origin 也是隔離的（GitHub 用 `githubusercontent.com`、Google 用 `googleusercontent.com` 就是這個原因）。

### 5. 限制檔案大小、上傳頻率、總空間

- 單檔大小限制（Spring：`spring.servlet.multipart.max-file-size`；Go：`http.MaxBytesReader`）。
- 每使用者總上傳量 quota。
- 每分鐘上傳次數 rate limit。

不然 → DoS 把磁碟塞爆。

### 6. 處理 ZIP / TAR 解壓的特殊地獄

如果你接受壓縮檔解壓：

- **ZipSlip**：壓縮檔內檔名是 `../../etc/cron.d/backdoor` → 解壓後寫到任意位置。**每個解壓出來的路徑都要做 prefix 驗證。**
- **Zip Bomb**：1KB 壓縮檔，解壓後 4GB → 磁碟 / 記憶體被打爆。**解壓時要限制總大小。**
- **Symlink in ZIP**：解出 symlink 指向 `/etc/passwd`，後續讀那個檔案讀到 system 檔案。**解壓時 reject 任何 symlink entry。**

```java
try (ZipInputStream zis = new ZipInputStream(in)) {
    ZipEntry entry;
    long totalRead = 0;
    while ((entry = zis.getNextEntry()) != null) {
        // 安全的目標路徑（跟前面 download 的邏輯一樣）
        Path target = extractDir.resolve(entry.getName()).normalize();
        if (!target.startsWith(extractDir)) {
            throw new SecurityException("Zip Slip detected: " + entry.getName());
        }

        // 拒絕 symlink entry
        if (entry.isDirectory()) {
            Files.createDirectories(target);
            continue;
        }

        // 限制總解壓大小
        try (OutputStream out = Files.newOutputStream(target)) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = zis.read(buf)) > 0) {
                totalRead += n;
                if (totalRead > 100 * 1024 * 1024) { // 100 MB 上限
                    throw new SecurityException("Zip too large");
                }
                out.write(buf, 0, n);
            }
        }
    }
}
```

---

## 七、常見的「我以為擋了但其實沒擋」陷阱

整理一份新手最常踩的雷：

| 你寫的 | 為什麼還是會被打 |
| :-- | :-- |
| `if (name.contains(".."))` | `..%2f`、`....//`、URL 雙重編碼 全部繞過 |
| `name.replaceAll("\\.\\.", "")` | `....//` 被 replace 成 `..` 後再次中招 |
| `if (name.startsWith("/"))` | 沒擋 Windows 反斜線 / `..`/相對路徑往上爬 |
| `String.startsWith(BASE_DIR.toString())` | `BASE_DIR + "-evil"` 也會 startsWith |
| `filepath.Join(base, name)` 就完事 | Join 不會擋 `..` |
| 只檢查副檔名 | 內容可以偽造，且某些 server 用 MIME / 內容判斷 |
| `Path.normalize()` 但不檢查 prefix | normalize 完還是可能在 base 外面 |
| 用使用者送的檔名直接當儲存檔名 | 檔名衝突、Path Traversal、檔名注入一次到位 |
| 解 ZIP 沒檢查每個 entry 的路徑 | Zip Slip 直接寫 `~/.ssh/authorized_keys` |
| 上傳目錄放 web root 底下 | `.svg` / `.html` / `.jsp` 直接被執行 |

---

## 八、自我檢查清單

設計或 code review 時逐項問自己：

1. 這個功能真的需要讓使用者輸入「檔名」嗎？能不能改成 ID + DB 對應？
2. 我有用 `Path` 物件比對 prefix（不是 String）嗎？
3. 我有處理 `..`、絕對路徑、編碼後的 `..`、Windows 反斜線嗎？
4. 我有用 `toRealPath()` / `EvalSymlinks` 把 symlink 解開後再檢查嗎？
5. 上傳的檔案我**自己決定檔名**（UUID）了嗎？
6. 上傳目錄是否在 web root **外**？
7. 副檔名白名單 + magic number 雙重檢查了嗎？
8. ZIP 解壓有沒有對每個 entry 做 prefix 驗證？有沒有限制總解壓大小？拒絕 symlink？
9. App process 是用最小權限的使用者跑的嗎？
10. 我的 `.env` / `application.yml` / `secrets` 不在「使用者可能讀到的目錄」附近吧？

---

## 九、總結與明天預告

**今天的關鍵字：「使用者送過來的字串如果會變成檔案路徑，他就有可能讀／寫整台機器。」**

Path Traversal 的恐怖之處不在難——它非常簡單，三個字元 `../` 就能玩。恐怖在於：**它躲在所有「我以為我已經擋了」的角落**：

- 我有檢查 `..` 啊（→ 編碼繞過）
- 我有用 `filepath.Join` 啊（→ Join 不擋 `..`）
- 我有 startsWith 比對啊（→ 字串比對會被 `-evil` 騙）
- 我有 normalize 啊（→ 你忘了檢查 normalize 完還在不在 base 底下）
- 我只給讀啊（→ 那也讀光你的 `.env` / `id_rsa`）

**Path Traversal 防禦的三條底線：**

1. **能不接觸使用者字串就不接觸**——用 ID + DB 對應，UUID 當儲存檔名。
2. **正規化後 prefix 驗證**——而且要用路徑物件比對，把 symlink 也展開。
3. **權限與沙箱當最後一道牆**——讓 app 連讀都讀不到敏感檔案。

檔案上傳則是 Path Traversal 的近親 + XSS、RCE 的綜合體。**核心心法：使用者上傳的是「資料」，不是「程式碼」，也不是「檔案系統指令」。**

---

**Day 12 預告：Command Injection（命令注入）**——當你的後端會 `Runtime.exec()` / `exec.Command()` 跑 shell 指令，使用者輸入的一個分號就能讓你執行任意系統命令。我們會看為什麼 `bash -c` 是危險的、為什麼 `exec("ls " + filename)` 比 `exec(["ls", filename])` 慘十倍。
