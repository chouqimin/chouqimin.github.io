---
title: "Day 44 — ZIP Slip / 壓縮檔解壓縮的路徑穿越攻擊"
date: 2026-06-09
tags: ["Path Traversal", "檔案上傳", "ZIP Slip"]
---

# Day 44 — ZIP Slip / 壓縮檔解壓縮的路徑穿越攻擊

> 適合對象：後端工程師（初學～中階）
> 主題：解壓縮 zip / tar / jar 時被路徑穿越覆蓋系統檔案，以及 Java / Go 的正確寫法
> 預估閱讀時間：18 分鐘

---

## 一、為什麼今天要講這個？

幾乎每個後端服務遲早都會碰到「使用者上傳壓縮檔」的需求：

- 後台讓使用者匯入一包資料（多個 CSV、圖片）
- CI/CD 從 S3 拉下 build artifact 解壓
- 外部廠商每天送一包 `.tar.gz` 報表進來
- 把使用者上傳的 ZIP 解開後再做處理

這時候很多人寫的程式碼長這樣：

```java
File outFile = new File(targetDir, entry.getName());
```

看起來人畜無害，**但只要壓縮檔裡有一個 entry 的名字是 `../../../../etc/cron.d/pwn`**，這行就會把檔案寫到 `targetDir` 之外，整個系統就被覆蓋了。

這個漏洞在 2018 年被 Snyk 大規模揭露，受影響的專案橫跨 Apache Commons Compress、Spring、Hadoop、Plexus、Selenium、JetBrains 等數千個 Java/Node/Go/Ruby 函式庫。叫做 **ZIP Slip**，CWE-22 的特殊子分類。

跟 Day 11 講的「Path Traversal」差別在哪？Day 11 是攻擊者控制 **HTTP 參數的檔名**；ZIP Slip 是攻擊者控制 **壓縮檔 entry 內部的檔名**——後者很多人完全沒想到要過濾。

---

## 二、漏洞原理：壓縮檔格式本身就允許「任何路徑」

ZIP、TAR、JAR 這些格式裡，每個 entry 的檔名只是一個字串。**規範並沒有強制檔名不能有 `..`**。

攻擊者只要用一個能寫入任意 entry 名稱的工具（例如自寫腳本、或直接用 Python `zipfile`），就能做出這樣的壓縮檔：

```
evil.zip
├── normal.txt              ← 正常檔案，混淆視聽
├── ../../etc/cron.d/pwn    ← 路徑穿越
└── ../../../home/app/.ssh/authorized_keys  ← 把攻擊者的 public key 塞進去
```

當後端用「entry 名稱直接接到 target 目錄」的方式解壓時，會做出：

```
new File("/var/app/uploads", "../../etc/cron.d/pwn").getAbsolutePath()
// → /etc/cron.d/pwn
```

如果服務以 root 跑，就是 RCE。如果以一般使用者跑，至少能覆蓋掉同使用者的 `.ssh/authorized_keys`、設定檔、或部署目錄裡的 `.jar`。

---

## 三、Java 場景：典型的危險寫法

```java
// ❌ 有漏洞的 ZIP 解壓
public void extract(InputStream zipStream, File targetDir) throws IOException {
    try (ZipInputStream zis = new ZipInputStream(zipStream)) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File outFile = new File(targetDir, entry.getName());  // ← 危險
            if (entry.isDirectory()) {
                outFile.mkdirs();
            } else {
                outFile.getParentFile().mkdirs();
                try (FileOutputStream fos = new FileOutputStream(outFile)) {
                    zis.transferTo(fos);
                }
            }
        }
    }
}
```

問題：`new File(targetDir, "../../etc/passwd")` 不會報錯，會直接給你一個指向 `/etc/passwd` 的 `File` 物件。

### 正確寫法：解壓前先驗證真實路徑

```java
public void extract(InputStream zipStream, File targetDir) throws IOException {
    // 1. 拿到「正規化後」的目標目錄絕對路徑
    Path targetRoot = targetDir.toPath().toAbsolutePath().normalize();

    try (ZipInputStream zis = new ZipInputStream(zipStream)) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            // 2. 解析這個 entry 真正會落在哪
            Path resolved = targetRoot.resolve(entry.getName())
                                      .toAbsolutePath()
                                      .normalize();

            // 3. 確認還在 targetRoot 底下
            if (!resolved.startsWith(targetRoot)) {
                throw new SecurityException(
                    "Zip entry is outside of the target dir: " + entry.getName());
            }

            // 4. 額外防禦：拒絕絕對路徑、Windows 磁碟代號
            if (entry.getName().contains("\0")) {
                throw new SecurityException("Null byte in entry name");
            }

            if (entry.isDirectory()) {
                Files.createDirectories(resolved);
            } else {
                Files.createDirectories(resolved.getParent());
                try (OutputStream os = Files.newOutputStream(resolved)) {
                    zis.transferTo(os);
                }
            }
        }
    }
}
```

關鍵三步驟：

1. **`normalize()`**：把 `..` 消化掉
2. **`startsWith(targetRoot)`**：確認最終路徑還在預期目錄裡
3. **比較的是「絕對路徑」**：相對路徑比較會被符號連結繞過

### 用成熟的函式庫更安全

如果你用 **Apache Commons Compress 1.18+**，它有內建檢查；但建議還是套上面那層 `startsWith` 驗證，因為 Commons Compress 預設**不會**幫你檢查 entry 名稱（你要自己呼叫 `ArchiveEntry.getName()` 後驗證）。

如果你用 **Spring 的 `ZipUtil` / `Plexus Archiver` 舊版**——直接升級，這幾個都有 CVE。

---

## 四、Go 場景：`archive/zip` 標準函式庫

Go 的 `archive/zip` 也完全不會幫你檢查路徑。

```go
// ❌ 有漏洞的 Go 版本
func Extract(src, dest string) error {
    r, err := zip.OpenReader(src)
    if err != nil {
        return err
    }
    defer r.Close()

    for _, f := range r.File {
        path := filepath.Join(dest, f.Name)  // ← 危險
        if f.FileInfo().IsDir() {
            os.MkdirAll(path, f.Mode())
            continue
        }
        if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
            return err
        }
        out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
        if err != nil {
            return err
        }
        rc, _ := f.Open()
        io.Copy(out, rc)
        out.Close()
        rc.Close()
    }
    return nil
}
```

`filepath.Join` 會做「乾淨化」但**不會阻止跳出根目錄**：

```go
filepath.Join("/var/app/uploads", "../../etc/passwd")
// → "/etc/passwd"   ← 沒擋
```

### 正確寫法

```go
func Extract(src, dest string) error {
    r, err := zip.OpenReader(src)
    if err != nil {
        return err
    }
    defer r.Close()

    // 1. 取得絕對且乾淨的根目錄
    destRoot, err := filepath.Abs(filepath.Clean(dest))
    if err != nil {
        return err
    }

    for _, f := range r.File {
        // 2. 解析最終落點
        target := filepath.Join(destRoot, f.Name)
        targetAbs, err := filepath.Abs(target)
        if err != nil {
            return err
        }

        // 3. 確認仍在根目錄之下（要加上路徑分隔符避免 prefix-match bug）
        if !strings.HasPrefix(targetAbs, destRoot+string(os.PathSeparator)) &&
            targetAbs != destRoot {
            return fmt.Errorf("zip slip detected: %q", f.Name)
        }

        // 4. 拒絕符號連結 entry（zip 也能存 symlink）
        if f.Mode()&os.ModeSymlink != 0 {
            return fmt.Errorf("symlink in archive not allowed: %q", f.Name)
        }

        if f.FileInfo().IsDir() {
            if err := os.MkdirAll(targetAbs, 0o755); err != nil {
                return err
            }
            continue
        }

        if err := os.MkdirAll(filepath.Dir(targetAbs), 0o755); err != nil {
            return err
        }
        if err := writeOne(f, targetAbs); err != nil {
            return err
        }
    }
    return nil
}

func writeOne(f *zip.File, target string) error {
    // O_EXCL 阻止覆蓋既存檔案（含被攻擊者預先放好的 symlink）
    out, err := os.OpenFile(target,
        os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
    if err != nil {
        return err
    }
    defer out.Close()

    rc, err := f.Open()
    if err != nil {
        return err
    }
    defer rc.Close()

    // 5. 限制大小，避免 zip bomb（見第六節）
    _, err = io.CopyN(out, rc, 100*1024*1024) // 100MB per file
    if err != nil && err != io.EOF {
        return err
    }
    return nil
}
```

注意三個 Go 特有的眉角：

1. **`HasPrefix` 要加分隔符**：否則 `/tmp/foo` 會被當成 `/tmp/foobar` 的前綴而過關
2. **拒絕 symlink entry**：zip 規範支援 symlink，攻擊者可以先解出一個 `link → /etc`，下一個 entry 寫進 `link/cron.d/pwn` 就會跳出去
3. **`O_EXCL` 阻止覆蓋**：如果根目錄裡已經有檔案是 symlink（例如同個 zip 前面的 entry 留下的），不加 `O_EXCL` 會跟著 symlink 寫出去

---

## 五、實戰：寫一個會炸的 zip 來做測試

最可靠的防禦驗證方式是**自己做一個惡意 zip**，丟給你的程式碼跑。

### Python 一行做出惡意 zip

```python
import zipfile
with zipfile.ZipFile('evil.zip', 'w') as z:
    z.writestr('normal.txt', 'hello')
    z.writestr('../../../../tmp/pwned.txt', 'gotcha')
```

### Java 單元測試

```java
@Test
void extract_shouldRejectZipSlip(@TempDir Path tmp) throws Exception {
    Path zipFile = tmp.resolve("evil.zip");
    try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(zipFile))) {
        zos.putNextEntry(new ZipEntry("normal.txt"));
        zos.write("hello".getBytes());
        zos.closeEntry();
        zos.putNextEntry(new ZipEntry("../../../etc/pwn.txt"));
        zos.write("gotcha".getBytes());
        zos.closeEntry();
    }

    Path target = tmp.resolve("out");
    Files.createDirectories(target);

    assertThatThrownBy(() ->
        extractor.extract(Files.newInputStream(zipFile), target.toFile()))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("outside of the target dir");

    // 額外確認：tmp 之外確實沒被寫進去
    assertThat(Files.exists(Path.of("/etc/pwn.txt"))).isFalse();
}
```

### Go 單元測試

```go
func TestExtract_RejectsZipSlip(t *testing.T) {
    tmp := t.TempDir()

    // 做一個惡意 zip
    zipPath := filepath.Join(tmp, "evil.zip")
    buf, _ := os.Create(zipPath)
    w := zip.NewWriter(buf)
    f1, _ := w.Create("normal.txt")
    f1.Write([]byte("hello"))
    f2, _ := w.Create("../../../tmp/pwn.txt")
    f2.Write([]byte("gotcha"))
    w.Close()
    buf.Close()

    dest := filepath.Join(tmp, "out")
    os.MkdirAll(dest, 0o755)

    err := Extract(zipPath, dest)
    if err == nil || !strings.Contains(err.Error(), "zip slip") {
        t.Fatalf("expected zip slip error, got %v", err)
    }

    if _, err := os.Stat("/tmp/pwn.txt"); err == nil {
        t.Fatal("attacker file was written outside target dir!")
    }
}
```

寫這種測試的好處：**未來重構解壓邏輯時，這條測試會立刻把退化抓出來**。

---

## 六、進階防禦：別忘了 zip bomb 和資源耗盡

ZIP Slip 是「寫到哪裡」的問題；同類型還有兩個「寫多少」的問題，建議一起防：

| 攻擊 | 攻擊手法 | 防禦 |
|------|---------|------|
| Zip Bomb | 一個 42 KB 的 zip 解開 4.5 PB（巢狀壓縮、極高壓縮比） | 限制單檔大小、總大小、entry 數量 |
| Zip Symlink | entry 是 symlink 指向 `/etc`，下一個 entry 寫到 symlink 底下 | 拒絕 symlink entry |
| File Descriptor 耗盡 | 上百萬個 0-byte entry | 限制 entry 數量 |

```java
private static final long MAX_ENTRY_SIZE = 100L * 1024 * 1024;  // 100MB
private static final long MAX_TOTAL_SIZE = 1024L * 1024 * 1024; // 1GB
private static final int  MAX_ENTRIES   = 10_000;

// 解壓時逐 entry 累計
long totalRead = 0;
int entryCount = 0;
while ((entry = zis.getNextEntry()) != null) {
    if (++entryCount > MAX_ENTRIES)
        throw new SecurityException("Too many entries");
    // ...用 BoundedInputStream 包住 zis，超過 MAX_ENTRY_SIZE 就丟例外
}
```

別只信任 `ZipEntry.getSize()`——那個值來自壓縮檔的 metadata，攻擊者可以亂寫。**要邊讀邊計數**。

---

## 七、TL;DR — 解壓縮的安全 5 條規則

1. **絕對路徑驗證**：解出來的 path 必須 `startsWith` 目標根目錄（加分隔符）
2. **拒絕 `..`、絕對路徑、`null byte`、Windows 磁碟代號**：在做檔案 IO 之前
3. **拒絕 symlink entry**：或至少不要 follow symlink
4. **用 `O_EXCL` / `CREATE_NEW`**：避免覆蓋既存檔案或 symlink
5. **限制大小與 entry 數量**：防 zip bomb 跟資源耗盡

---

## 八、自我檢查清單

對著你目前服務裡所有「會接收 / 解壓縮使用者檔案」的地方，問自己：

- [ ] 有沒有在解壓**之前**驗證每個 entry 的目標路徑？
- [ ] 比較用的是 **絕對路徑 + normalize 後** 的字串嗎？
- [ ] `HasPrefix` 有沒有加分隔符（Go）？或用 `Path.startsWith`（Java）？
- [ ] 有沒有限制單檔大小、總大小、entry 數量？
- [ ] symlink entry 是拒絕還是 follow？
- [ ] 用的是 root 跑？還是專用的 unprivileged user？解壓目錄是不是寫死的最小範圍？
- [ ] 有沒有對應的單元測試，會放一個惡意 zip 進去？

---

## 九、延伸閱讀

- Snyk 2018 年的 ZIP Slip 原始揭露：<https://security.snyk.io/research/zip-slip-vulnerability>
- CWE-22：Path Traversal
- CVE-2018-1263、CVE-2018-8013、CVE-2018-11771：Spring / Plexus / Commons Compress 的 ZIP Slip 案例
- Go 官方提案 `archive/zip: add Reader.Open` 增加路徑保護（2023 後逐步加強，但你還是該自己驗）

---

**今日結語**：解壓縮看起來是「把檔案放到資料夾裡」這麼無聊的事，但只要少寫一個 `startsWith` 檢查，就是一個能讓對方寫入任意檔案的 RCE。明天我們來聊 **WebSocket 安全：Cross-Site WebSocket Hijacking（CSWSH）與長連線授權**——為什麼 WebSocket 握手不會自動繼承你 REST API 的 CSRF / Origin 防護，攻擊者怎麼從別的網站直接連上你的 WebSocket、冒用使用者身分，以及後端該怎麼驗 Origin 與在連線後持續授權。
