---
title: "Day 106：版本規則對了，但 repo 正在發佈到一半，client 剛好來抓，會不會讀到「新 snapshot 配舊 targets」的半成品？——TUF consistent snapshot 與 hash-prefixed 檔名下載，go-tuf `ConsistentSnapshot` 開關＋`PrefixTargetsWithHash` 的發佈原子性"
date: 2026-08-18
tags: ["TUF", "供應鏈安全", "consistent-snapshot", "發佈原子性"]
---

接續 Day105 預告：昨天把消費端的**版本規則**收完了——`trustedmetadata` 用「版本單調遞增＋過期檢查＋上層 meta 綁定」擋下 rollback／freeze／mix-and-match，證明「client 手上這份 metadata 是不是最新、彼此對不對得起來」。但那整套判斷有一個**沒明講的前提**：client 必須「先能一次抓到一整套對得起來的檔案」，版本規則才有東西可判斷。今天翻到**檔案層**的問題：**repo 正在發佈新版（先傳 targets、再傳 snapshot、最後 timestamp），一個 client 剛好在發佈中途來抓——它會不會讀到「新的 snapshot 指向的 targets 版本，但抓到的卻是還沒被覆蓋的舊 targets 檔案」這種半成品？**

**這篇是延伸／接續，不是重新介紹 TUF。** 明確不重述 Day105 的版本單調／過期／綁定規則（`UpdateTimestamp`／`UpdateSnapshot`／`VerifyLengthHashes`），也不重述 Day104 的委派遍歷。今天只聚焦一件事：**TUF 的「consistent snapshot（一致快照）」機制——repo 端怎麼靠「版本前綴的 metadata 檔名（`<version>.snapshot.json`）」與「雜湊前綴的 target 檔名（`<hash>.<name>`）」，讓新舊版本的檔案在 repo 上並存、互不覆蓋，使得任何一個 client 不管在發佈的哪個瞬間來抓，都只會抓到「一整套當初一起簽發、對得起來」的檔案，而不會撞上「發佈到一半」的競態。** consistent snapshot 這個機制在本系列是**首次介紹**。

安全主軸先講在前面：**Day105 的版本規則回答「這份對不對版」，consistent snapshot 回答「怎麼在真實的、會被並發讀寫的 repo 上，讓 client 每次都『整套抓齊、抓到一致的一套』」。前者是判斷邏輯，後者是讓那個邏輯有正確輸入的『擷取與發佈原子性』機制。沒有它，一個誠實的 repo 光是「正常發佈新版」這個動作，就可能在發佈窗口內把半成品餵給並發的 client——不需要任何攻擊者。**

> 本文的 Go 範例對照 `github.com/theupdateframework/go-tuf/v2` 的 `master` 原始碼：`metadata/updater/updater.go` 的 `DownloadTarget` / `downloadMetadata` / `loadRoot` / `loadSnapshot` / `loadTargets` / `persistMetadata`，以及 `metadata/config/config.go` 的 `UpdaterConfig.PrefixTargetsWithHash`（預設 `true`）與 `Root.Signed.ConsistentSnapshot` 欄位，皆為實際存在的呼叫與欄位，非杜撰。go-tuf/v2 為維護中版本，實務請釘在含修補的維護版（承 Day104 CVE-2024-47534／Day18 版本衛生）。


## 一、先看「非一致快照」的競態：覆蓋式檔名的原罪

先講清楚不用 consistent snapshot 時會發生什麼，才知道這機制在補什麼。

一個 TUF repo 發佈一輪更新的**固定順序是「由下往上」**（跟 client 消費的「由上往下」相反）：

```text
1. 先寫新的 targets.json（指向新成品）
2. 再寫新的 snapshot.json（記住新 targets 的版本＋雜湊）
3. 最後寫新的 timestamp.json（記住新 snapshot 的版本＋雜湊）
```

為什麼是這個順序？因為**上層是下層的錨點**（Day105）：`timestamp` 指向 `snapshot`、`snapshot` 指向各 `targets`。你必須「先把被指向的東西放好，才能發佈指向它的指標」，否則指標會指到一個還不存在的東西。

問題在於：**如果檔名是固定的**——`snapshot.json`、`targets.json`——那「寫新版」就是**覆蓋舊檔**。於是發佈過程出現一個危險窗口：

```text
時間軸(非一致快照,固定檔名):
t0  repo: snapshot.json=v41(指向 targets v41), targets.json=v41
t1  repo 開始發佈 v42: 先覆蓋 targets.json = v42   ← 危險窗口開始
t2  ── client A 剛好在這裡來抓 ──
      抓 timestamp → 還是 v41(還沒更新) → 說 snapshot 該是 v41
      抓 snapshot.json → 拿到 v41(還沒覆蓋) → 說 targets 該是 v41 版本+雜湊
      抓 targets.json → 但檔案已被覆蓋成 v42! → 雜湊對不上 v41 → 更新失敗
t3  repo 覆蓋 snapshot.json = v42
t4  repo 覆蓋 timestamp.json = v42   ← 危險窗口結束
```

看清楚 t2 的 client A：它**不是被攻擊**，是 repo 自己發佈到一半，讓它撞上「timestamp/snapshot 說要 targets v41，但 `targets.json` 這個檔名已經被 v42 蓋掉」。Day105 的 `VerifyLengthHashes` 會忠實地把它擋下（回更新失敗）——**安全上不會受害，但可用性受害**：一個誠實 repo 的每一次發佈，都在製造一段「並發 client 更新失敗」的窗口。發佈越頻繁、client 越多、CDN 傳播越慢，這段窗口的傷害越大。

更糟的一種排列：如果攻擊者能控制發佈時序或 CDN 的傳播不一致，他甚至能**刻意延長或利用這個窗口**，讓 client 在「新 timestamp 配舊 snapshot」的組合上卡住——這就退化成 Day105 的 mix-and-match 邊緣。consistent snapshot 從根上把這個窗口消掉。


## 二、consistent snapshot 的核心一招：不覆蓋，改用「版本／雜湊前綴檔名」讓新舊並存

consistent snapshot 的解法一句話：**發佈新版時不覆蓋舊檔，而是寫成一個「檔名帶版本或雜湊前綴」的新檔案，讓新舊版本在 repo 上並存。** 這樣「發佈」就從「覆蓋」變成「新增」——新增是天生原子的（新檔案在完全寫好前，沒有任何指標指向它）。

具體命名規則：

- **metadata 用版本前綴**：`snapshot.json` → `42.snapshot.json`、`targets.json` → `42.targets.json`、委派角色 `jar-team.json` → `42.jar-team.json`。
- **target 用雜湊前綴**：`order-service.jar` → `<sha256hex>.order-service.jar`。
- **root 一律版本化**：`1.root.json`、`2.root.json`……（這條**與開關無關**，root 永遠版本化，見第四節）。
- **timestamp 永遠不加前綴**：它固定叫 `timestamp.json`，是唯一會被覆蓋的檔——它就是整個 repo 狀態的「游標」（見第五節）。

由這一招直接推出兩個性質：

1. **發佈原子性**：發新版是「新增帶前綴的檔」，舊檔原封不動還在。client 在任何瞬間看到的都是「某個完整的、對得起來的舊狀態」，直到 timestamp 這一個檔被原子替換，才「一次翻頁」到新狀態。
2. **內容定址 / 快取永不失效**：target 用內容雜湊命名，`<hash>.order-service.jar` 的內容永遠等於那個 hash——它**不可能被改寫**（改內容就是改檔名）。CDN／鏡像可以無限期快取、永不需要 invalidate，也天生擋掉「同一 URL 內容被偷換」。


## 三、開關在哪：`root.Signed.ConsistentSnapshot`

要不要走這套，由 **root metadata 裡的一個 bool 決定**，consumer 端讀 `root.Signed.ConsistentSnapshot`。go-tuf 的下載邏輯全都以它為分支條件：

```go
// updater.go DownloadTarget:是否對 target 檔名加雜湊前綴,取決於 root 的開關
consistentSnapshot := update.trusted.Root.Signed.ConsistentSnapshot
if consistentSnapshot && update.cfg.PrefixTargetsWithHash {
    // ...組出 <hash>.<name> 的遠端路徑(見第五節)
}
```

```go
// updater.go loadSnapshot:是否用版本前綴抓 snapshot,也取決於同一個開關
version := ""
if update.trusted.Root.Signed.ConsistentSnapshot {
    version = strconv.FormatInt(snapshotMeta.Version, 10) // 版本從 timestamp 記的 snapshot meta 來
}
data, err = update.downloadMetadata(metadata.SNAPSHOT, length, version)
```

三個後端要記住的點：

- **它是 root 說了算，不是 client 說了算**：開不開 consistent snapshot 是**發行端**的 repo 佈署決定，寫在 root metadata 裡、被 root 金鑰簽名保護。client 只是照 root 的宣告執行。攻擊者想把「開」改成「關」來誘導 client 走覆蓋式命名？他得改 root——沒 root 金鑰改不動（Day101）。
- **消費端還有一個本地開關 `PrefixTargetsWithHash`**：go-tuf `UpdaterConfig` 有這個欄位，**預設 `true`**（原始碼註解直接寫 `use hash-prefixed target files with consistent snapshots`）。注意 target 的雜湊前綴要**兩個條件同時成立**（`consistentSnapshot && PrefixTargetsWithHash`）才會啟用；metadata 的版本前綴則只看 root 的 `ConsistentSnapshot`。一般不要去關 `PrefixTargetsWithHash`，關了會讓你對一個「只放 `<hash>.<name>` 檔」的一致快照 repo 抓不到 target。
- **root 不吃這個開關**：下一節解釋。


## 四、metadata 檔名：`<version>.<role>.json`，且 root 永遠版本化

看 go-tuf 怎麼把版本前綴組進 URL——就一個函式：

```go
// updater.go downloadMetadata:version 為空→不加前綴;有值→<version>.<role>.json
func (update *Updater) downloadMetadata(roleName string, length int64, version string) ([]byte, error) {
    urlPath := ensureTrailingSlash(update.cfg.RemoteMetadataURL)
    if version == "" {
        urlPath = fmt.Sprintf("%s%s.json", urlPath, url.PathEscape(roleName))       // timestamp.json
    } else {
        urlPath = fmt.Sprintf("%s%s.%s.json", urlPath, version, url.PathEscape(roleName)) // 42.snapshot.json
    }
    return update.cfg.Fetcher.DownloadFile(urlPath, length, 0)
}
```

**「version 從哪來」才是 consistent snapshot 跟 Day105 綁定鏈接起來的地方**，這是本篇最關鍵的一環：

```go
// loadSnapshot:要抓哪個版本的 snapshot?→ 由 timestamp 裡記的 snapshot meta 版本決定
snapshotMeta := update.trusted.Timestamp.Signed.Meta["snapshot.json"]
version := ""
if update.trusted.Root.Signed.ConsistentSnapshot {
    version = strconv.FormatInt(snapshotMeta.Version, 10)
}

// loadTargets:要抓哪個版本的 targets?→ 由 snapshot 裡記的該角色 meta 版本決定
metaInfo := update.trusted.Snapshot.Signed.Meta[fmt.Sprintf("%s.json", roleName)]
version := ""
if update.trusted.Root.Signed.ConsistentSnapshot {
    version = strconv.FormatInt(metaInfo.Version, 10)
}
```

把這個跟 Day105 疊起來看，整條鏈是這樣扣的：

```text
timestamp.json(唯一固定檔名) ──記著 snapshot 版本 v_s──▶ 去抓 <v_s>.snapshot.json
<v_s>.snapshot.json          ──記著各 targets 版本 v_t──▶ 去抓 <v_t>.targets.json / <v_t>.jar-team.json
```

**這就是「一致」的來源**：你手上這份 timestamp 一旦定了，它就決定了「該抓哪個版本的 snapshot」；那份 snapshot 又決定了「該抓哪些版本的 targets」。因為每個版本都有**獨立不覆蓋的檔名**，這一整套「timestamp 點名的檔案」在 repo 上一定都還在、而且就是當初一起簽發的那一套。**Day105 是「驗版本對不對」，這裡是「按版本去抓對應的獨立檔名」——版本規則與檔名擷取是同一件事的兩面。**

**root 為什麼永遠版本化、不吃開關？** 看 `loadRoot`：

```go
// loadRoot:root 一律帶版本抓,從 N+1 逐版往上找,直到 404
for nextVersion := lowerBound; nextVersion < upperBound; nextVersion++ {
    data, err := update.downloadMetadata(metadata.ROOT, update.cfg.RootMaxLength,
        strconv.FormatInt(nextVersion, 10)) // ← version 永遠有值
    ...
}
```

root 的更新是 Day101 的「嚴格 +1 逐版驗簽輪替」——client 得**逐份**抓 `1.root.json`、`2.root.json`……每份被前一份簽名背書。這種「逐版補鏈」本質上就需要「每一版都是獨立可取的檔名」，所以 **root 一律版本化與 consistent snapshot 開關無關**，是 root 輪替機制的內建需求。timestamp 則相反——它是游標，必須固定檔名才能被「覆蓋式翻頁」。中間兩層（snapshot／targets）才是被 `ConsistentSnapshot` 開關左右的。


## 五、target 檔名：`<hash>.<name>`，內容定址

target 檔案不用版本前綴，用**雜湊前綴**——因為 target 沒有「版本號」概念，它的身分就是內容雜湊。看 `DownloadTarget`：

```go
// updater.go DownloadTarget(節錄):組出 target 的遠端路徑
targetRemotePath := targetFile.Path
consistentSnapshot := update.trusted.Root.Signed.ConsistentSnapshot
if consistentSnapshot && update.cfg.PrefixTargetsWithHash {
    hashes := ""
    for _, v := range targetFile.Hashes { // 取「第一個」雜湊的 hex
        hashes = hex.EncodeToString(v)
        break
    }
    baseName := filepath.Base(targetFilePath)
    dirName, ok := strings.CutSuffix(targetFilePath, "/"+baseName)
    if !ok {
        targetRemotePath = fmt.Sprintf("%s.%s", hashes, baseName)          // <hash>.<name>
    } else {
        targetRemotePath = fmt.Sprintf("%s/%s.%s", dirName, hashes, baseName) // <dir>/<hash>.<name>
    }
}
fullURL := fmt.Sprintf("%s%s", targetBaseURL, targetRemotePath)
data, err := update.cfg.Fetcher.DownloadFile(fullURL, targetFile.Length, 0)
// 抓回來一樣要過 Day105 的長度+雜湊驗證,前綴只是「找對檔」,不取代驗證
err = targetFile.VerifyLengthHashes(data)
```

三個要注意的細節：

- **`<hash>` 是 target 的長度雜湊之一，來自 snapshot→targets 綁定鏈裡簽過名的 `targetFile.Hashes`**——不是 client 自己算了才去抓，是「用 metadata 裡記的雜湊去拼檔名」。所以攻擊者無法用「換一個 hash 前綴」誘導你抓到別的檔：那個 hash 是被 targets metadata 簽名保護的。
- **`for range Hashes { break }` 取「第一個」——而 Go map 迭代是隨機的**。若一個 target 記了多種雜湊演算法（如 sha256 與 sha512），這裡抓到哪一個前綴是非決定性的。這在正常一致快照 repo 沒問題（repo 會為每個雜湊都放一份 hardlink，抓哪個都在），但如果你自建 repo 只放了 sha256 前綴的檔、metadata 卻多記了 sha512，就可能偶發 404。**自建發行端的落地提醒：每個宣告的雜湊都要有對應前綴檔，或 metadata 只記你實際落檔的那種雜湊。**
- **前綴只負責「找對檔」，不取代驗證**：抓回來照樣走 `VerifyLengthHashes`。雜湊前綴是「內容定址的定位」，Day105 的雜湊比對是「內容正確性的驗證」，兩者不互相取代。


## 六、發佈原子性：timestamp 是唯一的「翻頁游標」

把前面串起來，看一次「一致快照 repo 發新版」時，並發 client 為什麼永遠讀不到半成品：

```text
時間軸(一致快照,前綴檔名):
t0  repo: 41.snapshot.json, 41.targets.json, <h41>.order-service.jar 都在; timestamp.json 指向 snapshot v41
t1  repo 發 v42:新增 <h42>.order-service.jar   ← 舊檔全都還在,沒有指標指向新檔
t2  repo 新增 42.targets.json                   ← 還是沒有指標指向它
t3  repo 新增 42.snapshot.json                  ← 還是沒有指標指向它
      ── client A 在 t1~t3 任何時刻來抓 ──
         抓 timestamp.json → 還指向 v41 → 就去抓 41.snapshot.json → 41.targets.json → <h41>.jar
         全套 v41 都在、都對得起來 → 成功,拿到「完整的舊版」
t4  repo 原子替換 timestamp.json → 指向 snapshot v42   ← 唯一的「翻頁」瞬間
      ── client B 在 t4 之後來抓 ──
         抓 timestamp.json → 指向 v42 → 42.snapshot.json → 42.targets.json → <h42>.jar
         全套 v42 都在、都對得起來 → 成功,拿到「完整的新版」
```

關鍵洞察：**除了 timestamp.json 這一個固定檔名的檔，其他所有檔都是「只新增、不覆蓋」。於是整個發佈的『不可分割翻頁』被壓縮到 timestamp.json 這一次替換上**——它之前，client 看到完整舊版；它之後，client 看到完整新版；**永遠沒有「半舊半新」的可見中間態**。timestamp 因此是整個 repo 狀態的**游標（cursor）**：它短效期（Day105 freeze 防線）＋它固定檔名（本篇原子翻頁），兩個角色合在一起。

這也解釋了 go-tuf `persistMetadata` 為什麼在 client 端也用「temp 檔寫完再 `os.Rename`」：

```go
// persistMetadata:client 端落地也要原子——寫 temp 再 rename,避免半寫檔被下次讀到
file, _ := os.CreateTemp(update.cfg.LocalMetadataDir, "tuf_tmp")
file.Write(data); file.Close()
os.Rename(file.Name(), fileName) // rename 在同檔系是原子操作
```

原子性是**兩端**的事：發行端用「前綴檔名＋最後翻 timestamp」保證遠端原子；消費端用「temp＋rename」保證本地快取原子。任一端不原子，並發或當機都可能讓下一輪讀到撕裂的狀態。


## 七、後端落地：發行端開開關，消費端別關前綴，CDN 白吃紅利

跟 Day101~105 同一條線：**這些機制你不該手刻**，`go-tuf` updater 內部就照 root 的開關跑完整套前綴擷取。但有三個維運層面的責任分給發行端與消費端：

**① 發行端：把 `ConsistentSnapshot` 開起來（幾乎沒有理由不開）。**

用 `go-tuf` / `tuf-on-ci` 佈署 repo 時，root metadata 的 `ConsistentSnapshot` 設 `true`。代價是 repo 會累積歷史版本檔（`41.snapshot.json`、`42.snapshot.json`……並存），需要保留策略去 GC 舊版；換來的是**發佈零競態＋CDN 永久快取**。對任何有並發 client 或走 CDN／鏡像的 repo，這個交換幾乎穩賺。Sigstore 公信 repo 就是開的。

**② 消費端：`PrefixTargetsWithHash` 保持預設 `true`，別自作聰明關掉。**

go-tuf `config.New` 預設就是 `true`。除非你明確知道你的 repo 是非一致快照且 target 用原名落檔，否則不要動它——關掉會讓你對一致快照 repo 抓 `<hash>.<name>` 抓成原名而 404。

**③ 本地快取目錄權限：go-tuf 幫你收好了（承 Day105 §8）。**

`EnsurePathsExist` 對本地 metadata／targets 目錄用 `0700`（原始碼註解明說「防止共享系統上其他使用者讀寫 TUF 快取」）。這正是 Day105 講的「trusted metadata 持久化且權限受控」在庫層的兌現——rollback 下限的檔案別讓別的使用者能改寫。

給 JVM 工程師的落地形態（承 Day80/101~105 老線）：**一致快照的檔名擷取對消費端一樣是透明的。** 用 `sigstore-java` 的 `dev.sigstore.tuf.Updater` 抓 target 時，它內部按 root 的一致快照宣告去組版本／雜湊前綴檔名，你不會、也不該碰到 `<hash>.<name>` 這層：

```java
// 概念示意:消費端只表達「刷新並要 target」,一致快照的前綴檔名擷取都在庫裡。
// 你的責任:(1) 確認你信任的 root 有把 consistentSnapshot 宣告清楚(發行端決定);
//          (2) 別去關等價於 PrefixTargetsWithHash 的行為;
//          (3) 本地 store 持久+權限受控(承 Day105),當機/並發下 rename 落地才不撕裂。
var updater = /* dev.sigstore.tuf.Updater,以可信 root + 本地持久 store 初始化 */;
updater.update();  // 內部:root(逐版) → timestamp(游標) → <v>.snapshot.json → <v>.targets.json
var targetInfo = updater.getTargetInfo("maven/com/acme/order-service.jar");
byte[] bytes   = updater.downloadTarget(targetInfo); // 內部抓 <hash>.order-service.jar 再驗長度雜湊
```

三個 JVM 重點：

- **一致快照是 repo 屬性，client 只照 root 宣告執行**——你要治理的是「發行端有沒有開、開了之後的版本保留策略」，不是 client。
- **內容定址 target 讓你的成品快取／鏡像更安全**——`<hash>.jar` 的內容不可能被同 URL 偷換，這對 JVM 生態的 Maven／制品庫鏡像是一層天然保護。
- **Java 1.8 跑不動就 sidecar**——`sigstore-java` 需 JDK 11+；1.8 服務照 Day80 老辦法把 TUF 驗證挪成獨立 sidecar／服務。

一句話：**檔名前綴與原子翻頁的「機制」交給維護中的庫；後端要治理的是「發行端開一致快照＋版本保留」與「消費端本地快取的持久與權限」。**


## 八、常見誤區

- **「consistent snapshot 是為了節省空間或加速。」** 相反，它**多存**了歷史版本檔。它換來的是**發佈原子性**（並發 client 不撞半成品）與**CDN 永久快取**，是安全與可用性機制，不是省成本機制。
- **「有了 Day105 的雜湊驗證，就不需要一致快照了。」** 不對。雜湊驗證會忠實擋下半成品——但那代表「誠實 repo 的每次發佈都在製造一段並發 client 更新失敗的窗口」。一致快照是把那個窗口從根上消掉，讓失敗不必發生。
- **「timestamp 也該加版本前綴才一致。」** 錯。timestamp 必須是**唯一固定檔名、可被覆蓋**的檔——它就是整套狀態的翻頁游標，一次原子替換完成「舊→新」。給它加前綴，就沒有東西當游標了。
- **「root 加不加版本前綴，跟一致快照開關一起決定。」** 錯。root **永遠**版本化（`1.root.json`、`2.root.json`），這是 Day101 逐版 +1 輪替補鏈的內建需求，與 `ConsistentSnapshot` 無關。
- **「雜湊前綴檔名本身就是驗證，抓到就安全。」** 不夠。前綴只負責「定位對的檔」，抓回來照樣要 `VerifyLengthHashes`。前綴是定址，雜湊比對是驗證，兩者不互相取代。
- **「target 記多種雜湊比較安全，前綴隨便挑一個。」** 有雷。go-tuf 取「map 第一個」而 Go map 迭代隨機——自建 repo 若沒為每個宣告雜湊都放對應前綴檔，會偶發 404。要嘛每種雜湊都放 hardlink，要嘛 metadata 只記你實際落檔那種。
- **「client 端不用管原子，反正遠端原子就好。」** 錯。`persistMetadata` 用 temp＋rename 是因為**本地快取也要原子**——當機或並發下，半寫的本地檔會毒到下一輪。兩端都要原子。


## 九、Code Review／設計 checklist（一致快照與擷取）

- **發行端開一致快照**：repo 的 root metadata `ConsistentSnapshot=true`；用 `go-tuf`／`tuf-on-ci` 佈署、非手刻發佈流程（第三、七節）。
- **版本保留策略**：一致快照會累積 `<version>.*.json` 與 `<hash>.*` 歷史檔，確認有 GC／保留策略，別無限膨脹也別刪到「還在被舊 client 引用」的版本（第七節）。
- **消費端不關前綴**：`PrefixTargetsWithHash` 維持預設 `true`，除非明確面對非一致快照 repo（第三節）。
- **發佈順序正確**：先寫下層帶前綴檔（targets→snapshot），最後才原子替換 `timestamp.json` 這個游標；別在游標翻頁前就讓 client 有路徑指到半成品（第一、六節）。
- **本地快取原子＋權限**：確認落地走 temp＋`rename`（go-tuf `persistMetadata`）、快取目錄權限受控（`EnsurePathsExist` 0700，承 Day105）（第六、七節）。
- **每個雜湊都有對應前綴檔**：自建 repo 時，target 宣告的每種雜湊都要有 `<hash>.<name>` 落檔，避開 go-tuf 取「map 第一個」的非決定性（第五節）。
- **前綴不取代驗證**：確認抓 target 後仍走 `VerifyLengthHashes`、抓 metadata 仍走 Day105 版本／過期／綁定檢查（第五節）。
- **版本衛生**：TUF client 釘在含修補的維護版、`govulncheck`／SBOM 當紅線（承 Day18/104/105）。


## 十、測試怎麼做

這層測試的核心是**「發佈中途來抓，抓到的一定是完整一套」**與**「檔名擷取按 root 開關正確分支」**：

- **一致快照 metadata 檔名正確**：root `ConsistentSnapshot=true` 時，斷言 `loadSnapshot` 抓的是 `<v>.snapshot.json`、`loadTargets` 抓 `<v>.targets.json`；開關為 `false` 時抓不帶前綴的名（第三、四節）。
- **root 一律版本化**：不論開關，斷言 `loadRoot` 抓的是 `<N>.root.json`、且逐版 +1（承 Day101）（第四節）。
- **version 來源正確**：斷言要抓的 snapshot 版本取自 timestamp 記的 meta、targets 版本取自 snapshot 記的 meta，而非 client 自己猜（第四節）。
- **target 雜湊前綴**：`ConsistentSnapshot && PrefixTargetsWithHash` 時，斷言 `DownloadTarget` 組出 `<hash>.<name>`（含目錄前綴情境 `<dir>/<hash>.<name>`），且 `<hash>` 取自簽過名的 `targetFile.Hashes`（第五節）。
- **發佈中途原子性（整合測試）**：模擬 repo「已寫 42.targets/42.snapshot，但 timestamp 仍指 v41」，斷言並發 client 抓到**完整 v41**而非半成品；接著原子替換 timestamp 後，斷言下一次抓到**完整 v42**（第六節）。
- **前綴不取代驗證**：給一個「檔名 hash 前綴對、但內容被動過」的 target，斷言 `VerifyLengthHashes` 仍失敗（第五節）。
- **本地快取原子**：模擬寫 metadata 中途當機（temp 檔存在但未 rename），斷言下次讀取不會拿到半寫檔、以既有有效檔為準（第六節）。
- **多雜湊前綴一致**：target 記 sha256＋sha512，repo 只放其一前綴檔，斷言你的部署要嘛兩種都放、要嘛 metadata 只記落檔那種，避免 go-tuf 隨機挑到缺檔那個而 404（第五節）。


## 十一、一句話總結

> Day105 把消費端的**版本規則**收完（版本單調＋過期＋綁定，判斷「這份對不對版」）；今天翻到**檔案層的一致性擷取與發佈原子性**——版本規則要能運作，前提是 client 每次都能「整套抓齊、抓到對得起來的一套」。TUF 的 **consistent snapshot** 就是這個前提：發新版時**不覆蓋、改用前綴檔名讓新舊並存**——metadata 用版本前綴（`downloadMetadata` 組 `<version>.snapshot.json`，版本從上層 meta 來，正是 Day105 綁定鏈在檔名層的兌現）、target 用雜湊前綴（`DownloadTarget` 在 `ConsistentSnapshot && PrefixTargetsWithHash` 時組 `<hash>.<name>`，內容定址、CDN 永久快取）、**root 永遠版本化**（Day101 逐版輪替的內建需求，與開關無關）、**timestamp 永遠固定檔名**（整個 repo 狀態的翻頁游標，唯一被覆蓋的檔）。於是整個發佈的「不可分割翻頁」被壓縮到**替換 timestamp.json 這一個原子動作**上——在它之前 client 看到完整舊版、之後看到完整新版，永遠沒有半舊半新的可見中間態。這讓一個**誠實 repo 的正常發佈不再對並發 client 製造更新失敗窗口**，也順帶把「同 URL 內容被偷換」擋在內容定址之外。後端工程師的可執行結論：**機制交給維護中的 go-tuf／sigstore-java（開關讀 root、前綴預設開）；你要治理的是——發行端把 `ConsistentSnapshot` 開起來並管好版本保留、消費端別關 `PrefixTargetsWithHash`、兩端都保原子（遠端最後翻 timestamp、本地 temp＋rename）、快取目錄權限受控。**


## 延伸閱讀

- **Day105 rollback／freeze／mix-and-match 防禦**——今天的直接上游。昨天講「版本規則怎麼判斷新舊對版」，今天講「按那些版本去抓對應的獨立前綴檔名」；版本規則與檔名擷取是同一件事的兩面。timestamp 短效期（freeze 防線）＋固定檔名（原子游標）是它的雙重角色。
- **Day104 委派消費端解析**——`loadTargets` 抓委派角色 metadata 時，一致快照下同樣走 `<version>.jar-team.json` 前綴；委派遍歷（找角色）之上，先有一致快照（抓對版本的檔）。
- **Day101 TUF root 輪替**——root 永遠版本化（`<N>.root.json`）是逐版 +1 補鏈的內建需求，解釋了為何 root 不吃一致快照開關。
- **Day18 供應鏈／SBOM**——「版本衛生」（TUF client 釘含修補版、納入掃描）仍是底線。
- **Day10 SSRF／輸入邊界**——repo／mirror URL 是輸入面，一致快照的內容定址（`<hash>.<name>` 不可被同 URL 偷換）補強了鏡像來源的可信，但 URL 本身仍要釘死、走 egress allowlist。

---

明天預告：**Day 107 — 一致快照讓「線上」擷取原子了，但如果 client 根本沒有網路呢？TUF 離線／氣隙更新與 go-tuf `UnsafeLocalMode`——為什麼 `unsafeLocalRefresh` 只靠本地快取就能載入 timestamp／snapshot／targets、它刻意偏離了 TUF 規範 5.3~5.7 的哪些檢查、又保留了哪些（root 驗簽＋過期仍驗），以及氣隙／sidecar 環境把 metadata 當「離線包」搬運時的 rollback 與新鮮度風險**
（這是**延伸／接續**，把視角從今天的「線上怎麼原子地抓齊一套」轉到「完全不連網時，只靠磁碟上那套快取能安全更新到什麼程度、代價是什麼」。情境：一台氣隙機器用隨身碟把 TUF metadata 搬進來、`UnsafeLocalMode=true` 只讀本地——示範 go-tuf `updater.go` 的 `unsafeLocalRefresh` 骨架（`UpdateTimestamp`／`UpdateSnapshot`／`UpdateDelegatedTargets` 全走本地檔、不 `downloadMetadata`），對照它跟 `onlineRefresh` 的差異，講清楚「離線包新鮮度＝搬進來那一刻的 timestamp 效期」這個被 freeze 防線放大的維運陷阱。明確不重述今天的前綴檔名與 Day105 的版本規則，聚焦**離線更新的信任降級與氣隙搬運的 rollback／freeze 風險**。標為延伸篇，UnsafeLocalMode 離線更新首次介紹。）
