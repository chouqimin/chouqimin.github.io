---
title: "Day 107：一致快照讓「線上」抓齊一套了，但如果 client 根本沒網路呢？——TUF 離線／氣隙更新與 go-tuf `UnsafeLocalMode`，只靠磁碟上那套快取能安全更新到什麼程度、代價是什麼"
date: 2026-08-19
tags: ["TUF", "供應鏈安全", "氣隙離線", "freeze-rollback"]
---

接續 Day106 預告：昨天講的 consistent snapshot 解的是「**線上**擷取的原子性」——repo 一邊發佈、client 一邊來抓，靠版本／雜湊前綴檔名讓 client 每次都抓到一整套對得起來的檔案。但整個 Day101～106 有一個從沒被挑戰的前提：**client 有網路，能連到 remote metadata URL 去 `downloadMetadata`。** 今天把這個前提拿掉：**一台氣隙（air-gapped）機器根本不連網，只有人拿隨身碟把一包 TUF metadata 搬進來。這種情況下，go-tuf 的 `UnsafeLocalMode` 讓 `Refresh()` 完全不碰網路、只讀磁碟上那套快取——它到底安全到什麼程度？它刻意偏離了 TUF 規範 5.3～5.7 的哪些檢查、又保留了哪些？離線包的「新鮮度」被 Day105 的 freeze 防線放大成什麼維運陷阱？**

**這篇是延伸／接續，不是重新介紹 TUF。** 明確不重述 Day106 的前綴檔名與發佈原子性，也不重述 Day105 的版本單調／過期／綁定規則本身。今天的延伸角度只有一個：**把視角從「線上怎麼原子地抓齊一套」轉到「完全不連網時，只靠磁碟上那套快取能安全更新到什麼程度、代價是什麼」。** go-tuf 的 `UnsafeLocalMode`／`unsafeLocalRefresh` 離線更新在本系列是**首次介紹**。

安全主軸先講在前面：**離線更新不是「拿掉網路的線上更新」，而是一次明確的信任降級（trust downgrade）。它保留了「完整性」（簽章）與「過期上限」（expiry）與「回滾下限」（本地持久化的 trusted metadata），但徹底交出了「liveness／活性」——你永遠不會知道遠端有沒有更新的版本。這個被交出的活性，正好把 Day105 用來擋 freeze 的「短效 timestamp」從一條防線變成一個維運計時器：離線包的可用壽命，就等於搬進來那一刻 timestamp 的剩餘效期。**

> 本文的 Go 範例對照 `github.com/theupdateframework/go-tuf/v2` 的 `master` 原始碼：`metadata/updater/updater.go` 的 `Refresh` / `onlineRefresh` / `unsafeLocalRefresh` / `loadRoot` / `loadLocalMetadata`、`metadata/config/config.go` 的 `UpdaterConfig.UnsafeLocalMode` 欄位，以及 `metadata/trustedmetadata` 的 `UpdateTimestamp` / `UpdateSnapshot` / `UpdateDelegatedTargets`，皆為實際存在的呼叫與欄位，非杜撰。go-tuf/v2 為維護中版本，實務請釘在含修補的維護版（承 Day104 CVE-2024-47534／Day18 版本衛生）。


## 一、線上 refresh 與離線 refresh 的分岔點：就一個 `if`

go-tuf 的 `Refresh()` 本體短到出乎意料——它只是一個開關：

```go
// metadata/updater/updater.go
//
// If UnsafeLocalMode is set, no network interaction is performed, only
// the cached files on disk are used. If the cached data is not complete,
// this call will fail.
func (update *Updater) Refresh() error {
	if update.cfg.UnsafeLocalMode {
		return update.unsafeLocalRefresh()
	}
	return update.onlineRefresh()
}
```

兩條路的差別，先擺成一張對照表，後面各節再拆：

| 步驟 | `onlineRefresh`（線上） | `unsafeLocalRefresh`（離線） |
|---|---|---|
| root | `loadRoot()`：從 remote 逐版 `N+1` 抓、`UpdateRoot` 驗簽補鏈、輪替（承 Day101） | **完全不做**。root 就是 `New()` 時傳進來的 `LocalTrustedRoot`，不更新、不輪替 |
| timestamp | `loadTimestamp()`：先讀本地→再從 remote `downloadMetadata` 抓新的 | **只讀本地** `timestamp.json`→`UpdateTimestamp` |
| snapshot | `loadSnapshot()`：先讀本地→需要時 remote 抓 | **只讀本地** `snapshot.json`→`UpdateSnapshot(data, false)` |
| targets | `loadTargets()`：先讀本地→需要時 remote 抓 | **只讀本地** `targets.json`→`UpdateDelegatedTargets` |
| 網路 | 有 | **完全沒有** |

一句話：**離線模式把「先讀本地、失敗再上網補」的每一步，砍成「只讀本地，讀不到就整個失敗」。** 網路那半邊被切掉了。


## 二、`unsafeLocalRefresh` 到底做了什麼、沒做什麼

直接看原始碼（節錄，去掉重複的 error handling）：

```go
// unsafeLocalRefresh tries to load the persisted metadata already cached
// on disk. Note that this is an usafe function, and does deviate from the
// TUF specification section 5.3 to 5.7 (update phases).
// The metadata on disk are verified against the provided root though,
// and expiration dates are verified.
func (update *Updater) unsafeLocalRefresh() error {
	// Root is already loaded  ← root 在 New() 就從 LocalTrustedRoot 載入了，這裡不碰

	// load timestamp（只從本地磁碟讀）
	p := filepath.Join(update.cfg.LocalMetadataDir, metadata.TIMESTAMP)
	data, _ := update.loadLocalMetadata(p)
	update.trusted.UpdateTimestamp(data)      // ← 驗簽＋版本＋過期，全都走 Day105 那套

	// load snapshot（只從本地磁碟讀）
	p = filepath.Join(update.cfg.LocalMetadataDir, metadata.SNAPSHOT)
	data, _ = update.loadLocalMetadata(p)
	update.trusted.UpdateSnapshot(data, false) // ← trusted=false，照樣驗版本＋雜湊綁定＋過期

	// targets（只從本地磁碟讀）
	p = filepath.Join(update.cfg.LocalMetadataDir, metadata.TARGETS)
	data, _ = update.loadLocalMetadata(p)
	update.trusted.UpdateDelegatedTargets(data, metadata.TARGETS, metadata.ROOT)

	return nil
}
```

關鍵在於：**它砍掉的是「下載」，不是「驗證」。** `loadLocalMetadata` 只是 `os.ReadFile`，把磁碟上的 `timestamp.json`／`snapshot.json`／`targets.json` 讀進來；但接手的 `UpdateTimestamp`／`UpdateSnapshot`／`UpdateDelegatedTargets` 仍然是 Day105 那三個一模一樣的函式——**簽章、版本單調遞增、過期、上層 meta 綁定，一個都沒少。**

### 保留了什麼（KEPT）

- **簽章驗證**：timestamp／snapshot／targets 仍要用 `LocalTrustedRoot` 裡授權的角色公鑰驗簽。攻擊者改一個位元組，`UpdateTimestamp` 就簽章失敗。**離線不等於不驗簽。**
- **過期檢查**：`Update*` 內部照樣 `IsExpired(RefTime)`。離線包裡的 timestamp 過期了？`unsafeLocalRefresh` 直接失敗——這是**好事**，是 fail-closed（承 Day105 freeze 防禦）。
- **回滾下限**：如果磁碟上原本就有一份更新的 trusted metadata（例如上一次搬進來的），這次讀進來的舊 timestamp 版本較低，`UpdateTimestamp` 回 `ErrBadVersionNumber` 拒收。**本地持久化的那份仍是 rollback 的地板（承 Day105）。**
- **綁定鏈**：snapshot 的雜湊／版本仍被 timestamp 釘、targets 仍被 snapshot 釘。mix-and-match 在離線模式一樣被綁定鏈擋。

### 交出了什麼（DEVIATION，5.3～5.7 的偏離）

- **沒有 root 輪替**：`onlineRefresh` 會 `loadRoot()` 逐版把 remote 的新 root 補上（Day101 的金鑰折損復原就靠這條）。`unsafeLocalRefresh` **完全不做**——root 永遠是你當初塞進 `LocalTrustedRoot` 的那份。**這是最致命的一條：root 金鑰在遠端已經因折損而輪替了，你的氣隙機器毫不知情，還在信任那把被偷的舊 root。**
- **沒有 liveness／活性**：線上模式的靈魂是「去 remote 問有沒有更新的」。離線模式**永遠不問**，因此它給你的最強保證只有「這份沒過期、沒被竄改、不比我手上的舊」——但它**無法保證這份是遠端最新的**。你可能拿著一份「合法、沒過期、但其實是三週前」的 metadata 在跑，離線模式一句話都不會抱怨。
- **沒有前綴檔名的意義**：Day106 的 consistent snapshot 是為了「發佈中途來抓不撕裂」，那是線上並發問題。離線只讀固定路徑的 `timestamp.json`／`snapshot.json`／`targets.json`（`loadLocalMetadata` 讀的是不帶前綴的固定檔名），前綴機制在這裡不參與。

用一句話總結這個信任降級：**離線更新保住了「不會被塞假貨、不會被塞過期、不會被塞更舊」，但放棄了「一定拿到最新」與「root 折損能自動修復」。**


## 三、freeze 防線在氣隙環境會反過來咬你

這是本篇最重要的維運洞見，也是預告點名的核心。

回想 Day105：**timestamp 故意設短效期（幾小時到幾天），是為了把 freeze 攻擊的窗口壓小**——攻擊者就算能一直餵你同一份舊 timestamp，你也會因為它「過期」而拒收，於是 freeze 撐不了多久。對**線上** client，這完全沒代價：它每隔幾分鐘就 `downloadMetadata` 抓一份新的、效期又刷新，短效期只是背景噪音。

但把同一套規則搬到**氣隙**環境，短效期的意義整個翻轉：

- 你在 `T` 時刻把一包 metadata 拷進隨身碟，此刻 timestamp 剩餘效期假設是 `E`（例如 remote 端 timestamp 設 7 天效期、你拷的時候它已經簽發 2 天了，`E ≈ 5 天`）。
- 隨身碟搬到氣隙機器，`unsafeLocalRefresh` 讀它——**只要還在 `E` 內就正常，一旦超過 `E`，`IsExpired` 為真，refresh 直接失敗。**
- 於是**離線包的可用壽命 = 搬進去那一刻 timestamp 的剩餘效期 `E`**，而不是你以為的「metadata 內容沒變就一直能用」。

**這就是 freeze 防線放大成的維運陷阱：** timestamp 效期越短（對線上越安全），氣隙機器就越快「過期斷更」。如果 remote 端把 timestamp 效期壓到 6 小時（Sigstore 這類高頻服務常見），那你的隨身碟從產出到插進氣隙機器，中間留給你的搬運窗口可能只剩幾小時——搬慢了，機器就用一份「過期但沒被竄改」的 metadata 卡住，`Refresh()` 直接 error。

**正確的維運姿態**是把它當成一個明確的「離線包鮮度 SLA」：

1. **搬運流程要在 timestamp 效期內完成**，而且要留緩衝——不是「產出後 5 天內搬到」，而是要監控「離線包產出時 timestamp 的剩餘效期」，若小於「搬運＋人工作業所需時間 ×安全係數」就不該發車。
2. **接受方要監控「這台氣隙機器上的 timestamp 還剩多久過期」**，過期前就要有下一包進場——這正是 Day101／Day102 講的「refresh 成功也要記指標、N 小時未成功告警」的離線版：對氣隙機器，指標不是「refresh 失敗率」，而是「當前 trusted timestamp 的剩餘效期」。
3. **如果你是離線包的發行端**，可以為氣隙通道**簽發一條效期較長的 timestamp**（例如專門的 mirror／offline profile），在「freeze 窗口」與「搬運頻率」之間做取捨——但要清楚這是拿「更長的 freeze 可容忍窗口」換「更低的搬運頻率」，是一個安全參數的明確調鬆，要進威脅模型評估，不是隨手拉長。


## 四、氣隙搬運本身的 rollback／freeze 風險

離線模式的驗證雖然保留了回滾下限，但**「下限」是相對於機器本地那份 trusted metadata 而言的**。氣隙環境有兩個特有的破口：

### 破口一：全新／被清空的機器沒有下限

`UpdateTimestamp` 拒收舊版本，靠的是「機器上已經有一份更新的」。但一台**剛裝好、或快取被清掉重來**的氣隙機器，`LocalMetadataDir` 是空的——它沒有下限。這時候誰控制隨身碟，誰就決定它的起點：

- 攻擊者（或一個被拖延的內部流程）遞給它一包「合法簽章、還沒過期、但其實是三週前、對應某個已知有漏洞版本」的 metadata。
- 離線模式驗簽過、驗過期過（還沒過期）、沒有更舊的可比——**全部通過**。機器就以這個舊狀態當起點，把有漏洞的版本當「最新」裝下去。

這是一個「**在過期窗口內的 rollback／freeze**」：不需要偷任何金鑰，只需要控制「哪一包被搬進去」，並趕在它過期前送達。線上 client 靠「去問 remote 拿到真正最新」自然免疫；氣隙機器**沒有這個對照源**，唯一的防線只剩「過期」——而攻擊者只要用「還沒過期的舊包」就繞過了。

**緩解**：氣隙機器的 `LocalMetadataDir` 要當成有狀態的信任錨——**別隨意清空、別重裝就從零開始**；bootstrap 一台新氣隙機器時，起始的 metadata 包要走**與日常搬運不同的、更高保證的管道**（人員雙簽、留證、對照 root 指紋），比照 Day101／Day102 的 TOFU 開機儀式，而不是「隨手一包」。

### 破口二：root 折損無法傳達

第二節說過離線模式不做 root 輪替。把它接到威脅模型：

- 遠端因為 timestamp／snapshot 線上金鑰折損，走 Day101 的流程用 root 簽了新版、換掉了被偷的金鑰；甚至 root 自己折損，門檻內其他 keyholder 簽了新 root 踢掉被偷的。
- **線上** client 下次 `loadRoot()` 就把新 root 補上、被偷的金鑰失效。
- **氣隙**機器的 `unsafeLocalRefresh` 對 root 一個字都不讀——它繼續信任舊 root，也就繼續信任那把已經被踢掉的、被偷的金鑰。攻擊者若拿被偷的金鑰簽一包「合法、沒過期」的 metadata 遞進去，氣隙機器照收。

**緩解**：**root 更新在氣隙環境必須是一條獨立的、人工的、帶外的流程。** 你不能靠日常那條「搬 timestamp／snapshot／targets」的隨身碟通道去更新 root——因為離線模式根本不從那些檔案更新 root。要更新氣隙機器的信任根，等於重新做一次 bootstrap：拿新 root、比對指紋、以新的 `LocalTrustedRoot` 重建 `Updater`。把「root 折損時，氣隙機群怎麼重新下發 root」寫進 runbook，是這類部署的必備條款——否則你的復原機制對氣隙那半根本沒生效。


## 五、Go：氣隙 client 的骨架與該有的護欄

離線模式的 client 端其實很短——重點不在程式碼多，而在**你自己補上的鮮度與 root 護欄**：

```go
import (
	"os"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

func newAirgapUpdater(rootBytes []byte, metaDir, targetDir string) (*updater.Updater, error) {
	cfg, err := config.New("", rootBytes) // remoteURL 給空字串：離線根本不連
	if err != nil {
		return nil, err
	}
	cfg.LocalMetadataDir = metaDir   // 隨身碟解出來、放到本機的 metadata 目錄
	cfg.LocalTargetsDir = targetDir
	cfg.UnsafeLocalMode = true       // ★ 關鍵開關：Refresh() 只讀本地、不碰網路

	up, err := updater.New(cfg)      // New() 內部把 rootBytes 當 LocalTrustedRoot 載入
	if err != nil {
		return nil, err
	}
	return up, nil
}

func airgapRefresh(up *updater.Updater) error {
	// Refresh() → 因 UnsafeLocalMode=true → 走 unsafeLocalRefresh()
	// 只讀 metaDir 下的 timestamp/snapshot/targets.json，全程驗簽＋版本＋過期
	if err := up.Refresh(); err != nil {
		// 這裡的失敗多半是「離線包過期了」或「被竄改／版本回滾」
		// 一定要當成硬失敗告警，別靜默吞掉繼續用舊 target
		return err
	}
	return nil
}
```

**離線模式下，你要自己補的三道護欄**（go-tuf 不會替你做，因為它刻意只做「讀本地＋驗」）：

```go
// 護欄一：離線包鮮度——主動盯 timestamp 剩餘效期，別等 Refresh() 過期才發現
func warnIfStale(up *updater.Updater, minRemaining time.Duration) {
	tm := up.GetTrustedMetadataSet()
	exp := tm.Timestamp.Signed.Expires        // 這份離線包的過期時間
	remaining := time.Until(exp)
	if remaining < minRemaining {
		// 承 Day16：這是「該換離線包了」的營運告警，不是攻擊告警
		alert("airgap-tuf-timestamp-staleness",
			"remaining", remaining, "expires", exp)
	}
}

// 護欄二：root 指紋——每次啟動記錄手上 root 的 sha256，
// 與帶外公告的「當前有效 root 指紋」對照；不符＝可能錯過 root 輪替
func assertRootFingerprint(rootBytes []byte, expectedSHA256 string) error {
	got := sha256Hex(rootBytes)
	if got != expectedSHA256 {
		return fmt.Errorf("airgap root fingerprint mismatch: got %s want %s (可能有 root 輪替未傳達)", got, expectedSHA256)
	}
	return nil
}

// 護欄三：本地 metadata 目錄權限與持久性（承 Day105/106）
// LocalMetadataDir 是這台氣隙機器唯一的 rollback 下限，
// 權限 0700、別讓非特權程序寫、別在部署腳本裡「清乾淨再來」
```

**注意 `RefTime` 與時鐘**：離線模式的過期檢查全靠機器本地時鐘（`RefTime` 預設 `time.Now()`）。氣隙機器**最容易出問題的就是時鐘**——沒有網路常常也沒有 NTP。時鐘若被往回撥（或電池沒電回到出廠時間），`IsExpired` 可能恆為假，freeze 防線與過期護欄一起失效（承 Day105「freeze 的隱性前提是時鐘可信」）。氣隙環境要嘛有可信的本地時間源（GPS／內網 authenticated NTP／硬體 RTC 加監控），要嘛把「時鐘偏移」納入這台機器的健康檢查。`go-tuf` 有 `UnsafeSetRefTime` 但**那是測試用**，別在生產拿它硬設時間繞過過期——那等於自己拆掉 freeze 防線。


## 六、JVM：sigstore-java 沒有等價開關，該怎麼落地

誠實講：**`UnsafeLocalMode` 是 go-tuf 特有的 config 欄位，`sigstore-java` 的 `dev.sigstore.tuf.Updater` 並沒有一個名字對得上的「離線模式」開關**（本系列一貫用 context7 核對套件與函式是否真的存在，這裡就不杜撰一個 `setUnsafeLocalMode()` 之類的 API）。JVM 側要達到「氣隙、只讀本地」的效果，靠的是**組態拓撲而不是一個開關**：

- **把 remote 指向本地 mirror**：`sigstore-java` 的 Updater 走 `MetaFetcher`／`TrustedMetaStore`（本地 metadata 存放）＋一個指向 metadata URL 的來源。氣隙做法是把「遠端 URL」換成一個**本機的、由隨身碟同步過來的 file/HTTP mirror**——Updater 以為自己在「線上」抓，其實抓的是搬進來的離線包。這條路的好處是**它仍然會做 root 輪替**（因為它把 mirror 當 remote 在跑 5.3～5.7 完整流程），代價是你要維護一個本機 mirror 目錄、且鮮度一樣受 timestamp 效期限制。
- **這其實比 go-tuf 的 `UnsafeLocalMode` 更「安全」一點**：因為它沒有偏離 5.3～5.7，root 輪替、逐版補鏈都還在——你只是把「網路」換成「一個受控的本機檔案來源」。缺點是你得自己保證那個 mirror 目錄的內容就是離線包、且原子替換（temp＋rename，承 Day106），別讓 Updater 讀到搬到一半的 mirror。
- **Java 1.8**：`sigstore-java` 需 JDK 11+，氣隙的 1.8 服務照 Day80／101 的老辦法——把 TUF 驗證挪成獨立 sidecar／前置工具，產出「已驗證的 target」再交給 1.8 主程序，別在 1.8 裡硬塞。

一句話對照：**go-tuf 給你一個「明確標記為 unsafe、真的一步都不上網」的離線開關；sigstore-java 沒有這個開關，你用「把 remote 換成本機 mirror」達到同樣的離線效果，順帶保住了 root 輪替——選哪條，取決於你要不要 root 折損能透過『換 mirror 內容』傳達，還是接受氣隙 root 必須人工帶外更新。**


## 七、常見誤區

- **「離線模式（`UnsafeLocalMode`）不驗簽，反正沒網路。」** 錯得最離譜。它砍的是「下載」不是「驗證」——timestamp／snapshot／targets 照樣用 root 授權的公鑰驗簽、驗版本、驗過期。函式名字裡的 unsafe 指的是「偏離 5.3～5.7 的完整流程（尤其不做 root 輪替、不保證最新）」，不是「不做密碼學驗證」。
- **「離線包內容沒改，就能一直用。」** 錯。可用壽命是 timestamp 的**剩餘效期**，不是內容有沒有變。過期了 `Refresh()` 直接失敗——這是 freeze 防禦在起作用，不是 bug。
- **「timestamp 效期設短一點比較安全，氣隙也一樣。」** 對線上對，對氣隙是把自己的搬運窗口壓小。氣隙要在「freeze 可容忍窗口」與「搬運頻率」之間做**明確取捨**，可能要為離線通道簽發較長效期的 timestamp，並把它當安全參數評估。
- **「氣隙機器裝好一次就好，metadata 之後自己更新。」** 錯。離線模式沒有 liveness，它永遠不會主動變新。你不搬新包，它就一路用舊的直到過期斷更。
- **「root 折損時，把新 metadata 搬進去就修好了。」** 錯。`unsafeLocalRefresh` **不從搬進去的檔案更新 root**。root 折損的復原在氣隙環境必須是獨立、人工、帶外的重新 bootstrap（換 `LocalTrustedRoot`、比對指紋），寫進 runbook。
- **「重裝氣隙機器、清掉快取重來比較乾淨。」** 危險。`LocalMetadataDir` 是這台機器唯一的 rollback 下限，清掉＝失去下限＝任何「合法、沒過期的舊包」都能當起點灌進來。重裝要走高保證的 bootstrap 通道。
- **「氣隙沒網路，時鐘不重要。」** 反了。離線模式的過期／回滾防禦全靠本地時鐘，氣隙又常沒 NTP——時鐘被回撥或跑掉，freeze 防線直接失效。時鐘可信是氣隙 TUF 的隱性前提。
- **「sigstore-java 也有 `UnsafeLocalMode`。」** 沒有。那是 go-tuf 特有欄位。JVM 側用「remote 指向本機 mirror」達到離線效果，且順帶保留 root 輪替。


## 八、Code Review／設計 checklist（離線／氣隙 TUF）

- **確認離線是刻意選的**：`UnsafeLocalMode=true`（或 JVM 的「remote 指向本機 mirror」）是明確的架構決定，且理解它偏離 5.3～5.7、不做 root 輪替、不保證最新（第一、二節）。
- **`Refresh()` 失敗必為硬失敗**：離線 refresh 失敗（多半是過期或回滾）要告警並拒絕繼續用舊 target，不得靜默吞掉（第五節）。
- **離線包鮮度監控**：主動盯當前 trusted timestamp 的剩餘效期，過期前告警換包；發行端監控「產出時剩餘效期是否夠搬運」（第三、五節）。
- **root 更新走帶外流程**：root 折損／輪替時，氣隙機群的 root 更新是獨立人工流程（換 `LocalTrustedRoot`＋比對指紋），已寫進 runbook（第四、五節）。
- **本地 metadata 目錄是有狀態信任錨**：`LocalMetadataDir` 權限 0700、不隨意清空、不「重裝從零」；新機 bootstrap 走高保證通道（第四節，承 Day105/106）。
- **時鐘可信**：氣隙機器有可信時間源或時鐘偏移監控，別用 `UnsafeSetRefTime` 在生產繞過過期（第五節，承 Day105）。
- **mirror 原子替換（JVM 或自建 mirror）**：本機 mirror 目錄的更新走 temp＋rename，別讓 Updater 讀到搬到一半的 mirror（第六節，承 Day106）。
- **版本衛生**：TUF client 釘含修補的維護版、`govulncheck`／SBOM 當紅線（承 Day104／18）。


## 九、測試怎麼做

離線／氣隙這層的測試核心是**「斷網後仍驗、過期即拒、回滾即拒、root 不會被離線包偷換」**：

- **離線 refresh 仍驗簽（存在證明）**：`UnsafeLocalMode=true`、把本地 `timestamp.json` 竄改一個位元組，斷言 `Refresh()` 失敗——證明離線不等於不驗簽（第二節）。
- **過期即拒（freeze 防禦存在證明）**：把本地離線包的 timestamp 設成已過期（或 `UnsafeSetRefTime` 往後撥到過期後），斷言 `Refresh()` 回過期錯誤而非放行——這是氣隙鮮度護欄的真實姿態（第三節）。
- **回滾即拒（下限存在證明）**：機器上先有 v42 的 trusted metadata，餵一包 v41 的離線包，斷言 `UpdateTimestamp` 回 `ErrBadVersionNumber`、機器保留 v42（第四節）。
- **空機無下限的風險迴歸**：清空 `LocalMetadataDir`，餵一包「合法、沒過期、但版本低」的離線包，斷言它**會被接受**（這是預期行為）——用這個測試把「空機沒有下限」這個風險釘成明確的已知事實，逼 bootstrap 走高保證通道（第四節）。
- **root 不隨離線包更新**：在離線包裡放一份「版本更高、簽章合法」的 `root.json`，斷言 `unsafeLocalRefresh` **不會**採用它（root 停在 `LocalTrustedRoot`）——證明 root 折損復原無法靠日常隨身碟通道傳達（第二、四節）。
- **時鐘回撥模擬**：把 `RefTime` 往回撥到離線包簽發之前，斷言過期／回滾判斷的行為，驗證「時鐘不可信＝防線失效」這個前提（第五節，承 Day105）。
- **鮮度告警觸發**：把剩餘效期設在門檻以下，斷言 `warnIfStale` 觸發營運告警（第五節）。
- **JVM mirror 原子性**：模擬 mirror 目錄更新到一半（temp 檔存在未 rename），斷言 Updater 讀到的是完整的舊 mirror 而非半成品（第六節，承 Day106）。


## 十、一句話總結

> Day106 把「線上」擷取的原子性收完（consistent snapshot 讓發佈中途來抓也不撕裂）；今天把網路整條拿掉——go-tuf 的 `UnsafeLocalMode` 讓 `Refresh()` 走 `unsafeLocalRefresh`，**只讀磁碟上的 `timestamp`／`snapshot`／`targets`、一步都不上網**，但它砍的是「下載」不是「驗證」：簽章、版本單調、過期、綁定鏈全部保留（都還是 Day105 那三個 `Update*` 函式），刻意偏離的是 5.3～5.7 裡「去 remote 補新版」與「root 輪替」那半——所以離線模式是一次明確的**信任降級**：保住「不被塞假貨、不被塞過期、不被塞更舊」，交出「一定拿到最新」與「root 折損自動修復」。這個交出的活性把 Day105 的 freeze 防線放大成一個維運計時器：**離線包的可用壽命＝搬進去那一刻 timestamp 的剩餘效期**，timestamp 效期越短（對線上越安全）氣隙就越快斷更，逼你把「搬運窗口」當成有 SLA 的鮮度問題來管。氣隙特有的兩個破口——**空機／被清空的機器沒有 rollback 下限**（任何合法未過期的舊包都能當起點），與**root 折損無法透過日常隨身碟通道傳達**（`unsafeLocalRefresh` 根本不更新 root）——都不需要偷金鑰，只需要控制「哪一包被搬進去、趕在過期前送達」。後端工程師的可執行結論：**離線是刻意選的架構決定，選了就要自己補三道 go-tuf 不做的護欄——盯 timestamp 剩餘效期（鮮度 SLA）、root 更新走帶外人工流程（別靠隨身碟）、本地 metadata 目錄當有狀態信任錨（別清空、別重裝從零、時鐘要可信）；JVM 沒有等價開關，用『remote 指向本機 mirror』達到離線效果並順帶保住 root 輪替。**


## 延伸閱讀

- **Day105 rollback／freeze／mix-and-match 防禦**——今天的直接理論底座。離線模式保留的那套版本／過期／綁定檢查，就是 Day105 的 `UpdateTimestamp`／`UpdateSnapshot`／`UpdateDelegatedTargets`；freeze 防線的「短效 timestamp」在今天被放大成氣隙鮮度計時器。
- **Day106 consistent snapshot**——今天的直接上游。昨天講「線上發佈中途來抓怎麼不撕裂」，今天把網路拿掉問「不連網時只靠磁碟能更新到什麼程度」；線上原子性與離線信任降級是同一套機制的兩端。
- **Day101 TUF root 輪替**——離線模式最致命的偏離就是不做 root 輪替。Day101 的金鑰折損復原（root 簽新版換 keyids）在氣隙環境無法自動生效，必須帶外重新 bootstrap。
- **Day102 私有 root signing 儀式／TOFU 開機**——氣隙機器的起始 metadata 包與 root 更新，都該比照 Day102 的高保證儀式（帶外、留證、比對指紋），而不是日常隨身碟。
- **Day80／Day81 SPIFFE sidecar**——Java 1.8 跑不動 sigstore-java 時，把 TUF 驗證挪成獨立 sidecar／前置工具的老辦法。

---

明天預告：**Day 108 — 離線模式靠「版本單調遞增」擋 rollback，但如果攻擊者不回滾、反而把版本號往「未來」灌呢？TUF fast-forward attack（快轉攻擊）與復原——當 timestamp／snapshot 線上金鑰被偷，攻擊者不改任何內容，只把版本號簽成天文數字（例如 2³²），害你的回滾防禦反過來把日後所有合法的低版本當成 rollback 拒收，等於用你自己的防線把你永久凍結在被偷的那一刻；示範 go-tuf 的版本上限與 `MaxRootRotations`／`MaxDelegations` 當 DoS 護欄、被快轉後 repo 端要怎麼跳版復原、以及為什麼「短效期＋逐版補鏈」在這裡同時是解藥也是陷阱**
（這是**延伸／接續**，把視角從今天的「版本太舊被擋」翻到「版本被灌太新反被自己的 rollback 防禦鎖死」。fast-forward attack 這個攻擊面在本系列是**首次介紹**，明確不重述 Day105 的版本單調機制本身與今天的離線流程，聚焦**快轉攻擊的成因、回滾防禦的反噬、與 repo 端的復原策略**。情境：一個被偷的 timestamp 金鑰把版本號從 43 簽成 4294967295，示範 client 端 `MaxRootRotations` 為何能同時擋 root 快轉的 DoS、以及 repo 端「跳到攻擊版本之上重新發佈」的復原動線。標為延伸篇。）
