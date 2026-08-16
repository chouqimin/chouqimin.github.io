---
title: "Day 105：委派找對角色了，但你手上那份 metadata「新不新、對不對版」誰保證？——TUF 消費端 rollback／freeze／mix-and-match 防禦，go-tuf `trustedmetadata` 的版本單調遞增＋過期檢查＋meta 綁定"
date: 2026-08-17
tags: ["TUF", "rollback攻擊", "供應鏈安全", "版本回滾"]
---

接續 Day104 預告：昨天把委派的**消費端解析**收完了——`preOrderDepthFirstWalk` 對一個 target 路徑做前序深度優先遍歷，「按出現順序找、每跳驗簽、命中截斷就收手、超出授權路徑一律不採信」，把委派切好的爆炸半徑在 client 端兌現。那是**橫向**的問題：在一棵委派樹上「找對角色」。今天翻到**縱向**的問題：**你找對了角色、驗過了簽名，但你手上那份 `timestamp` / `snapshot` / `targets` 到底是不是 repo 目前最新、彼此對不對得起來的版本？** 一個站在中間人或惡意鏡像位置的攻擊者，可以完全不偷任何金鑰、拿一份**簽名 100% 合法、只是版本較舊**的 metadata 回放給你，讓你錯過一個「修掉已知漏洞」的成品更新——這就是 **rollback（回滾）攻擊**。

**這篇是延伸／接續，不是重新介紹 TUF。** 明確不重述 Day104 的委派遍歷（`preOrderDepthFirstWalk`、順序即信任、路徑逃逸），也不重述 Day101 的頂層四角色 threshold 驗證與 root 輪替機制。今天只聚焦一件事：**消費端的「trusted metadata set」更新規則——client 手上這份 root/timestamp/snapshot/targets 怎麼靠「版本單調遞增＋過期檢查＋上層 meta 綁定」擋下三種只玩「版本與時間」的攻擊：rollback（回滾到舊版本）、freeze（凍結在舊版本）、mix-and-match（把不同 repo 狀態的 metadata 拼在一起）。** 這三個攻擊面在本系列是**首次介紹**。

安全主軸先講在前面：**委派解決的是「找對角色」，trusted metadata set 解決的是「拿對版本」。攻擊者就算一把金鑰都沒偷到，只要能讓你採信一份「合法但過時」或「合法但拼裝」的 metadata，就能讓你錯過安全更新、或下載到不該搭在一起的成品。防線不是簽名——簽名它都通過——而是版本必須單調遞增、metadata 必須沒過期、下層必須被上層的版本與雜湊釘死。**

> 本文的 Go 範例對照 `github.com/theupdateframework/go-tuf/v2` 的 `master` 原始碼：`metadata/trustedmetadata/trustedmetadata.go` 的 `UpdateRoot` / `UpdateTimestamp` / `UpdateSnapshot` / `UpdateTargets` / `UpdateDelegatedTargets` / `checkFinalTimestamp` / `checkFinalSnapshot`，函式、欄位與錯誤型別（`ErrBadVersionNumber` / `ErrEqualVersionNumber` / `ErrExpiredMetadata`）皆為實際存在的呼叫，非杜撰。go-tuf/v2 為維護中版本（go.mod 目前為 Go 1.25），CVE-2024-47534（Day104）已於 `>v2.0.0` 修復，實務請釘在含修補的維護版（例如 v2.3.1 或更新）。


## 一、三種只玩「版本與時間」的攻擊

先把三個攻擊講清楚，它們的共同特徵是：**攻擊者不需要任何有效金鑰、不需要偽造任何簽名**。他要的只是一個能改動「你收到哪份 metadata」的位置——中間人、被攻陷的 CDN／鏡像、或一個惡意的內部快取。

- **Rollback（回滾）**：攻擊者把一份**舊的、但當年簽名合法**的 metadata 回放給你。例如：昨天 repo 發了 `snapshot` v42，把一個修掉 RCE 的新版 `order-service.jar` 標了進去；攻擊者攔住你的請求，改回吐 v41 給你——v41 的簽名完全有效，只是它還指向那個有漏洞的舊 jar。你若採信 v41，就**永遠拿不到那個安全更新**。這是供應鏈裡最陰險的一種：什麼都沒被竄改，只是「時間被倒轉」。

- **Freeze（凍結）**：rollback 的極端版。攻擊者不需要回放「更舊」的，只要**一直吐同一份舊 metadata**，把你凍結在某個時間點，讓你永遠看不到任何後續更新。差別在於：rollback 是「往回」，freeze 是「原地卡住」。

- **Mix-and-match（拼裝）**：攻擊者把**不同 repo 狀態、各自簽名都合法**的 metadata 拼在一起餵給你。例如給你 `timestamp` 是今天的、`snapshot` 是三週前的、某個 `targets` 又是上週的——每一份單獨看簽名都對，但它們**從來沒有在同一個 repo 狀態下被一起發佈過**。這樣攻擊者可以「挑」出一個對他有利的組合：新到不會過期、舊到還含漏洞成品。

TUF 的 trusted metadata set 就是專門把這三個一起擋下的機制。關鍵在於：**簽名驗證（Day101）只證明「這份 metadata 是 repo 簽的」，它證明不了「這份是不是最新的、是不是跟其他份對得起來的」。** 後者要靠版本與時間的規則。


## 二、trusted metadata set：client 手上那份「可信狀態」

go-tuf 把 client 目前信任的一整組 metadata 收在一個 struct 裡——`TrustedMetadata`。它就是「你手上這份可信 repo 狀態」的具體形態：

```go
// metadata/trustedmetadata/trustedmetadata.go
type TrustedMetadata struct {
	Root      *metadata.Metadata[metadata.RootType]
	Snapshot  *metadata.Metadata[metadata.SnapshotType]
	Timestamp *metadata.Metadata[metadata.TimestampType]
	Targets   map[string]*metadata.Metadata[metadata.TargetsType] // 頂層 targets 與各委派角色
	RefTime   time.Time // 判斷「過期」用的參考時間(見第五節 freeze)
}
```

client 更新流程是**固定順序**的一條鏈——`root(N) → timestamp → snapshot → targets → 委派 targets`——而 `TrustedMetadata` 用「狀態機」硬性擋住亂序：

```go
// 這些防呆不是型別花招,而是「更新規則」的一部分:
func (t *TrustedMetadata) UpdateTimestamp(...) {
	if t.Snapshot != nil {   // 已經有 snapshot 了還想更新 timestamp?
		return nil, &metadata.ErrRuntime{Msg: "cannot update timestamp after snapshot"}
	}
	...
}
func (t *TrustedMetadata) UpdateSnapshot(...) {
	if t.Timestamp == nil {  // 還沒 timestamp 就想更新 snapshot?
		return nil, &metadata.ErrRuntime{Msg: "cannot update snapshot before timestamp"}
	}
	if t.Targets[metadata.TARGETS] != nil {
		return nil, &metadata.ErrRuntime{Msg: "cannot update snapshot after targets"}
	}
	...
}
```

為什麼順序重要？因為**上層 metadata 是下層的「防回滾錨點」**：`timestamp` 記著 `snapshot` 該是哪個版本、哪個雜湊；`snapshot` 記著每個 `targets` 該是哪個版本、哪個雜湊。你必須「先拿到並驗過上層，才能用它去核下層」。順序錯了，錨點就不在手上，rollback／mix-and-match 就有縫。

接下來三節，一個攻擊一節，直接對照原始碼看 go-tuf 怎麼擋。


## 三、Rollback 防禦：版本只能往上，不能往下

rollback 的解藥是一句話：**任何 metadata 的版本號都必須單調遞增，拿舊版本蓋新版本一律拒絕。** go-tuf 在每一層都埋了這個檢查。

### 3-1 root：嚴格 +1，一版都不能跳

```go
// UpdateRoot
if newRoot.Signed.Version != trusted.Root.Signed.Version+1 {
	return nil, &metadata.ErrBadVersionNumber{
		Msg: fmt.Sprintf("bad version number, expected %d, got %d",
			trusted.Root.Signed.Version+1, newRoot.Signed.Version)}
}
```

root 不只是「不能回滾」，而是**必須剛好 +1**——你不能從 v3 直接跳到 v7。這強迫 client 把 v4、v5、v6 逐份驗過（每一份都要被前一份簽名背書），攻擊者無法用「藏掉中間某一版」的方式偷渡一次金鑰輪替。這條就是 Day101 root 輪替的另一半，今天不展開，只定位它也是 rollback 家族的一員。

### 3-2 timestamp：舊版直接拒，同版特別處理

```go
// UpdateTimestamp,當已有一份 trusted timestamp 時:
if trusted.Timestamp != nil {
	// 防止 timestamp 版本回滾
	if newTimestamp.Signed.Version < trusted.Timestamp.Signed.Version {
		return nil, &metadata.ErrBadVersionNumber{
			Msg: fmt.Sprintf("new timestamp version %d must be >= %d",
				newTimestamp.Signed.Version, trusted.Timestamp.Signed.Version)}
	}
	// 版本相等:保留舊的,回一個「相等」的特定錯誤
	if newTimestamp.Signed.Version == trusted.Timestamp.Signed.Version {
		return nil, &metadata.ErrEqualVersionNumber{...}
	}
	// 連「timestamp 指向的 snapshot 版本」也不能倒退
	snapshotMeta := trusted.Timestamp.Signed.Meta["snapshot.json"]
	newSnapshotMeta := newTimestamp.Signed.Meta["snapshot.json"]
	if newSnapshotMeta.Version < snapshotMeta.Version {
		return nil, &metadata.ErrBadVersionNumber{
			Msg: fmt.Sprintf("new snapshot version %d must be >= %d",
				newSnapshotMeta.Version, snapshotMeta.Version)}
	}
}
```

三個細節後端要看懂：

- **`<` 直接拒（`ErrBadVersionNumber`）**：這就是 rollback 的核心攔截。攻擊者回放 timestamp v41、你手上已是 v42 → 擋下。
- **`==` 是獨立的 `ErrEqualVersionNumber`**：版本相同不是錯，是「沒有新東西」——保留舊的即可。把「相等」跟「回滾」分成兩個錯誤型別，是為了讓上層 updater 能對「沒更新」與「被攻擊」做不同處理（沒更新是正常，回滾要警戒）。
- **連「指標」都防回滾**：`timestamp` 裡記著 `snapshot.json` 該是哪個版本。就算攻擊者給你一份**版本更高的 timestamp**，但把裡面指向的 snapshot 版本偷偷改小，這行也擋下——**rollback 防禦不只看 metadata 自己的版本，還看它「指向下層的那個版本號」**。

### 3-3 snapshot：逐一比對，且「不准刪東西」

```go
// UpdateSnapshot,當已有一份 trusted snapshot 時:
if trusted.Snapshot != nil {
	for name, info := range trusted.Snapshot.Signed.Meta {
		newFileInfo, ok := newSnapshot.Signed.Meta[name]
		// 不准移除任何一份 metadata 的記錄
		if !ok {
			return nil, &metadata.ErrRepository{Msg: fmt.Sprintf("new snapshot is missing info for %s", name)}
		}
		// 不准回滾任何一份 targets metadata 的版本
		if newFileInfo.Version < info.Version {
			return nil, &metadata.ErrBadVersionNumber{...}
		}
	}
}
```

`snapshot` 是「所有 targets／委派角色版本號的總表」。這裡兩道檢查：**不准刪**（舊 snapshot 有記錄的角色，新 snapshot 不能憑空少掉——否則攻擊者可以「讓某個角色消失」來繞過它的版本防護）＋**逐角色不准回滾**（每個 targets 角色的版本都只能往上）。這樣即使攻擊者只想針對「某一個委派角色」做 rollback，也會在這關被逐一擋下。


## 四、「intermediate metadata」：為什麼過期的舊版還要留著

這是 rollback 防禦裡最容易被誤解、卻最精妙的一點，值得單獨一節。

看 `UpdateTimestamp` / `UpdateSnapshot` 的註解，它們都說：**「即使是過期的 intermediate（中間）metadata 也允許被載入」**。乍看很反直覺——過期的東西不是該拒嗎？

關鍵在於 rollback 防禦的**下限（floor）是誰**。防回滾靠的是「新版本必須 >= 我目前手上這份的版本」。那「我目前手上這份」如果過期了，該丟掉嗎？**不能丟。** 因為一旦丟掉，你的版本下限就掉回「沒有下限」，攻擊者就能拿一份「比你剛丟掉那份更舊、但還沒過期」的 metadata 塞給你——rollback 又成立了。

所以 go-tuf 的設計是：

- **過期的 timestamp／snapshot 仍然「載入」，但只當作「防回滾的版本下限」用**——它不會被當成有效的「最終」metadata 拿去下載成品。
- **「有沒有過期」的把關，放在 `checkFinalTimestamp` / `checkFinalSnapshot`**——只有當一份 metadata 要被當成「這輪更新的最終結果」時，才檢查它過期沒。

用白話講：**舊版 metadata 過期了，它「不能再拿來辦事」，但它「還記得版本號」，這個記憶就是擋 rollback 的地基。你可以載入一份過期的舊 timestamp 當下限，然後要求下一份新 timestamp 版本更高——新的那份如果也過期，就在 `checkFinalTimestamp` 被擋（見下一節 freeze）；如果沒過期，就順利接上。** 這就是為什麼原始碼要把「載入」跟「當最終版驗過期」拆成兩步。


## 五、Freeze 防禦：過期即拒，攻擊者凍不住

freeze 的解藥是**過期檢查**。TUF 的每一份 metadata 都有 `expires` 欄位，`timestamp` 通常設得很短（例如一天），這是刻意的——**它是整條鏈裡「時效最緊」的一環，逼 client 頻繁回源、逼攻擊者的「凍結」有保鮮期上限。**

```go
// checkFinalTimestamp:timestamp 一旦要被當「最終版」用,就查過期
func (trusted *TrustedMetadata) checkFinalTimestamp() error {
	if trusted.Timestamp.Signed.IsExpired(trusted.RefTime) {
		return &metadata.ErrExpiredMetadata{Msg: "timestamp.json is expired"}
	}
	return nil
}

// checkFinalSnapshot:過期 + 版本要對得上 timestamp 記的版本(見第六節)
func (trusted *TrustedMetadata) checkFinalSnapshot() error {
	if trusted.Snapshot.Signed.IsExpired(trusted.RefTime) {
		return &metadata.ErrExpiredMetadata{Msg: "snapshot.json is expired"}
	}
	...
}
```

還有 root 那層——`UpdateTimestamp` 一開頭就先擋「最終 root 過期」：

```go
// client workflow 5.3.10: 確保最終 root 沒過期
if trusted.Root.Signed.IsExpired(trusted.RefTime) {
	return nil, &metadata.ErrExpiredMetadata{Msg: "final root.json is expired"}
}
```

freeze 攻擊的極限就被 `expires` 框住了：**攻擊者可以吐同一份舊 timestamp，但一旦它過了 `expires`，`checkFinalTimestamp` 就回 `ErrExpiredMetadata`，client 拒絕拿它去載入 snapshot——攻擊者無法把你凍結超過 timestamp 的有效期。** 這就是為什麼 repo 端「timestamp 有效期要短」是一個**安全參數**，不是效能參數：它直接決定 freeze 攻擊的最長有效窗口。

這裡藏著一個**只有這篇會講、Day104 不會有的後端落地陷阱**：

> **freeze 防禦 = 過期檢查 = 完全依賴 `RefTime`（client 的時鐘）。** 如果攻擊者能同時控制你的**系統時鐘**（例如透過 NTP 中間人把時間往回撥），他就能讓 `IsExpired` 永遠回 false，把過期的 metadata 變成「看起來沒過期」——freeze 防禦就被繞過了。

所以後端部署 TUF client 時，**時鐘可信度是 freeze 防禦的隱性前提**：用受信任、經過驗證的時間源（authenticated NTP / NTS，或至少監控時鐘偏移），別讓一台「時間可被攻擊者操縱」的機器去跑安全更新。這條在單純「用庫就好」之外，是後端維運真正要負責的一塊。


## 六、Mix-and-match 防禦：上層用「版本＋雜湊」把下層釘死

mix-and-match 的解藥是**綁定（binding）**：不讓你自由拼裝，每一層都被上一層的「版本號＋長度雜湊」釘死，只能組出「當初一起發佈」的那一套。

這條綁定鏈是這樣扣起來的：

**① `timestamp` 釘 `snapshot`**（版本 + 雜湊）：

```go
// UpdateSnapshot:用 timestamp 裡記的 snapshot 長度/雜湊,驗你收到的 snapshot 位元組
snapshotMeta := trusted.Timestamp.Signed.Meta["snapshot.json"]
if !isTrusted {
	err = snapshotMeta.VerifyLengthHashes(snapshotData) // 對不上就拒
	...
}
// 且 checkFinalSnapshot 還要求版本相符:
func (trusted *TrustedMetadata) checkFinalSnapshot() error {
	...
	snapshotMeta := trusted.Timestamp.Signed.Meta["snapshot.json"]
	if trusted.Snapshot.Signed.Version != snapshotMeta.Version {
		return &metadata.ErrBadVersionNumber{
			Msg: fmt.Sprintf("expected %d, got %d", snapshotMeta.Version, trusted.Snapshot.Signed.Version)}
	}
	return nil
}
```

**② `snapshot` 釘每個 `targets`**（版本 + 雜湊）：

```go
// UpdateDelegatedTargets:用 snapshot 裡記的該角色長度/雜湊 + 版本,驗你收到的 targets
meta, ok := trusted.Snapshot.Signed.Meta[fmt.Sprintf("%s.json", roleName)]
if !ok {
	return nil, &metadata.ErrRepository{Msg: fmt.Sprintf("snapshot does not contain information for %s", roleName)}
}
err = meta.VerifyLengthHashes(targetsData) // 雜湊對不上→拒
...
if newDelegate.Signed.Version != meta.Version { // 版本對不上→拒
	return nil, &metadata.ErrBadVersionNumber{
		Msg: fmt.Sprintf("expected %s version %d, got %d", roleName, meta.Version, newDelegate.Signed.Version)}
}
```

把這兩段合起來看就是完整的綁定鏈：

```text
timestamp ──(版本 v_s + 雜湊 h_s)──▶ snapshot
                                       └──(版本 v_t + 雜湊 h_t)──▶ targets / 各委派角色
```

攻擊者想 mix-and-match？他得找一組「timestamp 指向的 snapshot 版本＋雜湊，剛好等於他想塞的那份舊 snapshot；而那份 snapshot 指向的每個 targets 版本＋雜湊，又剛好等於他想塞的那些舊 targets」——但這些**版本與雜湊都被上層簽名保護**，他改不動上層（沒金鑰），就只能整組拿「當初一起簽發」的那一套。**雜湊綁定擋掉「換內容不換版本」，版本綁定擋掉「換版本不換內容」，兩個一起上，拼裝就無縫可鑽。**

一句話：**mix-and-match 防禦 = 不給你選的自由。你收到的 snapshot 必須正是 timestamp 點名的那一版那個雜湊，你收到的每個 targets 必須正是 snapshot 點名的那一版那個雜湊。整條鏈只有一個合法組合。**


## 七、把三個攻擊放進同一條更新鏈看

現在把 Day104（橫向找角色）跟今天（縱向驗版本）合起來，看一次完整的 client 更新，安全檢查落在哪：

```text
1. root(N) → root(N+1) → ...     每份 +1、自簽+舊 root 簽、最終 root 不過期
                                  〔rollback: 版本嚴格遞增〕〔freeze: 最終 root 過期即拒〕
2. timestamp                      舊版拒/同版留舊/指向的 snapshot 版本不回滾;最終 timestamp 過期即拒
                                  〔rollback + freeze〕
3. snapshot                       用 timestamp 的版本+雜湊綁定;逐角色不回滾、不准刪;最終 snapshot 過期即拒、版本要對上 timestamp
                                  〔rollback + freeze + mix-and-match〕
4. targets / 委派 targets         用 snapshot 的版本+雜湊綁定;版本要對上、過期即拒
                                  〔mix-and-match + freeze〕
   └─ 這一步「內部」才是 Day104:preOrderDepthFirstWalk 沿委派樹找對角色
```

看清楚兩件事的分工：

- **Day104（橫向）**：在第 4 步「內部」，決定「這個 target 路徑該由哪個角色簽名背書」。
- **今天（縱向）**：決定「第 2、3、4 步拿到的每一份 metadata，是不是最新、彼此對不對得起來」。

**兩者缺一不可，而且順序上是「先縱向、後橫向」**——你得先靠 trusted metadata set 確認「這份 snapshot／targets 是最新且互相綁定的正確版本」，才輪到委派遍歷在那份「已確認新鮮」的 targets 裡找角色。如果縱向漏了，攻擊者用一份舊 targets 就能讓你在一棵**過時的委派樹**上找角色——你 Day104 做得再對，找到的也是舊世界的答案。


## 八、後端落地：你的責任不是實作,是「持久化＋時鐘＋版本衛生」

跟 Day101/102/103/104 同一條線：**這些更新規則你不該手刻**，`go-tuf` updater 內部就跑完整條鏈。但這篇的攻擊面有三個**維運層面**的責任，是「用庫就好」蓋不掉的，後端要自己扛：

**① 持久化 trusted metadata（否則 rollback 防禦形同虛設）。**

rollback 防禦靠「我手上這份的版本」當下限。如果你的 client **每次啟動都從乾淨狀態開始、把上次的 trusted metadata 丟掉**，那你的版本下限每次都掉回「只有初始 root」——攻擊者就能在每次啟動時，餵你一份「比上次舊、但比初始 root 新」的 metadata，rollback 又活了。**正確做法是把上次驗過的 timestamp/snapshot/targets 存到本地、下次啟動載回來當下限。** go-tuf 的 updater 本來就會維護本地 metadata 目錄，你要做的是**別把它當快取隨手清掉**，並確保它的存取權限受控（別讓攻擊者能改寫你的本地 trusted 狀態，那等於直接改你的下限）。

**② 時鐘可信（否則 freeze 防禦被繞過）。**

第五節講過：`IsExpired(RefTime)` 完全依賴系統時鐘。部署 TUF client 的機器要用受信任的時間源、監控時鐘偏移。這一條沒有任何「庫」能幫你，是純維運責任。

**③ 版本衛生（承 Day18 / Day104）。**

TUF client 本身也是依賴。CVE-2024-47534（Day104）就是「client 版本沒釘好」會漏掉的那類洞。把 TUF client 釘在含修補的維護版、納入 SBOM 與 `govulncheck` 掃描。

給 JVM 工程師的落地形態（承 Day80/101/102/103/104 老線）：**版本規則對消費端一樣是透明的。** 用 `sigstore-java` 的 `dev.sigstore.tuf` 抓 target 時，它內部維護一份持久化的 trusted metadata store，rollback/freeze/mix-and-match 的版本與過期檢查都在庫裡跑：

```java
// 概念示意:消費端只表達「刷新並要 target」,版本單調/過期/綁定檢查都在庫裡。
// 你的責任:(1) 給它一個「持久且權限受控」的本地 metadata 目錄當 rollback 下限;
//          (2) 確保這台機器時鐘可信(freeze 防禦前提);
//          (3) 把 TUF client 版本釘在含修補的維護版。
var updater = /* dev.sigstore.tuf.Updater,以可信 root + 本地持久 store 初始化 */;
updater.update();  // 內部:root→timestamp→snapshot→targets,逐層驗版本單調/過期/上層綁定
var targetInfo = updater.getTargetInfo("maven/com/acme/order-service.jar");
byte[] bytes   = updater.downloadTarget(targetInfo);
```

三個 JVM 重點：

- **本地 store 要持久且權限受控**——它是 rollback 下限，清掉或被寫壞都等於卸掉防禦。
- **時鐘可信是 freeze 防禦的前提**——別在時間可被操縱的機器上跑安全更新。
- **Java 1.8 跑不動就 sidecar**——`sigstore-java` 需 JDK 11+；1.8 服務照 Day80 老辦法，把 TUF 驗證挪成獨立 sidecar／服務。

一句話：**版本規則的「演算法」交給庫，但「持久化下限、可信時鐘、版本衛生」是後端維運的活。**


## 九、常見誤區

- **「簽名驗過了，metadata 就可信了。」** 錯。簽名只證明「repo 簽的」，證明不了「最新、對版」。rollback 回放的舊 metadata 簽名 100% 有效——它輸在版本，不是簽名。
- **「rollback 只要比對 metadata 自己的版本就好。」** 不夠。還要防「指向下層的版本被倒退」（timestamp 指的 snapshot 版本、snapshot 指的每個 targets 版本），以及「不准刪 snapshot 裡的角色記錄」。
- **「過期的舊 metadata 直接丟掉最乾淨。」** 錯，而且危險。丟掉會讓 rollback 下限歸零。go-tuf 刻意「載入過期的 intermediate metadata 當版本下限」，只在「當最終版用」時才查過期（`checkFinalTimestamp` / `checkFinalSnapshot`）。
- **「freeze 防禦是庫的事，我不用管。」** 錯。freeze 防禦 = 過期檢查 = 依賴系統時鐘。攻擊者若能操縱 client 時鐘，就能繞過。時鐘可信是你的維運責任。
- **「timestamp 有效期短只是為了效能／即時性。」** 錯。它是 freeze 攻擊的最長有效窗口上限，是**安全參數**。
- **「mix-and-match 靠簽名就能擋。」** 不夠。每份單獨簽名都合法。要靠「上層用版本＋雜湊把下層釘死」的綁定鏈，只留一個合法組合。
- **「client 每次重跑從頭開始最安全。」** 相反。丟掉持久化的 trusted metadata = 丟掉 rollback 下限。本地 store 要持久且權限受控。
- **「這些我自己實作也不難。」** 版本單調、intermediate 當下限、過期只在最終版查、三層雜湊＋版本綁定——細節多到連專業實作都出過 High 級 bug（Day104 的 CVE）。用維護中的庫、釘對版本。


## 十、Code Review／設計 checklist（消費端版本與時間）

- **用庫、不手刻**：metadata 更新走 `go-tuf` `trustedmetadata`／`sigstore-java`，沒有自幹的版本比對或過期檢查（第八節）。
- **版本釘死含修補**：TUF client 釘在含 CVE-2024-47534 修補的維護版；`govulncheck`／SBOM 當紅線（承 Day18/104）。
- **本地 trusted store 持久且權限受控**：確認 client 會把驗過的 timestamp/snapshot/targets 存本地、下次載回當 rollback 下限；該目錄權限受控、不被隨手清、不可被攻擊者改寫（第八節）。
- **時鐘可信**：跑 TUF client 的機器用受信任時間源、監控時鐘偏移——freeze 防禦的隱性前提（第五、八節）。
- **repo 端 timestamp 有效期夠短**：理解 timestamp `expires` = freeze 攻擊窗口上限，是安全參數不是效能參數（第五節）。
- **失敗即中止**：版本回滾（`ErrBadVersionNumber`）、過期（`ErrExpiredMetadata`）任一觸發就中止整輪更新；別在應用層 catch 後「盡力下載」繞過（第三、五節）。
- **區分「沒更新」與「被攻擊」**：`ErrEqualVersionNumber`（版本相等＝沒新東西）是正常，`ErrBadVersionNumber`（版本倒退）要當可疑事件記錄告警（第三節）。
- **綁定鏈完整**：確認 snapshot 用 timestamp 的版本＋雜湊綁定、targets 用 snapshot 的版本＋雜湊綁定，且版本必須相符（第六節）。


## 十一、測試怎麼做

這層測試多半是**「攻擊擋得下的存在證明」**——證明回滾拒、凍結拒、拼裝拒。很多可直接對照 TUF conformance 測試的思路：

- **timestamp rollback 擋得下**：手上 trusted timestamp v42，餵一份簽名合法的 v41，斷言 `UpdateTimestamp` 回 `ErrBadVersionNumber`、不採信（第三節）。
- **同版不當更新**：餵一份版本相等的 timestamp，斷言回 `ErrEqualVersionNumber`、保留舊的、不報成「被攻擊」（第三節）。
- **指向下層的版本也防回滾**：餵一份「timestamp 版本更高、但裡面 snapshot meta 版本更低」的組合，斷言仍被擋（第三節）。
- **snapshot 逐角色不回滾＋不准刪**：舊 snapshot 記了 `roleA=v5`，餵一份把 `roleA` 降到 v4、或整個少掉 `roleA` 的新 snapshot，斷言各自回 `ErrBadVersionNumber` / `ErrRepository`（第三節）。
- **freeze 擋得下**：把 `RefTime` 撥到 timestamp `expires` 之後，斷言 `checkFinalTimestamp` 回 `ErrExpiredMetadata`、無法載入 snapshot（第五節）。
- **intermediate 過期仍當下限**：載入一份過期舊 timestamp（當下限）後，斷言仍能接受版本更高的新 timestamp、且新的若也過期會在 final 檢查被擋（第四節）。
- **時鐘操縱模擬**：把 `RefTime` 往回撥（模擬 NTP 中間人），斷言你的部署有偵測時鐘偏移的手段——這條測的是維運控制，不只是庫（第五、八節）。
- **mix-and-match 擋得下（雜湊）**：給一份「版本對、但內容/雜湊對不上 timestamp 所記」的 snapshot，斷言 `VerifyLengthHashes` 失敗（第六節）。
- **mix-and-match 擋得下（版本）**：給一份「雜湊對、但版本對不上」的 targets，斷言 `UpdateDelegatedTargets` 回 `ErrBadVersionNumber`（第六節）。
- **持久化下限**：模擬 client 重啟，斷言它從本地 store 載回 trusted metadata 當下限，而非歸零重來（第八節）。


## 十二、一句話總結

> Day104 把委派的**消費端橫向解析**收完（沿委派樹找對角色）；今天翻到**縱向的版本與時間可信度**——找對角色沒用，如果你手上那份 metadata 是舊的、拼裝的。攻擊者不必偷任何金鑰，只要能改「你收到哪份 metadata」，就能玩三種攻擊：**rollback**（回放合法但過時的舊版，讓你錯過安全更新）、**freeze**（一直吐同一份舊的，把你凍在漏洞版本）、**mix-and-match**（拼裝不同 repo 狀態、各自合法的 metadata）。go-tuf 的 `trustedmetadata` 用三招一起擋：**版本單調遞增**（`UpdateTimestamp`/`UpdateSnapshot` 舊版回 `ErrBadVersionNumber`，root 嚴格 +1，連「指向下層的版本」都防回滾）；**過期檢查**（`checkFinalTimestamp`/`checkFinalSnapshot` 過期回 `ErrExpiredMetadata`，timestamp 短效期就是 freeze 窗口上限）；**上層用版本＋雜湊把下層釘死**（timestamp 釘 snapshot、snapshot 釘每個 targets，只留一個合法組合擋 mix-and-match）。其中最精妙的一點：**過期的 intermediate metadata 仍要載入當「防回滾下限」，只在當最終版用時才查過期**——丟掉它，rollback 下限就歸零。後端工程師的可執行結論：**演算法交給維護中的 TUF client、釘對版本；但三件維運事你得自己扛——把 trusted metadata「持久化且權限受控」（rollback 下限）、確保機器「時鐘可信」（freeze 防禦前提）、把 client「版本衛生」納入掃描。任何一項漏掉，簽名全對的 metadata 一樣能把你帶回舊世界。**


## 延伸閱讀

- **Day104 TUF 委派消費端解析**——今天的橫向對照。昨天在一棵委派樹上「找對角色」；今天確保「那棵樹本身是最新、對版的」。兩者順序上是先縱向確認版本、後橫向找角色。
- **Day101 TUF 信任根散布／輪替**——root 的 threshold 驗證與 +1 單調輪替在那天講完；今天不重述，只定位 root 版本 +1 也是 rollback 家族的一員。
- **Day18 供應鏈／SBOM**——「版本衛生」（把 TUF client 釘在含 CVE 修補的版本、納入掃描）是供應鏈防線的一環。
- **Day16 安全日誌與監控**——`ErrBadVersionNumber`（版本倒退）該當可疑事件告警，區別於 `ErrEqualVersionNumber`（沒更新）。
- **Day19 TLS**——傳輸層擋不下 rollback（攻擊者可在受信任 TLS 端點後的鏡像回放舊 metadata）；rollback 防禦必須在 metadata 層，這正是 TUF 補 TLS 不足的地方。

---

明天預告：**Day 106 — 版本規則對了，但 client 到底怎麼「原子地」抓到互相對得起來的那一整套 metadata？TUF consistent snapshot 與 hash-prefixed 檔名下載——為什麼一致快照 repo 要用 `<version>.snapshot.json` 與 `<hash>.target` 命名、`root.Signed.ConsistentSnapshot` 開關對「發佈原子性、並行下載不撕裂、舊 client 續讀舊版本」的意義，以及非一致快照 repo 在「發佈到一半」時的競態風險**
（這是**延伸／接續**，把視角從今天的「版本規則怎麼判斷新舊對版」轉到「檔案層怎麼命名與擷取，才能讓那套規則在真實下載時不被撕裂」。情境：repo 正在發佈新版（先傳 targets、再傳 snapshot、最後 timestamp），一個 client 剛好在中途來抓——一致快照用「版本／雜湊前綴檔名」讓新舊版本檔案並存、互不覆蓋，client 永遠抓到一整套對得起來的；非一致快照則可能讀到「新 snapshot 配舊 targets」的半成品。示範 go-tuf updater 的檔名擷取邏輯與 `Config` 的 `PrefixTargetsWithHash`。明確不重述今天的版本單調／過期／綁定規則與 Day104 委派遍歷，聚焦**檔案層的一致性擷取與發佈原子性**。標為延伸篇，consistent snapshot 一致性下載機制首次介紹。）
