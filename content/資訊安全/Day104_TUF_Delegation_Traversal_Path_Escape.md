---
title: "Day 104：委派授權設對了，消費端會不會找錯角色、下載錯成品？——TUF 委派的 client 端 pre-order DFS 解析、Terminating 截斷與路徑逃逸防禦，與那個把『順序』當信任的 CVE-2024-47534"
date: 2026-08-16
tags: ["TUF", "委派解析", "供應鏈安全", "CVE-2024-47534"]
---

接續 Day103 預告：昨天把委派的**發行端**收完了——`targets` 一把金鑰通吃全 repo 就是 root 之下的新單點，用命名委派（`Paths`／`Threshold`／`Terminating`）與 hash bin（`SuccinctRoles` 的 `BitLength`／`NamePrefix`）把簽署權往下拆、把爆炸半徑關進一小格。今天把鏡頭從發行端翻到**消費端**：**你設計得再漂亮的委派拓撲，最後都要靠 client 端「拿到一個 target 路徑，沿委派樹一層層找出負責角色、驗簽、拒絕越權」的解析來兌現。這一步做錯，攻擊者就算沒偷到任何金鑰，也能讓你下載到錯的成品。**

**這篇不是重新介紹委派，也不重述 Day103 的發行端授權與 hash bin 分片、不重述 Day101 頂層四角色的 threshold 驗證機制。** 今天只聚焦消費端的四件事：

1. **pre-order DFS 遍歷**——`go-tuf/v2` updater 拿到一個 target 路徑，怎麼沿委派樹做「前序深度優先」搜尋，為什麼「先檢查自己、再往下鑽」。
2. **順序即信任**——為什麼委派的「出現順序」決定採信誰；以及 go-tuf 那則把順序搞錯就會下載錯成品的安全公告 **CVE-2024-47534 / GHSA-4f8r-qqr9-fq8j**。
3. **`Terminating` 的消費端語意**——同一個旗標，Day103 從發行端講「這段路徑獨不獨佔」，今天講消費端「命中截斷角色後，剩下的待訪角色要不要全部清掉、不再回頭」。
4. **路徑逃逸防禦**——為什麼一個**被攻陷的下層委派角色**，在自己的 metadata 裡簽一筆「超出父角色授權路徑」的 target，消費端解析**根本不會採信**；以及 cycle／visited／`MaxDelegations` 這些「別讓遍歷本身變成 DoS」的護欄。

安全主軸先講在前面：**委派的安全不是只靠發行端把授權設對，而是靠消費端把「解析」做對——照出現順序找、每一跳都驗簽、命中截斷就收手、超出授權的路徑一律不採信。少了任何一項，委派切好的爆炸半徑就會在 client 端漏回去。**

> 本文的 Go 範例對照 `github.com/theupdateframework/go-tuf/v2` 的 `master` 原始碼：`metadata/updater/updater.go` 的 `preOrderDepthFirstWalk`、`metadata/metadata.go` 的 `Delegations.GetRolesForTarget`／`SuccinctRoles.GetRolesForTarget`／`DelegatedRole.IsDelegatedPath`／`isTargetInPathPattern`／`VerifyDelegate`，函式與欄位皆為實際存在的呼叫，非杜撰。go-tuf/v2 現行維護版本為 v2.3.1（2025-01），CVE-2024-47534 已於 `>v2.0.0` 修復。


## 一、消費端到底在解什麼問題

先把消費端的職責講清楚，跟發行端劃開。發行端（Day103）煩惱的是「怎麼把簽署權往下拆、授權誰負責哪段路徑」；消費端煩惱的是**反向**的問題：

> 我手上只有一個 target 路徑，例如 `maven/com/acme/order-service/1.4.2/order-service.jar`。整個 repo 有 `targets` 頂層、底下一堆命名委派、再底下 1024 個 hash bin……**這個路徑到底該由哪個角色的簽名來背書？我要怎麼「安全地」找到它、而且不被一個沒被授權的角色騙過去？**

在 `go-tuf/v2`，這件事的入口就一個方法——消費端要哪個 target，就問 updater：

```go
import (
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

func fetch(up *updater.Updater) error {
	// 1. 沿委派樹找出「誰負責這個 target」,並取回它的長度/雜湊資訊。
	//    副作用:過程中會按需下載/驗證所需的委派 metadata。
	ti, err := up.GetTargetInfo("maven/com/acme/order-service/1.4.2/order-service.jar")
	if err != nil {
		return err // 找不到負責角色,或任何一跳驗簽失敗
	}
	// 2. 下載並用上一步找到的 metadata 驗長度/雜湊。
	_, _, err = up.DownloadTarget(ti, "", "")
	return err
}
```

`GetTargetInfo` 內部呼叫的，就是今天的主角 `preOrderDepthFirstWalk`。它的官方註解一句話點出全篇的靈魂：

> `preOrderDepthFirstWalk` interrogates the tree of target delegations **in order of appearance (which implicitly order trustworthiness)**, and returns the matching target found in **the most trusted role**.

「出現順序 = 信任順序」「回傳最受信任那個角色裡找到的 target」——這兩句就是接下來每一節都在保護的東西。


## 二、pre-order DFS：go-tuf updater 怎麼走委派樹

委派是一棵樹（甚至可能被惡意做成有環的圖）：`targets` 委派給 `A`、`B`；`B` 再委派給 `C`；hash bin 則是一次長出 1024 個葉子。消費端要在這棵樹上找一個 target，用的是**前序（pre-order）深度優先搜尋**。下面是 `go-tuf/v2` `updater.go` 的實際演算法，我保留原始結構、加上中文註解：

```go
type roleParentTuple struct {
	Role   string // 要訪問的委派角色名
	Parent string // 它的父角色(委派者)——驗簽時需要,由父角色驗子角色
}

func (update *Updater) preOrderDepthFirstWalk(targetFilePath string) (*metadata.TargetFiles, error) {
	// 待訪清單,當 stack 用(從尾端 pop)。起點是頂層 targets,其父是 root。
	delegationsToVisit := []roleParentTuple{{Role: metadata.TARGETS, Parent: metadata.ROOT}}
	visitedRoleNames := map[string]bool{} // 走過的角色,用來擋環(cycle)

	// 護欄:訪問過的角色數不得超過 cfg.MaxDelegations,且還有東西可訪
	for len(visitedRoleNames) <= update.cfg.MaxDelegations && len(delegationsToVisit) > 0 {
		// 從 stack 頂端取一個角色
		delegation := delegationsToVisit[len(delegationsToVisit)-1]
		delegationsToVisit = delegationsToVisit[:len(delegationsToVisit)-1]

		// 擋環:走過的角色直接跳過,不重複訪問
		if visitedRoleNames[delegation.Role] {
			continue
		}

		// 下載+驗證這個角色的 targets metadata(內部由父角色 VerifyDelegate,見第八節)
		targets, err := update.loadTargets(delegation.Role, delegation.Parent)
		if err != nil {
			return nil, err
		}

		// 【前序檢查】先看「這個角色自己」有沒有列出這個 target。
		//   有 → 立刻回傳,這就是「最先命中的角色 = 最受信任的角色」。
		if target, ok := targets.Signed.Targets[targetFilePath]; ok {
			return target, nil
		}

		// 自己沒有,才把它標記為已訪,然後往下鑽它的委派。
		visitedRoleNames[delegation.Role] = true

		if targets.Signed.Delegations != nil {
			var childRolesToVisit []roleParentTuple
			// 關鍵:只拿「路徑命中」的子角色(第六節路徑逃逸防禦的核心)
			roles := targets.Signed.Delegations.GetRolesForTarget(targetFilePath)
			for _, r := range roles {
				childRolesToVisit = append(childRolesToVisit,
					roleParentTuple{Role: r.Name, Parent: delegation.Role})
				if r.Terminating {
					// 命中截斷角色:清掉佇列裡其餘一切,不再回頭(第五節)
					delegationsToVisit = []roleParentTuple{}
					break
				}
			}
			// 反轉後再接到尾端,確保 pop 出來的順序 == 委派宣告的順序
			slices.Reverse(childRolesToVisit)
			delegationsToVisit = slices.Concat(delegationsToVisit, childRolesToVisit)
		}
	}
	return nil, fmt.Errorf("target %s not found", targetFilePath)
}
```

三個一定要看懂的點：

- **「前序」= 先檢查當前角色自己，再往下鑽子角色。** 一走到某個角色，先問「你自己這份 metadata 有沒有列這個 target」；有就直接回傳、不再往下。這保證「愈上層、愈早出現的角色，愈優先被採信」。
- **stack + `slices.Reverse` = 維持宣告順序。** 子角色是 append 進 `childRolesToVisit`（保持宣告順序），但因為 stack 是「後進先出」，直接 push 會把順序倒過來，所以先 `Reverse` 再接上去——pop 出來就還原成宣告順序。這個「反轉」不是花招，它就是「出現順序 = 信任順序」在資料結構上的落地，**下一節那個 CVE 正是這裡的順序被打亂**。
- **每一跳都是「先下載驗證、才檢查」。** `loadTargets` 會先把該角色 metadata 抓下來、由父角色驗簽通過，才輪到 `targets.Signed.Targets[...]` 這行去讀內容。消費端**從不信任還沒驗過的 metadata**（第八節細談）。


## 三、順序即信任：為什麼「誰先出現」這麼要命

把上一節的規則翻成攻擊者視角就懂了。假設某路徑同時被兩個委派命中：

- `payments-team`：發行端刻意排在**前面**，是這段路徑的正牌負責人。
- `catch-all`：排在**後面**的寬鬆委派（或一個被攻陷、被塞進來的低權角色）。

正確行為是：**先訪問 `payments-team`，它列出的 target 一命中就回傳**——`catch-all` 根本輪不到。這就是「回傳最受信任角色裡找到的 target」。攻擊者就算能讓 `catch-all` 簽一個假的同名 target，只要遍歷順序正確、`payments-team` 先被檢查，假貨就永遠蓋不過真貨。

**反過來，如果遍歷順序被打亂、`catch-all` 先被訪問到，攻擊者的假 target 就會先命中、先回傳——消費端下載到錯的成品，而且全程沒有任何一把金鑰被偷、沒有任何一個簽名驗不過。** 這就是「順序即信任」的另一面：順序錯了，等於信任錯了。

這不是假想。go-tuf 真的踩過這個坑。


## 四、CVE-2024-47534 / GHSA-4f8r-qqr9-fq8j：一個 `map` 就能讓你下載錯成品

2024-10-01，go-tuf 發布安全公告 **GHSA-4f8r-qqr9-fq8j**（**CVE-2024-47534**，Severity **High**）。標題直白：*Incorrect delegation lookups can make go-tuf download the wrong artifact*。

- **受影響套件／版本**：`github.com/theupdateframework/go-tuf/v2/metadata`，`<= v2.0.0`；`> v2.0.0` 已修。
- **怎麼被抓到的**：TUF conformance 測試套件的 `test_graph_traversal` 專門檢查「client 追委派的順序」。測試案例 `two-level-delegations` 長這樣：`targets` 委派給 `A`、也給 `B`，`B` 再委派給 `C`，**預期訪問順序是 `A → B → C`**。但某次 CI 跑出來，go-tuf 追成了 `B → C → A`。順序錯了。
- **根因**：`Delegations.GetRolesForTarget` 當年回傳的是 `map[string]bool`——**Go 的 map 迭代順序是隨機的**。第二節那個「append 保持宣告順序、再 Reverse 還原」的前提，被上游一個亂序的 map 直接破功。委派的「出現順序」在資料結構這一層就丟了，於是「信任順序」跟著丟。
- **修法**：把回傳從 map 改成**有序的 slice**。今天的 `master` 原始碼就是修好的樣子，連註解都把公告連結釘在函式上：

```go
// GetRolesForTarget return the names and terminating status of all
// delegated roles who are responsible for targetFilepath
// Note the result should be an ordered list, ref. GHSA-4f8r-qqr9-fq8j
func (role *Delegations) GetRolesForTarget(targetFilepath string) []RoleResult {
	var res []RoleResult
	if role.Roles != nil { // 命名委派:按 Roles 宣告順序逐一比對路徑
		for _, r := range role.Roles {
			if ok, err := r.IsDelegatedPath(targetFilepath); err == nil && ok {
				res = append(res, RoleResult{Name: r.Name, Terminating: r.Terminating})
			}
		}
	} else if role.SuccinctRoles != nil { // hash bin:算出唯一命中的那個 bin
		res = role.SuccinctRoles.GetRolesForTarget(targetFilepath)
	}
	return res // 有序:與 Roles 宣告順序一致
}
```

`RoleResult` 只有兩個欄位——`Name`（角色名）與 `Terminating`（截不截斷）——但**它是 slice、有序**，這就是修法的全部重點。一個「map 換成 slice」的差別，CVSS 打到 8.7，因為它動搖的是「順序即信任」這條地基。

給後端工程師的一句話：**這類 bug 不是你手刻委派解析才會遇到——它就藏在你依賴的 TUF client 版本裡。你能做的防禦是「版本衛生」：把 TUF client 釘在含修補的版本（go-tuf `>v2.0.0`，實務用 v2.3.1），並讓 SBOM／`govulncheck` 把 CVE-2024-47534 當紅線掃。** 委派解析交給維護中的庫，但「庫的哪個版本」是你的責任（承 Day18 供應鏈、Day101/102「把驗證工程交給維護中的庫」）。


## 五、`Terminating` 的消費端語意：命中截斷，就把佇列清乾淨

Day103 從**發行端**講 `Terminating`：「這段路徑命名空間要不要被這個角色獨佔」。今天看它在**消費端**遍歷時到底做了什麼——回頭看第二節那段：

```go
if r.Terminating {
	delegationsToVisit = []roleParentTuple{} // 清掉佇列裡「其餘所有」待訪角色
	break                                    // 本層在它之後宣告的角色也不再加入
}
```

翻成白話：**當遍歷命中一個 `Terminating: true` 的角色，消費端會把待訪佇列裡剩下的角色全部丟掉——包含祖先層排隊等著的兄弟角色——然後把搜尋收斂在「這個截斷角色（及本層排在它之前的角色）的子樹」。之後在這個子樹裡找不到 target，就是找不到，不再回頭去試別人。** 這就是預告講的「`Terminating` 截斷的消費端語意」與「不 backtracking」。

為什麼這關乎安全？回到第三節的 `payments-team` vs `catch-all`：

- 發行端把 `payments-team` 設成 `Terminating: true`、負責 `maven/payments/*.jar`。
- 消費端查 `maven/payments/x.jar` 時，`GetRolesForTarget` 依序回傳 `[payments-team(term), catch-all]`。迴圈走到 `payments-team`，因為它截斷 → **清空佇列、break**，`catch-all` 連被 push 的機會都沒有。
- 結果：`maven/payments/*` 這段路徑，消費端**只認** `payments-team`。就算 `catch-all` 被攻陷、想影子出一個 `maven/payments/x.jar`，它在消費端的遍歷裡根本不會被訪問到。

反之，若 `payments-team` 忘了設截斷（`Terminating: false`）、而且它自己沒列出這個 target，遍歷就會**穿透（fallthrough）**繼續往後找到 `catch-all`——這時 `catch-all` 就有機會供應那個 target。**發行端 Day103 設 `Terminating` 的那個決定，是在消費端這裡被真正執行的。** 兩天要合起來看：發行端決定「獨不獨佔」，消費端負責「命中就收手」。

補一個 Day103 埋過的點：**hash bin（`SuccinctRoles`）在消費端天生就是截斷的。** 原始碼 `SuccinctRoles.GetRolesForTarget` 回傳的 `RoleResult` 永遠 `Terminating: true`（註解：*we consider all succinct_roles as terminating, for more information read TAP 15*），而且只回傳**唯一一個**算出來的 bin：

```go
func (role *SuccinctRoles) GetRolesForTarget(targetFilepath string) []RoleResult {
	// 取 SHA-256 最左邊 BitLength 個 bit 當 bin 編號(對照 Day103 的 binFor)
	h := sha256.Sum256([]byte(targetFilepath))
	binNumber := binary.BigEndian.Uint32(h[:4]) >> (32 - role.BitLength)
	suffix := fmt.Sprintf("%0*x", suffixLen, binNumber)
	// 只回傳一個 bin,且一律 terminating
	return []RoleResult{{Name: fmt.Sprintf("%s-%s", role.NamePrefix, suffix), Terminating: true}}
}
```

所以 hash bin 的消費端解析特別乾淨：**算一次雜湊 → 得到唯一 bin → 就認它、不 fallthrough。** 分片本來就該互斥獨佔，消費端語意也如實反映。


## 六、路徑逃逸防禦：下層角色簽不了「父角色沒授權的路徑」

這是今天的重點，也是 Day103 第五節「委派只能收窄不能放大」那句話在**消費端**的兌現。威脅場景：

> 一個下層委派角色 `jar-team`，父角色只授權它 `maven/*.jar`。假設 `jar-team` 的簽署金鑰**被攻陷**了。攻擊者在 `jar-team` 自己的 metadata 裡，塞了一筆 `infra/db-credentials.env`（完全超出它被授權的路徑），並用偷來的 `jar-team` 金鑰簽好。消費端會不會因此下載到這筆越權的 target？

答案是**不會**，而且防禦是**結構性**的——不是靠某個額外的檢查函式，而是靠遍歷「路由」本身。關鍵在第二節那行：

```go
roles := targets.Signed.Delegations.GetRolesForTarget(targetFilePath)
```

消費端要找 `infra/db-credentials.env` 時，是從**父角色**（授權 `jar-team` 的那個上層 `targets`）的委派表出發，呼叫 `GetRolesForTarget("infra/db-credentials.env")`。而 `GetRolesForTarget` 只會回傳「路徑真的命中」的子角色——它對每個候選子角色呼叫 `IsDelegatedPath`：

```go
func (role *DelegatedRole) IsDelegatedPath(targetFilepath string) (bool, error) {
	if len(role.Paths) > 0 { // 命名委派:逐一比對授權的 Paths
		for _, pathPattern := range role.Paths {
			if isTargetInPathPattern(targetFilepath, pathPattern) {
				return true, nil
			}
		}
	}
	// ...(hash-prefix 分支略)
	return false, nil
}
```

`jar-team` 被父角色授權的 `Paths` 是 `["maven/*.jar"]`。拿 `infra/db-credentials.env` 去比對：

```go
// isTargetInPathPattern:以 "/" 切段,段數要相等,再逐段 filepath.Match
targetParts  := strings.Split("infra/db-credentials.env", "/") // ["infra","db-credentials.env"]
patternParts := strings.Split("maven/*.jar", "/")              // ["maven","*.jar"]
// 第一段 "infra" 不 match "maven" → false
```

不 match。於是**父角色的 `GetRolesForTarget("infra/db-credentials.env")` 根本不會把 `jar-team` 回傳**。`jar-team` 這個角色，在「查 `infra/db-credentials.env`」這條路徑上，**永遠不會被 push 進待訪佇列、永遠不會被訪問**。它 metadata 裡那筆越權的 `infra/db-credentials.env`，是一筆**永遠不會被消費端讀到的死資料**。

把這個防禦講到位，要分清楚兩種「看起來像越權」的情況：

- **真・路徑逃逸（擋得下）**：下層在 metadata 裡簽一筆**超出**父角色授權 `Paths` 的 target。消費端因為「路由不到」而完全不採信——如上。**這是委派安全的地基：一個被攻陷的下層角色，爆炸半徑被父角色的授權路徑硬性框死，逃不出去。**
- **濫用自己合法範圍（要靠 Day103）**：下層在**授權範圍內**做壞事，例如 `jar-team` 授權 `maven/*.jar`，它就簽一個惡意的 `maven/order-service.jar`。這**不是**路徑逃逸——它在自己地盤內，消費端會採信。防這個要靠 Day103 的發行端設計：把 `Paths` 收到最窄、對高價值下層要求 `Threshold ≥ 2`、對敏感段落用 `Terminating` 獨佔。**消費端擋得下「逃出授權」，擋不下「授權給錯的人」——後者是發行端的責任。**

一句話：**路徑逃逸防禦不是一道額外的門，而是遍歷本身只走「父角色授權的路」。委派把爆炸半徑收窄的承諾，就是靠消費端「只路由到被授權的子角色」來兌現的。**


## 七、別讓遍歷本身變成 DoS：cycle、visited、MaxDelegations

委派是「上層授權下層」，但沒有什麼阻止一個惡意或寫壞的 repo 做出**環**（`A` 委派 `B`、`B` 又委派回 `A`）或**超深／超寬**的委派圖。消費端在人家的資料上跑圖遍歷，必須自我保護，否則光是解析就能被拖垮（承 Day31 ReDoS、Day71/72 DoS 那條「別在攻擊者可控輸入上無界遞迴」的老線）。go-tuf 的三道護欄都在第二節那段裡：

- **`visitedRoleNames` 擋環**：每訪問一個角色就記進 set，再遇到直接 `continue`。`A → B → A` 的第二個 `A` 會被跳過，不會無限繞。
- **前序檢查後才標記 visited**：注意順序是「先檢查自己有沒有 target、回傳；沒有才標記 visited」。這確保「同一個角色不會為了同一個 target 被重複展開」，同時不影響「它自己能不能命中」。
- **`cfg.MaxDelegations` 封頂**：迴圈條件 `len(visitedRoleNames) <= update.cfg.MaxDelegations`。訪問過的角色數一超過上限就停，避免惡意 repo 用「幾萬個委派」的圖把 client 拖到天荒地老（委派炸彈）。上限值走設定（TUF 規範對「最大委派層數」本就有建議），你在初始化 updater 時可依風險調整。

這三道護欄的共同精神：**消費端在遍歷別人給的委派圖時，把「圖可能有惡意結構」當預設，用 visited 擋環、用計數封頂。** 別假設 repo 一定是善意的良性樹。


## 八、每一跳都要驗簽：`VerifyDelegate` 落在遍歷的哪一步

前面幾節都在講「怎麼找對角色」，但消費端的安全還有另一半：**找到的每一個角色 metadata，都必須先被它的父角色驗過簽名、達到門檻，才准讀內容。** 這件事發生在第二節的 `loadTargets` 裡——它下載該角色 metadata 後，會走 trusted metadata set 的更新流程，由**父角色**對子角色呼叫 `VerifyDelegate`。這裡**不重述 Day101 的 threshold 驗證機制**，只定位它在遍歷中的位置與兩個消費端關鍵：

```go
// VerifyDelegate:由委派者(父角色,root 或 targets)驗被委派者(子角色)的簽名是否達門檻。
// 命名委派傳角色名(如 "jar-team");hash bin 傳算出的 bin 名(如 "bin-2ce")。
func (meta *Metadata[T]) VerifyDelegate(delegatedRole string, delegatedMetadata any) error {
	// ...收集該委派角色的 KeyIDs 與 Threshold(命名委派來自 Delegations.Roles,
	//    hash bin 來自 Delegations.SuccinctRoles),逐一驗章、湊門檻...
	if len(signingKeys) < roleThreshold {
		return &ErrUnsignedMetadata{Msg: "not enough signatures"} // 門檻不足 → 整跳失敗
	}
	return nil
}
```

兩個消費端該記住的點：

- **驗簽在「檢查 target」之前。** 遍歷的每一跳都是「先 `loadTargets`（下載＋`VerifyDelegate` 通過）→ 才 `targets.Signed.Targets[...]` 讀內容」。任何一跳門檻不足，`GetTargetInfo` 直接回錯、整個解析中止——**你不會拿到一個「沒驗過的角色」裡的 target**。
- **門檻是「不同公鑰」的門檻，不是「不同簽名筆數」。** go-tuf 的 `VerifyDelegate` 用**公鑰指紋**（PKIX 公鑰的 SHA-256）去重來湊門檻，而不是數簽名筆數。這擋掉一種鑽漏洞：同一把金鑰用不同 keyid（例如同時登記成 `ecdsa` 與 `ecdsa-sha2-nistp256`）重複登記，想用「一把鑰匙冒充兩票」湊過 `Threshold: 2`——在 go-tuf 這會被算成一票。這條細節對「委派門檻到底穩不穩」很關鍵，Code Review 別漏。

所以消費端解析的完整一跳是：**下載角色 metadata → 父角色 `VerifyDelegate` 驗到門檻 → 前序檢查它有沒有 target → 有就回傳、沒有就按授權路徑往下路由。** 「找對角色」與「每跳驗簽」缺一不可。


## 九、發行端 vs 消費端：誰做什麼，Java 落在哪

跟 Day101/102/103 一樣，先分清楚你的後端服務站哪一端：

**發行端（authoring／repo 維運）**：設計委派拓撲、設 `Paths`／`Terminating`／`Threshold`、產金鑰、簽各層 metadata（Day103 的地盤，`go-tuf`／`tuf-on-ci`）。**今天的一切消費端解析，都不該由你手刻。**

**消費端（你的後端服務多半在這）**：要一個 target，就 `GetTargetInfo` → `DownloadTarget`，前序遍歷、順序、截斷、路徑逃逸防禦、驗簽——**全部由 updater 內部完成，你不該自己實作 DFS、自己算 bin、自己核 `VerifyDelegate`。** CVE-2024-47534 正說明：連 go-tuf 這種專業實作，都會在「遍歷順序」這種細節上出過 High 級 bug——你手刻只會更慘。消費端的正確姿勢是**用維護中的庫、釘對版本**。

給 JVM 工程師的落地形態（承 Day80/101/102/103 那條老線）：**委派解析對消費端是透明的。** 用 `sigstore-java` 的 `dev.sigstore.tuf.Updater` 抓並驗 target 時，它內部就會走委派樹的遍歷與驗簽，你的 Spring 服務只管「要哪個 target」：

```java
// 概念示意:消費端只表達「要哪個 target」,委派樹遍歷/順序/截斷/驗簽都在庫裡。
// 你的責任不是實作遍歷,而是:把 TUF client 釘在含 CVE 修補的版本。
var updater = /* dev.sigstore.tuf.Updater,由可信 root 初始化 */;
updater.update();                       // 刷新頂層 metadata
var targetInfo = updater.getTargetInfo("maven/com/acme/order-service.jar");
byte[] bytes = updater.downloadTarget(targetInfo); // 內部:沿委派樹解析 + 每跳驗簽
```

三個 JVM 落地重點：

- **版本衛生 = 你的主要防線。** 消費端安全的成敗，很大一部分是「你用的 TUF client 有沒有含 CVE-2024-47534 這類遍歷修補」。把 TUF client 版本納入依賴掃描與 SBOM（Day18），別讓一個過期的 client 把「順序即信任」漏回去。
- **別手刻遍歷。** 委派解析、`Terminating` 語意、路徑比對、bin 計算——全都留給庫。你自己寫，八成會在順序或路徑逃逸上開洞。
- **Java 1.8 跑不動就 sidecar。** `sigstore-java` 需 JDK 11+；Java 1.8 服務照 Day80 老辦法，把 TUF 驗證挪成獨立 sidecar／服務，別為了相容硬把驗證邏輯搬進 1.8 手刻。

一句話：**消費端的委派解析是「用對庫、釘對版本」的工程，不是「自己寫一棵 DFS」的工程。**


## 十、常見誤區

- **「委派授權設對了，消費端隨便找找就好。」** 錯。順序（第三、四節）、截斷（第五節）、路徑逃逸（第六節）、每跳驗簽（第八節）任何一項在 client 端做錯，發行端切好的爆炸半徑就漏回去。CVE-2024-47534 就是「授權沒問題、解析順序錯」的活教材。
- **「遍歷順序只是效能，不影響安全。」** 錯。順序 = 信任（`in order of appearance implicitly order trustworthiness`）。順序被打亂，較不受信任的角色可能先命中、先回傳，導致下載錯成品——這正是那則 High 級 CVE 的核心。
- **「一個 `map` 而已，能有多嚴重。」** CVSS 8.7。Go map 迭代隨機 → 委派順序不定 → 信任順序不定。修法就是「map 換 ordered slice」。
- **「被攻陷的下層角色可以簽任何 target。」** 不行。它只能在**父角色授權的 `Paths` 內**動；超出授權的路徑，消費端因「路由不到」而完全不採信（第六節）。但**授權範圍內**它確實能作惡——那要靠 Day103 發行端把 `Paths` 收窄、`Threshold` 拉高。
- **「`Terminating` 是發行端的事，消費端不用管。」** 發行端**設定**它，消費端**執行**它：命中截斷角色就清空佇列、不 fallthrough。兩天要合起來看。
- **「hash bin 也要 fallthrough 找好幾個。」** 不用。`SuccinctRoles` 算出**唯一**一個 bin、且一律 terminating，認它就好（第五節）。
- **「消費端要自己驗每個角色的簽名。」** 不用自己刻，但要知道它**發生在遍歷的每一跳、在讀 target 之前**；且門檻是「不同公鑰」的門檻（第八節）。
- **「委派圖是善意的，遍歷不會出事。」** 別假設。環與超深委派可以拖垮 client，要靠 visited／`MaxDelegations` 護欄（第七節）。


## 十一、Code Review／設計 checklist（消費端）

- **用庫、不手刻**：target 解析走 `go-tuf` updater／`sigstore-java`，沒有自幹的委派 DFS、bin 計算或 `VerifyDelegate`（第九節）。
- **版本釘死含修補**：TUF client 釘在含 CVE-2024-47534 修補的版本（go-tuf `>v2.0.0`，實務 v2.3.1）；`govulncheck`／SBOM 把此 CVE 當紅線（第四、九節）。
- **順序即信任**：確認你用的 client 版本，委派查找回傳的是**有序**結果（非 map）；升級後別被舊版依賴悄悄拉回（第四節）。
- **截斷語意正確**：理解命中 `Terminating` 角色會清空佇列、不 fallthrough；對「需獨佔的敏感路徑」在發行端設截斷，消費端才擋得下影子（第五節，承 Day103）。
- **路徑逃逸靠路由**：確認遍歷只路由到「父角色授權路徑命中」的子角色；被攻陷下層簽的越權 target 不會被讀到（第六節）。
- **每跳驗簽**：解析的每一跳都先 `VerifyDelegate` 達門檻才讀 target；門檻以「不同公鑰」計、擋同鑰多登記（第八節）。
- **遍歷護欄**：updater 設有合理的 `MaxDelegations`；理解 visited 擋環，避免惡意委派圖 DoS（第七節）。
- **失敗即中止**：任一跳驗簽失敗或找不到負責角色，`GetTargetInfo` 回錯、整體中止——別在應用層 catch 後「盡力下載」繞過（第八節）。


## 十二、測試怎麼做

消費端這層的測試，多半是**「解析行為的存在證明」**——證明順序對、截斷對、越權擋得下、環拖不垮。很多可以直接對照 TUF conformance 的思路（CVE-2024-47534 就是 conformance 測出來的）：

- **graph traversal 順序**：擺 `targets→A`、`targets→B`、`B→C`，斷言訪問順序穩定為 `A→B→C`（不是有時 `B→C→A`）。這正是 `test_graph_traversal` / `two-level-delegations` 的意旨——把 CVE-2024-47534 變成一條會亮紅燈的回歸測試。
- **順序即信任**：讓前後兩個委派都命中同一路徑、各簽一個不同 target，斷言回傳的是**前面**那個角色的 target（最受信任者勝）。
- **`Terminating` 不 fallthrough**：擺一個截斷角色 + 一個後面較寬的委派，斷言後者**無法**對截斷角色獨佔的路徑供應 target（影子攻擊擋得下）。
- **路徑逃逸擋得下**：讓下層角色（授權 `maven/*.jar`）在自己 metadata 簽一筆 `infra/secret.env`，斷言消費端查該路徑時**根本不路由到它**、回傳 not found（第六節的存在證明）。
- **glob 段數陷阱**：斷言 `maven/*.jar` 命中 `maven/a.jar`、**不**命中 `maven/com/a.jar`（`*` 不跨 `/`），確認消費端路由與發行端授權對齊（承 Day103）。
- **bin 命中唯一且截斷**：對已知路徑斷言算出的 bin 名與 `SuccinctRoles.GetRolesForTarget` 一致、且只回一個、`Terminating: true`（第五節）。
- **門檻不足擋得下**：拿一份「只湊到 `Threshold−1` 把有效簽章」的下層 metadata，斷言該跳 `VerifyDelegate` 失敗、解析中止（第八節）。
- **同鑰多登記不加分**：同一公鑰用兩個 keyid 登記、各簽一次，斷言在 `Threshold: 2` 下仍**驗不過**（只算一票，第八節）。
- **環與深度護欄**：造一個 `A→B→A` 的環、或超過 `MaxDelegations` 的深委派，斷言解析會終止（回 not found／達上限），不會無限繞或爆掉（第七節）。


## 十三、一句話總結

> Day103 把委派的**發行端**收完（授權誰負責哪段路徑、hash bin 分片）；今天翻到**消費端**——那些授權最後都要靠 client 的解析來兌現。`go-tuf/v2` updater 對一個 target 路徑做**前序深度優先**遍歷：**先檢查當前角色自己、再按「宣告順序」往下路由**（`preOrderDepthFirstWalk` + `slices.Reverse` 維持順序），因為「出現順序 = 信任順序」，回傳最先命中（最受信任）角色裡的 target。這條地基脆到什麼程度？go-tuf 曾因 `GetRolesForTarget` 回傳**亂序的 map**而追錯委派、下載錯成品——**CVE-2024-47534 / GHSA-4f8r-qqr9-fq8j，CVSS 8.7**，修法就是「map 換成有序 slice」。消費端還有三道要做對的事：**`Terminating` 命中即清空佇列、不 fallthrough**（Day103 發行端設定、今天消費端執行）；**路徑逃逸靠「只路由到父角色授權路徑命中的子角色」硬性框死**——被攻陷的下層簽一筆超出授權的 target，消費端因路由不到而完全不採信；以及**每一跳都先 `VerifyDelegate` 達門檻才讀 target**（門檻以不同公鑰計，擋同鑰多登記）。最後別讓遍歷自己變 DoS：`visited` 擋環、`MaxDelegations` 封頂。後端工程師的可執行結論就一句：**委派解析交給維護中的 TUF client、把版本釘在含 CVE 修補的 `>v2.0.0`（v2.3.1），別手刻遍歷——順序、截斷、路徑逃逸、驗簽，任何一項在 client 端做錯，發行端切好的爆炸半徑就會漏回去。**


## 延伸閱讀

- **Day103 TUF targets 委派與 hash bin**——今天的上游（發行端）。昨天設 `Paths`／`Terminating`／`Threshold`、切 hash bin；今天講消費端怎麼把這些授權兌現：按順序找、命中截斷收手、越權路徑不採信。
- **Day101 TUF 信任根散布／輪替**——頂層四角色的 threshold 驗證機制在那天講完，今天不重述，只定位 `VerifyDelegate` 在委派遍歷的哪一步發生。
- **Day18 供應鏈／SBOM**——消費端的「版本衛生」（把 TUF client 釘在含 CVE-2024-47534 修補的版本、納入 SBOM／`govulncheck`）就是供應鏈防線的一環。
- **Day07 最小權限**——路徑逃逸防禦＝消費端只路由到「父角色最小授權」內的子角色，`Paths` 就是最小權限邊界的消費端執行。
- **Day31／Day71／Day72**——委派圖可能有環或超深，消費端遍歷要用 visited／`MaxDelegations` 護欄，呼應「別在攻擊者可控輸入上無界遞迴」。

---

明天預告：**Day 105 — 委派解析對了，但 client 手上那份 metadata「新不新、對不對版」誰保證？TUF 消費端的 rollback / freeze / mix-and-match 攻擊防禦——`trustedmetadata` 更新規則：snapshot/timestamp/targets 的版本只能單調遞增、過期即拒、consistent snapshot 綁定同一 repo 狀態**
（這是**延伸／接續**，把視角從今天的「委派樹橫向解析」轉到「metadata 縱向的版本與時間可信度」：今天保證「找對角色」，明天保證「你手上這份 targets/snapshot/timestamp 沒被降級、沒被凍結在舊版本」。情境：一個位於中間人或惡意鏡像位置的攻擊者，回放一份**簽名合法但版本較舊**的 snapshot，想讓你錯過一個已知漏洞成品的更新——示範 go-tuf `trustedmetadata` 的 `UpdateSnapshot`／`UpdateTimestamp` 為何用「版本單調遞增＋過期檢查＋snapshot meta 綁定」把 rollback／freeze／mix-and-match 一起擋下。明確不重述今天的委派遍歷與 Day101 root 輪替，聚焦**消費端 trusted metadata set 的更新規則與版本回滾防禦**。標為延伸篇，rollback／freeze／mix-and-match 攻擊面首次介紹。）
