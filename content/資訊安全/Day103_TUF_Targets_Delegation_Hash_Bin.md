---
title: "Day 103：一把 targets 金鑰簽上萬個檔案就是新的單點——TUF targets 委派與 hash bin delegation：把簽署權往下分、收斂爆炸半徑"
date: 2026-08-15
tags: ["TUF", "targets 委派", "hash bin", "供應鏈安全"]
---

接續 Day102 預告：昨天把「自己當根」那條線收完了——root 金鑰儀式、離線門檻保管、線上 vs 離線角色的自動化邊界、退場治理。root 顧好了，但昨天第四節那張「四角色自動化邊界」表裡，`targets` 被我一句「離線、原則不自動」輕輕帶過。今天要還這筆帳：**當你的私有 artifact／模型 registry 有成千上萬個 target，卻全部由單一 `targets` 金鑰簽，這把金鑰就成了 root 之下新的高價值單點——它能為 repo 裡任何一個檔案背書。**

這正是 Day101「四角色分離＝把爆炸半徑切四段」留下的伏筆：那把刀只切到**頂層四角色**之間。今天往下鑽一層，切 `targets` 底下的**委派（delegation）**——把 Day101 的爆炸半徑概念，從「root／targets／snapshot／timestamp 四段」，推進到 `targets` 的**樹狀委派拓撲**。

**這篇不重述 Day101 與 Day102。** 頂層四角色各自的威力與上線程度（Day101）、root 儀式與離線門檻保管（Day102）——那些昨天前天講完了，今天不再開一次。今天只聚焦三件事：

1. **委派的兩種形態**——命名委派（按路徑把 `*.jar` 交給團隊角色）與 hash bin（按雜湊把上萬個 target 均勻分片）。
2. **路徑約束與 `Terminating` 語意**——委派最容易誤解、也最關乎安全的兩個旋鈕：一個委派能簽哪些路徑、簽不到時要不要往下找。
3. **blast radius 收窄**——「一把委派金鑰被偷」到底只炸掉一小段路徑，還是整個 repo；以及這一切的維運成本在哪。

安全主軸先講在前面：**簽署權不該集中。root 之下的 `targets` 若一把金鑰通吃全 repo，你只是把 Day102 拚命離線保管的那顆單點，往下複製了一份。委派的意義，就是讓「偷一把金鑰」的傷害，被關進它負責的那一小格。**

> 本文的 Go 範例對照 `github.com/theupdateframework/go-tuf/v2/metadata` 的 `master` 原始碼與官方 `examples/repository/basic_repository.go`，函式與欄位（`Delegations`／`DelegatedRole`／`SuccinctRoles`／`VerifyDelegate`／`AddKey`／`RevokeKey`）皆為實際存在的呼叫，非杜撰。go-tuf/v2 為現行維護版本（取代舊版 v0.7.0，Sigstore 在用）。


## 一、問題：單一 `targets` 金鑰 = root 之下的新單點

先把威脅講清楚。Day101 的頂層 `targets` 角色，職責是「為 target 檔案的完整性背書」——它在 metadata 裡列出每個 target 的路徑、hash、長度，然後簽名。消費端信任這份 `targets.json`，就等於信任裡面每一筆。

問題在規模。一個公司內部的 artifact registry，`maven/**` 底下可能有上萬個 `.jar`、`models/**` 底下幾千個模型檔、`npm/**`、`containers/**`……如果這些**全部**寫進同一份 `targets.json`、由**同一把** `targets` 金鑰簽：

- **這把金鑰能為 repo 裡任何檔案背書。** 偷到它＝可以替換、新增任何一個 target 的 hash，讓消費端下載到被掉包的成品。這就是 Day18 供應鏈那條「信任被集中在一個點」的老病，只是換到 TUF 這層。
- **爆炸半徑 = 整個 repo。** Day101 好不容易把 root 關進離線門檻，結果 `targets` 這把「天天要動、要簽新版成品」的金鑰，反而握著全 repo 的背書權，還不能像 root 那樣一年只碰幾次。
- **簽署動線被綁死成一條。** 平台團隊、ML 團隊、前端團隊發的東西全擠在同一把金鑰、同一份 metadata 底下，一個團隊的疏失波及所有人。

Day102 我們對 root 的答案是「離線、門檻、分持」。但 `targets` 不能照抄——它效期短、要頻繁簽新成品，關進離線門檻等於叫平台每天跑一次 root 儀式，不可行。`targets` 的答案不是「保管得更嚴」，而是**把它的簽署權往下拆**：委派。


## 二、委派的兩種形態：命名委派 vs hash bin

TUF 的委派，本質是「`targets` 角色不自己簽所有 target，而是**授權**一批下層角色，各自負責一段 target，並為它們的公鑰與門檻背書」。就像 Day101 root 對四角色的頂層委派，只是這次是 `targets` 對更下層的委派——同一套「上層授權下層、爆炸半徑逐層收窄」的遞迴。

有兩種切法，解的是不同規模的問題：

| 形態 | 怎麼分 | 適合 | go-tuf 欄位 |
|---|---|---|---|
| **命名委派（standard）** | 按**路徑語意**分：`maven/*` 給平台團隊、`models/*` 給 ML 團隊 | 少量、**有意義的邊界**（依團隊／產品線／路徑前綴） | `Delegations.Roles []DelegatedRole`（`Paths`） |
| **hash bin（succinct）** | 按**檔名雜湊**均勻分片成 N 個 bin，跟語意無關 | **上萬個**同性質 target，沒有天然邊界可分 | `Delegations.SuccinctRoles`（`BitLength`、`NamePrefix`） |

心法一句話：**命名委派切「誰負責」，hash bin 切「攤平規模」。** 前者讓 `models/*` 被 ML 團隊的金鑰簽、跟平台團隊互不越界（邊界是人為、語意的）；後者是當你有三萬個 `.jar`、沒有天然的人為邊界時，用雜湊把它們**均勻**灑進 1024 個 bin，讓「偷一把 bin 金鑰」只碰得到 1/1024 的 target。兩者可以疊：先命名委派把 `maven/*` 交給平台，平台再對它的三萬個 jar 做 hash bin。

下面兩節分別落地。


## 三、命名委派：把 `*.jar` 交給團隊角色（go-tuf/v2）

先看命名委派。發行端的動作是：在**上層** `targets` 的 metadata 裡，放一段 `Delegations`，宣告「我信任一個叫 `jar-team` 的下層角色，它的公鑰是這些、門檻是 2、負責路徑 `maven/*.jar`」。以下對照官方 `basic_repository.go` 的委派段（欄位皆為實際存在）：

```go
package main

import (
	"crypto/ed25519"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// 在「上層 targets」metadata 裡宣告一個下層委派角色 jar-team。
// 注意:這裡只放下層角色的「公鑰」與「路徑/門檻約束」——私鑰在團隊自己手上,
// 上層 targets 從頭到尾不持有下層私鑰(承 Day101/102「AddKey 只收公鑰」的同一條靈魂)。
func delegateJarTeam(top *metadata.Metadata[metadata.TargetsType], jarTeamPub ed25519.PublicKey) error {
	jarKey, err := metadata.KeyFromPublicKey(jarTeamPub)
	if err != nil {
		return err
	}
	jarKeyID, err := jarKey.ID()
	if err != nil {
		return err
	}

	top.Signed.Delegations = &metadata.Delegations{
		Keys: map[string]*metadata.Key{jarKeyID: jarKey},
		Roles: []metadata.DelegatedRole{
			{
				Name:        "jar-team",
				KeyIDs:      []string{jarKeyID},
				Threshold:   2,                       // 下層也能要求多簽(承 Day101 threshold)
				Terminating: false,                   // 見第四節:簽不到時要不要往下找
				Paths:       []string{"maven/*.jar"}, // 只授權這段路徑
			},
		},
	}

	// 上層 targets 是委派者,效期可以拉長、動得少(承 basic_repository.go 的
	// 「delegators should be less volatile」);真正天天換的成品由下層 jar-team 簽。
	// 之後 jar-team 自己維護一份獨立的 targets metadata(檔名 jar-team.json),
	// 只列 maven/*.jar 那些 target,並用「它自己的」金鑰簽。
	return nil
}
```

三個一定要看懂的點：

- **`Paths` 是授權邊界。** `jar-team` 只被授權簽 `maven/*.jar`。它就算在自己的 metadata 裡塞了一筆 `models/secret.bin`，消費端解析時也不會認——因為那不在上層授權給它的路徑內（第五節詳談）。委派**只能收窄、不能放大**。
- **`Threshold` 讓下層也能多簽。** 委派不是「把單點下放成另一個單點」。高價值的下層（例如簽正式版 jar 的角色）可以要求 2-of-3，讓偷一把下層金鑰也還不夠。
- **`Keys` 只收公鑰。** 跟 Day102 root 儀式一樣：上層只收集下層的公鑰與門檻，下層私鑰散在各團隊手上，沒有任何一台機器同時握有全部委派金鑰。

發行端把 target 從上層挪到下層後，記得走完 Day101 的整套發版連動：下層 `jar-team.json` 進 snapshot、snapshot 進 timestamp、逐一 bump 版本、各自簽名（`ClearSignatures` → `Sign` → `ToFile`）。


## 四、`Terminating`：委派最容易誤解的旗標

`Terminating` 決定「**消費端沿委派往下找 target 時，走到這個角色、路徑有命中、但這裡沒有這個 target，要不要繼續往後找**」。它是路徑命名空間的「圍欄」，直接關乎爆炸半徑與防影子攻擊：

- **`Terminating: true`（截斷）**：只要 target 路徑落進這個角色的 `Paths`，搜尋就**停在這裡**。若這個角色沒列出該 target → 判定「找不到」，**不再往後面的委派找**。效果：這段路徑命名空間**被這個角色獨佔**，後面任何委派都不能再對這段路徑插手。
- **`Terminating: false`（不截斷／可穿透）**：這個角色路徑命中但沒有該 target 時，**繼續往後面的委派找**。效果：允許 fallthrough，多個委派可以對重疊路徑接力。

為什麼這關乎安全？想像上層先委派 `maven/*` 給 `jar-team`（`Terminating: true`），後面又有一個較寬鬆的 `catch-all` 委派。若 `jar-team` 設成截斷，攻擊者就算攻下 `catch-all` 那把金鑰，也**無法**用它去簽一個 `maven/evil.jar`——因為搜尋在 `jar-team` 就被截斷了，`maven/*` 這段是 `jar-team` 獨佔的地盤。反過來若忘了設截斷，`catch-all` 就能「影子」出一個上層以為由 `jar-team` 負責的路徑。

判準：**你希望這段路徑「只此一家」，就 `Terminating: true`；你要的是「這個角色優先、沒有就退回別人接手」，才 `false`。** hash bin 的每個 bin 都是天生截斷的（第七節），因為分片本來就該互斥獨佔。


## 五、路徑約束怎麼比對——glob 分段的陷阱與「委派不能放大」

命名委派的安全全靠「路徑到底怎麼比對」。go-tuf/v2 的 `DelegatedRole.IsDelegatedPath` 有兩個必須知道的行為：

**其一：glob 是「逐段比對、段數要相等」，`*` 不跨 `/`。** 原始碼把 target 路徑與 pattern 都以 `/` 切段，`len(targetParts) != len(patternParts)` 直接判不match，再逐段 `filepath.Match`。這代表：

- `maven/*.jar` 匹配 `maven/order-service.jar`（2 段對 2 段）。
- `maven/*.jar` **不**匹配 `maven/com/acme/order.jar`（4 段 vs 2 段）——`*` 只吃**同一層**，不會穿透子目錄。
- 想涵蓋整棵子樹，TUF 的 glob **沒有 `**`**；你得按深度多寫 pattern，或改用 hash bin（這也是實務上「目錄結構深、又想細分」直接倒向 hash bin 的原因）。

這個陷阱的危險在於**你以為授權了一整棵樹，其實只授權了一層**：把 `Paths: ["maven/*"]` 當成「整個 maven 都給你」，結果 `maven/com/acme/x.jar` 根本不在授權內，消費端解析不到、或落到你沒預期的別的委派——排錯到天亮。Code Review 要把「pattern 段數 vs 真實 target 深度」當一條檢查項。

**其二：委派只能收窄，不能放大父角色的權限。** 這是委派安全的地基，也是我明天要展開的主線：一個下層角色，就算在自己的 metadata 裡列了一筆超出上層授權 `Paths` 的 target，消費端在解析時也**不會**採信它——因為信任是「上層授權下層負責哪段」逐層下傳的，下層無權自行擴權。go-tuf 對「哪個委派負責哪個 target」的解析（`Delegations.GetRolesForTarget`）是一份**有序**清單，順序會影響結果，官方為此發過安全公告（GHSA-4f8r-qqr9-fq8j，委派順序處理）——這條消費端解析的細節與濫用，就是明天 Day104 的題目，今天先在發行端把授權邊界設對。


## 六、hash bin：上萬個 target 怎麼分片

命名委派解「有語意邊界」的切分。但當你有三萬個性質一樣的 `.jar`、沒有天然的人為邊界，命名委派會爆炸：難道手寫三萬條 `DelegatedRole`？

hash bin 的心法：**不看語意，只按檔名的雜湊，把 target 均勻灑進 N 個 bin，每個 bin 是一個下層委派角色、由一把（或一組）bin 金鑰簽。** 「均勻」是重點——雜湊天然把 target 打散，每個 bin 大約 1/N 的量，不會有某個 bin 特別肥。

分片邏輯（這正是消費端拿到一個 target 路徑、要決定「該去哪個 bin metadata 找它」的算法，對照 go-tuf/v2 `SuccinctRoles.GetRolesForTarget` 的 `master` 實作）：

```go
import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
)

// 給定 target 路徑,算出它落在哪個 bin 角色。對照 go-tuf/v2
// metadata.SuccinctRoles.GetRolesForTarget(已核對 master 原始碼)。
func binFor(targetPath string, bitLength int, namePrefix string) string {
	numberOfBins := int(math.Pow(2, float64(bitLength)))
	// suffixLen:最後一個 bin 的十六進位長度。bit_length=10 → 1024 bins
	// → 後綴 000..3ff → suffixLen=3
	suffixLen := len(strconv.FormatInt(int64(numberOfBins-1), 16))

	h := sha256.Sum256([]byte(targetPath))
	// 取雜湊最左邊 bit_length 個 bit:先當成 big-endian uint32,再右移
	binNumber := binary.BigEndian.Uint32(h[:4]) >> (32 - bitLength)

	// 角色名 = 前綴-補零的十六進位 bin 編號,例如 bin-2ce
	return fmt.Sprintf("%s-%0*x", namePrefix, suffixLen, binNumber)
}
```

用 `bit_length=10`（1024 個 bin、前綴 `bin`）實際跑幾個路徑，這些是我用上面同一套算法算出的真值：

```text
maven/com/acme/order-service/1.4.2/order-service.jar   -> bin-2ce  (第 718 / 1024 格)
models/llm/checkout-ranker/v7/model.safetensors        -> bin-047  (第  71 / 1024 格)
npm/@acme/ui/3.0.1/ui.tgz                              -> bin-0f6  (第 246 / 1024 格)
```

三個 target 各自散到不同 bin。發行端要簽 `order-service.jar` 時，只動 `bin-2ce` 這個角色的 metadata、用 `bin-2ce` 的金鑰簽；消費端要驗它，也只需算出 `bin-2ce`、抓那一份 bin metadata。**簽署與驗證都被限縮在 1/1024 的範圍。**

bit_length 怎麼選（bins = 2^bit_length）：

| bit_length | bins 數 | 每 bin 約含（3 萬 target） | 角色名後綴 |
|---:|---:|---:|---|
| 8 | 256 | ~117 | `00`..`ff` |
| 10 | 1024 | ~29 | `000`..`3ff` |
| 12 | 4096 | ~7 | `000`..`fff` |
| 14 | 16384 | ~2 | `0000`..`3fff` |

**bit_length 越大＝爆炸半徑越小（偷一把 bin 金鑰碰得到的 target 越少），但代價是 metadata 角色數暴增**（第八節談成本）。實務常見落在 8～12：太小分片不夠細，太大 metadata 管理成本吃不消。


## 七、go-tuf/v2 的 `SuccinctRoles`：免手寫上萬個角色

如果 hash bin 要在 `root.json`／`targets.json` 裡**逐一列出** 1024 個 `DelegatedRole`，那份 metadata 會爆肥。TUF 為此有 **succinct roles**（TAP 15）：只用「一把（組）金鑰＋`bit_length`＋`name_prefix`」四個欄位，就**succinctly** 描述整組 1024 個均勻 bin，不必展開。go-tuf/v2 的 `Delegations.SuccinctRoles` 就是它（欄位皆實際存在）：

```go
// 發行端:對「上層 targets(或某個命名委派角色)」一次委派出 1024 個 hash bin。
// 不必列舉 1024 條 DelegatedRole——SuccinctRoles 四個欄位描述整組。
top.Signed.Delegations = &metadata.Delegations{
	Keys: map[string]*metadata.Key{binKeyID: binKey},
	SuccinctRoles: &metadata.SuccinctRoles{
		KeyIDs:     []string{binKeyID}, // 這組 bin 用的簽署金鑰(可多把+門檻)
		Threshold:  1,
		BitLength:  10,    // 2^10 = 1024 個 bin
		NamePrefix: "bin", // 角色名 bin-000 .. bin-3ff
	},
}

// 加金鑰給 succinct 這組時,role 參數可忽略(原始碼:
// 「If SuccinctRoles is used then the role argument can be ignored」)
_ = top.Signed.AddKey(binKey, "") // 進 SuccinctRoles.KeyIDs
```

消費端驗一個 bin 的簽名時，用的還是 Day101/basic_repository.go 那個 `VerifyDelegate`——委派者驗被委派者。succinct 的情況下，它自動改用 `SuccinctRoles.KeyIDs`／`Threshold` 來核（原始碼已處理這個分支）：

```go
// 委派者(上層 targets)驗某個 bin 角色的 metadata 簽名是否達門檻。
// 對命名委派傳角色名(如 "jar-team");對 hash bin 傳算出來的 bin 名(如 "bin-2ce")。
err := top.VerifyDelegate("bin-2ce", binMeta)
```

一個常被問的點：**bin 角色多，但消費端不會全抓。** 因為 consistent snapshot 下每個 bin metadata 是獨立、版本化的檔案，消費端只需算出命中的那一個 bin（第六節的 `binFor`）、抓那一份，不是把 1024 份全下載。付出的是**發行端** metadata 數量與 snapshot 條目的膨脹，不是消費端的下載量。


## 八、blast radius：偷一把金鑰，炸多大

把前面幾節收斂成一張「金鑰被偷、影響半徑」對照表——這是整篇的重點，也是要不要做委派的判準：

| 架構 | 一把「簽成品」金鑰被偷，攻擊者能替換？ | 復原怎麼做 | 代價／成本 |
|---|---|---|---|
| **單一 `targets` 金鑰** | **整個 repo** 任一 target | root 出手換 `targets` 金鑰（Day101） | metadata 最簡單，但爆炸半徑最大 |
| **命名委派** | 被偷角色**授權路徑內**的 target（如只有 `maven/*.jar`） | **上層 `targets`** `RevokeKey`＋`AddKey` 換掉該下層角色金鑰 | 需維護 N 個角色與路徑邊界 |
| **hash bin（1024）** | 該 bin 的 **~1/1024** target | 上層 `RevokeKey`＋`AddKey` 換該 bin 金鑰 | metadata 角色數暴增、snapshot 變肥 |

三個要看懂的結論：

- **委派把「換金鑰」從發版事件降級成局部動作。** 被偷的是下層委派金鑰時，**不必動 root**——由**上層 `targets`** 用 `RevokeKey`／`AddKey` 換掉那個角色（或那個 bin）的金鑰即可，爆炸半徑就是「那一段路徑／那一個 bin」。這正是 Day101「金鑰折損復原：非 root 角色被偷＝上層簽新版換 keyids」在 targets 樹狀委派的下沉。

```go
// 下層 bin/委派角色金鑰疑似外洩:上層 targets 換掉它,影響面只有這個角色。
_ = top.Signed.RevokeKey(oldBinKeyID, "bin-2ce")
_ = top.Signed.AddKey(newBinKey, "bin-2ce")
// 只有 bin-2ce 受影響,repo 其餘 1023 個 bin 與所有命名委派毫髮無傷。
```

- **爆炸半徑與 metadata 成本是蹺蹺板。** bit_length 拉大、bin 變多＝半徑更小，但 snapshot 要列更多 bin metadata、發行端要管更多角色。這跟 Day102「root 門檻拉高更安全但要湊更多人簽」是同一種取捨思維：**安全性換運維成本，沒有免費的細分。**
- **委派不改變頂層。** root 仍是離線門檻（Day102）、snapshot／timestamp 仍是線上頻繁重簽（Day101/102）。委派只在 `targets` 這根枝幹上長出子樹，把「簽成品」這件高頻動作的權限往下攤平。


## 九、發行端 vs 消費端：誰簽、誰驗，Java 落在哪

跟 Day101/102 一樣，要分清楚**你的後端服務站在哪一端**：

**發行端（authoring／repo 維運）**：設計委派拓撲、產各角色金鑰、簽各層 metadata。這是 `go-tuf/v2`（本文範例）或 `python-tuf`／`tuf-on-ci`（承 Day102）的地盤。**別在你的 Java／Go 業務服務裡手刻委派 metadata 與簽章**——手刻路徑約束、`Terminating` 語意、bin 分片、門檻，必漏（Day101 到今天沒變的老規矩）。

**消費端（驗證／下載 target）**：這才是絕大多數後端服務的位置。你要的是「給我 `maven/order-service.jar`，幫我沿委派樹找到負責它的角色、驗簽、比對 hash、下載」。go-tuf/v2 的 `updater`（`metadata/updater`）與 sigstore 的工具會**自動**走完委派解析——你不必自己算 bin、自己核 `VerifyDelegate`。

給 JVM 工程師的落地形態（呼應 Day80/81/101/102 那條老線）：委派**拓撲的驗證對消費端是透明的**。用 `sigstore-java` 的 `dev.sigstore.tuf.Updater`（Day101 提過的消費端）抓並驗 target 時，它內部就會處理 targets 委派的解析，你的 Spring 服務只管「要哪個 target」。委派的**設計與簽署**留在 `go-tuf`／`tuf-on-ci`；Java 1.8 跑不動 `sigstore-java`（需 JDK 11+）就照 Day80 的老辦法把驗證挪成 sidecar。一句話：**委派是發行端的拓撲工程，消費端只享受「爆炸半徑已經被收窄」的結果。**


## 十、委派金鑰的上線程度與輪替

承 Day102 第四節那條「線上 vs 離線自動化邊界」——委派金鑰也要問同一題：**這把委派／bin 金鑰，能不能上線自動簽？**

判準跟頂層一樣看**威力**，但委派讓你有了更細的刻度：

- **高權命名委派**（例如簽正式版 release jar 的角色）：威力接近頂層 `targets`，該**離線或半離線＋門檻多簽**，比照 Day102 對 targets 的謹慎。
- **低權、高頻的 bin 金鑰**（例如 CI 每次 build 都要簽一堆快照 artifact）：可以上線、放 KMS（私鑰不落地，承 Day102），因為單一 bin 的爆炸半徑已經被 hash bin 關到 1/N——這正是「先用委派把威力關小，才敢把它上線」的順序，不能反過來。

**絕不能做的**：為了 CI 方便，把**上層 `targets` 或高權命名委派**金鑰直接放上線自動簽。那等於把「能為一大段路徑背書」的金鑰暴露在 CI 攻擊面下，CI 被入侵就直接改一整段的信任內容——Day102 對 root／targets「別上線」的鐵律，在委派這層一模一樣，只是現在你可以**用 bin 把該上線的部分縮到最小**再上線。

輪替與折損復原（第八節已示範）：委派金鑰的排程輪替，由**上層角色**重簽新版（`RevokeKey`＋`AddKey`＋bump 版本），不驚動 root。這比頂層金鑰輪替輕得多，也是委派的隱藏紅利——**你把「需要動 root／頂層 targets 的重大事件」，降級成了「動某個下層角色」的日常維運。**


## 十一、常見誤區

- **「`targets` 一把金鑰簽全 repo 沒差，反正它被 root 保護。」** root 保護的是「誰能當 targets」，不是「targets 那把金鑰被偷後能炸多大」。單一 targets＝root 之下的全 repo 單點，委派就是來拆它的。
- **「委派就是把單點下放成另一個單點。」** 不是——下層一樣能設 `Threshold` 多簽，且爆炸半徑被 `Paths`／bin 關進一小格。委派收窄的是**半徑**，不是把問題平移。
- **「`Paths: ["maven/*"]` 就等於整個 maven 都給它。」** go-tuf 的 glob `*` 不跨 `/`、段數要相等，`maven/*` 不吃 `maven/com/acme/x.jar`。跨子樹要嘛多寫 pattern、要嘛用 hash bin。
- **「`Terminating` 隨便設。」** 設錯＝路徑命名空間沒圍好，後面較寬的委派可以影子出你以為被獨佔的路徑。要獨佔就 `true`。
- **「hash bin 的 bit_length 越大越好。」** 半徑是變小了，但 metadata 角色數與 snapshot 條目跟著爆。安全換成本的蹺蹺板，實務多落在 8～12。
- **「下層委派角色可以在自己 metadata 裡簽任何 target。」** 不行——委派只能收窄不能放大，超出上層授權 `Paths` 的 target 消費端不採信（明天 Day104 展開）。
- **「委派金鑰都可以上線自動簽，反正有委派。」** 只有被 hash bin／`Paths` 關小威力的低權角色該上線；高權命名委派與上層 `targets` 仍比照 Day102 別上線。
- **「消費端要自己算 bin、自己核 VerifyDelegate。」** 不用——`go-tuf` updater／`sigstore-java` 會自動走委派解析，手刻反而容易漏（把驗證工程交給維護中的庫，承 Day101/102）。


## 十二、Code Review／設計 checklist

- **拆單點**：`targets` 底下**沒有**一把金鑰通吃全 repo；成千上萬個 target 至少按團隊／路徑做命名委派，超大量同質 target 再疊 hash bin（第一、二節）。
- **路徑邊界**：每個命名委派的 `Paths` **就是**它該負責的範圍，段數與真實 target 深度對得上（`*` 不跨 `/`）；沒有委派宣告超過它該碰的路徑（第三、五節）。
- **`Terminating` 設對**：需要獨佔的路徑命名空間設 `Terminating: true`，避免後面較寬委派影子插手；`false` 只用在刻意要 fallthrough 的接力（第四節）。
- **下層也多簽**：高價值下層（正式版 release）設 `Threshold ≥ 2`，別把委派做成新的單簽單點（第三節）。
- **金鑰只收公鑰**：上層 `Delegations.Keys` 只放下層公鑰，下層私鑰散在各團隊；沒有一台機器同時握有全部委派金鑰（第三節，承 Day102）。
- **上線程度分層**：只有被 bin／`Paths` 關小威力的低權角色金鑰上線（KMS、私鑰不落地）；上層 `targets` 與高權命名委派**不上線**（第十節，承 Day102）。
- **輪替走上層**：下層委派／bin 金鑰折損，用**上層** `RevokeKey`＋`AddKey` 換、不動 root；此流程寫進 runbook（第八、十節，承 Day101）。
- **消費端交給庫**：驗證走 `go-tuf` updater／`sigstore-java`，不手刻委派解析與 bin 計算（第九節）。


## 十三、測試怎麼做

委派這層的「測試」多是**授權邊界的存在證明**——證明「越權簽的東西進不來」「金鑰折損只炸一格」：

- **越權路徑被擋**：讓 `jar-team`（授權 `maven/*.jar`）在自己 metadata 裡簽一筆 `models/x.bin`，斷言消費端解析**不採信**它（委派不能放大的存在證明，明天 Day104 主線）。
- **glob 段數陷阱**：斷言 `maven/*.jar` 匹配 `maven/a.jar`、**不**匹配 `maven/com/a.jar`，把「以為授權了整棵樹」這個誤解變成紅燈的測試。
- **`Terminating` 語意**：擺一個截斷委派＋一個後面較寬的委派，斷言後者**無法**對前者獨佔的路徑供應 target（影子攻擊擋得下）。
- **bin 分片正確**：對已知路徑斷言 `binFor` 算出的 bin 名與 go-tuf `SuccinctRoles.GetRolesForTarget` 一致（例如 `maven/com/acme/order-service/1.4.2/order-service.jar` → `bin-2ce`），確保發行端與消費端算出同一個 bin。
- **門檻不足擋得下**：拿一份「只湊到 `Threshold−1` 把有效簽章」的下層 metadata，斷言 `VerifyDelegate` 拒收（承 Day101 門檻存在證明）。
- **折損半徑演練**：假設「`bin-2ce` 金鑰外洩」，實際走一遍 `RevokeKey`／`AddKey`，斷言**只有** `bin-2ce` 的簽名失效、其餘 bin 與命名委派照常——證明爆炸半徑真的被關在一格。
- **上線金鑰稽核**：CI 斷言上層 `targets`／高權命名委派的 keyid **沒有**任何已知線上 KMS keyid 混入（承 Day102 第九節組態掃描，下沉到委派層）。


## 十四、一句話總結

> Day101 講「四角色分離＝爆炸半徑切四段」、Day102 講「root 那段怎麼離線保管」；今天把刀往下切一層——**`targets` 一把金鑰簽上萬個 target，就是 root 之下的新單點，委派把它的簽署權往下拆、把爆炸半徑關進一小格。** 兩種切法：**命名委派**按路徑語意把 `maven/*.jar` 交給團隊角色（go-tuf `Delegations.Roles` 的 `Paths`／`Threshold`／`Terminating`），`Paths` 是只能收窄不能放大的授權邊界、glob 的 `*` 不跨 `/`、`Terminating` 決定路徑命名空間獨不獨佔；**hash bin** 按檔名雜湊把上萬個 target 均勻灑進 2^bit_length 個 bin（go-tuf `SuccinctRoles` 的 `BitLength`／`NamePrefix`，免列舉），偷一把 bin 金鑰只碰得到 1/N。收窄的紅利：委派金鑰折損由**上層 `targets`** `RevokeKey`／`AddKey` 換掉、不驚動 root，把「動 root 的重大事件」降級成「動某個下層角色」的日常；代價是 metadata 角色數與 snapshot 膨脹，安全換運維成本的蹺蹺板。發行端用 `go-tuf`／`tuf-on-ci` 設計拓撲，消費端 `sigstore-java`／updater 透明享受「半徑已收窄」的結果——一句話：**簽署權不該集中，root 之下也一樣；把 `targets` 這把通吃全 repo 的金鑰拆成一格一格，偷一把只炸一格。**


## 延伸閱讀

- **Day101 TUF 信任根散布／輪替／金鑰折損復原**——今天的上游。頂層四角色分離與「非 root 角色被偷＝上層簽新版換 keyids」，今天下沉到 `targets` 樹狀委派：委派金鑰折損由上層 `targets` 換掉，不動 root。
- **Day102 自建／私有 TUF 信任根運維**——昨天講 root 儀式與「線上 vs 離線自動化邊界」；今天把那條邊界用到委派金鑰上：先用 bin／`Paths` 把威力關小，才敢把低權角色上線。
- **Day18 供應鏈／SBOM**——單一 `targets` 通吃全 repo，就是「信任集中在一個點」的供應鏈老病；委派是把這個點打散。
- **Day07 最小權限**——委派＝把「簽 target」的權限按路徑最小化下放，`Paths` 就是最小權限邊界。
- **Day15／Day16**——委派金鑰仍是高價值祕密，各層金鑰保管、上線程度、輪替與越權嘗試都要進 SIEM。

---

明天預告：**Day 104 — 委派設對了，但消費端怎麼「安全地」沿委派樹找 target？TUF 委派的 client 端解析與路徑逃逸防禦——pre-order DFS 遍歷、`Terminating` 截斷的消費端語意、下層委派角色不能簽父角色沒授權的路徑、以及 go-tuf 那則委派順序安全公告（GHSA-4f8r-qqr9-fq8j）**
（這是**延伸／接續**，把今天的視角從**發行端**翻到**消費端**：今天講「怎麼授權下層負責哪段路徑」，明天講「消費端 `go-tuf/v2` updater 拿到一個 target 路徑，怎麼沿委派樹一層層 `GetRolesForTarget` 找到負責角色、`VerifyDelegate` 驗簽、並拒絕『下層宣稱父角色沒授權的路徑』的越權」。情境：一個被攻陷的下層委派角色，試圖簽一筆超出它 `Paths` 的 target，示範消費端解析為何**不採信**、以及委派解析的**順序**為何是安全關鍵（承今天第五節伏筆與那則 advisory）。明確不重述今天發行端的委派授權與 hash bin 分片、不重述 Day101 頂層 threshold 驗證，聚焦消費端的**委派樹遍歷、截斷語意、路徑逃逸防禦與 cycle／visited 保護**。標為延伸篇，委派的消費端解析首次介紹。）
