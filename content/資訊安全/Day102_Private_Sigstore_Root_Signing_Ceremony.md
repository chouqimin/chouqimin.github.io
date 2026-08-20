---
title: "Day 102：自己當根之前先想清楚——自建 Sigstore／TUF 信任根的金鑰儀式、離線門檻保管與輪替治理"
date: 2026-08-14
tags: ["Sigstore", "TUF", "金鑰儀式", "供應鏈安全"]
---

接續 Day101 預告：昨天把 TUF 信任根「怎麼運作、client 怎麼驗」講完了——threshold 多簽、root rotation 的補鏈、TOFU 開機、四角色分離、金鑰折損復原。那一整套的前提其實只有一句話：**有一份 `root.json`，是「某些人拿某些金鑰簽出來的」。** 昨天我們站在 client 那端問「我憑什麼相信這份 root」；今天換到發行端問一個更重的問題：**那些金鑰是誰產的、放哪、怎麼簽、被偷了誰有權救？**

這正是 Day101 第七、第十節末尾點名、卻刻意留給今天的：當你不能只用公信 Sigstore 公有實例、必須**自建一套私有信任根**時，那幾把離線 root 金鑰的**儀式（key ceremony）與治理**怎麼落地。

**這篇不重述 Day101 的機制。** threshold 驗證演算法、root rotation 的「舊門檻 AND 新門檻都要簽」迴圈、TOFU 補鏈規則、`clearMetaDueToKeyRotation`——那些是 client 與庫的事，昨天講完了，今天不再開一次。今天只聚焦三條**人與流程**的線：

1. **金鑰儀式**——root 金鑰為什麼要離線產生、門檻多人各持一份、簽署要在受控環境並全程留證。
2. **線上 vs 離線角色的自動化邊界**——哪些金鑰可以上線自動重簽，哪些必須離線人工，這條線怎麼切。
3. **自建的信任治理與退場**——自己當根＝公信生態的外部制衡不在了，怎麼用「儀式留證＋門檻＋稽核」補回來，以及**什麼時候根本不該自建**。

安全主軸先講在前面：**公信實例幫你把 root 儀式外包了；自建就是把這份最重的責任攬回自己身上——攬得起再自建，攬不起就別動手去拆別人已經幫你顧好的那顆釘子。**


## 一、先問「該不該自建」——退場決策放最前面

大多數團隊的正確答案是**不要自建**。把這題放第一節，是因為它比後面所有技術細節都重要：一旦決定自建，你就把「Sigstore 五位 keyholder＋一整套公開儀式」的責任，換成「你們公司三個人＋一份沒人審過的內部流程」。

什麼情況**才**該自建私有信任根：

- **完全離線／氣隙環境**：機器連不到 `tuf-repo-cdn.sigstore.dev`，公信 TUF repo 根本抓不到（這時你需要的是「自建 mirror」，不一定是「自建 root」，兩者差很多，見第八節）。
- **法遵要求信任根在自己掌控內**：某些主權雲、金融、軍工情境不接受「信任根的離線金鑰在別家公司手上」。
- **你要簽的根本不是 container image**：你把 TUF 拿來發自家的韌體、ML 模型、設定檔信任根，跟 Sigstore 的公有實例沒關係。

什麼情況**不**該自建，卻很多人衝動自建：

- 「我只是想用自己的 Fulcio／Rekor」——這通常只需要**自建元件＋沿用信任根散布機制**，甚至可以繼續用公信 TUF root 當外框，不需要自己跑 root 儀式。
- 「公信 root 我不放心」——你自建的 root，離線金鑰保管、門檻、輪替、稽核**很可能比 Sigstore 那套公開流程更糟**，只是換成你看不到自己的破綻而已。

**退場條款要在自建那天就寫好**（承 Day35 資產生命週期的精神）：什麼條件下停止自建、把信任根遷回公信實例或收掉私有 repo、離線金鑰如何銷毀留證。信任根最怕的不是被攻破，是「當初誰決定自建的人都離職了，沒人敢動、也沒人知道怎麼退」。


## 二、公信實例到底幫你外包了什麼

把 Day101 那份 `root.json` 從「client 怎麼驗」翻到背面，看「發行端做了什麼」。以 Sigstore 公有實例為例（這些是公開資訊，你自建時就是要親手重做一遍）：

- **root 是 3-of-5 門檻**：五位來自不同公司與學術機構的 keyholder，各自持一把離線硬體金鑰；要動 `root.json`（改 key、改門檻、改效期），至少要湊到 5 把裡的 3 把簽名。
- **root 金鑰離線、放在硬體上**：keyholder 用 **YubiKey**（PIV 的 Digital Signature slot）簽，私鑰**永遠不落地成檔案**。
- **一年簽幾次、有排程也有臨時**：正常一年約 2～3 次 signing event（換效期、輪金鑰），外加突發事件（某把金鑰疑似外洩就緊急輪替）。
- **儀式跑在 CI 上、全程公開留證**：現在用的是 `tuf-on-ci` 工具，signing event 就是 `sigstore/root-signing` repo 裡的一個 PR——每位 keyholder 在本機插 YubiKey 簽名、推一個 `sign/*` 分支、開 PR，門檻湊齊才 merge。每一次簽署都是 git 歷史上一筆可稽核的紀錄。

看清楚這張清單，你就懂「自建」的重量：上面每一條——找齊門檻人數、每人一把硬體金鑰、離線保管、排程與臨時儀式、全程留證——**都要你自己重建一套**。這不是寫程式，是**治理與流程**。


## 三、金鑰儀式（key ceremony）在幹嘛——與 Day83 的異同

金鑰儀式的本質，是把「產生並使用最高權限金鑰」這件事，從「某工程師在自己筆電上跑個指令」升級成**一場多人見證、全程留證、離線進行的受控活動**。它要同時滿足三件看似衝突的事：

- **離線產生**：root 私鑰在氣隙或硬體內產生，從不以明文檔案存在於任何連網機器（承 Day15 祕密管理的最高等級）。
- **門檻分持**：不讓任何單一個人能獨立動用 root。5 選 3 的意義是——偷一把、丟一把都不致命，但要湊齊 3 把才有事（這正是 Day101「threshold 讓被偷一把還不致命」的發行端對應）。
- **全程留證**：誰、在什麼時間、對哪個版本、用哪把金鑰簽了什麼，都要留下可事後稽核的證據。

**跟 Day83「SPIRE Server 的 upstream CA／簽發金鑰 HSM」是表兄弟，但管的東西不同：**

| 面向 | Day83 SPIRE CA 金鑰 | Day102 TUF root 金鑰 |
|---|---|---|
| 保護對象 | 一把 CA 簽發金鑰 | root／targets／snapshot／timestamp 四個角色、多把金鑰 |
| 使用頻率 | 線上、常態簽發 SVID | root 離線、一年動幾次 |
| 保管 | HSM／KMS，服務常態存取 | 離線硬體＋門檻多人分持，人工動用 |
| 折損影響 | CA 被偷＝可冒簽任意 workload 身分 | root 被偷＝可改寫整個信任根（更上游） |

同樣是「金鑰保管」，Day83 管的是**一把常態上線的 CA 金鑰**，靠 HSM／KMS 的存取控制；今天管的是**四個角色、上線程度天差地別的一組金鑰**，靠離線＋門檻＋儀式。别把 CA 那套「丟進 KMS 就好」直接套到 root 上——root 金鑰的威脅模型是「一年碰幾次、碰一次影響全世界」，它該離線分持，不該像 CA 金鑰那樣掛在一個服務帳號下隨傳隨到。


## 四、線上 vs 離線角色：自動化邊界怎麼切

這是自建運維最容易做錯、也最能體現「你懂不懂 TUF」的一節。TUF 四角色的效期與重簽頻率天差地別，這條線直接決定「哪些金鑰能上線自動化、哪些必須離線人工」：

| 角色 | 效期 | 重簽頻率 | 金鑰上線程度 | 該不該自動化 |
|---|---|---|---|---|
| `root` | 以**年**計 | 一年幾次 | **離線**、門檻硬體 | 不自動化，人工儀式 |
| `targets` | 數週～數月 | 有新 target 才動 | **離線**（或半離線） | 原則不自動，看規模 |
| `snapshot` | 短 | 每次 repo 有變就重簽 | **線上** | 必須自動化 |
| `timestamp` | **以天／小時計** | 頻繁、到期就要重簽 | **線上** | 必須自動化 |

心法一句話：**effort 跟威力成反比。** 威力最大的 `root`（能改信任根本身）動得最少、關在離線硬體與門檻後面；`timestamp` 威力被刻意關到最小（它只能宣告「這是最新的」，擋 freeze 攻擊），代價是它要頻繁重簽——所以它**必須上線自動化**，不可能一天叫五個 keyholder 插 YubiKey 一次。

切這條線的兩個鐵律：

1. **線上金鑰只能是「威力被關小」的角色**（snapshot／timestamp）。一旦你為了省事把 targets 甚至 root 金鑰也放上線自動簽，等於把最高權限金鑰暴露在你 CI 的攻擊面下——CI 被入侵就直接改信任根，Day18 供應鏈那一整套白防。
2. **線上金鑰用 KMS 託管、私鑰永不落地。** snapshot／timestamp 的簽署金鑰放 GCP KMS／AWS KMS，程式只拿到「簽名能力」而非私鑰本身。

線上角色的自動重簽（timestamp 到期前重簽）用維護中的 `go-tuf/v2` 就能寫成排程。以下是**線上 timestamp 重簽**的骨架——注意它跟 Day101 client 端完全是兩回事，這是 repo／發行端 API（`github.com/theupdateframework/go-tuf/v2/metadata`）：

```go
package main

import (
	"crypto"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// 線上角色（timestamp）的自動重簽：排程每隔一段時間跑一次，趕在到期前產新版。
// 這裡示範用本機金鑰載入 signer；生產環境要把它換成 KMS 託管的
// SignerVerifier（sigstore 的 pkg/signature/kms），私鑰永遠不出 KMS。
func resignTimestamp(ts *metadata.Metadata[metadata.TimestampType],
	snapshotVersion int64, onlineKey crypto.PrivateKey) error {

	// 1) 指到最新 snapshot、bump 版本（版本嚴格遞增，防 rollback，承 Day101）
	ts.Signed.Meta["snapshot.json"] = metadata.MetaFile(snapshotVersion)
	ts.Signed.Version += 1

	// 2) 續命：短效期是 timestamp 擋 freeze 的關鍵，別為了少跑幾次把它拉長（承 Day78/99）
	ts.Signed.Expires = time.Now().AddDate(0, 0, 1).UTC() // 以「天」計

	// 3) 用線上金鑰重簽（清掉舊簽章再簽）
	signer, err := signature.LoadSigner(onlineKey, crypto.Hash(0))
	if err != nil {
		return err
	}
	ts.ClearSignatures()
	if _, err := ts.Sign(signer); err != nil {
		return err
	}

	// 4) 落地發佈
	return ts.ToFile("timestamp.json", true)
}
```

**離線角色的 root 儀式不寫成這種 app 程式——它是人工流程＋專用工具。** 這正是給後端工程師的重要提醒：**別在你的 Java／Go 服務裡手刻 root 簽署。** 離線儀式用 `tuf-on-ci` 這類專用工具跑，keyholder 在本機插 YubiKey、簽名、開 PR，門檻湊齊 merge。設定「誰是簽署人、門檻幾把、效期多久、哪些角色走線上金鑰」是一條 CLI：

```bash
# 設定／變更角色的簽署人、門檻、效期與線上金鑰（在 signing event 分支上跑）
tuf-on-ci-delegate <event-branch> root
# 互動式問你：root 的 keyholder 有誰、threshold 幾把、root.json 效期多久……
# snapshot/timestamp 則設成由某把線上（KMS）金鑰負責
```

給 JVM 工程師的落地形態（呼應 Day80／81 那條「Java 1.8 跑不動就把它挪出去」的老規矩）：**root 儀式不是應用程式的職責。** 你的 Spring 服務是 Day101 那個**消費端**（用 `sigstore-java` 的 `dev.sigstore.tuf.Updater` 抓並驗 root），儀式與 repo 維運交給 `tuf-on-ci`（Python CLI＋硬體金鑰）或 `go-tuf`。硬要在 JVM 裡自動化線上角色，也是 shell out 去呼叫這些維護中的工具，而不是自己拿 Bouncy Castle 手刻 TUF 簽章——手刻必漏，這條規則從 Day101 到今天沒變。


## 五、`root.json` 的角色金鑰與 threshold 設定

把上面兩節落到組態上。一份 `root.json` 的核心就是「哪些金鑰、各角色門檻多少」。下面是簡化但符合規格的骨架，重點在**標出離線硬體 keyid 與線上 KMS keyid 的分層**：

```json
{
  "signed": {
    "_type": "root",
    "spec_version": "1.0.31",
    "version": 3,
    "expires": "2027-08-14T00:00:00Z",
    "keys": {
      "a1b2…(offline / YubiKey #1)": { "keytype": "ecdsa", "scheme": "ecdsa-sha2-nistp256", "keyval": { "public": "…" } },
      "c3d4…(offline / YubiKey #2)": { "keytype": "ecdsa", "scheme": "ecdsa-sha2-nistp256", "keyval": { "public": "…" } },
      "e5f6…(offline / YubiKey #3~#5)": { "keytype": "ecdsa", "scheme": "ecdsa-sha2-nistp256", "keyval": { "public": "…" } },
      "77aa…(online / KMS: snapshot)": { "keytype": "ecdsa", "scheme": "ecdsa-sha2-nistp256", "keyval": { "public": "…" } },
      "88bb…(online / KMS: timestamp)": { "keytype": "ecdsa", "scheme": "ecdsa-sha2-nistp256", "keyval": { "public": "…" } }
    },
    "roles": {
      "root":      { "keyids": ["a1b2…","c3d4…","e5f6…", "..."], "threshold": 3 },
      "targets":   { "keyids": ["…offline…"],                    "threshold": 2 },
      "snapshot":  { "keyids": ["77aa…(KMS)"],                   "threshold": 1 },
      "timestamp": { "keyids": ["88bb…(KMS)"],                   "threshold": 1 }
    },
    "consistent_snapshot": true
  },
  "signatures": [
    { "keyid": "a1b2…", "sig": "…" },
    { "keyid": "c3d4…", "sig": "…" },
    { "keyid": "e5f6…", "sig": "…" }
  ]
}
```

三個一定要看懂的設計：

- **`root` 門檻 ≥ 3、且 keyids 全是離線硬體金鑰。** 這是整份檔案唯一「動它要開儀式」的角色。門檻別設 1（等於單點）、也別把全部 keyid 設成門檻（丟一把就永遠簽不出來，救不回來）。5 選 3 是「容忍丟 2 把、容忍偷 2 把」的平衡點。
- **`snapshot`／`timestamp` 的 keyid 是線上 KMS 金鑰、門檻 1。** 它們要頻繁自動重簽，門檻多簽在這裡沒意義（反正都在同一套自動化裡），威力也被關小。
- **`signatures` 陣列裡至少要有門檻數量、且來自授權 keyid 的有效簽章**——這就是 Day101 client 端驗的東西，今天你是**產出**它的人。

用 `go-tuf/v2` 建立與輪替時，加金鑰、設門檻、離線分持簽署都有對應 API（這些是我實際核對過官方 `examples/repository/basic_repository.go` 存在的呼叫，非杜撰）：

```go
// 建 root、把每位 keyholder 的「公鑰」加進 root（私鑰留在各自硬體，永不集中）
root := metadata.Root(expiresInOneYear)
root.Signed.AddKey(keyholder1Pub, "root")
root.Signed.AddKey(keyholder2Pub, "root")
// … 共 5 把
root.Signed.Roles["root"].Threshold = 3      // 3-of-5

// 離線門檻簽署（out-of-band）：每位 keyholder 各自讀檔、簽、寫回同一檔，湊到門檻為止
root.FromFile("3.root.json")
root.Sign(keyholderSigner)                    // 你這把
root.ToFile("3.root.json", true)              // 傳給下一位再簽

// 驗證門檻是否已滿足（產出前自檢）
root.VerifyDelegate("root", root)
```

`AddKey` 只吃**公鑰**——這句話是門檻分持的靈魂：root 的私鑰從頭到尾散在五個人的硬體裡，`root.json` 只收集公鑰與各人的簽名，**沒有任何一台機器同時握有門檻數量的私鑰**。


## 六、離線門檻 root 金鑰的保管治理

金鑰產出來只是開始，保管才是長期戰。這一節全是**治理**，不是程式（承 Day15，但拉到「皇冠寶石」等級）：

- **硬體、離線、門檻分持。** 每把 root 金鑰在一個硬體 token（YubiKey PIV／HSM）內產生、不可匯出；由不同的人、最好在不同地理位置持有。門檻（如 3）要 < 總數（如 5），才同時擋得住「偷一把」和「丟一把」。
- **保管方式要有明文記錄。** 誰持有哪把、放哪個保險庫、備援在哪、緊急聯絡人是誰——這份清單本身要納入稽核（承 Day101 Code Review checklist 那條「保管方式有明文記錄」）。沒寫下來的門檻＝人一走就少一把、卻沒人知道。
- **緊急輪替的授權要事先定義。** 「某把 root 金鑰疑似外洩，誰有權發起緊急 signing event、湊哪幾把簽掉它」——這要在事故發生**前**就寫進 runbook。事故當下才在問「這把是誰保管的」就太慢了。復原機制本身 Day101 講過（root 被偷＝門檻內其他金鑰簽新版把它踢掉），今天補的是**發起這個動作的治理授權**。
- **儀式要留證。** 每次動 root 都留下：哪個版本、改了什麼（加/撤哪把 key、門檻變動、效期）、誰簽的、什麼時間。用 `tuf-on-ci` 時這天然就是 git PR 歷史；自己土炮時，這份證據鏈要另外建，而且要防竄改（承 Day16 audit log 防竄改）。

一個最常見的自建災難，是**把 5 選 3 做成「3 把金鑰都在同一台離線機器、同一個保險箱」**。這在密碼學上是 3-of-3、在物理上是 1-of-1——一次入侵、一場火災就全沒了。門檻的價值來自**分散**，把它們集中保管等於把門檻退化成單點。


## 七、自建 = 失去外部制衡，用儀式＋門檻＋稽核補回

這是自建最隱形、也最該想清楚的代價。回顧 Day77：公開 CA 有 Certificate Transparency 當「全世界都看得到你簽了什麼」的外部監視器，內部 CA 沒有——是盲區。**自建 TUF 信任根是一模一樣的處境**：公信 Sigstore 的 root 儀式跑在公開 repo、任何人都能稽核那 3-of-5 是不是真的照規矩來；你自建的 root，**沒有任何外人在看**。

失去的外部制衡，只能用內部機制補回：

- **儀式全程留證且可稽核**（第六節）——把「沒人在外面看」換成「至少我們自己留了防竄改的完整紀錄」。
- **門檻分持強制多人參與**——把「一個管理員說了算」換成「要串通門檻數量的人才作得了惡」，抬高內部作惡門檻。
- **把信任根健康接進 SIEM**（第九節）——把「沒人監控」換成「root 版本跳變、門檻被調低、效期異常都會告警」。

**最誠實的補法是：別自建。** 如果你自建後，這三樣（留證、門檻、稽核）沒有一樣做得比 Sigstore 公開流程好，那你只是把一個有外部監督的信任根，換成一個沒人看得到破綻的信任根——風險不是降低了，是被藏起來了。


## 八、client 怎麼 bootstrap 你的自建 root（承 Day101 TOFU）

repo 建好了，client 端怎麼信任它？這裡接回 Day101 的 TOFU：**第一份 root 沒有更舊版可驗，只能靠帶外管道拿到並 pin 指紋。** 自建情境下，這一步就是叫 client 用 `cosign initialize` 指到你的 mirror 與 root（旗標我核對過 `cosign initialize` 官方文件確實存在）：

```bash
# 讓 client 信任「你自建的」TUF 信任根，而不是公信實例
cosign initialize \
  --mirror  https://tuf.internal.example.com \
  --root    ./root.json \
  --root-checksum sha256:<第一份 root 的預期指紋>
# 快取寫進 $HOME/.sigstore/root/；之後 client 靠 TUF rotation 自動追新版
```

兩個接回 Day101 的重點：

- **`--root-checksum` 就是 TOFU 的 pin。** 若 root 是透過 http(s) 抓的，這個 checksum 是必填——這正是 Day101「第一份 root 靠帶外＋pin sha256」的指令化。CI 要斷言「內嵌／發下去的第一份 `root.json` 的 sha256 == 預期值」，換它必須是一次過審的 commit。
- **`--mirror` 指到自建 repo URL＝新的 SSRF／供應鏈攻擊面**（承 Day101 第九節、Day10）：這個 URL 要釘死受審、不吃動態輸入，client 出站走 egress allowlist，別讓被 SSRF 的服務借你的 client 去打內網。

**這裡也回答第一節那個伏筆：「自建 mirror」≠「自建 root」。** 很多氣隙需求其實只需要把公信的 `root.json` 帶外搬進來、自己架一個 mirror 同步 metadata 與 targets（`--mirror file:///…` 或內網 URL），**繼續用 Sigstore 那份公開儀式簽出來的 root**。這樣你拿到離線可用性，卻不必自己扛 root 儀式——絕大多數「我要離線」的團隊，要的是這個，不是自己當根。


## 九、Day16 稽核：把儀式與線上角色掃成 CI／排程

承 Day16、也承 Day101 第十節那句「monitor 掛了跟沒壞事長一樣」——信任根的維運健康要主動掃，分兩類：

**組態掃描（靜態，CI）：** 斷言 `root` 門檻 ≥ 你的下限（別讓某次改動偷偷把門檻調成 1）、`root`／`targets` 的 keyid 全是離線金鑰（沒有線上 KMS keyid 混進高權角色）、線上角色只有 snapshot／timestamp、第一份 root 指紋與預期相符、mirror URL 是釘死常數。這些 Go／Java 都能寫成單元測試：解析 `root.json`、比對 `roles[*].threshold` 與 `keyids`、算 sha256。

**執行期掃描（排程）：** 監控 `root`／`timestamp` 的**剩餘效期比例**（不是固定天數）與線上重簽的成功率——**timestamp 長時間沒更新，跟「repo 沒事」在儀表板上長得一模一樣**，所以線上重簽**成功也要記指標**，並對「N 小時內沒有一次成功重簽」告警（承 Day79、Day100、Day101 同一個道理）。

進 SIEM 的訊號（承 Day16）：`root 版本跳變`（尤其大幅前進＝可能發生過緊急輪替，值得人看一眼）、`root/targets 門檻被調低`（危險訊號）、`root/timestamp 效期即將到期`、`線上重簽連續失敗`、`第一份 root 指紋不符`、`signing event 缺少門檻數量的簽名卻被 merge`（儀式被繞過）。

**CI 靜態掃不到、只能靠治理補的**：那 5 把離線金鑰到底怎麼保管、輪替儀式誰主持、被偷了誰有權簽緊急 root——這些是第六節那份流程與盡職調查，不是字串比對。**這也是自建與公信最大的差別：公信把這塊外包了，自建就是你自己的責任。**


## 十、常見誤區

- **「自己當根比較安全，信任根在我手上。」** 通常相反——你的離線保管、門檻、輪替、稽核很可能比公信的公開流程更糟，只是破綻換成你自己看不到。
- **「我要離線，所以要自建 root。」** 混淆了「自建 mirror」與「自建 root」。離線多半只需前者，繼續用公信簽出來的 root（第八節）。
- **「root 金鑰丟 KMS 就好，跟 Day83 的 CA 一樣。」** CA 金鑰常態上線、靠 KMS 存取控制；root 一年動幾次、影響全世界，該離線＋門檻分持，不是掛個服務帳號隨傳隨到。
- **「5 選 3，那我把 3 把放同一台離線機器最方便。」** 物理上退化成單點，一次入侵／一場火災全沒。門檻的價值來自分散。
- **「timestamp 金鑰放線上很危險，應該也離線。」** timestamp 本來就設計成線上頻繁重簽、威力被關到只能擋 freeze；離線反而讓它沒法頻繁更新，freeze 窗口變大。
- **「targets 也自動簽比較省事。」** 那是把高權角色暴露在 CI 攻擊面下，CI 被入侵就直接改信任內容。只有 snapshot／timestamp 該上線。
- **「root 簽署我在服務裡用 Bouncy Castle 手刻就好。」** 手刻門檻／效期／rotation 必漏（Day101 的老話）；儀式用 `tuf-on-ci`、repo 用 `go-tuf`，你的 JVM 服務只當消費端（`sigstore-java`）。
- **「自建了就一勞永逸。」** 沒有退場條款的信任根最危險：決策者離職、沒人敢動、也沒人知道怎麼退回公信。


## 十一、Code Review／治理 checklist

- **決策層**：有白紙黑字的「為什麼自建」與**退場條款**；能明確說出「不自建、改用公信實例或自建 mirror」的替代方案為何被否決（第一、八節）。
- **金鑰儀式**：root 金鑰**離線硬體產生、不可匯出**，`AddKey` 只進公鑰；門檻 < 總數（如 3-of-5）；離線金鑰**由不同人、不同地點分持**，不集中在一台機器（第五、六節）。
- **自動化邊界**：線上金鑰**只有** snapshot／timestamp，且託管在 KMS 私鑰不落地；`root`／`targets` 的 keyid **沒有**任何線上金鑰混入（第四、五節）。
- **保管治理**：金鑰持有人／保管處／備援／緊急聯絡人**有明文記錄並納入稽核**；緊急輪替的發起授權**事先定義在 runbook**（第六節）。
- **留證與制衡**：每次動 root 都有**防竄改、可稽核**的完整紀錄（誰、何時、改什麼、幾把簽的）；用 `tuf-on-ci` 走 PR 天然留證（第六、七節）。
- **client bootstrap**：第一份 root **帶外＋pin sha256**（`--root-checksum`）、換它要過 Code Review 與告警；mirror URL **釘死不吃輸入、出站走 egress allowlist**（第八節，承 Day10／101）。
- **稽核上線**：門檻下限、效期剩餘比例、線上重簽成功率都有指標與告警；「重簽成功也記指標＋N 小時未成功告警」（第九節，承 Day16）。


## 十二、測試與演練怎麼做

信任根這層「測試」很多是**演練**——你要證明「壞的簽署進不來」「儀式被繞過會被抓到」：

- **門檻不足擋得下**：拿一份「只湊到 threshold−1 把有效簽章」的 `root.json`，斷言你的 CI／消費端拒收（門檻的存在證明，承 Day101／Day100「守門員存在證明」）。
- **未授權金鑰不算數**：用一把「不在 `root` keyids 內」的合法金鑰簽 root，斷言不被計入門檻。
- **高權角色混入線上金鑰會 fail**：CI 斷言 `root`／`targets` 的 keyid 若出現任何已知的線上 KMS keyid，測試直接紅（第九節組態掃描）。
- **門檻被調低告警**：把 `root` threshold 從 3 改成 1 的變更，斷言 CI／SIEM 會標記為危險訊號。
- **第一份 root 指紋**：CI 斷言發下去的第一份 `root.json` 的 sha256 == 預期，改動即 fail（承 Day101 TOFU）。
- **線上重簽失效演練**：停掉 timestamp 自動重簽排程，斷言「N 小時未成功重簽」告警會叫，而不是靜靜地讓 timestamp 過期（偵測型控制的存在證明）。
- **緊急輪替桌面演練**：假設「keyholder A 的金鑰外洩」，實際走一遍 runbook——湊得齊門檻嗎？發起授權清楚嗎？多久能簽出把 A 踢掉的新 root？演練的目的是在**真出事前**發現流程的洞。
- **退場演練**：實際試一次「把信任根從自建切回公信實例／自建 mirror」，確認離線金鑰銷毀留證、client 重新 `initialize` 的流程走得通。


## 十三、一句話總結

> Day101 講「TUF 信任根怎麼運作、client 怎麼驗」；今天講「當你必須自己當根，那幾把離線 root 金鑰的**儀式與治理**怎麼落地」。三條線：**① 金鑰儀式**——root 金鑰離線硬體產生、門檻多人各持（如 5 選 3、YubiKey）、簽署全程受控留證，`AddKey` 只收公鑰讓私鑰永不集中；跟 Day83 SPIRE CA 金鑰是表兄弟，但管的是四角色、上線程度天差地別的一組金鑰，不是一把常態上線的 CA。**② 自動化邊界**——威力跟 effort 成反比：`root`／`targets` 離線人工、`snapshot`／`timestamp` 線上 KMS 自動重簽（用 `go-tuf/v2` 排程，`sigstore-java` 只當消費端），把高權角色放上線＝自己把信任根接到 CI 攻擊面。**③ 治理與退場**——自建＝失去 CT／公信生態那種外部制衡（承 Day77 內部 CA 盲區），只能用「儀式留證＋門檻分持＋稽核上線」補回；而最誠實的補法往往是**別自建**：先問「自建 mirror 夠不夠」，退場條款在自建那天就寫好。一句話：**公信實例幫你把最重的 root 儀式外包了；自建就是把這份責任攬回自己身上——攬得起再自建，攬不起，就別去拆別人已經幫你釘好的那顆釘子。**


## 延伸閱讀

- **Day101 TUF 信任根散布／輪替**——今天的前提。昨天講機制（threshold 驗證、rotation 補鏈、TOFU、折損復原），今天講「產出那份 root 的人與流程」，明確不重述昨天的驗證演算法與 rotation 迴圈。
- **Day83 SPIRE Server upstream CA／HSM**——同樣是最高權限金鑰保管，但那是一把常態上線的 CA 金鑰；今天是四角色、離線門檻的一組金鑰，威脅模型不同。
- **Day77 Certificate Transparency／內部 CA 盲區**——自建信任根＝失去外部制衡，跟內部 CA 沒有 CT 是同一種盲區，補法也同構（留證＋稽核）。
- **Day15 祕密管理**／**Day16 監控**——root 離線金鑰是皇冠寶石等級的祕密；儀式留證、門檻、效期、重簽成功率全進 SIEM。
- **Day10 SSRF**——自建 mirror／repo URL 是 client 週期性主動去連的外部位址：釘死、egress allowlist、size／timeout。
- **Day80／Day81 SPIFFE**——「Java 1.8 跑不動就把它挪出去」與「別為了跑起來自己拆信任根」，在 root 儀式這層一模一樣：儀式交給 `tuf-on-ci`，JVM 服務只當消費端。

---

明天預告：**Day 103 — root 顧好了，但 targets 一把金鑰要簽上萬個檔案也太危險——TUF targets 委派與 hash bin delegation：把簽署權往下分，縮小 targets 金鑰的爆炸半徑**
（這是**全新主題**，承今天第四節「targets 角色」與 Day101「四角色分離、爆炸半徑」——但那些講的都是**頂層四角色**之間的分離，明天往下鑽一層：`targets` 底下的**委派（delegation）**。情境：一個私有 artifact／模型 registry 有成千上萬個 target，如果全部由單一 `targets` 金鑰簽，這把金鑰就成了新的高價值單點。明天示範用 `go-tuf/v2` 的 `Delegations`／`DelegatedRole`（`Paths`、`Terminating`、`Threshold`）把 `*.jar` 委派給團隊角色、用 **hash bin** 把上萬個 target 分片委派，讓「一把委派金鑰被偷」只影響它負責的那一小段路徑，而不是整個 repo——把 Day101 的「爆炸半徑」概念從頂層四角色推進到 targets 樹狀委派。明確不重述今天的 root 儀式與離線保管，聚焦 targets 以下的委派拓撲、路徑約束與 blast radius 收窄。這是全新主題，`targets` 委派首次介紹。）
