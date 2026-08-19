---
title: "Day 108：離線模式靠「版本單調遞增」擋 rollback，但攻擊者不回滾、反而把版本號往未來灌呢？——TUF fast-forward attack（快轉攻擊）與復原：你的回滾防禦如何被反噬成永久凍結、go-tuf 的 `MaxRootRotations` DoS 護欄、以及 repo 端的 key 輪替復原動線"
date: 2026-08-20
tags: ["TUF", "供應鏈安全", "fast-forward-attack", "金鑰折損復原"]
---

接續 Day107 預告：昨天講離線／氣隙模式時，rollback 防禦的核心是「版本單調遞增」——client 記住手上最高版本當**下限**，任何更舊的版本一律拒收（Day105 的 `UpdateTimestamp`／`UpdateSnapshot`）。整個 Day105～107 都預設攻擊者想讓你「退回舊版」（rollback／freeze）。今天把攻擊方向反過來問：**如果偷到 timestamp／snapshot 線上金鑰的攻擊者不改任何內容、也不回滾，反而把版本號往「未來」灌成天文數字（例如 `2³²`）呢？** 你精心設計的「版本只能往上」的回滾下限，會不會反過來把你**永久凍結**在被偷的那一刻？

**這篇是延伸／接續，不是重新介紹 TUF。** 明確不重述 Day105 的版本單調／過期規則本身，也不重述 Day107 的離線流程。**fast-forward attack（快轉攻擊）這個攻擊面在本系列是首次介紹。** 今天的延伸角度只有一個：**把鏡頭從「版本太舊被擋」翻到「版本被灌太新、反被你自己的 rollback 防禦鎖死」——快轉攻擊怎麼成立、回滾防禦怎麼被反噬、go-tuf 用什麼護欄擋住連帶的 DoS、以及 repo 端要靠什麼動線才能真正復原。**

安全主軸先講在前面：**快轉攻擊不是偽造內容，而是「污染版本空間」。它把 client 的 rollback 下限一次拉到天上，之後所有合法、正確、但版本較低的更新，都會被 client 自己的回滾防禦當成 rollback 拒收。這意味著單靠 client 端的版本規則救不了自己——真正的解藥是 repo 端用離線 root 金鑰輪替掉被偷的 timestamp／snapshot 金鑰（TUF 規範 5.3.11 的 fast-forward attack recovery），讓 client 手上那份被灌爆的舊 metadata「因為簽章失效而被丟棄」，才能重新接受低版本。short-lived timestamp 這個 Day105 用來擋 freeze 的良藥，在快轉場景下反而是加速你進入死狀態的陷阱。**

> 本文的 Go 範例對照 `github.com/theupdateframework/go-tuf/v2` 的 `master` 原始碼：`metadata/config/config.go` 的 `UpdaterConfig`（`MaxRootRotations`／`MaxDelegations`／`RootMaxLength` 等欄位與 `New()` 的預設值）、`metadata/updater/updater.go` 的 `loadRoot`／`loadTimestamp`，以及 `metadata/trustedmetadata/trustedmetadata.go` 的 `UpdateTimestamp`／`UpdateSnapshot`（含原始碼註解 `no need to check for 5.3.11 (fast forward attack recovery)`）。皆為實際存在的欄位、函式與註解，非杜撰。go-tuf/v2 為維護中版本，實務請釘在含修補的維護版（承 Day104 CVE-2024-47534／Day18 版本衛生）。


## 一、快轉攻擊：不偽造內容，只灌版本號

先把 Day105 的鐵律擺出來，因為快轉攻擊利用的正是它——`UpdateTimestamp` 的回滾檢查（實際原始碼）：

```go
// 若已有可信 timestamp，檢查是否為 rollback 攻擊
if trusted.Timestamp != nil {
    // 不准把 timestamp 版本往回退
    if newTimestamp.Signed.Version < trusted.Timestamp.Signed.Version {
        return nil, &metadata.ErrBadVersionNumber{...} // 新版 < 舊版 → 拒收
    }
    // 版本相同就繼續用舊的
    if newTimestamp.Signed.Version == trusted.Timestamp.Signed.Version {
        return nil, &metadata.ErrEqualVersionNumber{...}
    }
    // 連 timestamp 指向的 snapshot 版本也不准回滾
    ...
}
```

這條規則對 rollback／freeze 完全正確：**client 記住手上最高版本 V，之後只接受 ≥ V 的版本。** 現在換攻擊者視角。

timestamp 與 snapshot 用的是**線上金鑰**（online keys）——它們必須跟著每次發佈自動簽名，所以私鑰常駐在簽署服務裡，是整個 TUF 信任鏈中**最容易被偷**的一環（相對地，root 用離線／門檻金鑰，Day101／Day102）。假設攻擊者偷到 timestamp 金鑰，他**不需要偽造任何 target、不需要改任何雜湊**，只要做一件事：

> 把 timestamp 的 `version` 從當前的 `43` 簽成 `4294967295`（`2³²−1`），效期照樣簽有效，其餘欄位照抄。

這份 metadata 在 client 眼裡**完全合法**：簽章對（用的是還沒被撤銷的真金鑰）、沒過期、版本比手上高——`newTimestamp.Version(2³²) > trusted.Timestamp.Version(43)`，通過回滾檢查，**被接受並持久化成新的 rollback 下限**。攻擊者對 snapshot 同樣操作，甚至對 snapshot 記錄的每個 targets meta 版本一起灌。

到這裡，攻擊者**什麼壞內容都沒塞**。他只做了一件事：把你的版本地板抬到天上。


## 二、反噬：你自己的回滾防禦把你鎖死

災難發生在攻擊被發現、repo 端把漏洞修好、發佈新版之後。

repo 的正常版本計數器還停在 `44`、`45`……它發佈一份**完全合法、包含安全修補**的 `timestamp v44`。你的 client 抓到它，走進同一段 `UpdateTimestamp`：

```
newTimestamp.Version (44)  <  trusted.Timestamp.Version (4294967295)
→ ErrBadVersionNumber：new timestamp version 44 must be >= 4294967295
→ 拒收
```

**你自己的 rollback 防禦，把所有日後合法的低版本更新，全部當成 rollback 攻擊擋掉了。** client 從此凍結在「攻擊者灌爆的那一刻」，repo 再怎麼發新版都推不進來——除非 repo 也把版本號一路灌到 `2³²` 以上，但那樣就是在燒掉整個 `int64` 版本空間，而且下次再被快轉就無路可退。這就是快轉攻擊真正的殺傷力：**它不是讓你裝到假貨，而是讓你「再也裝不到真貨」——一種用你自己的安全機制實現的、持久化的阻斷服務（DoS）。**

對照 Day107 的離線場景會更清楚：離線包的 rollback 下限一旦被灌爆，你連「搬一包新的正版進去」都會被本地下限擋下——快轉攻擊在氣隙環境是特別難救的，因為沒有線上 root 輪替可以自動把舊金鑰撤掉。


## 三、為什麼 client 端救不了自己：`5.3.11` 這行註解的意思

你可能會想：那 client 端加一個「版本上限」不就好了？灌超過某個閾值就拒收？

**沒那麼簡單，而且 go-tuf／python-tuf 都刻意不這麼做。** 原因是：合法的 repo 也可能因為運維事故、資料庫遷移、或就是跑了很多年而讓版本號變得很大。client 無從分辨「大版本」是攻擊還是正常演進——任何硬編的數字上限都會誤殺合法 repo，或被攻擊者停在閾值以下繞過。所以 client 的版本欄位就是 `int64`，**沒有魔術上限**。

go-tuf 的 `UpdateTimestamp` 裡有一行很關鍵的原始碼註解，正是這件事的線索：

```go
// client workflow 5.3.10: Make sure final root is not expired.
if trusted.Root.Signed.IsExpired(trusted.RefTime) {
    // no need to check for 5.3.11 (fast forward attack recovery):
    // timestamp/snapshot can not yet be loaded at this point
    return nil, &metadata.ErrExpiredMetadata{Msg: "final root.json is expired"}
}
```

TUF 規範 §5.3.11 就叫 **fast-forward attack recovery**，它的原文動作是：**「載入新 root 後，如果 timestamp 和／或 snapshot 的金鑰被輪替了，就刪掉本地的 timestamp 與 snapshot metadata。」** 這行註解說「在 `UpdateTimestamp` 這個點不用做 5.3.11」——因為此刻 timestamp／snapshot 都還沒載入，**復原的觸發點不在版本判斷這裡，而在 root 更新那裡。** 換句話說：

> **快轉攻擊的解藥從來不是 client 端的版本邏輯，而是「root 輪替掉被偷的金鑰」這個 repo 端動作。**

這把責任交回給 repo：唯有 repo 用**離線 root 金鑰**（攻擊者偷不到）簽一份新 root、在裡面把 timestamp／snapshot 的公鑰換掉，client 才有辦法認出「手上那份灌爆的舊 metadata 是被撤銷的金鑰簽的」，進而丟棄它、重新接受低版本。


## 四、復原怎麼真的發生：root 輪替讓灌爆的舊 metadata「簽章失效」

看 go-tuf 的 `loadTimestamp`（線上 refresh，實際原始碼精簡版）就懂復原機制的物理原理：

```go
func (update *Updater) loadTimestamp() error {
    // 先試著讀本地 timestamp（可能是被攻擊者灌爆的那份 v=2³²）
    data, err := update.loadLocalMetadata(".../timestamp")
    if err == nil {
        _, err := update.trusted.UpdateTimestamp(data)
        if err != nil {
            if errors.Is(err, &metadata.ErrRepository{}) {
                // 本地 timestamp「驗簽失敗」→ 視為無效，不當下限，繼續往下抓 remote
                log.Info("Local timestamp is not valid")
            } else {
                return err
            }
        }
    }
    // 不論本地成不成功，都從 remote 抓一份新的
    data, _ = update.downloadMetadata(metadata.TIMESTAMP, ...)
    _, err = update.trusted.UpdateTimestamp(data) // 用「已載入的 root」驗這份 remote timestamp
    ...
}
```

關鍵在 `UpdateTimestamp` 內部這一句（Day105 講過）——**timestamp 是用「當前 trusted root」的金鑰去驗的**：

```go
err = trusted.Root.VerifyDelegate(metadata.TIMESTAMP, newTimestamp)
```

把整條復原動線串起來：

1. repo 偵測到 timestamp 金鑰外洩，用**離線 root 金鑰**簽一版**新 root**（`N+1`），在裡面把 `timestamp` 角色的公鑰換成一把全新的（舊金鑰作廢）。
2. client 下一次 `Refresh()` 先跑 `loadRoot()`，**逐版**把 root 從 `N` 補到 `N+1`（下一節詳談這個迴圈）。此刻 `trusted.Root` 已經是「認得新 timestamp 金鑰、不再認得舊金鑰」的版本。
3. client 讀本地那份被灌爆的 `timestamp v=2³²`——它是**舊金鑰**簽的。`VerifyDelegate` 對著**新 root** 驗，簽章對不上，回 `ErrRepository`。
4. `loadTimestamp` 把這個錯當成「本地 timestamp 無效」，**丟棄它、不拿它當 rollback 下限**，改抓 remote。
5. remote 那份是 repo 用**新金鑰**簽的、版本可能只是 `44` 的乾淨 timestamp。因為手上已經沒有「可信的舊 timestamp」當下限（第 3 步那份被判無效了），`44` 直接被接受。**復原完成。**

一句話：**快轉攻擊靠「金鑰還有效」讓灌爆版本被接受；復原就靠「輪替金鑰讓那份灌爆版本簽章失效」把它踢掉。** 這也是為什麼規範把 timestamp／snapshot 設計成線上金鑰、root 設計成離線門檻金鑰——**online 金鑰是拿來被偷之後可以輪替的那一層**，root 才是輪替它們的權威。復原不需要 client 端任何魔術版本上限，只需要 client 老實照 spec 用「當前 root」驗每一層。


## 五、連帶的 DoS：`loadRoot` 迴圈與 `MaxRootRotations` 護欄

上一節第 2 步「逐版把 root 補齊」藏著另一個攻擊面。看 `loadRoot` 的實際原始碼：

```go
func (update *Updater) loadRoot() error {
    // 下限＝手上 root 版本 +1；上限＝下限 + MaxRootRotations
    lowerBound := update.trusted.Root.Signed.Version + 1
    upperBound := lowerBound + update.cfg.MaxRootRotations

    for nextVersion := lowerBound; nextVersion < upperBound; nextVersion++ {
        data, err := update.downloadMetadata(metadata.ROOT, update.cfg.RootMaxLength,
            strconv.FormatInt(nextVersion, 10)) // 抓 <nextVersion>.root.json
        if err != nil {
            var tmpErr *metadata.ErrDownloadHTTP
            if errors.As(err, &tmpErr) && tmpErr.StatusCode == http.StatusNotFound {
                break // 404＝沒有更新的 root 了，正常收尾
            }
            return err
        }
        // UpdateRoot 內部強制 version 嚴格 +1、且要新舊 root 互簽（Day101）
        if _, err = update.trusted.UpdateRoot(data); err != nil {
            return err
        }
        update.persistMetadata(metadata.ROOT, data)
    }
    return nil
}
```

root 更新是**逐版補鏈**（Day101）：不能跳版，`N → N+1 → N+2`，每一版都要被前一版的門檻金鑰簽名認證。這對安全是必要的，但也開了一個 DoS 缺口：**如果攻擊者能對 root 也做快轉（把 root 版本號灌很高），或一個惡意 mirror 對每個 `<version>.root.json` 都回 200 拖著你，client 會不會被拖進一個幾十億次的下載迴圈？**

`MaxRootRotations`（`New()` 預設 **256**）就是這道護欄：**單次 refresh 最多往上追 256 個 root 版本**，追不完就停。這把「root 逐版補鏈」的成本封頂，擋住惡意 mirror 用無限 root 鏈把 client 拖死的 DoS。

同一組護欄還有兩層要記住：

- **`RootMaxLength` / `TimestampMaxLength` / `SnapshotMaxLength` / `TargetsMaxLength`**（預設 `512000` / `16384` / `2000000` / `5000000` bytes）——每個 metadata 下載都有長度上限，擋住「無限大 metadata」型 DoS。快轉攻擊常跟「灌大檔」一起出現，這層是配套。
- **`MaxDelegations`（預設 32）**——`preOrderDepthFirstWalk` 遍歷委派圖的上限（Day104）。targets 也可能被快轉（snapshot 記錄的 targets meta 版本被灌爆），委派層數封頂避免遍歷爆炸。

要講清楚一個**常見誤解**：`MaxRootRotations` **不是「版本號上限」**，它是「單次 refresh 追版本的次數上限」。它不會、也不能拒絕一份「版本號是 `2³²` 但簽章合法」的 metadata——**擋灌爆版本的是金鑰輪替（第四節），不是這個數字。** 這兩件事常被混為一談，Code Review 時要分清楚。


## 六、repo 端的復原動線：先輪替金鑰，別急著跳版

站在維運 repo 的後端工程師角度，被快轉之後**正確的復原順序**是：

1. **止血**：撤下被偷金鑰的簽署權限，確認攻擊者不能再簽新 metadata。
2. **輪替 online 金鑰（這是真正的解藥）**：用**離線 root 金鑰**簽一版新 root，把 timestamp／snapshot 的公鑰換成全新的。這一步一做，全 fleet 手上那些「舊金鑰簽的灌爆 metadata」在下一次 refresh 時全部簽章失效被丟棄（第四節）。**優先做這一步，而不是急著調版本號。**
3. **重新發佈乾淨 metadata**：用新金鑰簽 timestamp／snapshot／targets。因為 client 已經丟棄了灌爆的舊下限，你**不需要**把版本號跳到 `2³²` 之上——正常從 `44` 繼續即可。
4. **只有在「無法輪替金鑰」的退化情境**（例如某些 client 硬把舊金鑰簽的 metadata 快取住、或離線氣隙 fleet 收不到新 root）才會被迫走「版本跳到攻擊值之上」的下策——而這正是快轉攻擊把版本灌到接近 `int64` 上限的目的：**燒光你的版本空間，讓跳版復原這條路也走不通。** 所以「靠跳版復原」是陷阱，不是主線。

這也回答了昨天預告裡那句「短效期＋逐版補鏈同時是解藥也是陷阱」：

- **short-lived timestamp（Day105 擋 freeze 的良藥）在快轉場景是陷阱**：攻擊者灌爆版本、但效期照樣簽短。當那份灌爆的 timestamp 過期後，client `checkFinalTimestamp` 失敗 → 想抓 remote → 若金鑰**還沒**輪替，remote 的低版本又被 rollback 下限擋掉 → client 進入「舊的過期不能用、新的版本太低不給用」的**硬死狀態**，比純 freeze 更快壞。短效期讓你更快撞牆，逼你必須盡快完成金鑰輪替。
- **逐版補鏈的 root recovery（解藥）**：復原一定要靠 root 逐版傳達到 client；但 `MaxRootRotations` 把單次追版封頂在 256——若 fleet 長期沒 refresh、落後的 root 版本數超過 256，單次 refresh 補不齊，得多跑幾輪。護欄本身也是復原節奏的限制，要納入 runbook。


## 七、後端落地：Go client 的自保姿態

client 端你**改不動**核心邏輯（也不該改），但可以在外圍加偵測與硬失敗：

```go
cfg, _ := config.New(remoteURL, rootBytes)
cfg.MaxRootRotations = 256 // 保留預設，別為了「追得更遠」而無限放大 → 反而放大 DoS 面
up, _ := updater.New(cfg)

if err := up.Refresh(); err != nil {
    // 快轉的兩種徵兆都會在這裡冒出來：
    //  - ErrBadVersionNumber：remote 低版本被本地灌爆下限擋下（金鑰還沒輪替）
    //  - ErrExpiredMetadata：灌爆的舊 timestamp 過期、又補不進新版
    // 一律硬失敗＋告警，別靜默吞掉繼續跑
    alert("TUF refresh failed, possible fast-forward / recovery-in-progress", err)
    return err
}

// 自保偵測①：盯 timestamp 版本的「異常跳躍」當偵測訊號（非阻擋，阻擋交給金鑰輪替）
ts := up.GetTrustedMetadataSet().Timestamp.Signed.Version
if ts-lastSeenVersion > sanityJump { // 例如一次跳超過幾千版就可疑
    alert("TUF timestamp version jumped abnormally", ts, lastSeenVersion)
}

// 自保偵測②：帶外比對 root 指紋，確認自己拿到的是「有輪替掉被偷金鑰」的新 root
assertRootFingerprintMatchesOOBAnnouncement(up)
```

三個要點：`MaxRootRotations` **保留預設別放大**（放大＝把 DoS 面放大）；refresh 失敗**必為硬失敗**（承 Day107）；版本異常跳躍只當**偵測告警訊號**，真正的阻擋永遠是 repo 端金鑰輪替——client 端別自作聰明加硬版本上限誤殺合法 repo。


## 八、JVM 端：別手刻，交給 sigstore-java 的 Updater

延續整個 TUF 系列的立場：**Java 端不要自己實作 fast-forward recovery 的判斷。** sigstore-java 的 `dev.sigstore.tuf.Updater` 透明實作了完整 TUF client workflow（含 §5.3.10／§5.3.11 的語意、root 逐版輪替、rollback／過期檢查），你手刻只會刻錯——快轉攻擊的復原正是最容易漏掉的一段。落地要點跟前幾天一致：

- **金鑰輪替是 repo／發行端的責任**，不是 client 能補的。JVM client 只要老實跟著 root 走，被偷金鑰輪替後，舊金鑰簽的灌爆 metadata 一樣會在 `verifyDelegate` 這層簽章失效被丟棄——機制與 go-tuf 同源。
- **Java 1.8 跑不動** sigstore-java（需 JDK 11+）時，沿用系列老辦法：把 TUF 驗證挪成獨立 **sidecar**／前置工具（承 Day80／Day101），別在 1.8 服務裡硬塞半套實作。
- **版本衛生為主防線**：釘含修補的維護版、`govulncheck`／SBOM 當紅線（承 Day18／Day104）。fast-forward 這類邏輯漏洞的修補常常就藏在 client 函式庫的小版本裡。


## 九、常見誤區

- **「client 加個版本上限，超過就拒收，不就擋掉快轉了？」** 錯。合法 repo 也可能有大版本號，任何硬編上限不是誤殺就是被停在閾值下繞過。go-tuf／python-tuf 都刻意不做版本上限（第三節）。
- **「快轉是塞假貨。」** 不是。攻擊者一個 target、一個雜湊都沒改，只灌版本號；殺傷力是「日後真貨推不進來」的持久化 DoS，不是「裝到假貨」（第二節）。
- **「repo 把版本號跳到攻擊值之上就修好了。」** 那是下策，還會燒版本空間、給下次快轉留死路。真正的解藥是**輪替被偷的 timestamp／snapshot 金鑰**（第四、六節）。
- **「`MaxRootRotations` 就是擋快轉的護欄。」** 混淆了。它擋的是「root 逐版補鏈被拖成無限迴圈」的 DoS，**不擋灌爆的版本號**；擋灌爆版本靠金鑰輪替（第五節）。
- **「short-lived timestamp 對快轉也是好事，反正能擋 freeze。」** 反了。灌爆＋短效期會讓 client 更快進入「舊的過期、新的版本太低」的硬死狀態，逼你更快完成金鑰輪替（第六節）。
- **「timestamp／snapshot 金鑰被偷不算大事，反正沒 root 金鑰。」** 快轉攻擊證明只靠 online 金鑰就能造成持久化 DoS——online 金鑰折損必須觸發 root 輪替流程，不能只是「換把新 key 繼續簽、不動 root」。
- **「氣隙離線 fleet 也一樣救得回來。」** 最難救。離線沒有線上 root 輪替自動撤舊金鑰，被灌爆的本地下限得靠帶外重新 bootstrap（承 Day107）。


## 十、Code Review／設計 checklist（fast-forward attack）

- **online 金鑰折損的 runbook 明列「輪替 → 重發」順序**：timestamp／snapshot 金鑰疑似外洩時，第一動作是用離線 root 輪替公鑰，而不是換把 key 繼續簽（第六節）。
- **repo 復原不靠跳版**：復原流程不把版本號跳到攻擊值之上當主線；跳版只在「無法輪替金鑰」的退化情境，且明知會燒版本空間（第六節）。
- **client refresh 失敗必為硬失敗＋告警**：`ErrBadVersionNumber`／`ErrExpiredMetadata` 不得靜默吞掉；把「remote 低版本被本地下限擋」當成潛在快轉／復原進行中的訊號（第七節）。
- **不自作聰明加 client 版本上限**：阻擋交給金鑰輪替，client 端只做「版本異常跳躍」的偵測告警，不做硬拒收（第三、七節）。
- **`MaxRootRotations` 保留預設別放大**：放大追版次數＝放大 root 逐版補鏈的 DoS 面；長期不 refresh 的 fleet 落後超過 256 版要多輪補齊，寫進運維預期（第五、六節）。
- **length caps 保留預設**：`*MaxLength` 是「灌大檔」型 DoS 的配套護欄，別為省事關掉（第五節）。
- **root 指紋帶外比對**：client 有機制確認自己拿到的新 root「確實輪替掉被偷金鑰」，而不是還信任舊金鑰（第七節，承 Day107）。
- **氣隙 fleet 有帶外 bootstrap 通道**：離線環境救快轉需人工帶外換 root／清下限，寫進 runbook（第六節，承 Day107）。
- **版本衛生**：TUF client（go-tuf／sigstore-java）釘含修補維護版、`govulncheck`／SBOM 當紅線（承 Day18／104）。


## 十一、測試怎麼做

快轉這層的測試核心是**「灌爆版本會被接受（證明攻擊成立）→ 低版本被自己防禦擋死（證明反噬）→ root 輪替後灌爆的舊 metadata 簽章失效被丟棄（證明復原）」**：

- **攻擊成立（灌爆被接受）**：用有效金鑰簽一份 `timestamp version=2³²−1`、效期有效，斷言 `UpdateTimestamp` **接受**它並把它持久化成新下限——把「快轉能得逞」釘成明確事實。
- **反噬存在（低版本被擋）**:承上，再餵一份合法的 `timestamp version=44`，斷言回 `ErrBadVersionNumber`（`must be >= 4294967295`）、client 卡住——把「rollback 防禦反噬成 DoS」釘成明確事實。
- **金鑰輪替復原（核心）**：先讓 client 手上有「舊金鑰簽的 `v=2³²` timestamp」；接著載入一版「輪替掉 timestamp 公鑰的新 root」；再餵舊金鑰簽的那份灌爆 timestamp，斷言 `VerifyDelegate` 失敗（`ErrRepository`）→ 被判無效丟棄；最後餵新金鑰簽的 `v=44`，斷言**被接受**。這條測試證明「復原靠金鑰輪替、不靠版本邏輯」。
- **短效期加速死狀態**：讓灌爆的 timestamp 效期設短並用 `UnsafeSetRefTime` 撥到其過期後，且金鑰尚未輪替，斷言 client 既不能用過期的舊版、又拒收低版本 remote——驗證第六節的「硬死狀態」。
- **`MaxRootRotations` DoS 護欄**:mock 一個對每個 `<version>.root.json` 都回合法簽名的惡意 mirror（或回 200 但版本一直 +1），斷言 `loadRoot` 在追滿 `MaxRootRotations` 版後停止、不無限迴圈。
- **length caps 生效**:餵一份超過 `TimestampMaxLength` 的 timestamp，斷言下載階段即拒，不進驗簽。
- **root 指紋帶外比對觸發**:模擬「拿到的 root 未輪替被偷金鑰」，斷言帶外比對告警觸發（第七節）。


## 十二、一句話總結

> Day107 把離線模式的 rollback 下限講完（灌不進更舊的包）；今天把攻擊方向反過來——**攻擊者偷到 timestamp／snapshot 的線上金鑰後，不偽造任何內容，只把版本號簽成 `2³²` 這種天文數字**，這份 metadata 因為「簽章有效、沒過期、版本更高」而通過你 Day105 的回滾檢查、被接受成新的 rollback 下限，於是**日後所有合法但版本較低的更新，全被你自己的回滾防禦當成 rollback 拒收**，client 永久凍結在被偷的那一刻——這是一種用你自己的安全機制實現的、持久化的阻斷服務（DoS），而不是「裝到假貨」。關鍵在於 client 端救不了自己：合法 repo 也可能有大版本，任何硬編的版本上限不是誤殺就是被繞過，所以 go-tuf／python-tuf 都刻意不做版本上限，`UpdateTimestamp` 那行 `no need to check for 5.3.11` 註解正指向真正的解藥不在版本判斷、而在 **TUF 規範 §5.3.11 的 fast-forward attack recovery**：repo 用**離線 root 金鑰**（攻擊者偷不到）簽一版新 root、把 timestamp／snapshot 的公鑰**輪替**掉，client 下次 refresh 逐版把 root 補齊後，手上那份灌爆的舊 metadata 因為是**被撤銷金鑰**簽的、在 `VerifyDelegate` 對著新 root 驗時**簽章失效被丟棄**，才重新接受低版本乾淨更新——所以復原是「金鑰輪替讓灌爆版本簽章失效」，不是「client 端某個魔術上限」。連帶的 DoS 面在 root 逐版補鏈的 `loadRoot` 迴圈，`go-tuf` 用 `MaxRootRotations`（預設 256）把單次追版封頂、配上 `*MaxLength` 長度上限與 `MaxDelegations`（32）擋住惡意 mirror 的無限鏈與灌大檔——但要分清楚：**這些護欄擋的是 DoS，擋灌爆版本的是金鑰輪替**。後端工程師的可執行結論：**online 金鑰折損的 runbook 第一動作是「用離線 root 輪替公鑰」而不是「換把 key 繼續簽」；復原別靠跳版（會燒版本空間、給下次快轉留死路）；client 端 refresh 失敗一律硬失敗＋告警、版本異常跳躍只當偵測訊號、別自加硬版本上限誤殺合法 repo；short-lived timestamp 這個擋 freeze 的良藥在快轉下反而加速你進死狀態，逼你把金鑰輪替的時效當成 SLA；JVM 交給 sigstore-java 的 Updater、Java 1.8 走 sidecar。**


## 延伸閱讀

- **Day105 rollback／freeze／mix-and-match 防禦**——今天的直接鏡像。Day105 講「版本只能往上」怎麼擋回滾，今天講同一條規則被灌爆版本反噬成持久 DoS；`UpdateTimestamp` 的回滾檢查在兩天裡是攻防兩面。
- **Day107 離線／氣隙 UnsafeLocalMode**——今天的直接上游。昨天講離線 rollback 下限，今天講這個下限被灌爆後在氣隙環境為何特別難救（沒有線上 root 輪替自動撤舊金鑰）。
- **Day101 TUF root 輪替**——復原的權威來源。fast-forward recovery 靠的正是 Day101 的 root 逐版輪替，把 online 金鑰換掉，讓灌爆 metadata 簽章失效。
- **Day102 私有 root signing 儀式**——輪替 online 金鑰要動用離線 root 金鑰，簽署動作該比照 Day102 的高保證儀式（帶外、留證、比對指紋）。
- **Day104 CVE-2024-47534／版本衛生**——fast-forward 這類邏輯漏洞的修補常藏在 client 函式庫小版本裡，`govulncheck`／SBOM 當紅線。


---

明天預告：**Day 109 — 我們用了九天把 TUF client 的每一條規則拆到原始碼：逐版補鏈、委派遍歷、rollback／freeze／mix-and-match、一致快照、離線模式、今天的 fast-forward recovery……但你怎麼「持續」確認自己釘的那版 go-tuf／sigstore-java 真的還在正確執行這些規則、沒被某次升級悄悄改壞？導入官方 tuf-conformance 一致性測試套件到 CI——把 spec 的 rollback／expiry／fast-forward／委派順序等情境當成回歸測試，對你 pin 的 client 版本每次 build 跑一輪，用 CVE-2024-47534（Day104 那個委派順序被 Go map 隨機化改壞的真實案例）示範「一個過得了單元測試、卻過不了 conformance 的迴歸」長什麼樣，以及後端如何把它接進 CI gate**
（這是**延伸／收束**，把視角從「單一攻擊面的防禦細節」翻到「怎麼用外部一致性測試套件把這九天的規則變成持續回歸」。tuf-conformance 測試套件導入在本系列是**首次介紹**，明確不重述任何單一攻擊面的機制本身，聚焦**conformance 與 unit test 的差別、能抓到哪類 spec-level 迴歸、以及接進 CI gate 的動線**。情境：對 pin 住的 go-tuf 版本跑 tuf-conformance，重現 Day104 CVE 那類「單元測試綠、conformance 紅」的委派順序迴歸。標為延伸篇。）
