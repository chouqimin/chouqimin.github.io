---
title: "Day 101：你把整條供應鏈的信任一路往上收斂，最後全壓在一份 root.json——它自己憑什麼可信？——TUF 信任根的散布、輪替與金鑰折損復原"
date: 2026-08-13
tags: ["TUF", "Sigstore", "supply-chain", "key-rotation"]
---

接續 Day100 預告：Day96 起 keyless 驗簽把信任的最後一節掛在「Rekor 說這筆在日誌裡」，Day99 為可用性建議自建鏡像 Rekor，Day100 又要求你「鎖 Rekor 的公鑰、鎖 witness 的公鑰、鎖 checkpoint 的簽章金鑰」。今天把這條線走到底——**你這一路把信任「往上收斂」，鎖了 Fulcio 的 root、鎖了 Rekor 的公鑰、鎖了 witness 的金鑰，但那些公鑰到底是誰、用什麼機制發給你的？換了怎麼辦？被偷了怎麼辦？** 這顆盲點 Day96 第一次點名（「TUF root 信任根沒固定」），Day97、Day99、Day100 第八節又各點一次，今天釘上。

先把定位講清楚：**這是全新主題（TUF 信任根首次介紹），但不重述 Day100 的 inclusion／consistency proof 與 Merkle 機制，也不重述 Day96 的 keyless 驗簽流程。** Day100 談的是「日誌本身可不可信」，今天談的是更底層一層——「你用來驗那些日誌、憑證、簽章的那一堆公鑰，本身可不可信、怎麼安全地換」。

三條線先擺出來：

> **① TUF 怎麼散布信任根**——`root.json` 怎麼把 Fulcio／Rekor／CT log／witness 的公鑰打包發下來，以及為什麼「寫死在程式裡」和「HTTPS 抓一抓就信」兩條路都不夠。
> **② root rotation 與 threshold 簽章**——root 用門檻式多把金鑰簽，新版必須被「舊 root」簽過才收，這樣換金鑰不斷鏈；以及第一次取得 root 的 TOFU 開機問題。
> **③ 角色分離把爆炸半徑關住**——root／targets／snapshot／timestamp 四種角色各管一段、金鑰的上線程度不同，一把被偷不會全盤皆輸。

一句話先擺出全篇主軸：

> **你這一路把信任往上收斂，最後全部收斂到 TUF root 這一份檔案——它就是整條供應鏈信任的最後一顆釘子。釘不牢，Day96～100 全部白做。**


## 一、承接與定位：信任一路往上收斂，最後壓在一份檔案上

回顧這一段的收斂路徑：Day96 驗映像簽章 → 要信 Fulcio 的憑證鏈 root 與 Rekor 的公鑰；Day97～98 驗 provenance／SBOM → 要信簽這些 attestation 的 identity；Day99 用 VSA 把驗證收斂成一份 → 要信 verifier 的公鑰；Day100 驗透明日誌 → 要信 Rekor checkpoint 的簽章金鑰與 witness 的副署金鑰。

每一層都在說「我信任的東西，是被某某公鑰簽過的」。問題是：**這些公鑰你是從哪拿到的？** 如果答案是「我 git clone 下來的一個 `cosign.pub`」「我在 Dockerfile 裡 `curl` 一個 keys.tar.gz」「我把 Rekor 公鑰硬編在 Java 常數裡」，那你整條供應鏈的信任根，就等於那一次 `curl`／那一行常數的安全性。攻擊者不需要偽造 Merkle 證明，也不需要攻破 Fulcio——他只要在你「取得那把公鑰」的那一刻把公鑰換掉，後面全鏈都會乖乖地對著他的金鑰驗過。

TUF（The Update Framework）就是專門解「**怎麼安全地把一組信任錨（公鑰）發給客戶端，並且讓這組錨可以被輪替、被撤換、被折損復原，而不需要你重新編譯、重新散布整個世界**」的框架。Sigstore 的公信實例（public-good instance）就是用 TUF 把 Fulcio／Rekor／CT log 的公鑰，以一份叫 `trusted_root.json` 的檔案發給所有 cosign／client——而這份 `trusted_root.json`，正是被 TUF 的 targets 角色簽過、再由 snapshot／timestamp／root 一層層背書的。


## 二、TUF 要解的問題：為什麼「寫死」和「HTTPS 抓」都不夠

後端工程師直覺會有兩種做法，兩種都有致命缺口。

**做法 A：把公鑰寫死在程式／設定裡。** 缺口是輪替：金鑰一旦要換（正常輪替、或被偷了要撤），你得重編譯、重發版、逼全世界的部署都升級——在金鑰折損的當下，這個延遲就是攻擊者的可用窗口。而且「寫死」通常只寫一把，一把被偷就等於整條鏈被接管，沒有門檻可言。

**做法 B：需要時用 HTTPS 去某個 URL 抓最新公鑰。** 缺口更多：

- **TLS 只保「傳輸中沒被改」，保不了「來源被入侵」。** 你信的是那台 server 的 TLS 憑證，但存放公鑰的 repo／bucket 本身被攻陷、被塞了惡意金鑰，TLS 一樣是綠鎖——這正是 Day96 說的「有簽章≠可信」在信任根這一層的翻版。
- **擋不住 rollback／freeze。** 攻擊者（或被入侵的 CDN）可以一直餵你「舊的那一版」，讓你永遠看不到「某把金鑰已經被撤銷」的新版本。單純 HTTPS 抓一個 JSON，你沒有任何機制知道「我拿到的是不是最新的」。
- **沒有角色分離、沒有門檻。** 一把 server 私鑰、一次入侵，全鏈換底。

TUF 的設計目標，就是把這些一次補齊：**信任根與更新內容分開、金鑰可門檻式輪替、被偷可離線復原、且「你看到的是不是最新的」本身可驗。** 它不取代 TLS，而是疊在 TLS 之上補「來源可信」與「新鮮度」這兩件 TLS 管不到的事。


## 三、四種角色：root／targets／snapshot／timestamp（角度③：角色分離＝爆炸半徑控制）

TUF 把「信任」拆成四種角色，每種一組金鑰、一份 metadata、一個明確職責。這不是為了複雜而複雜——**是為了讓「一把金鑰被偷」的後果被關在一個小盒子裡。**

| 角色 | 職責 | 金鑰上線程度 | 效期 | 被偷的後果 |
|------|------|------------|------|-----------|
| **root** | 信任根：列出其他三個角色（與 root 自己）的公鑰與門檻 | **離線**、門檻多簽、極少動 | 長（月～年） | 最嚴重，但門檻＋離線讓單把無用 |
| **targets** | 簽「實際要發的檔案」（Sigstore 的 `trusted_root.json` 就是一個 target） | 離線／半離線 | 中 | 能偽造目標檔，但受 snapshot／root 約束 |
| **snapshot** | 把「當下所有 metadata 的版本號」釘在一起，防 mix-and-match | **線上** | 短 | 能做版本混搭，但簽不出新 targets 內容 |
| **timestamp** | 頻繁重簽、宣告「這是最新快照」，防 freeze／rollback | **線上** | 很短（時／天） | 只能做 freeze，且 root 可換掉它的金鑰 |

心智模型：**越是威力大的角色，金鑰越離線、越少用、越靠門檻多簽保護；越是要頻繁自動化的角色（timestamp／snapshot），金鑰越常上線、但威力被刻意關小。** timestamp 金鑰因為要頻繁重簽必須放線上（容易被偷），但它被偷了最多只能讓你「看不到更新」（freeze），偷不走 targets 的簽發權；而威力最大的 root 金鑰，因為極少動，可以離線鎖在 HSM／保險箱、還要湊到門檻（例如 5 把湊 3 把）才簽得出東西。

這就是角度③：**四個角色把爆炸半徑切成四段，一把金鑰被偷，壞的只是它那一段，而且大多可以靠 root 簽一版新的把它換掉。**


## 四、threshold 簽章：root.json 不是「一把金鑰說了算」

`root.json` 裡對每個角色都記了兩樣東西：`keyids`（哪些公鑰有權簽這個角色）與 `threshold`（要湊到幾把有效簽章才算數）。驗證邏輯是：**從「這個角色允許的 keyids」裡，收集實際附上的有效簽章，去重後數量 ≥ threshold 才通過。** 一把金鑰被偷、但沒湊到門檻，就簽不出一份合法的 root。

sigstore-java 的 `dev.sigstore.tuf.Updater` 裡這段邏輯（`verifyDelegate`）長這樣，把心法抄成示意（**你不用自己寫，生產直接用庫**）：

```java
// 示意：sigstore-java (dev.sigstore.tuf) 內部驗門檻的心法，非要你手刻
// role：這個角色允許的 keyids 與 threshold；publicKeys：keyid → 公鑰
void verifyDelegate(List<Signature> signatures,
                    Map<String, Key> publicKeys,
                    Role role,
                    byte[] signedBytes) {
    var goodSigs = new HashSet<String>();
    for (String keyid : role.getKeyids()) {        // 只認這個角色「被授權」的金鑰
        var matched = signatures.stream()
                .filter(s -> s.getKeyId().equals(keyid))
                .collect(Collectors.toList());
        if (matched.size() > 1) throw new DuplicateKeyIdsException(matched, keyid); // 同 keyid 重複＝拒
        if (matched.size() == 1) {
            var key = publicKeys.get(keyid);
            if (key != null && verifiers.newVerifier(key)
                    .verify(signedBytes, Hex.decode(matched.get(0).getSignature()))) {
                goodSigs.add(keyid);               // 用 Set 去重，同一把不重複計入門檻
            }
        }
    }
    if (goodSigs.size() < role.getThreshold())     // ★ 沒湊到門檻＝簽章不成立
        throw new SignatureVerificationException(role.getThreshold(), goodSigs.size());
}
```

三個容易忽略、但庫已經幫你守好的點：**① 只認角色授權的 keyids**（別人拿一把合法但無權的金鑰來簽不算數）；**② 同一個 keyid 出現多次只計一次**（防「一把金鑰簽兩次假裝湊到門檻」）；**③ 少一票就整份拒收**。這三點正是「寫死一把公鑰」永遠給不了的保護。


## 五、root rotation：N+1 必須被 N 簽過（角度②）

輪替是 TUF 的靈魂。情境：你手上的 client 內嵌的是 root 第 3 版，但 repo 上已經輪替到第 7 版（中間換過金鑰）。client 怎麼從 3 安全地走到 7？

規則是：**新版 root 必須「同時」被兩組門檻簽過——被『舊版 root 列出的金鑰』簽（證明是舊信任鏈授權的輪替）、也被『新版 root 自己列出的金鑰』簽（證明新金鑰同意接手）。** client 從手上的第 3 版開始，抓 4.root.json 驗、抓 5.root.json 驗……一路逐版驗到抓不到下一版為止。每一跳都要通過「舊簽新」這道檢查，中間任何一版斷了就停——攻擊者無法憑空插入一版沒被舊 root 授權的 root。

sigstore-java 的 `updateRoot()` 把 TUF 規格 5.3 節照著實作，關鍵幾行（示意）：

```java
// 示意：sigstore-java updateRoot() 的核心迴圈（對應 TUF spec 5.3）
int baseVersion = trustedRoot.getSignedMeta().getVersion();
int nextVersion = baseVersion + 1;
while (nextVersion < baseVersion + MAX_UPDATES) {          // MAX_UPDATES=1024，防無限補鏈
    var newRoot = metaFetcher.getRootAtVersion(nextVersion);
    if (newRoot.isEmpty()) break;                          // 抓不到下一版＝已到最新
    verifyDelegate(trustedRoot, newRoot.get());            // (a) 被「舊 root 門檻」簽過
    verifyDelegate(newRoot.get(), newRoot.get());          // (b) 被「新 root 門檻」簽過
    if (newRoot.get().version() != nextVersion)            // 版本必須嚴格遞增
        throw new RollbackVersionException(...);
    trustedRoot = newRoot.get();                           // 接受這一版，繼續往上
    nextVersion++;
}
throwIfExpired(trustedRoot.getExpiresAsDate());            // ★ 只在「最終版」檢查效期
if (hasNewKeys(oldSnapshotRole, newSnapshotRole)          // snapshot／timestamp 金鑰若被輪替
 || hasNewKeys(oldTimestampRole, newTimestampRole))
    trustedMetaStore.clearMetaDueToKeyRotation();          // 丟掉用舊金鑰簽的快取
```

這裡有一個**極容易誤解、但設計上刻意如此**的細節，兩個主流實作都一致：**補鏈途中的「中間版本 root」就算已經過期，也不算錯——效期只在走到「最終那一版」時才檢查。** go-tuf v2 的文件寫得很直白：

> `UpdateRoot` verifies and loads `rootData` as new root metadata. Note that **an expired intermediate root is considered valid: expiry is only checked for the final root** in `UpdateTimestamp()`.

為什麼？因為「離線很久才開機」的 client 很正常——它手上是三個月前的第 3 版，這期間 repo 因為金鑰輪替連發了 4、5、6、7 版，其中第 4、5 版早就過了效期。如果中間版過期就卡死，這台 client 永遠補不到最新、也永遠換不到新金鑰。所以 TUF 選擇：**中間版只驗「有沒有被合法輪替鏈簽過」，不驗效期；效期留給最終版把關**（擋 freeze——攻擊者不能餵你一份很舊、早就過期的「最終」root 讓你停在被撤銷的金鑰上）。這條規則你自己手刻幾乎一定會漏，這也正是「別自己驗、用維護中的庫」的最好理由。


## 六、TOFU 開機問題：第一份 root 從哪來（角度②下半）

輪替解決了「第 N 版怎麼到第 N+1 版」，但**第一份 root 呢？** 它沒有「更舊的一版」可以驗它——這是 TUF 唯一的 Trust On First Use（TOFU）點。第一份 root 只能「自己驗自己」（用它自己列出的門檻金鑰驗它自己的簽章，確認格式與門檻成立），但沒有任何外部錨點能證明「這份 root 本身沒被掉包」。

所以，**第一份 root 的可信度，完全等於你「取得它的那個管道」的完整性。** 實務上的做法是把它錨定在「你怎麼拿到 client」這件事上：

- **Sigstore／cosign**：直接把一份 `root.json` 內嵌在 client 二進位裡（隨 release 一起、經過發行簽章）。第一次跑 `cosign initialize` 時用這份內嵌 root 開機，之後就靠 TUF 自我更新——你信這份 root，是因為你信你拿到的 cosign 二進位。
- **企業自建 TUF repo**：你得自己把第一份 root 以「完整性受保護」的方式散布給內部（打進 base image、經內部簽章的組態、綁進部署 pipeline），並且**把它的指紋（hash）pin 起來、納入 Code Review 與稽核**——換第一份 root 應該是一件「要人簽核、會被告警」的大事，不是隨手改一個 URL。

把 TOFU 講白：**TUF 沒有魔法憑空產生信任，它只是把「你必須帶外信任一次」這件事，壓縮到「一份 root.json」這個最小、最少變動、最好保護的東西上**——之後所有輪替都自動、可驗、不需再帶外。你要守的，就是這一次。


## 七、金鑰折損復原：被偷了怎麼辦（不用重編譯全世界）

這是 TUF 相對「寫死公鑰」最大的價值。分兩種情況：

**timestamp／snapshot／targets 金鑰被偷** — 用離線的 root 金鑰（湊門檻）簽一份新 root，把被偷角色的 `keyids` 換成新公鑰、`threshold` 視情況調整，推到 repo。client 下次 refresh 走 root rotation 補到新版，自動改用新金鑰；上面那段 `clearMetaDueToKeyRotation()` 會把「用舊金鑰簽的快取 metadata」丟掉，逼它重抓。**被偷的那把金鑰從此簽什麼都不算數。**

**root 金鑰被偷** — 最嚴重，但因為 root 是門檻多簽（例如 5 把湊 3 把），偷一把還不夠簽出合法 root。復原方式：用門檻內「沒被偷的其他 root 金鑰」簽一版新 root，移除被偷的 key、加入新 key。只要被偷的數量沒達門檻，攻擊者就無法搶先簽出一份「把你踢出去」的 root，而你可以搶先簽出「把他踢出去」的 root。**這就是為什麼 root 一定要離線＋門檻——它把「單點折損」變成「要同時偷到門檻數量才致命」。**

對照「寫死公鑰」：寫死＝被偷只能重編譯、重發版、賭全世界升級的速度快過攻擊者利用的速度；TUF＝簽一版新 root 推出去，client 自動輪替，**折損復原從「工程發版事件」降級成「一次簽署操作」。**


## 八、後端實作：Go／Java 怎麼用（重點是「別自己驗」）

TUF 的驗證邏輯（門檻、rotation、rollback、效期、角色交叉約束）細節多到自己手刻幾乎一定有洞。後端該做的是**用維護中的庫**，把心力放在「釘好第一份 root、設好 repo URL 與 egress、監控效期與 refresh」。

**Go**——`github.com/theupdateframework/go-tuf/v2`（撰稿時 v2.4.2，2026-05 仍在更新）。高階 `updater` 一把搞定整個 5.3 workflow：

```go
// Go 1.21 — go-tuf v2 高階 client：一個 Refresh() 跑完 root→timestamp→snapshot→targets 全鏈驗證
import (
    "github.com/theupdateframework/go-tuf/v2/metadata/config"
    "github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

// bootstrapRoot：帶外取得、內嵌在程式裡的第一份 root.json（TOFU 錨點）
cfg, err := config.New(remoteURL, bootstrapRoot)
if err != nil { return err }
cfg.LocalMetadataDir = localMetaDir   // 已驗過的 metadata 快取（做 rollback 保護的依據）
cfg.LocalTargetsDir  = localTgtDir
cfg.RemoteTargetsURL = remoteURL + "/targets"

up, err := updater.New(cfg)
if err != nil { return err }
if err := up.Refresh(); err != nil {   // 任一步驗不過（門檻不足／版本回退／過期／freeze）都在這裡失敗
    return fmt.Errorf("TUF refresh 失敗，拒絕使用可能被竄改的信任根: %w", err)
}
```

若只想示範 rotation 本身，低階 `trustedmetadata` 把每一跳攤開：

```go
// Go 1.21 — 低階：手動補 root 鏈，看清「舊簽新」與「效期只驗最終版」
import "github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"

trusted, err := trustedmetadata.New(bootstrapRoot) // New 已 self-verify：root 必須被自己門檻的金鑰簽過
if err != nil { return err }
for _, newRootBytes := range newerRoots {          // 3→4→5→6→7 逐版
    if _, err := trusted.UpdateRoot(newRootBytes); err != nil {
        // UpdateRoot 內部同時驗：被舊 root 門檻簽 AND 被新 root 門檻簽、版本遞增、type 正確
        return err                                 // 中間版過期不算錯（效期留給下一步）
    }
}
if _, err := trusted.UpdateTimestamp(timestampBytes); err != nil { // ★ 這裡才擋「最終 root 過期」與 freeze
    return err
}
```

**Java**——`dev.sigstore:sigstore-java`（1.2.0+ 仍在維護，含安全性釋出）。內含 `dev.sigstore.tuf.Updater`（builder），或更常見的是直接用上層的 Sigstore verifier 讓它替你在背後管 TUF：

```java
// Java 21 — sigstore-java 的 TUF client（builder）；生產通常用更上層的 verifier 包住它
import dev.sigstore.tuf.Updater;

Updater updater = Updater.builder()
    .setTrustedRootPath(rootProvider)   // 第一份 root.json（TOFU 錨點，帶外內嵌）
    .setTrustedMetaStore(metaStore)     // 本地已驗 metadata 快取（rollback 保護）
    .setMetaFetcher(metaFetcher)        // 指向 TUF repo 的來源（URL 要受控，見第九節）
    .setTargetStore(targetStore)
    .setTargetFetcher(targetFetcher)
    .build();

updater.update();  // 內部依 TUF 5.3：updateRoot → updateTimestamp → updateSnapshot → updateTargets
// update() 沒丟例外，才代表整條信任鏈（含 rotation、rollback、效期）都驗過了
```

> 環境提醒：`sigstore-java` 需要 JDK 11 以上，**純 Java 1.8 專案無法直接引入**。1.8 環境的兩條路：把「驗簽／驗信任根」這段挪到一個 JDK 11+ 的 sidecar／獨立服務去做（跟 Day80／Day81 把 mTLS／SVID 驗證挪出應用同一個思路），或推動主服務升版。無論哪條，都**不要**因為 1.8 跑不動就自己用 jjwt／手刻 JSON 去「土炮驗 root.json」——TUF 的門檻與 rotation 規則自己寫必漏，等於親手拆掉信任根。


## 九、拒收過期 metadata 與「repo URL 就是新的攻擊面」

兩個後端最容易自己搞砸的地方，庫幫你守了一半，另一半要你配合。

**拒收過期 metadata（庫已守，別關掉）。** 上面每個實作都會在「最終 root、timestamp、snapshot、targets」上檢查 `expires > 現在`。這道檢查是擋 **freeze 攻擊**的關鍵：攻擊者餵你一份「內容合法但很舊」的 metadata，想讓你停在「某把金鑰還沒被撤銷」的世界裡。timestamp 效期短（時／天）就是為了讓這個 freeze 窗口極小——你如果為了「少打幾次 repo」去把快取 TTL 拉超長、或吞掉過期錯誤，等於自己把 freeze 窗口拉大（這跟 Day78 OCSP soft-fail、Day99 快取 TTL≤撤權空窗是同一類時效性取捨）。

**repo URL 是 SSRF／供應鏈的新觸發點（要你守）。** 你的 TUF client 會「週期性、自動地」去連一個 URL 抓 metadata 與 targets。這正是 Day10 SSRF 的教科書觸發條件：

- **repo URL 絕不吃動態輸入**（別讓使用者、環境變數注入、或某個 config service 決定你去哪抓信任根）——它應該是釘死的常數、納入 Code Review。
- **出站走 egress allowlist**，只准連你的 TUF repo／CDN 網域，別讓被 SSRF 的服務借你的 client 去打內網 metadata endpoint。
- **設 size 與 timeout 上限**（庫多半有 `MAX_META_BYTES` 之類的預設，別關）。
- **把第一份 root 的指紋 pin 起來**：CI 斷言「內嵌 root.json 的 sha256 == 預期值」，換 root 必須是一次過審的 commit——這是你唯一的 TOFU 錨點，值得被當成祕密等級保護（承 Day15）。


## 十、Day16 稽核：把 TUF 健康掃成 CI／排程（承 Day16）

透明日誌那套「monitor 掛了跟沒壞事長一樣」的偵測型控制通病，在信任根這層一樣成立。要掃的分兩類：

**組態掃描（靜態，CI）：** 斷言 client 內嵌的 root 版本不低於某個下限（別讓某個服務卡在三年前的 root）、repo URL 是釘死常數不吃輸入、egress allowlist 有涵蓋 TUF 網域、第一份 root 指紋與預期相符。這幾條 Go／Java 都能寫成單元／整合測試（解析內嵌 `root.json` 的 `version`、比對 keyids 與 threshold、算 sha256）。

**執行期掃描（排程）：** 監控 root／timestamp 的**剩餘效期比例**（不是固定天數）與 refresh 成功率——**timestamp 長時間沒更新到，跟「repo 沒事」在儀表板上長得一模一樣**，所以 refresh **成功也要記指標**，並對「N 小時內沒有一次成功 refresh」告警（跟 Day100 monitor、Day79「太久沒換發」同一個道理）。

進 SIEM 的訊號（承 Day16）：`root 版本跳變`（尤其是版本大幅前進＝可能發生過緊急輪替，值得人看一眼）、`root/timestamp 效期即將到期`、`threshold 變小`（門檻被調低是危險訊號）、`TUF refresh 連續失敗`、`內嵌 root 指紋與預期不符`。

**CI 靜態掃不到、要靠治理補的**：root 的那幾把離線金鑰到底怎麼保管（HSM？誰持有？門檻幾人？）、輪替儀式（key ceremony）由誰主持、被偷了誰有權簽緊急 root——這些是流程與盡職調查，不是字串比對。這也正是明天的主題。


## 十一、常見誤區

- **「把 Rekor／Fulcio 公鑰寫死在常數裡最單純」** — 單純到金鑰一輪替就得重編譯全世界，被偷了沒有門檻、沒有復原路徑。TUF 就是來取代這個直覺的。
- **「HTTPS 抓一份 keys.json 就夠了，反正有 TLS」** — TLS 保傳輸、保不了來源 repo 被入侵，也擋不了 freeze／rollback。
- **「root.json 一把金鑰簽的」** — root 是門檻多簽，這正是它被偷一把還不致命的原因。
- **「補鏈途中某版 root 過期了，一定是壞了」** — 相反，中間版過期是合法的，效期只驗最終版；卡在這裡通常是自己手刻驗證漏了規則。
- **「第一份 root 也用 TUF 驗就好」** — 第一份沒有更舊版可驗，是唯一的 TOFU 點，只能靠帶外＋內嵌＋pin 指紋保護。
- **「timestamp 金鑰放線上很危險，應該離線」** — timestamp 本來就設計成線上頻繁重簽，威力被刻意關小（只能 freeze），離線反而讓它沒法頻繁更新。該離線的是 root。
- **「repo URL 讓 config 動態決定比較彈性」** — 那是把信任根的來源交給輸入控制＝SSRF／供應鏈破口，URL 要釘死受審。
- **「用了 TUF 就不用管了」** — 要管 refresh 成功率、效期、egress、第一份 root 的指紋；TUF 把信任根的維運變簡單，不是變不存在。


## 十二、Code Review checklist

- 信任根（Fulcio／Rekor／CT／witness 公鑰）是**經 TUF 發下來**的，不是硬編常數、不是執行期 `curl` 抓的。
- 用的是**維護中的 TUF 庫**（Go `go-tuf/v2`、Java `sigstore-java`），沒有自己手刻門檻／rotation／效期驗證。
- 第一份 root（TOFU 錨點）**帶外內嵌**、指紋被 pin、換它要過 Code Review 與告警。
- TUF repo URL 是**釘死常數、不吃動態輸入**，出站走 **egress allowlist**，有 size／timeout 上限（承 Day10）。
- **沒有**任何地方吞掉「metadata 過期」或「refresh 失敗」的錯誤去硬跑（那是自己打開 freeze 窗口，承 Day78／Day99）。
- root 的離線金鑰是**門檻多簽**、保管方式（HSM／持有人／門檻數）有明文記錄（承 Day15，細節見明天）。
- refresh **成功也記指標**，對「N 小時未成功 refresh」與「root 版本／threshold 異動」告警（承 Day16）。


## 十三、測試怎麼寫（最關鍵是「壞的 root 進不來」與「freeze 擋得下」）

- **門檻不足**：給一份「合法金鑰但只湊到 threshold-1 把」的 root，斷言 client 拒絕（門檻驗證的存在證明，承 Day100／Day76 的「守門員存在證明」）。
- **未授權金鑰**：用一把「不在該角色 keyids 內」的合法金鑰簽 root，斷言不算數。
- **rotation 斷鏈**：塞一版「沒被舊 root 簽過」的新 root，斷言補鏈在該版停下／報錯，不會被接受。
- **rollback 演練**：餵一版 version 比本地小的 root／timestamp，斷言 `RollbackVersionException` 類錯誤。
- **freeze 演練**：餵一份「內容合法但已過期」的最終 timestamp，斷言拒收（別讓過期的最新被當最新）。
- **中間版過期但最終版有效**：補鏈途中放一版過期的中間 root、最終版未過期，斷言**能**補到最新（驗證你沒把「中間版過期」誤判成錯——這條專防手刻漏規則）。
- **第一份 root 指紋**：CI 斷言內嵌 `root.json` 的 sha256 == 預期，改動即 fail。
- **egress 邊界**：把 repo URL 指向內網位址，斷言被 egress allowlist 擋下（承 Day10）。


## 十四、一句話總結

> Day96～100 把供應鏈信任一路往上收斂——驗簽、驗 provenance、驗 SBOM、收斂成 VSA、驗透明日誌——最後全部壓在「你憑什麼相信那一堆公鑰」這件事上。今天釘上：**用 TUF 把 Fulcio／Rekor／CT／witness 的公鑰當一份可驗、可輪替、可折損復原的 `root.json` 發下來。** 三條線：**① 散布**——別寫死（換金鑰要重編譯全世界、被偷無解）、別只靠 HTTPS 抓（TLS 保傳輸不保來源、擋不了 freeze），TUF 疊在 TLS 上補「來源可信」與「新鮮度」。**② 輪替＋門檻**——root 門檻多簽，新版必須被舊 root＋新 root 兩組門檻都簽過才收（rotation 不斷鏈），補鏈途中中間版過期算數、效期只驗最終版（讓離線很久的 client 也能補到最新），第一份 root 是唯一的 TOFU 點只能帶外內嵌＋pin 指紋。**③ 角色分離**——root／targets／snapshot／timestamp 各管一段、金鑰上線程度不同，威力大的離線門檻、要頻繁的上線但威力關小，一把被偷關在一段裡、大多能靠 root 簽新版換掉。折損復原因此從「工程發版事件」降級成「一次簽署操作」。後端的責任不是自己驗（門檻／rotation／效期自己手刻必漏，用 `go-tuf/v2`、`sigstore-java`），而是**釘好第一份 root、鎖死 repo URL 與 egress、監控效期與 refresh**。一句話：**你這一路把信任往上收斂，最後全部收斂到 TUF root 這一份檔案——它就是整條供應鏈信任的最後一顆釘子，釘不牢，Day96～100 全部白做。**


## 延伸閱讀

- **Day96 Sigstore 映像簽章**——keyless 驗簽留下的「TUF root 信任根沒固定」盲點，就是今天釘上的那顆；今天不重述 keyless 怎麼驗，只補「那些公鑰怎麼安全發下來」。
- **Day99 VSA**／**Day100 透明日誌**——一路要求「鎖 verifier 公鑰、鎖 Rekor 公鑰、鎖 witness 公鑰」，今天回答「這些公鑰是誰發的、怎麼換」。今天明確不重述 Day100 的 inclusion／consistency proof。
- **Day78 OCSP soft-fail**／**Day99 快取 TTL**——metadata 效期、freeze 窗口、快取 TTL，跟 soft-fail 空窗是同一類時效性風險決策。
- **Day10 SSRF**——TUF repo URL「週期性主動去連一個外部位址抓信任根」正是 SSRF 觸發點：URL 釘死、egress allowlist、size／timeout。
- **Day15 祕密管理**／**Day16 監控**——root 離線金鑰是皇冠寶石等級的祕密；refresh 成功率、效期、版本／門檻異動全進 SIEM。
- **Day80／Day81 SPIFFE**——「Java 1.8 跑不動就把驗證挪 sidecar」與「別為了跑起來自己拆掉信任根」，在 TUF 這層一模一樣適用。

---

明天預告：**Day 102 — 公信 Sigstore 那份 root.json 是別人的信任根，如果你必須自己當根呢？——自建／私有 Sigstore 信任根的運維：TUF root-signing 金鑰儀式、離線門檻 root 金鑰保管與輪替治理**
（這是**全新主題**，承今天第十節末尾與第七節點名的「離線 root 金鑰怎麼保管、輪替儀式誰主持、緊急輪替誰有權簽」——今天講的是 TUF 信任根「怎麼運作、怎麼驗」，明天講「當你不能只用公信實例、必須自建一套時，那些離線 root 金鑰的儀式與治理怎麼落地」。三條線：**① root-signing 金鑰儀式（key ceremony）**——為什麼 root 金鑰要離線產生、門檻多人各持一份（例如 5 選 3）、簽署要在受控環境並全程留證，跟 Day83 SPIRE CA key 的 HSM 保管是表兄弟但這裡管的是 TUF root 四角色而非單一 CA；**② 線上 vs 離線角色的自動化邊界**——timestamp／snapshot 要頻繁重簽必須自動化上線，targets／root 離線人工，怎麼在「可自動輪替」與「離線不外洩」之間切這條線；**③ 自建的信任治理與退場**——自己當根＝CT／公信生態的外部制衡不在了（承 Day77 內部 CA 盲區），要用「儀式留證＋門檻＋稽核」補回來，以及「什麼時候根本不該自建、老實用公信實例就好」的決策。程式與組態面會示範：root metadata 的角色金鑰與 threshold 設定、離線簽署與線上角色分工的 pipeline 思路，以及自建 repo 的 root 指紋 pin 與稽核。安全主軸一句話：**公信實例幫你把 root 儀式外包了，自建就是把這份最重的責任攬回自己身上——攬得起再自建，攬不起就別拆掉別人已經幫你顧好的那顆釘子。** 這是全新主題，聚焦自建 Sigstore 信任根的金鑰儀式與治理，不重述今天的 threshold／rotation 驗證機制。）
