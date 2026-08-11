---
title: "Day 100：你為了可用性自建的鏡像 Rekor，會不會對你說謊？——透明日誌的信任模型與監控"
date: 2026-08-12
tags: ["transparency-log", "Rekor", "supply-chain", "monitoring"]
---

接續 Day99 預告：Day99 為了收斂 admit-time 的驗證量，把「驗證」與「消費驗證結果」拆開，用 VSA 讓 admit 只驗一份摘要；第五節還為了可用性，建議「本地鏡像 Rekor」把 admit 對透明日誌的網路依賴留在自己網路內。今天要付這筆帳——**你把可用性押在自建的那面鏡子上，但你憑什麼相信那份日誌沒被動手腳、沒對不同人給不同版本？**

先把定位釘死：**這是接續系列的延伸篇，不是重講 Day96 的 keyless 驗簽流程，也不是重講 Day77 的 Certificate Transparency 入門。** Day96 怎麼驗 Fulcio 短命憑證、怎麼鎖 issuer＋subject，今天完全不重述；Day77 的「透明日誌是什麼、Merkle Tree 長怎樣、Log/Monitor/Auditor 三種角色、SCT 是收據、怎麼用 crt.sh 當 monitor 抓自家憑證誤發」也不重講。今天換一個 Day77 當初刻意略過的角度——Day77 說「Auditor 由瀏覽器與研究者做，後端一般不需自己扮演」，**但當你為了可用性自建鏡像 Rekor，你就是那個 Auditor 了，這件事外包不掉。** 這篇聚焦「透明日誌本身的信任模型」，放在 Sigstore／Rekor＋自建鏡像的情境下。

延伸角度先講明白，這篇只走三條線：

> **① 兩種證明，Day77 只講了一半**——`inclusion proof`（你的 entry 真的被收進日誌了，Merkle 路徑驗給你看）與 `consistency proof`（日誌只 append、不偷改歷史）。這兩個是 admit 消費 Rekor 時「該要而常常沒要」的東西——大多數人只信 Rekor 回的那張 `SignedEntryTimestamp`（SET）收據就放行了。
> **② split-view／分裂視圖攻擊**——一個被控制或作惡的日誌，可以對受害者給「有惡意 entry」的視圖、對稽核者給「乾淨」的視圖。光靠 inclusion proof 擋不住，因為每個視圖各自內部自洽。要靠 **witness／gossip**（多方見證同一個 log root）才抓得到——這正是「自建鏡像 Rekor」最危險的盲區。
> **③ 監控 vs 阻擋的分工**——透明日誌的本質是「事後可稽核」不是「事前擋下」。admit 做阻擋（fail-closed，承 Day91），monitor 做偵測（持續拉 log、驗 consistency、對「出現我沒授權簽的 entry」告警，承 Day35 主動偵測、Day16 SIEM）。兩者是不同的工，都要有。

一句話先擺出全篇主軸：

> **透明日誌讓「作惡可被發現」，但「可被發現」不等於「已經有人在看」——你自建的那面鏡子，得有人拿另一面鏡子去對照它。**

---

## 一、問題：admit 對 Rekor 的信任，到底建立在什麼上

先把 Day96 keyless 驗簽那一刻，Rekor 扮演的角色講清楚（不是重講怎麼驗，是點出「信任落在哪個字上」）。keyless 的簽章用的是 Fulcio 簽的**短命憑證**，憑證幾分鐘就過期。那你今天驗一個幾個月前簽的映像，憑證早就過期了，怎麼還能信？答案就是 Rekor：簽章當下這筆記錄被寫進透明日誌，Rekor 回一張 **SET（SignedEntryTimestamp）**當收據，證明「這個簽章在憑證還有效的時間點，就已經進了日誌」。於是驗證的邏輯變成「憑證當時有效 ＋ 這筆有進 Rekor」＝可信。

看到問題了嗎？**整條 keyless 信任鏈，最後有一節是掛在「Rekor 說了算」上面。** 而大多數驗證流程對 Rekor 的信任，就停在「Rekor 回了一張 SET、SET 的簽章用 Rekor 公鑰驗得過」——就放行了。

這裡有兩個沒被追問的洞：

1. **SET 只是一張「我保證會收進去」的收據，不是「已經在裡面」的證明。** 這跟 Day77 的 SCT 是同一種東西：log 給你一個承諾（承諾在 MMD／Maximum Merge Delay 內公開）。承諾 ≠ 兌現。只驗 SET 不驗 inclusion proof，等於收了張支票就當現金花。
2. **就算 entry 真的在「這份日誌」裡，你怎麼知道「這份日誌」跟全世界看到的是同一份？** 一個作惡的 Rekor 可以維護一棵只給你看的樹，裡面自洽地塞進惡意 entry，inclusion proof 一路驗得過——但那棵樹只有你看得到。

第一個洞由 **inclusion proof** 補（第二節），第二個洞 inclusion proof 補不了，要靠 **consistency proof＋witness**（第三、四節）。而 Day99 那個「自建鏡像 Rekor」的建議，剛好把這兩個洞都放大了：鏡像可能落後（給你舊視圖）、可能被動手腳（給你假視圖），而它是你自己網路內的單點，沒有外部壓力逼它誠實。

---

## 二、兩種證明，Day77 只講了一半（角度①）

Day77 講 CT 時說過「Log 是 append-only Merkle Tree，可用 Merkle proof 驗證歷史沒被改」。那句話其實把**兩種不同的證明**混成一句帶過了。它們回答的是完全不同的問題，缺任何一個都有對應的攻擊：

| 證明 | 回答的問題 | 沒有它會怎樣 |
|---|---|---|
| **inclusion proof**（Merkle audit path） | 「我這筆 entry，真的在這棵樹（這個 root）裡嗎？」 | 只信 SET＝只信承諾，日誌可以永遠不兌現、或兌現一個你看不到的版本 |
| **consistency proof** | 「新的樹（size n₂）是舊的樹（size n₁）純 append 長出來的嗎？歷史有沒有被改寫？」 | 日誌可以偷偷改寫或刪掉過去的 entry，你完全不會發現 |

**inclusion proof** 的驗法：Rekor 給你這筆 entry 的 `logIndex`、`treeSize`、一串 `hashes[]`（audit path，就是從你那片葉子往上爬到 root 時，每一層的 sibling 雜湊），還有一個簽過名的 `checkpoint`（signed tree head：treeSize＋rootHash＋Rekor 簽章）。你自己用葉子雜湊一路往上重算 root，算出來的 root 要等於 checkpoint 上那個**被 Rekor 簽過**的 rootHash。

關鍵區別在這：**Day96 只驗「SET 簽章對不對」，那只證明「Rekor 對這筆下了收據」；驗 inclusion proof 才證明「這筆真的被算進了一個 Rekor 簽章背書的 root」。** 前者是承諾，後者是兌現。

Merkle 的雜湊要用 RFC 6962 的 domain separation：葉子是 `SHA256(0x00 || entry)`、內部節點是 `SHA256(0x01 || left || right)`——這個 `0x00`／`0x01` 前綴是防「把某個內部節點的雜湊拿來冒充一片葉子」的第二原像攻擊，別漏。Rekor 底層是 Trillian，走的就是 RFC 6962 這套。

### Go（Go 1.21）——重算 Merkle root，驗 inclusion proof

```go
package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

// RFC 6962 domain separation：葉子 0x00 前綴、內部節點 0x01 前綴
func hashLeaf(entry []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(entry)
	return h.Sum(nil)
}

func hashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// 用 audit path 從葉子往上重算 root。
// 示意：以 index 奇偶逐層決定 sibling 在左或右。
// 真實 Rekor 樹大小非 2 的次方，邊界要用 RFC 6962 §2.1.1 完整演算法；
// 生產環境請直接用 sigstore 官方驗證庫，別自己手刻這段。
func recomputeRoot(leafHash []byte, index uint64, auditPath [][]byte) []byte {
	r := leafHash
	idx := index
	for _, sibling := range auditPath {
		if idx&1 == 0 {
			r = hashNode(r, sibling) // 我在左，sibling 在右
		} else {
			r = hashNode(sibling, r) // 我在右，sibling 在左
		}
		idx >>= 1
	}
	return r
}

// verifyInclusion：entry 真的在「這個 signedRoot」裡嗎？
// signedRoot 必須是「已經用 Rekor 公鑰驗過簽章的 checkpoint rootHash」，
// 不是 Rekor 隨手回的一個 hex 字串——驗簽那關（鎖 Rekor 公鑰）省不得。
func verifyInclusion(entry []byte, index uint64, auditPath [][]byte, signedRoot []byte) error {
	got := recomputeRoot(hashLeaf(entry), index, auditPath)
	if !bytes.Equal(got, signedRoot) {
		return fmt.Errorf("inclusion proof 不符：重算 root=%x，checkpoint 簽章 root=%x", got, signedRoot)
	}
	return nil
}

func main() {
	// 概念示意的假資料；實際 entry/path/root 來自 Rekor LogEntry 的 verification.inclusionProof
	entry := []byte("rekor-entry-bytes")
	auditPath := [][]byte{ /* Rekor 回的 hashes[]，已 hex 解碼 */ }
	var index uint64 = 0
	signedRoot := hashLeaf(entry) // 單葉樹的 root 就是葉子雜湊（示意）

	if err := verifyInclusion(entry, index, auditPath, signedRoot); err != nil {
		fmt.Println("拒絕放行：", err)
		return
	}
	fmt.Println("inclusion proof 通過：這筆確實在被簽章背書的 root 裡")
}
```

重點不在你會不會手刻 Merkle（**你不該手刻，生產一律用 sigstore 驗證庫**）。重點是**觀念**：`verifyInclusion` 的最後一個參數 `signedRoot`，必須是「先用 Rekor 公鑰驗過 checkpoint 簽章、確認沒被竄改的那個 root」。如果你把 Rekor 隨手回的 root 直接餵進來當比對基準，那你重算得再對也沒意義——攻擊者連 root 一起給你假的，自洽得很。**inclusion proof 只證明「這筆在這個 root 裡」，它不證明「這個 root 是真的、是全世界公認的那個」。** 後半句就是第三、四節的 split-view。

---

## 三、consistency proof 與「自建鏡像會不會偷改歷史」

inclusion proof 顧的是「單一時間點的一筆」。但透明日誌的價值是「**歷史不可改**」——一個曾經被記錄的惡意簽章，不能事後被日誌偷偷刪掉，好像沒發生過。這條靠 **consistency proof**。

它證明的是：日誌從 size n₁（root R₁）長到 size n₂（root R₂）的過程，是**純 append**——R₁ 的每一片葉子，在 R₂ 裡原封不動地還在原位，只是後面接了新葉子。如果日誌想改寫或刪掉一筆舊 entry，它就湊不出一個能同時對得上「舊 R₁」和「新 R₂」的 consistency proof。

這件事對「自建鏡像 Rekor」特別要命。Day99 §5 為了可用性，把 Rekor 鏡像拉進自己網路內。好處是 admit 不再依賴外部 SLA；壞處是——**這面鏡子現在是你自己網路裡一個可被入侵、可被組態錯誤搞壞的單點**，而且它少了「全世界都在盯著公有 Rekor」的外部壓力。一個被入侵的鏡像可以：

- **落後**（stale）：不同步新 entry，讓你以為某個「已被撤銷／已被記錄為惡意」的狀態還沒發生；
- **回捲**（rollback）：給你一個 treeSize 變小的視圖，抹掉某些歷史；
- **分叉**（fork／split-view）：對你的 admit 給一個視圖、對你的稽核 monitor 給另一個視圖。

前兩種，**consistency proof＋checkpoint 新鮮度**就能抓：你只要持續記住「上次看到的 checkpoint（n₁, R₁）」，每次鏡像給你新的 checkpoint（n₂, R₂）時，要求它附一份從 n₁ 到 n₂ 的 consistency proof，並且斷言 `n₂ ≥ n₁`。size 變小＝回捲，直接告警；consistency proof 對不上＝改寫歷史，直接告警。這跟 Day78 OCSP soft-fail 是同一類時效性風險：**你對「世界變了沒」的唯一感知，就是這個一直往前長的 checkpoint，所以它只能單調遞增、且每一步都要能證明是 append。**

第三種（分叉／split-view）——consistency proof 也擋不住，因為攻擊者給你的那一支視圖，自己內部是完全 append-consistent 的。這就得靠 witness。

---

## 四、split-view／分裂視圖攻擊與 witness（角度②）

把前面兩節的極限講白：

- inclusion proof 證明「這筆在**這個** root 裡」；
- consistency proof 證明「**這條**歷史線是純 append 的」；
- 但兩者都沒回答：「**這條歷史線，是不是全世界看到的同一條？**」

**split-view（又叫 fork／分裂視圖）攻擊**就鑽這個縫：一個被控制的日誌（尤其是你自建、對外沒有見證的鏡像）維護**兩棵各自 append-consistent 的樹**。對你的 admission（受害者）出示 A 視圖：裡面有一筆惡意映像的簽章，inclusion proof 完美、consistency proof 完美，於是 admit 放行。對你的稽核 monitor 或任何外部觀察者出示 B 視圖：乾淨的，沒那筆惡意簽章。**兩邊各自都驗得過，但兩邊看到的根本不是同一份日誌。** 你在 A 世界被攻破，卻在 B 世界的稽核報告裡一片祥和。

inclusion／consistency 都是「單一觀察者對單一日誌」的自證，數學上再嚴謹，也證明不了「沒有第二個視圖存在」。要抓分叉，唯一的路是**讓多方比對「他們各自看到的 log root 是不是同一個」**——這就是 **witness／gossip**。

- **witness（見證者）**：一群獨立於日誌營運方的第三方，各自去讀日誌的 checkpoint，覺得沒問題就**副署（co-sign）**那個 checkpoint——等於公開宣告「我在這個 size 看到的 root 是這個」。你的 admit／monitor 除了驗 Rekor 自己的簽章，還要求 checkpoint 上有**足夠數量的 witness 副署**（門檻式，像 Day85 提過的 threshold 概念）。攻擊者要餵你假視圖，就得同時買通到門檻數量的獨立 witness——成本從「入侵一個鏡像」暴增到「同時入侵一票互不相干的第三方」。
- **gossip**：觀察者之間互相交換「我看到的 checkpoint」，一旦有人手上的 root 跟別人對不上，分叉就曝光了。

Sigstore 生態正在把 witness／monitor 網路標準化（checkpoint 的簽章／副署格式、witness 副署協定都在演進中，實作前先確認你用的 Rekor 版本與 client 支不支援、副署格式是哪一版，別把欄位路徑寫死）。對後端的**可操作結論**很直接：

> **你可以為了可用性自建鏡像 Rekor，但你不能同時把「信任」也自建。** 鏡像負責「快、就近」，witness／gossip 負責「這面鏡子沒對我說謊」。自建鏡像＋不接任何外部 witness＝你親手做了一個「只有你看得到、沒有任何人能反駁」的日誌，split-view 的門檻直接歸零。

這也正面回答了 Day77 收尾沒展開的那句：Day77 說「Auditor 由瀏覽器與研究者做，後端一般不需自己扮演」——那是因為**公有** CT log 有全世界的 witness 在盯。一旦你把日誌搬進自己家（自建鏡像），那個「全世界在盯」的前提就消失了，**Auditor 這個角色你賴不掉，只能自己扛起來**（或明確地把信任接回一個有外部見證的公有 log）。

---

## 五、監控 vs 阻擋的分工（角度③）

講到這裡要收一個常見的誤解：**透明日誌不是一個「事前擋下壞東西」的機制，它是「事後讓壞事藏不住」的機制。** admit 那一刻驗 inclusion proof，能擋下「根本沒進日誌」的簽章；但「一筆惡意簽章大方地進了日誌、inclusion proof 完美」——透明日誌設計上**不會擋**，它只保證這筆「賴不掉、查得到」。真正把「查得到」變成「有人查」的，是 **monitor**。

所以分工是這樣，兩件事、兩支程式、別混為一談：

- **admit（阻擋，同步、fail-closed）**：承 Day91／Day96，驗簽＋驗 inclusion proof＋（消費 VSA 時）驗新鮮度，不合格就擋。它管的是「**這個東西能不能跑起來**」。
- **monitor（偵測，非同步、持續）**：承 Day35 subdomain 那種主動偵測、Day16 SIEM。它管的是「**日誌裡有沒有出現我沒授權、但宣稱是我的簽章身分的 entry**」，以及「**日誌本身有沒有被回捲／分叉**」。它不擋任何 Pod，它只負責「有人在看」。

monitor 具體要做四件事，每次拉到新 checkpoint 時：

1. **驗 checkpoint 簽章**——用釘死的 Rekor 公鑰（這把公鑰哪來的、怎麼輪替，是明天 TUF 的主題）。
2. **驗 consistency proof**——新 checkpoint 是舊的 append 延伸，`treeSize` 單調遞增（抓落後／回捲，第三節）。
3. **比對 witness 副署**——同一個 checkpoint 有沒有足夠 witness 背書、root 跟 witness 看到的一致（抓 split-view，第四節）。
4. **掃新 entries**——出現「宣稱是我的簽章 identity、但我這邊沒有對應的授權發布紀錄」的 entry，立刻告警（抓「有人冒用我的身分簽了東西並塞進日誌」）。

### Java（Java 21）——monitor：consistency＋witness＋未授權 entry 告警

```java
import java.util.List;
import java.util.Set;

public class RekorMonitor {

    // 上次成功驗過的 checkpoint（signed tree head）
    record Checkpoint(long treeSize, byte[] rootHash, byte[] logSignature) {}

    // witness 對某個 checkpoint 的副署
    record WitnessCosign(String witnessId, long treeSize, byte[] rootHash) {}

    private static final int WITNESS_THRESHOLD = 2; // 門檻：至少幾個獨立 witness 同意（承 Day85 threshold）

    // 這些驗證細節請交給 sigstore 官方庫；此處只表達「monitor 該檢查哪幾件事」
    static boolean verifyLogSignature(Checkpoint cp, byte[] rekorPubKey) { /* 鎖 Rekor 公鑰 */ return true; }
    static boolean verifyConsistency(Checkpoint prev, Checkpoint next) { /* prev→next 純 append */ return true; }

    /** 回傳空字串代表通過；非空代表偵測到問題（要告警，但 monitor 不擋 Pod）。 */
    static String inspect(Checkpoint prev, Checkpoint next,
                          List<WitnessCosign> witnesses,
                          Set<String> myAuthorizedDigests, // 我這邊「有授權發布」的 digest
                          List<String> newEntryDigests,    // 這次新出現、宣稱是我 identity 的 entry
                          byte[] rekorPubKey) {

        // 1. checkpoint 簽章：連 Rekor 自己都沒簽對，後面免談
        if (!verifyLogSignature(next, rekorPubKey))
            return "checkpoint 簽章驗不過：可能被竄改或公鑰不符";

        // 2. 單調遞增 + append-only（抓落後/回捲）
        if (next.treeSize() < prev.treeSize())
            return "treeSize 倒退：%d → %d，疑似 rollback/stale 鏡像".formatted(prev.treeSize(), next.treeSize());
        if (!verifyConsistency(prev, next))
            return "consistency proof 對不上：歷史可能被改寫";

        // 3. witness 副署（抓 split-view）：同一個 treeSize+root，要有足夠 witness 看到一樣的東西
        long agree = witnesses.stream()
                .filter(w -> w.treeSize() == next.treeSize()
                          && java.util.Arrays.equals(w.rootHash(), next.rootHash()))
                .map(WitnessCosign::witnessId)
                .distinct().count();
        if (agree < WITNESS_THRESHOLD)
            return "witness 背書不足：只有 %d 個 witness 同意這個 root（門檻 %d）——可能是 split-view"
                    .formatted(agree, WITNESS_THRESHOLD);

        // 4. 出現「宣稱是我、但我沒授權」的 entry → 有人冒用我的簽章身分（承 Day35 主動偵測）
        for (String d : newEntryDigests) {
            if (!myAuthorizedDigests.contains(d))
                return "偵測到未授權 entry：digest=%s 宣稱由我簽發，但我無對應授權紀錄".formatted(d);
        }
        return "";
    }

    public static void main(String[] args) {
        // 排程持續執行（承 Day16）；成功也要記指標，別只在失敗時才有聲音——見第六節
    }
}
```

（Java 1.8 環境把 `record`／text block／`formatted` 換成一般 class 與字串串接即可，核心邏輯不變。）

這支的靈魂不是任何一行 API，而是**它把「日誌可信度」拆成四個獨立可告警的檢查**，而且它**只告警、不阻擋**——阻擋是 admit 的事，monitor 越權去擋反而會把偵測系統變成新的可用性單點（承 Day72 自己給自己加瓶頸）。

---

## 六、四個「驗了等於沒驗」的盲點

1. **只驗 SET，不驗 inclusion proof。** 最常見。SET 是「我保證收進去」的收據，不是「已經在裡面」的證明——跟 Day77 SCT 一模一樣。只收支票不兌現，日誌可以永遠不公開、或公開一個你看不到的版本。價值全在「兌現」那一步（inclusion proof），不在「有收據」。
2. **驗了 inclusion proof，卻把 Rekor 隨手回的 root 當比對基準。** inclusion proof 只證明「這筆在**這個** root 裡」；如果這個 root 本身沒經過「Rekor 公鑰驗簽的 checkpoint」，攻擊者連 root 一起給你假的，你重算得再漂亮也是在驗一個假世界的自洽性（第二節）。
3. **自建鏡像 Rekor，卻不接任何 witness／gossip。** 你親手做了一個「只有你看得到、外部無人能反駁」的日誌，split-view 門檻歸零（第四節）。可用性是省到了，代價是把透明日誌最核心的「全世界都在盯」給拆了。鏡像可以自建，信任不能自建。
4. **有 admit 驗簽，就以為不用 monitor（或反過來，有 monitor 就把 admit 放鬆）。** 兩者管不同的事：admit 擋「沒進日誌的東西」，monitor 抓「進了日誌的壞東西」與「日誌本身被回捲／分叉」。透明日誌是「事後可稽核」，沒有 monitor 就等於「作惡可被發現，但沒有人在發現」——鎖裝了，沒人看監視器（承 Day77 那句「沒人裝了鎖就拆監視器」，這裡是反過來：裝了監視器卻沒人看螢幕）。

---

## 七、稽核：把兩類問題掃成 CI／排程（承 Day16）

跟 Day92～99 同一條 pipeline。透明日誌的信任有兩個面向要掃：**驗證組態**（admit 到底驗到哪一層）與**執行期健康**（monitor 有沒有在跑、日誌有沒有被回捲）。

- **組態掃描（靜態）**：掃 admit 的驗證設定，斷言它**同時**做到「驗 SET／驗 inclusion proof／checkpoint 的 root 有經過 Rekor 公鑰驗簽」，而不是停在只驗 SET。這條專治盲點①②。
- **執行期掃描（排程）**：第五節那支 monitor 本身，就是執行期稽核。額外要掃的是「**monitor 有沒有在跑**」——這是偵測型控制的通病（承 Day77）：**monitor 掛掉，跟「日誌很乾淨、沒有壞事」，在儀表板上長得一模一樣。**

所以 monitor 一定要**成功也記指標**，並對「N 小時內沒有一次成功執行」告警——因為「有失敗（error）」跟「根本沒被排到、連 error 都產不出來」是兩件事。再加一條陽性測試：定期對一個「已知該告警」的情境（例如刻意餵一個 treeSize 倒退的 checkpoint）跑斷言，確認 monitor 真的會叫——這就是 monitor 的「存在證明」，跟 Day77「陽性測試＝monitor 存在證明」、Day76「pin 不命中反例＝pinning 存在證明」是同一個道理。

進 SIEM 的訊號（承 Day16）：`consistency proof 失敗`、`treeSize 倒退`、`witness 背書數低於門檻`、`出現未授權 identity 的 entry`、`monitor N 小時未成功執行`。這幾條任何一條響，都代表「你押注的那面鏡子出事了」。

**CI 靜態掃不到、要靠別的手段補的**：witness 到底夠不夠獨立（那些 witness 會不會其實是同一個人開的？這是治理與盡職調查，不是字串比對）、自建鏡像的同步延遲容忍度該設多長（那是風險決策，跟 Day99 快取 TTL≤撤權空窗同一類取捨）、Rekor 公鑰本身是誰發的（那是明天 TUF 的主題）。

---

## 八、Code Review checklist

- admit 消費 Rekor 時，**同時**驗 SET **與** inclusion proof，沒有停在只驗 SET（盲點①）。
- inclusion proof 的比對基準 root，來自**經 Rekor 公鑰驗簽的 checkpoint**，不是 Rekor 裸回的 root（盲點②）。
- 若自建鏡像 Rekor（承 Day99 §5），**同時**接了 witness／gossip，checkpoint 要求達門檻的 witness 副署（盲點③）。
- 有一支**獨立於 admit 的 monitor**，持續驗 consistency proof、`treeSize` 單調遞增、掃未授權 entry（盲點④、第五節）。
- monitor **成功也記指標**，並對「N 小時未成功執行」告警；有陽性測試證明 monitor 會叫（第七節、承 Day77）。
- admit 與 monitor **職責分離**：admit 擋、monitor 只告警不擋（避免 monitor 變成可用性單點，承 Day72）。
- Rekor／witness 的公鑰有明確的信任根與輪替機制（承 Day96 盲點「TUF root 沒固定」，明天展開）。

## 九、測試怎麼寫（最關鍵是「假視圖擋得下」與「monitor 真的會叫」兩條）

- **只有 SET 沒有 inclusion proof**：斷言 admit 拒絕（防盲點①，別讓「有收據」就放行）。
- **inclusion proof 對，但 checkpoint 簽章驗不過**：斷言 admit 拒絕（防盲點②，root 沒被 Rekor 簽就不可信）。
- **rollback 演練**：餵 monitor 一個 `treeSize` 比上次小的 checkpoint，斷言告警（第三節）。
- **改寫歷史演練**：餵一個 consistency proof 對不上的新 checkpoint，斷言告警。
- **split-view 演練**：給 admit 一個「有惡意 entry、自洽」的 A 視圖，同時 witness 們看到的是 B 視圖的 root，斷言 witness 門檻檢查擋下／告警（第四節，這條專防自建鏡像的分叉）。
- **未授權 entry 演練**：在日誌塞一筆「宣稱是我 identity、但我無授權紀錄」的 entry，斷言 monitor 告警（承 Day35）。
- **monitor 存在證明**：對已知該告警的情境跑陽性測試，斷言真的會叫；再測「monitor 進程沒被排到」時，`N 小時未成功` 告警會響（第七節）。

---

## 十、一句話總結

> Day96 起，keyless 驗簽把信任的最後一節掛在「Rekor 說這筆在日誌裡」；Day99 為可用性又建議「自建鏡像 Rekor」——今天付帳：**你憑什麼相信那面鏡子沒對你說謊？** 三條線。**① 兩種證明，Day77 只講了一半**：`inclusion proof` 證明「這筆真的在一個被 Rekor 簽章背書的 root 裡」（不是只信 SET 那張收據），`consistency proof` 證明「日誌只 append、沒偷改歷史」（抓落後／回捲）——RFC 6962 的 `0x00`／`0x01` domain separation 別漏，且比對基準 root 一定要來自驗過簽的 checkpoint。**② split-view／分裂視圖**：inclusion／consistency 都只能自證「單一觀察者對單一日誌」，證明不了「沒有第二個視圖」；一個作惡日誌能對受害者與稽核者各給一份自洽的假視圖，只有 **witness／gossip**（多方副署同一個 root、達門檻）抓得到——這正是自建鏡像最危險的盲區，**鏡像可以自建，信任不能自建**。**③ 監控 vs 阻擋**：透明日誌是「事後可稽核」不是「事前阻擋」，admit 做 fail-closed 的擋（擋沒進日誌的），monitor 做持續偵測（驗 consistency、比對 witness、掃未授權 entry，承 Day35／Day16），兩者職責分離、都要有。四個盲點：**①只驗 SET 不驗 inclusion、②拿裸 root 當基準、③自建鏡像卻不接 witness、④以為有 admit 就不用 monitor**。稽核最要命的是「monitor 掛了跟沒壞事長一樣」，所以**成功也要記指標、要有陽性測試證明它會叫**。一句話：**透明日誌讓「作惡可被發現」，但「可被發現」不等於「已經有人在看」——你自建的那面鏡子，得有人拿另一面鏡子去對照它。**

---

## 延伸閱讀

- **Day77 Certificate Transparency／CAA**——透明日誌的入門地基：Log/Monitor/Auditor 三角色、Merkle Tree、SCT、monitor 抓誤發。今天不重述，而是接續它刻意略過的 Auditor 角色——當你自建鏡像，這角色賴不掉。
- **Day96 Sigstore 映像簽章**——keyless 為何要靠 Rekor（短命憑證＋透明日誌），以及它留下的「TUF root 沒固定」盲點，明天處理。
- **Day99 VSA**——第五節「本地鏡像 Rekor」正是今天要付帳的對象：可用性紅利的代價是把 Auditor 責任攬上身。
- **Day78 憑證撤銷 OCSP soft-fail**——鏡像落後／checkpoint 新鮮度，跟 soft-fail 空窗是同一類時效性風險決策。
- **Day72 Slowloris／slow HTTP DoS**——admit 對外抓日誌是自己加的可用性瓶頸；monitor 若去擋 Pod 也會變成新單點。
- **Day35 Subdomain Takeover**——monitor「掃出現我沒授權的東西就告警」，跟主動偵測子網域被接管是同一種偵測型控制。
- **Day16 Security Logging／Monitoring**——consistency 失敗、treeSize 倒退、witness 不足、未授權 entry、monitor 未執行，全進 SIEM。

---

明天預告：**Day 101 — 你今天鎖定的那些公鑰（Rekor 的簽章金鑰、witness 的副署金鑰、Fulcio root），到底是誰、用什麼機制發給你的？——TUF（The Update Framework）與 Sigstore 信任根的散布、輪替與金鑰折損復原**
（這是**全新主題**，承 Day96 當初留下、也在今天第八節再次點名的盲點「TUF root 信任根沒固定」。今天一路要求「鎖 Rekor 公鑰、鎖 witness 公鑰」，但那些公鑰是誰發給你的、換了怎麼辦、被偷了怎麼辦，全都懸而未決——明天就把這顆「信任的最後一顆釘子」釘上。三條線：**① Sigstore 靠 TUF 散布信任根**——`root.json` 怎麼把 Fulcio／Rekor／CT log／witness 的公鑰打包發下來，為什麼不是寫死在程式裡、也不是 HTTPS 抓一抓就信；**② root rotation 與 threshold 簽章**——TUF 的 root 用門檻式多把金鑰簽，N→N+1 版必須被「舊 root」簽過才收，這樣就算換金鑰也不會斷鏈，以及第一次取得 root 的 TOFU 開機問題；**③ 角色分離把爆炸半徑關住**——root／targets／snapshot／timestamp 四種角色各管一段、各自的金鑰在線上程度不同，一把被偷不會全盤皆輸。程式面會示範：Java／Go 驗 `root.json` 的 threshold 簽章、拒收過期 metadata、以及安全地做 root 版本輪替（N+1 必須被 N 簽過）的思路。安全主軸一句話：**你這一路把信任「往上收斂」，最後全部收斂到 TUF root 這一份檔案——它就是整條供應鏈信任的最後一顆釘子，釘不牢，Day96～100 全部白做。** 這是全新主題，聚焦 TUF 信任根的散布、輪替與金鑰折損復原，不重述今天的 inclusion／consistency proof 機制。）
