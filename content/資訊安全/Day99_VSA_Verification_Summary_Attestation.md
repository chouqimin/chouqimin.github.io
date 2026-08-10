---
title: "Day 99：attestation 越驗越多拖垮 admit——用 VSA 把「驗證」與「消費驗證結果」拆開"
date: 2026-08-11
tags: ["VSA", "attestation", "admission-control", "supply-chain", "SLSA"]
---

接續 Day98 預告：Day96 驗「誰簽的」、Day97 驗「怎麼 build 的」、Day98 驗「裡面裝了什麼、現在安不安全」。三天下來，供應鏈信任是補齊了，但也埋下一個工程問題——**每一個 Pod 起容器的那一刻，admission 都要重新驗一大堆 attestation**：驗映像簽章、抓 Rekor 對透明日誌、對 provenance predicate 下 conditions、對 SBOM 的 `packages[]` 下 conditions、對 vuln 的 `vulnerabilities[]` 下 severity threshold……attestation 越加越多，admit 的延遲與可用性壓力就越大（承 Day72 的 slow/資源耗盡視角、Day91 的 webhook 單點）。今天談怎麼收斂它。

先把定位講清楚：**這是接續系列的延伸篇，不是重講 Day96／97／98 各自的驗證機制。** 那三天怎麼驗簽、怎麼鎖 issuer＋subject、怎麼對 predicate 內容下斷言，今天完全不重述。今天聚焦一件那三天沒碰、而且是「驗證越堆越多」之後才浮現的事——**驗證結果的收斂與消費**：把「做驗證」跟「消費驗證結果」拆成兩件事，用 **VSA（Verification Summary Attestation）** 讓 admit 從「每次重驗一大堆原始 attestation」變成「只驗一份可信摘要」。

延伸角度先講明白，這篇只走三條線：

> **① VSA 是什麼、解決什麼**——由一個可信的「驗證器」(policy verifier) 預先把簽章、provenance、SBOM、漏洞 gate 全驗完，產出一份 SLSA VSA，記錄「這個 digest 已通過哪套 policy、結果是 PASSED、達到什麼 SLSA 等級」；admit 只需驗這一份。
> **② 信任邊界搬家的代價**——admit 不再自己驗原始 attestation，等於把信任集中到「產 VSA 的那個 verifier」，於是 verifier 的 identity、policy 版本、VSA 的新鮮度變成新的必驗欄位。
> **③ 效能與可用性硬化**——admit-time 對外抓 Rekor／registry 的網路依賴怎麼收斂（本地鏡像 Rekor、referrers 快取、驗證結果快取 TTL 與撤權延遲的取捨）。

一句話先擺出全篇主軸：

> **當要驗的東西越來越多，把「驗證」與「消費驗證結果」拆開——但你只是把信任從「一堆原始 attestation」搬到「產 VSA 的 verifier ＋ 那份 summary 的新鮮度」，信任根一樣要釘死。**

---

## 一、問題：admit 那一刻，到底在做多少事

先把 Day96～98 累積下來的 admit-time 工作量攤開。一個 Pod `CREATE` 進來，Kyverno／policy-controller 對它引用的每個映像，大致要做：

1. 解析 tag → digest（或要求已是 digest），把 digest 釘死（承 Day22／Day96 `mutateDigest`）。
2. 抓映像簽章（OCI referrers 或 Rekor），驗簽、鎖 keyless issuer＋subject（Day96）。
3. 抓 provenance attestation，驗簽，再對 `predicate` 的 `buildType／builder.id／repository` 下 conditions（Day97）。
4. 抓 SBOM attestation，驗簽，再對 `packages[]` 下「禁用套件／授權」conditions（Day98）。
5. 抓 vuln attestation，驗簽，再對 `vulnerabilities[]` 下 severity threshold（Day98）。

每一步都可能是一次對 registry／Rekor 的**對外網路往返**加一次密碼學驗簽。乘上「一個 Pod 好幾個 container image」「一個 Deployment 滾動更新一次拉起幾十個 Pod」「HPA 尖峰同時擴容」，這條 admission 路徑就從「驗個簽章」變成「每個 Pod 都在同步阻塞地做五類外呼＋驗簽」。

後果有兩個，剛好都是系列前面警告過的老坑：

- **延遲**：admission webhook 是同步阻塞的，API server 在等它回話（承 Day91）。驗證越重，Pod 排程越慢，滾動更新與擴容越拖。
- **可用性**：只要 Rekor／registry 在尖峰時慢或掛，這五類外呼就跟著慢或失敗。而驗簽類政策正確的設定是 `failurePolicy: Fail`（fail-closed，承 Day91）——於是「外部依賴抖一下」直接等於「新 Pod 起不來」。這就是 Day72 那種「拖慢／耗盡就等於 DoS」的變形，只是這次的瓶頸是你自己加上去的驗證鏈。

你不能為了可用性把 `failurePolicy` 改成 `Ignore`——那等於供應鏈 gate fail-open，Day91／Day96 講過後果。真正的解法不是「少驗一點」，而是**把重活從 admit-time 搬走**。

---

## 二、VSA 是什麼、解決什麼（角度①）

核心觀念一句話：**「做驗證」跟「消費驗證結果」不必在同一個時間、同一個地方發生。**

把 Day96～98 那五類驗證，交給一個獨立的、可信的 **policy verifier**（可以是 CI 的一個 job、release gate、或叢集外一支專責服務）在**部署之前**一次做完。它驗完之後，不是把結果寫在某個資料庫，而是產出一份**簽章過的 attestation**，昭告：「映像 `sha256:abc…` 已經用 policy `v7` 驗過簽章＋provenance＋SBOM＋漏洞，結果 **PASSED**，達到 SLSA Build L3。」這份東西就是 **VSA（Verification Summary Attestation）**，是 SLSA 定義的一種 in-toto predicate。

它長這樣（`predicateType` 是 `https://slsa.dev/verification_summary/v1`，外層 in-toto Statement 結構跟 Day97／98 一致）：

```jsonc
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "registry.example.com/payments/api",
      "digest": { "sha256": "abc123..." } }   // 綁 digest 不綁 tag，承 Day22
  ],
  "predicateType": "https://slsa.dev/verification_summary/v1",
  "predicate": {
    "verifier": { "id": "https://ci.example.com/policy-verifier" }, // 誰驗的
    "timeVerified": "2026-08-11T02:14:00Z",                          // 何時驗的 → 新鮮度
    "resourceUri": "registry.example.com/payments/api@sha256:abc123...",
    "policy": {                                                      // 用哪套 policy 驗的
      "uri": "https://git.example.com/security/admit-policy@v7",
      "digest": { "sha256": "def456..." }
    },
    "inputAttestations": [                                           // 驗了哪些原始 attestation
      { "uri": "...provenance...", "digest": { "sha256": "..." } },
      { "uri": "...spdx-sbom...",  "digest": { "sha256": "..." } },
      { "uri": "...vuln-scan...",  "digest": { "sha256": "..." } }
    ],
    "verificationResult": "PASSED",                                 // 結論：PASSED / FAILED
    "verifiedLevels": [ "SLSA_BUILD_LEVEL_3" ],
    "slsaVersion": "1.0"
  }
}
```

（VSA v0.2 與 v1 的欄位路徑略有差異，例如 v0.2 沒有 `verifier`／`inputAttestations`、用 `slsaVersion` 搭 `dependencyLevels`；跟 Day97 provenance v0.2 vs v1 一樣，實作前先確認你的 verifier 產的是哪版，別把路徑寫死在錯的版本上。）

於是 admit-time 的工作從「驗五類原始 attestation」塌縮成一件事：**驗這一份 VSA 的簽章，並確認 `verificationResult == PASSED`。** 原本要抓 provenance／SBOM／vuln 三份 predicate、跑三組 conditions、可能三次外呼，現在變成抓一份 VSA、驗一次簽、看一個欄位。這就是收斂帶來的效能紅利——但先別急著爽，第四節就要算這筆紅利的代價。

要強調的是：**VSA 沒有讓任何一項驗證消失。** provenance 還是驗了、SBOM 還是驗了、CVE threshold 還是套了——只是**由 verifier 在 admit 之外做完**。admit 消費的是「摘要」，不是「省略」。

---

## 三、admit 只驗一份 VSA：政策怎麼寫

延用 Day96～98 那套 Kyverno `verifyImages ＋ attestations.conditions`，差別只在：這次只宣告**一種** attestation 型別（VSA），conditions 對的是 VSA 的欄位。

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-passed-vsa
spec:
  validationFailureAction: Enforce      # 真的擋（承 Day92/94）
  background: false
  webhookConfiguration:
    failurePolicy: Fail                  # fail-closed（承 Day91）
  rules:
    - name: verify-vsa-only
      match:
        any:
          - resources:
              kinds: ["Pod"]
              operations: ["CREATE", "UPDATE"]   # 別漏 UPDATE（承 Day92）
      verifyImages:
        - imageReferences: ["registry.example.com/payments/*"]
          attestations:
            - type: https://slsa.dev/verification_summary/v1
              attestors:
                - entries:
                    # 鎖「產 VSA 的 verifier」的簽章身分——不是各原始 build/scan workflow
                    - keyless:
                        subject: "https://ci.example.com/policy-verifier"
                        issuer: "https://token.actions.githubusercontent.com"
              conditions:
                - all:
                    # ① 必須 PASSED，不是「有 VSA 就放行」
                    - key: "{{ element.predicate.verificationResult }}"
                      operator: Equals
                      value: "PASSED"
                    # ② 鎖住「用哪一版 policy 驗的」——擋掉拿舊/弱 policy 產的 VSA
                    - key: "{{ element.predicate.policy.digest.sha256 }}"
                      operator: Equals
                      value: "def456..."
                    # ③ 新鮮度：timeVerified 不能太舊（示意，實作用 time_since/time_before）
                    - key: "{{ time_since('', element.predicate.timeVerified, '') }}"
                      operator: LessThan
                      value: "24h"
```

一樣先打預防針：**重點不在 YAML 語法**（不同 Kyverno／policy-controller 版本的 JMESPath 路徑與 time 函式寫法有差，`element` 是不是那樣展開、`time_since` 參數順序，實作前務必用 `kyverno test` 對一份真實 VSA 跑一遍）。重點是**三個判準都要顯式寫出來**，缺一個就退化成「有 VSA 就好」的假 gate：

1. **`verificationResult == PASSED`**——這是 VSA 存在的全部意義。只驗「有一份 VSA」不驗結論，就是 Day98 盲點①（只驗存在性不驗內容）在 VSA 層原封不動地重演。verifier 也會為 `FAILED` 的映像產 VSA（記錄「驗過，沒過」），你不看這欄就等於放行失敗品。
2. **鎖 `policy.digest`**——不然攻擊者可以拿一套**寬鬆的舊 policy**去產一份技術上 PASSED 的 VSA。鎖住 policy 的 digest，等於宣告「我只接受用『這一版、我認可的規則』驗出來的結論」。
3. **新鮮度（`timeVerified`）**——理由跟 Day98 一模一樣：**PASSED 是「當時」通過，不是「現在」安全**。CVE 資料庫會更新，一份三個月前 PASSED 的 VSA，今天可能對應著一個新爆的 Critical。第五節會展開這條與撤權的取捨。

還有一個關鍵設定原則：**admit 只宣告 VSA 這一種型別**。如果你在同一條政策裡又列 provenance、又列 SBOM、又列 vuln，那 VSA 的收斂效益就白費了——你會兩邊都驗。要嘛信任 VSA、admit 只驗它；要嘛不信、admit 自己驗原始 attestation。**不要既搬了信任、又不肯放下重活。**

---

## 四、信任邊界搬家的代價（角度②）

VSA 的效能紅利不是天上掉下來的，是拿**信任的集中**換的。原本 admit 自己驗五類原始 attestation，信任分散在「各 build/scan workflow 的 identity＋各份 predicate 的內容」；用了 VSA 之後，admit 對這些**一律不看**，只信「產 VSA 的那個 verifier 說 PASSED」。

這代表信任邊界整個搬了家。搬家之後，有三個欄位從「參考資訊」升格成「**admit 必驗**」：

- **verifier 的 identity**：這是新的信任單點。誰能簽出你叢集會接受的 VSA，誰就能讓任意映像進來——因為 admit 不再自己驗原始證據了。所以 `attestors` 那段鎖的 issuer＋subject，鎖的必須是**那個 verifier 專屬、且不受 PR／一般開發者污染的**簽章身分（承 Day96 盲點②、Day97「build 自填欄位不可信」的同一個道理：產結論的實體要在被驗對象的污染範圍之外）。verifier 若能被任何 CI job 冒名，整套 VSA 就是空的。
- **policy 版本（`policy.uri` / `policy.digest`）**：VSA 說「PASSED」永遠要追問「**用哪套規則判的**」。verifier 的 policy 被人偷偷降級（把 Critical 從拒改成放、把 identity 鎖拿掉），它照樣產 PASSED。admit 鎖 `policy.digest`（第三節②）只是下游防線，上游得治理：**verifier 的 policy 要版本控管、變更要 review、要進 SIEM**（承 Day16）。
- **VSA 的新鮮度（`timeVerified`）**：信任集中之後，「這份結論是什麼時候做出來的」變得更關鍵。因為 admit 已經不看原始證據了，它對「世界變了沒」的唯一感知，就剩 VSA 上那個時間戳。

把它跟 Day97 的收尾接起來就是：**信任根一樣要釘死，只是這次的「信任根」從一堆原始 attestation 收斂成了「verifier 的身分 ＋ policy 版本 ＋ 那份 summary 的新鮮度」。** 你沒有讓信任變少，你讓信任變**集中**——集中的東西，防護要更硬，不是更鬆。

---

## 五、效能與可用性硬化（角度③）

VSA 把「五類外呼」收斂成「一份 VSA」，已經砍掉大半 admit-time 的對外依賴。但只要 admit 還要**抓那份 VSA、還要對 Rekor 查它在不在透明日誌**，網路依賴就沒歸零。這一節談把剩下的依賴也收斂掉，同時不把安全性一起收斂掉。

**1）本地鏡像 Rekor / 就近取 attestation。** admit-time 直接打公有 Rekor／外部 registry，等於把叢集的 Pod 排程可用性綁在外部服務的 SLA 上（承 Day72 的可用性視角）。做法是在叢集內或就近部署 **Rekor 鏡像**、把 attestation 走 **OCI referrers 就近快取**，讓 admit 的讀取留在你控制的網路內。代價是——鏡像會不會落後、會不會被動手腳？這正是「你信任集中到哪、就要監控哪」的延伸（也是明天要談的透明日誌信任問題）。

**2）驗證結果快取 ＋ TTL。** 同一個映像 digest 短時間內被大量 Pod 引用（滾動更新、HPA 擴容），沒必要每個 Pod 都重驗一次 VSA。對 `digest → 驗證結果` 做快取，能把尖峰的驗簽量壓下來。但快取 TTL 是一把雙面刃：

> **快取 TTL 太短 → 效能紅利吐回去；太長 → 撤權延遲變長。**

「撤權延遲」是這裡的安全核心。假設某映像的 VSA 因為新爆 CVE 被 verifier 撤銷（或重驗成 FAILED），但你的 admit 快取還記著三十分鐘前那個 PASSED——這三十分鐘內，被撤銷的映像照樣進得來。這跟 Day78 憑證撤銷「soft-fail 的空窗」是同一種取捨：**你必須明確決定，能接受多長的撤權空窗，並把 TTL 設在那條線內**，而不是為了效能無腦拉長。高風險命名空間 TTL 短一點、甚至不快取；一般負載可以放寬。

**3）新鮮度是快取之外的第二道閘。** 就算不談撤銷，第三、四節那條「`timeVerified` 不能太舊」本身就是抵抗 stale 的關鍵：CVE 狀態會漂移，一份夠舊的 PASSED 就該被要求「拿去重驗、產張新的 VSA 再來」。**新鮮度閘管的是「結論會過期」，快取 TTL 管的是「我多快感知到結論被推翻」**——兩者是不同的旋鈕，別混為一談，也別只設一個。

一句話收束這節：**效能硬化的每一步（鏡像 Rekor、referrers 快取、結果快取）都是在「拿更多信任換更少外呼」，所以每一步都要配一個對應的監控或時效閘，否則你省下的延遲會變成看不見的安全空窗。**

---

## 六、四個「驗了等於沒驗」的盲點

VSA 特別容易讓人以為「我有在驗供應鏈」，實際上驗了個寂寞。四個最常見的：

1. **只驗「有 VSA」不驗 `verificationResult == PASSED`。** 最致命也最常見。verifier 對 FAILED 的映像也會產 VSA，你不看結論就等於把失敗品當通過品放進來。這是 Day98 盲點①在 VSA 層的翻版，價值 100% 在「驗結論內容」而不是「驗存在性」。
2. **不鎖 verifier identity、不鎖 policy 版本。** 前者讓任何人都能冒名產 PASSED（信任單點失守），後者讓人用寬鬆舊 policy 洗出一張技術上 PASSED 的 VSA（第四節）。兩個一起漏，VSA 形同虛設。
3. **VSA 過期／stale 照收。** 沒有新鮮度閘，一份幾個月前的 PASSED 可以無限期通行，完全接不住這期間新爆的 CVE。PASSED 是「當時」不是「現在」——這句話 Day98 對 vuln 講過，對 VSA 一字不改地成立，而且更危險，因為 VSA 把「現在該不該放」這件事整包代理掉了。
4. **admit 還同時驗一堆原始 attestation，或反過來完全放掉 admit 只信 CI。** 前者白費 VSA 的收斂（兩邊都驗，沒省到）；後者是把 gate 從「東西真的要跑起來的最後一關」退回 CI，於是繞過 CI 的手動 `kubectl apply` 就全逃了（承 Day96／98「admit 是唯一涵蓋所有部署路徑的必經之路」）。正解是**admit 只驗 VSA、但 admit 一定要驗**——收斂的是「驗什麼」，不是「要不要在 admit 驗」。

---

## 七、稽核：把兩類漏洞掃成 CI（承 Day16）

跟 Day92／94／95／96／97／98 跑**同一條 pipeline**。VSA 有兩個面向要掃：**執行期**（叢集裡有沒有 Pod 用了「沒有對應 PASSED VSA」或「VSA 已過期」的映像）與**組態**（VSA 政策本身是不是真的在驗內容）。下面 Go 掃執行期、Java 掃組態。

### Go（Go 1.21）——掃「跑著的 Pod 有沒有合格 VSA」

思路：`kubectl` 撈全叢集 Pod，從 `status.containerStatuses[].imageID` 取**真正跑起來的 digest**（不是 spec 裡可能還是 tag 的 image），對每個 unique digest 用 `cosign` 取 VSA、檢查 `verificationResult` 與 `timeVerified` 新鮮度。抓三類問題：(a) 根本沒有 VSA；(b) 有 VSA 但不是 PASSED；(c) VSA 過期。

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const freshnessSLA = 24 * time.Hour

type podList struct {
	Items []struct {
		Metadata struct {
			Name, Namespace string
		} `json:"metadata"`
		Status struct {
			ContainerStatuses []struct {
				Image   string `json:"image"`
				ImageID string `json:"imageID"` // 例：registry/api@sha256:abc...
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

// VSA predicate 只取我們要判的欄位
type vsaPredicate struct {
	Predicate struct {
		VerificationResult string `json:"verificationResult"`
		TimeVerified       string `json:"timeVerified"`
	} `json:"predicate"`
}

// 回傳這個 digest 的 VSA 判定結果字串；空字串代表合格
func checkVSA(imageRef string) string {
	// 概念示意：實際用 cosign verify-attestation 並鎖 verifier identity（承 Day96）
	out, err := exec.Command("cosign", "verify-attestation",
		"--type", "https://slsa.dev/verification_summary/v1",
		"--certificate-identity", "https://ci.example.com/policy-verifier",
		"--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
		imageRef, "--output", "json").Output()
	if err != nil {
		return "沒有可驗證的 VSA（盲點①/②：缺 VSA 或驗簽失敗）"
	}
	var v vsaPredicate
	if err := json.Unmarshal(out, &v); err != nil {
		return "VSA 解析失敗"
	}
	if v.Predicate.VerificationResult != "PASSED" {
		return fmt.Sprintf("VSA 結論=%s，不是 PASSED（盲點①）", v.Predicate.VerificationResult)
	}
	t, err := time.Parse(time.RFC3339, v.Predicate.TimeVerified)
	if err != nil {
		return "timeVerified 無法解析（新鮮度不可判＝視為不合格）"
	}
	if time.Since(t) > freshnessSLA {
		return fmt.Sprintf("VSA 過期：timeVerified=%s 超過 SLA（盲點③）", v.Predicate.TimeVerified)
	}
	return ""
}

func main() {
	out, err := exec.Command("kubectl", "get", "pods", "-A", "-o", "json").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kubectl 失敗：", err)
		os.Exit(2)
	}
	var pl podList
	if err := json.Unmarshal(out, &pl); err != nil {
		fmt.Fprintln(os.Stderr, "解析失敗：", err)
		os.Exit(2)
	}

	seen := map[string]string{} // digest → 判定結果，避免重複驗同一映像
	failed := false
	for _, p := range pl.Items {
		for _, cs := range p.Status.ContainerStatuses {
			ref := cs.ImageID
			if !strings.Contains(ref, "@sha256:") {
				// 跑著的容器竟然不是 by-digest，本身就是紅旗（承 Day22/Day96）
				fmt.Printf("FAIL %s/%s：image 非 by-digest（%s），無法對應 VSA\n",
					p.Metadata.Namespace, p.Metadata.Name, cs.Image)
				failed = true
				continue
			}
			verdict, ok := seen[ref]
			if !ok {
				verdict = checkVSA(ref)
				seen[ref] = verdict
			}
			if verdict != "" {
				fmt.Printf("FAIL %s/%s：%s → %s\n",
					p.Metadata.Namespace, p.Metadata.Name, ref, verdict)
				failed = true
			}
		}
	}
	if failed {
		os.Exit(1) // CI 判紅
	}
	fmt.Println("OK：所有執行中 Pod 的映像都有新鮮且 PASSED 的 VSA")
}
```

### Java（Java 21）——掃「VSA 政策有沒有真的在驗內容」

思路：撈 Kyverno `ClusterPolicy`，找出宣告了 VSA 型別的 `verifyImages`，檢查它的 `conditions` 有沒有同時覆蓋三個判準（PASSED、鎖 policy.digest、新鮮度），以及 `attestors` 有沒有鎖 identity。這支專治盲點①②——「有 VSA 政策，但只驗存在性」。

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class VsaPolicyAudit {

    private static final String VSA_TYPE =
            "https://slsa.dev/verification_summary/v1";
    private static final ObjectMapper M = new ObjectMapper();

    // 把整段 conditions 攤成純文字，關鍵字有沒有出現一次判斷（示意；嚴謹版應逐條解析 key）
    private static boolean mentions(String conditionsText, String needle) {
        return conditionsText.contains(needle);
    }

    public static void main(String[] args) throws Exception {
        // kubectl get clusterpolicies -o json 的輸出從 stdin 餵進來
        JsonNode root = M.readTree(System.in);
        boolean failed = false;

        for (JsonNode pol : root.path("items")) {
            String name = pol.at("/metadata/name").asText();
            String action = pol.at("/spec/validationFailureAction").asText();

            for (JsonNode rule : pol.at("/spec/rules")) {
                for (JsonNode vi : rule.path("verifyImages")) {
                    for (JsonNode at : vi.path("attestations")) {
                        if (!VSA_TYPE.equals(at.path("type").asText())) continue;

                        String conds = at.path("conditions").toString();

                        if (at.path("attestors").isMissingNode()
                                || at.path("attestors").isNull()) {
                            System.out.printf("FAIL %s：VSA 沒鎖 attestors identity（盲點②，承 Day96）%n", name);
                            failed = true;
                        }
                        if (!mentions(conds, "verificationResult")) {
                            System.out.printf("FAIL %s：VSA 沒驗 verificationResult==PASSED（盲點①）%n", name);
                            failed = true;
                        }
                        if (!mentions(conds, "policy")) {
                            System.out.printf("FAIL %s：VSA 沒鎖 policy 版本/digest（盲點②）%n", name);
                            failed = true;
                        }
                        if (!mentions(conds, "timeVerified") && !mentions(conds, "time_since")) {
                            System.out.printf("FAIL %s：VSA 沒有新鮮度判準（盲點③）%n", name);
                            failed = true;
                        }
                    }
                }
            }
            if ("Audit".equals(action)) {
                System.out.printf("FAIL %s：validationFailureAction=Audit，沒真的擋（承 Day92/94）%n", name);
                failed = true;
            }
        }
        if (failed) System.exit(1);   // CI 判紅
        System.out.println("OK：VSA 政策都有鎖 identity + PASSED + policy 版本 + 新鮮度 + Enforce");
    }
}
```

（Java 1.8 環境把 `var` 換成明確型別、text block 換成一般字串即可；本例未用到 1.8 缺的 API。）

**CI 靜態掃不到、要靠別的手段補的**：verifier 的 policy 內容對不對（那要對 verifier 自己做 review 與版控，是治理流程不是 CI 字串比對）、快取 TTL 設多長才符合你的撤權空窗容忍度（那是風險決策）、Rekor 鏡像有沒有落後或被動手腳（那要對透明日誌本身做監控——明天的主題）。執行期承 Day16：**VSA 政策變更、verifier policy 版本變更、admit 對 VSA 的 deny 事件都進 SIEM**，對「PASSED VSA 過期率上升」「某 verifier 突然為異常多的 digest 產 VSA（可能被冒名）」「deny 歸零（可能被改成 Audit）」告警。

---

## 八、Code Review checklist

- admit 政策**只宣告 VSA 一種型別**，沒有又同時列 provenance／SBOM／vuln（否則收斂白費，盲點④）。
- conditions 同時覆蓋 **`verificationResult == PASSED`**、**鎖 `policy.digest`**、**新鮮度（`timeVerified`）**三條，缺一不可（盲點①③）。
- `attestors` 鎖的是**產 VSA 的 verifier**專屬 identity（issuer＋subject），不是各原始 build/scan workflow（盲點②、承 Day96）。
- `validationFailureAction: Enforce` ＋ webhook `failurePolicy: Fail`（fail-closed，承 Day91/92/94）。
- `operations` 含 **CREATE＋UPDATE**（承 Day92），映像走 by-digest（承 Day22/96）。
- 驗證結果快取有 **TTL**，且 TTL ≤ 可接受的撤權空窗（承 Day78 soft-fail 取捨）。
- verifier 的 **policy 有版控、變更要 review 並進 SIEM**（信任邊界搬家後的治理，第四節）。
- Rekor／attestation 的 admit-time 讀取有**就近鏡像／快取**，且鏡像本身納入監控（第五節）。

## 九、測試怎麼寫（最關鍵是「FAILED 擋得下」與「過期擋得下」兩條）

- **FAILED 演練**：拿一份 `verificationResult: FAILED` 的 VSA 送 Pod，斷言被拒——這條專防盲點①「只驗有 VSA」。
- **過期演練**：拿一份 `timeVerified` 超過 SLA 的 PASSED VSA，斷言被擋（而不是因為「有 PASSED」就放行）——防 stale。
- **冒名 verifier 演練**：用一個非受信 identity 簽出來的 PASSED VSA，斷言驗簽關先擋下（承 Day96）。
- **舊 policy 演練**：拿一份用「非白名單 `policy.digest`」產的 PASSED VSA，斷言被擋——防「用寬鬆舊規則洗 VSA」。
- **收斂正確性演練**：確認 admit 在只驗 VSA 的情況下，對「provenance 該擋的映像」仍會擋——因為那個映像的 VSA 會是 FAILED 或根本沒有。這條驗證「把重活搬給 verifier」沒有把安全性一起搬掉。
- **撤權空窗演練**：撤銷某 digest 的 VSA 後，量測 admit 在 TTL 內／外的行為，確認空窗長度符合預期。
- **稽核迴歸**：把 VSA 政策的某條 conditions（PASSED／policy／新鮮度）拿掉，斷言第七節的 Go／Java 稽核在 CI 判紅。

---

## 十、一句話總結

> Day96 驗「誰簽的」、Day97 驗「怎麼 build 的」、Day98 驗「裡面裝了什麼」——三天累積下來，admit 那一刻要驗的 attestation 越來越多，延遲與可用性（承 Day72／91）跟著惡化。今天的解法不是少驗，而是**把「做驗證」與「消費驗證結果」拆開**：由一個可信的 policy verifier 在 admit 之外把簽章＋provenance＋SBOM＋漏洞全驗完，產出一份 **SLSA VSA**（記錄「這個 digest 用哪套 policy 驗過、結果 PASSED、達到什麼 SLSA 等級」），admit 只驗這一份 VSA 的簽章與 `verificationResult == PASSED`，把「重驗多份」塌縮成「驗一份摘要」。但這份效能紅利是拿**信任的集中**換的：admit 不再自己看原始證據，於是 **verifier 的 identity、policy 版本（`policy.digest`）、VSA 的新鮮度（`timeVerified`）** 三個欄位從參考資訊升格成必驗——信任沒變少，只是變集中，集中的東西防護要更硬。四個「驗了等於沒驗」的盲點：**①只驗有 VSA 不驗 PASSED**（價值全在結論）、**②不鎖 verifier identity 與 policy 版本**（信任單點失守／舊 policy 洗 VSA）、**③VSA 過期照收**（PASSED 是「當時」不是「現在」，CVE 會漂移）、**④白費收斂或退回 CI**（admit 只驗 VSA、但 admit 一定要驗）。效能硬化每一步——本地鏡像 Rekor、referrers 快取、驗證結果快取——都是「拿更多信任換更少外呼」，所以每步都要配對應的監控或時效閘（快取 TTL ≤ 撤權空窗，承 Day78）。稽核（承 Day16）用 Go 掃「跑著的 Pod 有沒有新鮮且 PASSED 的 VSA」、Java 掃「VSA 政策是不是真的在驗內容」，跟 Day92～98 同一條 pipeline，verifier policy 變更進 SIEM。一句話：**當要驗的東西越來越多，就把「驗證」與「消費驗證結果」拆開——用 VSA 讓 admit 只驗一份可信摘要，但務必記得，你只是把信任根從「一堆原始 attestation」搬到「產 VSA 的 verifier ＋ 那份 summary 的新鮮度」，信任根一樣要釘死。**

---

## 延伸閱讀

- **Day98 SBOM／漏洞 admission gate**——本篇收斂的對象之一：VSA 把 Day96/97/98 的驗證預先做完，其中「新鮮度」這條的道理（PASSED 是「當時」）直接繼承自 Day98 對 CVE 的討論。
- **Day97 provenance／SLSA attestation**——同屬 SLSA 家族，in-toto Statement 三層結構與「v0.2 vs v1 欄位路徑差異」的注意事項在 VSA 上一模一樣。
- **Day96 Sigstore 映像簽章驗證**——地基：VSA 的第一關仍是驗簽、鎖 issuer＋subject，只是這次鎖的是「產 VSA 的 verifier」。
- **Day91 admission webhook 與 `failurePolicy`**——為什麼 admit 驗得越重可用性壓力越大、為什麼還是得 fail-closed。
- **Day78 憑證撤銷 OCSP soft-fail**——驗證結果快取 TTL 與「撤權空窗」的取捨，跟 OCSP soft-fail 是同一類時效性風險決策。
- **Day72 Slowloris／slow HTTP DoS**——admit-time 對外抓 Rekor／registry 的網路依賴，是自己給自己加上的可用性瓶頸。
- **Day16 Security Logging／Monitoring**——VSA 政策變更、verifier policy 版本、deny 事件與 VSA 過期率進 SIEM。

---

明天預告：**Day 100 — 你把可用性押在「本地鏡像 Rekor」上，那面鏡子會不會對你說謊？——透明日誌（transparency log）的信任與監控：inclusion proof、consistency proof、split-view 攻擊與 witness／monitor**
（這是**接續系列的延伸篇**，把今天第五節「本地鏡像 Rekor、admit-time 對透明日誌的依賴」拉出來單獨處理一個沒回答的問題：**Day96 起我們一路把信任押在「Rekor 說這條簽章在日誌裡」，但你憑什麼相信那份日誌（尤其是你為了可用性自建的鏡像）沒被動手腳、沒對不同人給不同版本？**延伸角度明確標示：**這不是重講 Day96 keyless 驗簽流程，而是聚焦「透明日誌本身的信任模型」**——三條線：**① 兩種證明**——`inclusion proof`（你的 entry 真的被收進日誌了，Merkle 路徑驗給你看）與 `consistency proof`（日誌只會 append、不會偷偷改寫歷史），這兩個是 admit 消費 Rekor 時該要而常常沒要的東西；**② split-view／分裂視圖攻擊**——一個被控制或作惡的日誌，可以對受害者給一個「有惡意 entry」的視圖、對稽核者給一個「乾淨」的視圖，光靠 inclusion proof 擋不住，要靠 **witness／gossip**（多方見證同一個 log root）才抓得到，這正是「自建鏡像 Rekor」最危險的盲區；**③ 監控 vs 阻擋的分工**——透明日誌的本質是「事後可稽核」不是「事前擋下」，所以要搭一支 **monitor**（持續拉 log、驗 consistency、對「出現我沒授權簽的 entry」告警，承 Day35 subdomain 那種主動偵測、Day16 SIEM）。程式面會示範：一段驗 inclusion proof 的 Merkle 路徑檢查、一支 monitor 持續驗 consistency proof 並比對 witness 根雜湊的 Go／Java 思路。安全主軸一句話：**透明日誌讓「作惡可被發現」，但「可被發現」不等於「已經有人在看」——你自建的那面鏡子，得有人拿另一面鏡子去對照它。** 這是接續系列的延伸篇，聚焦透明日誌的信任模型與監控，不重述 Day96 的 keyless 驗簽機制。）
