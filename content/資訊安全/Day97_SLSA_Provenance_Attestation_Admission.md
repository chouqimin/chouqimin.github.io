---
title: "Day 97：只驗簽章還不夠——在 admit 那一刻驗 provenance／SLSA attestation，不只問「誰簽的」還問「怎麼 build 出來的」"
date: 2026-08-07
tags: ["SLSA", "provenance", "attestation", "supply-chain", "admission-control"]
---

接續 Day96 預告：Day96 把 **Sigstore/cosign 映像簽章**落到 admit 那一刻，在 Pod 建立的瞬間問三個問題——**有沒有簽、是誰簽的（issuer＋subject）、admit 的 digest 對不對**。今天把供應鏈信任再往前推一層：**就算簽章對，這映像到底是怎麼 build 出來的？來源 repo 對不對？是不是在受保護的 CI 跑出來的？有沒有經過 fork PR 這種不受信任的觸發？** 這就是 **provenance／SLSA attestation** 要回答的事。

先說清楚定位：**這是接續系列的新主題，不是重新介紹 Day96 的簽章驗證機制，也不是重述 Day18 的供應鏈入門（SBOM、Trivy、govulncheck、dependency confusion 那些）。** 今天只聚焦一件事——**admission-time 的 provenance／attestation「內容」驗證**：不是驗「有沒有 attestation」，而是驗「attestation 裡面寫的那份 build 履歷，其欄位值符不符合我對『可信 build』的定義」。

一句話擺開兩者的分工：

> **簽章證明「是可信的人交付的」，provenance 證明「是用可信的方式、從可信的原始碼做出來的」。**

Day96 擋的是「被掉包／被冒名簽章的映像」；今天擋的是另一種更隱蔽的問題——**簽章完全合法，但這個映像是攻擊者用你信任的身分、在一條不受保護的路徑上 build 出來的**（例如：一個 fork PR 觸發的 CI、一個被塞了惡意步驟的 workflow、一份根本不是從你正牌 repo 來的原始碼）。

---

## 一、為什麼「簽章對」還不夠——一個具體的攻擊情境

Day96 教會你 keyless 一定要鎖 `issuer`＋`subject`，避免「任何人都能簽你的映像名」。假設你真的鎖好了：只接受 `subject` 是 `https://github.com/my-org/my-repo/.github/workflows/release.yml@refs/heads/main`、`issuer` 是 GitHub Actions 的 OIDC。看起來滴水不漏。

但請想像這個場景：

1. 你的 release workflow（`release.yml`）在某次改動裡，為了「方便測試」，加了一段 `on: pull_request` 的觸發條件，或某個 reusable workflow 被 fork PR 也能跑到。
2. 攻擊者送一個 fork PR，PR 裡動了 build script，把後門編進映像。
3. CI 在**同一個 `release.yml`、同一個 repo** 的 context 下跑起來，向 Fulcio 換到的 OIDC 身分**subject 完全一樣**。
4. cosign 簽了這個帶後門的映像，Rekor 也記了。**你的 admission 簽章政策，一個字都挑不出毛病。**

問題出在哪？**簽章的 identity 只證明「這是 `release.yml` 這個 workflow 簽的」，但沒有證明「這次 build 的觸發者、原始碼 ref、build 參數是可信的」。** 那份資訊在哪？——在 **provenance predicate** 裡。SLSA provenance 會如實記錄「這映像是哪個 `buildType`、`sourceUri` 是哪個 repo、`invocation` 是被什麼事件觸發的、build 在什麼環境跑的」。

**驗簽章看的是「憑證上的身分」，驗 provenance 看的是「build 履歷的內容」。前者攻擊者可以在合法身分下偽造一份漂亮履歷，除非你真的去讀履歷內容。**

---

## 二、attestation 長什麼樣——in-toto 信封與 SLSA predicate

cosign 的 attestation 不是憑證，而是一份**被簽章的 JSON 聲明**，格式是 **in-toto attestation**。結構分三層，理解這三層才知道「該對哪裡下斷言」：

```jsonc
{
  // 外層：in-toto Statement
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    { "name": "ghcr.io/my-org/app",
      "digest": { "sha256": "abc123..." } }      // 這份履歷是關於哪個映像 digest
  ],
  "predicateType": "https://slsa.dev/provenance/v1", // 履歷的「型別」
  "predicate": {
    // 內層：SLSA provenance v1 的實際內容 —— 真正要驗的地方
    "buildDefinition": {
      "buildType": "https://actions.github.io/buildtypes/workflow/v1",
      "externalParameters": {
        "workflow": {
          "ref": "refs/heads/main",
          "repository": "https://github.com/my-org/my-repo",
          "path": ".github/workflows/release.yml"
        }
      },
      "resolvedDependencies": [
        { "uri": "git+https://github.com/my-org/my-repo@refs/heads/main",
          "digest": { "gitCommit": "def456..." } }
      ]
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/my-org/my-repo/.github/workflows/release.yml@refs/heads/main"
      },
      "metadata": {
        "invocationId": "https://github.com/my-org/my-repo/actions/runs/123/attempts/1"
      }
    }
  }
}
```

（註：SLSA provenance 有 **v0.2** 與 **v1** 兩版，欄位路徑差很多——v0.2 是 `predicate.invocation.configSource.uri`、`predicate.builder.id`；v1 改成 `predicate.buildDefinition.externalParameters.*` 與 `predicate.runDetails.builder.id`。GitHub Actions 產的 predicate 內容也隨 `actions/attest-build-provenance` 版本演進。**實作前務必對你那個版本 dump 一份真的 predicate 出來看欄位路徑，別照抄本文字串。** 這點跟 Day96 提醒「Kyverno 欄位隨版本改」同一個道理。）

整個信任鏈是這樣扣起來的：

- **cosign attest** 在 CI 產出這份 Statement，並用**跟簽映像同一把 keyless／keyful 身分**簽它 → 所以驗 attestation 的第一步，仍然是 Day96 那套「驗簽、鎖 issuer＋subject」。**Day96 是地基，今天蓋在它上面。**
- **subject.digest** 把履歷綁到具體映像 digest → 換句話說，attestation 也是綁 digest 不綁 tag，TOCTOU 那套（承 Day22）一樣要防。
- **predicate 內容** 才是今天新增的驗證面：`buildType`、`repository`、`ref`、`builder.id` 這些欄位，要拿去跟「我心中可信 build 的樣子」逐條比對。

---

## 三、在 admit 驗 predicate 內容——Kyverno verifyImages 的 attestations 條件

Day96 的 `verifyImages` 只驗簽章存在性與 identity。要驗 provenance 內容，多加一個 `attestations` 區塊，在裡面對 predicate 的欄位下 `conditions`：

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-trusted-provenance
spec:
  validationFailureAction: Enforce      # 承 Day96：安全政策不留 Audit（fail-open 的一種）
  webhookConfiguration:
    failurePolicy: Fail                  # 承 Day91/96：弄掛驗證器不能等於放行
  rules:
    - name: check-slsa-provenance
      match:
        any:
          - resources:
              kinds: ["Pod"]
              operations: ["CREATE", "UPDATE"]   # 承 Day92：漏 UPDATE 就能先建後 patch 繞過
      verifyImages:
        - imageReferences:
            - "ghcr.io/my-org/*"
          failureAction: Enforce
          required: true                 # 不符合的映像要「被拒」而非「略過」
          mutateDigest: true             # 承 Day96：把 tag 釘成 digest，驗的＝跑的
          attestor:                      # 第一關仍是驗簽（Day96），鎖死身分
            - entries:
                - keyless:
                    issuer: "https://token.actions.githubusercontent.com"
                    subject: "https://github.com/my-org/my-repo/.github/workflows/release.yml@refs/heads/main"
                    rekor:
                      url: "https://rekor.sigstore.dev"
          attestations:                  # 第二關才是今天的重點：驗 predicate 內容
            - type: "https://slsa.dev/provenance/v1"
              attestors:
                - entries:
                    - keyless:           # attestation 本身也要是可信身分簽的
                        issuer: "https://token.actions.githubusercontent.com"
                        subject: "https://github.com/my-org/my-repo/.github/workflows/release.yml@refs/heads/main"
              conditions:
                - all:
                    # ① 來源 repo 必須是我的正牌 repo
                    - key: "{{ buildDefinition.externalParameters.workflow.repository }}"
                      operator: Equals
                      value: "https://github.com/my-org/my-repo"
                    # ② build 觸發的 ref 必須是受保護分支，不能是 tag/PR ref
                    - key: "{{ buildDefinition.externalParameters.workflow.ref }}"
                      operator: Equals
                      value: "refs/heads/main"
                    # ③ builder 必須是我指定的那條 workflow（鎖死 builder.id）
                    - key: "{{ runDetails.builder.id }}"
                      operator: Equals
                      value: "https://github.com/my-org/my-repo/.github/workflows/release.yml@refs/heads/main"
                    # ④ buildType 必須是 GitHub Actions，不接受不明 builder
                    - key: "{{ buildDefinition.buildType }}"
                      operator: Equals
                      value: "https://actions.github.io/buildtypes/workflow/v1"
```

回頭看第一節那個 fork PR 攻擊：即使簽章 identity 對，只要 fork PR 是以 `refs/pull/xxx/merge` 之類的 ref 觸發、或 `repository` 是 fork 出去的位址，**條件 ①② 就當場攔下**。這正是「驗履歷內容」補上「驗簽章」漏掉的那一塊。

（policy-controller 的 `ClusterImagePolicy` 走的是另一套 schema——`policy` 欄位用 **CUE 或 Rego** 對 predicate 下斷言，例如一段 Rego：`input.predicate.buildDefinition.buildType == "https://actions.github.io/buildtypes/workflow/v1"`。表達力比 Kyverno 的 `conditions` 更強，但也更容易寫錯，一樣要對照你版本的 schema。）

---

## 四、後端／CI 的接點——從 `cosign attest` 產出到 admission 消費

這條鏈要成立，CI 端得先「誠實地」產出 provenance，admission 端才有東西可驗。後端工程師實際會碰到的接點：

**CI 產出（build 那一刻）：**

```bash
# 1) 簽映像（Day96）
cosign sign --yes "ghcr.io/my-org/app@${DIGEST}"

# 2) 產出並簽 SLSA provenance attestation
#    現代做法多用 GitHub 的 actions/attest-build-provenance 直接產（自動走 keyless），
#    或用 cosign attest 帶自產的 predicate：
cosign attest --yes \
  --predicate provenance.json \
  --type "https://slsa.dev/provenance/v1" \
  "ghcr.io/my-org/app@${DIGEST}"

# 3) 同場也可把 SBOM 當 attestation 一起帶（承 Day18，內容驗證留 Day98）
cosign attest --yes \
  --predicate sbom.spdx.json \
  --type spdxjson \
  "ghcr.io/my-org/app@${DIGEST}"
```

**admission 消費（deploy 那一刻）：** 就是第三節那份政策。

中間有個觀念要釐清——**SLSA build level 決定「這份 provenance 值不值得信」**：

- **provenance 是誰產的？** 如果是**build script 自己在容器裡呼叫 cosign attest**，那攻擊者只要能改 build script，就能連映像帶「漂亮的假 provenance」一起產出來簽——**provenance 跟被它描述的成品出自同一個可被污染的環境，等於自己幫自己開證明**。這對應 SLSA 較低的 build level。
- **higher build level** 要求 provenance 由**與 build 隔離的可信 builder**產生（例如 GitHub 的 provenance 是平台在 workflow 外層產、build job 動不到），`buildType`、`ref`、觸發者這些欄位是平台如實填的，build script 竄改不了。**這才是 provenance 可信的前提：產 provenance 的實體，要在 build 能污染的範圍之外。**
- 所謂 **hermetic／isolated build** 的假設也在這裡——build 過程無法對外拉不受控的依賴、無法影響 provenance 的生成，`resolvedDependencies` 才有意義。

實務上後端不必自己實作 builder 隔離，但**要知道「你 admission 政策信的那份 provenance，是不是由 build 動不到的實體產的」**。如果 provenance 是 build script 自己 `cosign attest` 產的，那第三節的 `conditions` 只是在驗一份「攻擊者也能填的表格」——**這就直接引出下一節的盲點①。**

---

## 五、四個「驗了等於沒驗」的盲點

Day96 有它的四大盲點；provenance 驗證有一組**平行、且更隱蔽**的盲點，本質是「Day96 盲點②（只驗有沒有簽、不驗誰簽）在 attestation 層的重演與加深」。

**盲點①：只驗「有沒有 provenance」，不驗 predicate 內容。**
最常見。政策只寫 `attestations: [{ type: "https://slsa.dev/provenance/v1" }]` 但沒有 `conditions`，等於只確認「這映像附了一張叫 provenance 的紙」，紙上寫什麼一概不看。**任何人只要能 `cosign attest` 一份 predicate（內容隨便填 `repository: evil/repo`），就通過。** 這跟 Day96「只驗有沒有簽、不驗誰簽」是同一個錯——差別只在這次被無視的是「履歷內容」而非「簽章身分」。**驗 provenance 的價值 100% 在 `conditions`，沒有 conditions 的 attestation 政策是零信任價值的裝飾。**

**盲點②：`builder.id`／`buildType` 沒鎖——誰都能宣稱自己是可信 builder。**
predicate 裡的 `runDetails.builder.id` 是「宣稱」，不是「保證」。如果你的 `conditions` 只驗了 `repository` 和 `ref`，卻沒鎖 `builder.id` 和 `buildType`，攻擊者可以在一個**不受保護的 builder**（自架的、或某個沒有隔離保證的 CI）上，產一份 `repository`／`ref` 都填對、但 `builder.id` 指向他自己 builder 的 provenance。**你以為驗了來源，其實沒驗「是在哪條受信任的 pipeline 跑的」。** 鎖 `builder.id` 到你確切那條 workflow，才擋得住「對的原始碼、錯的 builder」。

**盲點③：predicate 欄位的信任邊界搞錯——把 build 能自填的欄位當可信依據。**
這是最需要腦子的一點：**predicate 裡的欄位，不是每一個都同等可信。** 由**隔離的 builder 平台如實填入**的欄位（GitHub Actions 的 `repository`、`ref`、觸發事件）可信；但如果某些欄位是 **build script 自己塞進去的**（例如自訂的 metadata、非平台保證的 field），那它跟映像內容一樣可被污染，拿它做安全判斷等於沒判。**下斷言前要問：這個欄位是誰填的？build 能不能改它？** 只對「build 改不動的平台欄位」下斷言才有意義（呼應第四節——provenance 可信的前提是產它的實體在 build 之外）。

**盲點④：「SLSA 等級宣稱」與「實際 build 隔離」脫節。**
一份 provenance 可以宣稱自己符合某個 SLSA level，但**宣稱不等於實際做到隔離**。如果你的 pipeline 實際上是 build script 自產 provenance（低隔離），卻在文件或政策裡當它是高 level 在信，那所有基於 provenance 的判斷都建立在流沙上——**跟 Day96 盲點③「信任根沒固定」同型：驗證鏈的根（產 provenance 的那個實體）如果本身不可信，底下驗得再嚴都能被抽換。**

---

## 六、常見誤區

- **「我驗了簽章（Day96）就不用驗 provenance」**：錯。簽章證明「可信身分交付」，provenance 證明「可信方式從可信原始碼做出」——第一節那個 fork PR 攻擊簽章完全合法，只有驗 provenance 內容才擋得住。兩件事、都要。
- **「有 attestation 就是可信 build」**：錯，最危險（盲點①）。任何人都能 `cosign attest` 一份亂寫的 predicate。沒 `conditions` 的 attestation 政策＝零價值。
- **「我驗了 repository 和 ref 就夠了」**：不夠（盲點②）。沒鎖 `builder.id`／`buildType`，攻擊者可用對的原始碼在錯的 builder 上產 provenance。
- **「predicate 裡寫什麼都能拿來驗」**：錯（盲點③）。只有 build 改不動的平台欄位才可信，build script 自填的欄位跟映像內容一樣可被污染。
- **「provenance 是 build script 自己產的，一樣能信」**：錯（盲點④／第四節）。產 provenance 的實體必須在 build 能污染的範圍之外，否則等於自己幫自己開證明。
- **「SLSA level 宣稱高就代表隔離做得好」**：錯。宣稱不等於實作，等級標籤與實際 build 隔離要對得上。

---

## 七、Code Review checklist

- [ ] attestation 政策**有 `conditions`**，不是只驗 `type` 存在（盲點①）——這是最該 grep 的：找「有 `attestations` 但底下沒 `conditions`／`policy`」的政策。
- [ ] `conditions` 同時鎖 **`repository`＋`ref`＋`builder.id`＋`buildType`**（盲點②）；`ref` 鎖到受保護分支，不接受 tag／PR ref。
- [ ] 下斷言的欄位都是 **build 改不動的平台欄位**，沒有拿 build script 自填欄位當安全依據（盲點③）。
- [ ] 清楚 provenance 由**與 build 隔離的 builder**產生，不是 build script 自產（盲點④／第四節）；SLSA level 宣稱與實際隔離對得上。
- [ ] attestation 本身的簽章有鎖 **issuer＋subject**（承 Day96），不是只驗「有簽」。
- [ ] 政策 **`failurePolicy: Fail`＋`validationFailureAction/failureAction: Enforce`**（承 Day91/96，不 fail-open）。
- [ ] `required: true`、`mutateDigest: true`（承 Day96，驗的 digest＝跑的 digest）。
- [ ] `match` 同時含 **CREATE 與 UPDATE**、有 background scan 盯既存工作負載（承 Day92/96 盲點④）。
- [ ] CI 端 `cosign attest` 產的 predicate 版本（v0.2 vs v1）與 admission 端 `conditions` 的欄位路徑對得上——別因版本升級靜默失準。
- [ ] provenance 驗證政策變更進 SIEM（承 Day16），對「conditions 被移除／放寬」告警。

## 八、測試／演練建議

- **無 provenance 演練（最基本）**：推一個**只簽章、沒 attest provenance**的映像部署，斷言 **Pod 被拒**（`required: true` 生效）。
- **fork PR 冒名演練（盲點①＋第一節，最重要）**：產一份 `repository` 是 fork、`ref` 是 PR merge ref 的 provenance，用**合法簽章身分**簽它、部署，斷言在有 `conditions` 的政策下**仍被拒**；再把政策的 `conditions` 拿掉，斷言**同一個惡意 provenance 被放行**＝證明沒 conditions 等於沒驗。
- **錯 builder 演練（盲點②）**：`repository`／`ref` 都填對、但 `builder.id` 指向另一條 workflow，斷言在鎖了 `builder.id` 的政策下**被拒**；放寬掉 `builder.id` 條件，斷言**被放行**。
- **build 自填欄位演練（盲點③）**：對一個 build script 能自訂的 metadata 欄位下斷言，示範攻擊者把它填成通過值即可繞過——體會「只該對平台欄位下斷言」。
- **版本漂移演練**：把 CI 從 provenance v0.2 升到 v1（欄位路徑變），斷言舊的 `conditions`（指向 v0.2 路徑）**靜默失準**（條件取不到值的行為要驗證是拒絕而非放行）——這是升級最容易踩的坑。
- **UPDATE 繞過演練（承 Day92/96）**：先建合規 Pod，再 `patch` 換成沒過 provenance 的映像，`match` 漏 `UPDATE` 時斷言改動生效＝漏洞；補上 UPDATE 後斷言被拒。
- **稽核迴歸（第九節那支）**：把某政策的 `attestations.conditions` 移除、或只留 `repository` 不鎖 `builder.id`，斷言稽核 CI **判紅**。

---

## 九、把「只驗簽章沒驗 provenance 內容」掃成 CI——Go／Java 稽核

盲點①是最容易在一大堆政策裡被漏掉的：某條 `verifyImages` 有驗簽章、卻沒有（或有名無實地）驗 provenance 內容。承 Day16，把它掃成 CI gate。思路是解析叢集裡所有 Kyverno 政策的 JSON，對每條 `verifyImages` 判斷「有 attestor（驗簽）卻沒有帶 `conditions` 的 attestations（沒驗 provenance 內容）」。

**Go（client-go／或直接吃 `kubectl get cpol -o json`）：**

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// 只挑我們關心的欄位，其餘忽略
type policyList struct {
	Items []struct {
		Metadata struct{ Name string } `json:"metadata"`
		Spec     struct {
			Rules []struct {
				Name         string `json:"name"`
				VerifyImages []struct {
					ImageReferences []string `json:"imageReferences"`
					Attestor        []any    `json:"attestor"`
					Attestations    []struct {
						Type       string `json:"type"`
						Conditions []any  `json:"conditions"`
					} `json:"attestations"`
				} `json:"verifyImages"`
			} `json:"rules"`
		} `json:"spec"`
	} `json:"items"`
}

func main() {
	out, err := exec.Command("kubectl", "get", "cpol", "-A", "-o", "json").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kubectl 取政策失敗:", err)
		os.Exit(2)
	}
	var pl policyList
	if err := json.Unmarshal(out, &pl); err != nil {
		fmt.Fprintln(os.Stderr, "解析失敗:", err)
		os.Exit(2)
	}

	failed := false
	for _, p := range pl.Items {
		for _, r := range p.Spec.Rules {
			for _, vi := range r.VerifyImages {
				hasAttestor := len(vi.Attestor) > 0
				// 有沒有「帶 conditions」的 provenance attestation
				provWithConditions := false
				for _, at := range vi.Attestations {
					if len(at.Conditions) > 0 {
						provWithConditions = true
					}
				}
				// 驗了簽章，卻沒對 attestation 內容下任何斷言 → 盲點①
				if hasAttestor && !provWithConditions {
					fmt.Printf("FAIL %s/%s images=%v：有驗簽卻沒驗 provenance 內容（缺 attestations.conditions）\n",
						p.Metadata.Name, r.Name, vi.ImageReferences)
					failed = true
				}
			}
		}
	}
	if failed {
		os.Exit(1) // CI 判紅
	}
	fmt.Println("OK：所有驗簽政策都有搭配 provenance 內容驗證")
}
```

**Java 21（Jackson，`ProcessBuilder` 取政策）：**

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ProvenanceAudit {
    public static void main(String[] args) throws Exception {
        Process proc = new ProcessBuilder("kubectl", "get", "cpol", "-A", "-o", "json")
                .redirectErrorStream(false).start();
        JsonNode root = new ObjectMapper().readTree(proc.getInputStream());

        boolean failed = false;
        for (JsonNode pol : root.path("items")) {
            String name = pol.path("metadata").path("name").asText();
            for (JsonNode rule : pol.path("spec").path("rules")) {
                String ruleName = rule.path("name").asText();
                for (JsonNode vi : rule.path("verifyImages")) {
                    boolean hasAttestor = vi.path("attestor").isArray()
                            && vi.path("attestor").size() > 0;
                    boolean provWithConditions = false;
                    for (JsonNode at : vi.path("attestations")) {
                        JsonNode cond = at.path("conditions");
                        if (cond.isArray() && cond.size() > 0) provWithConditions = true;
                    }
                    if (hasAttestor && !provWithConditions) {
                        System.out.printf(
                            "FAIL %s/%s：有驗簽卻沒驗 provenance 內容（缺 attestations.conditions）%n",
                            name, ruleName);
                        failed = true;
                    }
                }
            }
        }
        if (failed) System.exit(1);       // CI 判紅
        System.out.println("OK：所有驗簽政策都有搭配 provenance 內容驗證");
    }
}
```

這支跟 Day96 的驗簽稽核、Day92/94/95 的 admission 政策稽核跑**同一條 pipeline**；provenance 政策的任何變更（尤其 `conditions` 被移除或放寬）進 SIEM 告警（承 Day16）。更進一步，可把「conditions 至少要鎖到 `builder.id`」也寫進判準，攔掉盲點②。

---

## 十、一句話總結

> Day96 教會在 admit 那一刻驗**映像簽章**（有沒有簽、是誰簽的、digest 對不對）之後，**最該補上的下一層，是驗這映像「怎麼 build 出來的」——provenance／SLSA attestation**。因為簽章只證明「可信身分交付」，而**一個合法身分（例如你正牌 `release.yml`）完全可能被 fork PR、被污染的 workflow 誘導去簽一個帶後門、卻 identity 一字不差的映像**——簽章政策挑不出毛病，只有讀 build 履歷內容才擋得住。attestation 是一份 **in-toto Statement**：外層綁 `subject.digest`（一樣綁 digest 不綁 tag，承 Day22）、`predicateType` 標型別、`predicate` 裡才是 **SLSA provenance** 的實際內容（`buildType`、`repository`、`ref`、`builder.id`）。驗它的第一關仍是 Day96 那套「驗簽、鎖 issuer＋subject」（**Day96 是地基**），第二關才是今天新增的——用 **Kyverno `verifyImages` 的 `attestations.conditions`**（或 policy-controller `ClusterImagePolicy` 的 CUE/Rego `policy`）**對 predicate 欄位逐條下斷言**：來源 repo 是不是我的、ref 是不是受保護分支、builder 是不是我指定那條 workflow、buildType 對不對。**真正要記的是四個「驗了等於沒驗」的盲點**：**①只驗「有 provenance」不驗 `conditions` 內容**——任何人都能 attest 一份亂寫 predicate，這是 Day96 盲點②在 attestation 層的重演，價值 100% 在 conditions；**②`builder.id`／`buildType` 沒鎖**——對的原始碼可以在錯的 builder 上產 provenance，要鎖死你那條 workflow；**③predicate 欄位信任邊界搞錯**——只有 build 改不動的平台欄位可信，build script 自填的欄位跟映像內容一樣可污染；**④SLSA 等級宣稱與實際隔離脫節**——產 provenance 的實體若在 build 污染範圍之內（build script 自產），等於自己幫自己開證明，跟 Day96 盲點③「信任根沒固定」同型。稽核（承 Day16）把「有驗簽卻沒驗 provenance 內容」用 Go／Java 掃成 CI，跟 Day92/94/95/96 的稽核跑同一條 pipeline，政策變更進 SIEM。一句話：**簽章證明「是可信的人交付的」，provenance 證明「是用可信的方式、從可信的原始碼做出來的」——把供應鏈信任從『誰簽的』再推進到『怎麼來的』，而且務必記得：驗的是履歷「內容」，不是履歷「存不存在」。**

---

## 延伸閱讀

- **Day96 Sigstore 映像簽章驗證**——本篇的地基：驗 provenance 的第一步仍是驗簽、鎖 issuer＋subject；今天在「簽章對」之上再問「build 履歷對不對」。
- **Day18 供應鏈 / SBOM / SLSA**——provenance 是 Day18 提過的 SLSA 概念在 admit 那一刻的落地；SBOM attestation 的內容驗證（漏洞閾值 gate）留到明天。
- **Day22 Race Condition / TOCTOU**——attestation 一樣綁 digest 不綁 tag，`mutateDigest` 讓「驗的 digest＝跑的 digest」，防 tag 掉包。
- **Day92 Kyverno 政策繞過**——`attestations` 是 `verifyImages` 的延伸；「只攔 CREATE 漏 UPDATE／既存要 background scan」的坑一模一樣。
- **Day91 admission webhook 與 `failurePolicy`**——provenance 驗證 fail-open 的後果同樣是「弄掛驗證器＝全放行」，必須 `Fail`。
- **Day16 Security Logging / Monitoring**——provenance 政策變更（尤其 conditions 被移除）與驗證失敗進 SIEM。
- **Day07 Broken Access Control**——「build 能自填的欄位別當安全依據」與「default deny」是同一種信任邊界思維。

---

明天預告：**Day 98 — provenance 驗完「怎麼來的」，再驗「裡面裝了什麼有沒有已知漏洞」：在 admit 用 SBOM attestation 做漏洞閾值 gate（cosign attest SBOM predicate ＋ Kyverno／policy-controller 對 SBOM 內容與 CVE severity 下 admission gate）**
（這是**接續系列的延伸篇**，把今天的「驗 build 履歷」推進到「驗成品內容」：Day96 問「誰簽的」、Day97 問「怎麼 build 的」、明天問「裡面裝了哪些套件、有沒有踩到不可接受的已知漏洞」。**延伸角度明確標示：這不是重講 Day18 的 SBOM 產生與 Trivy／govulncheck 掃描入門，而是聚焦 admission-time 的「SBOM attestation 內容驗證」與「漏洞閾值 gate」**——角度三條：**① 怎麼在 admit 消費 SBOM attestation**——`cosign attest --type spdxjson`／CycloneDX 產的 SBOM predicate 長什麼樣、Kyverno `attestations.conditions` 或 policy-controller 怎麼對「元件清單」「授權」「是否含某禁用套件」下斷言，以及 severity threshold（例如「有 Critical CVE 就拒」）怎麼落成 gate；**② build-time 掃描 vs admit-time gate 的分工**——Day18 在 build 前掃、今天在 admit 那一刻擋，為什麼「build 掃過」不等於「admit 該放」（掃描時間點的 CVE 資料與部署時已經不同、掃描結果會不會被繞過），SBOM 的「新鮮度」與「掃描結果 attestation」怎麼一起驗；**③ 盲點**——只驗「有 SBOM」不驗內容（盲點①在 SBOM 版重演）、SBOM 與實際映像內容不符（attest 的是 A、跑的是 B）、severity threshold 一刀切的誤區（可利用性 vs CVSS 分數脫節、白名單 CVE 管理）。程式面會示範一條 Kyverno 對 SBOM／CVE 下 gate 的政策、一段 CI 產 SBOM／vuln-scan attestation 的片段、以及一支稽核「叢集裡有沒有部署了帶不可接受 CVE 映像」的 Go／Java 思路。安全主軸一句話：**簽章證明「誰交付」、provenance 證明「怎麼來的」、SBOM＋漏洞 gate 證明「裡面裝的東西現在還安不安全」——把供應鏈信任的最後一塊『成品內容』也擋在 admit 那一刻。** 這是接續系列的延伸篇，聚焦 admission-time 的 SBOM／漏洞內容 gate，不重述 Day18 SBOM 入門與 Day96／97 的簽章／provenance 機制。）
