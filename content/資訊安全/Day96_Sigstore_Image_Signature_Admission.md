---
title: "Day 96：admission 學會會攔會改之後，最該拿它做的一件事——在 Pod 建立那一刻驗映像簽章（Sigstore cosign ＋ Kyverno verifyImages／policy-controller）"
date: 2026-08-06
tags: ["Sigstore", "cosign", "image-signature", "supply-chain", "admission-control"]
---

接續 Day95 預告：Day91–95 把 admission 五條路擺齊了——自寫 webhook（Day91）、Gatekeeper／Kyverno 政策（Day92）、內建固定的 PSA（Day93）、內建可自訂驗證側 VAP（Day94）、內建可自訂改寫側 MAP（Day95）。今天不是再開一條「怎麼攔／怎麼改」的路，而是回答一個更前面的問題：**學會會攔會改之後，最該拿 admission 攔的東西是什麼？** 答案是把 **Day18 的供應鏈信任**落到 admit 那一刻——**在 Pod 建立的瞬間，驗證它要跑的映像有沒有被可信來源簽章、digest 對不對**，讓「只跑簽過的映像」從口號變成叢集政策。

**這是接續系列的新主題（映像簽章驗證與 Sigstore 首次介紹），但不重講：** Day18 的供應鏈攻擊分類、SBOM/Trivy/govulncheck 掃描入門，以及 Day91–95 的 admission 機制本身（webhook 是什麼、mutating 為什麼在 validating 之前、`failurePolicy` fail-open 成因、Kyverno 政策骨架怎麼寫）。這些前面都講過，今天只借用、不重述。

延伸主軸只有一條，用三段收：**① 怎麼在 admit 驗簽**——`keyless`（Fulcio 短命憑證＋Rekor 透明日誌，承 Day77 Certificate Transparency 思路）vs `keyful`（自管公鑰）、Kyverno `verifyImages` 或 sigstore policy-controller 怎麼設、驗過之後常搭配 mutation **把 tag 釘成 digest**（承 Day95 MAP／Day18「用 digest 不用 `:latest`」）；**② 後端與 CI 的接點**——build 階段 `cosign sign`、部署階段 admission `cosign verify`，signing key／OIDC identity 放哪、attestation（SBOM、provenance，承 Day18 SLSA）怎麼一起驗；**③ 盲點**——`failurePolicy`/fail-open 讓「驗簽器掛了就放行」＝等於沒驗、只驗簽不驗 identity（誰簽的沒鎖＝任何人簽都過）、TUF root／Rekor 信任根怎麼固定、以及「驗簽 admission 只攔 CREATE 漏了既存與 UPDATE」。

> ⚠️ 版本與 API 提醒（承本系列偏好）：Sigstore 各元件（`cosign`、Fulcio、Rekor、TUF root）與 **Kyverno `verifyImages` 規則欄位**（`imageReferences`、`attestors`、`keyless`/`keys`、`mutateDigest`、`required`、`verifyDigest`）、**sigstore policy-controller** 的 `ClusterImagePolicy` schema，都隨版本演進，欄位名與預設值會變（例如 `mutateDigest`、`verifyDigest` 的預設、keyless `issuer`/`subject` 的比對語意）。本文示範的是「驗簽 admission 該驗什麼、怎麼被寫穿」的**意圖**，不是某一版的精確 schema；實作前請對照**你那個 Kyverno／policy-controller／cosign 版本**的官方文件確認欄位路徑與預設，別直接照抄字串。

---

## 一、承接與定位：admission 能攔能改了，那就拿它守供應鏈的最後一哩

Day18 講供應鏈時，防線都在 **build 之前／之中**：掃依賴（Dependency-Check／govulncheck／Trivy）、產 SBOM、想像 SLSA provenance。但這些都擋不住一件事——**別人推了一個沒經過你 pipeline 的映像到你的 registry，或有人偷改了 Deployment 的 image 欄位指到惡意映像**。build 掃得再乾淨，只要「跑什麼映像」這一步沒被鎖住，前面全白做。

admission 剛好補在這一刀口上：**Pod 要被建立的那一刻，apiserver 手上就有完整的 `spec.containers[].image`**。這時候問三個問題就能把供應鏈信任閉環：

1. **這映像有沒有被簽？**（存在性）
2. **是被「誰」簽的？**（identity——這是最容易漏的一問）
3. **我 admit 的 digest，跟被簽的 digest 是不是同一個？**（把 tag 釘成 digest，杜絕「簽 `v1.2`、跑被人偷換的 `v1.2`」）

三問都過才放行。這正是 Day91–95 那套 admission 能力**最有價值的一個用途**：不是攔 `privileged`、不是補 label，而是把「只跑可信來源、且 digest 鎖定的映像」變成**進不了叢集就被擋下**的硬政策。

擺進 admission 光譜：驗簽你有兩條主流實作——**Kyverno `verifyImages`**（承 Day92 的 Kyverno，多一種規則型別）與 **sigstore policy-controller**（專做這件事的 admission controller，用 `ClusterImagePolicy`）。兩者底層都靠 **Sigstore/cosign** 的驗證邏輯。本文以 Kyverno 為主線示範，policy-controller 的差異在第三節點出。

---

## 二、怎麼在 admit 驗簽：keyless vs keyful，以及「驗過就把 tag 釘成 digest」

### 1）先分清楚 keyful 與 keyless——差別在「信任根」放哪

**keyful（自管公鑰）**：你自己保管一對簽章金鑰，CI 用私鑰 `cosign sign`，admission 用公鑰驗。信任根＝**你那把公鑰**。簡單直觀，但你得自己扛金鑰保管與輪替（承 Day15 Secrets Management）——私鑰外洩＝任何人都能簽出「合法」映像。

**keyless（Sigstore 招牌做法）**：CI **不長期保管私鑰**。簽的當下，cosign 拿 CI 的 **OIDC 身分**（GitHub Actions／GitLab／自建 IdP 的 token）去 **Fulcio** 換一張**短命憑證**（有效期分鐘級），用它簽完就丟；同時把簽章紀錄寫進 **Rekor** 這個**公開透明日誌**（概念承 Day77 Certificate Transparency——「簽了什麼都留下不可否認的公開紀錄」）。信任根＝**Fulcio 的 CA ＋ Rekor 的 log ＋ 你指定的 OIDC identity**。好處是沒有長命私鑰可外洩；代價是信任根變多、要固定（見第四節 TUF）。

> 關鍵心法：**keyless 不是「不用驗身分」，恰恰相反——它把「誰能簽」從「誰有私鑰」換成「誰有那個 OIDC 身分」。** 所以 keyless 政策裡**一定要鎖 `issuer` 與 `subject`**，否則等於「任何人用任何 GitHub 帳號簽都算數」（第四節盲點②）。

### 2）Kyverno `verifyImages`：keyless 版政策（鎖 identity 是重點）

下面這條政策要求 `myregistry.example.com/*` 底下的映像，必須有一張 **keyless 簽章**，且**簽章者身分**必須是「我的 GitHub Actions release workflow」：

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: Enforce      # 對照 Day92/94：留在 Audit 等於沒擋
  webhookTimeoutSeconds: 30
  failurePolicy: Fail                    # 驗簽器掛了要擋，不是放行（盲點①）
  rules:
    - name: check-signature
      match:
        any:
          - resources:
              kinds: ["Pod"]
      verifyImages:
        - imageReferences:
            - "myregistry.example.com/*"
          mutateDigest: true             # 驗過後把 tag → digest 釘死（承 Day95 MAP／Day18）
          verifyDigest: true
          required: true                 # 找不到符合的映像規則＝拒絕，不是略過
          attestors:
            - entries:
                - keyless:
                    # ↓↓ 這三行才是安全的核心：鎖「誰簽的」
                    subject: "https://github.com/my-org/my-repo/.github/workflows/release.yml@refs/tags/*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: "https://rekor.sigstore.dev"
```

三個最容易被寫錯而放水的點，先在這裡標起來（第四節展開）：

- **`subject`/`issuer` 一定要鎖死且精確**。用萬用 `subject: "*"` 或漏掉 `issuer`＝驗了個寂寞。`subject` 用 glob 也要小心，`.../*` 別寬到把任何 workflow 都放行。
- **`required: true`**。否則「沒有任何規則命中這個映像」時 Kyverno 會**略過**而非拒絕——攻擊者推一個不符合 `imageReferences` 的映像名就繞過了。
- **`mutateDigest: true`**（驗過把 tag 釘 digest）。這一步讓 Day95 的 MAP 心法在這裡落地：**驗的是簽章綁的 digest，跑的也強制是同一個 digest**，杜絕 TOCTOU（簽 `v1.2`、admit 到一半 registry 的 `v1.2` 被換掉，承 Day22）。

### 3）keyful 版（自管公鑰）長這樣

如果你走 keyful，把 `keyless` 換成 `keys`：

```yaml
      verifyImages:
        - imageReferences: ["myregistry.example.com/*"]
          mutateDigest: true
          required: true
          attestors:
            - entries:
                - keys:
                    publicKeys: |-
                      -----BEGIN PUBLIC KEY-----
                      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
                      -----END PUBLIC KEY-----
                    rekor:
                      url: "https://rekor.sigstore.dev"   # keyful 也可上傳透明日誌
```

keyful 沒有 identity 要鎖，但**公鑰就是你唯一的信任根**——它放哪、怎麼輪替、私鑰怎麼保管，全部回到 Day15。

---

## 三、後端與 CI 的接點：build 時簽、admit 時驗，中間把 attestation 一起帶上

驗簽 admission 只是**消費端**；生產端在 CI。整條鏈是：**CI build → `cosign sign`（keyless 用 OIDC）→ 推 registry → 部署時 admission `cosign verify`**。

### 1）CI 端：keyless 簽章（GitHub Actions 範例心智模型）

```bash
# CI 內，映像已 build 並 push，這裡拿到的是 digest 不是 tag
IMAGE="myregistry.example.com/api@sha256:abc123..."

# keyless：不帶私鑰，cosign 自動走 OIDC → Fulcio 取短命憑證 → 簽 → 寫 Rekor
COSIGN_EXPERIMENTAL=1 cosign sign --yes "$IMAGE"

# 同時把 provenance / SBOM 當 attestation 一起簽上去（承 Day18 SLSA）
cosign attest --yes --type slsaprovenance --predicate provenance.json "$IMAGE"
cosign attest --yes --type cyclonedx      --predicate sbom.cdx.json    "$IMAGE"
```

重點：**簽的對象是 digest（`@sha256:...`）不是 tag**。tag 會飄，digest 不會——這跟 admission 端 `mutateDigest` 是一體兩面。

### 2）後端服務要自己驗一次映像時（Java / Go）：把 verify 當成一段可測的邏輯

admission 是叢集層防線，但很多後端場景（例如你自己的**部署編排服務**、**內部映像晉級（promotion）流程**、或 CD pipeline 的一個 gate）會想**在程式裡先驗一次再放行**。這時不要自己重寫驗簽，**呼叫 cosign 當子程序、把「驗什麼」寫成明確斷言**即可：

Go——注意「非零 exit code＝驗證失敗＝擋」，而且 identity 要顯式帶：

```go
package verify

import (
	"context"
	"fmt"
	"os/exec"
)

// VerifyKeyless 驗證映像具備符合指定 issuer/subject 的 keyless 簽章。
// 回傳 nil = 通過；非 nil = 擋（fail-closed，呼叫端不可忽略 error）。
func VerifyKeyless(ctx context.Context, imageDigestRef, issuer, subjectRegexp string) error {
	if imageDigestRef == "" || issuer == "" || subjectRegexp == "" {
		// 缺任何一項就等於沒鎖 identity，直接視為失敗（盲點②）
		return fmt.Errorf("verify: image/issuer/subject 都必須提供，不可留空")
	}
	cmd := exec.CommandContext(ctx, "cosign", "verify",
		"--certificate-oidc-issuer", issuer,
		"--certificate-identity-regexp", subjectRegexp, // 鎖「誰簽的」
		imageDigestRef, // 必須是 @sha256:... 而非 tag
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("verify failed for %s: %w\n%s", imageDigestRef, err, out)
	}
	return nil
}
```

Java（Spring 環境常見「CD gate 服務」）——同樣把非零 exit 當失敗，**預設拒絕**：

```java
public final class CosignVerifier {

    /** 通過回傳 true；任何異常或非零 exit 都回傳 false（fail-closed）。 */
    public boolean verifyKeyless(String imageDigestRef, String issuer, String subjectRegexp) {
        if (isBlank(imageDigestRef) || isBlank(issuer) || isBlank(subjectRegexp)) {
            return false; // 缺 identity 條件 = 不放行（盲點②）
        }
        try {
            Process p = new ProcessBuilder(
                    "cosign", "verify",
                    "--certificate-oidc-issuer", issuer,
                    "--certificate-identity-regexp", subjectRegexp,
                    imageDigestRef // 必須是 @sha256:...
            ).redirectErrorStream(true).start();

            boolean finished = p.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
            if (!finished) { p.destroyForcibly(); return false; } // 逾時 = 擋，不是放行
            return p.exitValue() == 0;
        } catch (Exception e) {
            return false; // 例外 = 擋（不要 catch 後 return true）
        }
    }

    private static boolean isBlank(String s) { return s == null || s.isBlank(); }
}
```

> 這兩段的靈魂不在 API，而在**預設值**：**缺條件回傳失敗、逾時回傳失敗、例外回傳失敗**。驗簽邏輯只要有一條路「出錯就放行」，攻擊者就會想辦法讓它出錯（盲點①）。

### 3）policy-controller 的差異（一句話）

sigstore **policy-controller** 用 `ClusterImagePolicy` 描述同樣的事（`authorities` 底下寫 `keyless.identities`／`key`、`ctlog`、`policy`），並用 **namespace label**（如 `policy.sigstore.dev/include: "true"`）決定哪些 namespace 納管。差異在：**它預設「未納管的 namespace 完全不驗」**——這正是第四節盲點④「只驗了一部分」的常見來源。選 Kyverno 還是 policy-controller 是工程取捨，但**要鎖 identity、要 fail-closed、要涵蓋所有該管的 namespace** 三件事一樣都不能少。

---

## 四、盲點：驗簽最常見的四種「驗了等於沒驗」

### 盲點① `failurePolicy`/fail-open——驗簽器掛了就放行＝沒驗（承 Day91）

驗簽 admission 多了一個 Day91 沒那麼致命、但這裡**特別致命**的可用性面：驗簽要連 **Rekor／Fulcio／registry** 抓憑證與日誌，網路一抖就可能 timeout。如果政策 `failurePolicy: Ignore`（或 policy-controller 的 fail-open 設定），**驗簽器一掛、一 timeout，所有映像直接放行**——攻擊者只要有辦法讓驗簽器連不到 Rekor（甚至 DoS 它，承 Day72），就能繞過整條供應鏈防線。

安全的映像政策**必須 `failurePolicy: Fail`**。代價是驗簽依賴的可用性變成你叢集寫入的關鍵路徑——所以要嘛用**本地鏡像的 Rekor/TUF**、要嘛接受這個單點並監控它（承 Day16），**不能用 fail-open 換可用性**。這是 Day91 fail-open 主題在供應鏈語境的重演，而且後果更直接。

### 盲點② 只驗「有沒有簽」不驗「誰簽的」——任何人簽都過（最常見）

`cosign verify` 只給公鑰、或 keyless 只寫 `issuer` 不寫 `subject`（或 `subject: "*"`）＝**只證明「這映像被某個 Sigstore 身分簽過」**。但 Fulcio 是公開的——**任何人**都能拿自己的 GitHub 帳號 keyless 簽你的映像名，然後它就「有簽章」了。攻擊者推一個惡意映像、自己簽一下，你的「只驗有沒有簽」政策就放行。

**驗簽的價值全在 identity**：keyless 要鎖死 `issuer`（例如 `https://token.actions.githubusercontent.com`）**且** `subject`（例如你那條 release workflow 的精確路徑）；keyful 要確保私鑰只有 CI 有。**「有簽章」不是信任，「是我信任的那個身分簽的」才是。**

### 盲點③ 信任根沒固定——TUF root／Rekor 被換掉，整條鏈換底

keyless 的信任根是 Fulcio CA ＋ Rekor log ＋ Sigstore 的 **TUF root**（描述「哪些根金鑰可信」的元資料）。如果你用**公開 Sigstore 實例**又沒固定 TUF root，理論上信任根換了你就跟著換。企業實務常見兩種硬化：**① 固定（pin）TUF root 版本**、**② 自建私有 Sigstore（自管 Fulcio/Rekor/TUF root）**，把信任根收回自己手上。這跟 Day76–78 憑證釘選／CT／信任根管理是同一套思路——**驗證鏈的根不固定，底下驗得再嚴都能被抽換**。

### 盲點④ 只攔 CREATE，漏了既存 Pod 與 UPDATE（承 Day92）

驗簽政策若 `match` 只寫 CREATE，會漏兩塊：**① 政策上線前就已經在跑的 Pod**（既存資源不會回頭被 admission 驗——要靠 Kyverno background scan／policy-controller 的既存掃描補）；**② 之後的 UPDATE**（先建合規 Pod，再 patch `image` 換成沒簽的映像）。這正是 Day92 盲點「只攔 CREATE 漏 UPDATE／既存要 audit」在驗簽語境的重演。政策要**同時涵蓋 CREATE 與 UPDATE**，並**開背景掃描**盯既存工作負載，否則「新的擋住、舊的與偷改的照跑」。

---

## 五、Day16 稽核：把「驗了等於沒驗」掃成 CI

四個盲點都能靜態掃。下面一支 Go 稽核，讀叢集裡所有 Kyverno `verifyImages` 政策，對每條規則做「**fail-open？沒鎖 identity？沒釘 digest？沒涵蓋 UPDATE？**」四檢查，判紅就讓 CI 失敗（承 Day16，與 Day92/94/95 稽核跑同一條 pipeline）：

```go
package audit

import "fmt"

// 簡化模型：實際請從 client-go 撈 kyverno.io/v1 ClusterPolicy 反序列化。
type VerifyRule struct {
	PolicyName       string
	FailurePolicy    string   // "Fail" / "Ignore"
	FailureAction    string   // "Enforce" / "Audit"
	Operations       []string // 該規則 match 的 operations
	Issuer           string   // keyless issuer；keyful 為 ""
	Subject          string   // keyless subject
	HasKeyfulKey     bool
	MutateDigest     bool
	Required         bool
}

func AuditVerifyRule(r VerifyRule) []string {
	var findings []string
	// 盲點① fail-open
	if r.FailurePolicy != "Fail" {
		findings = append(findings, "failurePolicy 非 Fail（驗簽器掛了會放行）")
	}
	if r.FailureAction != "Enforce" {
		findings = append(findings, "validationFailureAction 非 Enforce（留在 Audit 等於沒擋）")
	}
	// 盲點② 沒鎖 identity（keyless 專屬）
	if !r.HasKeyfulKey { // keyless 才需要鎖 issuer/subject
		if r.Issuer == "" || r.Subject == "" || r.Subject == "*" {
			findings = append(findings, "keyless 未鎖定 issuer/subject（任何人簽都過）")
		}
	}
	// 盲點④ 沒涵蓋 UPDATE
	if !contains(r.Operations, "UPDATE") {
		findings = append(findings, "operations 漏 UPDATE（先建合規再 patch 掉 image 可繞過）")
	}
	// 釘 digest / required
	if !r.MutateDigest {
		findings = append(findings, "mutateDigest 未開（簽 tag 跑被換掉的 tag，TOCTOU）")
	}
	if !r.Required {
		findings = append(findings, "required 非 true（不符合 imageReferences 的映像被略過）")
	}
	return findings
}

func contains(ss []string, x string) bool {
	for _, s := range ss {
		if s == x {
			return true
		}
	}
	return false
}

func main() {
	rules := loadVerifyRulesFromCluster() // 讀 kyverno.io/v1 ClusterPolicy
	failed := false
	for _, r := range rules {
		if f := AuditVerifyRule(r); len(f) > 0 {
			failed = true
			for _, msg := range f {
				fmt.Printf("[FAIL] %s: %s\n", r.PolicyName, msg)
			}
		}
	}
	if failed {
		panic("image-signature policy audit failed")
	}
}
```

Java（Spring 環境常用 fabric8 或 official client）的等價思路一樣：`ApiClient` 撈 `kyverno.io/v1` 的 `clusterpolicies`，對每條 `verifyImages` 做同樣五檢查。重點不在 SDK，而在**把「驗簽政策被寫壞」的定義寫成 CI 斷言**，讓它跟 Day94 VAP 稽核、Day92 policy 稽核、Day95 MAP 稽核**跑在同一條 pipeline**，並把「映像政策變更」進 SIEM（承 Day16）。

> 註（承本系列偏好）：上面的欄位（`mutateDigest`、`required`、keyless `issuer`/`subject`、`verifyDigest`）在 Kyverno 隨版本演進，欄位名與預設值可能改；policy-controller 的 `ClusterImagePolicy` 又是另一套 schema。實作前請對照**你那個版本**的官方文件確認，別直接照抄字串。

---

## 六、常見誤區

- **「我掃過 Trivy 沒 CVE，就不用驗簽了」**：錯。Day18 的掃描證明「這映像內容當時沒已知漏洞」，驗簽證明「跑的是我 pipeline 產出、沒被中途掉包的那個映像」——**兩件事、都要**。掃描擋內容，驗簽擋來源與掉包。
- **「有簽章就是可信」**：錯，最危險（盲點②）。Fulcio 公開，任何人都能簽你的映像名。沒鎖 `issuer`/`subject` 的驗簽＝零信任價值。
- **「驗簽器掛了先放行比較不影響上線」**：錯（盲點①）。fail-open 讓「弄掛驗簽器」成為繞過手段。安全政策要 `failurePolicy: Fail`。
- **「簽 tag 就好」**：錯。tag 會飄，要簽 digest、admit 端 `mutateDigest` 釘 digest，否則 TOCTOU（承 Day22）。
- **「政策上了就全叢集都保護」**：錯（盲點④）。既存 Pod 不回頭驗、UPDATE 可換 image、未納管 namespace（policy-controller 尤其）根本沒驗。要背景掃描＋涵蓋 UPDATE＋涵蓋所有該管 namespace。

---

## 七、Code Review checklist

- [ ] 政策 **`failurePolicy: Fail`**、`validationFailureAction: Enforce`（不 fail-open、不留 Audit，盲點①）。
- [ ] keyless **同時鎖 `issuer` 與 `subject`**，`subject` 不是 `*`、glob 範圍不寬（盲點②）；keyful 公鑰的保管與輪替有交代（承 Day15）。
- [ ] `required: true`（不符合 `imageReferences` 的映像被拒而非略過）。
- [ ] `mutateDigest: true`／`verifyDigest: true`（驗的 digest＝跑的 digest，杜絕 tag 掉包，承 Day22/Day95）。
- [ ] `match` 同時含 **CREATE 與 UPDATE**，且已開 **background scan** 盯既存工作負載（盲點④）。
- [ ] 信任根有交代：TUF root pin 或自建 Sigstore；Rekor URL 明確（盲點③）。
- [ ] 涵蓋範圍完整：policy-controller 的 namespace label 納管沒漏、沒有「豁免大洞」namespace（承 Day92 exempt 後門）。
- [ ] CI build 端 `cosign sign` 簽的是 **digest**、OIDC identity 就是 admission 端鎖的那個。
- [ ] attestation（SBOM/provenance）若也要求，`cosign attest`／驗證端條件對得上（承 Day18 SLSA）。
- [ ] 第五節那支 CI 稽核已納入 pipeline；映像政策變更進 SIEM（承 Day16）。

## 八、測試 / 演練建議

- **未簽映像演練（最基本）**：推一個**沒簽**的映像、部署，斷言 **Pod 被拒**；把政策 `validationFailureAction` 改 `Audit`，斷言**放行但有告警**——體會「留在 Audit 等於沒擋」。
- **冒名簽章演練（盲點②，最重要）**：用一個**別的** GitHub 帳號 keyless 簽同一個映像名，斷言在「有鎖 `subject`」的政策下**仍被拒**；再故意把 `subject` 放寬成 `*`，斷言**冒名簽章被放行**＝證明沒鎖 identity 等於沒驗。
- **fail-open 演練（盲點①）**：阻斷驗簽器對 Rekor 的網路（模擬 timeout），`failurePolicy: Fail` 時斷言**部署被拒**、`Ignore` 時斷言**未簽映像被放行**——體會 fail-open 代價。
- **tag 掉包演練（TOCTOU）**：簽 `app@sha256:A`，之後把 registry 的 `app:v1` 重推成 `sha256:B`（未簽），用 tag 部署，斷言 `mutateDigest`/`verifyDigest` 開啟時**跑的是被釘死的 A 而非 B**（或直接被拒）。
- **UPDATE 繞過演練（盲點④）**：先建合規 Pod，再 `patch` 把 `image` 換成未簽映像，若 `match` 漏 `UPDATE` 斷言**改動生效未被擋**＝漏洞；補上 UPDATE 後斷言被拒。
- **既存工作負載演練**：政策上線前先跑一個未簽 Pod，上線後斷言 **background scan 判出違規**（既存不會自動被 admission 攔）。
- **稽核迴歸（第五節）**：把某政策設 `failurePolicy: Ignore`、或 `subject: "*"`、或關掉 `mutateDigest`，斷言第五節那支 CI **判紅**。

---

## 九、一句話總結

> Day91–95 教會 admission 會攔會改之後，**最該拿它做的一件事，是把 Day18 的供應鏈信任落到 admit 那一刻**——在 Pod 建立的瞬間，用 **Sigstore/cosign**（透過 **Kyverno `verifyImages`** 或 **sigstore policy-controller `ClusterImagePolicy`**）問三個問題：**有沒有簽、是誰簽的、admit 的 digest 對不對**，三問全過才放行。簽法兩種：**keyless**（CI 用 OIDC 身分向 **Fulcio** 換短命憑證簽、寫 **Rekor** 透明日誌，承 Day77 CT，沒長命私鑰可外洩，但信任根多、要固定 TUF root）與 **keyful**（自管公鑰，信任根單純但私鑰保管回到 Day15）。CI 端 `cosign sign` 簽的是 **digest 不是 tag**，可再 `cosign attest` 把 **SBOM／SLSA provenance**（承 Day18）一起帶上；admission 端 `mutateDigest` 把 tag 釘成 digest，讓「驗的 digest＝跑的 digest」。**真正要記的是驗簽有四種「驗了等於沒驗」**：**①fail-open**——`failurePolicy: Ignore` 讓「弄掛驗簽器（DoS Rekor，承 Day72）＝全放行」，安全政策必須 `Fail`；**②只驗有沒有簽、不驗誰簽的**——Fulcio 公開，任何人都能簽你的映像名，keyless 一定要鎖死 `issuer`＋`subject`（不是 `*`），**「有簽章」不是信任，「我信任的身分簽的」才是**；**③信任根沒固定**——TUF root／Rekor 可被抽換，要 pin 或自建 Sigstore，同 Day76–78 信任根管理；**④只攔 CREATE**——漏既存 Pod（要 background scan）與 UPDATE（先建合規再 patch 掉 image，承 Day92）。稽核（承 Day16）把這四個盲點用 Go/Java 掃成 CI，跟 Day92/94/95 稽核跑同一條 pipeline，映像政策變更進 SIEM。一句話：**把「只跑可信身分簽章、且 digest 鎖定的映像」變成進不了叢集就被擋下的硬政策——admission 學到會攔會改，最值得攔的就是這個。**

---

## 延伸閱讀

- **Day18 供應鏈 / SBOM / SLSA**——本篇是它的「落地那一哩」：Day18 在 build 前掃內容、想像 provenance，今天在 admit 那一刻把「只跑可信來源映像」變成硬政策；SBOM/provenance 用 `cosign attest` 一起帶上。
- **Day91 admission webhook 與 `failurePolicy`**——驗簽 fail-open 是這裡的重演，而且後果更直接（弄掛驗簽器＝全放行）。
- **Day92 Kyverno 政策繞過**——`verifyImages` 是 Kyverno 的另一種規則型別；「只攔 CREATE 漏 UPDATE／既存要 background scan／exempt 後門」的坑一模一樣。
- **Day95 MAP（mutation）**——`mutateDigest`「把 tag 釘成 digest」就是驗簽場景最有價值的一次 mutation 應用。
- **Day77 Certificate Transparency / Day76 Pinning / Day78 信任根**——Rekor 透明日誌承 CT 思路、TUF root 固定承信任根釘選；驗證鏈的根不固定，底下驗再嚴都能被抽換。
- **Day15 Secrets Management**——keyful 的私鑰保管與輪替；keyless 之所以誘人，正是為了不長期持有這把私鑰。
- **Day22 Race Condition / TOCTOU**——「簽 tag、跑被換掉的 tag」是典型 TOCTOU，`mutateDigest`/`verifyDigest` 是它的解。
- **Day16 Security Logging / Monitoring**——映像政策變更與驗簽失敗進 SIEM，對「新增豁免 namespace／政策改 fail-open」告警。

---

明天預告：**Day 97 — 只驗簽章還不夠：在 admit 驗「provenance／SLSA attestation」——不只問「誰簽的」，還問「這映像是在哪條 pipeline、用什麼原始碼 build 出來的」（cosign verify-attestation ＋ in-toto/SLSA provenance predicate ＋ Kyverno verifyImages 的 attestations 條件）**
（這是**接續系列的新主題**，把今天的「驗簽章」推進到「驗來歷」：Day96 問的是「有沒有被我信任的身分簽」，明天問更深一層——**「就算簽章對，這映像到底是怎麼 build 出來的？來源 repo 對不對？是不是在受保護的 CI 跑出來的？有沒有經過人工核准？」**。角度三條：**① 怎麼在 admit 驗 attestation**——`cosign attest` 產的 **SLSA provenance predicate**（in-toto 格式）長什麼樣、Kyverno `verifyImages` 的 `attestations[].conditions` 或 policy-controller 的 `policy`（CUE/Rego）怎麼對 predicate 內容下斷言（例如「`buildType` 必須是我的 GitHub Actions」「`sourceUri` 必須是 `my-org/my-repo`」「build 觸發者不是 fork PR」），承今天 attestation 的帶入；**② 後端與 CI 的接點**——SLSA build level 怎麼對應到「provenance 能不能被信」、hermetic/isolated build 的假設、`cosign attest --predicate` 從 CI 產出到 admission 消費的完整鏈，SBOM attestation 一起驗（承 Day18）；**③ 盲點**——只驗「有 provenance」不驗 predicate 內容（等於盲點②在 attestation 版重演——任何人都能簽一份亂寫的 provenance）、predicate 欄位信任邊界（`builderId` 沒鎖＝誰都能宣稱自己是可信 builder）、以及「SLSA 等級宣稱」與「實際 build 隔離」脫節。程式面會示範一條 Kyverno `verifyImages` 的 `attestations` 政策、一段 `cosign attest`/`verify-attestation` 的 CI 片段、以及一支稽核「叢集裡有沒有只驗簽章卻沒驗 provenance 內容」的 Go/Java 思路。安全主軸一句話：**簽章證明「是可信的人交付的」，provenance 證明「是用可信的方式、從可信的原始碼做出來的」——把供應鏈信任從『誰簽的』再推進到『怎麼來的』。** 這是接續系列的新主題，聚焦 admission-time 的 provenance/attestation 內容驗證，不重述 Day96 簽章驗證機制與 Day18 供應鏈入門。）
