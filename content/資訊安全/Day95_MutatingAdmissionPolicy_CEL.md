---
title: "Day 95：admission 光譜的最後一塊——MutatingAdmissionPolicy（MAP）：用 CEL 在 apiserver in-process 做「改寫」的第四條路，以及「mutation-before-validation 讓違規被粉飾」這個 Day91/92 老坑在內建 CEL 版的重演"
date: 2026-08-05
tags: ["Kubernetes", "MutatingAdmissionPolicy", "CEL", "admission-control"]
---

接續 Day94 預告：Day91 收 **admission webhook 這條管線本身**（`failurePolicy` fail-open/fail-closed、webhook 成叢集單點）、Day92 收 **跑在管線上的 Gatekeeper／Kyverno 政策內容與繞過**、Day93 收 **內建但固定的 PSA**（三等級三模式、只管 Pod、不能自訂）、Day94 收 **內建 ＋ 可自訂 ＋ 免 webhook 的驗證側 VAP＋CEL**（第三象限，但 VAP 只能「驗證」不能「改寫」）。今天補上 admission 光譜的**最後一塊**——**改寫側**的內建版：**MutatingAdmissionPolicy（MAP）**，一樣用 **CEL** 表達，在 apiserver in-process 執行，於 **v1.32 alpha、v1.34 beta**。把四條路擺齊後，這篇的重點不是「又一個新玩具」，而是**mutation 這半邊自帶的老坑**——mutation 跑在 validation 之前、reinvocation 順序不定要冪等——在內建 CEL 版一格都沒少。

**這是接續 admission 系列的新主題（MAP 首次介紹），但不重講：** Day91 的 mutating webhook 機制與 `reinvocationPolicy`、Day92 的 Gatekeeper `Assign`／Kyverno `mutate` 寫法、Day93 的 PSA、Day94 的 VAP validation 側與 CEL 基礎語法。admission 鏈長怎樣、mutating 為什麼排在 validating 之前、CEL 有哪些變數、`failurePolicy` fail-open 的成因——前四天都講過，今天不重述，只聚焦 mutation 在 CEL 版的新面貌與老坑。

延伸角度三段收：**① MAP 怎麼寫**——`MutatingAdmissionPolicy`（CEL `mutations[]`，每條指定 `patchType`：**`ApplyConfiguration`** 走 server-side apply merge，或 **`JSONPatch`**）＋ `MutatingAdmissionPolicyBinding`（`matchResources`／`paramRef`），用「幫沒設 `seccompProfile` 的容器補 `RuntimeDefault`」「補預設 label」當後端可落地例子，對照 Day91 mutating webhook 回 JSONPatch、Day92 Gatekeeper `Assign`／Kyverno `mutate`；**② 為什麼還是「in-process 免 webhook」那條路**——跟 VAP 一樣甩掉 `caBundle` 憑證輪替、可用性單點、啟動死結、網路往返延遲，但 CEL 天花板照舊（複雜 mutation 回 webhook）；**③ MAP 自己的盲點——全是 Day91/92 mutation 老坑在 CEL 版重演**：mutation 在 validation 之前所以「補預設＝把違規粉飾掉、讓後面的 VAP／PSA 抓不到原始輸入」（承 Day92 盲點③）、reinvocation 隨機順序所以 **mutation 必須冪等**（承 Day91 `reinvocationPolicy`／承 Day22 併發思維）、`failurePolicy` 與 `matchConditions` 選擇器同 VAP 一樣會寫穿。

> ⚠️ MAP 於 **v1.32 進 alpha**（feature gate `MutatingAdmissionPolicy`）、**v1.34 進 beta**（beta 預設開啟 feature gate，但仍需在 kube-apiserver 開 `--runtime-config=admissionregistration.k8s.io/v1beta1=true` 才有 `MutatingAdmissionPolicy` 與 `MutatingAdmissionPolicyBinding` 這兩個物件）。`patchType`（`ApplyConfiguration`／`JSONPatch`）、CEL 可用變數（`object`/`oldObject`/`request`/`params`/`namespaceObject`/`authorizer`/`variables`）、`reinvocationPolicy` 的值、type checking 行為，都會隨版本演進——請對照**你那個叢集版本**的官方文件，別死記某個欄位字串。本文示範的是「MAP 怎麼被設定、怎麼把違規粉飾掉、怎麼因不冪等而在 reinvocation 下爆掉」的**意圖**，不是某一版的精確 schema 表。

---

## 一、承接與定位：把 admission 四條路擺齊，MAP 補上「改寫側」

前四天已經把 admission 光譜攤開，這裡只把 MAP 的座標補上，不重講各條路的內容。兩個維度：**規則能不能自訂**、**要不要自己維運一支 webhook**；再加一個正交的維度：**這條路能不能改寫（mutate）還是只能驗證（validate）**。

| 路線 | 自訂規則 | 免 webhook | 能改寫 | 前情 |
|---|:---:|:---:|:---:|---|
| mutating／validating webhook（自寫） | ✅ 最強 | ❌ 要養 webhook | ✅（mutating） | Day91 |
| Gatekeeper `Assign`／Kyverno `mutate` | ✅ | ❌ 要裝 engine＋webhook | ✅ | Day92 |
| PSA | ❌ 固定三等級 | ✅ 內建 | ❌ 只驗證 | Day93 |
| **VAP**＋CEL | ✅ | ✅ 內建 | ❌ **只驗證** | Day94 |
| **MAP**＋CEL | ✅ | ✅ 內建 | ✅ **改寫** | **Day95（今天）** |

一句話定位：**MAP 之於 VAP，就像 mutating webhook 之於 validating webhook**——同一條 in-process 免 webhook 的路，MAP 補的是 VAP 做不到的「改寫」那半邊。四條路擺齊後，選型準則不變（承 Day94）：**簡單、只看物件本身的規則往內建（VAP/MAP）搬，省維運；複雜、跨資源、要外呼的規則留給 webhook／Gatekeeper／Day90 ext_authz**。差別只在「你要驗證還是要改寫」。

---

## 二、MAP 怎麼寫：Policy＋Binding，`mutations[]` 兩種 `patchType`

MAP 跟 VAP 一樣拆成兩個物件：**`MutatingAdmissionPolicy`** 定義「改什麼」、**`MutatingAdmissionPolicyBinding`** 決定「套在哪」。差別在 VAP 是 `validations[]`（回傳 bool 決定 Deny/Allow），MAP 是 `mutations[]`（回傳一段 patch 把物件改掉）。

### 1）`patchType: ApplyConfiguration`（走 server-side apply merge）

最推薦、最不容易踩坑的寫法。CEL 回傳一個 **apply configuration 物件**（用 `Object{}` 建構器），apiserver 用 **server-side apply 的 merge 策略**把它併進原物件——你只要描述「想補上的欄位長怎樣」，不用管原本有沒有、陣列怎麼對齊。

以「幫每個沒設 `seccompProfile` 的容器補上 `RuntimeDefault`」為例（這是後端最常見、最該落地的一條 hardening 預設）：

```yaml
apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingAdmissionPolicy
metadata:
  name: default-seccomp-runtimedefault
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]   # 盲點③：漏了 UPDATE 就能 patch 繞過（承 Day92）
        resources: ["pods"]
  failurePolicy: Fail                        # 盲點②：安全相關的 mutation 該 Fail，Ignore＝出錯就不補
  reinvocationPolicy: IfNeeded               # 盲點①的關鍵：可能被重跑，mutation 必須冪等
  mutations:
    - patchType: ApplyConfiguration
      applyConfiguration:
        expression: >
          Object{
            spec: Object.spec{
              securityContext: Object.spec.securityContext{
                seccompProfile: Object.spec.securityContext.seccompProfile{
                  type: "RuntimeDefault"
                }
              }
            }
          }
```

`ApplyConfiguration` 的好處正是**天生冪等**（承盲點①）：不論 `seccompProfile` 原本有沒有、重跑幾次，merge 的結果都是同一個 `RuntimeDefault`。這也是官方推薦優先用它、少用 `JSONPatch` 的原因。

### 2）`patchType: JSONPatch`（自己寫 RFC 6902 patch，威力大但坑也大）

當你要做 merge 表達不了的事（例如「只在某條件成立時」加一個 annotation），才用 `JSONPatch`。CEL 用 `JSONPatch{}` 建構器回傳一組 op：

```yaml
  mutations:
    - patchType: JSONPatch
      jsonPatch:
        expression: >
          !has(object.metadata.labels) || !("team" in object.metadata.labels)
            ? [
                JSONPatch{
                  op: "add",
                  path: "/metadata/labels/team",
                  value: "unassigned"
                }
              ]
            : []
```

注意 `JSONPatch` 的兩個內建坑，都是「你自己接手了冪等與逃逸的責任」：

1. **不冪等的寫法會在 reinvocation 下爆炸**（盲點①）：例如 `op: "add", path: "/spec/containers/0/env/-"` 每跑一次就 append 一筆 env，reinvocation 跑兩次就重複——`ApplyConfiguration` 不會有這問題，`JSONPatch` 要自己用「先判斷存在再決定加不加」擋掉。
2. **path 要跳脫**：JSON Pointer 裡的 `/` 與 `~` 要寫成 `~1`、`~0`；label key 若含 `/`（如 `example.com/team`）漏跳脫就會 patch 到錯的位置甚至失敗。CEL 有 `jsonpatch.escapeKey()` 之類 helper（依版本），別手拼。

### 3）Binding：決定套在哪（跟 VAP 同一套選擇器）

```yaml
apiVersion: admissionregistration.k8s.io/v1beta1
kind: MutatingAdmissionPolicyBinding
metadata:
  name: default-seccomp-binding
spec:
  policyName: default-seccomp-runtimedefault
  matchResources:
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: ["kube-system"]          # 盲點③：exempt 範圍寫太寬＝後門（承 Day92）
```

**注意 MAP 的 Binding 沒有 `validationActions` 這種 `Deny/Warn/Audit` 開關**——因為 mutation 不是「擋不擋」而是「改不改」，它一定會作用。這反而是盲點的來源：**沒有 dry-run 檔位，一上線就直接改物件**，出錯不會像 VAP 那樣「只 Audit 放行」，而是「靜默把每個新物件都改了」，見第四節。

---

## 三、為什麼還是「in-process 免 webhook」那條路：省的是維運，換的是 CEL 天花板

這一段的結論跟 Day94 VAP 幾乎一字不差，因為 MAP 走的是同一條路，這裡只點出「改寫側」特有的差異，不重述免 webhook 的整包好處。

**省下來的**（承 Day91 那一整包 webhook 負擔，全消失）：不用 `caBundle` 憑證輪替（承 Day79 ACME 的心法在這裡是「連要輪替的東西都沒有」）、不再是可用性單點、沒有「webhook 掛了整個叢集寫不進去」的啟動死結、每次寫入少一趟網路往返（承 Day72 延遲即攻擊面）。in-process 執行，延遲更低。

**換回來的天花板**（同 VAP，CEL 刻意受限）：不能外呼、不能跨資源查、有 CEL 成本預算。對 mutation 來說還多一條限制——**你只能用 `object`／`params` 等既有資料算出要補的值**，算不出來的（例如「去 KMS 拿一把 key 塞進去」「查外部 registry 拿 digest」）就得回 mutating webhook 或 Day92 的 engine。**MAP 與 webhook 是分層併用不是二選一**：簡單的補預設（seccomp、label、`imagePullPolicy`）用 MAP，複雜的（注入 sidecar、查外部拿值）留給 webhook。

---

## 四、MAP 自己的盲點：mutation 半邊的老坑在 CEL 版重演

VAP 的四個盲點（`Warn`/`Audit` 沒上線、`failurePolicy`、選擇器寫穿、CEL 邏輯錯）Day94 都講過。MAP 因為是「改寫」，多了兩個 mutation 專屬、而且都是 Day91/92 的老坑：

### 盲點① mutation 必須冪等——reinvocation 順序不定（承 Day91 `reinvocationPolicy`、承 Day22）

admission 允許在一輪裡**重新調用（reinvocation）**mutation：當 A 的 mutation 改了物件、可能觸發 B 再跑、B 又可能觸發 A 再跑。順序與次數**不保證**。這意味著：

> **任何 MAP mutation 都必須寫成「跑一次和跑 N 次結果相同」。**

`ApplyConfiguration` 天生冪等，是安全預設；`JSONPatch` 的 `add` 到陣列尾（`/-`）、`copy`、無條件 `add` 都可能非冪等，reinvocation 下就變成「env 被塞兩份」「annotation 疊加」。這是 Day22 TOCTOU／併發思維在 admission 的翻版：**不要假設「只跑一次」，要假設「隨時可能被重跑、順序未知」**。

### 盲點② mutation 在 validation 之前——補預設＝把違規粉飾掉（承 Day92 盲點③，最危險）

admission 鏈是 **先 mutating、後 validating**（Day91 講過機制，這裡講它在 MAP 的安全後果）。所以：

> 如果你用 MAP「自動補上」一個安全關鍵欄位，後面的 VAP／PSA 看到的是**已經被你補好的合規物件**，而不是使用者送進來的**原始違規輸入**——攔截被降級成粉飾。

具體災難：使用者送一個沒設 `seccompProfile`、還跑 `privileged: true` 的 Pod。你的 MAP 好心把 `seccompProfile` 補成 `RuntimeDefault`——現在這個 Pod「看起來乖了一半」，PSA `restricted` 或你的 VAP 可能因為某些欄位被補齊而**不再報那麼明顯**，甚至讓稽核以為「使用者本來就有設」。**mutation 該補的是無關安全判定的預設值（label、`imagePullPolicy`），不該拿來替使用者「修正」他違反的安全政策**——安全違規要用 VAP/PSA **擋下並回報**，不是用 MAP 靜默補齊。

判準一句話：**「補上去會不會改變後面 validation 的結論？」會，就不要用 mutation 補，改用 validation 擋。**

### 盲點③（承 VAP）`failurePolicy` 仍在、選擇器仍會寫穿

- **`failurePolicy: Ignore`**＝CEL 編譯或執行出錯時**不套用這個 mutation**。對安全 hardening 的 MAP，這代表「出錯就不補 seccomp／不補預設」＝默默 fail-open。安全相關的 mutation 該 `Fail`（承 Day91）。
- **`operations` 漏 `UPDATE`**＝先建合規、再 patch 成違規就繞過（承 Day92）；`matchConditions`／`namespaceSelector` 寫太寬＝改到不該改的、太窄＝漏改。
- **沒有 dry-run 檔位**（第二節提過）：MAP 不像 VAP 有 `Audit` 可先觀察，一 apply 就真的改。**上線前一定要用 `--dry-run=server` 對代表性資源看 diff**，別直接套生產。

---

## 五、Day16 稽核：把「危險的 MAP mutation」掃成 CI

承 Day16／Day92／Day94 同一套心法：政策本身也是攻擊面，要能被靜態稽核。對 MAP 要掃三件事：**(a) 安全關鍵欄位被 mutation 靜默補預設而非 validation 擋下（盲點②）**、**(b) `failurePolicy: Ignore`（盲點③）**、**(c) 用了 `JSONPatch` 且有非冪等嫌疑（盲點①）**。

沿用系列慣用的 Go 範例——用 client-go 掃叢集裡的 `MutatingAdmissionPolicy`：

```go
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// 安全關鍵欄位：被 mutation「補」到這些路徑，等於用改寫粉飾違規（盲點②）
var securityCriticalPaths = []string{
	"securityContext", "seccompProfile", "runAsNonRoot",
	"privileged", "allowPrivilegeEscalation", "capabilities", "hostNetwork",
}

func main() {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		os.Exit(2)
	}
	cs := kubernetes.NewForConfigOrDie(cfg)

	policies, err := cs.AdmissionregistrationV1beta1().
		MutatingAdmissionPolicies().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "list MAP:", err)
		os.Exit(2)
	}

	failed := false
	for _, p := range policies.Items {
		// (b) failurePolicy: Ignore = 安全 mutation fail-open
		if p.Spec.FailurePolicy != nil && *p.Spec.FailurePolicy == admissionregistrationv1beta1.Ignore {
			fmt.Printf("[FAIL] MAP %q failurePolicy=Ignore（出錯就不套用，安全 mutation 應為 Fail）\n", p.Name)
			failed = true
		}
		for i, m := range p.Spec.Mutations {
			expr := ""
			switch {
			case m.ApplyConfiguration != nil:
				expr = m.ApplyConfiguration.Expression
			case m.JSONPatch != nil:
				expr = m.JSONPatch.Expression
				// (c) JSONPatch 且無條件 add 到陣列尾 = 非冪等嫌疑
				if strings.Contains(expr, `op: "add"`) && strings.Contains(expr, `/-"`) &&
					!strings.Contains(expr, "has(") && !strings.Contains(expr, " in ") {
					fmt.Printf("[WARN] MAP %q mutations[%d] JSONPatch 疑似非冪等 append（reinvocation 會重複）\n", p.Name, i)
					failed = true
				}
			}
			// (a) 補安全關鍵欄位 = 用 mutation 粉飾，應改用 VAP/PSA 擋
			for _, path := range securityCriticalPaths {
				if strings.Contains(expr, path) {
					fmt.Printf("[FAIL] MAP %q mutations[%d] 觸及安全關鍵欄位 %q，"+
						"安全違規應由 VAP/PSA 擋下並回報，而非 mutation 靜默補齊（盲點②）\n", p.Name, i, path)
					failed = true
				}
			}
		}
	}

	if failed {
		os.Exit(1) // 讓 CI 判紅
	}
	fmt.Println("MAP audit passed")
}
```

Java（Spring 環境常用 fabric8 或 official client）的等價思路一樣：`ApiClient` 撈 `admissionregistration.k8s.io/v1beta1` 的 `mutatingadmissionpolicies`，對每條 `mutations[]` 做同樣三檢查。重點不在 SDK，而在**把「危險 mutation」的定義寫成 CI 斷言**，讓它跟 Day94 那支 VAP 稽核、Day92 那支 policy 稽核**跑在同一條 pipeline**，並把「MAP 政策變更」進 SIEM（承 Day16）。

> 註（承本系列偏好）：上面用到的 `admissionregistration/v1beta1` 型別（`MutatingAdmissionPolicies()`、`FailurePolicy`、`Mutations`）在 client-go 隨 Kubernetes 版本演進，`v1beta1` 也可能在後續版本轉正為 `v1`。實作前請對照**你叢集對應的 client-go 版本**確認型別路徑與欄位名，別直接照抄字串。

---

## 六、常見誤區

- **「有 MAP 幫我補 seccomp，就不用 PSA/VAP 擋了」**：錯，且危險（盲點②）。mutation 補預設會讓 validation 看不到原始違規。補預設與擋違規是**兩件事、要分開**：MAP 補無關判定的預設，VAP/PSA 擋安全違規。
- **「mutation 只跑一次」**：錯（盲點①）。reinvocation 會重跑、順序不定，非冪等 mutation 會累加。優先用 `ApplyConfiguration`。
- **「MAP 有 Audit 模式可以先觀察」**：錯。MAP 沒有 `validationActions`，一 apply 就真的改；要觀察請用 `--dry-run=server` 看 diff。
- **「JSONPatch 比較靈活所以都用它」**：能用 `ApplyConfiguration` 就別用 `JSONPatch`——後者要你自己扛冪等與 path 跳脫。
- **「beta 預設開就代表能用」**：v1.34 beta 預設開 feature gate，但仍要在 apiserver 開 `--runtime-config=admissionregistration.k8s.io/v1beta1=true`，托管叢集（GKE/EKS/AKS）能不能改、哪版有，要各自確認。

---

## 七、Code Review checklist

- [ ] 這條 mutation **改的欄位與安全判定無關**（label、`imagePullPolicy`、預設 annotation）；若觸及 `securityContext`/`privileged`/`capabilities` 等，改用 VAP/PSA 擋（盲點②）。
- [ ] 優先 `patchType: ApplyConfiguration`；用 `JSONPatch` 時已確認**冪等**（不無條件 append、先判斷存在），且 path 已正確跳脫（盲點①）。
- [ ] `failurePolicy: Fail`（安全 mutation 不 fail-open，盲點③）。
- [ ] `operations` 含 `CREATE` **與** `UPDATE`（避免先建後 patch 繞過，承 Day92）；`matchConstraints`/`matchConditions` 範圍不寬不窄。
- [ ] `reinvocationPolicy` 的選擇（`Never`/`IfNeeded`）與冪等假設一致。
- [ ] Binding 的 `namespaceSelector`/exempt 範圍最小化，不留 `kube-system` 以外的大洞。
- [ ] 上線前已 `--dry-run=server` 看過代表性資源 diff；MAP 沒有 Audit 檔位。
- [ ] 第五節那支 CI 已納入 pipeline；MAP 政策變更進 SIEM（承 Day16）。
- [ ] 與 VAP/PSA/webhook 的分工清楚：MAP 補簡單預設、validation 擋違規、複雜/外呼 mutation 回 webhook。

## 八、測試 / 演練建議

- **冪等演練（盲點①，最重要）**：對同一資源手動觸發兩次 mutation（或構造會 reinvocation 的政策組合），斷言**結果與跑一次相同**；對 `JSONPatch` 版故意寫無條件 `add /-`，斷言**env/label 被塞兩份**＝測試失敗，證明非冪等會爆。
- **粉飾演練（盲點②）**：送一個既沒 `seccompProfile`、又 `privileged: true` 的 Pod，先只掛 MAP（補 seccomp）不掛 VAP，斷言 **Pod 被建成且違規被「補了一半」**；再補上 VAP/PSA `restricted`，斷言**原始違規被擋下並回報**——證明 mutation 不能替代 validation。
- **`failurePolicy` 演練（盲點③）**：故意寫一條執行期會出錯的 CEL（存取不存在欄位不先 `has()`），`Fail` 時斷言**該資源被拒**、`Ignore` 時斷言**放行但沒補**——體會 fail-open 代價，確認安全 mutation 留 `Fail`。
- **UPDATE 繞過演練（承 Day92）**：先建合規 Pod，再 `patch` 掉被補的欄位，若 `operations` 漏 `UPDATE` 斷言**改動生效未被重補**＝漏洞。
- **dry-run diff 演練**：對代表性 Deployment/Pod 跑 `kubectl apply --dry-run=server` 看 MAP 產生的 diff，確認**只改到預期欄位**、沒波及其他。
- **稽核迴歸（第五節）**：把某 MAP 設 `failurePolicy: Ignore`、或加一條觸及 `securityContext` 的 mutation，斷言第五節那支 CI **判紅**。

---

## 九、一句話總結

> admission 四條路到今天擺齊：Day91 是「自寫 webhook」（表達力最強，但要養 `caBundle` 憑證、可用性單點、啟動死結、多一趟網路，承 Day79/91/72），Day92 是「外掛 engine」（Gatekeeper／Kyverno，validate＋mutate 都能，但仍要裝、要管 webhook、政策要寫對），Day93 是「內建但固定」的 PSA（免裝最穩、只三等級只管 Pod、不能自訂），Day94 是「內建 ＋ 可自訂 ＋ 免 webhook」的**驗證側 VAP＋CEL**；**Day95 的 MutatingAdmissionPolicy（MAP，v1.32 alpha／v1.34 beta，`admissionregistration.k8s.io/v1beta1`）補上最後一塊——同一條 in-process 免 webhook 的路的「改寫側」**。它一樣拆 `MutatingAdmissionPolicy`（CEL `mutations[]`，`patchType` 選 **`ApplyConfiguration`**（SSA merge、天生冪等、首選）或 **`JSONPatch`**（威力大、要自扛冪等與跳脫））＋ `MutatingAdmissionPolicyBinding`（`matchResources`／`paramRef`，**注意沒有 `validationActions`／沒有 Audit 檔位，一 apply 就真的改**）。**免 webhook 的好處與 CEL 天花板同 VAP**：省下憑證輪替、可用性單點、延遲；但不能外呼、不能跨資源、算不出的值仍回 webhook，**分層併用不是二選一**。**MAP 真正要記的是 mutation 半邊的兩個老坑在 CEL 版重演**：**①非冪等會爆**（reinvocation 順序不定、可能重跑，`JSONPatch` 無條件 append 會累加，優先 `ApplyConfiguration`，承 Day91 `reinvocationPolicy`／Day22 併發思維）；**②mutation 在 validation 之前＝補預設會把違規粉飾掉**（後面的 VAP/PSA 看到的是被你補好的物件不是原始違規輸入，攔截被降級成粉飾——安全違規要用 validation 擋下並回報，mutation 只補無關判定的預設，承 Day92 盲點③）；外加 VAP 那套 `failurePolicy: Ignore` fail-open、`operations` 漏 `UPDATE`、選擇器寫穿照樣適用。稽核（承 Day16）把「MAP 觸及安全關鍵欄位／`failurePolicy: Ignore`／`JSONPatch` 非冪等嫌疑」用 Go/Java 掃成 CI，跟 Day94 VAP、Day92 policy 稽核跑同一條 pipeline，政策變更進 SIEM。一句話：**MAP 讓你「不養 webhook 也能寫自訂的改寫規則」，把簡單的補預設從 webhook 搬進 apiserver——省下的是維運，換來的是 CEL 天花板；而「mutation 要冪等」「mutation 別粉飾違規」這兩個一再重演的老坑，內建 CEL 版一格都沒少。**

---

## 延伸閱讀

- **Day94 VAP＋CEL**——本篇的驗證側對照：VAP 只能驗證、MAP 補改寫，兩者同一條 in-process 免 webhook 的路，`failurePolicy`/`matchConditions`/選擇器坑共用。
- **Day91 mutating webhook 與 `reinvocationPolicy`**——MAP 的價值是「免掉這一整包 webhook 負擔」；但 mutation-before-validation 與 reinvocation 冪等的心法直接繼承自這裡。
- **Day92 Gatekeeper `Assign`／Kyverno `mutate` 繞過**——MAP 是同一件事的內建 CEL 版；盲點②「mutation 改掉 validation 內容」就是 Day92 盲點③的重演。
- **Day93 PSA**——MAP 補預設常被誤當成「PSA 的替代」，其實兩者角色相反：MAP 補、PSA 擋，別用補預設粉飾掉 PSA 該擋的違規。
- **Day22 Race Condition / TOCTOU**——「別假設只跑一次、順序未知」正是 reinvocation 冪等要求的思維來源。
- **Day18 供應鏈**——「補預設 `imagePullPolicy`／禁 `:latest`」是 MAP 的典型安全用途；而「admit 時驗映像簽章」是明天的主題。
- **Day16 Security Logging / Monitoring**——把 MAP 政策變更與稽核結果進 SIEM，對「新增觸及安全欄位的 mutation」告警。

---

明天預告：**Day 96 — 把 admission 用在供應鏈信任的落地：admit 那一刻驗證映像簽章（Sigstore cosign ＋ Kyverno `verifyImages`／sigstore policy-controller）**
（這是**接續系列的新主題**，把 Day91–95 的 admission 能力接到 Day18 的供應鏈信任上：前五天講的是「怎麼在 admit 攔／改物件」，明天講一個最有價值的 admission 用途——**在 Pod 建立那一刻，驗證它要跑的映像有沒有被可信來源簽章、digest 對不對**，讓「只跑簽過的映像」從口號變成叢集政策。角度三條：**① 怎麼在 admit 驗簽**——`keyless`（Fulcio 短命憑證＋Rekor 透明日誌，承 Day77 Certificate Transparency 的思路）vs `keyful`（自管公鑰）、Kyverno `verifyImages` 或 sigstore policy-controller 怎麼設、驗過後常搭配 mutation **把 tag 釘成 digest**（承今天 MAP／Day18「用 digest 不用 `:latest`」）；**② 後端與 CI 的接點**——build 階段 `cosign sign`、部署階段 admission 驗 `cosign verify`，signing key／OIDC identity 放哪、attestation（SBOM、provenance，承 Day18 SLSA）怎麼一起驗；**③ 盲點**——`failurePolicy`/fail-open 讓「驗簽器掛了就放行」＝等於沒驗（承 Day91）、只驗簽不驗 identity（誰簽的沒鎖＝任何人簽都過）、TUF root／Rekor 信任根怎麼固定、以及「驗簽 admission 只攔 CREATE 漏了既存與 UPDATE」。程式面會示範一條 Kyverno `verifyImages` 政策、一段 `cosign sign`/`verify` 的 CI 片段、以及一支稽核「叢集裡有沒有未經簽章驗證就放行的 namespace」的 Go/Java 思路。安全主軸一句話：**admission 學到會攔會改之後，最該拿它做的一件事，就是把「只跑可信來源、且 digest 鎖定的映像」變成進不了叢集就擋下的硬政策——把 Day18 的供應鏈信任，落到 admit 那一刻。** 這是接續系列的新主題，聚焦 admission-time 映像簽章驗證與 Sigstore，不重述 Day18 供應鏈入門與 Day91–95 的 admission 機制。）
