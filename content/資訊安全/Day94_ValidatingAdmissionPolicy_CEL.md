---
title: "Day 94：Kubernetes 內建、免 webhook、可寫自訂規則的第三條路——ValidatingAdmissionPolicy（VAP）＋ CEL：怎麼寫、為什麼是第三象限、以及「留在 Warn/Audit 等於沒擋」在 CEL 版的重演"
date: 2026-08-04
tags: ["Kubernetes", "ValidatingAdmissionPolicy", "CEL", "admission-control"]
---

接續 Day93 預告：Day91 收 **admission webhook 這條管線本身**、Day92 收 **跑在管線上的 Gatekeeper／Kyverno 政策內容**（兩者都是「外掛」路線：要裝 engine、要管 webhook 憑證與可用性、政策要自己寫對），Day93 收 **Kubernetes 內建、免裝、預設開的 PSA**（但只有 `privileged`/`baseline`/`restricted` 三個固定等級、不能寫自訂規則）。今天收 admission 光譜的**第三象限**——**內建 ＋ 可寫自訂規則 ＋ 免 webhook**：**ValidatingAdmissionPolicy（VAP）**，用 **CEL（Common Expression Language）** 表達規則，在 apiserver in-process 執行，v1.30 GA。

**這是接續 admission 系列的新主題（VAP 首次介紹），但不重講：** Day91 的 webhook 機制與 `failurePolicy` fail-open/fail-closed 的成因、Day92 的 Gatekeeper `ConstraintTemplate`＋Rego 與 Kyverno `ClusterPolicy` 政策寫法、Day93 的 PSA 三等級三模式。admission 鏈長怎樣、mutating 為什麼在 validating 之前、Rego/Kyverno pattern 怎麼寫、restricted 擋哪些欄位——前三天都講過，今天不重述。

延伸角度只有一條主軸，用三段收：**① VAP 怎麼寫**——`ValidatingAdmissionPolicy`（CEL `validations`）＋ `ValidatingAdmissionPolicyBinding`（`matchResources`／`paramRef`／`validationActions`），會用 **Day92 同一條「禁 `:latest`／要 resource limits」規則**，但改用內建 CEL 表達，示範它跟 Gatekeeper Rego／Kyverno pattern 的取捨；**② 為什麼是「第三條路」**——免 webhook 就整包甩掉 Day91 的 `caBundle` 憑證輪替、可用性單點、啟動死結，延遲也更低（in-process），但 **CEL 表達力有天花板**；**③ VAP 自己的盲點**——`validationActions`（`Deny`/`Warn`/`Audit`）根本是 Day92 `dryrun`/`Audit`、Day93 `enforce`/`warn`/`audit` 的又一次翻版（留在 `Warn`/`Audit` 等於沒擋）、`failurePolicy` 仍在、`matchConditions`/`paramRef` 選擇器寫太寬太窄、以及 **CEL 邏輯寫錯讓它永遠通過**（承 Day92「政策邏輯靜態掃不到、要單元測試」）。

> ⚠️ VAP 於 v1.29 進 beta（feature gate `ValidatingAdmissionPolicy`＋開 `admissionregistration.k8s.io/v1beta1`），**v1.30 GA**，穩定 API 為 `admissionregistration.k8s.io/v1`，兩個物件 `ValidatingAdmissionPolicy` 與 `ValidatingAdmissionPolicyBinding`。CEL 可用變數（`object`/`oldObject`/`request`/`params`/`namespaceObject`/`authorizer`/`variables`）、`validations[].reason` 對應的 HTTP 狀態、`paramRef.parameterNotFoundAction`、type checking 的行為，都會隨版本演進——請對照**你那個叢集版本**的官方文件，別死記某個欄位字串。本文示範的是「VAP 怎麼被設定、被留在 Audit、被 CEL 邏輯寫穿」的**意圖**，不是某一版的精確 schema 表。

---

## 一、承接與定位：admission 的三條路，VAP 補齊第三象限

把前四天擺成一張表，VAP 的位置就清楚了。兩個維度：**規則能不能自訂**、**要不要自己維運一支 webhook**。

| | 固定規則 | 可寫自訂規則 |
|---|---|---|
| **要外掛 webhook** | —（沒人這樣做） | **Day91–92：自寫 webhook／Gatekeeper／Kyverno** |
| **內建、免 webhook** | **Day93：PSA（三固定等級）** | **Day94：VAP（CEL 自訂）← 今天** |

三條路的取捨一句話收：

- **自寫 webhook／Gatekeeper／Kyverno（Day91–92）**：表達力最強（Rego／Kyverno DSL／可呼叫外部、查跨資源），代價是**你得養一支 webhook**——`caBundle` 憑證輪替（承 Day79）、webhook 掛掉＝叢集寫入單點（承 Day91 `failurePolicy`）、每次 API 寫入多一趟網路往返（承 Day72 延遲）、啟動死結。
- **PSA（Day93）**：免裝、免 webhook、最穩，但**只有三個固定等級、只管 Pod-level、不能自訂**（「禁 `:latest`」「要 resource limits」它一概不管）。
- **VAP（Day94）**：**内建（apiserver in-process）＝沒有那支 webhook**，所以 Day91 那一整包 webhook 維運負擔全部消失；同時**可以用 CEL 寫自訂規則**，補上 PSA 做不到的「禁 `:latest`／要 limits／命名規範」。它填的就是「我想寫自訂規則，但不想為此養一支 webhook」的空缺。

> 一句定位：**VAP 不是要取代 Gatekeeper／Kyverno，而是把「簡單到中等、只看被寫入物件本身」的自訂規則從 webhook 搬進 apiserver。** 真正複雜的（要查 DB、要呼叫外部授權服務、要跨多個資源做決策）還是得回 webhook／Gatekeeper 或 Day90 的 ext_authz——因為 CEL 有天花板（第四節）。

一條貫穿全篇、承 Day91/92/93 的邊界照舊成立：**VAP 跟所有 admission 一樣，只在資源「被寫入的當下」（CREATE/UPDATE…）觸發，管不到已經跑著的既存資源。** 上線 VAP 前的存量盤點，跟 Day92 的 Gatekeeper audit／Kyverno background scan 是同一件事——只是 VAP 自己沒有內建的 audit controller，存量得靠 `validationActions: [Audit]` 寫進 audit log（承 Day16）再撈。

---

## 二、VAP 怎麼寫：Policy＋Binding＋CEL 三件事

VAP 把「規則」和「套在哪」拆成兩個物件，這是它跟 webhook 最大的結構差異：

- **`ValidatingAdmissionPolicy`**：定義**規則本身**（CEL `validations`），但**光有它不會生效**——它只是一份「規則模板」。
- **`ValidatingAdmissionPolicyBinding`**：把 policy **綁到實際資源**（`matchResources`）、指定**違規要怎麼處理**（`validationActions`）、可選帶參數（`paramRef`）。

這個拆法的用意：同一份 policy 可以被多個 binding 用不同的 `validationActions`（一個 ns 先 `Audit` 觀察、另一個 ns 直接 `Deny`）、套不同範圍——類似 Gatekeeper 的 `ConstraintTemplate`（規則）vs `Constraint`（實例）。

### （1）Policy：CEL 規則本身

用 **Day92 同一條規則**（禁 `:latest`、要 resource limits）來對照，改用 CEL 表達：

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: require-safe-images
spec:
  failurePolicy: Fail          # CEL 編譯/執行出錯時 fail-closed（第五節，承 Day91）
  matchConstraints:            # 這份 policy「可能」套用到哪些資源（binding 還會再收窄）
    resourceRules:
      - apiGroups:   [""]
        apiVersions: ["v1"]
        operations:  ["CREATE", "UPDATE"]   # 安全政策必含 UPDATE（承 Day92：只攔 CREATE 會被 patch 繞過）
        resources:   ["pods"]
  variables:                   # 先把常用運算式抽成變數，validations 引用 variables.xxx
    - name: containers
      expression: "object.spec.containers"
  validations:
    # 規則一：禁浮動 tag（承 Day18），要求帶 digest 或明確版本
    - expression: "variables.containers.all(c, !c.image.endsWith(':latest') && !c.image.contains('@sha256:') == false || !c.image.endsWith(':latest'))"
      # ↑ 這行故意寫得繞，第五節會用它當「CEL 邏輯永遠通過」的反面教材；正確版見下
      message: "container image must not use ':latest' tag"
      reason: Invalid
    # 規則二：每個容器都要有 resource limits（PSA 管不到，承 Day93）
    - expression: "variables.containers.all(c, has(c.resources) && has(c.resources.limits) && has(c.resources.limits.cpu) && has(c.resources.limits.memory))"
      message: "every container must set cpu and memory limits"
      reason: Invalid
```

CEL 幾個關鍵可用變數（承上警告框，隨版本可能增減）：

- **`object`**：本次被寫入的資源（UPDATE 時是新版）。
- **`oldObject`**：UPDATE 前的舊版（CREATE 時為 `null`）——可用來寫「只准往嚴格改、不准放寬」。
- **`request`**：`AdmissionRequest` 詮釋資料（`request.operation`、`request.userInfo` 等）。
- **`params`**：`paramRef` 綁進來的參數物件（第（3）點）。
- **`namespaceObject`**：被寫入資源所在 namespace 的物件（可讀它的 label——例如「只有貼了 `tier: prod` 的 ns 才強制」）。
- **`authorizer`**：可在 CEL 裡做 RBAC 檢查（例如「除非這個 user 有某權限，否則擋」）。

`validations[].reason` 決定被擋時 apiserver 回的 HTTP 狀態（`Unauthorized`/`Forbidden`/`Invalid`/`RequestEntityTooLarge`）；`message` 是固定字串，若要動態訊息用 `messageExpression`（也是 CEL）。

### （2）Binding：綁資源、決定動作

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: require-safe-images-binding
spec:
  policyName: require-safe-images
  validationActions: ["Deny"]       # ★ 這一格決定「到底擋不擋」——第五節整節在講它
  matchResources:                   # 在 policy 的 matchConstraints 之上再收窄
    namespaceSelector:
      matchExpressions:
        - key: pod-security.kubernetes.io/enforce   # 例：只對已納管的 ns 套（可換成你自己的 label）
          operator: Exists
    # 也可用 objectSelector、excludeResourceRules 等進一步縮/排除範圍
```

**`validationActions` 是一個「陣列」，可以組合**——`["Deny"]` 直接擋；`["Warn", "Audit"]` 只回警告＋記 audit log 但**放行**；`["Deny", "Audit"]` 擋且留痕。這正是第五節的核心陷阱：**留在 `["Warn"]` 或 `["Audit"]` 就等於沒擋**，跟 Day92 的 `dryrun`/`Audit`、Day93 的 `warn`/`audit` 一模一樣的坑，只是換個欄位名重演。

### （3）paramRef：把 policy 參數化（可選但很實用）

同一份 CEL 邏輯，門檻值不寫死、抽成參數。例如「Deployment 副本數上限」由參數決定：

```yaml
# Policy：宣告吃一個參數型別，validations 用 params.xxx
spec:
  paramKind:
    apiVersion: v1
    kind: ConfigMap
  validations:
    - expression: "object.spec.replicas <= int(params.data.maxReplicas)"
      messageExpression: "'replicas exceeds limit ' + params.data.maxReplicas"
---
# Binding：指定要綁哪個參數物件；找不到參數時的行為要明講
spec:
  policyName: limit-replicas
  paramRef:
    name: replica-limits
    namespace: policy-config
    parameterNotFoundAction: Deny    # ★ 參數找不到時 fail-closed；設 Allow＝參數一刪政策就形同虛設
  validationActions: ["Deny"]
```

> `parameterNotFoundAction` 是一個容易被忽略的 fail 行為旋鈕（承 Day91 fail-open/fail-closed 家族）：設 `Allow`＝參數物件一被刪，這條政策就整條放行；安全政策應設 `Deny`，並把參數物件的寫入權收好（承 Day07——**參數本身就是政策的一部分，誰能改參數誰就能改政策**）。

---

## 三、為什麼是「第三條路」：免 webhook 甩掉什麼、又換回什麼天花板

### （1）免 webhook＝Day91 那一整包負擔消失

VAP 在 apiserver **in-process** 執行 CEL，沒有那支對外的 webhook，於是 Day91 講的每一個 webhook 痛點在 VAP 上**都不存在**：

- **沒有 `caBundle`**：不用發憑證給 webhook、不用輪替、不用擔心過期造成全叢集寫入失敗（承 Day79/19）。
- **沒有可用性單點**：不會因為「webhook Pod 掛了／被打垮」而觸發 `failurePolicy` 擋下全叢集寫入（承 Day91/72）。VAP 的「可用性」就是 apiserver 自己的可用性。
- **沒有啟動死結**：不用小心翼翼排除 webhook 自身 namespace（承 Day91）。
- **延遲更低**：CEL in-process 評估，沒有「apiserver → webhook」那趟網路往返，每次 API 寫入的延遲預算好很多（承 Day72）。

一句話：**你把「規則邏輯」交給 apiserver 內建的 CEL 引擎跑，就不必再為了跑這段邏輯養一台高權限、要管憑證與可用性的服務。**

### （2）換回來的代價：CEL 表達力有天花板

天下沒有白吃的午餐。免 webhook 的代價是**規則只能用 CEL 寫，而 CEL 是刻意設計成「有限、可終止、沙箱」的**：

- **不能呼叫外部服務**：沒有 `http.send`（對比 Rego 可以、對比自寫 webhook 更是隨便打）。要「查外部授權系統再決定」＝回 Day90 ext_authz／webhook。
- **不能任意查叢集裡其他資源**：CEL 只看得到「這次請求相關」的東西（`object`/`oldObject`/`namespaceObject`／`authorizer` RBAC 檢查／`paramRef` 綁進來的參數）。要做「這個 Ingress 的 host 有沒有跟別的 Ingress 撞」這種**跨資源**決策，VAP 做不到，得回 Gatekeeper（有 `data.inventory`）或 webhook。
- **有成本預算（cost budget）**：CEL 運算式有執行成本上限，防止你寫出拖垮 apiserver 的重運算（例如對超大 list 做巢狀 `all()`）。太貴的運算式會被拒絕或中止。

所以取捨很清楚：**「只看被寫入物件本身、規則邏輯不太複雜」的自訂規則 → VAP 最划算（免 webhook）；一旦要外呼、要跨資源、要重邏輯 → 回 webhook／Gatekeeper／Day90 ext_authz。** VAP 跟它們是**併用、分層**，不是二選一——就像 Day93 說 PSA 跟 policy engine 併用一樣。

---

## 四、VAP 自己的盲點（承 Day92/93 一路重演的那些坑）

VAP 免掉了 webhook 的坑，但**政策層的坑一個都沒少**，而且很多是前幾天原封不動搬過來。

### 盲點①：`validationActions` 留在 `Warn`/`Audit` 等於沒擋（Day92/93 翻版）

這是最重要、最常犯的一條。`validationActions: ["Warn"]` 或 `["Audit"]`＝**違規照樣放行**，只是回個警告或記 audit log。它跟：

- Day92 Gatekeeper `enforcementAction: dryrun`／Kyverno `failureAction: Audit`
- Day93 PSA `warn`/`audit` 模式

是**同一個坑的第三次重演**：觀察期先用 `Audit` 盤存量很合理，但**觀察完忘了切 `Deny`＝這條政策常駐不設防**，靜態看「政策存在」以為在擋，其實門大開。第六節的稽核就是專門抓這個。

> 跟 Day91 `failurePolicy: Ignore`（fail-open）要分清楚：`Ignore` 是「CEL 出錯才放行」，`Warn`/`Audit` 是「**沒出錯、活得好好的，但本來就不擋**」——後者更徹底、更容易被遺忘。

### 盲點②：`failurePolicy` 仍在（CEL 也會出錯）

VAP 沒有 webhook，但 `failurePolicy`（`Fail`/`Ignore`）**照樣存在**——因為 **CEL 運算式本身會失敗**：編譯錯誤、執行期型別錯誤（存取不存在的欄位沒先 `has()`）、超出成本預算。這些情況下：

- `failurePolicy: Fail`（預設，建議）＝出錯就擋，fail-closed（承 Day07 default deny）。
- `failurePolicy: Ignore`＝出錯就放行，fail-open——一條寫錯（永遠丟型別錯誤）的政策若設 `Ignore`，等於整條靜默失效。

所以 Day91 的心法照搬：**安全政策該 `Fail`；但 `Fail` 搭「寫得爛、常常丟錯」的 CEL＝可能誤擋合法請求**，因此 CEL 要先型別檢查、先測（第六、九節）。

### 盲點③：`matchConditions`／`matchResources`／`paramRef` 選擇器寫太寬或太窄

- **`matchConditions`（CEL）** 是「apiserver 端再細判斷要不要評估這條政策」的閘門。寫太窄＝該管的請求被 `matchConditions` 濾掉、政策根本沒跑（**漏擋**）；寫太寬又把不相關請求也拉進來評估（**多花成本、可能誤擋**）。
- **`matchResources` 只選了 `pods`** 卻沒想到「Deployment 代建 Pod」的路徑——這是 Day92/93 講過的老問題：直接 match `pods` 時，違規會在 Pod 層被擋，但 Deployment `apply` 成功、Pod 靜默起不來（錯藏在 ReplicaSet event）。要嘛也 match 工作負載資源（對 Deployment 的 `spec.template` 寫 CEL），要嘛接受「Pod 層擋＋Deployment 層靜默」這個已知邊界並用監控補（承 Day93 第七節）。
- **`paramRef` 找不到參數**：見第二節（3）——`parameterNotFoundAction: Allow` 是後門。

### 盲點④：CEL 邏輯寫錯，讓政策「永遠通過」（承 Day92「語法對≠邏輯對」）

這是政策即程式碼的通病，VAP 一樣中招。第二節（1）規則一那行我**故意寫錯**：

```
variables.containers.all(c, !c.image.endsWith(':latest') && !c.image.contains('@sha256:') == false || !c.image.endsWith(':latest'))
```

CEL 運算子優先序讓這行實際上化簡成「只要 image 不以 `:latest` 結尾就通過」，中間那段 `@sha256` 條件被 `|| !c.image.endsWith(':latest')` 短路掉了——**語法完全正確、apiserver 收得下、type check 也過，但邏輯上對某些 image 永遠回 true**。正確版應該是清楚拆開的兩個 `validations` 或明確的布林式：

```yaml
validations:
  # 明確、可讀、可測：禁 :latest
  - expression: "object.spec.containers.all(c, !c.image.endsWith(':latest'))"
    message: "container image must not use ':latest' tag"
    reason: Invalid
  # 要求帶 digest（承 Day18）——分成獨立一條，不要跟上一條用 || 攪在一起
  - expression: "object.spec.containers.all(c, c.image.contains('@sha256:'))"
    message: "container image must be pinned by digest"
    reason: Invalid
```

**心法：一個 `validations` 只表達一件事、用 `has()` 守空值、別用 `||` 把多個條件擠成一行短路自己。** 這種「永遠通過」的錯**靜態掃不出來**（語法是對的），只能靠單元測試（第九節）——跟 Day92 的 `opa test`/`kyverno test` 是同一套心法：**政策即程式碼，就要當程式碼測**。

---

## 五、Day16 稽核：掃「VAP 有 policy 卻只 `Warn`/`Audit` 沒 `Deny`」

承 Day16／Day91／Day92／Day93 同一套心法，最該進 CI 的靜態訊號是：**有 `ValidatingAdmissionPolicyBinding`，但它的 `validationActions` 只有 `Warn`/`Audit`、沒有 `Deny`**（盲點①），以及 **`failurePolicy: Ignore`**（盲點②）。

一次撈（binding 與 policy 都是 cluster-scoped）：

```bash
kubectl get validatingadmissionpolicybindings -o json     # 掃 validationActions
kubectl get validatingadmissionpolicies -o json           # 掃 failurePolicy
```

### Go 版（Go 1.21）

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type bindingList struct {
	Items []struct {
		Metadata struct{ Name string } `json:"metadata"`
		Spec     struct {
			PolicyName        string   `json:"policyName"`
			ValidationActions []string `json:"validationActions"`
		} `json:"spec"`
	} `json:"items"`
}

type policyList struct {
	Items []struct {
		Metadata struct{ Name string } `json:"metadata"`
		Spec     struct {
			FailurePolicy string `json:"failurePolicy"` // 空字串代表未設，預設 Fail
		} `json:"spec"`
	} `json:"items"`
}

func kubectlJSON(v any, args ...string) {
	out, err := exec.Command("kubectl", args...).Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "kubectl %v failed: %v\n", args, err)
		os.Exit(2)
	}
	if err := json.Unmarshal(out, v); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal failed: %v\n", err)
		os.Exit(2)
	}
}

func hasDeny(actions []string) bool {
	for _, a := range actions {
		if a == "Deny" {
			return true
		}
	}
	return false
}

func main() {
	var bl bindingList
	var pl policyList
	kubectlJSON(&bl, "get", "validatingadmissionpolicybindings", "-o", "json")
	kubectlJSON(&pl, "get", "validatingadmissionpolicies", "-o", "json")

	red := false

	for _, b := range bl.Items {
		// 判紅：binding 沒有 Deny（只 Warn/Audit，或整個沒設＝不做任何動作）
		if !hasDeny(b.Spec.ValidationActions) {
			fmt.Printf("[RED] binding %q (policy=%s) validationActions=%v 沒有 Deny＝不擋\n",
				b.Metadata.Name, b.Spec.PolicyName, b.Spec.ValidationActions)
			red = true
		}
	}

	for _, p := range pl.Items {
		// 判紅：failurePolicy 明確設成 Ignore（CEL 出錯就放行）；未設＝預設 Fail，OK
		if p.Spec.FailurePolicy == "Ignore" {
			fmt.Printf("[RED] policy %q failurePolicy=Ignore＝CEL 出錯就 fail-open\n", p.Metadata.Name)
			red = true
		}
	}

	if red {
		os.Exit(1)
	}
	fmt.Println("OK: 所有 VAP binding 都含 Deny，且沒有 failurePolicy=Ignore")
}
```

### Java 版（Java 21；1.8 把 `var`／`List.of` 換傳統寫法即可）

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;

public class VapAudit {
    static final ObjectMapper M = new ObjectMapper();

    static JsonNode kubectlJson(String... args) throws Exception {
        var pb = new ProcessBuilder(args).redirectErrorStream(false);
        var p = pb.start();
        var node = M.readTree(p.getInputStream());
        if (p.waitFor() != 0) { System.err.println("kubectl failed: " + List.of(args)); System.exit(2); }
        return node;
    }

    static boolean hasDeny(JsonNode actions) {
        if (actions == null || !actions.isArray()) return false;
        for (var a : actions) if ("Deny".equals(a.asText())) return true;
        return false;
    }

    public static void main(String[] args) throws Exception {
        var bindings = kubectlJson("kubectl", "get", "validatingadmissionpolicybindings", "-o", "json");
        var policies = kubectlJson("kubectl", "get", "validatingadmissionpolicies", "-o", "json");
        boolean red = false;

        for (var b : bindings.path("items")) {
            var actions = b.path("spec").path("validationActions");
            if (!hasDeny(actions)) {
                System.out.printf("[RED] binding %s (policy=%s) validationActions=%s 沒有 Deny＝不擋%n",
                        b.path("metadata").path("name").asText(),
                        b.path("spec").path("policyName").asText(), actions.toString());
                red = true;
            }
        }

        for (var p : policies.path("items")) {
            // 未設 failurePolicy＝預設 Fail，OK；明確 Ignore 才判紅
            var fp = p.path("spec").path("failurePolicy").asText("Fail");
            if ("Ignore".equals(fp)) {
                System.out.printf("[RED] policy %s failurePolicy=Ignore＝CEL 出錯就 fail-open%n",
                        p.path("metadata").path("name").asText());
                red = true;
            }
        }

        if (red) System.exit(1);
        System.out.println("OK: 所有 VAP binding 都含 Deny，且沒有 failurePolicy=Ignore");
    }
}
```

**CI 靜態掃不到、要另外補的（承 Day92）：**

- **CEL 邏輯對不對**（盲點④「永遠通過」語法是對的，掃不出來）——靠單元測試（第九節）。
- **`matchConditions`／`matchResources` 該不該這樣選**——靜態只能抓「明顯漏 UPDATE」，抓不到「這個範圍到底對不對」。
- **`paramRef` 的參數物件寫入權**（承 Day07）——參數就是政策，得掃誰能改那個 ConfigMap。
- **既存違規存量**——VAP 沒有內建 audit controller，要靠 `Audit` 動作寫進 apiserver audit log 再撈（執行期產物，承 Day16）。

執行期承 Day16：把 VAP 的 `Deny` 事件、`Audit` annotation、政策/ binding 的變更進 SIEM，對「政策實際處於 `Warn`/`Audit`（P1）」「某政策 deny 突然歸零（可能被改成 Audit 或 binding 被刪）」「CEL 執行錯誤率上升（政策可能對某些輸入 fail-open 了，端看 `failurePolicy`）」告警。

---

## 六、常見誤區

| 誤區 | 為什麼錯 |
|---|---|
| VAP 是 GA 就能取代 Gatekeeper／Kyverno | CEL 有天花板：不能外呼、不能跨資源查、有成本上限。複雜規則仍需 policy engine／webhook（第三節）。 |
| 建了 `ValidatingAdmissionPolicy` 就在擋 | Policy 只是規則模板，**沒有 binding 不生效**；binding 的 `validationActions` 沒 `Deny` 也不擋（盲點①）。 |
| `validationActions: Audit` 比較安全，先觀察 | 觀察期合理，但**忘了切 `Deny`＝常駐不設防**（Day92/93 同坑第三次）。 |
| VAP 沒 webhook，就沒有 `failurePolicy` 問題 | CEL 會編譯/執行出錯，`failurePolicy` 照樣在；`Ignore`＝出錯就 fail-open（盲點②）。 |
| CEL 語法對＝規則對 | 語法對可能邏輯「永遠通過」（盲點④），靜態掃不到，要單元測試。 |
| match `pods` 就管住所有部署 | Deployment 代建：Pod 層擋、Deployment 靜默 apply 成功、Pod 起不來（承 Day92/93）。 |
| `paramRef` 找不到參數會擋 | 看 `parameterNotFoundAction`；設 `Allow`＝參數一刪政策形同虛設（第二節 3）。 |
| VAP in-process 所以沒延遲成本 | CEL 有成本預算，寫太貴的巢狀運算式會拖慢/被拒；比 webhook 低但不是零。 |
| VAP 會清掉既存違規資源 | admission 只擋新寫入，既存資源照跑（承 Day91/92/93 邊界）。 |
| policy 的參數 ConfigMap 是普通設定 | 參數就是政策的一部分，誰能改參數誰能改政策（承 Day07）。 |
| 有 VAP 就不用 PSA | VAP 補自訂規則，PSA 當 Pod 安全底盤，兩者併用（承 Day93）。 |

---

## 七、Code Review checklist

**政策真的在擋（承 Day92/93 盲點①）**

- [ ] 每個要生效的 `ValidatingAdmissionPolicy` 都有對應的 `ValidatingAdmissionPolicyBinding`（沒 binding＝規則模板放著不生效）。
- [ ] 安全政策的 binding `validationActions` 含 `Deny`（不是只有 `Warn`/`Audit`）；`Audit` 只在觀察期用，且有切 `Deny` 的期限。
- [ ] `failurePolicy` 為 `Fail`（未設即預設 Fail，OK）；沒有無意設成 `Ignore`。

**攔截面完整（承 Day92 只攔 CREATE／Day93 Deployment 邊界）**

- [ ] `matchConstraints.resourceRules.operations` 含 `CREATE` **與** `UPDATE`（否則建合規再 patch 成違規繞過）。
- [ ] 想管的資源真的被 match（Pod-only 的政策清楚知道「Deployment 靜默、Pod 才擋」，或另對工作負載 `spec.template` 寫 CEL）。
- [ ] `matchConditions` 沒把該管的請求濾掉（漏擋），也沒寬到把無關請求全拉進來評估。

**CEL 與參數（承 Day07/Day18/盲點④）**

- [ ] 每個 `validations` 只表達一件事，用 `has()` 守空值，沒有用 `||` 把多條件擠成一行短路自己。
- [ ] 政策通過 type checking（看 `status.typeChecking`，雖不阻擋但會警告存取不存在的欄位）。
- [ ] `paramRef.parameterNotFoundAction` 為 `Deny`（安全政策），且參數物件的寫入權有收（承 Day07）。

**與其他 admission 併用（承 Day93）**

- [ ] VAP 補自訂規則、PSA 當 Pod 安全底盤、複雜/跨資源/外呼規則留給 Gatekeeper／Kyverno／webhook——分層清楚，不是拿 VAP 硬幹做不到的事。
- [ ] 稽核（承 Day16）已納入第五節那支 CI，並把 `Deny`/`Audit`/政策變更進 SIEM。

---

## 八、測試 / 演練建議

- **「政策真在擋」演練（盲點①，最重要）**：對 `validationActions: [Deny]` 的政策送違規資源（用 `:latest` 的 Pod），斷言**被拒且錯誤訊息是你的 `message`**；把 binding 改成 `[Audit]` 重送，斷言**放行但 audit log 有一筆**——證明「有政策 ≠ 在擋」。
- **CEL 邏輯單元測試（盲點④）**：把 CEL 運算式當程式碼測——用一組「該過／該擋」的 object 樣本跑（可用 `kubectl create --dry-run=server` 送測試資源，或以 CEL playground／`cel-go` 對運算式直接餵樣本），特別針對「永遠通過」寫一條**故意違規卻通過就判測試失敗**的斷言。
- **UPDATE 繞過演練（承 Day92）**：先建一個合規 Pod，再 `patch` 成違規（換成 `:latest`），斷言**被擋**；若被放行＝`operations` 漏了 `UPDATE`。
- **Deployment 靜默演練（承 Day93）**：對只 match `pods` 的政策 `apply` 一個違規 Deployment，斷言 **Deployment 建成功但 `READY 0/N`、錯在 RS event**；證明 Pod-only match 的已知邊界，決定是否補 match 工作負載。
- **`failurePolicy` 演練（盲點②）**：故意寫一條會執行期出錯的 CEL（存取不存在欄位不先 `has()`），`failurePolicy: Fail` 時斷言**被擋**、改 `Ignore` 斷言**放行**——體會 fail-open 的代價，並確認安全政策留在 `Fail`。
- **參數後門演練（第二節 3）**：`parameterNotFoundAction: Allow` 時刪掉參數物件，送違規資源斷言**竟被放行**；改 `Deny` 重來斷言**被擋**——確認參數缺失時的 fail 行為。
- **稽核迴歸（第五節）**：把某 binding 從 `[Deny]` 改 `[Audit]`、或把某 policy 設 `failurePolicy: Ignore`，斷言第五節那支 CI **判紅**。

---

## 九、一句話總結

> Day91–92 是 admission 的「外掛」路線（自寫 webhook／Gatekeeper／Kyverno：表達力最強，但要養 webhook——`caBundle` 憑證、可用性單點、啟動死結、每次寫入多一趟網路，承 Day79/91/72），Day93 是「內建但固定」的 **PSA**（免裝、免 webhook、最穩，但只有 `privileged`/`baseline`/`restricted` 三固定等級、只管 Pod、不能自訂）；**Day94 的 ValidatingAdmissionPolicy（VAP，v1.30 GA，`admissionregistration.k8s.io/v1`）補齊第三象限——「內建 ＋ 可寫自訂規則 ＋ 免 webhook」**。它把規則拆成兩個物件：**`ValidatingAdmissionPolicy`**（CEL `validations`＋`matchConstraints`＋`variables`＋`failurePolicy`＋可選 `paramKind`）定義規則、**`ValidatingAdmissionPolicyBinding`**（`policyName`＋`matchResources`＋`paramRef`＋**`validationActions`**）決定套在哪、怎麼處理；CEL 可用 `object`/`oldObject`/`request`/`params`/`namespaceObject`/`authorizer`，用「禁 `:latest`／要 resource limits」這條 Day92 同款規則就能改寫成 `object.spec.containers.all(c, !c.image.endsWith(':latest'))`。**為什麼是第三條路**：免 webhook＝Day91 那一整包負擔（憑證輪替、可用性單點、啟動死結、網路往返延遲）全消失、in-process 延遲更低；**換回來的天花板**是 CEL 刻意受限——不能外呼、不能跨資源查、有成本預算，所以複雜/跨資源/要外部授權的規則仍得回 Gatekeeper／webhook／Day90 ext_authz，**VAP 與它們是分層併用不是二選一**。**VAP 自己四個盲點都是前幾天的重演**：**①`validationActions` 留在 `Warn`/`Audit`＝等於沒擋**（Day92 `dryrun`/`Audit`、Day93 `warn`/`audit` 第三次翻版，觀察完忘了切 `Deny`＝常駐不設防）；**②`failurePolicy` 仍在**（CEL 會編譯/執行出錯，`Ignore`＝出錯 fail-open，安全政策該 `Fail`，承 Day91）；**③`matchConditions`/`matchResources`/`paramRef` 選擇器寫太寬太窄**（漏擋或多花成本，`parameterNotFoundAction: Allow` 是後門，`match pods` 有 Deployment 靜默邊界承 Day93）；**④CEL 邏輯寫錯「永遠通過」**（語法對≠邏輯對，用 `||` 短路自己，靜態掃不到、要單元測試，承 Day92）。稽核（承 Day16）把「有 binding 卻沒 `Deny`」「`failurePolicy: Ignore`」寫成 CI（Go/Java 掃 `validatingadmissionpolicybindings`/`validatingadmissionpolicies`），CEL 邏輯與 `matchConditions` 範圍靠單元測試補，執行期對「政策實際只 Audit、deny 歸零、CEL 錯誤率上升」告警。一句話：**VAP 讓你「不養 webhook 也能寫自訂 admission 規則」，把簡單到中等、只看物件本身的規則從 webhook 搬進 apiserver——省下的是維運，換來的是 CEL 表達力天花板；而「留在 Audit 等於沒擋」這個一再重演的陷阱，它一格都沒少。**

---

## 延伸閱讀

- **Day93 PSA**——本篇上游：Day93 收「內建但固定」的 PSA，Day94 收「內建但可自訂、還免 webhook」的 VAP，兩者併用（PSA 底盤＋VAP 自訂）。
- **Day92 Gatekeeper／Kyverno 政策繞過**——VAP 的 `validationActions`（Deny/Warn/Audit）就是 Day92 `enforcementAction`（deny/dryrun/warn）／`failureAction`（Enforce/Audit）的又一次翻版；複雜/跨資源規則仍回 Gatekeeper。
- **Day91 admission webhook 與 `failurePolicy`**——VAP 的價值正是「免掉 Day91 這一整包 webhook 負擔」；但 `failurePolicy` fail-open/fail-closed 的心法在 CEL 出錯時照樣適用。
- **Day90 ext_authz**——「要呼叫外部授權服務再決定」是 CEL 的天花板外側，回 Day90 的 Envoy ext_authz／OPA。
- **Day18 供應鏈**——「禁 `:latest`／要 digest」是 VAP 最典型的自訂規則範例，本篇 CEL 直接示範。
- **Day07 Broken Access Control**——`paramRef` 的參數物件、`authorizer` 的 RBAC 檢查都落在存取控制邊界：誰能改參數＝誰能改政策。
- **Day16 Security Logging / Monitoring**——把 VAP 的 `Deny`/`Audit`/政策變更進 SIEM，對「政策實際只 Audit、deny 歸零、CEL 錯誤率上升」告警。

---

明天預告：**Day 95 — admission 光譜的最後一塊：MutatingAdmissionPolicy——用 CEL 做 in-process「改寫」的第四條路**
（這是**接續 admission 系列的新主題**，不重講 Day91 mutating webhook 機制、Day92 Gatekeeper Assign／Kyverno mutate、Day93 PSA、Day94 VAP 的 validation 側。VAP 只能「驗證」不能「改寫」；改寫這半邊，內建版就是 **MutatingAdmissionPolicy（MAP）**——用 CEL 表達 mutation、在 apiserver in-process 跑，於 **v1.32 alpha、v1.34 beta**（`admissionregistration.k8s.io/v1beta1`，需開 feature gate 與 `--runtime-config`；請對照你的叢集版本）。角度三條：**① MAP 怎麼寫**——`MutatingAdmissionPolicy`＋`MutatingAdmissionPolicyBinding`，`mutations[]` 每條指定 `patchType`（**`ApplyConfiguration`** 用 server-side apply merge，或 **`JSONPatch`**），會用「幫沒設 `seccompProfile` 的容器補 `RuntimeDefault`」「補預設 label」當後端可落地例子，對照 Day91 mutating webhook 回 JSONPatch、Day92 Gatekeeper `Assign`／Kyverno `mutate`；**② 為什麼還是「in-process 免 webhook」那條路**——跟 VAP 一樣甩掉 caBundle／可用性單點／延遲，但 CEL 天花板照舊（複雜 mutation 回 webhook）；**③ MAP 自己的盲點——全是 Day91/92 mutation 老坑在 CEL 版重演**：**mutation 在 validation 之前**（承 Day91，所以 `mutate` 補預設會讓後面的 VAP／PSA 抓不到原始違規＝把攔截降級成粉飾，承 Day92 盲點③）、**reinvocation 隨機順序＝mutation 必須冪等**（承 Day91 `reinvocationPolicy`／Day22）、`failurePolicy` 與 `matchConditions` 同 VAP。程式面會示範 MAP＋Binding 的 YAML、幾條 `ApplyConfiguration`／`JSONPatch` mutation、以及一支稽核「安全關鍵欄位被 `mutate` 靜默補預設而非 `validate` 擋下」的思路（承 Day92 盲點③同一套 Day16 心法）。安全主軸一句話：**Day94 收「內建可自訂」的驗證側（VAP），Day95 收改寫側（MAP），把 admission 四條路（自寫 webhook／外掛 engine／內建固定 PSA／內建 CEL 的 VAP＋MAP）擺齊，並把「mutation-before-validation 讓違規被粉飾」這個 Day91/92 的老坑在內建 CEL 版再標一次。** 這是接續 admission 系列的新主題，聚焦內建 MutatingAdmissionPolicy 與 CEL mutation，不重述 mutating webhook 機制與 Gatekeeper/Kyverno mutate 寫法。）
