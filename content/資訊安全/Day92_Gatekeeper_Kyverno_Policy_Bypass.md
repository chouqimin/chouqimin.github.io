---
title: "Day 92：OPA Gatekeeper / Kyverno 政策即程式碼的盲點與繞過——政策怎麼寫、dryrun/Audit 等於沒上線、excludedNamespaces/exempt 後門、mutation 改掉 validation 看到的內容、UPDATE/subresource 繞過、既存資源與政策單元測試（延伸篇）"
date: 2026-08-02
tags: ["Kubernetes", "Gatekeeper", "Kyverno", "policy-as-code"]
---

接續 Day91 預告：Day91 收的是 **admission webhook 這條管線本身**——誰能改它的 config、它攔誰、它掛了 `failurePolicy` 該 fail-open 還是 fail-closed。今天往下一層，收 **跑在這條管線上的「政策內容」**：OPA Gatekeeper 的 `ConstraintTemplate`／`Constraint`（內嵌 Rego）與 Kyverno 的 `ClusterPolicy`（validate／mutate／generate）——政策怎麼寫，以及它們最常見的盲點與繞過。

**這篇是延伸篇，不重講 Day91 的 admission webhook 機制與 `failurePolicy`、不重講 Day90 的 Rego 語法基礎與 `opa test` 基礎、也不重講 Day07 的 default deny 入門。** admission 鏈長怎樣、mutating 為什麼在 validating 之前、`failurePolicy` 的 fail-open/fail-closed、Rego 的 `default allow := false`——前面都講過，今天不重述。

延伸角度只有一條主軸：**Day91 讓「webhook 管線」穩了（誰能改、攔誰、掛了怎麼辦）；但管線再穩，只要跑在上面的政策留一個 `dryrun`、一個過寬的 `exempt`、或漏了 `UPDATE`／subresource，就等於沒防。** 這篇用三段收好：**① 政策怎麼寫**——Gatekeeper `ConstraintTemplate`＋`Constraint`、Kyverno `ClusterPolicy`，用「禁止 `:latest`／要求 image 帶 digest（承 Day18）／要求 resource limits」當後端可落地的例子；**② 常見繞過與盲點**——`dryrun`/`Audit` 等於沒上線、`excludedNamespaces`/exempt 後門、mutation 改掉 validation 看到的欄位（承 Day91 mutating-before-validating 順序）、只攔 `CREATE` 漏 `UPDATE`／subresource、以及 admission 只管新寫入既存違規要靠 audit/background scan（承 Day91 那條邊界）；**③ 怎麼測政策**——把 policy 當程式碼用 `opa test`（Gatekeeper Rego）與 `kyverno test` 寫單元測試（承 Day90 Rego 可測性）。

> ⚠️ Gatekeeper（`templates.gatekeeper.sh/v1` `ConstraintTemplate`、`constraints.gatekeeper.sh` 動態產生的 Constraint kind、`spec.enforcementAction`、`spec.match.excludedNamespaces`）與 Kyverno（`kyverno.io` `ClusterPolicy`／`Policy`、`spec.validationFailureAction`、`spec.rules[].validate.failureAction`、`spec.background`、`match`/`exclude`、`spec.rules[].match.any[].resources.operations`）的欄位會隨版本明顯變動。特別注意：**Kyverno 的 `spec.validationFailureAction`（`Enforce`/`Audit`，1.9 起大寫、舊版小寫已移除）在較新版（約 1.13）已標為 deprecated，改用「每條 rule 的」`spec.rules[].validate.failureAction`。** 本文用較新的 per-rule 寫法為主，並在需要時標註舊寫法。實際請對照你那套 Gatekeeper／Kyverno 版本的官方文件，別照抄字串——這裡示範的是**「政策內容怎麼被寫壞、被繞過」的意圖**，不是某一版的精確語法。

---

## 一、先定位：這篇收的是「政策內容」，不是「管線」

Day91 把 admission 拆成兩段：**管線**（`*WebhookConfiguration`、`failurePolicy`、憑證、可用性）和**內容**（webhook 背後那支程式到底做了什麼檢查）。Day91 收管線，這篇收內容。

在真實叢集裡，多數團隊不會自己手寫 Day91 那支 `AdmissionReview` handler，而是裝一個 **policy engine** 幫你把政策寫成宣告式的 YAML／Rego：

- **OPA Gatekeeper**：你寫 `ConstraintTemplate`（裡面內嵌一段 **Rego**，定義「什麼叫違規」）＋ `Constraint`（套用這個 template、指定 `match` 範圍與 `enforcementAction`）。Gatekeeper 自己註冊一支 validating（＋可選 mutating）webhook，把 Day91 的管線都接好。
- **Kyverno**：你寫 `ClusterPolicy`／`Policy`（用 YAML DSL 或 CEL 表達 `validate`／`mutate`／`generate`／`verifyImages` 規則），不必寫 Rego。Kyverno 同樣自己管理那支 webhook。

一句話定位：**你裝了 Gatekeeper／Kyverno，等於把 Day91 的管線交給它管；你要負責的是「政策內容」寫對沒有。** 而政策內容的盲點——`dryrun`、過寬 exempt、mutation 順序、漏 `UPDATE`/subresource、既存資源——**沒有一個是 Day91 的 `failurePolicy` 能救的**。`failurePolicy: Fail` 只保證「webhook 掛了會擋」，不保證「webhook 活著時，你的政策真的有在擋」。這兩件事是正交的，這也是為什麼 Day91 收完管線，還得有 Day92 收內容。

> 一個貫穿全篇、承 Day91 第一節的邊界：**admission（不論自寫 webhook 還是 Gatekeeper/Kyverno）只在「資源被寫入的當下」觸發，管不到「已經在叢集裡的既存資源」。** 你今天上線一條 enforce 政策，它擋得住之後的新資源，但**擋不掉昨天就違規跑著的資源**——那要靠 Gatekeeper 的 **audit** 或 Kyverno 的 **background scan**（第七節）。這條邊界 Day91 標記過，這篇把它落到「政策怎麼補既存資源」上。

---

## 二、政策怎麼寫：Gatekeeper 與 Kyverno（同一條規則，兩種寫法）

用一條後端最常見的規則當範例：**容器 image 不准用 `:latest`、也不准不帶 tag（要求帶 digest 或明確版本，承 Day18 供應鏈——`:latest` 是浮動 tag，同一個 tag 今天明天可能是不同 image，等於放棄了可重現與可稽核）。**

### Gatekeeper：ConstraintTemplate（內嵌 Rego）＋ Constraint

`ConstraintTemplate` 定義「什麼叫違規」，Rego 一定要有 **`violation` 區塊**；`Constraint` 是這個 template 的實例，決定**攔誰**（`match`）與**故障以外的執行方式**（`enforcementAction`）。

```yaml
# ① ConstraintTemplate：定義規則（內嵌 Rego，承 Day90 但這裡不重講 Rego 語法基礎）
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdisallowedimagetags
spec:
  crd:
    spec:
      names:
        kind: K8sDisallowedImageTags   # 會動態產生一個 constraints.gatekeeper.sh 下的 CRD
      validation:
        openAPIV3Schema:
          type: object
          properties:
            tags:
              type: array
              items: { type: string }
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8sdisallowedimagetags
        violation[{"msg": msg}] {
          c := input.review.object.spec.containers[_]        # 拿到被檢查的資源
          endswith(c.image, ":latest")                       # 用 :latest → 違規
          msg := sprintf("不准使用浮動 tag :latest：%v", [c.image])
        }
        violation[{"msg": msg}] {
          c := input.review.object.spec.containers[_]
          not contains(c.image, "@sha256:")                  # 沒帶 digest
          not contains(c.image, ":")                         # 也沒帶任何 tag
          msg := sprintf("image 必須帶明確 tag 或 digest：%v", [c.image])
        }
```

```yaml
# ② Constraint：套用 template、指定攔截範圍與執行動作
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sDisallowedImageTags
metadata:
  name: disallow-latest-tag
spec:
  enforcementAction: deny          # ★ 預設就是 deny（真的擋）；dryrun/warn 是「不擋」（第三節）
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    excludedNamespaces: ["kube-system"]   # ★ 這行是雙面刃（第四節）
```

### Kyverno：ClusterPolicy（不寫 Rego）

Kyverno 用 YAML pattern，不必寫 Rego。同一條規則：

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-latest-tag
spec:
  background: true                 # ★ 開啟 background scan 掃既存資源（第七節）
  rules:
    - name: require-image-tag-or-digest
      match:
        any:
          - resources:
              kinds: ["Pod"]
              operations: ["CREATE", "UPDATE"]   # ★ 一定要含 UPDATE（第六節）
      validate:
        failureAction: Enforce      # ★ 新版 per-rule 寫法（舊版是 spec.validationFailureAction: Enforce）
        message: "image 不准用 :latest，必須帶明確 tag 或 digest"
        pattern:
          spec:
            containers:
              - image: "!*:latest"   # 不准以 :latest 結尾
```

> **`validate` 也可以用 `deny.conditions` 或 CEL（`validate.cel`）表達更複雜的邏輯**，但主軸不變：`match` 決定攔誰、`failureAction` 決定擋不擋、`background` 決定掃不掃既存。**mutate 規則**（第五節）則是用 `mutate.patchStrategicMerge` 改寫資源。

一句話：**兩種引擎都把 Day91 那支 handler 變成宣告式政策——你只要寫「什麼叫違規、攔誰、擋不擋」。** 但也正因為變宣告式，「擋不擋（第三節）、攔誰（第四、六節）、跟 mutation 的先後（第五節）、既存怎麼辦（第七節）」這幾個旋鈕一設錯，政策就形同虛設。下面逐一收。

---

## 三、盲點一：政策留在 `dryrun` / `Audit`——上線了，但根本沒在擋

這是最常見、也最致命的一個：**政策部署了、`kubectl get` 看得到、CI 綠了，但它其實只是「記錄違規」，不擋任何東西。**

- **Gatekeeper**：`enforcementAction` 有三個值——`deny`（預設，真的擋）、`dryrun`（**不擋**，只把違規記到 Constraint 的 `status.violations`）、`warn`（**不擋**，但會在 `kubectl apply` 時回一段警告）。很多人「先用 `dryrun` 觀察一陣子」是對的做法，**但忘了改回 `deny` 就上線了**——政策看起來在跑，實際門開著。
- **Kyverno**：對應的是 `failureAction`（舊版 `spec.validationFailureAction`）——`Enforce`（擋）vs `Audit`（**不擋**，只寫進 `PolicyReport`/`ClusterPolicyReport`）。同樣的陷阱：留在 `Audit` 等於沒 enforce。

為什麼危險，跟 Day91 的 fail-open **形似但成因不同**，要分清楚：

- Day91 的 fail-open（`failurePolicy: Ignore`）是「**webhook 掛掉時**放行」——平常有在擋，只有故障那段沒擋。
- 這裡的 `dryrun`/`Audit` 是「**webhook 好好活著也不擋**」——是政策內容本身就沒在 enforce，比 fail-open 更徹底地「等於沒防」。

而且跟 fail-open 一樣可被利用：攻擊者只要知道某條關鍵政策還在 `dryrun`/`Audit`，就能大方部署違規資源，因為它只會被「記一筆」而不會被擋。**`dryrun`/`Audit` 只該是上線前的短暫觀察期，不是常駐狀態；任何常駐在 `dryrun`/`Audit` 的安全關鍵政策，都要當成「未上線」看待並告警（第八節稽核會抓）。**

一句話：**部署 ≠ 上線。政策是否真的在擋，看的是 `enforcementAction: deny`／`failureAction: Enforce`，不是「政策存在」。**

---

## 四、盲點二：`excludedNamespaces` / exempt 被濫用成後門

政策幾乎都需要「排除某些 namespace」——最典型的是排除 `kube-system`（承 Day91 第三節：fail-closed 下攔控制面會卡死）。**問題是這個 exempt 清單一旦過寬，或被當成「這個 team 嫌政策煩，先把他們 namespace 加進 exempt」的萬用開關，政策就被從內部掏空了。**

- **Gatekeeper**：`Constraint.spec.match.excludedNamespaces`，以及 Gatekeeper 全域的 `Config`（`config.gatekeeper.sh`）裡的 `spec.match.excludedNamespaces`（全域排除，影響**所有** Constraint，比單條 Constraint 的排除更危險）。
- **Kyverno**：`spec.rules[].exclude`（可排 namespace、`clusterRoles`/`roles`、`subjects`、甚至特定 `subjects`/ServiceAccount）。Kyverno 預設還會排除一些系統來源，`exclude` 寫太寬同樣是後門。

真實風險有三層：

1. **exempt namespace 變成合規逃生艙**：任何能往被排除 namespace 部署的人，都自動繞過所有排除它的政策。攻擊者拿到某個「剛好在 exempt 清單裡」namespace 的部署權，就能跑 privileged、掛 `:latest`、拿掉 `securityContext`——政策對他完全無效。
2. **exempt by user/role/SA 更隱蔽**：Kyverno 可以 `exclude` 特定 `subjects`/`clusterRoles`。一條「排除 `cluster-admin`」看似合理，但如果某個 CI ServiceAccount 綁了很大的 role，它就自動繞過政策——這跟 Day07 的越權、Day49 的 BFLA 同源：**豁免清單本身就是一種存取控制決策，寫寬了就是開後門。**
3. **exempt 沒有到期、沒有審核**：「先加進去之後再說」的 exempt 永遠不會被拿掉。

防禦：**exempt 只給控制面必要 namespace（`kube-system` 等），任何業務 namespace 的豁免都要走審核、標註原因與到期、並且被稽核（第八節）盯著**。能用「更精準的 `match`（只納管該管的）」就別用「先全攔再大量 exempt」——後者是把爆炸半徑先開到最大再挖洞。

一句話：**exempt 清單是政策的信任邊界；一條過寬的 `excludedNamespaces`/`exclude`，比政策寫錯還危險，因為它是「合法的繞過」。**

---

## 五、盲點三：mutation 改掉了 validation 要看的內容（承 Day91 mutating-before-validating）

Day91 標記過：admission 鏈裡 **mutating 在 validating 之前**。Gatekeeper（Assign/mutation）與 Kyverno（`mutate` 規則）都能改寫資源。這帶出一個很反直覺的盲點：**你的 validate 政策看到的，永遠是「被所有 mutation 改寫過之後」的資源，不是使用者原本送的那份。**

兩個具體的坑：

**① 「mutate 幫你補預設」會讓 validate 抓不到原始違規。** 假設你寫了一條 mutate：「Pod 沒設 `runAsNonRoot` 就幫他補 `true`」，又寫了一條 validate：「Pod 必須 `runAsNonRoot: true`」。你以為 validate 會擋掉沒設的人——但因為 mutate 先跑、已經幫他補好了，validate 永遠看到 `true`、永遠通過。結果是：**違規被「靜默修正」而不是「被擋下並回報」**，你完全不知道有多少 Deployment 其實原本是錯的。對安全關鍵欄位，這是把「攔截」偷偷降級成「粉飾」。

**② mutate 可能設出不安全的預設，而 validate 又剛好沒檢查那個欄位。** mutate 的預設值如果太寬鬆（例如補了一個過度授權的 `securityContext`），且 validate 沒覆蓋到，資源就帶著「政策自己塞進去的不安全預設」進了叢集。

心法（承 Day91）：

- **安全關鍵欄位優先用 validate（deny）而不是 mutate（silent fix）**——你要的是「違規被擋下、被看到」，不是「被政策悄悄改好」。mutate 適合「補非安全性的樣板欄位」，不適合當安全防線。
- **若一定要 mutate＋validate 併用，記住 validate 檢查的是 post-mutation 狀態**，別預期 validate 能抓到 mutate 已經改掉的東西；要抓「原始輸入違規」得在 mutate 之前另做，或乾脆不 mutate。
- **mutation 必須冪等（承 Day91 第五節 `reinvocationPolicy`／Day22）**：多條 mutation 互相改、可能被重跑，改寫邏輯重複套用結果要一致。

一句話：**mutate 先跑、validate 後跑——所以「用 mutate 修、用 validate 擋」放在同一欄位時，validate 只會看到修好的版本，違規被藏起來。安全關鍵欄位要 deny，不要 silent fix。**

---

## 六、盲點四：只攔 `CREATE` 漏 `UPDATE` / subresource 繞過

政策的 `match` 決定「哪些操作會觸發檢查」。Gatekeeper 的 webhook 預設攔 `CREATE` 與 `UPDATE`；Kyverno 的 validate 預設也涵蓋 `CREATE`/`UPDATE`。**問題出在兩種情況：你「主動把範圍縮小了」，或「有些寫入路徑根本不是主資源的 CREATE/UPDATE」。**

**① 主動縮成只 `CREATE`＝開了 `UPDATE` 後門。** 有人為了「少攔一點、減少誤擋」，把 Kyverno 的 `match.any[].resources.operations` 設成 `["CREATE"]`。後果：攻擊者先建一個**合規**的資源（過檢查），再 `kubectl edit`/`patch` 把它**改成違規**——因為 `UPDATE` 沒被攔，改動長驅直入。**安全政策的 `operations` 必須同時含 `CREATE` 和 `UPDATE`**（除非你非常確定該資源不可變）。

**② subresource 繞過——最容易被漏、也最實務的一種。** 有些危險操作走的不是 Pod 的 CREATE/UPDATE，而是 **subresource**：

- **`pods/ephemeralcontainers`（`kubectl debug`）**：往一個**正在跑的 Pod**注入一個臨時容器。如果你的政策只攔 Pod 的 CREATE/UPDATE，這條路能塞進一個 privileged／掛了敏感 mount 的 debug 容器——**主資源沒被改，subresource 被改，政策沒看到。**
- **`pods/exec`、`pods/attach`**：進到容器裡執行命令。要限制誰能 exec，光靠「擋 Pod 建立」沒用，得攔 `pods/exec` 這個 subresource（或用 RBAC 收 exec 權，承 Day07）。

Gatekeeper 與 Kyverno 都支援明確匹配 subresource，但**你得記得寫**——預設只攔主資源時，`ephemeralcontainers`/`exec` 就是繞過口。

**③ 控制器代建的繞過（Kyverno autogen）**：Pod 通常是 Deployment/Job 等控制器代建的。Kyverno 有 **autogen**，會自動幫「匹配 Pod 的政策」產生對應 Pod controller 的規則；**但如果 autogen 被關掉、或你只 `match: Pod` 又把控制器的 ServiceAccount 放進 `exclude`**，使用者用 Deployment 部署時，實際建 Pod 的是控制器 SA，就可能繞過只針對「使用者直接建 Pod」的政策。

一句話：**政策的攔截面 = `operations`（必含 CREATE＋UPDATE）× 資源（含該管的 subresource）× 代建路徑（autogen/控制器 SA）。漏任何一段，就有一條合法寫入路徑不經過你的政策。**

---

## 七、盲點五：admission 只擋新寫入，既存違規要靠 audit / background scan

承 Day91 第一節、也承第一節那條邊界：**你今天上線一條 enforce 政策，它只對「之後的寫入」生效，昨天就違規跑著的資源它一個都碰不到。** 這不是 bug，是 admission 的本質——它是「入口的門」，不是「屋裡的巡邏」。

兩種引擎各有巡邏機制：

- **Gatekeeper audit**：audit controller 週期性掃描叢集**既存資源**，把違反現有 Constraint 的資源列進 **`Constraint.status.violations`**。你上線政策後，該去看 audit 結果，才知道存量有多少違規要清。
- **Kyverno background scan**：政策開 `spec.background: true`，Kyverno 會定期用現有政策掃既存資源，產出 **`PolicyReport`/`ClusterPolicyReport`**。`background: false` 就沒有這層——只有 admission 當下擋新的，存量完全不可見。

兩個實務重點：

1. **上線新 enforce 政策前，先用 audit/background scan 盤存量**：直接上 `deny`/`Enforce` 不會回頭刪既存違規資源，但會讓「既存違規資源的下一次 `UPDATE`」突然被擋（因為 UPDATE 也被攔，第六節），造成看似無關的部署失敗。先盤點、先修，再切 enforce。
2. **`background: false` / 沒看 audit＝存量盲區**：政策只擋門口，屋裡有多少違規你不知道。這也是為什麼稽核（第八節）要抓 `background: false`。

一句話：**enforce 管未來、audit/background scan 管存量；只設 enforce 不看 audit/background，等於只鎖了門卻從沒巡過屋裡。**

---

## 八、Day16 稽核：掃政策本身的危險狀態

前七節的坑，多數能從政策物件的 JSON **靜態掃出來**，寫成 CI（甚至自己就是一條 admission 政策——用政策管政策），這是 Day16「把偵測升級成預防」在 policy-as-code 的落點（承 Day87/88/90/91 同一套心法：先在 chat/CI 跑一次看資料長相，再寫解析）。

先看資料長相（Kyverno 的 ClusterPolicy/Policy 可以一次撈成一個 List）：

```bash
kubectl get clusterpolicies,policies -A -o json          # Kyverno
kubectl get constrainttemplates -o json                  # Gatekeeper：Constraint 是動態 CRD，需先列 template 再逐 kind 撈
```

> **Gatekeeper 的 Constraint 是動態產生的 CRD**（每個 `ConstraintTemplate` 產生一個 `constraints.gatekeeper.sh` 下的 kind），沒有單一 `kubectl get constraints` 能一次撈全部。稽核腳本要先 `get constrainttemplates` 拿到所有 kind，再對每個 kind `kubectl get <kind> -o json` 檢查 `spec.enforcementAction`。下面的 Go/Java 範例以 **Kyverno ClusterPolicy** 為主（單一 List、乾淨），Gatekeeper 部分於文末以 shell 示意。

**Go 版**：掃每條 Kyverno ClusterPolicy，抓四件事——① `failureAction`/`validationFailureAction` 是 `Audit`（沒 enforce，第三節）；② `background: false`（存量盲區，第七節）；③ `exclude` 過寬（後門，第四節）；④ validate 規則的 `operations` 只含 `CREATE` 漏 `UPDATE`（第六節）。

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type resources struct {
	Kinds      []string `json:"kinds"`
	Operations []string `json:"operations"`
	Namespaces []string `json:"namespaces"`
}
type matchBlock struct {
	Any []struct {
		Resources resources `json:"resources"`
	} `json:"any"`
	All []struct {
		Resources resources `json:"resources"`
	} `json:"all"`
}
type rule struct {
	Name    string     `json:"name"`
	Match   matchBlock `json:"match"`
	Exclude matchBlock `json:"exclude"`
	Validate *struct {
		FailureAction string `json:"failureAction"` // 新版 per-rule
	} `json:"validate"`
}
type policy struct {
	Metadata struct{ Name string } `json:"metadata"`
	Spec     struct {
		Background              *bool  `json:"background"`
		ValidationFailureAction string `json:"validationFailureAction"` // 舊版 policy-level
		Rules                   []rule `json:"rules"`
	} `json:"spec"`
}
type polList struct {
	Items []policy `json:"items"`
}

func has(list []string, x string) bool {
	for _, v := range list {
		if v == x {
			return true
		}
	}
	return false
}

// 這條 rule 實際生效的 action：per-rule 優先，否則看 policy-level，預設 Audit（Kyverno 未設時的保守假設）
func effectiveAction(p policy, r rule) string {
	if r.Validate != nil && r.Validate.FailureAction != "" {
		return r.Validate.FailureAction
	}
	if p.Spec.ValidationFailureAction != "" {
		return p.Spec.ValidationFailureAction
	}
	return "Audit"
}

func main() {
	out, err := exec.Command("kubectl", "get", "clusterpolicies,policies", "-A", "-o", "json").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kubectl 失敗：", err)
		os.Exit(2)
	}
	var pl polList
	if err := json.Unmarshal(out, &pl); err != nil {
		fmt.Fprintln(os.Stderr, "JSON 解析失敗：", err)
		os.Exit(2)
	}

	fail := false
	for _, p := range pl.Items {
		// ② background:false → 存量盲區
		if p.Spec.Background != nil && !*p.Spec.Background {
			fmt.Printf("WARN %s：background=false（既存違規資源不會被掃，第七節）\n", p.Metadata.Name)
		}
		for _, r := range p.Spec.Rules {
			id := p.Metadata.Name + "/" + r.Name
			if r.Validate == nil {
				continue // 只審 validate 規則
			}

			// ① 沒在 enforce（Audit）→ 判紅：安全政策留在 Audit 等於沒上線
			if effectiveAction(p, r) == "Audit" {
				fmt.Printf("FAIL %s：validate 動作為 Audit（未 enforce，等於沒在擋，第三節）\n", id)
				fail = true
			}

			// ④ operations 只含 CREATE 漏 UPDATE
			for _, m := range r.Match.Any {
				ops := m.Resources.Operations
				if len(ops) > 0 && has(ops, "CREATE") && !has(ops, "UPDATE") {
					fmt.Printf("FAIL %s：match operations 只含 CREATE 漏 UPDATE（建完再改即繞過，第六節）\n", id)
					fail = true
				}
			}

			// ③ exclude 過寬：排除整個 namespace / 用萬用字元
			for _, e := range r.Exclude.Any {
				for _, ns := range e.Resources.Namespaces {
					if ns == "*" {
						fmt.Printf("FAIL %s：exclude namespaces 含 \"*\"（等於關閉政策，第四節）\n", id)
						fail = true
					} else {
						fmt.Printf("WARN %s：exclude 了 namespace %q（確認是否為必要豁免且有到期，第四節）\n", id, ns)
					}
				}
			}
		}
	}

	if fail {
		os.Exit(1)
	}
	fmt.Println("OK：所有 Kyverno 政策皆 enforce、含 UPDATE、無過寬 exclude")
}
```

**Java 版**（Jackson，對稱邏輯，判紅同上）：

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class KyvernoPolicyAudit {
    static final ObjectMapper OM = new ObjectMapper();

    static boolean listHas(JsonNode arr, String x) {
        for (JsonNode v : arr) if (x.equals(v.asText())) return true;
        return false;
    }

    // per-rule 優先，否則 policy-level，預設 Audit
    static String effectiveAction(JsonNode spec, JsonNode rule) {
        String perRule = rule.path("validate").path("failureAction").asText("");
        if (!perRule.isEmpty()) return perRule;
        return spec.path("validationFailureAction").asText("Audit");
    }

    public static void main(String[] args) throws Exception {
        Process p = new ProcessBuilder("kubectl", "get",
                "clusterpolicies,policies", "-A", "-o", "json").start();
        JsonNode root = OM.readTree(p.getInputStream());

        boolean fail = false;
        for (JsonNode pol : root.path("items")) {
            String name = pol.path("metadata").path("name").asText();
            JsonNode spec = pol.path("spec");

            if (spec.has("background") && !spec.path("background").asBoolean()) {
                System.out.printf("WARN %s：background=false（既存違規不會被掃，第七節）%n", name);
            }
            for (JsonNode rule : spec.path("rules")) {
                if (rule.path("validate").isMissingNode()) continue;
                String id = name + "/" + rule.path("name").asText();

                if ("Audit".equals(effectiveAction(spec, rule))) {
                    System.out.printf("FAIL %s：validate 動作為 Audit（未 enforce，第三節）%n", id);
                    fail = true;
                }
                for (JsonNode m : rule.path("match").path("any")) {
                    JsonNode ops = m.path("resources").path("operations");
                    if (ops.size() > 0 && listHas(ops, "CREATE") && !listHas(ops, "UPDATE")) {
                        System.out.printf("FAIL %s：operations 只含 CREATE 漏 UPDATE（第六節）%n", id);
                        fail = true;
                    }
                }
                for (JsonNode e : rule.path("exclude").path("any")) {
                    for (JsonNode ns : e.path("resources").path("namespaces")) {
                        if ("*".equals(ns.asText())) {
                            System.out.printf("FAIL %s：exclude namespaces 含 \"*\"（第四節）%n", id);
                            fail = true;
                        } else {
                            System.out.printf("WARN %s：exclude namespace \"%s\"（確認必要且有到期，第四節）%n",
                                    id, ns.asText());
                        }
                    }
                }
            }
        }
        if (fail) System.exit(1);
        System.out.println("OK：所有 Kyverno 政策皆 enforce、含 UPDATE、無過寬 exclude");
    }
}
```

**Gatekeeper enforcementAction 的 shell 稽核**（先列 template 再逐 kind 掃 `dryrun`/`warn`）：

```bash
# 掃所有 Gatekeeper Constraint 是否還在 dryrun/warn（第三節）
for kind in $(kubectl get constrainttemplates -o jsonpath='{.items[*].spec.crd.spec.names.kind}'); do
  kubectl get "$kind" -o json 2>/dev/null | \
    jq -r --arg k "$kind" '.items[]
      | select((.spec.enforcementAction // "deny") != "deny")
      | "WARN \($k)/\(.metadata.name)：enforcementAction=\(.spec.enforcementAction)（未 deny，等於沒在擋）"'
done
```

三個 CI 靜態掃不到、但要補的角度：

- **政策的邏輯對不對——CI 看不到**：`match` 接上了、`failureAction: Enforce` 也對，但 Rego/pattern 裡到底有沒有真的表達「那條規則」、有沒有寫錯讓它永遠通過，靜態掃不出來。這只能靠第十節的政策單元測試守。
- **exempt 是否「合理」——CI 只能抓過寬，抓不到「該不該給」**：一條 `exclude: team-x` 語法上完全正常，但它該不該存在、有沒有到期、是不是後門，要靠審核流程與到期稽核，不是掃 JSON 能決定的。
- **既存違規存量——要看 audit/background 結果**：`Constraint.status.violations` 與 `PolicyReport` 是執行期產物，CI 當下看不到。

**執行期承 Day16**：把 Gatekeeper 的 audit 結果／Kyverno 的 `PolicyReport`、以及 webhook 的 deny 事件打進 SIEM，對三件事告警——① **安全關鍵政策實際處於 `dryrun`/`Audit`**（門開著、政策形同虛設，P1）；② **`PolicyReport`/`status.violations` 中既存違規數突增**（有人往 exempt namespace 或走 subresource 塞違規資源）；③ **deny 事件對特定 namespace/使用者尖峰**（可能在探哪條政策沒生效）。**因為「政策到底有沒有在擋、存量有多少違規、有沒有人在戳繞過口」這幾件事，靜態掃掃不到,只能靠執行期抓。**

---

## 九、常見誤區

| 誤區 | 為什麼錯 |
|---|---|
| 「政策部署了就等於在擋」 | `dryrun`/`Audit` 是部署了但不擋，只記錄；要 `deny`/`Enforce` 才真的擋（第三節） |
| 「`Audit`/`dryrun` 比較安全，先觀察」 | 觀察期沒錯，但忘了切回 enforce＝常駐不設防，還能被主動利用（第三節） |
| 「`failurePolicy: Fail` 了政策就穩了」 | 那是 Day91 的管線；政策留在 `dryrun`/漏 UPDATE，webhook 再穩也沒防（第一節） |
| 「把某 team 加進 `excludedNamespaces` 省事」 | 一條過寬 exempt＝合法後門，任何能往該 ns 部署的人全繞過（第四節） |
| 「exempt 用 role/SA 排除比較精準」 | 豁免特定 role/SA 也是存取控制決策，寫寬＝越權後門（第四節，承 Day07/49） |
| 「用 mutate 幫忙修，再用 validate 檢查」 | mutate 先跑，validate 只看到修好的版本，原始違規被靜默藏起（第五節，承 Day91） |
| 「mutate 補的預設一定安全」 | mutate 可能塞出過寬預設，validate 又沒覆蓋＝不安全預設長驅直入（第五節） |
| 「只攔 `CREATE` 就夠了」 | 建一個合規的、再 UPDATE 成違規即繞過；`operations` 必含 CREATE＋UPDATE（第六節） |
| 「攔了 Pod 就攔到所有危險操作」 | `ephemeralcontainers`(kubectl debug)/`exec` 是 subresource，不攔就是繞過口（第六節） |
| 「政策 match Pod，Deployment 自然也被管」 | 靠 Kyverno autogen；autogen 關掉或 exclude 控制器 SA＝控制器代建繞過（第六節） |
| 「上線 enforce 政策，叢集就乾淨了」 | admission 只管新寫入，既存違規要靠 audit/background scan 盤（第七節，承 Day91） |
| 「`background: false` 沒差」 | 沒 background＝存量違規完全不可見,只擋門口沒巡屋裡（第七節） |
| 「政策語法對就代表邏輯對」 | Rego/pattern 可能永遠通過或抓錯欄位，靜態掃不出，要單元測試（第八、十節） |

---

## 十、Code Review / 維運 checklist

**政策真的在擋（第三節，承 Day91 fail 行為的心法）**

- [ ] Gatekeeper `Constraint.spec.enforcementAction` 為 `deny`（`dryrun`/`warn` 只在明確、短暫的觀察期，且有到期）。
- [ ] Kyverno validate 的 `failureAction`（或舊版 `spec.validationFailureAction`）為 `Enforce`；任何 `Audit` 都有明確理由與到期。
- [ ] CI 判紅「安全關鍵政策處於 `dryrun`/`Audit`」；執行期對「實際處於不擋狀態」告警。

**攔截面完整（第五、六節，承 Day91 mutating 順序）**

- [ ] `operations` 同時含 `CREATE` 與 `UPDATE`（除非資源確定不可變）。
- [ ] 需要時明確匹配 subresource（`pods/ephemeralcontainers`、`pods/exec`）；exec 另用 RBAC 收（承 Day07）。
- [ ] 確認 Kyverno autogen 生效或政策已覆蓋 Pod controller；控制器 SA 未被誤放進 `exclude`。
- [ ] 安全關鍵欄位用 validate（deny）而非 mutate（silent fix）；mutate 邏輯冪等（承 Day22/Day91）。

**豁免與存量（第四、七節，承 Day07/49）**

- [ ] `excludedNamespaces`/`exclude` 只含控制面必要項；業務豁免有原因、到期、審核。
- [ ] Gatekeeper 全域 `Config` 的 `excludedNamespaces` 特別審（影響所有 Constraint）。
- [ ] Kyverno `spec.background: true`；上線 enforce 前已用 audit/background scan 盤存量並修。

**稽核（第八節，承 Day16）**

- [ ] CI 掃「`dryrun`/`Audit`（判紅）、`background:false`、只 CREATE 漏 UPDATE、`exclude` 含 `*`/過寬」。
- [ ] 執行期把 `PolicyReport`/`status.violations`/deny 事件進 SIEM 並告警。

---

## 十一、測試 / 演練建議

- **把 policy 當程式碼測（承 Day90 Rego 可測性）**：Gatekeeper 的 Rego 用 **`opa test`** 寫單元測試（給一個違規物件斷言 `violation` 有輸出、給合規物件斷言沒有）；Kyverno 用 **`kyverno test`**（`kyverno-test.yaml` 描述 policy＋resource＋預期 pass/fail）與 `kyverno apply` 在 CI 對範例資源跑。**政策沒有測試＝你不知道它到底有沒有在抓對東西（第八節 CI 靜態掃不到邏輯）。**
- **enforce 迴歸（第三節）**：把某條安全政策改成 `dryrun`/`Audit`，斷言第八節的 CI **判紅**；送一個違規資源斷言在 `Enforce`/`deny` 下**被擋**、在 `Audit`/`dryrun` 下**被放行但有報告**——證明兩種狀態的差別真的如你所想。
- **UPDATE 繞過演練（第六節）**：先建一個**合規**資源（過檢查），再 `kubectl patch` 成違規，斷言**被擋**；若通過＝你的 `operations` 漏了 `UPDATE`。
- **subresource 繞過演練（第六節）**：對一個跑著的 Pod 用 `kubectl debug`（注入 `ephemeralcontainers`）塞一個 privileged 容器，斷言**被擋**；若成功注入＝政策沒攔 subresource。
- **mutation 順序測試（第五節）**：對「mutate 補預設＋validate 檢查同欄位」的組合，送一個原始就違規的資源，斷言**你預期的結果**（若你要的是「被擋」，卻發現被 mutate 靜默修好而通過，代表你把攔截降級成粉飾了）。
- **exempt 後門演練（第四節）**：往一個在 `excludedNamespaces`/`exclude` 裡的 namespace 部署違規資源，斷言它**確實不被政策攔**（確認豁免範圍就是你以為的那麼大，沒有多），並確認這個豁免有審核紀錄與到期。
- **既存存量盤點（第七節）**：上線 enforce 前跑 Gatekeeper audit／Kyverno background scan，斷言 `status.violations`/`PolicyReport` 有列出既存違規；`background: false` 時斷言**掃不到存量**（用來證明這個盲區真實存在）。

---

## 十二、一句話總結

> Day91 收 **webhook 管線本身**（誰能改、攔誰、掛了 `failurePolicy` 怎麼辦），Day92 收 **跑在管線上的政策內容**——用 Gatekeeper（`ConstraintTemplate` 內嵌 Rego＋`Constraint`）或 Kyverno（`ClusterPolicy` 的 validate/mutate）把政策寫成宣告式 YAML，但五個盲點沒一個是 `failurePolicy` 能救的：**① `dryrun`/`Audit` 等於沒上線**——`enforcementAction: deny`／`failureAction: Enforce` 才真的擋，留在 `dryrun`/`Audit` 是「webhook 活著也不擋」，比 fail-open 更徹底沒防；**② `excludedNamespaces`/exempt 後門**——一條過寬的豁免＝合法繞過，任何能往該 ns/該 role 部署的人全繞過（承 Day07/49），exempt 是政策的信任邊界要審核、到期、稽核；**③ mutation 改掉 validation 看到的內容**（承 Day91 mutating-before-validating）——mutate 先跑，validate 只看到修好的版本，「用 mutate 修＋用 validate 擋」同一欄位＝違規被靜默藏起，安全關鍵欄位要 deny 不要 silent fix，且 mutation 要冪等（承 Day22）；**④ 只攔 `CREATE` 漏 `UPDATE`/subresource**——`operations` 必含 CREATE＋UPDATE（否則建完再改繞過）、`pods/ephemeralcontainers`(kubectl debug)/`exec` 是 subresource 要明確攔、Deployment 代建靠 autogen 別誤 exclude 控制器 SA；**⑤ admission 只管新寫入既存違規要 audit/background scan**（承 Day91）——enforce 管未來、Gatekeeper audit／Kyverno `background:true`+`PolicyReport` 管存量，上線 enforce 前先盤存量再切。稽核（承 Day16）把「`dryrun`/`Audit`、`background:false`、只 CREATE 漏 UPDATE、`exclude` 過寬」寫成 CI（Go/Java 掃 `clusterpolicies` JSON、shell 掃 Gatekeeper `enforcementAction`），執行期對「政策實際不擋、存量違規突增、deny 尖峰」告警；政策本身用 `opa test`/`kyverno test` 當程式碼測（承 Day90），因為「政策邏輯對不對、有沒有人在戳繞過口」靜態掃不到。一句話：**管線再穩，政策留一個 `dryrun`、一個過寬 `exempt`、一個漏掉的 `UPDATE`/subresource，或忘了盤既存資源，就等於沒防——policy-as-code 的安全，不在「政策存在」，在「政策真的在擋、擋的是對的範圍、而且測得出來」。**

---

## 延伸閱讀

- Day91 admission webhook 信任邊界與 `failurePolicy`——本篇上游：Day91 收「管線本身」（誰能改、攔誰、掛了怎麼辦），今天收「跑在管線上的政策內容」怎麼被寫成 dryrun、被 exempt 掏空、被 mutation 與 UPDATE/subresource 繞過。
- Day90 mesh `ext_authz` OPA/Rego 授權——本篇用到 Gatekeeper 的 Rego 與 `opa test`；Day90 講 Rego 語法基礎與可測性，今天講 Rego 寫成 admission 政策後的盲點，不重述語法。
- Day07 Broken Access Control / default deny——`enforcementAction: deny`/`failureAction: Enforce` 是 default deny 在政策層的落點；exempt 清單本身就是一種存取控制決策，寫寬＝後門。
- Day49 BFLA——豁免特定 role/ServiceAccount 而繞過政策，與功能層級授權沒收好同源。
- Day18 供應鏈 / 弱點依賴——禁 `:latest`、要求 image 帶 digest 就是把「可重現與可稽核」寫進政策，是本篇範例規則的動機。
- Day22 Race Condition / Idempotency——mutation 政策可能被多次呼叫（承 Day91 `reinvocationPolicy`），改寫必須冪等。
- Day16 Security Logging / Monitoring——把 `PolicyReport`/`status.violations`/deny 事件進 SIEM，對「政策實際不擋、存量違規突增」告警（靜態掃永遠掃不到執行期的門開沒開）。

---

明天預告：**Day 93 — Kubernetes 內建的 Pod Security Admission（PSA）與 Pod Security Standards：built-in admission 與 Gatekeeper/Kyverno policy engine 的取捨**
（這是**新主題但接續 admission 系列**，不重講 Day91 的 webhook 機制、也不重講 Day92 的 Gatekeeper/Kyverno 政策寫法。Day91–92 收的是「外掛式 policy engine」（自寫 webhook 或 Gatekeeper/Kyverno）；明天收 Kubernetes **內建、不用裝任何東西**的 admission plugin——Pod Security Admission。角度三條：**① PSA 是什麼、怎麼用**——三個等級（`privileged`/`baseline`/`restricted`，對應 Pod Security Standards）、三種模式（`enforce`/`audit`/`warn`，各自獨立可疊加）、靠 **namespace label**（`pod-security.kubernetes.io/enforce: restricted` 等）驅動，會用「把某 namespace 設成 `restricted`、擋掉 privileged/hostPath/hostNetwork」當後端可落地的例子；**② built-in vs policy engine 的取捨**——PSA 免安裝、輕、穩，但**只有三個固定等級、只管 Pod-level、不能寫自訂規則**（要「禁 `:latest`」「要 resource limits」這種自訂規則就得回去用 Day92 的 Gatekeeper/Kyverno）；兩者常常是**併用**（PSA 兜底 Pod 安全基線＋policy engine 補自訂規則），不是二選一；**③ PSA 自己的盲點**——它靠 namespace label 驅動，所以**誰能改 namespace label 誰就能降級整個 namespace 的安全等級**（承 Day07 RBAC，這是 PSA 的信任邊界）、`exemptions`（放行特定 usernames/runtimeClassNames/namespaces，承 Day92 第四節 exempt 後門的同一風險）、以及「PSA 只在 Pod 建立/更新時擋，管不到既存 Pod」（承 Day91/92 那條 admission 邊界）。程式面會示範 namespace 的 PSA label YAML、`restricted` 等級擋掉的典型欄位、以及一支掃「namespace 沒設 enforce label／被降級成 privileged／exemptions 過寬」的稽核（Go/Java，承 Day92 第八節同一套心法）。安全主軸一句話：**Day92 收「你自己寫的政策」怎麼被繞過，Day93 收「Kubernetes 幫你內建的那套 Pod 安全基線」怎麼用、什麼時候夠、什麼時候要搭 policy engine，以及它自己那條「namespace label＝安全等級」的信任邊界怎麼守。** 這是接續 admission 系列的新主題，聚焦內建 PSA 與 built-in/policy-engine 取捨，不重述 webhook 機制與 Gatekeeper/Kyverno 政策寫法。）
