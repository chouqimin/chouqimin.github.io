---
title: "Day 93：Kubernetes 內建的 Pod Security Admission（PSA）與 Pod Security Standards——三等級（privileged/baseline/restricted）、三模式（enforce/audit/warn）、namespace label 驅動、built-in vs Gatekeeper/Kyverno 取捨、以及「誰能改 label 誰能降級」的信任邊界"
date: 2026-08-03
tags: ["Kubernetes", "Pod Security Admission", "admission-control", "RBAC"]
---

接續 Day92 預告：Day91 收 **admission webhook 這條管線本身**，Day92 收 **跑在管線上的 Gatekeeper／Kyverno 政策內容**——這兩天都是「外掛式 policy engine」：你得自己裝一個東西（自寫 webhook、Gatekeeper 或 Kyverno），它才會幫你把政策接到 admission 鏈上。今天收 Kubernetes **內建、不用裝任何東西**的那個 admission plugin——**Pod Security Admission（PSA）**，以及它背後的 **Pod Security Standards** 三等級。

**這是接續 admission 系列的新主題，但不重講 Day91 的 webhook 機制與 `failurePolicy`、也不重講 Day92 的 Gatekeeper／Kyverno 政策寫法。** admission 鏈長怎樣、mutating 為什麼在 validating 之前、`failurePolicy` fail-open/fail-closed、Gatekeeper 的 `ConstraintTemplate`＋Rego、Kyverno 的 `ClusterPolicy` validate/mutate——前兩天都講過，今天不重述。

延伸角度只有一條主軸：**Day91–92 是「外掛」路線（要裝 engine、要管 webhook 憑證與可用性、政策要自己寫對），PSA 走的是「內建」路線——apiserver 內建、預設就開、靠 namespace label 驅動、只有三個固定等級。** 這篇用三段收好：**① PSA 是什麼、怎麼用**——三等級（`privileged`/`baseline`/`restricted`）、三模式（`enforce`/`audit`/`warn`）、靠 namespace label 開，用「把某 namespace 設成 `restricted`、擋掉 privileged／hostPath／hostNetwork」當後端可落地的例子；**② built-in vs policy engine 的取捨**——PSA 免裝、輕、穩，但只有固定等級、只管 Pod-level、不能寫自訂規則（「禁 `:latest`」「要 resource limits」這種還是得回 Day92 的 Gatekeeper／Kyverno），兩者常常是**併用**不是二選一；**③ PSA 自己的盲點**——namespace label＝安全等級，所以**誰能改 label 誰能降級整個 namespace**（承 Day07 RBAC 信任邊界）、`exemptions` 後門（承 Day92 第四節）、以及 enforce 只套用到 Pod 不套用到 Deployment＋只擋新寫入管不到既存（承 Day91/92 那條 admission 邊界）。

> ⚠️ PSA 的欄位與等級定義會隨 Kubernetes 版本演進。namespace label 前綴 `pod-security.kubernetes.io/`（`enforce`/`audit`/`warn` 與對應的 `*-version`）、cluster 端的 `AdmissionConfiguration`（`apiserver.config.k8s.io/v1`）內嵌 `PodSecurityConfiguration`（`pod-security.admission.config.k8s.io/v1`，1.23 為 v1beta1、1.25 起 v1）、以及 `baseline`/`restricted` 各自「擋哪些欄位」的細節，都要對照**你那個叢集版本**的官方 Pod Security Standards 文件，別照抄字串或死記某個欄位清單——這裡示範的是「PSA 怎麼被設定、被降級、被繞過」的**意圖**，不是某一版的精確欄位表。PSA 在 v1.23 進 beta（預設開）、v1.25 GA；更早的叢集可能還在用已被移除的 PodSecurityPolicy（PSP），本文不涵蓋 PSP。

---

## 一、先定位：PSA 是「內建」的那條路，跟 Day91–92 的「外掛」正交

把 admission 這幾天的關係擺清楚（承 Day91 的 admission 鏈、承 Day92 的政策內容）：

| | Day91 | Day92 | **Day93（本篇）** |
|---|---|---|---|
| 收什麼 | webhook **管線本身** | 跑在管線上的**政策內容** | **內建的 Pod 安全基線** |
| 實作 | 自寫 admission webhook | Gatekeeper／Kyverno（外掛 engine） | **PSA（apiserver 內建 plugin）** |
| 要不要裝東西 | 要（自己寫＋部署） | 要（裝 engine） | **不用，預設就開** |
| 規則怎麼來 | 自己寫 handler | 自己寫 Constraint/ClusterPolicy | **官方定義的三個固定等級** |
| 能不能自訂 | 能（任意邏輯） | 能（Rego/YAML/CEL） | **不能，只有三選一** |
| 靠什麼觸發 | `*WebhookConfiguration` | Constraint/Policy 的 `match` | **namespace 的 label** |

一句話定位：**PSA 不是要取代 Gatekeeper／Kyverno，而是補一個「免安裝、擋得住最基本 Pod 逃逸」的底盤。** 它的優點全來自「內建」——沒有 Day91 那支 webhook，就沒有 caBundle 憑證輪替、沒有 webhook Pod 掛掉造成的可用性單點、沒有 `failurePolicy` fail-open/fail-closed 的兩難、沒有啟動死結；它的限制也全來自「內建且固定」——你只能在三個等級裡選，改不動、加不了自訂規則。

> 一個貫穿全篇、承 Day91／Day92 的邊界：**PSA 跟所有 admission 一樣，只在「Pod 被寫入的當下」觸發，管不到「已經在 namespace 裡跑著的既存 Pod」。** 你今天把一個 namespace 貼上 `enforce: restricted`，它擋得住之後的新 Pod，但**擋不掉昨天就違規跑著的 Pod**（第七節會講：relabel 時 apiserver 會對既存違規 Pod 回警告，但不會驅逐）。這條邊界 Day91/92 標記過，這篇落到 PSA 上。

---

## 二、PSA 是什麼：三等級 × 三模式 × namespace label

PSA 只做一件事：**在 Pod 建立／更新的當下，拿它去比對「這個 namespace 要求的 Pod Security Standard 等級」，違規就依模式處理。** 三個維度：

### （1）三等級 = Pod Security Standards（由寬到嚴）

- **`privileged`**：完全不設限。什麼都放行——等於沒有 PSA。
- **`baseline`**：擋掉「已知的權限提升與 host 逃逸」這種**明顯危險**的東西。典型會擋：`privileged: true` 容器、host namespaces（`hostNetwork`/`hostPID`/`hostIPC`）、`hostPath` volume、`hostPort`（受限）、`Unconfined` 的 seccomp、危險的 `sysctls`、以及新增 `NET_BIND_SERVICE` 以外的 Linux capabilities。這是「別讓容器直接踩到 node」的最低線。
- **`restricted`**：在 baseline 之上再套「目前 Pod 硬化最佳實務」。除了 baseline 全部，還**強制要求**：`runAsNonRoot: true`、`allowPrivilegeEscalation: false`、`capabilities.drop: ["ALL"]`（只准 `add: ["NET_BIND_SERVICE"]`）、`seccompProfile.type` 必為 `RuntimeDefault` 或 `Localhost`、volume 類型限縮（大致只剩 `configMap`/`secret`/`emptyDir`/`downwardAPI`/`projected`/`ephemeral`/PVC 等非 host 類）。

一句話：**baseline 是「不准逃出容器」，restricted 是「連容器內都以最小權限跑」。** 後端服務絕大多數應該以 restricted 為目標；真的需要特權的（CNI、監控 agent、儲存 driver）才用 baseline/privileged，並且**單獨隔一個 namespace**（第五、六節）。

### （2）三模式（互相獨立，可疊加）

同一個等級，可以用三種模式套，各自獨立、可同時設：

- **`enforce`**：違規 Pod **直接被拒**（reject，API 回錯）。
- **`audit`**：違規 Pod **照樣放行**，但在 **audit log** 記一筆 annotation（給稽核／SIEM 用，承 Day16）。
- **`warn`**：違規 Pod **照樣放行**，但回一段**使用者可見的警告**（`kubectl apply` 時會印出來）。

**關鍵差異（第七節會展開）：`enforce` 只套用到 Pod 本身，不套用到「建立 Pod 的工作負載資源」（Deployment/StatefulSet/Job…）；`warn` 和 `audit` 則會套用到工作負載資源。** 這就是為什麼實務上常見的漸進式收斂配置是：**`enforce: baseline` + `warn: restricted` + `audit: restricted`**——底線先 enforce 住 baseline，同時用 warn/audit 讓大家在 Deployment 層就看到「你離 restricted 還差什麼」，等清乾淨了再把 enforce 拉到 restricted。

### （3）靠 namespace label 驅動

PSA 沒有自己的 CRD——它讀 **namespace 的 label**：

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: payments
  labels:
    # enforce：違規直接擋（只套用到 Pod 本身，不套用到 Deployment，第七節）
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.30   # ★ 釘版本：升級叢集不會突然改變 restricted 的定義
    # warn/audit：對工作負載資源（Deployment 等）也生效，補 enforce 的盲區（第七節）
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.30
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.30
```

> **`*-version` 是常被忽略但很重要的一個旋鈕。** 等級的定義（restricted 到底擋哪些欄位）會隨 Kubernetes 版本微調。釘 `enforce-version: v1.30` 代表「用 1.30 那版的 restricted 定義」，升級叢集時**行為不變**；用 `latest` 則代表「永遠跟著最新」——升級後可能突然多擋一個以前沒擋的欄位（好處是拿到最新硬化，代價是升級可能讓原本能起的 Pod 起不來）。安全關鍵 namespace 建議**釘明確版本並納入變更流程**，別放 `latest` 讓叢集升級順便改變你的安全語意。

**沒貼 label 的 namespace 吃誰？** 吃 cluster 端 `PodSecurityConfiguration` 的 `defaults`；而 defaults 若沒特別設，`enforce` 的預設值是 **`privileged`**——也就是**沒貼 label ＝ 沒防護**。這是第八節稽核最重要的一條：**「namespace 沒有 enforce label」不是中性狀態，而是「門開著」。**

---

## 三、實例：把 namespace 設成 restricted，看它擋掉什麼

貼上第二節那個 `payments` namespace（`enforce: restricted`）後，送這個 Pod：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
  namespace: payments
spec:
  hostNetwork: true                    # ← baseline 起就擋（host namespace 逃逸）
  containers:
    - name: app
      image: myapp:1.2.3
      securityContext:
        privileged: true               # ← baseline 起就擋
        allowPrivilegeEscalation: true # ← restricted 要求 false
        runAsNonRoot: false            # ← restricted 要求 true
        capabilities:
          add: ["SYS_ADMIN"]           # ← restricted 要求 drop ALL、只准 add NET_BIND_SERVICE
      volumeMounts:
        - { name: host, mountPath: /host }
  volumes:
    - name: host
      hostPath: { path: / }            # ← baseline 起就擋 hostPath
```

`enforce: restricted` 下這個 Pod 會被**直接拒絕**，API 回一段列出所有違規欄位的錯誤（PSA 一次把所有違規列出來，不是逐條擋）。改成合規的 restricted Pod：

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
  namespace: payments
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault             # restricted 要求 RuntimeDefault 或 Localhost
  containers:
    - name: app
      image: myapp@sha256:abcd...      # 承 Day18：帶 digest 而非浮動 tag
      securityContext:
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]                # 只准再 add: ["NET_BIND_SERVICE"]
      resources:
        requests: { cpu: "100m", memory: "128Mi" }
        limits:   { cpu: "500m", memory: "256Mi" }
```

> 注意最後那段 `resources.limits`——**PSA 一個字都不會檢查它。** restricted 管的是「安全性欄位」（特權、逃逸、非 root），**不管 resource limits、不管 image 用不用 `:latest`、不管 label/annotation 規範**。要擋這些，得回 Day92 的 Gatekeeper／Kyverno。這正是第四節「取捨」的核心：PSA 給你安全底盤，自訂規則交給 policy engine。

---

## 四、built-in vs policy engine：不是二選一，是併用

把 PSA 跟 Day92 的 Gatekeeper／Kyverno 攤開比：

| 面向 | PSA（內建） | Gatekeeper／Kyverno（外掛，Day92） |
|---|---|---|
| 安裝／維運 | **免裝、預設開、無 webhook 可維運** | 要裝、要管 webhook 憑證與可用性（Day91） |
| 可用性風險 | **幾乎沒有**（apiserver 內建） | webhook 掛了牽動 `failurePolicy`（Day91 單點） |
| 規則範圍 | **只有三個固定等級、只管 Pod-level** | 任意自訂（image、resource、label、跨資源…） |
| 表達力 | 選等級，改不動 | Rego／YAML DSL／CEL，想寫什麼寫什麼 |
| 既存資源 | relabel 時只回警告（第七節） | Gatekeeper audit／Kyverno background scan（Day92 第七節） |

**結論是併用，不是二選一：**

- **PSA 當底盤**：全叢集（尤其把 cluster default `enforce` 從 `privileged` 拉到至少 `baseline`）先兜住「不准 privileged、不准 host 逃逸、不准 hostPath」這條**免裝就有、又不會因為 webhook 掛掉而失效**的底線。就算你的 Gatekeeper／Kyverno webhook 某天掛了、被繞了（Day92），PSA 這層還在。
- **policy engine 補自訂**：PSA 管不到的（禁 `:latest`／要 digest、要 resource limits、命名規範、特定 label 必填、跨資源一致性），交給 Day92 的 Gatekeeper／Kyverno。

一句話：**PSA 是「內建的安全氣囊」，policy engine 是「你自己加裝的規則」。氣囊不會因為你沒裝改裝套件而失效，這正是把它當底盤的價值——縱深防禦（承 Day01 以來的主軸），別把全部賭在單一層。**

---

## 五、盲點一：namespace label ＝ 安全等級 → 誰能改 label 誰能降級（信任邊界，承 Day07）

這是 PSA **最關鍵**的信任邊界，也是它「靠 label 驅動」這個設計的直接代價：**PSA 的安全等級寫在 namespace 的 label 上，所以任何有權限改那個 label 的人，就能把整個 namespace 的安全等級降下來。**

具體 RBAC 路徑（承 Day07 存取控制）：

1. **對 `namespaces` 有 `update`／`patch` 權**的人，可以把 `pod-security.kubernetes.io/enforce: restricted` 改成 `privileged`，或乾脆**刪掉這個 label**（刪掉＝退回 cluster default，多半是 privileged）。改完之後，這個 namespace 的 enforce 形同關閉，接著就能大方部署 privileged／hostPath Pod。
2. **對 `namespaces` 有 `create` 權**的人，可以在**建立 namespace 的當下**就把 label 設成 `privileged`——從頭到尾沒有「降級」動作，直接生一個不設防的 namespace。
3. 這跟 Day91「誰能改 `*WebhookConfiguration` 誰能全叢集攔截」、Day92「誰在 `exclude` 清單裡誰就繞過」是**同一類問題**：**改政策生效範圍的權限，本身就是最高等級的安全決策。**

防禦：

- **收 namespace 的寫入權**：`update`/`patch`/`create` on `namespaces`（尤其能改 `metadata.labels`）應該只給平台團隊，不要隨業務 RBAC role 一起發出去。這是 Day07「控制面最高等級權限」的落點。
- **用 policy engine 反過來守 PSA 的 label**（PSA 守不了自己）：既然 PSA 沒辦法「禁止有人把自己降級」，就用 Day92 的 Gatekeeper／Kyverno 寫一條 admission 政策——**攔 namespace 的 UPDATE，禁止把 `pod-security.kubernetes.io/enforce` 改成 `privileged` 或刪除**。這是「用外掛 engine 補內建 PSA 盲點」的具體例子，也再次說明兩者為何併用。
- **稽核 label 變更**（第八節＋承 Day16）：把「namespace PSA label 被改成 privileged／被移除」當成 P1 事件打進 SIEM。

一句話：**PSA 把安全等級外包給 namespace label，於是 namespace label 的寫入權就成了 PSA 的信任邊界——收不住這個 RBAC，restricted 貼得再漂亮，有權的人一個 `kubectl label` 就掀掉。**

---

## 六、盲點二：`exemptions` 是後門（承 Day92 第四節同一風險）

Day92 講過 Gatekeeper 的 `excludedNamespaces`、Kyverno 的 `exclude` 過寬就是後門。PSA 有**完全對應**的東西——cluster 端 `PodSecurityConfiguration` 的 **`exemptions`**：

```yaml
# 傳給 kube-apiserver 的 --admission-control-config-file
apiVersion: apiserver.config.k8s.io/v1
kind: AdmissionConfiguration
plugins:
  - name: PodSecurity
    configuration:
      apiVersion: pod-security.admission.config.k8s.io/v1
      kind: PodSecurityConfiguration
      defaults:                     # 沒貼 label 的 namespace 吃這組預設
        enforce: "baseline"         # ★ 把「沒設定」的預設從 privileged 拉到 baseline，是最高槓桿的一招
        enforce-version: "latest"
        warn: "restricted"
        audit: "restricted"
      exemptions:                   # ★ 這三個清單就是後門（承 Day92 第四節）
        usernames: []               # 這些 user 送的 Pod 完全跳過 PSA
        runtimeClassNames: []       # 用這些 runtimeClass 的 Pod 跳過
        namespaces: ["kube-system"] # 這些 namespace 完全跳過（連 label 都不看）
```

三種豁免各自的風險：

1. **`exemptions.namespaces`——比 namespace label 更硬的後門**：被列進來的 namespace **完全跳過 PSA**——就算你在上面貼 `enforce: restricted`，PSA 也**不看**。所以「被 exempt 的 namespace」＋「能往它部署的人」＝完全不受 PSA 管。跟 Day92 exempt namespace「合規逃生艙」一模一樣。
2. **`exemptions.usernames`——按身分豁免最隱蔽**：某個 CI／controller 的 user（或 ServiceAccount 對應的 user）被 exempt，它送的**任何** Pod 都跳過 PSA。這跟 Day07 越權、Day49 BFLA 同源：**豁免清單本身就是一種存取控制決策，列寬了就是開後門。**
3. **`exemptions.runtimeClassNames`——最容易被漏看**：豁免特定 runtimeClass，意圖通常是「給 gVisor/Kata 這種本身就強隔離的 runtime 放行」，但如果某個 runtimeClass 其實沒那麼硬、又被 exempt，就等於開了一條「只要指定這個 runtimeClass 就跳過 PSA」的路。

**跟 Day92 exempt 不同的一點：PSA 的 `exemptions` 在 cluster 端 admission config 裡，改它要動 apiserver 設定（多半是 control plane／IaC 層），一般 `kubectl` 看不到、也改不到。** 這是雙面刃：好處是不像 namespace label 那樣容易被業務 RBAC 動到；壞處是它**藏在叢集設定裡、`kubectl get` 稽核不到**，很容易被遺忘（第八節：這條要靠盤 apiserver 設定／IaC，不是掃 namespace）。

防禦（承 Day92）：`exemptions` 只留控制面真正必要的（`kube-system` 等），每一筆都要有原因、審核、到期；`usernames`/`runtimeClassNames` 尤其要克制——按身分／runtime 豁免比按 namespace 更難稽核。

---

## 七、盲點三：enforce 只套用到 Pod、不套用到 Deployment；且只擋新寫入（承 Day91/92 邊界）

這節收兩個「你以為擋住了，其實沒有」的盲區。

### （1）`enforce` 不套用到工作負載資源——違規被「靜默吞掉」

第二節提過：**`enforce` 只套用到 Pod 本身，不套用到 Deployment/StatefulSet/Job 等建立 Pod 的資源。** 這帶來一個很反直覺、很容易誤判的現象：

> 你在 `enforce: restricted` 的 namespace 裡 `kubectl apply` 一個**違規的 Deployment**——Deployment **會建立成功、沒有任何錯誤**。接著 ReplicaSet 建立、要去建 Pod，這一步才被 PSA 擋下。結果是：**Deployment 存在、但 `READY 0/3`，Pod 一個都起不來，而錯誤只藏在 ReplicaSet 的 event 裡**（`kubectl describe rs` 或 `kubectl get events` 才看得到 `FailedCreate ... violates PodSecurity "restricted"`）。

為什麼這樣設計：如果 enforce 直接擋 Deployment，一個違規會讓 `kubectl apply` 當場失敗，看似清楚——但 Kubernetes 選擇只擋最終的 Pod，避免「controller 半途卡住」的複雜狀態。代價就是：**只設 `enforce` 的人，會以為 apply 成功＝合規，其實 Pod 根本沒起。**

**這正是 `warn` 和 `audit` 存在的理由**——它們**會**套用到 Deployment：

- `warn: restricted`：`kubectl apply` 那個違規 Deployment 時，**當場回一段警告**，使用者立刻知道「這個 Pod template 不合 restricted」。
- `audit: restricted`：把違規記進 audit log，稽核／SIEM（承 Day16）看得到。

所以「只設 enforce、不設 warn/audit」不是省事，是**把回饋藏起來**：Pod 靜默起不來，開發者一頭霧水。**enforce 一定要搭 warn（至少同等級），讓工作負載層的違規在 apply 時就浮出來。** 這是第八節稽核的一條（有 enforce 沒 warn＝判黃）。

### （2）只擋新寫入，既存 Pod 不受影響（承 Day91/92）

承第一節那條邊界：**PSA 只在 Pod 建立／更新當下觸發。** 你把一個既有 namespace 從 `privileged` 改貼 `enforce: restricted`：

- **既存那些違規 Pod 不會被驅逐、不會被殺**——它們繼續跑。
- apiserver 在你 relabel 的當下，會**對現有違規 Pod 回一段警告**（告訴你「現在有 N 個 Pod 不符新等級」），但**只是警告**。
- 真正被擋的是**之後**的新 Pod（含既存 Pod 的下一次重建／滾動更新——這時才會撞上 restricted 而起不來）。

實務順序（承 Day92 第七節「先盤存量再切 enforce」）：**先用 `warn`/`audit` 貼上目標等級觀察一段時間、把 audit log 裡的違規清乾淨，再把 `enforce` 拉上去**——否則某天一次滾動更新，一批既存服務突然因為 restricted 起不來，看起來像莫名其妙的部署失敗。

一句話：**enforce 管的是「未來的 Pod」，而且只認 Pod 不認 Deployment——所以既存違規要靠 audit 盤、Deployment 層違規要靠 warn 露；只設一個 enforce，等於只鎖了未來的正門，側門和存量都沒看。**

---

## 八、Day16 稽核：掃 namespace 的 PSA 狀態

前三節的盲點，大多能從 **namespace 的 label** 靜態掃出來，寫成 CI（承 Day92 第八節同一套心法：先在 chat/CI 跑一次看資料長相，再寫解析）。

先看資料長相（namespace 是 cluster-scoped，一次撈成一個 List）：

```bash
kubectl get namespaces -o json | jq '.items[].metadata | {name, labels}'
```

**Go 版**：掃每個 namespace，抓四件事——① 完全沒設 `enforce` label（吃 cluster 預設多半＝privileged＝無防護）；② 明確 `enforce: privileged`（主動降級）；③ enforce 弱於該 namespace 應有的最低等級；④ 有 enforce 但沒 warn（Deployment 層違規會被靜默吞掉，第七節）。

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

const (
	enforceLabel = "pod-security.kubernetes.io/enforce"
	warnLabel    = "pod-security.kubernetes.io/warn"
)

// 等級強弱：privileged < baseline < restricted
var rank = map[string]int{"privileged": 0, "baseline": 1, "restricted": 2}

// 控制面 namespace 另有規則（可能刻意較寬或走 exemptions），不在此稽核（承 Day91 排除控制面）
var controlPlane = map[string]bool{
	"kube-system": true, "kube-node-lease": true, "kube-public": true,
}

type ns struct {
	Metadata struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
}
type nsList struct {
	Items []ns `json:"items"`
}

func main() {
	const minLevel = "baseline" // 業務 namespace 至少要 baseline

	out, err := exec.Command("kubectl", "get", "namespaces", "-o", "json").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kubectl 失敗：", err)
		os.Exit(2)
	}
	var list nsList
	if err := json.Unmarshal(out, &list); err != nil {
		fmt.Fprintln(os.Stderr, "JSON 解析失敗：", err)
		os.Exit(2)
	}

	fail := false
	for _, n := range list.Items {
		name := n.Metadata.Name
		if controlPlane[name] {
			continue
		}
		enforce, ok := n.Metadata.Labels[enforceLabel]

		// ① 沒有 enforce label → 吃 cluster 預設（多半 privileged）＝門開著
		if !ok || enforce == "" {
			fmt.Printf("FAIL %s：沒有 %s label（吃 cluster 預設，多半＝privileged 無防護）\n", name, enforceLabel)
			fail = true
			continue
		}
		// ② 明確降級成 privileged
		if enforce == "privileged" {
			fmt.Printf("FAIL %s：enforce=privileged（明確降級，等於關閉 PSA）\n", name)
			fail = true
			continue
		}
		// ③ enforce 弱於最低要求
		if rank[enforce] < rank[minLevel] {
			fmt.Printf("WARN %s：enforce=%s 弱於最低要求 %s（確認是否刻意例外）\n", name, enforce, minLevel)
		}
		// ④ 有 enforce 沒 warn → 工作負載層違規會被靜默吞掉（第七節）
		if _, hasWarn := n.Metadata.Labels[warnLabel]; !hasWarn {
			fmt.Printf("WARN %s：有 enforce 但沒有 warn label（Deployment 層違規不會在 apply 時提示，第七節）\n", name)
		}
	}

	if fail {
		os.Exit(1)
	}
	fmt.Println("OK：所有業務 namespace 都有 enforce label 且未降級為 privileged")
}
```

**Java 版**（Java 17+，Jackson，對稱邏輯，判紅同上；1.8 可把 `Map.of`/`Set.of`/`var`/text block 換成傳統寫法）：

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;
import java.util.Set;

public class PsaNamespaceAudit {
    static final ObjectMapper OM = new ObjectMapper();
    static final String ENFORCE = "pod-security.kubernetes.io/enforce";
    static final String WARN    = "pod-security.kubernetes.io/warn";
    static final Map<String, Integer> RANK = Map.of("privileged", 0, "baseline", 1, "restricted", 2);
    static final Set<String> CONTROL_PLANE = Set.of("kube-system", "kube-node-lease", "kube-public");

    public static void main(String[] args) throws Exception {
        final String minLevel = "baseline";

        Process p = new ProcessBuilder("kubectl", "get", "namespaces", "-o", "json").start();
        JsonNode root = OM.readTree(p.getInputStream());

        boolean fail = false;
        for (JsonNode n : root.path("items")) {
            String name = n.path("metadata").path("name").asText();
            if (CONTROL_PLANE.contains(name)) continue;

            JsonNode labels = n.path("metadata").path("labels");
            String enforce = labels.path(ENFORCE).asText("");

            if (enforce.isEmpty()) {                                   // ①
                System.out.printf("FAIL %s：沒有 %s label（吃 cluster 預設，多半＝privileged）%n", name, ENFORCE);
                fail = true;
                continue;
            }
            if ("privileged".equals(enforce)) {                        // ②
                System.out.printf("FAIL %s：enforce=privileged（明確降級，等於關閉 PSA）%n", name);
                fail = true;
                continue;
            }
            if (RANK.getOrDefault(enforce, 0) < RANK.get(minLevel)) {  // ③
                System.out.printf("WARN %s：enforce=%s 弱於最低要求 %s（確認是否刻意例外）%n", name, enforce, minLevel);
            }
            if (labels.path(WARN).asText("").isEmpty()) {              // ④
                System.out.printf("WARN %s：有 enforce 但沒有 warn label（Deployment 層違規不會在 apply 提示，第七節）%n", name);
            }
        }
        if (fail) System.exit(1);
        System.out.println("OK：所有業務 namespace 都有 enforce label 且未降級為 privileged");
    }
}
```

三個 CI 掃 namespace label **掃不到、要另外補**的角度：

- **`exemptions` 過寬——掃 namespace label 看不到**（第六節）：`exemptions` 在 apiserver 的 admission config 裡，`kubectl get namespaces` 撈不到。要盤它得看 control plane 設定／IaC（Terraform、kubeadm config、託管叢集的 API），把 `exemptions.usernames/runtimeClassNames/namespaces` 納入設定審查，不是掃 namespace 能決定的。
- **等級「夠不夠」——CI 只能抓「有沒有／降沒降」，抓不到「該不該是 restricted」**：一個 `enforce: baseline` 語法完全正常，但這個放金流服務的 namespace 該不該是 restricted，要靠人審，不是掃 label 能判。
- **既存違規 Pod 存量——要看 audit log／warn 輸出**（第七節）：namespace 貼了 restricted，但裡面既存有多少違規 Pod 還跑著，label 上看不出來，得看 audit annotation／relabel 時的警告。

**執行期承 Day16**：把 PSA 的 **audit annotation**（違規 Pod 事件）與 namespace label 變更打進 SIEM，對三件事告警——① **業務 namespace 的 `enforce` 被改成 `privileged` 或被移除**（有人在降級，P1，第五節信任邊界）；② **audit log 中某 namespace 違規 Pod 數突增**（可能有人往被降級或被 exempt 的 namespace 塞特權 Pod）；③ **`exemptions` 清單被異動**（第六節後門，通常伴隨 apiserver 設定變更）。**因為「有沒有人降級 namespace、有沒有人往豁免處塞違規、exemptions 有沒有被動」這幾件事，靜態掃 label 掃不到，只能靠執行期抓。**

---

## 九、常見誤區

| 誤區 | 為什麼錯 |
|---|---|
| 「裝了 Kubernetes 就有 PSA 保護」 | PSA 預設開，但沒貼 label 的 namespace 吃預設 `privileged`＝沒防護；要主動貼 label 或設 cluster default（第二節） |
| 「沒貼 label 是中性、沒差」 | 沒 `enforce` label＝吃 cluster 預設多半 privileged＝門開著，不是中性（第二、八節） |
| 「PSA 能取代 Gatekeeper／Kyverno」 | PSA 只有三固定等級、只管 Pod 安全欄位；禁 `:latest`／要 resource limits 等自訂規則得回 policy engine（第三、四節） |
| 「有 Gatekeeper 就不用 PSA」 | policy engine 靠 webhook，掛了/被繞就沒防（Day92）；PSA 內建當底盤縱深（第四節） |
| 「貼了 `enforce: restricted` 就穩了」 | 誰能改 namespace label 誰就能改回 privileged；label 寫入權是 PSA 信任邊界（第五節，承 Day07） |
| 「`exemptions` 只是給系統用的小設定」 | exempt 的 namespace/user/runtimeClass 完全跳過 PSA＝硬後門，且藏在 apiserver 設定裡難稽核（第六節，承 Day92） |
| 「`enforce` 會擋掉違規的 Deployment」 | enforce 只套用到 Pod，違規 Deployment 建得成功、Pod 靜默起不來，錯藏在 RS event（第七節） |
| 「只設 enforce、warn/audit 可省」 | warn/audit 才套用到工作負載資源；沒 warn＝Deployment 層違規不提示，開發者一頭霧水（第七節） |
| 「貼上 restricted，既存違規 Pod 就被清掉」 | admission 只擋新寫入；既存 Pod 繼續跑，只在 relabel 時回警告不驅逐（第七節，承 Day91/92） |
| 「`enforce-version` 不用設，用 latest 就好」 | latest 會讓叢集升級順便改變 restricted 定義，可能讓原本能起的 Pod 起不來；安全 ns 應釘版本（第二節） |
| 「restricted 有管 resource limits／image tag」 | restricted 只管安全性欄位（特權/逃逸/非 root）；limits、`:latest` 一概不管（第三節） |

---

## 十、Code Review / 維運 checklist

**PSA 有真的在防（第二、八節）**

- [ ] cluster 端 `PodSecurityConfiguration.defaults.enforce` 至少設到 `baseline`（把「沒貼 label」的預設從 `privileged` 拉起來，最高槓桿）。
- [ ] 業務 namespace 都有 `pod-security.kubernetes.io/enforce` label，且**不是** `privileged`；後端服務 namespace 以 `restricted` 為目標。
- [ ] `enforce` 搭 `warn`（至少同等級），讓 Deployment 層違規在 `kubectl apply` 時就露出來（第七節）。
- [ ] 安全關鍵 namespace 釘 `*-version` 明確版本，納入叢集升級變更流程（別放 `latest`）。

**信任邊界與豁免（第五、六節，承 Day07/49/Day92）**

- [ ] `namespaces` 的 `create`/`update`/`patch`（尤其改 `labels`）只給平台團隊；業務 RBAC role 不含。
- [ ] 用 policy engine（Day92）攔 namespace UPDATE，禁止把 `enforce` 改成 `privileged` 或刪除（PSA 守不了自己）。
- [ ] `PodSecurityConfiguration.exemptions`（usernames/runtimeClassNames/namespaces）只含控制面必要項，每筆有原因、審核、到期；納入 apiserver 設定審查（不是掃 namespace）。

**與 policy engine 併用（第四節）**

- [ ] PSA 當 Pod 安全底盤；自訂規則（禁 `:latest`/要 digest 承 Day18、要 resource limits、命名/label 規範）交給 Gatekeeper／Kyverno（Day92）。
- [ ] 需要特權的工作負載（CNI/監控/儲存 driver）隔離到單獨 namespace，該 namespace 的較寬等級與 exemptions 有明確理由。

**稽核（第八節，承 Day16）**

- [ ] CI 掃「namespace 沒 enforce label（判紅）、enforce=privileged（判紅）、enforce 弱於最低要求、有 enforce 沒 warn」。
- [ ] 執行期把 PSA audit annotation、namespace label 變更、exemptions 異動進 SIEM 並告警。

---

## 十一、測試 / 演練建議

- **restricted 擋得住演練（第三節）**：往 `enforce: restricted` 的 namespace 送第三節那個 privileged/hostPath/hostNetwork Pod，斷言**被拒**且錯誤列出所有違規欄位；送合規版斷言**通過**。
- **Deployment 靜默吞違規演練（第七節，最容易誤判的一個）**：在 `enforce: restricted`（**故意不設 warn**）的 namespace `apply` 一個違規 Deployment，斷言 **Deployment 建立成功但 `READY 0/N`、Pod 起不來、錯在 RS event**；再補上 `warn: restricted` 重來，斷言 **apply 當場回警告**——證明 warn 的價值。
- **降級信任邊界演練（第五節）**：用一個只有業務 RBAC 的身分，嘗試把 namespace `enforce` 改成 `privileged`，斷言**被 RBAC 或你的 policy engine 政策擋下**；若成功改掉＝namespace 寫入權沒收好。
- **既存 Pod 不被驅逐演練（第七節）**：先在 privileged namespace 跑一個違規 Pod，再把 namespace relabel 成 `enforce: restricted`，斷言**既存 Pod 續跑、只收到警告**；接著手動重建該 Pod，斷言**這次被擋**（證明「既存放行、重建才擋」的邊界）。
- **exemptions 後門演練（第六節）**：把某 namespace 加進 `exemptions.namespaces`，往它送違規 Pod，斷言**即使貼了 restricted label 也照樣放行**（確認 exempt 的範圍就是你以為的那麼大），並確認這筆豁免有審核與到期。
- **cluster default 演練（第二、八節）**：建一個**完全不貼 label** 的 namespace，送違規 Pod，斷言結果符合你的 `defaults.enforce`（若你沒設 default、預設 privileged，會**放行**——用這個證明「沒 label＝門開著」的盲區真實存在）。
- **version pinning 演練（第二節）**：把 `enforce-version` 釘在舊版，模擬叢集升級，斷言原本能起的 Pod **行為不變**；改成 `latest` 再測，觀察是否有欄位在新版被多擋（證明釘版本對升級穩定性的價值）。

---

## 十二、一句話總結

> Day91 收 **webhook 管線**、Day92 收 **跑在管線上的 Gatekeeper／Kyverno 政策**（都是「外掛」路線：要裝 engine、要管 webhook 可用性、政策要自己寫對）；Day93 收 Kubernetes **內建、免裝、預設開**的那條路——**Pod Security Admission（PSA）**，靠 namespace label 驅動、只做「Pod 安全基線」。三個維度：**三等級**＝`privileged`（不設限）／`baseline`（擋 privileged、host namespace、hostPath 等明顯逃逸）／`restricted`（再加 runAsNonRoot、drop ALL caps、seccomp RuntimeDefault、allowPrivilegeEscalation:false）；**三模式**（獨立可疊加）＝`enforce`（違規直接拒，**但只套用到 Pod 不套用到 Deployment**）／`audit`（放行記 audit log）／`warn`（放行回使用者警告，**warn/audit 會套用到工作負載資源**）；靠 **namespace label**（`pod-security.kubernetes.io/enforce` 等＋`*-version` 釘版本）開，沒貼 label ＝吃 cluster 預設多半 `privileged`＝**門開著**。**built-in vs policy engine 不是二選一是併用**：PSA 免裝、無 webhook 可維運、不會因 webhook 掛掉失效，適合當**安全底盤**（把 cluster default `enforce` 拉到至少 baseline）；但它只有三固定等級、只管 Pod-level、**不能寫自訂規則**——禁 `:latest`／要 digest（承 Day18）、要 resource limits、命名規範這些得回 Day92 的 Gatekeeper／Kyverno。PSA 三個盲點：**① namespace label＝安全等級**——誰有 `namespaces` 的 label 寫入權誰就能把 `restricted` 改回 `privileged` 或刪掉（承 Day07 RBAC 信任邊界），PSA 守不了自己，得用 policy engine 攔 namespace UPDATE 反過來守它；**② `exemptions`（usernames/runtimeClassNames/namespaces）是後門**——被 exempt 的完全跳過 PSA、連 label 都不看（承 Day92 第四節），且藏在 apiserver admission config 裡 `kubectl` 稽核不到；**③ enforce 只套用到 Pod、只擋新寫入**——違規 Deployment 建得成功但 Pod 靜默起不來（錯藏在 RS event，所以 enforce 一定要搭 warn 讓工作負載層違規露出來），既存違規 Pod relabel 時只回警告不驅逐（承 Day91/92，先 warn/audit 盤乾淨再切 enforce）。稽核（承 Day16）把「namespace 沒 enforce label／被降級成 privileged／有 enforce 沒 warn」寫成 CI（Go/Java 掃 `kubectl get namespaces` 的 label），`exemptions` 過寬要另盤 apiserver 設定，執行期對「namespace 被降級、audit 違規突增、exemptions 被動」告警。一句話：**PSA 是內建的安全氣囊——免裝、擋得住最基本的 Pod 逃逸、又不會因為你的 webhook 掛掉而失效，所以拿來當底盤最划算；但它只有固定等級、守不了自己的 label、也管不到既存與 Deployment 層——安全底盤要 PSA，自訂規則要 policy engine，兩層一起才是縱深。**

---

## 延伸閱讀

- Day92 Gatekeeper／Kyverno 政策盲點與繞過——本篇上游：Day92 收「外掛 policy engine 的政策內容」怎麼被寫成 dryrun、被 exempt 掏空、被 UPDATE/subresource 繞過；今天收「內建 PSA」怎麼用、什麼時候夠、什麼時候要搭 policy engine，兩者併用而非二選一。
- Day91 admission webhook 信任邊界與 `failurePolicy`——PSA 是 apiserver 內建 plugin，沒有 Day91 那支 webhook，因此沒有 caBundle 憑證輪替、可用性單點、`failurePolicy` 兩難；這正是把 PSA 當「不會因 webhook 掛掉而失效的底盤」的價值。
- Day07 Broken Access Control / default deny——PSA 的 namespace label 寫入權（誰能 `update`/`create` namespace）就是它的信任邊界；把 cluster default `enforce` 拉到 baseline＝default deny 在 Pod 安全的落點。
- Day49 BFLA——`exemptions.usernames` 按身分豁免 PSA，與功能層級授權沒收好同源：豁免清單本身就是存取控制決策。
- Day18 供應鏈 / 弱點依賴——「禁 `:latest`／要求 image 帶 digest」PSA 一概不管，得回 Gatekeeper／Kyverno；這說明 PSA（安全底盤）與 policy engine（自訂規則）各管一段。
- Day16 Security Logging / Monitoring——把 PSA audit annotation、namespace label 變更、exemptions 異動進 SIEM，對「namespace 被降級、違規突增」告警（靜態掃 label 掃不到執行期的降級與繞過）。

---

明天預告：**Day 94 — 內建、免 webhook、可寫自訂規則的第三條路：ValidatingAdmissionPolicy（VAP）＋ CEL**
（這是**接續 admission 系列的新主題**，不重講 Day91 的 webhook 機制、不重講 Day92 的 Gatekeeper/Kyverno 政策寫法、也不重講 Day93 的 PSA 三等級。把這幾天的 admission 光譜補齊：**Day91–92 是「外掛 engine（webhook）＋可自訂規則」，Day93 是「內建（PSA）但只有固定等級、不能自訂」，Day94 收第三個象限——「內建 ＋ 可寫自訂規則 ＋ 免 webhook」＝ValidatingAdmissionPolicy（VAP，用 CEL 運算式表達規則，apiserver in-process 執行，v1.30 GA）。** 角度三條：**① VAP 怎麼寫**——`ValidatingAdmissionPolicy`（定義 CEL `validations`）＋ `ValidatingAdmissionPolicyBinding`（綁 `matchResources` 與 `paramRef`），會用 Day92 同一條「禁 `:latest`／要 resource limits」規則，但改用**內建 CEL** 表達（`object.spec.containers.all(c, !c.image.endsWith(":latest"))`），示範它跟 Gatekeeper Rego／Kyverno pattern 的取捨；**② 為什麼是「第三條路」**——免 webhook 就整包甩掉 Day91 的 caBundle 憑證、可用性單點、啟動死結，延遲也更低（in-process），但 **CEL 表達力有天花板**（不能呼叫外部服務、不能查叢集裡其他資源、複雜跨資源/外部授權還是得回 webhook/Gatekeeper 或 Day90 的 ext_authz）；**③ VAP 自己的盲點**——`validationActions`（`Deny`/`Warn`/`Audit`）根本就是 Day92 `dryrun`/`Audit` 與 Day93 `enforce`/`warn`/`audit` 的又一次翻版（留在 `Warn`/`Audit` 等於沒擋）、`failurePolicy` 仍在（CEL 編譯或執行出錯時 fail-open/closed，承 Day91）、`matchConditions`/`paramRef` 選擇器寫太寬或太窄、以及 CEL 運算式邏輯寫錯讓它永遠通過（承 Day92「政策邏輯靜態掃不到、要單元測試」）。程式面會示範 VAP＋Binding 的 YAML、幾條後端可落地的 CEL 運算式、以及一支掃「VAP 的 `validationActions` 只有 `Warn`/`Audit` 沒 `Deny`」的稽核（Go/Java，承 Day92/93 同一套 Day16 心法）。安全主軸一句話：**Day93 收「內建但固定」的 PSA，Day94 收「內建但可自訂、還免 webhook」的 VAP——把 admission 的三條路（自寫 webhook／外掛 engine／內建 CEL）擺齊，講清楚各自的表達力、可用性成本與那個一再重演的「留在 Audit 等於沒擋」陷阱。** 這是接續 admission 系列的新主題，聚焦內建 ValidatingAdmissionPolicy 與 CEL，不重述 webhook 機制、Gatekeeper/Kyverno 政策寫法與 PSA 等級。）
