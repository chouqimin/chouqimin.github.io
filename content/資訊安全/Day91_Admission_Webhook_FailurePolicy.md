---
title: "Day 91：Kubernetes admission webhook 的信任邊界與可用性——mutating/validating webhook 自身加固、failurePolicy fail-open vs fail-closed、以及 webhook 成為叢集單點（延伸篇）"
date: 2026-08-01
tags: ["Kubernetes", "admission-webhook", "failurePolicy", "control-plane"]
---

接續 Day90 預告：Day90 收的是**資料面**的 fail 行為——Envoy 對每個請求先問一個外部授權服務（`ext_authz`），一旦你把 `failure_mode_allow` 設成 open，授權服務一掛就全部放行。今天把**同一個「故障時該開還是該關」的問題，翻到 Kubernetes 控制面的 admission webhook**：`ValidatingWebhookConfiguration`／`MutatingWebhookConfiguration` 的 `failurePolicy: Fail`（fail-closed，webhook 掛了就擋下所有被攔到的 API 寫入）vs `Ignore`（fail-open，webhook 掛了就放行未經檢查的資源）。

**這篇是延伸篇，不重講 Day07 的存取控制入門、也不重講 Day87 的 sidecar injector「是什麼」，更不重講 Day90 的 `ext_authz` 資料面授權。** 什麼是 default deny、injector 怎麼把 Envoy 注進 pod、`ext_authz` 契約怎麼接——前面都講過，今天不重述。這篇只聚焦一件事：**當你把「某個資源能不能進叢集」的決策，外接給一個 webhook 時，那個 webhook 就變成控制面上的一個高權限、爆炸半徑極大、且會影響全叢集寫入可用性的元件——它的信任邊界怎麼收、fail 行為怎麼取捨、可用性怎麼撐。**

延伸角度只有一條主軸：**Day90 讓 Envoy 能問「這一次請求你到底能不能過」（資料面，每個請求）；Day91 讓 API server 能問「這一個資源你到底能不能進叢集」（控制面，每次 API 寫入）——但你外接出去的那個 webhook，它的權限、憑證、可用性與 fail 行為，就是控制面的新信任邊界與新單點。** 這篇用三段收好：**① 爆炸半徑**——為什麼 admission webhook 是比 Day87 injector 更集中、更危險的高權限元件；**② fail 行為**——`failurePolicy` 的 `Fail`（fail-closed）vs `Ignore`（fail-open），正是 Day90 那題在 admission 的翻版；**③ 兩者兼顧**——用 `namespaceSelector`／`objectSelector` 縮攔截範圍、webhook 服務 HA、`timeoutSeconds` 與 `reinvocationPolicy` 的設定，把「安全（fail-closed）」與「叢集寫入可用性」同時撐住。

> ⚠️ 以下 `admissionregistration.k8s.io/v1` 的 `ValidatingWebhookConfiguration`／`MutatingWebhookConfiguration` 欄位（`failurePolicy`、`sideEffects`、`admissionReviewVersions`、`matchPolicy`、`namespaceSelector`／`objectSelector`、`timeoutSeconds`、`reinvocationPolicy`、`matchConditions`）與 `admission.k8s.io/v1` 的 `AdmissionReview`，都會隨你的 Kubernetes 版本、CNI、以及所用的 policy engine（OPA Gatekeeper／Kyverno）版本不同。實際請對照你那套的官方文件，別照抄字串。這裡示範的是**「admission webhook 的信任邊界在哪、fail 行為怎麼取捨、可用性怎麼補」**的意圖，不是某一版的精確語法。

---

## 一、先定位：admission webhook 在控制面的哪個位置

Day90 攔的是**資料面**的請求：業務流量進 Envoy，轉發前先問授權服務。今天攔的是**控制面**的請求：有人 `kubectl apply` 一個 Deployment、CI 建一個 Pod、controller 改一個資源——這些都是打到 **kube-apiserver** 的 API 寫入，在寫進 etcd 之前，會經過一條 admission 鏈：

```text
[控制面 API 寫入路徑]
  kubectl/CI/controller
        │  (建立/更新資源)
        ▼
   kube-apiserver
        │ ① Authentication（你是誰）
        │ ② Authorization（RBAC，你能不能寫，承 Day07）
        │ ③ Mutating admission ─▶ MutatingWebhookConfiguration ─▶ 你的 webhook（可「改寫」資源）
        │ ④ Object schema validation
        │ ⑤ Validating admission ─▶ ValidatingWebhookConfiguration ─▶ 你的 webhook（只能「准/拒」）
        ▼
      etcd（持久化）

  webhook 掛了怎麼辦？  failurePolicy: Ignore（放行未檢查資源） vs Fail（擋下所有被攔到的寫入）
```

兩種 webhook，權限天差地別：

- **`MutatingWebhookConfiguration`（改寫）**：在資源寫進 etcd 前**修改它**。Day87 的 sidecar injector 就是這種——它把 Envoy 容器與 SPIFFE CSI volume 改寫進 pod spec。OPA Gatekeeper／Kyverno 的 mutation 政策也是這種。
- **`ValidatingWebhookConfiguration`（准/拒）**：只能對資源說 **allow／deny**，不能改。policy 檢查（「不准用 privileged 容器」「image 必須帶 digest」）最常是這種。

一句話定位：**Day90 的 `ext_authz` 決定「這一次業務請求過不過」；admission webhook 決定「這一個資源進不進得了叢集」。** 前者每個業務請求問一次、在 Envoy；後者每次 API 寫入問一次、在 apiserver。**但兩者共享同一個致命問題：你把決策外接給一個服務，那個服務的可用性與 fail 行為，就變成新的攻擊面與單點。** Day90 收資料面那題，Day91 收控制面這題。

> 一個 Day92 才展開、但這裡要先標記的邊界：**admission webhook 只在「資源被寫入的當下」（CREATE／UPDATE／DELETE／CONNECT）觸發，管不到「已經在叢集裡的既存資源」。** 也就是：你今天上線一條「禁止 privileged」的 policy，它擋得住之後的新 Pod，但擋不了昨天就已經跑著的 privileged Pod——那要靠 Gatekeeper 的 audit／Kyverno 的 background scan 去掃既存資源。**admission 是「入口的門」，不是「屋裡的巡邏」。** 這條界線與政策本身的盲點，留 Day92。

---

## 二、爆炸半徑：admission webhook 是控制面上最該提防的高權限元件

Day87 講過 injector 這種 mutating webhook「能改寫全叢集任何被攔到的 pod、爆炸半徑比 hostPath 更大」。今天把這句話擴成一整節，因為它是理解後面所有加固的前提：**admission webhook 站在每一次 API 寫入的必經之路上，能力大、信任高、又是單點。**

**① 能力面：mutating webhook 幾乎能對被攔到的資源做任何事。** 它拿到完整的資源物件、回一個 JSONPatch，apiserver 就照著改。這代表一個被攻陷（或寫壞）的 mutating webhook 可以：把**惡意 sidecar／init container** 塞進每個 Pod（承 Day87 的注入能力，只是反過來被利用）、把 image 換成攻擊者的（承 Day18 供應鏈）、加一個把 secret 外送的 env、拿掉別人剛設好的 `securityContext`。**validating webhook 雖然只能准/拒，但「能拒」本身就是能力**——一個惡意 validating webhook 可以拒掉所有部署、或選擇性放行後門資源。

**② 信任面：誰能建立／修改 `*WebhookConfiguration`，誰就能攔截全叢集。** 這兩種 config 是 **cluster-scoped** 的高權限物件。能對它們 `create`／`update` 的人，等於能在全叢集的 API 寫入路徑上插一隻手——這是 Day07 存取控制在控制面的最高等級落點之一。**這個 RBAC 權限必須收給平台團隊，絕不能隨便給 namespace 級的操作者。**

**③ 憑證面：`caBundle` 是 apiserver 信任這個 webhook 的唯一根據。** webhook 走 HTTPS，apiserver 用 config 裡的 `caBundle` 驗 webhook 的伺服器憑證（承 Day19／75）。這帶出兩個風險：**憑證外洩／`caBundle` 被替換＝有人能假冒 webhook**（攔截或竄改 apiserver 送去的 `AdmissionReview`）；**伺服器憑證過期沒輪替＝webhook 呼叫全失敗**，接著 `failurePolicy` 就會決定叢集是「全擋」還是「全放」（第四節）——所以憑證輪替（承 Day79 cert-manager／ACME 的思路）在這裡同時是可用性與安全問題。

**④ 端點面：in-cluster service vs 外部 url。** `clientConfig` 可以指向叢集內的 `service`，也可以指向外部 `url`。**外部 `url` 意味著控制面的 admission 決策依賴一個叢集外的端點**——它的可用性、網路可達性、TLS 信任都變成新的外部依賴（也更容易被 Day10 那類 SSRF／中間人角度盯上）。能用 in-cluster `service` 就別用外部 `url`。

一句話：**admission webhook 不是「一個小工具」，是控制面上一個能改寫／攔截全叢集資源、被高度信任、又坐在每次寫入必經之路上的元件。** 它的三個要收的邊界——**誰能改它的 config（RBAC）、它攔誰（scope）、apiserver 憑什麼信它（憑證／端點）**——就是第三節。

---

## 三、信任邊界加固：RBAC、`namespaceSelector` 排除自身與 kube-system、憑證、端點

把第二節的四個面收成可落地的設定。

**① RBAC——收 `*WebhookConfiguration` 的寫入權。** `create`／`update`／`patch`／`delete` `validatingwebhookconfigurations` 與 `mutatingwebhookconfigurations` 的權限，只給平台團隊的少數角色。這是「改模板＝改每個資源怎麼被處理」的最高權限（承 Day07／Day87 對 injector ConfigMap 寫入權的同一心法）。

**② `namespaceSelector`／`objectSelector`——精準攔截，別攔到自己與控制面。** 這是 admission webhook 最重要、也最常設錯的一項，理由有兩個，一個是**安全與爆炸半徑**，一個是**避免死結（self-deadlock）**：

- **別攔 `kube-system` 與其他控制面 namespace**：如果你的 webhook 用 `failurePolicy: Fail` 又攔到 `kube-system`，一旦 webhook 自己不可用，連控制面元件的資源都寫不進去，叢集可能整個卡死。
- **別攔 webhook 自己所在的 namespace**：這是經典的**啟動死結**——webhook 的 Pod 要被（重新）排程時，apiserver 得先呼叫 webhook 才能建立那個 Pod，但 webhook 正是還沒起來的那個，於是永遠起不來。**用 `namespaceSelector` 把 webhook 自身 namespace 與控制面 namespace 排除掉，是 fail-closed 能安全落地的前提。**

Kubernetes 1.21+ 會自動在每個 namespace 標上 `kubernetes.io/metadata.name` label，正好拿來做排除。加固版 `ValidatingWebhookConfiguration`：

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: pod-policy.example.com
webhooks:
  - name: pod-policy.example.com          # 必須是 FQDN
    admissionReviewVersions: ["v1"]        # v1 必填，明確版本
    sideEffects: None                      # 無外部副作用 → dry-run 安全（見下方說明）
    failurePolicy: Fail                    # 預設 fail-closed（第四節）；v1 的預設本來就是 Fail
    matchPolicy: Equivalent                # 等價比對，避免 apiVersion 變體繞過
    timeoutSeconds: 5                       # 短逾時（第五節，承 Day72）
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name # 1.21+ 自動標在每個 namespace 上
          operator: NotIn
          values: ["kube-system", "kube-node-lease", "webhook-system"]  # 排除控制面 + webhook 自身 namespace
    objectSelector:
      matchLabels:
        policy.example.com/enforce: "true" # 只攔明確標記要納管的資源 → 縮小爆炸半徑
    rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]                # 精準列舉，不要 "*"（第七節稽核會抓 "*"）
        scope: Namespaced
    clientConfig:
      service:                             # in-cluster service，優於外部 url
        namespace: webhook-system
        name: pod-policy-webhook
        path: /validate
        port: 443
      caBundle: <base64-CA>                # apiserver 用它驗 webhook 憑證（承 Day79 輪替）
```

`MutatingWebhookConfiguration` 幾乎一樣，但多一個 `reinvocationPolicy`（第五節）。

**③ `sideEffects: None`——讓 dry-run 與重試安全。** `sideEffects` 宣告你的 webhook 會不會對「叢集狀態以外」造成副作用（例如去改一個外部系統）。設 `None` 表示沒有副作用，apiserver 在 dry-run 時才敢照常呼叫、失敗時才敢安全重試。**webhook 本身應該是純粹的決策／改寫，不要在 admission 過程去寫外部系統**（那既是副作用問題，也是把外部系統拉進關鍵路徑的可用性問題）。

**④ 憑證與端點——用 in-cluster `service` + 自動輪替的憑證。** `caBundle` 與 webhook 伺服器憑證要能自動輪替（cert-manager 之類，承 Day79），避免過期造成全面呼叫失敗；能用 `service` 就別用外部 `url`（第二節④）。

一句話：**加固 admission webhook＝收「誰能改它」（RBAC）、收「它攔誰」（`namespaceSelector`／`objectSelector` 精準且排除自身與控制面）、收「apiserver 憑什麼信它」（in-cluster service＋可輪替憑證）。** 這三收好，第四節的 fail-closed 才敢開。

---

## 四、`failurePolicy`：fail-open（Ignore）vs fail-closed（Fail）——Day90 同一題的控制面翻版

這是整篇的核心，也是 Day90 那題原封不動搬到控制面。你把「資源能不能進叢集」外接給 webhook，就多了一個問題：**當 webhook 逾時／連不上／憑證錯／回錯時，apiserver 該怎麼辦？**

- **fail-open（`failurePolicy: Ignore`）**：webhook 不可用時**放行未經檢查的資源**。後果是——**webhook 一掛，所有本來要被它檢查／改寫的資源，就這樣沒被檢查地進了叢集**。對 policy webhook（Gatekeeper／Kyverno）而言，這等於「政策在 webhook 故障那段時間全部失效」；對 injector 這種 mutating webhook 而言，這等於「該注入的 sidecar 沒注入就跑起來了」。而且——**攻擊者可以主動去打垮／拖慢 webhook 來「開門」**，把可用性問題變成 policy 繞過（跟 Day90 打垮授權服務觸發 fail-open 完全同構，慢也算，承 Day72）。
- **fail-closed（`failurePolicy: Fail`，`v1` 的預設）**：webhook 不可用時**擋下所有被它攔到的 API 寫入**。安全，但代價是——**webhook 變成「所有被攔到的資源都得先過它」的可用性單點**：它掛了，被它攔的那些資源（可能是全叢集的 Pod／Deployment）就全部寫不進去，部署凍結。

**預設就該 fail-closed（`Fail`）。** admission 是安全控制，不是效能優化；「拿不到決策」時保守地擋，才符合 default deny（承 Day07）。`Ignore` 只在極少數、有明確理由、且範圍極窄（例如某條非安全關鍵的 webhook）時才考慮，而且要有告警（第七節）。

但 fail-closed 讓 webhook 成為叢集寫入的可用性單點，這正是很多團隊「乾脆設 Ignore」的原因——**而那是把安全丟掉換可用性，方向反了。** 正確做法是**用第三節的縮範圍＋第五節的架構，把可用性補回來，而不是用 fail-open 把 admission 整個關掉。**

一個常被搞混、要跟 Day90 一起記牢的點：**`failurePolicy` 只影響「webhook 呼叫失敗（逾時／連不上／憑證錯）」這種基礎設施故障，不影響「webhook 明確回 deny」。** 明確的 deny 永遠是 deny。`failurePolicy` 開的是「故障時的預設」，不是「把 deny 當 allow」——跟 Day90 的 `failure_mode_allow` 一模一樣。

> 真實維運的血淚點：一個 `failurePolicy: Fail` 又 `rules` 開太廣（`resources: ["*"]`）的 webhook，只要自己掛掉或變慢，就能讓整個叢集無法建立任何資源——這類「webhook 拖垮叢集」的事故非常常見。**這不是叫你改回 `Ignore`，而是叫你把範圍縮窄（第三節）、把可用性撐住（第五節），讓 fail-closed 不會變成全叢集事故。**

---

## 五、兩者兼顧：縮攔截範圍＋HA＋`timeoutSeconds`＋`reinvocationPolicy`

fail-closed 是對的，單點問題用架構解。四個旋鈕：

**① 縮攔截範圍（`namespaceSelector`／`objectSelector`／`rules`）——一石二鳥。** 這是最有效的一招：webhook 只攔它非攔不可的資源，其餘一律不進 webhook。這**同時**降低了爆炸半徑（第二節）**和**可用性依賴——因為 webhook 掛掉時，fail-closed 只會擋住「本來就被它攔的那一小撮資源」，而不是全叢集的寫入。`objectSelector` 用 label 精準納管、`rules` 精準列舉 resource／operation，別用 `*`。

**② webhook 服務 HA。** 既然決定 fail-closed，就別讓單一 replica 決定全叢集寫入的生死：webhook 服務**多副本**、配 **PodDisruptionBudget**、**跨 node／跨可用區**散佈，避免一次滾動更新或一個 node 掛掉就讓 webhook 整個不可用。（注意上一節的死結：HA 的前提是 webhook 自身 namespace 已被 `namespaceSelector` 排除，否則副本重排時又卡住。）

**③ `timeoutSeconds`——短，但別太短（預設 10，範圍 1–30）。** webhook 在每一次被攔到的 API 寫入的關鍵路徑上：**設太長**→webhook 一慢，每個相關 API 寫入的延遲都被它拖住，`kubectl apply` 卡住、controller reconcile 變慢（承 Day72，慢也是一種 DoS）；**設太短**→高負載或冷啟動時正常請求被誤判逾時，fail-closed 就變成大量誤擋。要**依 webhook 實際延遲壓測定出 timeout**，不是拍腦袋，通常抓在幾秒內。

**④ `reinvocationPolicy`（僅 mutating）——多個 mutating webhook 互相改寫時的正確性。** mutating webhook 是**依序**呼叫的，如果 webhook A 先改了資源、之後 webhook B 又改了同一塊，A 可能需要「再看一次、再改一次」。`reinvocationPolicy: IfNeeded` 就是允許在後續 webhook 有改動時**重新呼叫**先前的 mutating webhook（預設 `Never` 不重呼叫）。代價是**同一個 webhook 可能被呼叫多次**，所以你的 mutation 邏輯**必須冪等**（重複套用結果不變，承 Day22 idempotency 的思路）——否則會出現「sidecar 被注入兩次」這種 bug。

> 更新的旋鈕（版本夠新才有）：`matchConditions` 讓你用 CEL 運算式在 apiserver 端就做更細的「要不要送去 webhook」判斷（例如只在某些欄位符合條件時才觸發），比 `namespaceSelector`／`objectSelector` 更精準地縮小關鍵路徑上的呼叫量。可用的話能進一步同時降低爆炸半徑與可用性依賴，但要確認你的叢集版本支援。

一句話：**跟 Day90 同構——預設 fail-closed，再用「縮範圍＋HA＋壓測定出的 timeout＋（mutating 的）冪等 reinvocation」把可用性補回來，而不是用 fail-open 把 admission 偷偷關掉。**

---

## 六、admission review handler：Go 與 Java（最小可用）

webhook 的介面很單純：**apiserver POST 一個 `AdmissionReview`（裡面有 `request`）過來，你回一個帶 `response` 的 `AdmissionReview`，`response.allowed` 決定准/拒。** 下面兩支都做同一件事——**拒絕 privileged 容器**（validating）。

### Go：validating webhook handler

```go
package main

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// validate：真正的檢查邏輯在你手上，這裡示意「不准 privileged 容器」
func validate(pod *corev1.Pod) (bool, string) {
	for _, c := range pod.Spec.Containers {
		if sc := c.SecurityContext; sc != nil && sc.Privileged != nil && *sc.Privileged {
			return false, "不允許 privileged 容器：" + c.Name
		}
	}
	return true, ""
}

func handle(w http.ResponseWriter, r *http.Request) {
	var review admissionv1.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil || review.Request == nil {
		http.Error(w, "bad AdmissionReview", http.StatusBadRequest) // 解不出來就別預設放行
		return
	}
	req := review.Request

	// 一定要回填 request 的 UID，apiserver 靠它把回應對上請求
	resp := &admissionv1.AdmissionResponse{UID: req.UID}

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		resp.Allowed = false
		resp.Result = &metav1.Status{Message: "無法解析 Pod：" + err.Error()}
	} else if ok, msg := validate(&pod); ok {
		resp.Allowed = true
	} else {
		resp.Allowed = false
		resp.Result = &metav1.Status{Message: msg} // deny 一定帶清楚原因，否則使用者看不懂為何被擋
	}

	out := admissionv1.AdmissionReview{TypeMeta: review.TypeMeta, Response: resp} // 回填 apiVersion/kind
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func main() {
	srv := &http.Server{
		Addr:      ":8443",
		Handler:   http.HandlerFunc(handle),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}, // apiserver 只走 HTTPS（承 Day19）
	}
	// 伺服器憑證要跟 webhook config 的 caBundle 對得上，且會過期要輪替（承 Day79）
	log.Fatal(srv.ListenAndServeTLS("/certs/tls.crt", "/certs/tls.key"))
}
```

> **mutating 版**：邏輯一樣，但不是回 `Allowed` 而是回一個 **JSONPatch**——`resp.Patch = <JSON patch bytes>`、`resp.PatchType = &pt`（`pt := admissionv1.PatchTypeJSONPatch`）。改寫要**冪等**（承第五節 `reinvocationPolicy`：可能被呼叫多次，例如注入前先檢查「是否已注入」再決定加不加）。injector（承 Day87）就是這種：檢查 pod 有沒有 Envoy 容器，沒有才 patch 進去。

### Java：Spring 收 AdmissionReview（Jackson）

```java
// Spring Boot 3（Java 17/21）。apiserver POST AdmissionReview JSON 過來，回一個帶 response 的 AdmissionReview。
@RestController
public class AdmissionController {

    private static final ObjectMapper OM = new ObjectMapper();

    @PostMapping(value = "/validate", consumes = "application/json", produces = "application/json")
    public ObjectNode validate(@RequestBody JsonNode review) {
        JsonNode req = review.path("request");
        String uid = req.path("uid").asText();          // 一定要回填 UID

        boolean allowed = true;
        String message = "";
        for (JsonNode c : req.path("object").path("spec").path("containers")) {
            if (c.path("securityContext").path("privileged").asBoolean(false)) {
                allowed = false;
                message = "不允許 privileged 容器：" + c.path("name").asText();
                break;
            }
        }

        ObjectNode resp = OM.createObjectNode();
        resp.put("uid", uid);                            // echo UID
        resp.put("allowed", allowed);
        if (!allowed) {
            resp.putObject("status").put("message", message); // deny 帶原因
        }

        ObjectNode out = OM.createObjectNode();
        out.put("apiVersion", "admission.k8s.io/v1");
        out.put("kind", "AdmissionReview");
        out.set("response", resp);
        return out;                                      // Spring 會以 HTTPS 回傳（伺服器憑證同上）
    }
}
```

> **版本註記**：Spring Boot 3 需要 Java 17+；**Java 1.8** 請用 Spring Boot 2（`@RestController`／`@PostMapping` 寫法相同）。無論哪版，webhook 都要：**回填 `uid`、以 HTTPS 服務且憑證對得上 `caBundle`、`deny` 帶清楚訊息、mutating 改寫必須冪等**。

**這兩支的重點不是程式多複雜，而是把「一個資源能不能進叢集」的判斷，做成一個必經、集中、可測試的決策點。** 但也正因為必經，它掛了就會依 `failurePolicy` 影響全叢集寫入——所以第三、四、五節的邊界與可用性，跟這段程式同等重要，甚至更重要。

---

## 七、Day16 稽核：掃 `failurePolicy: Ignore`／沒排除自身 namespace／`timeoutSeconds` 過長／`rules` 過廣

`*WebhookConfiguration` 幾個最危險的狀態都能靜態掃出來，寫成 CI／自身也可以是一條 admission policy，就是 Day16「把偵測升級成預防」在控制面的落點（承 Day87／88／90 第六節同一套心法：先在 chat／CI 跑一次看資料長相，再寫解析）。

先看資料長相（這兩種都是 cluster-scoped，不用 `-A`；用逗號一次撈成一個 List）：

```bash
kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations -o json
```

**Go 版**：掃每個 webhook，抓四件事——① `failurePolicy: Ignore`（fail-open，第四節）；② `namespaceSelector` **沒排除 `kube-system` 與 webhook 自身 namespace**（死結／攔控制面風險，第三節）；③ `timeoutSeconds` 過長（拖垮關鍵路徑，第五節，承 Day72）；④ `rules` 用 `*`（爆炸半徑過大，第二節）／用外部 `url`／`sideEffects` 非 `None`。

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type nsSelector struct {
	MatchExpressions []struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values"`
	} `json:"matchExpressions"`
}

type webhook struct {
	Name              string     `json:"name"`
	FailurePolicy     string     `json:"failurePolicy"`  // 預設 Fail（v1）
	TimeoutSeconds    *int       `json:"timeoutSeconds"` // 預設 10
	SideEffects       string     `json:"sideEffects"`
	NamespaceSelector nsSelector `json:"namespaceSelector"`
	ClientConfig      struct {
		URL     *string `json:"url"`
		Service *struct {
			Namespace string `json:"namespace"`
		} `json:"service"`
	} `json:"clientConfig"`
	Rules []struct {
		APIGroups  []string `json:"apiGroups"`
		Resources  []string `json:"resources"`
		Operations []string `json:"operations"`
	} `json:"rules"`
}

type whList struct {
	Items []struct {
		Metadata struct{ Name string } `json:"metadata"`
		Webhooks []webhook             `json:"webhooks"`
	} `json:"items"`
}

// namespaceSelector 是否用 NotIn(kubernetes.io/metadata.name) 排除了指定 namespace
func (ns nsSelector) excludes(target string) bool {
	for _, e := range ns.MatchExpressions {
		if e.Key == "kubernetes.io/metadata.name" && e.Operator == "NotIn" {
			for _, v := range e.Values {
				if v == target {
					return true
				}
			}
		}
	}
	return false
}

func has(list []string, x string) bool {
	for _, v := range list {
		if v == x {
			return true
		}
	}
	return false
}

func main() {
	out, err := exec.Command("kubectl", "get",
		"validatingwebhookconfigurations,mutatingwebhookconfigurations", "-o", "json").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kubectl 失敗：", err)
		os.Exit(2)
	}
	var whs whList
	if err := json.Unmarshal(out, &whs); err != nil {
		fmt.Fprintln(os.Stderr, "JSON 解析失敗：", err)
		os.Exit(2)
	}

	fail := false
	for _, cfg := range whs.Items {
		for _, wh := range cfg.Webhooks {
			id := cfg.Metadata.Name + "/" + wh.Name

			// ② 沒排除 kube-system + webhook 自身 namespace（fail-closed 下的死結／攔控制面風險）→ 判紅
			if !wh.NamespaceSelector.excludes("kube-system") {
				fmt.Printf("FAIL %s：namespaceSelector 未排除 kube-system（fail-closed 恐攔控制面/死結）\n", id)
				fail = true
			}
			if wh.ClientConfig.Service != nil {
				selfNs := wh.ClientConfig.Service.Namespace
				if !wh.NamespaceSelector.excludes(selfNs) {
					fmt.Printf("FAIL %s：namespaceSelector 未排除自身 namespace %q（啟動死結風險）\n", id, selfNs)
					fail = true
				}
			}

			// ① fail-open
			if wh.FailurePolicy == "Ignore" {
				fmt.Printf("WARN %s：failurePolicy=Ignore（fail-open，webhook 故障放行未檢查資源，需簽核）\n", id)
			}

			// ③ timeout 過長
			to := 10
			if wh.TimeoutSeconds != nil {
				to = *wh.TimeoutSeconds
			}
			if to > 10 {
				fmt.Printf("WARN %s：timeoutSeconds=%d 過長（慢 webhook 拖垮每次 API 寫入，承 Day72）\n", id, to)
			}

			// ④ 爆炸半徑 / 端點 / 副作用
			for _, ru := range wh.Rules {
				if has(ru.APIGroups, "*") || has(ru.Resources, "*") || has(ru.Operations, "*") {
					fmt.Printf("WARN %s：rules 含 \"*\"（攔截範圍過大，爆炸半徑大）\n", id)
					break
				}
			}
			if wh.ClientConfig.URL != nil {
				fmt.Printf("WARN %s：clientConfig 使用外部 url（優先用 in-cluster service）\n", id)
			}
			if wh.SideEffects != "None" && wh.SideEffects != "NoneOnDryRun" {
				fmt.Printf("WARN %s：sideEffects=%q（應為 None/NoneOnDryRun）\n", id, wh.SideEffects)
			}
		}
	}

	if fail {
		os.Exit(1)
	}
	fmt.Println("OK：所有 webhook 都排除了 kube-system 與自身 namespace")
}
```

**Java 版**（Jackson，對稱邏輯，判紅同上）：

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class WebhookAudit {
    static final ObjectMapper OM = new ObjectMapper();

    static boolean excludes(JsonNode nsSelector, String target) {
        for (JsonNode e : nsSelector.path("matchExpressions")) {
            if ("kubernetes.io/metadata.name".equals(e.path("key").asText())
                    && "NotIn".equals(e.path("operator").asText())) {
                for (JsonNode v : e.path("values")) {
                    if (target.equals(v.asText())) return true;
                }
            }
        }
        return false;
    }

    static boolean listHasStar(JsonNode arr) {
        for (JsonNode v : arr) if ("*".equals(v.asText())) return true;
        return false;
    }

    public static void main(String[] args) throws Exception {
        Process p = new ProcessBuilder("kubectl", "get",
                "validatingwebhookconfigurations,mutatingwebhookconfigurations", "-o", "json").start();
        JsonNode root = OM.readTree(p.getInputStream());

        boolean fail = false;
        for (JsonNode cfg : root.path("items")) {
            String cfgName = cfg.path("metadata").path("name").asText();
            for (JsonNode wh : cfg.path("webhooks")) {
                String id = cfgName + "/" + wh.path("name").asText();
                JsonNode nsSel = wh.path("namespaceSelector");

                if (!excludes(nsSel, "kube-system")) {
                    System.out.printf("FAIL %s：namespaceSelector 未排除 kube-system%n", id);
                    fail = true;
                }
                JsonNode svc = wh.path("clientConfig").path("service");
                if (!svc.isMissingNode()) {
                    String selfNs = svc.path("namespace").asText();
                    if (!excludes(nsSel, selfNs)) {
                        System.out.printf("FAIL %s：namespaceSelector 未排除自身 namespace \"%s\"%n", id, selfNs);
                        fail = true;
                    }
                }

                if ("Ignore".equals(wh.path("failurePolicy").asText("Fail"))) {
                    System.out.printf("WARN %s：failurePolicy=Ignore（fail-open，需簽核）%n", id);
                }
                int to = wh.path("timeoutSeconds").asInt(10);
                if (to > 10) {
                    System.out.printf("WARN %s：timeoutSeconds=%d 過長（承 Day72）%n", id, to);
                }
                for (JsonNode ru : wh.path("rules")) {
                    if (listHasStar(ru.path("apiGroups")) || listHasStar(ru.path("resources"))
                            || listHasStar(ru.path("operations"))) {
                        System.out.printf("WARN %s：rules 含 \"*\"（爆炸半徑大）%n", id);
                        break;
                    }
                }
                if (!wh.path("clientConfig").path("url").isMissingNode()) {
                    System.out.printf("WARN %s：clientConfig 使用外部 url%n", id);
                }
                String se = wh.path("sideEffects").asText("");
                if (!"None".equals(se) && !"NoneOnDryRun".equals(se)) {
                    System.out.printf("WARN %s：sideEffects=\"%s\"（應為 None/NoneOnDryRun）%n", id, se);
                }
            }
        }
        if (fail) System.exit(1);
        System.out.println("OK：所有 webhook 都排除了 kube-system 與自身 namespace");
    }
}
```

三個 CI 靜態掃不到、但要補的角度：

- **RBAC——誰能寫 `*WebhookConfiguration`（第二節②）**：這要另外掃 ClusterRole／ClusterRoleBinding（`verbs` 含 `create/update/patch` × `resources` 含 `validatingwebhookconfigurations/mutatingwebhookconfigurations`），確認只有平台角色有這個高權限。上面掃 config 本身抓不到這件事。
- **webhook 服務到底有沒有真做檢查、改寫是不是冪等——CI 看不到**：config 接上了、`failurePolicy` 也對，但 handler 裡到底有沒有那句 `if privileged → deny`、mutating 是不是重複套用會出錯，靜態掃不出來。這只能靠第十節的測試守。
- **憑證有效期與 HA——執行期才看得到**：伺服器憑證快過期、webhook 副本數不足、跨 node 分佈不夠，都是執行期狀態。

**執行期承 Day16**：把 apiserver 的 **admission webhook 呼叫失敗**（`apiserver_admission_webhook_*` 指標／audit log）與 webhook 自身的 allow/deny 決策打進 SIEM，對三件事告警——① **webhook 呼叫失敗率上升**（代表 webhook 正在故障：fail-closed 時是「寫入正被大量擋下」、fail-open 時是「門正開著、資源正沒被檢查地進來」，兩者都是 P1）；② **`Ignore` 的 webhook 實際發生失敗**（fail-open 被觸發＝policy 正在被繞過）；③ **webhook 延遲逼近 `timeoutSeconds`**（快用完延遲預算，離大量誤擋或拖垮 API 寫入不遠）。**因為「webhook 故障時門是開還是關、有沒有被繞過」這件事，靜態掃永遠掃不到，只能靠執行期抓。**

---

## 八、常見誤區

| 誤區 | 為什麼錯 |
|---|---|
| 「admission webhook 就是個小工具」 | 它坐在每次 API 寫入的必經路上、能改寫/攔截全叢集資源、被 apiserver 高度信任＝控制面高權限單點（第二節） |
| 「`failurePolicy: Ignore` 比較不會影響叢集」 | 那等於「webhook 一掛，未檢查的資源就進得來」＝policy 形同虛設，還能被主動打垮來繞過（第四節，承 Day90/72） |
| 「fail-closed 會讓 webhook 變單點，所以用 Ignore」 | 單點要用縮範圍/HA/短 timeout 補，不是靠 fail-open 把 admission 丟掉（第四、五節） |
| 「`failurePolicy` 會把 deny 也放行」 | 它只管「故障時的預設」，明確 deny 永遠是 deny（第四節，同 Day90 failure_mode_allow） |
| 「webhook 攔全叢集（含 kube-system）比較保險」 | fail-closed 下 webhook 一掛連控制面都寫不進＝叢集卡死；還會 self-deadlock（第三節） |
| 「webhook 不用排除自己的 namespace」 | 自身 Pod 重排時 apiserver 得先呼叫還沒起來的 webhook＝啟動死結（第三節） |
| 「`rules: resources:[\"*\"]` 省事」 | 攔到一切＝爆炸半徑最大、可用性依賴最廣；精準列舉才對（第二、七節） |
| 「`timeoutSeconds` 設大一點比較不會誤擋」 | 它在每次寫入的關鍵路徑上，太長＝慢 webhook 拖垮所有 API 寫入（第五節，承 Day72） |
| 「多個 mutating webhook 不會互相影響」 | 依序執行、後者改動可能需要前者重跑；要 `reinvocationPolicy: IfNeeded` 且 mutation 冪等（第五節，承 Day22） |
| 「webhook 憑證是維運細節」 | `caBundle`＝apiserver 信任它的根據；外洩＝可假冒、過期＝全面呼叫失敗觸發 failurePolicy（第二、三節，承 Day79/19） |
| 「用外部 url 當 webhook 端點沒差」 | 把控制面決策綁到叢集外端點＝多一個可用性/信任/SSRF 面；能用 in-cluster service 就別用（第二節，承 Day10） |
| 「admission 擋住了就等於叢集乾淨」 | admission 只管新寫入，管不到既存資源；既存要靠 audit/background scan（第一節，Day92） |

---

## 九、Code Review / 維運 checklist

**爆炸半徑與信任邊界（第二、三節，承 Day07/87）**

- [ ] `create/update/patch` `validatingwebhookconfigurations`／`mutatingwebhookconfigurations` 的 RBAC 只給平台團隊少數角色。
- [ ] `namespaceSelector` 排除了 `kube-system`、其他控制面 namespace、**以及 webhook 自身 namespace**（避免攔控制面與啟動死結）。
- [ ] `objectSelector`／`rules` 精準納管，不用 `*`；`clientConfig` 用 in-cluster `service` 而非外部 `url`。
- [ ] `caBundle` 與伺服器憑證可自動輪替（承 Day79），過期不會靜默造成全面失敗；`sideEffects: None`。

**fail 行為與可用性（第四、五節，承 Day07/90/72）**

- [ ] `failurePolicy` 預設 `Fail`（fail-closed）；任何 `Ignore` 都有明確理由、極窄範圍、且有告警。
- [ ] webhook 服務 HA（多副本／PDB／跨 node），fail-closed 才不會讓單一 replica 決定全叢集寫入生死。
- [ ] `timeoutSeconds` 是壓測定出的短逾時（通常數秒），不是拍腦袋放大。
- [ ] mutating webhook 若需 `reinvocationPolicy: IfNeeded`，其 mutation 邏輯**冪等**（承 Day22）。

**稽核（第七節，承 Day16）**

- [ ] CI／admission 掃「未排除 kube-system/自身 namespace（判紅）、`failurePolicy: Ignore`、`timeoutSeconds` 過長、`rules` 含 `*`、外部 `url`、`sideEffects` 非 None」。
- [ ] 執行期把 webhook 呼叫失敗率、`Ignore` 的實際 fail-open 觸發、webhook 延遲進 SIEM 並告警。

---

## 十、測試 / 演練建議

- **fail-closed 演練（最關鍵的可用性/安全測試）**：把 webhook 服務**停掉**或注入逾時，斷言被它攔的資源**被擋（fail-closed）**而非放行；同時**斷言 `kube-system` 與 webhook 自身 namespace 的資源仍能正常寫入**（證明排除生效、沒把控制面一起鎖死）。
- **啟動死結演練（第三節）**：在 webhook 完全不可用的狀態下，重排 webhook 自己的 Pod，斷言它**能起得來**（證明自身 namespace 已被 `namespaceSelector` 排除）；若起不來＝你有死結。
- **`failurePolicy: Ignore` 迴歸（第七節）**：把某個安全關鍵 webhook 改成 `Ignore`，斷言第七節的 CI **判紅**或至少判黃要簽核。測不過代表稽核是擺設。
- **未排除 kube-system 迴歸**：把 `namespaceSelector` 的排除拿掉，斷言 CI **判紅**。
- **object-level 決策測試**：送一個違規資源（privileged Pod）斷言**被拒且回應帶清楚原因**；送一個合規資源斷言**放行**——直接測 handler 的 `allow/deny` 是不是真的生效（CI 靜態掃不到這件事，第七節）。
- **冪等 mutation 測試（第五節，承 Day22）**：對同一資源**重複套用** mutating webhook（模擬 `reinvocationPolicy: IfNeeded` 多次呼叫），斷言結果不變（例如 sidecar 只被注入一次）。
- **延遲預算測試（第五節，承 Day72）**：對 webhook 注入延遲逼近 `timeoutSeconds`，量測對 `kubectl apply`／controller reconcile 的 P99 影響，以及是否開始出現逾時誤擋——用來校準 timeout 與 HA。
- **憑證輪替測試（第二、三節，承 Day79）**：讓伺服器憑證接近到期並輪替，斷言 webhook 呼叫**不中斷**；模擬憑證過期，斷言監控**告警**（而不是靜默觸發 failurePolicy）。

---

## 十一、一句話總結

> Day90 收**資料面**「每個請求該不該過」的 fail 行為（Envoy `ext_authz`），Day91 收**控制面**「每個資源該不該進叢集」的 fail 行為（admission webhook）——同一題，換個場。**爆炸半徑**：admission webhook（`Mutating` 能改寫、`Validating` 能准拒）坐在每次 API 寫入的必經路上、能攔截/改寫全叢集資源、被 apiserver 靠 `caBundle` 高度信任，是控制面高權限單點——所以要收三個邊界：誰能改它的 config（RBAC 收平台團隊）、它攔誰（`namespaceSelector`/`objectSelector`/`rules` 精準且**排除 kube-system 與自身 namespace**，否則攔控制面/啟動死結）、apiserver 憑什麼信它（in-cluster service＋可輪替憑證，承 Day79）。**fail 行為**：`failurePolicy: Ignore`（fail-open）＝webhook 一掛放行未檢查資源＝policy 形同虛設、還能被主動打垮繞過（承 Day90/72）；`Fail`（fail-closed，v1 預設）＝webhook 掛了擋下被攔到的寫入、安全但成可用性單點；預設就該 `Fail`，`failurePolicy` 只管故障預設、明確 deny 永遠 deny。**兩者兼顧**：縮攔截範圍（一石二鳥：同時降爆炸半徑與可用性依賴）＋webhook HA＋壓測定出的短 `timeoutSeconds`（太長拖垮每次 API 寫入，承 Day72）＋mutating 的 `reinvocationPolicy: IfNeeded` 配冪等 mutation（承 Day22），而不是用 fail-open 換可用性。handler 很單純（Go/Java 各一支：解 `AdmissionReview`、回填 `uid`、`allowed`/`deny` 帶原因、HTTPS 服務、mutating 回冪等 JSONPatch）；稽核（承 Day16）把「未排除 kube-system/自身、`Ignore`、`timeout` 過長、`rules` 含 `*`、外部 `url`」寫成 CI，執行期對 webhook 呼叫失敗率、fail-open 觸發、延遲告警。一句話：**你把「資源進不進叢集」外接給 webhook，就等於在控制面立了一個能改寫全叢集、又決定全叢集寫入生死的元件——預設 fail-closed，用縮範圍/HA/短 timeout 撐住可用性，別用 fail-open 把 admission 偷偷關掉；而它只管「入口的門」，屋裡的既存資源要靠 audit 巡邏。**

---

## 延伸閱讀

- Day90 mesh `ext_authz` 授權——本篇上游：Day90 收資料面「每個請求該不該過」的 fail-open vs fail-closed，今天把同一題翻到控制面 admission webhook「每個資源該不該進叢集」。
- Day87 SPIRE × service mesh——sidecar injector 就是一種 mutating admission webhook；Day87 講它「是什麼、注入範圍=身分範圍」，今天講這類 webhook 自身的加固、`failurePolicy` 與單點問題。
- Day07 Broken Access Control / default deny——`failurePolicy: Fail`（fail-closed）就是 default deny 在 admission 的落點；RBAC 收 `*WebhookConfiguration` 寫入權是控制面的最高等級存取控制。
- Day72 Slow HTTP DoS——webhook 在每次 API 寫入的關鍵路徑上，`timeoutSeconds` 沒設好，慢的 webhook 就是拖垮全叢集寫入的一種 DoS；攻擊者也可打垮它來觸發 fail-open。
- Day79 ACME / 憑證自動輪替——webhook 伺服器憑證與 `caBundle` 要能自動輪替，過期會造成全面呼叫失敗接著觸發 `failurePolicy`。
- Day22 Race Condition / Idempotency——mutating webhook 在 `reinvocationPolicy: IfNeeded` 下可能被多次呼叫，改寫必須冪等。
- Day16 Security Logging / Monitoring——把 webhook 呼叫失敗率、fail-open 觸發、延遲進 SIEM，對故障與繞過告警（靜態掃永遠掃不到執行期的門開沒開）。

---

明天預告：**Day 92 — OPA Gatekeeper / Kyverno 政策即程式碼的盲點與繞過：ConstraintTemplate/Constraint（Gatekeeper Rego）與 Kyverno ClusterPolicy 怎麼寫、enforce vs audit/dryrun、admission 只擋「新寫入」擋不到既存資源（要 background scan/audit 補）、`excludedNamespaces`/exempt 被濫用、mutation 改掉 validation 看到的內容、update/subresource 繞過，以及 policy 的單元測試（延伸篇）**
（這是**延伸篇**，不重講 Day91 的 admission webhook 機制與 `failurePolicy`、也不重講 Day07 的 default deny。Day91 收的是「webhook 這條管線本身」的信任邊界與可用性——誰能改它、它攔誰、掛了怎麼辦；明天往下一層，收「跑在這條管線上的**政策內容**」怎麼被寫壞、被繞過。延伸角度三條：**① 政策怎麼寫**——Gatekeeper 的 `ConstraintTemplate`（內嵌 Rego）+ `Constraint`、Kyverno 的 `ClusterPolicy`（validate/mutate/generate 規則），會用「禁止 latest tag／要求 image 帶 digest（承 Day18）／要求 resource limits」當後端可落地的例子；**② 常見繞過與盲點**——政策留在 `enforcementAction: dryrun`／Kyverno `Audit` 模式（只記錄不擋，等於沒上線）、`excludedNamespaces`/exempt 清單被濫用成後門、mutation webhook 在 validation 之前改掉了 validation 要看的欄位（承 Day91 mutating-before-validating 的順序）、只攔 `CREATE` 沒攔 `UPDATE`／subresource 造成的繞過、以及「admission 只管新寫入、既存違規資源要靠 audit/background scan 補」（承 Day91 第一節那條邊界）；**③ 怎麼測政策**——用 `opa test`（Gatekeeper Rego）與 `kyverno test`／CLI 對政策寫單元測試，把 policy 當程式碼測（承 Day90 Rego 可測性的思路）。程式面會示範 `ConstraintTemplate`/`Constraint` 與 `ClusterPolicy` 的 YAML、一段 Gatekeeper Rego、以及一支掃「政策還在 dryrun/Audit、`excludedNamespaces` 過寬、只攔 CREATE 漏 UPDATE」的稽核。安全主軸一句話：**Day91 收「webhook 管線本身」的信任邊界與 fail 行為，Day92 收「跑在管線上的政策」怎麼被寫成 dryrun、被 exempt 清單掏空、被 mutation 與 UPDATE/subresource 繞過——管線再穩，政策留一個 dryrun 或一個過寬的 exempt，就等於沒防。** 這是延伸篇，只聚焦政策內容的盲點與繞過，不重述 admission webhook 機制與存取控制入門。）
