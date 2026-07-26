---
title: "Day 87：SPIRE × service mesh — Envoy SDS 怎麼餵 SVID、Istio AuthorizationPolicy 用 SPIFFE ID 授權，以及 sidecar 幫你終結 mTLS 的信任邊界（延伸篇）"
date: 2026-07-27
tags: ["SPIFFE", "SPIRE", "Istio", "Envoy"]
---

接續 Day86 預告：Day86 第五節把 mesh sidecar 當成「把 socket 從應用手裡收走」的一種隔離形態點了名、沒展開——應用完全不碰 Workload API socket，由 pod 裡的 Envoy sidecar 透過 SDS 拿 SVID、幫應用終結 mTLS，應用只講純 HTTP 給 localhost。今天就展開這個形態：**身分沒有消失，只是搬進了 sidecar 與注入器，你得知道它搬去哪、那裡的門有沒有關。**

**這篇是延伸篇，不重講 Day80 的 SVID／attestation 兩層基礎，也不重講 Day19／74／75 的 mTLS 握手與憑證驗證基礎，更不重講 Day86 的 socket 掛載方式。** SPIFFE ID 怎麼塞在 SVID、Agent 怎麼靠 attestation 發證、mTLS 握手怎麼跑、go-spiffe／java-spiffe 怎麼寫——前面都講過，今天不重述。這篇聚焦一件事：**當你決定「應用不自己拿 SVID、交給 mesh」之後，身分的驗發與授權從應用碼搬到了哪裡，那些新落點各自是什麼門。**

延伸角度只有一條主軸：**Day80 的 library 模式裡，「跟誰通話、接不接受」是應用自己用 authorizer 決定的（`AuthorizeID`）；mesh 模式把這件事整包搬給 Envoy——好處是身分與 mTLS 徹底離開應用碼，壞處是三個新的門冒出來，而且應用對「我到底在跟誰通話」變無感。** 三個新的門逐一拆：① Envoy 怎麼拿 SVID——不是應用連 Workload API，是 **Envoy 透過 SDS 向 SPIRE Agent 要憑證與 trust bundle**；② 信任邊界搬去哪——**誰能決定注入這個 sidecar（mutating webhook）、SDS 通道怎麼保護**；③「sidecar 幫我做」的兩面刃——**localhost 明文那一段、應用對通話對象無感、以及繞過 sidecar 直連（承 Day38）**。

> ⚠️ 以下 Istio annotation／label（`spiffe.io/...`）、Envoy SDS 欄位、SPIRE Agent socket 路徑、AuthorizationPolicy 的 principal 字串形式，都會隨你的 Istio／SPIRE／Envoy 版本與整合方式不同。實際請對照你那套的官方 manifest，別照抄字串。這裡示範的是**信任邊界搬到哪、每道門怎麼收**的意圖，不是某一版的精確語法。

---

## 一、先定位：mesh 不是「給 workload 加身分」，是把「拿身分」從應用手裡收走

先把 Day80 的兩種形態擺在一起看，才不會把 mesh 當成另一個功能：

```text
[library 模式（Day80）]  應用碼 ── go-spiffe/java-spiffe ──▶ Workload API socket ──▶ SVID
                         └ 應用自己在 authorizer 裡決定「接不接受對方 SPIFFE ID」

[mesh 模式（今天）]      應用碼 ── 純 HTTP ──▶ localhost:Envoy ── SDS ──▶ Workload API socket ──▶ SVID
                         └ Envoy 幫應用終結 mTLS，接不接受由 Envoy/Istio 的 AuthorizationPolicy 決定
```

差別不是「有沒有身分」，而是**身分的三件事——拿憑證、驗對方、決定授權——從應用進程搬到了 Envoy 進程**。這帶來三個被搬移的責任，也就是今天要逐一檢查的三道門：

```text
門一：Envoy 怎麼拿到 SVID？          → SDS 通道（第二節）
門二：誰決定把這個 sidecar 注進來？   → sidecar injector / mutating webhook（第三節）
門三：Envoy 憑什麼接受對方？          → AuthorizationPolicy 的 principals（第四節）
```

一句話定位：**Day86 收窄的是「應用容器連不連得上 socket」；mesh 乾脆讓應用不碰 socket——但 socket 沒有消失，是搬進了 sidecar；而「決定誰能通話」也從應用的 authorizer 搬進了 Istio 的 policy。** 你要問的不再是「應用有沒有掛到 socket」，而是「**Envoy 有沒有安全地拿到 SVID、這個 Envoy 是誰放進來的、它的 policy 有沒有真的收窄**」。

---

## 二、門一：Envoy 怎麼拿 SVID —— SDS，不是應用連 Workload API（承 Day80）

關鍵事實一句話：**SPIRE Agent 的 Workload API endpoint 同時實作了 Envoy 的 SDS（Secret Discovery Service）協定。** 所以 Envoy 不需要「另一套」拿憑證的機制——它連上**同一個** Agent socket，用 SDS 這個 Envoy 原生協定跟 Agent 要兩種東西：

```text
Envoy ── SDS(gRPC over Agent socket) ──▶ SPIRE Agent
  ① tls_certificate      ← 這個 workload 自己的 X509-SVID（憑證 + 私鑰）
  ② validation_context   ← trust bundle（CA 根，用來驗對方 SVID）
```

而且 SDS 是**串流訂閱**：SVID 快到期、Agent 重簽時，Agent 主動把新的憑證從 SDS stream 推給 Envoy，Envoy 熱換上——**沒有重啟、沒有檔案 reload**。這正是 Day79「reload 不重啟」與 Day80「X509Source 背景自動更新」的 mesh 版：換發被平台接管，只是接管者從應用進程裡的 `X509Source` 換成了 sidecar 裡的 Envoy。

Envoy 這端的接線（bootstrap，示意）：先定義一個指向 Agent socket 的 SDS cluster，再在對外 listener 的 `transport_socket` 引用它：

```yaml
# Envoy bootstrap（示意）：SDS 來源指向 SPIRE Agent 的 Workload API socket
node: { id: "order-service", cluster: "tenant-a" }

static_resources:
  clusters:
    - name: spire_agent                     # ← SDS 的來源
      connect_timeout: 1s
      http2_protocol_options: {}
      load_assignment:
        cluster_name: spire_agent
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    pipe:                    # Unix domain socket，就是 Agent 那個 socket
                      path: /run/spire/agent-sockets/spire-agent.sock

  listeners:
    - name: outbound
      # ... filter_chains 省略 ...
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          common_tls_context:
            tls_certificate_sds_secret_configs:      # ① 拿自己的 SVID
              - name: "spiffe://example.org/ns/tenant-a/sa/order-service"
                sds_config: { api_config_source: { api_type: GRPC, grpc_services: [ envoy_grpc: { cluster_name: spire_agent } ] } }
            combined_validation_context:
              default_validation_context:
                # ② 用 trust bundle 驗對方，並限定只接受哪些 SPIFFE ID（authZ 的雛形，正解在第四節）
                match_typed_subject_alt_names:
                  - san_type: URI
                    matcher: { exact: "spiffe://example.org/ns/tenant-b/sa/ledger-service" }
              validation_context_sds_secret_config:  # trust bundle 也走 SDS
                name: "spiffe://example.org"
                sds_config: { api_config_source: { api_type: GRPC, grpc_services: [ envoy_grpc: { cluster_name: spire_agent } ] } }
```

三個要點，全都呼應前面幾天：

- **對方身分比對的是 SAN 的 URI，不是 DNS name（承 Day75／Day80）**：`match_typed_subject_alt_names` 的 `san_type: URI` ——這就是 Day80 說的「SPIFFE 比對 SAN URI，完全不看主機名」在 Envoy 的落點。你在這裡**千萬不要**退回去比對 DNS name / 主機名，那是 Day75 的世界，SVID 根本沒有 DNS SAN。
- **憑證與 trust bundle 都不是檔案，是 SDS 動態供給**：所以「憑證 reload 不重啟」是 Envoy＋SDS 內建的，不用你自寫熱替換。維運關注點從 Day79「憑證會不會換」變成 Day80「SPIRE 基礎設施（Agent／SDS 通道）在不在」。
- **Envoy 到 Agent 這條 SDS 通道本身，就是 Day86 那個 socket**：Envoy 連上 Agent socket 這件事，一樣要走 attestation——SPIRE Agent 對「連上 SDS 的 Envoy」做 workload attestation（`SO_PEERCRED` 反查 Envoy 進程特徵，Day84），符合 registration entry 才發對應 SVID。**所以 SDS 沒有繞過 attestation，它只是把「連 socket 的主體」從應用換成了 Envoy。** Day86 的閘門一、Day84 的閘門二，在 mesh 裡一個都沒少，只是守門對象變成 sidecar。

在 Istio 整合下，你通常不用手寫這段 bootstrap——istiod 幫你生。你要做的是**讓 pod 選用 SPIRE 當身分來源**：把 Agent socket 用 SPIFFE CSI Driver（Day86）掛進 sidecar，並用 annotation／label 讓 istiod 把 Envoy 的 SDS 指到那個 socket，同時**在 SPIRE 建對應的 registration entry**（沒有 entry，Envoy 連上 SDS 也拿不到 SVID——閘門二）：

```yaml
# Istio pod 選用 SPIRE 身分（示意，實際 annotation/label 依你的 Istio+SPIRE 版本）
apiVersion: v1
kind: Pod
metadata:
  name: order-service
  namespace: tenant-a
  labels:
    spiffe.io/spiffe-id: "true"          # 讓 istiod 知道這個 pod 走 SPIRE SDS
  annotations:
    inject.istio.io/templates: "sidecar" # 注入 Envoy（門二：誰能下這個決定？見第三節）
spec:
  serviceAccountName: order-service       # ← attestation selector 會綁到它（Day84）
  containers:
    - name: app
      image: registry.example.com/order-service@sha256:...   # 綁 digest（Day18/84）
  volumes:
    - name: spiffe-workload-api
      csi:
        driver: csi.spiffe.io             # Day86：受控地把 Agent socket 掛給 sidecar
        readOnly: true
```

一句話收束門一：**mesh 沒有發明新的身分，它只是把「連 socket 拿 SVID」的角色從應用換成 Envoy，並用 SDS 這個串流協定把「reload 不重啟」做進基礎設施。attestation 兩道門（Day84／Day86）原封不動，守的對象變成 sidecar。**

---

## 三、門二：信任邊界搬去哪 —— sidecar 注入器是新的高權限點（承 Day07 / Day86）

這是 mesh 最容易被忽略的一道門。前面說「應用不碰 socket，交給 sidecar」——那**這個 sidecar 是怎麼跑進 pod 裡的**？答案：**mutating admission webhook（sidecar injector）**。你給 pod 打個 label／annotation，webhook 在 pod 建立時把 Envoy 容器與 SPIFFE CSI volume**改寫進 pod spec**。

把 Day86 的心智搬過來就懂它為什麼是資安邊界了：

- Day86 說 `hostPath` 直掛是「誰能在 pod spec 寫上這段，誰就掛得到 socket」；**mesh 把這件事換了個位置——不是應用自己宣告掛載，而是 injector 幫它宣告。** 於是問題從「誰能寫 hostPath」變成「**誰能決定 injector 對哪些 pod 動手、injector 注入的模板內容誰能改**」。
- **mutating webhook 是叢集裡權限極高的元件**：它能改寫任何被它攔到的 pod spec。能改 injector 的模板（`ConfigMap`／`MutatingWebhookConfiguration`），等於能決定「每個 pod 裡多跑一個什麼容器、掛什麼 volume、有什麼 securityContext」——這是 Day07 最小權限裡最該收緊的一類物件。
- **注入範圍就是身分發放範圍**：哪些 namespace／pod 會被注入 Envoy＋SPIRE SDS，等於「哪些 workload 會拿到 mesh 身分」。注入條件（namespace label、pod annotation）設得太寬，等於把身分發給了不該有身分的 pod——這是 Day86「不需要身分的 pod 就別掛 socket」在 mesh 的對應版：**不需要身分的 pod 就別被注入。**

收窄方向（都承 Day07）：

```text
- MutatingWebhookConfiguration / injector 的 ConfigMap → RBAC 收到只有平台團隊能改（改模板＝改每個 pod 多什麼容器）
- 注入範圍用明確的 namespace label / pod annotation 選入，而不是「整個叢集預設注入」
- injector 注入的 sidecar 模板本身要過 PodSecurity（承 Day86：securityContext 收窄、drop caps、runAsNonRoot）
- 注入器與 SPIRE Agent 之間、Envoy 與 Agent 之間的 SDS 通道（就是那個 socket）用 Day86 的 socket 存取控制收好
```

一句話收束門二：**mesh 把「應用自己掛 socket」換成「injector 幫應用掛」，方便的代價是多出一個能改寫全叢集 pod 的高權限元件。你把應用層的 `hostPath` 收乾淨了（Day86），但如果 injector 的模板與注入範圍沒人管，攻擊面只是從應用搬到了控制平面——而且搬到了一個更集中、爆炸半徑更大的地方。**

---

## 四、門三：authN ≠ authZ —— AuthorizationPolicy 用 SPIFFE ID 當 principals（承 Day07 / Day49 / Day81）

這是 mesh 最常見、也最致命的錯誤來源。Envoy 幫你把 mTLS 跑起來、驗過對方 SVID——**但「驗過身分」不等於「允許他做這件事」。** Day81 已經敲過這個釘子：`aud` 驗過不是授權；今天在 mesh 是同一件事的另一面——**mTLS 握手成功只證明「對方是一個合法的、有 SVID 的 workload」，它沒回答「這個 workload 可不可以呼叫我這個服務／這個路徑」。** 後者是 Istio `AuthorizationPolicy` 的事。

`AuthorizationPolicy` 用對方的 SPIFFE ID 當 `principals`（Istio 慣例會把 `spiffe://` 前綴去掉）：

```yaml
# 先在 namespace（或整個 mesh）鋪一張「預設拒絕」——這是最關鍵、最常被漏掉的一步
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: default-deny-all
  namespace: tenant-a
spec:
  {}          # 沒有任何 rule 的 ALLOW policy＝什麼都不允許＝這個 namespace 預設拒絕
---
# 再明確允許「誰」可以呼叫 ledger-service 的「哪個路徑」
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: allow-order-to-ledger
  namespace: tenant-a
spec:
  selector:
    matchLabels: { app: ledger-service }
  action: ALLOW
  rules:
    - from:
        - source:
            principals:
              # ← 對方的 SPIFFE ID（去掉 spiffe:// 前綴）。逐一列舉，別用萬用字元
              - "example.org/ns/tenant-a/sa/order-service"
      to:
        - operation:
            methods: ["POST"]
            paths: ["/v1/transfer"]     # authZ 收到方法＋路徑層級（承 Day49 function-level）
```

三個致命誤區，全是 Day07／Day49 在 mesh 的重演：

- **沒有預設拒絕，等於預設全通**：Istio 的規則是——**某個 workload 若沒有任何 ALLOW policy 命中它，就是允許所有請求。** 你以為「裝了 mesh、跑了 mTLS 就安全」，但如果沒鋪那張 `spec: {}` 的預設拒絕，mTLS 只是把「誰都能連」變成「誰有 SVID 都能連」——**authN 收了，authZ 開著。** 這是 mesh 最大的假安全。
- **`principals: ["*"]` ＝驗了身分沒授權**：`*` 匹配「任何有 mTLS 身分的來源」。寫成這樣，等於 Day81 的 `AuthorizeMemberOf`、Day82 的跨 domain `MemberOf`——「自己人就放行」是 authN 不是 authZ。**你的信任邊界裡只要有一個服務被打穿，它就能拿著自己合法的 SVID 橫著呼叫所有 `principals: ["*"]` 的服務。**
- **principal 方向填反**：跟 Day81「驗證端照抄上游 ID」同一種錯。`from.source.principals` 要填的是**允許誰來呼叫我**（上游的 ID），`selector` 選的是**我自己**（被保護的服務）。填反了就是「允許自己呼叫自己」或匹配不到任何來源——policy 形同虛設。

補一個 mesh 專屬的坑：**應用其實還是「看得到」對方身分——Envoy 會把對方 SPIFFE ID 塞進 `X-Forwarded-Client-Cert`（XFCC）header 給應用。** 但這是把「密碼學證明的身分」降級成「一個 HTTP header」——**應用如果直接信 XFCC 來做業務授權，就要確保這個 header 只可能由自己的 sidecar 注入、外部絕對送不進來**（承 Day38：繞過 gateway 直連、偽造轉發 header）。這條線的安全性，完全取決於第五節要講的「有沒有人能繞過 sidecar」。

一句話收束門三：**mTLS + SVID 回答「你是誰」，`AuthorizationPolicy` 回答「你能不能做這件事」——兩者是 AND，缺一不可（Day81／Day49）。mesh 幫你把 authN 做得很漂亮，但 authZ 是你自己要鋪的：先預設拒絕，再逐一用確切 SPIFFE ID 開通，永遠不要 `principals: ["*"]`。**

---

## 五、「sidecar 幫我做」的兩面刃

把身分與 mTLS 徹底移出應用碼，好處很實在：應用只講純 HTTP，連 go-spiffe／java-spiffe 都不用寫（Day80 的 authorizer、Day82 的 `acceptedSpiffeIds` 全省了），憑證輪替、trust bundle 更新、mTLS 握手全由平台接管。但代價是三個新的盲點：

**① 應用對「我在跟誰通話」變無感。**
library 模式裡，`AuthorizeID(serverID)` 就寫在應用碼裡——你 code review 時看得到「這個呼叫只接受哪個 SPIFFE ID」。mesh 模式裡，這個決定搬到了 `AuthorizationPolicy`（另一個團隊、另一個 repo、另一個 YAML）。應用工程師常會**誤以為「反正 mesh 會擋」而完全不驗**，於是授權邏輯掉進「沒人負責」的縫裡：應用覺得是平台的事，平台只鋪了 authN。**心智矯正：mesh 把 authN 平台化了，但 authZ 的業務規則（誰能轉帳、誰能讀哪個租戶）永遠是應用＋policy 的共同責任（Day07／Day49）。**

**② localhost 明文那一段。**
應用 ↔ 自己的 sidecar 是**走 pod 內 loopback 的純 HTTP，沒有加密**。正常情況這可接受（同一個 pod、共用 network namespace）。但要意識到：**pod 裡任何一個容器都共用這個 network namespace**——多容器 pod 裡塞了一個第三方映像的 sidecar，它就能看到（甚至攔到）你應用與 Envoy 之間那段明文。所以「mesh 全程 mTLS」這句話有個星號：**pod 內那一跳是明文的，你的隔離邊界是 pod，不是容器。** 別在多租戶 pod 裡混不受信任的容器。

**③ 繞過 sidecar 直連（承 Day38）——這是 mesh 最大的隱形破口。**
Envoy 靠 pod 啟動時注入的 iptables 規則，把應用的進出流量重導向自己。但這套「攔截」有前提，一旦前提破了，攻擊者就能**繞過 sidecar 直接打應用埠**，於是 mTLS、AuthorizationPolicy、XFCC——全部跳過：

```text
正常：caller Envoy ──mTLS──▶ 目標 Envoy ──明文 localhost──▶ 目標 app
繞過：攻擊者 ─────────────純 HTTP 直連 pod IP:appPort────────▶ 目標 app（沒 mTLS、沒 policy、可自捏 XFCC）
```

常見的破口：**應用綁 `0.0.0.0` 對整個 pod 網路開埠**（而非只綁 `127.0.0.1` 給 sidecar）、`PeerAuthentication` 停在 `PERMISSIVE`（同時收 mTLS 與明文，攻擊者送明文就跳過身分）、用 `excludeInboundPorts` 把某些埠排除攔截、headless service 直連 pod IP、以及「反正 gateway／sidecar 驗過了、後端不用驗」這個 Day38 的老毛病。**這正好接回第四節的 XFCC**：如果應用信 XFCC 做授權，而攻擊者能繞過 sidecar 直連並自己塞一個 XFCC header，那你的授權就是攻擊者說了算。

這道「怎麼確保沒有人能繞過 sidecar」的門很大，**留給明天整篇處理**。今天只需要記住結論：**mesh 的所有保護，都建立在「流量真的走了 sidecar」這個前提上；這個前提不是自動成立的，要靠 STRICT mTLS ＋ NetworkPolicy ＋ 應用只綁 loopback 一起強制。**

---

## 六、Day16 稽核：哪些流量沒走 sidecar、哪些 principal 開太寬

mesh 的兩個最危險狀態——**「principal 開成 `*`（authN 當 authZ）」**與**「namespace 沒有預設拒絕（預設全通）」**——都能靜態掃出來。把它寫成 CI／admission，就是 Day16「把偵測升級成預防」在 mesh 的落點。

先看資料長相（在 chat／CI 裡先跑一次再寫解析，承 Day86 心法）：

```bash
kubectl get authorizationpolicy -A -o json
```

**Go 版**：掃所有 `AuthorizationPolicy`，抓「`principals` 含 `*`」與「`from` 為空＝任何來源皆可」，並回報「哪些 namespace 有 selector 卻沒有預設拒絕」。

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type apList struct {
	Items []struct {
		Metadata struct {
			Name, Namespace string
		} `json:"metadata"`
		Spec struct {
			Action   string `json:"action"`
			Selector *struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"selector"`
			Rules []struct {
				From []struct {
					Source struct {
						Principals []string `json:"principals"`
					} `json:"source"`
				} `json:"from"`
			} `json:"rules"`
		} `json:"spec"`
	} `json:"items"`
}

func main() {
	out, err := exec.Command("kubectl", "get", "authorizationpolicy", "-A", "-o", "json").Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "取不到 AuthorizationPolicy：", err)
		os.Exit(2)
	}
	var list apList
	if err := json.Unmarshal(out, &list); err != nil {
		fmt.Fprintln(os.Stderr, "JSON 解析失敗：", err)
		os.Exit(2)
	}

	fail := false
	nsHasDefaultDeny := map[string]bool{}

	for _, p := range list.Items {
		// 預設拒絕：action=ALLOW（Istio 預設）且沒有任何 rule
		if (p.Spec.Action == "" || p.Spec.Action == "ALLOW") && len(p.Spec.Rules) == 0 {
			nsHasDefaultDeny[p.Metadata.Namespace] = true
		}
		for _, r := range p.Spec.Rules {
			if len(r.From) == 0 { // 沒有 from＝任何來源皆可（只要有 mTLS 身分）
				fmt.Printf("FAIL %s/%s：rule 沒有 from，等於允許任何來源\n", p.Metadata.Namespace, p.Metadata.Name)
				fail = true
			}
			for _, f := range r.From {
				for _, pr := range f.Source.Principals {
					if pr == "*" || pr == "" {
						fmt.Printf("FAIL %s/%s：principals 含萬用字元（authN 當 authZ）\n", p.Metadata.Namespace, p.Metadata.Name)
						fail = true
					}
				}
			}
		}
	}

	// 有 workload 的 namespace 卻沒有預設拒絕＝預設全通
	for _, ns := range []string{"tenant-a", "tenant-b"} { // 實務改成掃實際 namespace 清單
		if !nsHasDefaultDeny[ns] {
			fmt.Printf("FAIL namespace %s：沒有預設拒絕 policy，未命中任何 ALLOW 的請求會被放行\n", ns)
			fail = true
		}
	}

	if fail {
		os.Exit(1)
	}
	fmt.Println("OK：無萬用 principal、各 namespace 皆有預設拒絕")
}
```

**Java 版**（Jackson，對稱邏輯，跑在 CI 或維運工具裡）：

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashSet;
import java.util.Set;

public class MeshAuthzAudit {
    public static void main(String[] args) throws Exception {
        ObjectMapper om = new ObjectMapper();
        Process p = new ProcessBuilder(
                "kubectl", "get", "authorizationpolicy", "-A", "-o", "json")
                .redirectErrorStream(false).start();
        JsonNode root = om.readTree(p.getInputStream());

        boolean fail = false;
        Set<String> nsWithWorkload = Set.of("tenant-a", "tenant-b"); // 實務換成實際清單
        Set<String> nsHasDefaultDeny = new HashSet<>();

        for (JsonNode item : root.path("items")) {
            String ns = item.path("metadata").path("namespace").asText();
            String name = item.path("metadata").path("name").asText();
            JsonNode spec = item.path("spec");
            String action = spec.path("action").asText("ALLOW");
            JsonNode rules = spec.path("rules");

            if ("ALLOW".equals(action) && (rules.isMissingNode() || rules.size() == 0)) {
                nsHasDefaultDeny.add(ns);
            }
            for (JsonNode r : rules) {
                JsonNode from = r.path("from");
                if (from.isMissingNode() || from.size() == 0) {
                    System.out.printf("FAIL %s/%s：rule 沒有 from，等於允許任何來源%n", ns, name);
                    fail = true;
                }
                for (JsonNode f : from) {
                    for (JsonNode pr : f.path("source").path("principals")) {
                        String v = pr.asText();
                        if ("*".equals(v) || v.isEmpty()) {
                            System.out.printf("FAIL %s/%s：principals 含萬用字元（authN 當 authZ）%n", ns, name);
                            fail = true;
                        }
                    }
                }
            }
        }
        for (String ns : nsWithWorkload) {
            if (!nsHasDefaultDeny.contains(ns)) {
                System.out.printf("FAIL namespace %s：沒有預設拒絕 policy，預設全通%n", ns);
                fail = true;
            }
        }
        if (fail) System.exit(1);
        System.out.println("OK：無萬用 principal、各 namespace 皆有預設拒絕");
    }
}
```

同一套心智可以再多掃兩項（承第五節）：`PeerAuthentication` 是否停在 `PERMISSIVE`、pod 是否用了 `traffic.sidecar.istio.io/excludeInboundPorts` 把埠排除攔截——這兩個是「繞過 sidecar」的靜態訊號，明天會展開。**執行期則承 Day16**：把 Envoy 的 access log 打進 SIEM，比對「哪些流量帶了對端 SPIFFE ID（走了 mTLS）、哪些是明文直連」，對後者告警——因為 policy 掃得再乾淨，也擋不住「根本沒走 sidecar」的流量。

---

## 七、常見誤區

| 誤區 | 為什麼錯 |
|---|---|
| 「裝了 mesh、跑了 mTLS 就安全」 | mTLS 只做 authN。沒鋪預設拒絕的 `AuthorizationPolicy`，等於「誰有 SVID 都能連」＝authZ 全開（第四節） |
| 「mesh 給 workload 加了身分」 | 身分還是 SPIRE 發的；mesh 只是把「拿 SVID／驗對方」從應用搬到 Envoy，attestation 兩道門（Day84/86）一個沒少（第一、二節） |
| 「Envoy 走 SDS 就繞過 attestation 了」 | 相反——Envoy 連 Agent socket 一樣要過 workload attestation，只是被反查的進程從應用變 Envoy（第二節） |
| 「SDS 拿憑證要自己寫 reload」 | SDS 是串流訂閱，Agent 主動推新 SVID，Envoy 熱換、不重啟（第二節） |
| 「Envoy 比對對方主機名就行」 | SVID 沒有 DNS SAN，要比對 `san_type: URI`；比 DNS name 一定失敗（承 Day75/80，第二節） |
| 「sidecar 是維運細節，跟資安無關」 | 注入靠 mutating webhook＝能改寫全叢集 pod 的高權限元件；注入範圍＝身分發放範圍（第三節） |
| 「principals 填 `*` 比較好管」 | `*`＝任何有身分的來源皆可＝authN 當 authZ，等於 Day81 `MemberOf`／Day82 跨 domain `MemberOf`（第四節） |
| 「from.source.principals 填自己的 ID」 | 方向反了。`from` 填「允許誰來呼叫我」（上游 ID），`selector` 才是自己（承 Day81，第四節） |
| 「有 mesh 應用就不用管授權」 | authZ 業務規則永遠是應用＋policy 共同責任；mesh 只平台化了 authN（第四、五節） |
| 「mesh 全程都加密」 | 應用 ↔ 自己 sidecar 那段走 pod 內 loopback 明文；隔離邊界是 pod 不是容器（第五節） |
| 「反正流量都會走 sidecar」 | 應用綁 `0.0.0.0`、PERMISSIVE、排除埠、直連 pod IP 都能繞過；mesh 保護全建立在「真的走了 sidecar」上（第五節、Day88） |
| 「應用信 XFCC header 做授權就好」 | XFCC 是把密碼學身分降級成 HTTP header；能繞過 sidecar 直連的人可自捏它（承 Day38，第四、五節） |

---

## 八、Code Review / 維運 checklist

**Envoy／SDS 接線（門一）**

- [ ] Envoy 的 SDS 來源指向 SPIRE Agent socket，憑證與 trust bundle 都走 SDS（不落靜態檔）。
- [ ] 對方身分比對用 `san_type: URI` 比 SPIFFE ID，**沒有**任何比對 DNS name／主機名的殘留（承 Day75/80）。
- [ ] 每個走 mesh 的 workload 都有對應 SPIRE registration entry（沒 entry＝Envoy 連上 SDS 也拿不到 SVID）。
- [ ] SVID 輪替走 SDS 串流（不重啟）；監控 SDS 通道／Agent 可用性（承 Day79/80）。

**sidecar 注入器（門二，承 Day07/86）**

- [ ] `MutatingWebhookConfiguration`／injector 模板（ConfigMap）的寫入權限收到只有平台團隊（改模板＝改每個 pod）。
- [ ] 注入範圍用明確 label／annotation 選入，不是全叢集預設注入；不需要身分的 pod 不被注入。
- [ ] 注入的 sidecar 模板本身過 PodSecurity（runAsNonRoot、drop caps、readOnlyRootFilesystem，承 Day86）。

**授權（門三，承 Day07/49/81）**

- [ ] 每個有 workload 的 namespace（或整個 mesh）都鋪了預設拒絕的 `AuthorizationPolicy`（`spec: {}`）。
- [ ] 沒有任何 policy 的 `principals` 含 `*`；來源逐一用確切 SPIFFE ID 列舉。
- [ ] `from.source.principals` 填的是上游 ID（允許誰來），`selector` 才是被保護的服務——方向沒填反。
- [ ] authZ 收到方法＋路徑層級（承 Day49），不是只到服務層。

**繞過與明文（第五節，承 Day38，細節見 Day88）**

- [ ] 應用只綁 `127.0.0.1` 給 sidecar，不綁 `0.0.0.0` 對整個 pod 網路開埠。
- [ ] `PeerAuthentication` 為 `STRICT`（非 `PERMISSIVE`）；沒有隨手 `excludeInboundPorts`。
- [ ] 應用若讀 XFCC 做授權，已確認外部無法繞過 sidecar 注入該 header。
- [ ] 多容器 pod 內不混入不受信任的容器（loopback 明文段共用 network namespace）。

---

## 九、測試 / 演練建議

- **繞過 sidecar 直連測試（最重要）**：從一個「未注入 sidecar」的 pod，用純 HTTP 直打目標 pod 的應用埠（pod IP:appPort），斷言**連不上或被拒**。連得上＝你的 mesh 保護全被跳過（mTLS、policy、XFCC 都沒了）——這是 Day88 STRICT＋NetworkPolicy 的存在證明。
- **預設拒絕存在測試**：對一個沒有明確 ALLOW 規則的服務發請求，斷言**被拒**。若被放行，代表該 namespace 沒鋪預設拒絕＝預設全通。
- **萬用 principal 迴歸**：把某條 policy 的 `principals` 從確切 ID 放寬成 `["*"]`，斷言第六節的 CI／稽核**判紅**。測不過代表你的 authZ 收窄是擺設。
- **principal 方向測試**：用一個**不在允許清單**的 SPIFFE ID（別的服務）帶著合法 SVID 呼叫受保護服務，斷言**被拒**——證明 policy 真的在比對來源，而不是形同虛設。
- **SVID 輪替不中斷（承 Day80）**：把 SVID 效期設短，跑超過一個效期，斷言 mesh 連線仍正常、且 Envoy 換上了新序號的憑證——驗證 SDS 串流熱換有效。
- **URI vs DNS 比對**：確認 Envoy／policy 是用 SPIFFE ID（URI SAN）判身分；故意用一個 DNS name 條件，斷言**匹配不到**（SVID 沒 DNS SAN，承 Day75）。
- **注入範圍演練（門二）**：對一個「不該有身分」的 namespace 部署 pod，斷言它**不會**被注入 Envoy／SPIRE SDS（注入範圍＝身分發放範圍，承 Day86）。
- **XFCC 偽造測試**：從繞過 sidecar 的路徑送一個自捏的 XFCC header 給應用，斷言應用**不會**因此授權——若會，代表應用把 HTTP header 當成了密碼學身分（承 Day38）。

---

## 十、一句話總結

> Day86 把「應用連不連得上 socket」收好之後，mesh 乾脆讓應用不碰 socket——但**身分沒有消失，只是搬家了**，你得知道它搬去哪、那裡的門有沒有關。搬去了三個地方，就是三道新的門：**門一，Envoy 透過 SDS 向 SPIRE Agent 拿 SVID 與 trust bundle**——SPIRE Agent 的 Workload API 同時講 Envoy SDS 協定，憑證與 bundle 都是串流訂閱、輪替熱換不重啟（承 Day79/80），而且 Envoy 連 Agent socket 一樣要過 attestation（Day84/86 兩道門一個沒少，只是守門對象從應用換成 sidecar），對方身分比對的永遠是 SAN 的 URI 不是主機名（承 Day75）；**門二，sidecar 是 mutating webhook 注入進來的**——這個 injector 能改寫全叢集每個 pod 的 spec，是比 Day86 的 `hostPath` 更集中、爆炸半徑更大的高權限點，「注入範圍」就等於「身分發放範圍」，模板與範圍沒人管，攻擊面只是從應用搬到了控制平面（承 Day07）；**門三，mTLS 驗過身分 ≠ 允許他做事**——這是 mesh 最致命的假安全，Envoy 幫你把 authN 做得漂亮，但 authZ 要你自己鋪：先用 `spec: {}` 的 `AuthorizationPolicy` 把 namespace 翻成預設拒絕，再逐一用**確切 SPIFFE ID** 當 `principals` 開通、收到方法＋路徑層級（承 Day49），永遠不要 `principals: ["*"]`（那是 Day81 `MemberOf` 的翻版：把「自己人就放行」的 authN 當成了 authZ），而且 `from` 填的是「允許誰來呼叫我」別填反（承 Day81）。最後是「sidecar 幫我做」的兩面刃：好處是身分與 mTLS 徹底離開應用碼、連 go-spiffe／java-spiffe 都不用寫，壞處是**應用對「跟誰通話」變無感**（authZ 掉進應用與平台之間沒人負責的縫）、**pod 內應用到 sidecar 那段是 loopback 明文**（隔離邊界是 pod 不是容器）、以及最大的隱形破口——**繞過 sidecar 直連**（應用綁 `0.0.0.0`、PERMISSIVE、排除埠、直打 pod IP，就能把 mTLS／policy／XFCC 全跳過，承 Day38）。一句話：**mesh 把身分的驗、發、授權從應用碼平台化了，但它把責任搬到了 SDS 通道、注入器、與 policy 三個新落點——mesh 的所有保護都建立在「流量真的走了 sidecar」這個不自動成立的前提上。**

---

## 延伸閱讀

- Day80 SPIFFE / SPIRE workload identity——本篇上游：Workload API、attestation 兩層、SVID／mTLS 基礎、sidecar／mesh 形態都在這，今天只展開「mesh 模式下身分搬去哪」。
- Day81 JWT-SVID 與 audience——authN≠authZ 的同一根釘子；`principals: ["*"]` 就是 `AuthorizeMemberOf` 的 mesh 版，方向填反也是同一種錯。
- Day82 SPIFFE Federation——mesh federation：SPIRE 透過 Envoy SDS 餵 federated bundle、授權收窄點同樣落在 `AuthorizationPolicy` 的 principals。
- Day84 SPIRE workload attestation selector——Envoy 連 SDS 一樣被 selector 反查；閘門二在 mesh 裡守的是 sidecar。
- Day86 Workload API socket 存取控制——閘門一；mesh 用 SPIFFE CSI Driver 把 socket 掛給 sidecar，本篇是它第五節的展開。
- Day07 Broken Access Control——預設拒絕、最小權限：`AuthorizationPolicy` 預設拒絕、injector 權限收窄都是它的搬移。
- Day49 BFLA——authZ 收到方法／路徑層級，不是只到服務層。
- Day38 X-Forwarded-For Spoofing——繞過 sidecar 直連、XFCC header 可被自捏，都是「繞過前置元件、偽造轉發 header」的同源問題。
- Day75 TLS 憑證驗證 MITM——為什麼比 SAN URI 不比 DNS name；別在 Envoy 退回主機名驗證。

---

明天預告：**Day 88 — mesh 全域強制 mTLS 與「繞過 sidecar」的封堵：PeerAuthentication STRICT mode、NetworkPolicy 縱深、以及 workload 綁 `0.0.0.0` vs `127.0.0.1` 的差別（延伸篇）**
（這是**延伸篇**，不重講 Day19／74／75 的 mTLS 與憑證驗證基礎、也不重講今天的 SDS 接線與 AuthorizationPolicy。今天第五節把「繞過 sidecar 直連」點名為 mesh 最大的隱形破口、只給了結論沒展開；明天整篇處理「怎麼強制流量真的走 sidecar」：**① `PeerAuthentication` 的 `STRICT` vs `PERMISSIVE`**——PERMISSIVE 同時收 mTLS 與明文（遷移期用，卻常忘了收），攻擊者送純 HTTP 就跳過身分；STRICT 拒絕一切非 mTLS 流量，示範怎麼分 namespace／workload 漸進收到全域 STRICT、以及收之前怎麼用 Day16 access log 確認「還有誰在送明文」免得一刀切斷線；**② 應用綁 `0.0.0.0` vs `127.0.0.1` 的生死差別**——Java（Spring Boot `server.address`／`InetSocketAddress`）與 Go（`net.Listen("tcp", ":8080")` vs `"127.0.0.1:8080"`）綁在哪，直接決定「應用埠有沒有對整個 pod 網路裸奔」，只綁 loopback 才逼所有流量非走 sidecar 不可；**③ NetworkPolicy 當縱深**——就算 STRICT 了，NetworkPolicy 仍要把「誰能連到誰的 pod IP」收到預設拒絕（承 Day07），因為 STRICT 是 L7 mesh 的事、NetworkPolicy 是 L3/L4 的事，兩層各擋一種繞過；以及 `excludeInboundPorts`／headless service／`hostNetwork` 這些「合法但打洞」的設定怎麼稽核。程式面會示範 `PeerAuthentication: STRICT` 與 default-deny `NetworkPolicy` 的 YAML、Go／Java 服務正確只綁 loopback 的寫法、以及一支掃「PERMISSIVE 殘留＋綁 0.0.0.0＋排除埠」的稽核工具。安全主軸一句話：**Day87 說 mesh 的保護全建立在「流量真的走了 sidecar」上，Day88 就把這個前提從「假設」變成「強制」——STRICT 擋明文、只綁 loopback 擋繞過、NetworkPolicy 收 L3/L4，三層一起把「繞過 sidecar」這條路封死。** 這是延伸篇，只聚焦「強制流量進 sidecar」的三層封堵，不重述 mTLS 握手與 SVID 基礎。）
