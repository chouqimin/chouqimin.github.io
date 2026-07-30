---
title: "Day 88：mesh 全域強制 mTLS 與封堵「繞過 sidecar」——PeerAuthentication STRICT、只綁 127.0.0.1、NetworkPolicy 縱深，把『流量真的走了 sidecar』從假設變強制（延伸篇）"
date: 2026-07-28
tags: ["Istio", "mTLS", "NetworkPolicy", "sidecar"]
---

接續 Day87 預告：Day87 第五節把「繞過 sidecar 直連」點名為 mesh 最大的隱形破口——攻擊者純 HTTP 直打 `pod IP:appPort`，mTLS、AuthorizationPolicy、XFCC 全部跳過——當時只給了結論、沒展開。今天整篇處理那個結論的另一半：**mesh 的所有保護都建立在「流量真的走了 sidecar」這個前提上；這個前提不會自動成立，你得用三層一起把它從『假設』變成『強制』。**

**這篇是延伸篇，不重講 Day19／74／75 的 mTLS 握手與憑證驗證基礎，也不重講 Day87 的 SDS 接線與 AuthorizationPolicy。** SVID 怎麼發、Envoy 怎麼透過 SDS 拿憑證、`principals` 怎麼寫、XFCC 是什麼——前面都講過，今天不重述。這篇只聚焦一件事：**怎麼讓「打進來的流量沒有任何一條路能繞過 Envoy」。**

延伸角度只有一條主軸：**Day87 的 authN／authZ 全是「流量已經進了 Envoy」之後的事；只要有一條路能讓封包在不碰 Envoy 的情況下抵達應用埠，前面兩天講的全數作廢。** 這條「繞過」不是單一破口，是三類前提各自會破，所以要三層各擋一種：**① `PeerAuthentication` `STRICT`**——把 Envoy 這一跳的「明文也收」關掉，堵住 PERMISSIVE 殘留；**② 應用只綁 `127.0.0.1`**——讓應用埠物理上不在 pod 網路上裸露，逼所有流量非走 sidecar 不可；**③ `NetworkPolicy` 預設拒絕**——在 L3/L4 收「誰能連到這個 pod IP」，擋掉 STRICT（L7）根本管不到的那條路。三層擋的是三種不同的繞過，缺一層就留一條路。

> ⚠️ 以下 Istio `PeerAuthentication`／annotation（`traffic.sidecar.istio.io/...`）、Kubernetes `NetworkPolicy`、Envoy 攔截埠（15006／15001／15020）等，都會隨你的 Istio／CNI／K8s 版本與 mesh 形態（sidecar vs ambient）不同。實際請對照你那套的官方 manifest，別照抄字串與埠號。這裡示範的是**三層各擋哪一類繞過**的意圖，不是某一版的精確語法。

---

## 一、先定位：三種繞過，三層封堵

先把「繞過 sidecar」拆成三條具體的路，才知道為什麼要三層、每層擋哪一條：

```text
[正常路徑] caller Envoy ──mTLS──▶ 目標 Envoy(15006) ──明文 loopback──▶ 目標 app(127.0.0.1:8080)

[繞過 A：明文被 Envoy 收下]  攻擊者 ──純 HTTP──▶ 目標 Envoy(15006) ──▶ app
                            破口：PeerAuthentication 停在 PERMISSIVE，Envoy 明文也收 ⇒ 身分沒驗
                            擋它的：層一 STRICT（Envoy 拒收非 mTLS）

[繞過 B：根本不進 Envoy]     攻擊者 ──純 HTTP 直打 pod IP:8080──▶ app（app 綁了 0.0.0.0）
                            破口：app 在 pod 網路介面上裸露 appPort；只要攔截有缺口就直達
                            擋它的：層二 只綁 127.0.0.1（app 在 pod 網路上根本沒開埠）

[繞過 C：連線壓根不該存在]   任意 pod ──▶ 目標 pod IP（走 excludeInboundPorts / hostNetwork / 直連）
                            破口：STRICT 是 L7 的事，管不到「誰能對這個 pod IP 開 TCP 連線」
                            擋它的：層三 NetworkPolicy 預設拒絕（L3/L4 收斂可達性）
```

一句話定位：**Day87 的 mTLS 與 policy 都是「封包已經進了 Envoy」之後才生效；這三層做的事，是確保封包沒有別條路可以不進 Envoy 就抵達應用。** 三層分屬三個層次——STRICT 在 Envoy（L7 mesh）、綁 loopback 在應用進程（socket 綁定）、NetworkPolicy 在 CNI（L3/L4）——**正因為分屬不同層，才各自擋得住另外兩層看不到的那條路。**

---

## 二、封堵層一：`PeerAuthentication` `STRICT` vs `PERMISSIVE`

先講最直接、也最常被漏收的一層。`PeerAuthentication` 決定 **Envoy 這一跳「收不收非 mTLS 的流量」**：

- **`PERMISSIVE`（很多 mesh 的預設起點）**：Envoy **同時**接受 mTLS 與明文。這是為了**遷移期**——你把 sidecar 逐步鋪進去時，還沒注入 sidecar 的舊服務得能用明文繼續呼叫，不然一裝 mesh 全斷線。**但它的代價是：攻擊者送純 HTTP，Envoy 一樣收下、一樣轉給應用，身分驗證形同虛設。** PERMISSIVE 是「暫時的、給遷移用的」，最常見的災難就是**上線後忘了收**，於是「裝了 mTLS」變成一句假話。
- **`STRICT`**：Envoy **拒絕一切非 mTLS 流量**。這才是「真的強制 mTLS」——沒有合法 SVID、握不出 mTLS 的連線，在 Envoy 這一跳就被拒。

Istio 的 `PeerAuthentication` 有三個作用範圍，由寬到窄會**疊加覆蓋**（越窄的越優先）：

```yaml
# 範圍一：mesh 全域 STRICT —— 放在 root namespace（通常是 istio-system）、且沒有 selector＝套整個 mesh
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: istio-system      # root namespace；沒有 selector＝mesh-wide
spec:
  mtls:
    mode: STRICT
---
# 範圍二：單一 namespace STRICT（沒有 selector，但不在 root namespace＝只套這個 ns）
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: tenant-a
spec:
  mtls:
    mode: STRICT
```

**漸進收窄，別一刀切。** 直接把 mesh-wide 從 PERMISSIVE 翻成 STRICT，會**當場切斷所有還在送明文的連線**（沒注入 sidecar 的舊服務、外部監控探針、忘了走 mesh 的批次任務）。正確順序是**先收 namespace、再收 mesh-wide**，而且**收之前先用 Day16 的手段確認「還有誰在送明文」**：

```text
1. 先開 Envoy 的 mTLS 觀測（access log／telemetry），找出目前哪些入站連線是明文（無對端 SPIFFE ID）。
2. 逐一把那些明文來源改成走 mesh（注入 sidecar）或明確排除（見第五節）。
3. 確認某個 namespace 已無明文入站後，先對該 namespace 上 STRICT。
4. 全部 namespace 收乾淨後，才把 root namespace 的 mesh-wide 翻成 STRICT。
```

遷移期若某個埠實在還不能收（例如一個吐 Prometheus 指標、暫時還沒走 mesh 的埠），用 **port-level 覆寫**把「暫時放行」收斂到單一埠，而不是讓整個 workload 停在 PERMISSIVE：

```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: legacy-metrics
  namespace: tenant-a
spec:
  selector:
    matchLabels: { app: legacy-metrics }
  mtls:
    mode: STRICT              # 這個 workload 預設 STRICT
  portLevelMtls:
    9090:
      mode: PERMISSIVE        # 只有 9090 暫時放行明文（遷移期，記得追蹤收回）
```

**但層一有個天花板，正是為什麼需要層二、層三：`STRICT` 只管「進到 Envoy 的流量必須是 mTLS」——它管不到「封包根本沒進 Envoy」。** 如果攻擊者能讓封包在不經過 Envoy 攔截的情況下直達應用埠（繞過 B、C），STRICT 完全使不上力，因為 Envoy 根本沒看到那條連線。所以 STRICT 是必要條件，不是充分條件。

---

## 三、封堵層二：應用只綁 `127.0.0.1`——`0.0.0.0` 的生死差別

這是三層裡**最常被後端工程師忽略、卻最關鍵**的一層，而且它就在**你的應用碼裡**，不在平台 YAML 裡。

先講機制。Envoy 幫應用終結 mTLS 之後，是**用 loopback 把明文轉給應用**（`127.0.0.1:appPort`）。也就是說：

- **應用只要綁 `127.0.0.1`，就能正常收到 sidecar 轉進來的流量**——因為 sidecar 就是從 loopback 連進來的。
- **但應用如果綁 `0.0.0.0`（所有介面），它就同時在 pod 網路介面上裸露了 `appPort`。** Istio 的 inbound iptables 通常會把打向 `pod IP:appPort` 的流量重導向 Envoy，但**這層攔截有前提，而且前提會破**：`excludeInboundPorts` 排除掉的埠、PERMISSIVE 殘留、同 pod 內另一個容器共用 network namespace 從內部直打、`hostNetwork` pod、以及攔截規則本身被誤設或未涵蓋的路徑。**只要攔截在任何一種情況下沒生效，綁 `0.0.0.0` 的應用就直接可達——mTLS、policy、XFCC 全跳過。**

所以層二的價值是**縱深防禦，不依賴單一攔截機制**：

```text
綁 0.0.0.0：app 在 pod 網路上開著 appPort，「繞不繞得過」取決於 iptables 攔截有沒有生效 ← 靠單一機制
綁 127.0.0.1：app 在 pod 網路上根本沒開埠，唯一入口是 loopback＝sidecar ← 物理上不可達，不靠攔截
```

一句話：**綁 `127.0.0.1` 是把「繞過」從『靠 iptables 攔得住』升級成『物理上不可達』——除了 loopback（就是 sidecar），沒有第二條路進得來。** 這件事平台幫不了你，只有應用自己選擇綁哪個介面。

### Go：`net.Listen` 綁哪裡

```go
// ❌ 綁全介面：pod IP:8080 也裸露在 pod 網路上
ln, _ := net.Listen("tcp", ":8080")            // ":8080" 等同綁所有介面（0.0.0.0 / ::）
_ = http.Serve(ln, handler)

// ✅ 只綁 loopback：唯一入口是 sidecar 從 127.0.0.1 轉進來
srv := &http.Server{
    Addr:    "127.0.0.1:8080",                 // 明確綁 loopback
    Handler: handler,
}
log.Fatal(srv.ListenAndServe())
```

gRPC（承 Day51）同理——別用會綁 wildcard 的寫法：

```go
// ❌ ":50051" 綁全介面
lis, _ := net.Listen("tcp", ":50051")
// ✅ 綁 loopback
lis, _ := net.Listen("tcp", "127.0.0.1:50051")
grpcServer.Serve(lis)
```

### Java：Spring Boot 與原生 socket 綁哪裡

Spring Boot **預設綁所有介面（`0.0.0.0`）**，用 `server.address` 收成 loopback；**別忘了管理／actuator 埠也要一起收**（它常是另一個獨立埠、也常被漏掉）：

```properties
# application.properties
server.address=127.0.0.1
management.server.address=127.0.0.1
```

原生 `ServerSocket`／`InetSocketAddress`／gRPC-Java（承 Day51）——注意「只給埠號」的建構子都是綁 wildcard：

```java
// ❌ 綁全介面（wildcard）
new ServerSocket(8080);                                       // bindAddr=null＝0.0.0.0
new InetSocketAddress(8080);                                  // wildcard

// ✅ 只綁 loopback
new ServerSocket(8080, 50, InetAddress.getLoopbackAddress()); // 第三參數指定綁定位址
new InetSocketAddress("127.0.0.1", 8080);

// gRPC-Java（承 Day51）：forPort(...) 綁 wildcard，改用 forAddress(...) 綁 loopback
io.grpc.Server s = NettyServerBuilder
        .forAddress(new InetSocketAddress("127.0.0.1", 50051))
        .addService(new LedgerService())
        .build()
        .start();
```

> Java 1.8 沒有 `java.net.http.HttpClient`，但上面 `ServerSocket`／`InetSocketAddress`／`InetAddress.getLoopbackAddress()` 在 1.8 與 21 都一樣可用；Spring Boot 的 `server.address`／`management.server.address` 屬性也是兩版通用。

### 一個必踩的維運坑：綁 loopback 之後，健康檢查怎麼進得來？

kubelet 的 HTTP `livenessProbe`／`readinessProbe` 是**從 node 打向 `pod IP:port`** 的——你把應用收成只綁 `127.0.0.1` 之後，kubelet 直接打 pod IP 會**連不上、探針失敗、pod 被反覆重啟**。解法不是把埠重新綁回 `0.0.0.0`（那等於白做），而是**讓探針也走 sidecar**：Istio 的 probe rewrite（`sidecar.istio.io/rewriteAppHTTPProbers`，近代版本預設開啟）會把 httpGet 探針改導向 pilot-agent（15020），由它經 sidecar 打到應用。**收 loopback 前先確認探針改寫有生效，否則你會用一次滾動更新把服務打掛。** 這是「綁 loopback」在 K8s 上最典型的翻車點。

---

## 四、封堵層三：`NetworkPolicy` 當 L3/L4 縱深

STRICT 收了 Envoy 那一跳、綁 loopback 收了應用埠的裸露——但還有一類繞過它們都管不到：**「誰能對這個 pod IP 開一條 TCP 連線」本身。** 這是 L3/L4 的事，`STRICT` 是 L7 mesh 的事，兩者根本不在同一層：

```text
STRICT（L7，Envoy 執行）      ：進到 Envoy 的流量「必須帶 mTLS 身分」——但管不到沒進 Envoy 的連線
NetworkPolicy（L3/L4，CNI 執行）：收斂「哪些來源能連到這個 pod IP 的哪個埠」——不看 mTLS，只看 IP/port
```

為什麼需要它？因為 **`hostNetwork` pod、`excludeInboundPorts` 排除的埠、node 層直連、CNI 特定路徑**這些「連線根本沒進 Envoy」的情況，STRICT 一律看不到；而 `NetworkPolicy` 是在 CNI 層擋「這條 TCP 連線准不准建立」，**不管你有沒有走 mesh**。所以它是 Day07「預設拒絕」在 L3/L4 的落點：先鋪一張**預設拒絕入站**，再逐一按 pod selector 開通。

```yaml
# ① 預設拒絕入站：選中 namespace 內所有 pod、沒有任何 ingress rule＝全部拒絕
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-a
spec:
  podSelector: {}                 # 空 selector＝套用到 ns 內每個 pod
  policyTypes: ["Ingress"]        # 只宣告 Ingress 型別、且不給 ingress 陣列＝入站全拒
---
# ② 明確允許：只有 order-service 能連 ledger-service 的 8080
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-order-to-ledger
  namespace: tenant-a
spec:
  podSelector:
    matchLabels: { app: ledger-service }   # 被保護的一方
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - podSelector:
            matchLabels: { app: order-service }   # 允許誰來連
      ports:
        - protocol: TCP
          port: 8080
```

三個要點：

- **`NetworkPolicy` 看不到 mTLS 身分**——它只認 pod selector／namespace／IP/port。所以它和 STRICT 是 **AND、不是替代**：`NetworkPolicy` 收「誰能連上」，STRICT 收「連上的人必須出示 mTLS 身分」。兩層擋兩種繞過，**一層都不能省**（承 Day07 default deny、Day87 authN≠authZ 的同構邏輯——這裡是「可達性」與「身分」各管一半）。
- **`policyTypes` 要寫明**。一個沒有 `ingress` 陣列、但 `policyTypes: ["Ingress"]` 的 policy 才是「入站全拒」；漏掉 `policyTypes` 或方向寫錯，預設拒絕就沒生效。出站要收就再加 `Egress`（和明天 egress 主題相關）。
- **`NetworkPolicy` 要 CNI 支援才有效**。不是每個 CNI 都執行 `NetworkPolicy`；用之前確認你的 CNI（Calico／Cilium 等）真的在強制它，否則你以為鋪了預設拒絕、其實 policy 是張廢紙——**這點務必用第六節的實測驗證，別假設。**

---

## 五、「合法但打洞」的設定：`excludeInboundPorts` / headless service / `hostNetwork`

三層鋪好之後，真正的漏水點往往是這些**「合法、有正當用途、但一設就打洞」**的旋鈕。它們不是 bug，是為特定需求存在的例外——問題在於**沒人稽核它們**：

- **`traffic.sidecar.istio.io/excludeInboundPorts`**：明確叫 Istio「這些入站埠**不要**攔進 Envoy」。用途是某些埠不能走 mesh（例如特殊協定）。代價：**這些埠上的流量完全不經 Envoy＝沒有 mTLS、沒有 AuthorizationPolicy、沒有 XFCC。** 每一個被排除的埠都是一個 STRICT 管不到的洞。能不用就不用；要用就用 `includeInboundPorts` 反過來**白名單**只納入該攔的埠，範圍更收斂。
- **headless service（`clusterIP: None`）**：client 直接拿到 pod IP 清單、直連 pod IP。正常情況 inbound iptables 仍會把它導進 Envoy，但**一旦搭上應用綁 `0.0.0.0`，直連 pod IP 就更容易命中裸露的應用埠**。headless + 綁 loopback + `NetworkPolicy` 一起看才安全。
- **`hostNetwork: true`**：pod 共用 **node 的** network namespace，per-pod 的 sidecar iptables 攔截**在這種 pod 上不成立**——等於整個 mesh 攔截失效，應用埠直接開在 node 上。這是最粗暴的繞過，通常只有基礎設施元件才該用；**應用 pod 出現 `hostNetwork: true` 幾乎都是紅旗。**
- 其它同類旗標：`sidecar.istio.io/inject: "false"`（整個 pod 不注入 sidecar＝根本沒 mesh 保護）、自訂 `interceptionMode`／`excludeOutboundPorts` 等。

一句話：**這些設定合法，但每一個都在你三層封堵上開一道後門；它們不該被禁止，該被『稽核到、有人簽核、有清單』。** 這正好接到第六節——把「有沒有人偷開後門」寫成靜態掃描。

---

## 六、Day16 稽核：靜態掃 PERMISSIVE 殘留 + 打洞設定，執行期抓明文直連

mesh 「繞過」的幾個最危險狀態——**PERMISSIVE 殘留、`excludeInboundPorts` 打洞、`hostNetwork` 繞過、namespace 沒有預設拒絕 `NetworkPolicy`**——都能靜態掃出來。把它寫成 CI／admission，就是 Day16「把偵測升級成預防」在這裡的落點（承 Day87 第六節的同一套心法：先在 chat／CI 跑一次看資料長相，再寫解析）。

先看資料長相：

```bash
kubectl get peerauthentication -A -o json
kubectl get pods -A -o json
kubectl get networkpolicy -A -o json
```

**Go 版**：掃 `PeerAuthentication` 抓「非 `STRICT`（含 port-level）」，掃 pod 抓 `excludeInboundPorts` 與 `hostNetwork`。

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type paList struct {
	Items []struct {
		Metadata struct{ Name, Namespace string } `json:"metadata"`
		Spec     struct {
			Mtls          *struct{ Mode string } `json:"mtls"`
			PortLevelMtls map[string]struct {
				Mode string `json:"mode"`
			} `json:"portLevelMtls"`
		} `json:"spec"`
	} `json:"items"`
}

type podList struct {
	Items []struct {
		Metadata struct {
			Name, Namespace string
			Annotations     map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			HostNetwork bool `json:"hostNetwork"`
		} `json:"spec"`
	} `json:"items"`
}

func kubectlJSON(v any, args ...string) {
	out, err := exec.Command("kubectl", args...).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kubectl 失敗：", err)
		os.Exit(2)
	}
	if err := json.Unmarshal(out, v); err != nil {
		fmt.Fprintln(os.Stderr, "JSON 解析失敗：", err)
		os.Exit(2)
	}
}

func main() {
	fail := false

	// ① PeerAuthentication：任何非 STRICT（含 port-level）都點名
	var pas paList
	kubectlJSON(&pas, "get", "peerauthentication", "-A", "-o", "json")
	for _, p := range pas.Items {
		if p.Spec.Mtls != nil && p.Spec.Mtls.Mode != "STRICT" {
			fmt.Printf("FAIL %s/%s：mtls.mode=%s（非 STRICT，明文可繞過身分）\n",
				p.Metadata.Namespace, p.Metadata.Name, p.Spec.Mtls.Mode)
			fail = true
		}
		for port, m := range p.Spec.PortLevelMtls {
			if m.Mode != "STRICT" {
				fmt.Printf("FAIL %s/%s：port %s mtls.mode=%s（port-level 放行明文）\n",
					p.Metadata.Namespace, p.Metadata.Name, port, m.Mode)
				fail = true
			}
		}
	}

	// ② Pod：excludeInboundPorts（打洞）與 hostNetwork（整台繞過 sidecar）
	var pods podList
	kubectlJSON(&pods, "get", "pods", "-A", "-o", "json")
	for _, pod := range pods.Items {
		if v := pod.Metadata.Annotations["traffic.sidecar.istio.io/excludeInboundPorts"]; v != "" {
			fmt.Printf("FAIL %s/%s：excludeInboundPorts=%q（這些埠完全不經 Envoy＝無 mTLS/policy）\n",
				pod.Metadata.Namespace, pod.Metadata.Name, v)
			fail = true
		}
		if pod.Spec.HostNetwork {
			fmt.Printf("FAIL %s/%s：hostNetwork=true（共用 node netns，sidecar 攔截失效）\n",
				pod.Metadata.Namespace, pod.Metadata.Name)
			fail = true
		}
	}

	if fail {
		os.Exit(1)
	}
	fmt.Println("OK：無非 STRICT PeerAuthentication、無 excludeInboundPorts / hostNetwork 打洞")
}
```

**Java 版**（Jackson，對稱邏輯，跑在 CI 或維運工具裡）：

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Iterator;

public class MeshBypassAudit {
    static final ObjectMapper OM = new ObjectMapper();

    static JsonNode kubectl(String... args) throws Exception {
        String[] cmd = new String[args.length + 1];
        cmd[0] = "kubectl";
        System.arraycopy(args, 0, cmd, 1, args.length);
        Process p = new ProcessBuilder(cmd).redirectErrorStream(false).start();
        return OM.readTree(p.getInputStream());
    }

    public static void main(String[] args) throws Exception {
        boolean fail = false;

        // ① PeerAuthentication 非 STRICT（含 port-level）
        for (JsonNode it : kubectl("get", "peerauthentication", "-A", "-o", "json").path("items")) {
            String ns = it.path("metadata").path("namespace").asText();
            String name = it.path("metadata").path("name").asText();
            JsonNode mtls = it.path("spec").path("mtls");
            if (!mtls.isMissingNode()) {
                String mode = mtls.path("mode").asText("PERMISSIVE");
                if (!"STRICT".equals(mode)) {
                    System.out.printf("FAIL %s/%s：mtls.mode=%s（非 STRICT）%n", ns, name, mode);
                    fail = true;
                }
            }
            JsonNode ports = it.path("spec").path("portLevelMtls");
            Iterator<String> fields = ports.fieldNames();
            while (fields.hasNext()) {
                String port = fields.next();
                String mode = ports.path(port).path("mode").asText("PERMISSIVE");
                if (!"STRICT".equals(mode)) {
                    System.out.printf("FAIL %s/%s：port %s mtls.mode=%s%n", ns, name, port, mode);
                    fail = true;
                }
            }
        }

        // ② Pod excludeInboundPorts / hostNetwork
        for (JsonNode pod : kubectl("get", "pods", "-A", "-o", "json").path("items")) {
            String ns = pod.path("metadata").path("namespace").asText();
            String name = pod.path("metadata").path("name").asText();
            String ex = pod.path("metadata").path("annotations")
                    .path("traffic.sidecar.istio.io/excludeInboundPorts").asText("");
            if (!ex.isEmpty()) {
                System.out.printf("FAIL %s/%s：excludeInboundPorts=%s（不經 Envoy）%n", ns, name, ex);
                fail = true;
            }
            if (pod.path("spec").path("hostNetwork").asBoolean(false)) {
                System.out.printf("FAIL %s/%s：hostNetwork=true（sidecar 攔截失效）%n", ns, name);
                fail = true;
            }
        }

        if (fail) System.exit(1);
        System.out.println("OK：無非 STRICT PeerAuthentication、無打洞設定");
    }
}
```

兩個 CI 掃不到、但一定要補的角度：

- **「namespace 有 workload 卻沒有預設拒絕 `NetworkPolicy`」**：延用 Day87 第六節那支稽核的 `nsHasDefaultDeny` 邏輯——掃 `kubectl get networkpolicy -A -o json`，對「`podSelector: {}` 且 `policyTypes` 含 `Ingress`、且無 `ingress` 陣列」記為該 ns 有預設拒絕，再對照有 workload 卻沒有預設拒絕的 ns 判紅。
- **「應用到底綁在哪個介面」CI 幾乎看不到**——因為那是**執行期**才觀察得到的 socket 狀態。補法有兩種：一是**執行期實測**（見第九節，從未注入 sidecar 的 pod 直打 pod IP:appPort 斷言被拒），二是**在 pod 內加一個啟動自檢**，用 `ss -tlnp` / `netstat` 斷言應用埠只 listen 在 `127.0.0.1`、一旦看到 `0.0.0.0:appPort` 就讓 pod 啟動失敗。前者測「繞得過嗎」，後者測「有沒有裸露」。

**執行期承 Day16**：在把 mesh-wide 翻成 STRICT **之前**，先把 Envoy 的 mTLS 觀測打進 SIEM，比對「哪些入站連線帶了對端 SPIFFE ID（走了 mTLS）、哪些是明文」，對後者告警——這既是第二節「收之前先確認還有誰在送明文」的資料來源，也是上線後「有人偷送明文／偷繞 sidecar」的偵測線。**因為 policy 與 STRICT 掃得再乾淨，都擋不住『根本沒走 sidecar』的流量；那條只能靠執行期的可達性測試與流量稽核抓。**

---

## 七、常見誤區

| 誤區 | 為什麼錯 |
|---|---|
| 「裝了 Istio、開了 mTLS 就是強制 mTLS」 | 預設常是 `PERMISSIVE`＝明文也收。沒翻成 `STRICT`，攻擊者送純 HTTP 一樣被 Envoy 收下（第二節） |
| 「`PERMISSIVE` 只是寬鬆一點，還算安全」 | 它讓身分驗證形同虛設——遷移期用的暫時態，忘了收＝「裝了 mTLS」是假話（第二節） |
| 「`STRICT` 開了就滴水不漏」 | STRICT 只管「進到 Envoy 的流量要 mTLS」，管不到「封包根本沒進 Envoy」（繞過 B/C）——是必要非充分（第二、三節） |
| 「應用綁哪個介面是效能／方便問題，跟資安無關」 | 綁 `0.0.0.0`＝appPort 在 pod 網路上裸露，攔截一破就直達；綁 `127.0.0.1`＝物理上只有 sidecar 進得來（第三節） |
| 「反正 iptables 會把流量導進 Envoy」 | 攔截有前提會破：排除埠、PERMISSIVE、同 pod 內鄰居、hostNetwork、規則誤設。別靠單一機制（第三、五節） |
| 「綁 loopback 後健康檢查掛了，那就綁回 `0.0.0.0`」 | 那等於白做。正解是讓探針走 sidecar（probe rewrite），不是把埠重新裸露（第三節） |
| 「有了 STRICT，`NetworkPolicy` 是多餘的」 | STRICT 是 L7、`NetworkPolicy` 是 L3/L4，擋不同的繞過；沒進 Envoy 的連線只有 `NetworkPolicy` 擋得到（第四節） |
| 「鋪了 `NetworkPolicy` 就一定生效」 | 要 CNI 支援並強制才算數；沒支援的 CNI 上它是張廢紙——一定要實測（第四節） |
| 「`excludeInboundPorts` 只是維運細節」 | 每個被排除的埠都完全不經 Envoy＝該埠無 mTLS/policy/XFCC，是 STRICT 管不到的洞（第五節） |
| 「`hostNetwork: true` 沒什麼大不了」 | 共用 node netns＝per-pod sidecar 攔截失效＝整個 mesh 保護對這 pod 不成立（第五節） |
| 「繞過 sidecar 是理論風險，不會真的發生」 | 綁 `0.0.0.0`＋PERMISSIVE 殘留＋沒有 `NetworkPolicy`，任何同網段 pod 純 HTTP 直打就成立（承 Day87/Day38） |

---

## 八、Code Review / 維運 checklist

**層一：`PeerAuthentication` STRICT（第二節）**

- [ ] mesh-wide（root namespace、無 selector）最終為 `STRICT`；沒有殘留的 mesh 級 `PERMISSIVE`。
- [ ] 各 namespace 的 `PeerAuthentication` 為 `STRICT`；`portLevelMtls` 沒有忘了收的 `PERMISSIVE`。
- [ ] 遷移期的 `PERMISSIVE` 都有到期追蹤與負責人，不是「先開著再說」。
- [ ] 翻 STRICT 前已用 Envoy mTLS 觀測確認「無明文入站」，採 namespace→mesh-wide 漸進收窄（承 Day16）。

**層二：應用只綁 loopback（第三節）**

- [ ] 應用主埠綁 `127.0.0.1`，不綁 `0.0.0.0`／`:port`（Go `net.Listen`、Java `server.address`／`ServerSocket` bindAddr）。
- [ ] 管理／actuator／metrics／gRPC 等**次要埠也一起收**（`management.server.address`、gRPC 用 `forAddress` 非 `forPort`）。
- [ ] 收 loopback 後，健康檢查改走 sidecar（probe rewrite 已生效），滾動更新不會把服務打掛。

**層三：`NetworkPolicy` 縱深（第四節，承 Day07）**

- [ ] 每個有 workload 的 namespace 都鋪了預設拒絕入站（`podSelector: {}` + `policyTypes: ["Ingress"]`、無 ingress rule）。
- [ ] 允許規則逐一按 pod selector／namespace + port 開通，不用寬鬆的全通。
- [ ] 已實測確認 CNI 真的在強制 `NetworkPolicy`（不是鋪了沒生效）。

**打洞設定與稽核（第五、六節，承 Day16）**

- [ ] 沒有非預期的 `excludeInboundPorts`；要用就改用 `includeInboundPorts` 白名單收斂。
- [ ] 應用 pod 無 `hostNetwork: true`、無 `sidecar.istio.io/inject: "false"`。
- [ ] CI／admission 掃「非 STRICT PeerAuthentication＋打洞 annotation＋缺預設拒絕 NetworkPolicy」並判紅。
- [ ] 執行期把「明文直連／未帶對端 SPIFFE ID」的流量打進 SIEM 告警。

---

## 九、測試 / 演練建議

- **繞過 sidecar 直連測試（最重要）**：從一個「未注入 sidecar」的 pod，用純 HTTP 直打目標 pod 的 `pod IP:appPort`，斷言**連不上或被拒**。連得上＝你的三層還有洞（app 綁了 `0.0.0.0`、或 `NetworkPolicy` 沒生效）——這正是 Day87 留下的破口，這條測試就是三層封堵的存在證明。
- **明文被拒測試（層一）**：對已 `STRICT` 的服務發**純 HTTP（非 mTLS）**請求，斷言**被 Envoy 拒**。若收下，代表 `PeerAuthentication` 還停在 `PERMISSIVE` 或沒生效。
- **應用只綁 loopback 測試（層二）**：在 pod 內跑 `ss -tlnp`，斷言應用埠只 listen 在 `127.0.0.1`、**沒有** `0.0.0.0:appPort`。看到 `0.0.0.0` 就是裸露。
- **健康檢查不中斷測試（層二）**：收成 loopback 後做一次滾動更新，斷言 liveness/readiness 探針全綠（probe rewrite 有效），服務不被反覆重啟。
- **`NetworkPolicy` 生效測試（層三）**：從一個**不在允許清單**的 namespace/pod 直連受保護 pod IP，斷言**連不上**；再從允許清單內連，斷言**通**——證明 CNI 真的在強制，而不是廢紙。
- **打洞迴歸（第五、六節）**：把某 pod 加上 `excludeInboundPorts` 或 `hostNetwork: true`，斷言第六節的 CI／admission **判紅**。測不過代表你的稽核是擺設。
- **STRICT 漸進切換演練（第二節）**：在測試叢集把某 namespace 從 `PERMISSIVE` 翻 `STRICT`，先斷言仍有明文來源時「該來源斷線、其餘正常」，驗證你的漸進順序與觀測能在切換前抓到殘留明文，避免正式環境一刀斷線。

---

## 十、一句話總結

> Day87 說 mesh 的所有保護都建立在「流量真的走了 sidecar」這個前提上，卻沒說這個前提**不會自動成立**；Day88 就把它從假設變強制——用三層各擋一種繞過，缺一層就留一條路。**層一 `PeerAuthentication` `STRICT`**：把 Envoy 這一跳的「明文也收」關掉（`PERMISSIVE` 是遷移期的暫時態，最常見的災難是上線後忘了收，於是「裝了 mTLS」變假話），收的時候要**先用 Day16 的 mTLS 觀測確認還有誰在送明文、採 namespace→mesh-wide 漸進切換**，別一刀斷線；但 STRICT 只管「進到 Envoy 的流量要 mTLS」、管不到「封包根本沒進 Envoy」，所以是必要非充分。**層二 應用只綁 `127.0.0.1`**：這是唯一在你應用碼裡的一層——Envoy 用 loopback 把明文轉給應用，所以應用只綁 loopback 就夠用，卻能讓 appPort **物理上不在 pod 網路裸露**，把「繞得過嗎」從『靠 iptables 攔』升級成『根本不可達』；Go 別用 `net.Listen("tcp", ":8080")`、Java 別讓 Spring Boot 停在預設 `0.0.0.0`（連 `management`／gRPC `forPort` 那些次要埠一起收），而且收之前確認**健康檢查走 sidecar**（probe rewrite），否則一次滾動更新把服務打掛。**層三 `NetworkPolicy` 預設拒絕**：STRICT 是 L7、`NetworkPolicy` 是 L3/L4，收的是「誰能對這個 pod IP 開連線」這件 STRICT 看不到的事，兩層是 AND（承 Day07 default deny），但要**實測確認 CNI 真的在強制**。最後是那些「合法但打洞」的旋鈕——`excludeInboundPorts`（該埠完全不經 Envoy）、headless service、`hostNetwork: true`（共用 node netns 讓 sidecar 攔截整個失效）——它們不該被禁止，該被**稽核到**：把「非 STRICT＋打洞 annotation＋缺預設拒絕 NetworkPolicy」寫成 CI／admission（承 Day16 把偵測升級成預防），執行期再對「明文直連／沒帶對端 SPIFFE ID」的流量告警。一句話：**Day87 把身分的驗發授權平台化了，Day88 把『流量真的走了 sidecar』這個所有保護的地基，用 L7（STRICT）＋進程（綁 loopback）＋L3/L4（NetworkPolicy）三層一起釘死——因為只要留一條繞過 Envoy 的路，前面兩天講的全數作廢。**

---

## 延伸閱讀

- Day87 SPIRE × service mesh——本篇上游：mesh 的 authN／authZ 全是「流量已進 Envoy」之後的事，第五節把「繞過 sidecar」點名為最大隱形破口、留給今天整篇處理。
- Day38 X-Forwarded-For Spoofing——繞過前置元件直連、偽造轉發 header 的同源問題；能繞過 sidecar 的人就能自捏 XFCC，這是三層封堵要防的攻擊者能力。
- Day07 Broken Access Control——預設拒絕、最小權限：`NetworkPolicy` 預設拒絕入站就是它在 L3/L4 的落點。
- Day10 / Day53 SSRF——egress allowlist 與出站控制；今天收的是入站，明天 egress 是同一件事的出站面。
- Day19 / Day74 / Day75 TLS / mTLS 基礎——STRICT 強制的就是這裡的 mTLS；今天不重述握手與憑證驗證，只講「怎麼逼流量非走它不可」。
- Day51 gRPC / Protobuf Security——gRPC server 綁 `forAddress(loopback)` 而非 `forPort(wildcard)`，同樣的 bind 陷阱。
- Day16 Security Logging / Monitoring——切 STRICT 前確認明文來源、上線後抓明文直連，都靠這裡的觀測與告警。

---

明天預告：**Day 89 — mesh egress：出站流量的身分與對外 mTLS——`ServiceEntry`／`DestinationRule`、egress gateway、防止應用繞過 egress 直接對外，以及「對第三方 API 的 mTLS 該由 mesh 還是應用做」（延伸篇）**
（這是**延伸篇**，不重講 Day19／74／75 的 mTLS 基礎、也不重講 Day10／53 的 SSRF 入門，更不重講今天的入站三層封堵。今天整篇在收**入站**——逼別人打進來的流量非走 sidecar 不可；明天翻到**出站**的鏡像面：**當你的服務主動往外打**（呼叫第三方支付 API、跨 mesh、對接雲端服務）時，身分怎麼跟著出站流量走、對外的 mTLS 該在哪裡終結、以及怎麼防止應用繞過受控的 egress 路徑直接對外。延伸角度三條：**① `ServiceEntry` 把「外部服務」納入 mesh 的認知**——沒被 `ServiceEntry` 宣告的外部目標，出站行為與可觀測性都是黑洞，這也是 Day10 SSRF「egress allowlist」在 mesh 的落點，但角度不同：Day10 防的是「應用被騙去打內網」，明天講的是「出站身分與對外加密該由誰負責」；**② `DestinationRule` 讓 Envoy 對外 originate TLS/mTLS**——把「對第三方的憑證與 mTLS」從應用碼搬到 sidecar（承 Day87 身分離開應用的同一主軸），示範 Java（`OkHttp`／Spring `RestClient`）與 Go（`http.Client`／`Transport`）「該不該自己在應用裡做對外 mTLS」的取捨；**③ egress gateway 與繞過**——就算鋪了 egress gateway，應用仍可能直接對外連而不經它（對稱於今天『繞過 sidecar』），怎麼用 `NetworkPolicy` egress 預設拒絕（承 Day07）＋出站攔截把「所有出站非走 egress 不可」釘死。程式面會示範 `ServiceEntry`＋`DestinationRule`（`ISTIO_MUTUAL`／`SIMPLE` originate TLS）的 YAML、Go／Java HTTP client「讓 mesh 終結對外 mTLS」與「應用自己做」兩種寫法的取捨、以及一支掃「對外目標沒有 `ServiceEntry`／egress 沒有預設拒絕」的稽核工具。安全主軸一句話：**Day88 收好了『別人怎麼打進來』，Day89 收『你怎麼打出去』——出站同樣要有身分、要受控、要防繞過，而且對外的信任邊界比內部更需要明確列舉。** 這是延伸篇，只聚焦 mesh 出站的身分與對外 mTLS，不重述 mTLS 握手與 SSRF 基礎。）
