---
title: "Day 86：SPIRE Workload API socket 的存取控制 — hostPath 直掛 vs SPIFFE CSI Driver、同機多租戶的第一道門（延伸篇）"
date: 2026-07-26
tags: ["SPIFFE", "SPIRE", "Workload API", "Kubernetes"]
---

接續 Day85 預告：Day80 把 attestation 講成兩層——node attestation 先確認「跑 Agent 的機器可信」，workload attestation 再確認「來要憑證的程序是誰」。Day85 拆了第一層（node attestor 的冒領邊界），Day84 拆了第二層（workload selector 的冒領邊界）。但這兩層都踩在一個沉默的前提上：**workload 得先「連得上」SPIRE Agent 那個 Unix domain socket，才輪得到 workload attestation 去反查它的特徵。** 今天聚焦那個 socket 本身的存取控制。

**這篇是延伸篇，不重講 Day80 的 attestation 兩層與 Workload API 基本流程，也不重講 Day84 的 workload selector 冒領邊界。** workload 呼叫 Workload API 不帶 token、Agent 靠 socket 對端 PID 反查屬性、selector 是 AND 怎麼收窄——Day80、Day84 都講過，今天不重述。這篇只聚焦一件前面點名、沒展開的事：**那個 Workload API socket 是怎麼被掛進 workload 容器的、誰掛得到、掛到之後的隔離邊界在哪。**

延伸角度只有一條主軸：**Day84／Day85 收窄的是「你是誰」；今天收窄的是「你連不連得上那個發身分的窗口」。** socket 開太大，attestation 收得再嚴，攻擊者也已經站在櫃台前——他還是拿不到不屬於他的 SVID（那是 attestation 的事），但他已經能對著 Workload API 敲門、探測、施壓（Day72），而且只要 selector 有一絲鬆（Day84），這道本可提前擋掉的攻擊面就白白留著。三件事逐一拆：① 掛載方式——hostPath 直掛 vs SPIFFE CSI Driver（承 Day11／Day07）；② 連得上 socket ≠ 拿得到 SVID——socket 是外層閘門，砍掉的是「機會」不是「發證」；③ 同機多租戶隔離——一個 node、一個 Agent、多租戶共用同一個 Workload API 時，租戶之間到底靠什麼隔開。

> ⚠️ 以下 socket 路徑（`/run/spire/agent-sockets`、`/spiffe-workload-api`…）、CSI driver 名稱（`csi.spiffe.io`）與 K8s 欄位會隨你的部署與版本不同。實際請對照你那套 SPIRE / SPIFFE CSI Driver 的官方 manifest，別照抄字串。這裡示範的是**存取邊界與收窄的意圖**，不是某一版的精確語法。

---

## 一、先定位：socket 是 attestation 之前的那道門

Day80 說過，workload 拿 SVID 的方式是連上 Agent 的 Workload API——一個 Unix domain socket，呼叫時**不帶任何 token 或祕密**，Agent 反過來用 socket 對端的核心層屬性（Linux `SO_PEERCRED` 拿到對端 PID，再由 OS／K8s 反查 UID、pod、SA、binary 路徑…）跟 registration entry 的 selector 比對，符合才發 SVID。

把這條路徑拆成兩段閘門，你會看到一個被 Day80／Day84 一路講下來、卻沒單獨拉出來的事實：

```text
[閘門一] 能不能連上這個 socket？                 ← 今天的主題（存取控制）
        ↓ 連得上
[閘門二] 連上之後，attestation 讓不讓你拿 SVID？   ← Day84（selector 冒領邊界）
```

Day84 整篇在講**閘門二**——同一台機器上另一個程序連上同一個 socket，能不能湊齊 selector 冒領身分。今天回到**閘門一**：那個 socket 憑什麼出現在你的容器裡？誰有能力把它掛進來？在 Kubernetes 裡，這個問題的答案幾乎完全由「**socket 怎麼掛進 pod**」決定——而這正是最容易被當成純維運細節、其實是資安邊界的地方。

一句話定位：**閘門二回答「你是誰」，閘門一回答「你在不在門口」。** 一個連門口都到不了的程序，連湊 selector 的機會都沒有——所以閘門一做好，是把冒領攻擊面**先砍一刀**；但它砍掉的是「機會」，發不發身分永遠是閘門二的事。兩道門是 AND，不是替代。

---

## 二、掛載方式一：hostPath 直掛 agent.sock（承 Day11 / Day07）

最直接的做法，是讓 workload pod 用 `hostPath` 把 Agent socket 所在的主機目錄掛進來：

```yaml
# 反例：workload pod 直接用 hostPath 掛 agent socket 目錄
apiVersion: v1
kind: Pod
metadata:
  name: order-service
  namespace: tenant-a
spec:
  containers:
    - name: app
      image: registry.example.com/order-service@sha256:...   # 綁 digest 承 Day18/84
      volumeMounts:
        - name: spire-agent-socket
          mountPath: /run/spire/agent-sockets
          readOnly: true
  volumes:
    - name: spire-agent-socket
      hostPath:
        path: /run/spire/agent-sockets   # ← 主機路徑直接開給這個 pod
        type: Directory
```

跑得起來，SVID 也拿得到。但這個 `hostPath` 是一個被低估的能力（承 Day11 掛載、Day07 最小權限）：

- **`hostPath` 本身就是高權限操作**：它讓 pod 直接掛到 node 的檔案系統。今天你掛的是 socket 目錄，改一個字串就能掛 `/`、`/var/run/docker.sock`、`/etc/kubernetes`……**能宣告 `hostPath` 的人，能摸的遠不只 agent socket。** 這正是 K8s Pod Security Standards 從 **baseline 檔次起就限制 `hostPath`**、`restricted` 更把可用 volume 型別收到白名單（`csi` 在內、`hostPath` 不在）的原因——它太泛用、太難收窄。
- **存取邊界＝「誰能在這個 node 上宣告這個 hostPath」**：任何能在該 node 排一個 pod、並在 spec 裡寫上這段 `hostPath` 的人，都能把 Workload API 掛進自己的容器，接著開始對 Agent 敲門（能不能拿到 SVID 是閘門二的事，但敲門這件事本身已經發生）。這條線的強度，封頂於「誰能在這個 namespace／node 部署帶 `hostPath` 的 pod」——又回到 Day07 的 RBAC。
- **`readOnly: true` 是必要但不充分**：把 mount 設 read-only 擋掉「往 socket 目錄寫東西」，但**連上 socket 這個動作本身不需要寫檔**（連 Unix domain socket 是對 inode 的 `connect` 操作，不是對你這個 read-only mount 寫檔）。所以 read-only 收的是「別讓 pod 汙染那個目錄」，不是「別讓 pod 用那個 socket」。

補一個容易誤解的點：**Agent socket 的檔案權限（mode／owner）在 SPIRE 設計裡刻意是寬鬆的**——SPIRE 不靠「socket 檔案權限」擋人，它靠 attestation（`SO_PEERCRED` 反查 PID 特徵）決定發不發。所以你不能指望「把 socket 設 0700」來做隔離；在 K8s 裡，真正的閘門一不是檔案 mode，而是**這個 socket 到底有沒有被掛進某個 pod**。這就是為什麼「掛載方式」本身是資安決策，不是維運口味。

---

## 三、掛載方式二：SPIFFE CSI Driver — 受控的 ephemeral inline volume

SPIFFE CSI Driver（driver 名稱 `csi.spiffe.io`）就是為了把「每個 workload 各自宣告 hostPath」這件事收掉而生的。它的做法：

**workload 端不再寫 `hostPath`**，改宣告一個 **ephemeral inline CSI volume**：

```yaml
# 正解：透過 SPIFFE CSI Driver 以 ephemeral inline volume 注入 Workload API，readOnly
apiVersion: v1
kind: Pod
metadata:
  name: order-service
  namespace: tenant-a
spec:
  containers:
    - name: app
      image: registry.example.com/order-service@sha256:...
      env:
        - name: SPIFFE_ENDPOINT_SOCKET
          value: unix:///spiffe-workload-api/spire-agent.sock
      volumeMounts:
        - name: spiffe-workload-api
          mountPath: /spiffe-workload-api
          readOnly: true
      securityContext:
        runAsNonRoot: true
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
  volumes:
    - name: spiffe-workload-api
      csi:
        driver: csi.spiffe.io
        readOnly: true          # ← 對 csi.spiffe.io 是必要語意
```

底層它做的是**唯讀 bind mount Agent socket 所在目錄**進容器。差別不在「有沒有用到 hostPath」——**CSI Driver 自己（一個 DaemonSet）還是得用 hostPath 去摸 Agent 的 socket 目錄**（這無可避免，socket 就在 node 上；連 CSI Driver 與 Agent 之間也是靠共用那個 hostPath 目錄，不能用 `emptyDir`，否則 driver pod 一重啟目錄就沒了、把 workload 的掛載打斷）——**差別在於：這個 hostPath 只出現在「一個受控的平台元件」裡，而不是散在每一個 workload pod 的 spec 裡。**

這就是關鍵的收窄：

| | hostPath 直掛 | SPIFFE CSI Driver |
|---|---|---|
| 誰宣告了 hostPath | **每一個要身分的 workload** | **只有 CSI Driver DaemonSet 一個** |
| workload spec 需要什麼 | `hostPath`（PSS baseline 起被限制） | 一個 `csi:` volume（不需 hostPath 權限） |
| 能不能用 PodSecurity `restricted` | 不行（hostPath 不在白名單） | 可以（csi 在白名單） |
| 攻擊面 | 每個 workload 都是一個「能宣告任意 hostPath」的點 | 收斂到一個平台元件 |
| CSIDriver 限制 | 無 | `csi.spiffe.io` 宣告只支援 ephemeral inline、無 controller provision/attach、要求 pod info 以驗證確實是 ephemeral 掛載 |

一句話：**CSI Driver 沒有消滅 hostPath，它把 hostPath 從「每個 workload 都要」收斂成「只有一個受控 DaemonSet 有」。** 於是你的 workload pod 可以全部關進 PodSecurity `restricted`，`hostPath` 這個泛用能力不再散落在應用層——這正是 Day07 最小權限搬到「身分注入」這一層。

> 別裝錯專案：這裡講的是 `spiffe/spiffe-csi`——掛 **Workload API socket** 的那個。另有 `cert-manager/csi-driver-spiffe` 是把 **X.509 SVID 當檔案**掛進 pod 的不同專案，解的是「不想用 Workload API、只想要憑證檔」的場景，driver 名稱與行為都不同，別混。

---

## 四、連得上 socket ≠ 拿得到 SVID：閘門一砍的是「機會」

這一節要把一個很容易走偏的直覺掰正：**收窄 socket 存取，不是為了「防止攻擊者拿到 SVID」——那是 attestation（閘門二、Day84）的責任，而且 attestation 本來就擋得住。** 一個連上 socket 卻湊不齊 selector 的惡意程序，Agent 根本不發它身分。

那閘門一到底在收什麼？收三件 attestation 不負責的事：

1. **砍掉「連上門」的機會，就砍掉「探測與施壓」的機會（承 Day72）**。能連上 Workload API 的程序，就算拿不到 SVID，仍能對這個 gRPC 端點發請求——探測、觸發錯誤、甚至嘗試把 Agent 的 Workload API 打到很忙（Day72 慢速／資源耗盡的思路搬到內部端點）。連不上 socket 的程序，這些一概沒機會。
2. **深度防禦：attestation 不是零 bug 的**。Day84 講的 selector 收窄是強防線，但「強防線」不等於「唯一防線」。萬一某天 registration entry 被人配寬了（selector drift）、或 Workload API 實作有瑕疵，**「根本連不上 socket」是那層失效時仍然站著的縱深**。把不該有任何 SPIFFE 身分的 pod（前端靜態站、無狀態工具容器、跑第三方映像的 job）**完全擋在 Workload API 之外**，是最乾淨的收窄——它們不需要身分，就不該掛到那個 socket。
3. **降低「同機冒領」的立足點（接第五節）**。Day84 的整個威脅模型是「同一台機器上另一個程序連上同一個 socket」。你能讓「同機但不該碰身分」的那些程序連 socket 都掛不到，Day84 要防的那個「另一個程序」就少一批。

反過來也要誠實：**閘門一不能取代閘門二。** 該有身分的 workload 本來就會掛到 socket，對它們來說 socket 是敞開的，能不能冒充彼此，100% 是 Day84 selector 的事。所以正確的心智是——

> **閘門一（socket 存取）把「不請自來的」擋在門外；閘門二（attestation selector）防「已入座的」互相冒充。兩道門各收一半，缺一不可。**

---

## 五、同機多租戶隔離：一個 node、一個 Agent、多租戶

這是本篇最需要講清楚、也最多人想錯的地方。場景：一個 node 上跑著租戶 A 和租戶 B 的 pod，node 上只有**一個 SPIRE Agent**、**一個 Workload API socket**。問題：**怎麼確保 A 的 pod 沒辦法透過那個 socket 去要到 B 的身分？**

先破一個直覺錯誤：**「給每個 workload 一個自己的 socket」不是 SPIRE 的隔離模型。** SPIRE 的主流部署是**一個 Agent 對外一個 Workload API**，CSI Driver 只是把「同一個 socket」分別掛進 A 和 B 的容器——A 和 B 掛到的是**同一個 Workload API**。所以你不能靠「socket 切開」來隔離租戶；socket 檔案權限在 SPIRE 設計裡也刻意寬鬆（第二節說過）。那租戶到底靠什麼隔開？攤平成四個層次，由弱到強：

**① 靠 attestation selector（Day84）——這是預設、也是同機共用 Agent 時的唯一實質隔離。**
A 的 pod 連上 socket，Agent 用 `SO_PEERCRED` 反查它的 PID → 得到 `k8s:ns:tenant-a`、`k8s:sa:...`、`container-image:@sha256:...`，跟 registration entry 比對。B 的身分綁的是 `k8s:ns:tenant-b`，A 的 pod 特徵對不上就發不了。**所以「同機多租戶」的隔離強度，等於 Day84 selector 的收窄強度**——selector 只綁 `k8s:ns` 而 A、B 又同 namespace，隔離就是零；綁到 `ns + sa + image@digest` 的 AND，A 要冒充 B 就得先能在 B 的 namespace、用 B 的 SA、跑 B 的映像起 pod——那已經不是冒領，是已經攻陷 B 了。

**② 靠 socket 存取控制（本篇閘門一）——收的是「不該有身分的第三者」，不是 A 對 B。**
第四節說過，閘門一擋的是「連不該連的程序」。在多租戶場景，它的價值是把「既不是 A 也不是 B、根本不該有身分」的 pod（某個跑第三方映像的 job、某個被打穿的 sidecar）擋在 Workload API 之外，縮小同機能對 socket 敲門的集合。但**它不區分 A 和 B**——A、B 都合法掛著 socket，A 對 B 的隔離還是回到 ①。

**③ 靠「根本不同機」——真正互不信任的租戶，別共用 Agent。**
如果 A、B 是**互不信任**（例如公有雲多租戶、跑使用者提交的程式碼），那「同一個 node、同一個 Agent」這件事本身就是風險：同機意味著共用 Agent、共用 socket，整個隔離就縮到 ①（selector 強度）加上 PID 重用／TOCTOU 的心智模型（Day22）。這種情境下，真正的邊界是**節點層隔離**——用 node pool／taint／`nodeSelector` 讓不同信任等級的租戶落在不同 node（各自的 Agent），A 的 pod 連 B 的 Agent 的 socket 都碰不到。**這比在同一個 Agent 上把 selector 收到極限更根本**：selector 再嚴，也是在「同一個發證窗口前排隊」；分 node 是「連窗口都不同」。

**④ mesh sidecar（Envoy SDS）——把 socket 從應用手裡收走的另一種形態。**
還有一種常見落地：應用**完全不碰 Workload API socket**，由 pod 裡的 mesh sidecar（Envoy）透過 SDS 拿 SVID、幫應用終結 mTLS，應用只講純 HTTP 給 localhost（承 Day80 sidecar／mesh 形態）。這把閘門一的邊界從「應用容器掛不掛得到 socket」移到「**誰能決定注入這個 sidecar、sidecar 與 Agent 之間那條 SDS 通道怎麼保護**」。隔離模型變了，但三道問句沒變：誰連得上發身分的窗口、連上之後 attestation 讓不讓拿、真正互不信任的要不要根本分開。這個形態的細節留給明天。

一句話收束多租戶：**同機共用 Agent 時，租戶之間的牆是 Day84 的 selector，不是 socket 檔案權限、也不是 CSI Driver；socket 存取控制收的是「第三者」，node 分離收的是「互不信任者」。搞錯哪道門收哪種人，你會把力氣花在收 socket 權限、卻讓 selector 開著。**

---

## 六、Day16 稽核：哪些 pod 掛了 agent socket

閘門一要能守，前提是你**知道誰掛了 socket**。這件事天生適合寫成 CI／admission 的機器檢查（承 Day16），別靠人翻 YAML。判準很單純：

- **application pod 不該用 `hostPath` 直掛 agent socket 目錄**——要嘛透過 SPIFFE CSI Driver、要嘛根本不該有身分。掃到 application pod 帶 `hostPath` 指向 socket 目錄＝判紅。
- **平台元件（SPIRE Agent、CSI Driver DaemonSet）本來就得用 hostPath**——白名單放行，別誤傷。
- **用了 `csi.spiffe.io` 但沒設 `readOnly: true`**＝收窄不完整，判黃。

**Go 版（解析 `kubectl get pods -A -o json`）：**

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// 對照 kubectl get pods -A -o json 的結構（只取需要的欄位）
type podList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			Volumes []struct {
				Name     string `json:"name"`
				HostPath *struct {
					Path string `json:"path"`
				} `json:"hostPath,omitempty"`
				CSI *struct {
					Driver   string `json:"driver"`
					ReadOnly *bool  `json:"readOnly,omitempty"`
				} `json:"csi,omitempty"`
			} `json:"volumes"`
		} `json:"spec"`
	} `json:"items"`
}

const csiDriver = "csi.spiffe.io"

// 平台自己的元件（Agent、CSI Driver）本來就得用 hostPath 摸 socket 目錄，白名單放行
var platformNamespaces = map[string]bool{"spire": true, "spire-system": true}

// socket 目錄的辨識片段：對照你那套部署的實際路徑調整
const socketDirHint = "/run/spire"

func main() {
	var pods podList
	if err := json.NewDecoder(os.Stdin).Decode(&pods); err != nil {
		fmt.Fprintln(os.Stderr, "parse pod list failed:", err) // 解析失敗往上丟，別當沒事
		os.Exit(2)
	}

	failed := false
	for _, p := range pods.Items {
		if platformNamespaces[p.Metadata.Namespace] {
			continue // 平台元件的 hostPath 是預期內的
		}
		id := p.Metadata.Namespace + "/" + p.Metadata.Name
		for _, v := range p.Spec.Volumes {
			// ① application pod 用 hostPath 指到 agent socket 目錄 = 直掛，攻擊面最大
			if v.HostPath != nil && strings.Contains(v.HostPath.Path, socketDirHint) {
				fmt.Printf("[FAIL] %s hostPath-mounts agent socket dir: %s\n", id, v.HostPath.Path)
				failed = true
			}
			// ② 用了 CSI driver 但沒設 readOnly = 收窄不完整
			if v.CSI != nil && v.CSI.Driver == csiDriver {
				if v.CSI.ReadOnly == nil || !*v.CSI.ReadOnly {
					fmt.Printf("[WARN] %s mounts %s without readOnly:true\n", id, csiDriver)
				}
			}
		}
	}
	if failed {
		os.Exit(1) // CI 紅 / 告警
	}
	fmt.Println("[OK] no application pod hostPath-mounts the agent socket directly")
}
```

**Java 版（對稱，Jackson 解析）：**

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.util.Set;

public class AgentSocketMountAudit {

    private static final String CSI_DRIVER = "csi.spiffe.io";
    // 平台元件（Agent / CSI Driver）本來就得用 hostPath，白名單放行
    private static final Set<String> PLATFORM_NS = Set.of("spire", "spire-system");
    // socket 目錄辨識片段：對照你那套部署的實際路徑調整
    private static final String SOCKET_DIR_HINT = "/run/spire";

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        boolean failed = false;

        try (InputStream in = System.in) {
            JsonNode root = mapper.readTree(in); // 解析失敗會丟例外，不靜默吞掉
            for (JsonNode pod : root.path("items")) {
                String ns = pod.path("metadata").path("namespace").asText();
                String name = pod.path("metadata").path("name").asText();
                if (PLATFORM_NS.contains(ns)) {
                    continue; // 平台元件的 hostPath 是預期內的
                }
                for (JsonNode v : pod.path("spec").path("volumes")) {
                    JsonNode hostPath = v.path("hostPath");
                    if (!hostPath.isMissingNode()
                            && hostPath.path("path").asText().contains(SOCKET_DIR_HINT)) {
                        System.out.printf("[FAIL] %s/%s hostPath-mounts agent socket dir: %s%n",
                                ns, name, hostPath.path("path").asText());
                        failed = true;
                    }
                    JsonNode csi = v.path("csi");
                    if (!csi.isMissingNode() && CSI_DRIVER.equals(csi.path("driver").asText())) {
                        if (!csi.path("readOnly").asBoolean(false)) {
                            System.out.printf("[WARN] %s/%s mounts %s without readOnly:true%n",
                                    ns, name, CSI_DRIVER);
                        }
                    }
                }
            }
        }

        if (failed) {
            System.exit(1); // CI 紅 / 告警
        }
        System.out.println("[OK] no application pod hostPath-mounts the agent socket directly");
    }
}
```

> 實務更穩的做法是把這條規則寫進 **admission policy**（OPA／Gatekeeper 或 Kyverno），在 pod 建立當下就擋，而不是事後掃。CI 掃描是最低限度的縱深；擋在 admission 是把 Day16 的「偵測」升級成「預防」（承 Day07 default deny）。上面兩段的欄位名（`hostPath.path`、`csi.driver`、`csi.readOnly`）以你那版 K8s 的實際 pod JSON 為準。

---

## 七、常見誤區

- **「socket 掛進來就安全了，反正有 attestation」** ── attestation 是閘門二；閘門一（誰掛得到 socket）你沒收，等於門口不設防、只靠櫃台驗身分。
- **「hostPath 設 readOnly 就沒事」** ── read-only 擋的是「往目錄寫」，擋不了「連上 socket」；連 socket 不需要寫檔。
- **「把 agent.sock 設 0700 做隔離」** ── SPIRE 刻意讓 socket 權限寬鬆、靠 attestation 認人；檔案 mode 不是它的隔離手段。
- **「CSI Driver 消滅了 hostPath」** ── 沒有，它把 hostPath 從每個 workload 收斂到一個受控 DaemonSet；差別在攻擊面收斂，不是 hostPath 消失。
- **「給每個 pod 自己的 socket 就能隔離租戶」** ── SPIRE 主流是一個 Agent 一個 Workload API，大家掛的是同一個；租戶隔離靠 Day84 selector，不是把 socket 切開。
- **「同機多租戶，selector 收緊就夠」** ── 真正互不信任的租戶，同機＝共用 Agent＝隔離縮到 selector＋PID／TOCTOU（Day22）；該用 node pool 分開，別在同一個發證窗口前把 selector 收到極限當終點。
- **「socket 存取控制能防 A 冒充 B」** ── 不能；A、B 都合法掛著 socket，A 對 B 的隔離是閘門二（selector）。閘門一收的是「不該有身分的第三者」。
- **「前端靜態站／工具容器掛個 socket 沒差」** ── 不需要身分的 pod 掛 Workload API，就是白送攻擊者一個立足點（Day72 探測／施壓、深度防禦被鑿一個洞）。
- **「csi.spiffe.io 跟 cert-manager 的 csi-driver-spiffe 是同一個」** ── 不是；前者掛 Workload API socket，後者把 X.509 SVID 當檔案掛。
- **「socket 掛哪誰都能改，反正 RBAC 有擋」** ── 那就去確認 RBAC 真的有擋「誰能部署帶 hostPath 的 pod」（Day07），別假設。

---

## 八、Code Review / 維運 checklist

**掛載方式**

- [ ] application pod **不用 `hostPath`** 直掛 agent socket；改用 SPIFFE CSI Driver 的 ephemeral inline volume，或根本不掛（不需要身分的 pod）。
- [ ] CSI volume 設 `readOnly: true`；workload 的 `volumeMount` 也 `readOnly`。
- [ ] workload pod 能關進 PodSecurity `restricted`（hostPath 不再散在應用層）。
- [ ] 分清 `spiffe/spiffe-csi`（掛 Workload API socket）與 `cert-manager/csi-driver-spiffe`（掛 SVID 檔案），別裝錯。

**存取範圍（閘門一）**

- [ ] 只有「真的需要 SPIFFE 身分」的 workload 才掛 Workload API；前端靜態站、工具容器、第三方映像 job 一律不掛。
- [ ] 「誰能部署帶 `hostPath` 的 pod」由 K8s RBAC 收緊（承 Day07）；平台元件（Agent、CSI Driver）的 hostPath 是唯一例外並受審核。
- [ ] securityContext 收窄：`runAsNonRoot`、`allowPrivilegeEscalation: false`、`readOnlyRootFilesystem`、`capabilities.drop: [ALL]`。

**多租戶隔離**

- [ ] 認清同機共用 Agent 時，租戶之間的牆是 Day84 selector（`ns + sa + image@digest` 的 AND），不是 socket 權限。
- [ ] 互不信任的租戶用 node pool／taint／nodeSelector 分到不同 node（各自 Agent），別共用同一個 Workload API。
- [ ] 若走 mesh sidecar（Envoy SDS），確認「誰能決定 sidecar 注入」與「SDS 通道保護」是收好的（Day87）。

**稽核（承 Day16）**

- [ ] CI／admission（OPA／Gatekeeper、Kyverno）掃 pod spec，攔 application pod 的 hostPath 直掛 agent socket、`csi.spiffe.io` 缺 `readOnly`。
- [ ] 對「非預期 namespace 出現 Workload API 掛載」告警；平台元件白名單之外的 hostPath-to-socket 一律當可疑。

---

## 九、測試 / 演練建議

- **hostPath 攔截測試（最重要）**：在測試叢集部署一個 application pod 用 `hostPath` 直掛 socket 目錄，斷言第六節的 CI／admission policy **判紅／擋下**。這是「閘門一存在」的證明——測不過代表你的 socket 存取控制是擺設。
- **不該有身分的 pod 掛 socket**：讓一個「本不需要身分」的 pod 掛上 Workload API，斷言稽核**告警**（它不該出現在允許清單）。
- **連得上 ≠ 拿得到 SVID**：讓一個掛了 socket、但特徵對不上任何 registration entry 的程序連上 Workload API，斷言 Agent **不發** SVID（閘門二仍然守著）——確認你沒把「掛得到 socket」誤當「拿得到身分」。
- **CSI readOnly 驗證**：對透過 `csi.spiffe.io` 掛入的 volume，在容器內嘗試往 mount 目錄寫檔，斷言**失敗**（read-only 生效）。
- **多租戶 selector 隔離迴歸**：把租戶 selector 從 `ns+sa+image@digest` 放寬成只綁 `ns`，斷言 Day84 的稽核／部署 gate **會紅**（提醒你同機隔離的牆鬆了）。
- **節點隔離演練**：對「互不信任租戶不同 node」的策略，斷言 A 租戶的 pod 排不到 B 的 node（taint／nodeSelector 生效），從而連 B 的 Agent socket 都碰不到。
- **PodSecurity restricted 驗證**：對 workload namespace 套 `restricted`，斷言帶 `hostPath` 的 pod **被 API server 拒絕**（把「不准直掛」變成平台強制，而非靠自律）。

---

## 十、一句話總結

> Day80 把 attestation 講成兩層，Day85 拆了第一層（node）、Day84 拆了第二層（workload selector），但兩層都預設一件事：workload 得先**連得上** Agent 的 Workload API socket。今天收窄的就是這道 attestation 之前的門。**閘門一（能不能連上 socket）回答「你在不在門口」，閘門二（attestation selector）回答「你是誰」——兩道 AND，缺一不可。** 掛載方式是資安決策：`hostPath` 直掛讓「每一個要身分的 workload」都變成一個能宣告任意主機路徑的點（PSS baseline 起就限制它、restricted 更把 volume 收進白名單），而 SPIFFE CSI Driver（`csi.spiffe.io`）用唯讀的 ephemeral inline volume，把 hostPath 從「每個 workload 都要」收斂成「只有一個受控 DaemonSet 有」——不是消滅 hostPath，是收斂攻擊面，順帶讓 workload 全關進 PodSecurity restricted。但要掰正一個直覺：**收窄 socket 存取不是為了防攻擊者拿到 SVID（那是 attestation 的事、而且它擋得住），而是砍掉「連上門去探測、施壓（Day72）」的機會，並在 attestation 萬一失手時留一道縱深，把根本不需要身分的 pod（前端站、工具容器、第三方 job）整個擋在 Workload API 之外。** 到了同機多租戶，最多人想錯的是「切 socket／收 socket 權限來隔離租戶」——SPIRE 是一個 Agent 一個 Workload API，A、B 掛的是同一個，socket 權限又刻意寬鬆，**租戶之間的牆從頭到尾是 Day84 的 selector（`ns+sa+image@digest` 的 AND）**；socket 存取控制收的是「不該有身分的第三者」，不是「A 對 B」。而真正互不信任的租戶，同機就等於把隔離縮到 selector＋PID／TOCTOU（Day22），該用的是 node pool 把它們分到不同 Agent——**selector 再嚴也是在同一個發證窗口前排隊，分 node 是連窗口都不同。** 最後用 Day16 收尾：把「application pod 不得 hostPath 直掛 agent socket」寫成 CI／admission（OPA／Gatekeeper、Kyverno）的機器規則，平台元件白名單放行，其餘一律判紅——把「偵測」升級成「預防」。一句話：**Day84／Day85 收窄了「你是誰」，Day86 收窄「你連不連得上發身分的那個窗口」——socket 開太大，attestation 收得再嚴，攻擊者也已經站在櫃台前了。**

---

## 延伸閱讀

- Day80 SPIFFE / SPIRE workload identity——本篇上游：Workload API、不帶 token 連 socket、attestation 兩層、sidecar／mesh 形態都在這，今天只展開「socket 存取」這道門。
- Day84 SPIRE workload attestation selector——閘門二（你是誰）；本篇是閘門一（你在不在門口）。同機多租戶的租戶牆就是 Day84 的 selector。
- Day85 SPIRE node attestation——第一層（機器可信）；跟本篇一起補齊「機器 → socket → 程序」三段門。
- Day07 Broken Access Control——「誰能部署帶 hostPath 的 pod」「不需要身分就不掛」都是最小權限與 default deny 的搬移。
- Day11 Path Traversal / File Upload——hostPath 掛載本身就是「把主機檔案系統接進容器」的高權限操作，收窄心法同源。
- Day16 Security Logging / Monitoring——「哪些 pod 掛了 agent socket」的稽核與 admission 攔截。
- Day22 Race Condition / TOCTOU——同機共用 Agent 時 PID 反查的 PID 重用／TOCTOU 心智模型。
- Day72 Slowloris / Slow HTTP DoS——連得上 Workload API 卻拿不到 SVID 的程序，仍能對這個內部端點探測／施壓的思路來源。

---

明天預告：**Day 87 — SPIRE 與 service mesh 的整合：Envoy SDS 如何餵 SVID、Istio + SPIRE 的身分發放，以及「sidecar 幫我終結 mTLS」的信任邊界（延伸篇）**
（這篇是**延伸篇**，不重講 Day80 的 SVID／attestation 基礎、也不重講今天的 socket 掛載方式。今天第五節把 mesh sidecar 當成「把 socket 從應用手裡收走」的一種隔離形態點了名、沒展開；明天就展開它：**① Envoy 怎麼拿 SVID**——不是應用連 Workload API，而是 Envoy 透過 **SDS（Secret Discovery Service）**向 SPIRE Agent 要憑證與 trust bundle，應用只講純 HTTP 給 localhost、mTLS 在 sidecar 終結（承 Day80 sidecar 形態、Day19／74 mTLS）；**② 信任邊界搬去哪**——身分從「應用容器掛不掛得到 socket」變成「誰能決定把這個 sidecar 注入進來、Envoy 與 Agent 之間那條 SDS 通道（也是一個 Unix domain socket）怎麼保護」，注入器（sidecar injector／mutating webhook）本身成了新的高權限點（承 Day07／今天閘門一）；**③「sidecar 幫我做」的兩面刃**——好處是身分與 mTLS 徹底離開應用碼、連 go-spiffe／java-spiffe 都不用寫，壞處是應用對「我到底在跟誰通話」變無感，`localhost` 明文那一段、Envoy 的 authorization policy（`principals` 綁 SPIFFE ID）配錯就等於身分驗了卻沒授權（承 Day07／Day49），以及「繞過 sidecar 直連」的老問題（承 Day38 繞過 gateway 直連內網全裸）。程式面會示範 Istio `AuthorizationPolicy` 用 SPIFFE ID 當 `principals` 的收窄、Envoy SDS 從 SPIRE Agent 取 SVID 的接線、以及用 Day16 角度稽核「哪些流量沒走 sidecar／哪些 principal 開太寬」。安全主軸一句話：**Day86 把 socket 收好之後，mesh 乾脆讓應用不碰 socket——但身分沒有消失，只是搬進了 sidecar 與注入器，你得知道它搬去哪、那裡的門有沒有關。** 這是延伸篇，只聚焦 SPIRE×mesh 的 SDS 接線與信任邊界搬移，不重述 mTLS 握手與 SVID 基礎。）
