---
title: "Day 85：SPIRE node attestation 的信任假設 — join token 重用、AWS IID 重放、K8s PSAT 的冒領邊界（延伸篇）"
date: 2026-07-25
tags: ["SPIFFE", "SPIRE", "Node Attestation", "Attestation"]
---

接續 Day84 預告：Day80 說 attestation 分兩層、缺一不可——第一層 node attestation「先確認跑 Agent 的機器可信」，第二層 workload attestation「再確認來要憑證的程序是誰」。Day84 已經把**第二層**拆開，看 registration entry 綁的那組 selector 有多難被同機另一個程序湊出來。今天回到**第一層**：那個「先確認機器可信」的動作，到底信了什麼？又能被怎麼騙？

**這篇是延伸篇，不重講 Day80 的 attestation 兩層基本流程，也不重講 Day84 的 workload selector 冒領邊界。** attestation 為什麼要兩層、workload 呼叫 Workload API 不帶 token 而是靠 socket 對端 PID 反查、selector 是 AND 怎麼收窄——Day80、Day84 都講過，今天不重述。這篇只聚焦一件 Day80 只點名、沒展開的事：**node attestation 的三個常見 attestor（join token、AWS IID、K8s PSAT）各自信了一個什麼樣的憑據，而那個憑據能不能被「不是那台機器的東西」拿到。**

延伸角度只有一條主軸：**node attestation 不是「機器連上來就算可信」，而是「你選的那個 attestor，它拿來當節點身分根的憑據，冒領邊界在哪」。** Day84 收窄的是「同一台可信 node 上、哪個程序是誰」；今天收窄的是更上游的「哪台機器憑什麼算可信 node」——**這一層被冒領，你在 workload 層收得再窄，都是蓋在流沙上。** 三個 attestor 各自拆：① join token（一段預先發出去的祕密）、② AWS IID（雲端 metadata 簽的節點文件）、③ K8s PSAT（projected service account token），最後回到 ④ 三者共同的心智模型與 Day16 稽核。

> ⚠️ 以下 HCL 欄位名稱（`assume_role`、`verify_organization`、`service_account_allow_list`、`audience`…）與 CLI 子指令會隨 SPIRE 版本與各 node attestor plugin 演進。實際部署請對照你那版 attestor 的官方文件，別照抄字串。這裡示範的是**冒領邊界與收窄的意圖**，不是某一版的精確語法。

---

## 一、先定位：node attestation 在信任鏈的最上游

Day80 說過，node attestation 通過後，SPIRE Server 會發一張**代表節點的 SVID** 給 Agent，這張 agent SVID 的 SPIFFE ID 長這樣：

```text
spiffe://example.org/spire/agent/<attestor>/<節點識別...>
```

三個 attestor 的 agent SPIFFE ID 各自是：

```text
spiffe://example.org/spire/agent/join_token/<token>
spiffe://example.org/spire/agent/aws_iid/<account>/<region>/<instance-id>
spiffe://example.org/spire/agent/k8s_psat/<cluster>/<node-uid>
```

這串路徑不只是名字——它**同時是「哪台機器用什麼 attestor 加入 trust domain」的稽核線索**（第五節會用到）。重點是：workload attestation（Day84）永遠發生在「這台 node 已經被信任」的前提之上。Agent 一旦拿到 agent SVID，它就是這台 node 上所有 workload 的發證代理；**如果一個攻擊者能讓 SPIRE Server 相信「他的機器是可信 node」，他就繞過了整個第一層，接下來 Day84 那些 selector 收窄，對他來說只是「在自己完全掌控的機器上湊特徵」——毫無難度。**

所以每個 attestor 都在回答同一個冒領問句：

> **「不是那台機器該獨佔的憑據，能不能被別的東西拿到、拿去讓 SPIRE Server 相信它是可信 node？」**

三個 attestor 三種信任根：**一段祕密 / 一份雲廠簽的文件 / 一張 K8s 簽的 token**。逐一拆。

---

## 二、join token：一段預先發出去的祕密（承 Day15 / Day26）

### 機制一句話（不展開）

`spire-server token generate` 產生一次性 token 並建立對應 registration entry，Agent 用 `-joinToken` 旗標或 config 裡的 `join_token` 帶著它來 attest。**用完立即失效**，且有 TTL。Server 用它發出 agent SVID：`spiffe://example.org/spire/agent/join_token/<token>`。

```bash
# Server 端：產生一次性 join token（帶 spiffeID 與短 TTL）
spire-server token generate \
    -spiffeID spiffe://example.org/agent/host-a \
    -ttl 300
# 輸出：Token: 8b1f...（這一串就是祕密）
```

```hcl
# Agent 端 agent.conf —— 反例：把 token 寫死在設定裡烤進 image
agent {
    # join_token = "8b1f..."   # ← 千萬別這樣，見下
    trust_domain = "example.org"
}
```

```bash
# 正解：token 由外部安全通道注入，用過即丟
spire-agent run -joinToken "$(read_token_from_secure_channel)"
```

### 信任假設與冒領邊界

join token 的信任假設只有一句：**這段 token 只有「該加入的那台機器」拿得到。** 這就是 Day15 的老問題——**它是一個祕密**，而祕密的破法你都熟：

- **外洩**：token 進了 log、CI 環境變數、Terraform state、被烤進 container image。誰讀到誰就能 bootstrap 一個 Agent。
- **重用**：想省事把「同一張 token」pre-bake 進 image 給一整批機器用——這直接違反一次性語意，第一台用掉之後其餘全部 attest 失敗；更糟的是若你關掉一次性或重發同值，等於把一把萬能鑰匙散出去。
- **塞進不該加入的機器**：token 本身不綁機器特徵（不像 IID 綁 instance、PSAT 綁 pod）。**誰持有 token，誰就能讓 Server 相信「我是那個 agent」**，然後這個 Agent 就能發放它被授權的 workload 身分。

一次性 + TTL 是內建緩解，但**不是免死金牌**：TTL 視窗內 token 被中途攔截，仍然是「誰先用誰得」；而且 SPIFFE ID 直接把 token 明文放進路徑（`.../join_token/<token>`），所以**別把 `spire-server agent list` 的輸出當公開資料**。

### 收窄

- **短 TTL、產生即用**：把可攔截視窗壓到最小，別預先產一批放著。
- **一機一張、絕不共用**：per-node 各發各的，別讓一張 token 對應多台。
- **傳遞走安全通道、絕不進 log**（承 Day15）：token 是 secret，比照 API key 對待——不落磁碟、不進版本控管、不寫 log。
- **認清定位**：join token 適合 bootstrap、裸機、開發環境的少量節點。**規模化生產不該用 join token 當節點身分根**——雲上用 IID、K8s 用 PSAT，讓「機器本身的可驗證屬性」當憑據，而不是「一段要人去保管的祕密」。這正是 Day15「別到處塞 secret」的心法搬到節點身分層。

---

## 三、AWS IID：雲端 metadata 簽的節點身分（承 Day10 SSRF）

### 機制一句話（不展開）

Agent 從 instance metadata 拿 AWS 簽名的 **Instance Identity Document（IID）**，送給 Server 驗簽。Server 發出 agent SVID：`spiffe://example.org/spire/agent/aws_iid/<account>/<region>/<instance-id>`——**account、region、instance 全編進 SPIFFE ID**。

信任假設：**IID 只有「那台 EC2 instance 上的程序」拿得到，且 AWS 的簽章保證它沒被偽造。** 簽章這半確實硬（偽造不了 AWS 的簽名），但「只有那台機器拿得到」這半，就是冒領邊界所在。

### 冒領邊界一：IID 對同機任何程序都可讀 —— 這就是 Day10 SSRF 的線

SPIRE 官方 `aws_iid` 文件的 Security Considerations 講得非常直白（值得原文記住）：

> The AWS Instance Identity Document … is available to any process running on the node by default. As a result, it is possible for non-agent code running on a node to attest to the SPIRE Server, allowing it to obtain any workload identity that the node is authorized to run.

翻成後端聽得懂的話：**metadata service 預設對 node 上「任何程序」開放**，所以不只 SPIRE Agent，連被 SSRF 打穿的服務、同機的惡意程序，都能讀到 IID 拿去 attest——**然後領走這台 node 被授權的任何 workload 身分**。這跟 Day10 講 SSRF 打 `169.254.169.254` 偷雲端憑證是**同一條線**：只要你的服務能被誘導去讀 metadata endpoint，它讀到的不只是臨時 IAM 憑證，還包括這份能讓 SPIRE 相信「我是可信 node」的 IID。

**緩解（兩手都要）**：

1. **TOFU（Trust On First Use）——SPIRE 內建**：每個 node **只能 attest 一次**，之後的 attestation 一律拒絕。所以就算非 Agent 程序能讀 IID，它也只能在「真 Agent 之前搶先」那一瞬間得手。而搶先的後果是——**真 Agent 會啟動失敗，Server 與 Agent 兩邊都留下 log**。這個「Agent 起不來」的訊號**不是雜訊，是可偵測的資安事件**，該告警、該當入侵調查（承 Day16）。
2. **IMDSv2 擋 SSRF 讀 metadata（承 Day10）**：要求 session token、把 hop limit 設為 1，讓「被 SSRF 的應用層」拿不到 metadata。這是把「IID 可讀範圍」從「node 上任何程序」實質收窄的關鍵一步，別只靠 TOFU 這一道。

### 冒領邊界二：IID 被重放到別台 / 別的帳號

IID 是**一份文件**，天生有「被搬走重放」的想像空間。TOFU 把「同一 node 重複 attest」擋掉了，但你還要收窄「**哪些帳號、哪些叢集的 node 有資格加入我的 trust domain**」，否則一個不相干 AWS 帳號開的 instance 也能來 attest。收窄靠 `aws_iid` 的幾個選項：

```hcl
NodeAttestor "aws_iid" {
    plugin_data {
        # 1) Server 用委派角色查 AWS，AccountID 取自 agent 送來的 IID
        assume_role = "spire-server-delegate"

        # 2) 只允許屬於「我的 AWS Organization」的帳號加入
        #    大型組織可改用 account_list_file 從檔案來源帳號清單（fail-closed：空清單=全拒）
        verify_organization = {
            account_list_file   = "/etc/spire/org-accounts.json"
            org_account_map_ttl = "15m"
        }

        # 3) 進一步限定 node 必須屬於指定 EKS cluster
        validate_eks_cluster_membership = {
            eks_cluster_names = ["prod-cluster", "staging-cluster"]
        }

        # skip_block_device 預設 false = 會檢查 root volume 沒被卸下再 attest（anti-tamper），別亂關成 true
    }
}
```

要點：

- **`assume_role` / `account_list_file`**：把「哪些帳號的 node 能加入」收到你自己的組織邊界，別讓任意 AWS 帳號都能 attest。`account_list_file` 是 fail-closed 的——檔案空或壞，對應帳號一律拒絕而不是放行，這個方向是對的。
- **`validate_eks_cluster_membership`**：再收一層，要求 attesting instance 真的屬於你指定的 EKS cluster（透過 ASG / node group 反查）。
- **`skip_block_device`**：預設 `false` 代表**會做**「root volume 有沒有在 attest 前被卸下」的防竄改檢查。這是防「把別台的 root volume 掛過來冒充」的機制，**別為了省事關掉**。
- **account/region/instance 編進 SPIFFE ID**：這讓你在 registration entry 綁 workload 時，可以用 `aws_iid:` 系列 selector（account_id、instance:id、region、sg、iamrole…）進一步限定「只有這個帳號、這個 instance 的 node 上的 workload」——把 Day84 的 selector 收窄接到 node 屬性上。

一句話：**IID 的簽章偽造不了，但「誰能讀到 IID」與「哪個帳號的 IID 算數」要你自己收窄**——前者靠 IMDSv2 + TOFU，後者靠 org / EKS 驗證。

---

## 四、K8s PSAT：projected service account token（承 Day05 / Day07）

### 機制一句話（不展開）

Agent 拿一張 **projected service account token（PSAT）**，Server 用 Kubernetes **TokenReview API** 驗簽並取回 namespace / SA / pod / node 等資訊，發出 agent SVID：`spiffe://example.org/spire/agent/k8s_psat/<cluster>/<node-uid>`。

### 為什麼是 PSAT，不是 legacy SAT——這本身就是一次信任假設升級

K8s 還有一個舊的 `k8s_sat` attestor，用的是傳統 service account token。兩者差在：

- **legacy SAT**：長效、**不綁 audience**、存在 Secret 裡可被讀走無限重用。任何能讀到那個 Secret 的東西都能拿它冒充。
- **PSAT（projected）**：走 TokenRequest / TokenRequestProjection，**綁 audience、有時效、會自動輪替**。token 外洩的重放窗口從「永久」縮到「幾分鐘級」，而且綁死用途。

所以「用 PSAT 不用 SAT」本身就是把節點身分憑據從「一顆躺著的長效祕密」升級成「短效、綁用途、會過期的憑據」——同一種 Day15 心法。

### 信任假設與冒領邊界

信任假設：**這張 `audience=spire-server` 的 token，只有「跑 Agent 的那個 SA / pod」拿得到。** 三個常見破口：

**① audience 沒綁好——最致命。** 若 Agent 拿的 token audience 太寬（例如用給 apiserver 的預設 audience），或 Server 端把 `audience` 設成空陣列 `[]`（退回用 k8s apiserver 的 audience），那**別的元件也吃同一張 token** = 這張 token 不再是「只給 SPIRE 用」的專屬憑證，任何拿得到它的東西都能冒充 Agent。正解是兩端對齊一個**專屬 audience**：

```hcl
# Server 端 agent.conf
NodeAttestor "k8s_psat" {
    plugin_data {
        clusters = {
            # clusters 空 = 沒有任何 cluster 被授權（fail-closed，good）
            "prod-cluster" = {
                # ② 只允許這個專屬 SA 當 agent 身分（見下）
                service_account_allow_list = ["spire:spire-agent"]
                # ① 專屬 audience，別留空、別和別人共用；預設就是 ["spire-server"]
                audience = ["spire-server"]
                # allowed_node_label_keys / allowed_pod_label_keys：label 是自陳資料，只當輔助
            }
        }
    }
}
```

```yaml
# Agent 端 pod：projected volume 的 audience 必須和 Server 對齊
volumes:
  - name: spire-agent-token
    projected:
      sources:
        - serviceAccountToken:
            path: spire-agent
            audience: spire-server      # ← 和上面的 audience 對齊，且是專屬用途
            expirationSeconds: 600
```

**② `service_account_allow_list` 太寬——承 Day07。** 沒設或設一堆 SA，代表「任何能在那些 namespace / 用那些 SA 起 pod 的人」都能讓自己的 pod 冒充 Agent。PSAT 的強度**封頂於 K8s RBAC**：**誰能用 `spire-agent` 這個 SA 起 pod、誰能在 `spire` namespace 部署**，決定了這道防線的實際強度。這跟 Day84 講「`k8s:sa` 的強度依賴 RBAC 收緊誰能挑 SA 開 pod」是同一條——只是那裡是 workload 層，這裡是 node 層。把 agent 用的 SA 獨立、RBAC 收到只有平台團隊能用它起 pod。

**③ `clusters` 空 = 沒人被授權（fail-closed）**——這個預設方向是對的；但別因為配錯 `kube_config_file` 或 TokenReview 權限，讓驗證在錯誤處理裡默默退化。TokenReview 需要 `tokenreviews: create` 與 `pods/nodes: get` 權限，缺了會驗不動。

**node / pod label selector（`allowed_node_label_keys` / `allowed_pod_label_keys`）** 是自陳資料，**只當輔助身分，別當唯一依據**——這點和 Day84 對 `pod-label` 的評價一模一樣：能改 manifest 的人就能改 label。

---

## 五、三個 attestor 的共同心智模型：node attestation 到底信什麼

把三者攤平對照，你會看到同一個結構：

| Attestor | 信任根（憑據） | 冒領邊界 | 主要收窄手段 |
|---|---|---|---|
| **join_token** | 一段預先發出去的祕密 | 祕密的老病：外洩 / 重用 / 塞進不該加入的機器 | 一次性 + 短 TTL、一機一張、走安全通道、規模化改用平台原生 attestor |
| **aws_iid** | AWS 簽名的 IID 文件 | IID 對同機任何程序可讀（Day10 SSRF）、重放到別台 / 別帳號 | TOFU 一次性、IMDSv2、`verify_organization` / EKS 驗證、`skip_block_device` |
| **k8s_psat** | K8s 簽的 audience-bound projected token | audience 太寬被別人吃、SA allowlist 太寬（Day07 RBAC）、退回 legacy SAT | 專屬 audience 兩端對齊、`service_account_allow_list` 收窄、RBAC 限誰能用該 SA 起 pod |

**共同的冒領結構永遠是這句**：拿到「不是那台機器該獨佔的憑據」→ Server 相信你是可信 node → 你領走這台 node 被授權的所有 workload 身分。

而所有收窄手段，本質都在壓縮同三個維度：**這個憑據能被誰拿到、能被用幾次、有效多久**。

- **能被用幾次**：join token 一次性、aws_iid TOFU。
- **有效多久**：join token TTL、PSAT 短效輪替。
- **能被誰拿到**：IMDSv2（IID 誰能讀）、audience（token 誰能吃）、org/EKS/SA allowlist（哪個範圍的機器算數）。

**與 workload 層（Day84）的關係**，一句話收尾：Day84 收窄的是「同一台可信 node 上，哪個程序是誰」；今天收窄的是「哪台機器憑什麼算可信 node」。**node 層被冒領比 workload 層更致命**，因為 workload attestation 的整個前提就是「這台 node 可信」——**第一層破了，Day84 selector 收得再窄，都是蓋在流沙上的精緻工事。**

---

## 六、Day16 稽核：哪台機器用什麼 attestor 加入了 trust domain

node attestation 是信任鏈最上游，被冒領時你最需要能回答：「**哪台機器、什麼時候、用什麼憑據加入了我的 trust domain？**」好消息是——agent SPIFFE ID 本身就編碼了 attestor 與節點識別，`spire-server` 也給了處置指令：

```bash
spire-server agent list                       # 列出所有已 attest 的 node（可依 attestation type 過濾）
spire-server agent show  -spiffeID <agent-id> # 看單一 node 的細節與 selector
spire-server agent evict -spiffeID <agent-id> # 解除 attest（之後可重新 attest）
spire-server agent ban   -spiffeID <agent-id> # 封鎖：banned node 無法再 attest
spire-server agent count                       # 已 attest node 總數
```

**該告警的事件**（承 Day16，進防竄改集中式日誌）：

- **aws_iid TOFU 衝突**：真 Agent 啟動失敗——這代表可能有非 Agent 程序搶先 attest，第三節說過，這是資安事件不是雜訊。
- **非預期 attestor 出現在生產**：例如生產環境冒出 `join_token` 型 agent（本應只在 bootstrap / 裸機用），很可能是有人拿外洩 token 塞進來。
- **非預期 account / cluster / SA**：出現不在你 org / EKS / SA allowlist 內的 agent SVID。
- **join token 短時間大量產生**：`token generate` 被異常呼叫。

### 一段可放進 CI / 監控的稽核小工具

把「解析 agent list、對非預期 attestor 告警」寫成看得見的檢查，別靠肉眼。下面兩段解析 `spire-server agent list -output json`（或走 API），對「生產不該出現的 attestor / 帳號」判紅。沿用 Day84 稽核腳本的風格。

**Go 版：**

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// 對照你那版 spire-server agent list -output json 的實際結構調整欄位
type agentList struct {
	Agents []struct {
		ID              string `json:"id"`               // spiffe://td/spire/agent/<attestor>/...
		AttestationType string `json:"attestation_type"` // join_token / aws_iid / k8s_psat ...
		Banned          bool   `json:"banned"`
	} `json:"agents"`
}

// 生產環境允許的 attestor 白名單：join_token 刻意不在內
var allowedInProd = map[string]bool{
	"aws_iid":  true,
	"k8s_psat": true,
}

func main() {
	var list agentList
	if err := json.NewDecoder(os.Stdin).Decode(&list); err != nil {
		fmt.Fprintln(os.Stderr, "parse agent list failed:", err) // 解析失敗要往上丟，別當沒事
		os.Exit(2)
	}

	failed := false
	for _, a := range list.Agents {
		if a.Banned {
			continue
		}
		if !allowedInProd[a.AttestationType] {
			// 例如生產冒出 join_token 型 agent = 高度可疑
			fmt.Printf("[FAIL] unexpected attestor %q in prod: %s\n", a.AttestationType, a.ID)
			failed = true
		}
		// 進階：對 aws_iid 再檢查 account 是否在允許清單
		if a.AttestationType == "aws_iid" && !strings.Contains(a.ID, "/aws_iid/") {
			fmt.Printf("[WARN] malformed aws_iid agent id: %s\n", a.ID)
		}
	}
	if failed {
		os.Exit(1) // CI 紅 / 告警
	}
	fmt.Println("[OK] all attested nodes use approved attestors")
}
```

**Java 版（對稱，Jackson 解析）：**

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.util.Set;

public class NodeAttestorAudit {

    // 生產允許的 attestor；join_token 刻意排除
    private static final Set<String> ALLOWED_IN_PROD = Set.of("aws_iid", "k8s_psat");

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        boolean failed = false;

        try (InputStream in = System.in) {
            JsonNode root = mapper.readTree(in);       // 解析失敗會丟例外，不靜默吞掉
            for (JsonNode agent : root.path("agents")) {
                if (agent.path("banned").asBoolean(false)) {
                    continue;
                }
                String id = agent.path("id").asText();
                String type = agent.path("attestation_type").asText();

                if (!ALLOWED_IN_PROD.contains(type)) {
                    System.out.printf("[FAIL] unexpected attestor \"%s\" in prod: %s%n", type, id);
                    failed = true;
                }
            }
        }

        if (failed) {
            System.exit(1); // CI 紅 / 告警
        }
        System.out.println("[OK] all attested nodes use approved attestors");
    }
}
```

> Java 版本備註：`spire-server agent list -output json` 的欄位名（`attestation_type`、`banned`…）以你那版 SPIRE 的實際輸出為準；若走 API 而非 CLI，改對 gRPC / Registration API 回應結構解析。這裡示範的是「把非預期 attestor 攔在上線前」的意圖。

---

## 七、常見誤區

- **「node attestation 做了就安全」** ── attestor 選型與收窄沒做，等於門開著。三個 attestor 各有冒領邊界。
- **「join token 方便，生產也用」** ── join token 是一段祕密，規模化必外洩；它的定位是 bootstrap / 裸機 / dev。
- **「同一張 join token 烤進 image 給整批機器」** ── 違反一次性，且散佈萬能鑰匙。
- **「IID 有 AWS 簽章就偽造不了，所以安全」** ── 簽章偽造不了，但 IID 對同機任何程序可讀（Day10 SSRF 就能偷），且能重放到別帳號；要 IMDSv2 + TOFU + org/EKS 驗證。
- **「TOFU 是多餘的限制」** ── TOFU 正是擋「非 Agent 程序搶先 attest」與「同 node 重放」的關鍵；Agent 啟動失敗要當資安事件查，不是重開就好。
- **「`skip_block_device = true` 反正跑得起來」** ── 你關掉的是「root volume 有沒有被卸下冒充」的防竄改檢查。
- **「PSAT 跟 legacy SAT 差不多」** ── SAT 長效、不綁 audience、可無限重放；PSAT 短效、綁 audience、自動輪替，差很多。
- **「`audience` 留空 `[]` 比較不會出錯」** ── 留空退回 apiserver audience，等於讓別的元件也能吃這張 token 冒充 Agent；要設專屬 audience 且兩端對齊。
- **「`service_account_allow_list` 放寬一點省得一直改」** ── 放寬等於讓任何能用那些 SA 起 pod 的人冒充 Agent；強度封頂於 K8s RBAC（Day07）。
- **「node 層被冒領頂多影響一台」** ── 相反，node 是信任鏈最上游，被冒領直接偽造「可信機器」，Day84 workload selector 收再窄都無效。

---

## 八、Code Review / 維運 checklist

**Attestor 選型與定位**

- [ ] 生產節點身分根**不用** join token；join token 只出現在 bootstrap / 裸機 / dev。CI 稽核（第六節）攔生產冒出的 `join_token` 型 agent。
- [ ] 雲上用 `aws_iid`（或對應雲廠 attestor）、K8s 用 `k8s_psat`（非 legacy `k8s_sat`），讓「機器可驗證屬性」當憑據而非一段祕密。

**join token（若有用）**

- [ ] 短 TTL、產生即用、一機一張，絕不共用、絕不 pre-bake 進 image。
- [ ] token 走安全通道注入，不進 log / CI 變數 / IaC state（承 Day15）。
- [ ] `spire-server agent list` 輸出當敏感資料看待（SPIFFE ID 含 token 明文）。

**aws_iid**

- [ ] IMDSv2 開啟（session token + hop limit=1），收窄「誰能讀 IID」，別只靠 TOFU（承 Day10）。
- [ ] `verify_organization`（`account_list_file` 或 org API）限定可加入的帳號；`validate_eks_cluster_membership` 限定 EKS cluster。
- [ ] `skip_block_device` 維持預設 `false`（保留 root volume 防竄改檢查）。
- [ ] TOFU 衝突（真 Agent 啟動失敗）進告警，當資安事件調查（承 Day16）。

**k8s_psat**

- [ ] Server `audience` 與 Agent projected volume 的 audience **兩端對齊且為專屬用途**，不留空 `[]`。
- [ ] `service_account_allow_list` 收到專屬 `spire-agent` SA；K8s RBAC 限「誰能用該 SA 起 pod / 在該 namespace 部署」（承 Day07）。
- [ ] `clusters` 明確列舉（空 = fail-closed）；TokenReview 權限正確，別讓驗證默默退化。
- [ ] `allowed_node_label_keys` / `allowed_pod_label_keys` 的 label 只當輔助，不當唯一身分（承 Day84）。

**稽核與範圍認知（承 Day16）**

- [ ] CI / 監控解析 `agent list`，對非預期 attestor / account / cluster / SA 告警（第六節腳本）。
- [ ] 非預期 node 用 `agent ban`（阻止再 attest）或 `agent evict`（解除，可重新 attest）處置，動作留稽核。
- [ ] 清楚 node attestation 防的是「哪台機器算可信 node」；跨到 node 上「哪個程序是誰」由 workload attestation（Day84）負責，別混為一談。

---

## 九、測試 / 演練建議

- **冒領搶先測試（aws_iid TOFU，最重要）**：在一台 node 上，讓一個**非 Agent 程序**搶先讀 IID 去 attest，斷言真 Agent 隨後**啟動失敗**且 Server / Agent 都留 log、告警有叫。這是「TOFU + 偵測」的存在證明——測不過代表你的搶先偵測是擺設。
- **IID 可讀性收窄驗證**：關 IMDSv2 時，從應用層容器 `curl` metadata endpoint 斷言**讀得到** IID（暴露 SSRF 偷 IID 的洞）；開 IMDSv2（hop limit=1）後斷言應用層**讀不到**（承 Day10）。
- **join token 一次性測試**：產一張 token，第一台 attest 成功後拿**同一張** token 給第二台，斷言**被拒**。把「一次性」寫成看得見的迴歸案例。
- **PSAT audience 不符測試**：把 Agent projected volume 的 audience 改成和 Server `audience` 不一致，斷言 attest **失敗**；再拿一張 audience 給別的元件用的 token 冒充，斷言**被拒**——audience 綁定的存在證明。
- **SA allowlist 收窄迴歸**：把 `service_account_allow_list` 從專屬 SA 放寬到整個 namespace / 通用 SA，斷言第六節 CI 稽核或部署 gate **會紅**。
- **非預期 attestor 攔截測試**：在測試環境故意用 join token 加入一個 agent，斷言第六節腳本把它**判紅**（生產不該有 join_token 型 agent）。
- **處置演練**：對一個可疑 agent 跑 `agent ban`，斷言它**無法再 attest**；跑 `agent evict` 後斷言它**可以重新 attest**——確認團隊知道兩者差別。

---

## 十、一句話總結

> Day80 把 attestation 講成兩層、缺一不可；Day84 拆了第二層（workload selector 冒領邊界），今天回到第一層——**node attestation 不是「機器連上來就可信」，而是「你選的那個 attestor，它拿來當節點身分根的那份憑據，能不能被『不是那台機器的東西』拿到」。** 三個常見 attestor 三種信任根、三種冒領邊界：**join token** 是一段預先發出去的祕密，踩的全是 Day15 老病——外洩、重用、塞進不該加入的機器，一次性加 TTL 只是緩解不是免死金牌，定位是 bootstrap / 裸機而非規模化生產身分根；**AWS IID** 的簽章偽造不了，但官方白紙黑字寫「IID 對 node 上任何程序都可讀」，於是被 SSRF 打穿的服務、同機惡意程序都能偷 IID 去 attest 領走整台 node 的身分（Day10 那條 `169.254.169.254` 的線），緩解要 TOFU 一次性 + IMDSv2 收窄誰能讀 + `verify_organization` / EKS 驗證收窄哪個帳號算數 + 別關 `skip_block_device` 的 root volume 防竄改；**K8s PSAT** 用短效、綁 audience、自動輪替的 projected token，本身就是把 legacy SAT 那顆長效裸祕密升級掉，但 `audience` 留空退回 apiserver audience 就讓別的元件也能吃這張 token 冒充 Agent，`service_account_allow_list` 太寬就讓任何能用那些 SA 起 pod 的人冒充——強度封頂於 K8s RBAC（Day07 誰能挑 SA 起 pod 的老題）。把三者攤平，收窄的其實是同三個維度：**這憑據能被誰拿到、能被用幾次、有效多久**——一次性 / TOFU 管次數、TTL / 短效輪替管時效、IMDSv2 / audience / org・SA allowlist 管範圍。最後用 Day16 縱深：agent SPIFFE ID 本身編碼 attestor 與節點識別，`spire-server agent list / show / ban / evict` 加上「解析 agent list、對生產冒出 join_token 型 agent 或非預期帳號告警」的 CI 稽核，讓「哪台機器用什麼憑據加入 trust domain」查得到、攔得住。一句話：**Day84 收窄了「node 上哪個程序是誰」，Day85 收窄「哪台機器憑什麼算可信 node」——這一層被冒領，你在 workload 層綁的每一條 selector，都只是蓋在流沙上的精緻工事。**

---

## 延伸閱讀

- Day80 SPIFFE / SPIRE workload identity——本篇上游：attestation 兩層、node attestor 名單、Workload API 概念都在這，今天只展開第一層的冒領邊界。
- Day84 SPIRE workload attestation selector——第二層（程序）冒領邊界；本篇是第一層（機器）。兩篇合起來才是完整的「這台機器 + 這個程序」信任鏈。
- Day10 SSRF——`aws_iid` 的核心風險線：能讓服務去讀 `169.254.169.254` metadata 就能偷 IID；IMDSv2 是同一套收窄。
- Day15 Secrets Management——join token 就是一段 secret，外洩 / 重用 / 傳遞的老病與收窄全在這。
- Day26 Webhook Security——「一次性 + 重放防護」的心智模型（TOFU 是節點層的重放防護）。
- Day07 Broken Access Control——`k8s_psat` 的 `service_account_allow_list` 強度封頂於「誰能用某 SA 起 pod」的 K8s RBAC。
- Day05 Session vs JWT——projected SA token 的 audience 綁定、短效、可驗證，與 token 設計取捨同源。
- Day16 Security Logging / Monitoring——「哪台機器用什麼 attestor 加入」的執行期稽核與非預期 attestor 的 CI 攔截。

---

明天預告：**Day 86 — SPIRE Agent 與 Workload API socket 的存取控制：SPIFFE CSI Driver、hostPath 掛載風險與同機多租戶隔離（延伸篇）**
（這篇是**延伸篇**，不重講 Day80 attestation 兩層、也不重講 Day84 workload selector 與今天的 node attestor。前面兩天把「哪台機器可信」「node 上哪個程序是誰」都收窄了，但這一切的前提是——workload 得先**連得上** SPIRE Agent 的那個 Unix domain socket，才輪得到 workload attestation 去反查它的特徵。明天聚焦那個 socket 本身的存取控制：**① socket 的掛載方式**——K8s 裡 Agent 的 `agent.sock` 常透過 `hostPath` 掛進各 pod，或改用 **SPIFFE CSI Driver** 以受控方式注入，兩者的存取邊界差在哪、為什麼「誰的 pod 掛到這個 socket」就是第一道門（承 Day11 掛載 / Day07 最小權限）；**② 連得上 socket ≠ 拿得到 SVID**——socket 只是外層閘門，真正發不發還是靠 Day84 的 workload attestation，但連不上 socket 的程序連「湊 selector」的機會都沒有，所以 socket 存取控制是把冒領攻擊面**先砍一刀**；**③ 同機多租戶隔離**——一個 node 上多租戶 workload 共用同一個 Agent 時，怎麼確保 A 租戶的 pod 沒辦法透過 socket 去要 B 租戶的身分，socket 權限、per-workload socket、mesh sidecar 各自的隔離模型。程式面會示範 K8s `securityContext` 與 volume 掛載收窄、SPIFFE CSI Driver 的 `readOnly` 注入，以及用 Day16 角度稽核「哪些 pod 掛了 agent socket」。安全主軸一句話：**Day84 / Day85 收窄了「你是誰」，Day86 要收窄「你連不連得上發身分的那個窗口」——socket 開太大，attestation 收得再嚴，攻擊者也已經站在櫃台前了。** 這是延伸篇，只聚焦 Workload API socket 的存取控制與同機隔離，不重述 attestation 兩層的基本流程。）
