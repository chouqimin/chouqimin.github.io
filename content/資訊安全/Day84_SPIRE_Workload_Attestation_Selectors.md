---
title: "Day 84：SPIRE workload attestation 的 selector 冒領邊界 — K8s / Unix / Docker 各平台怎麼被騙（延伸篇）"
date: 2026-07-24
tags: ["SPIFFE", "SPIRE", "Workload Attestation", "Selector"]
---

接續 Day83 預告：Day80 講 workload attestation 時說，Agent 會「反過來觀察呼叫方的核心層屬性（PID → UID/GID、K8s pod/SA、binary 路徑、SELinux label）比對 registration entry 才發 SVID」，聽起來像一道沒有祕密可偷、硬到攻不破的防線。今天就來拆這道防線的**真實邊界**。

**這篇是延伸篇，不重講 Day80 的 attestation 兩層基本流程，也不碰 Day83 的 CA 金鑰保管。** node attestation 怎麼先確認機器可信、為什麼兩層缺一不可、workload 呼叫 Workload API 不帶 token 而是靠 socket 對端 PID 反查——這些 Day80 都講過，今天不重述。這篇只聚焦一件 Day80 只點名、沒展開的事：**你在 registration entry 綁的那組 selector，到底有多難被「同一台機器上的另一個程序」湊出來。**

延伸角度只有一條主軸：**attestation 不是「有做就安全」，而是「你綁的那組 selector 的冒領邊界在哪」——selector 開太寬，Day80 那道最精妙的防線就退化成擺設。** 三個平台各自拆：① K8s selector、② Unix selector、③ Docker selector，再回答 ④ 為什麼單一 selector 幾乎都能繞、必須疊加。

> ⚠️ 以下 selector 的 key 名稱（`k8s:ns`、`k8s:sa`、`unix:sha256`、`docker:label`…）會隨 SPIRE 版本與各 workload attestor plugin 演進。實際部署請對照你那版 attestor 的官方文件，別照抄字串。這裡示範的是**冒領邊界與收窄的意圖**，不是某一版的精確語法。

---

## 一、先定位威脅：selector 是一組 AND，冒領＝同機另一個程序湊齊同一組

Day80 說 registration entry 長這樣：一個 SPIFFE ID，配上一組 selector。關鍵性質是——**那組 selector 是 AND**。Agent 對來要 SVID 的程序做 attestation，只有**每一條 selector 都對得上**，才把這個 SPIFFE ID 的 SVID 發給它。

所以威脅模型很窄、很具體：**同一個 SPIRE Agent 管的同一台機器（同一個 node）上，有另一個程序被攻陷或本來就是惡意的（隔壁 pod 被 RCE、同機的低權限服務、被塞進來的 sidecar）。它連上同一個 Workload API socket，Agent 一樣會對它做 attestation。問題只剩一個：它能不能湊出和 `payment-service` 一模一樣的那組 selector？**

- selector 綁得**越寬**（例如只綁「在 production namespace」），同機湊齊的程序**越多** → 冒領越容易。
- selector 綁得**越窄、越難自我偽造**（例如綁到「這支確切 binary 的 sha256」），同機能湊齊的**只剩它自己** → 冒領越難。

這就是為什麼 Day80 把 workload attestation 說成「最精妙」卻沒展開——精妙的不是「有做 attestation」，是「你選的 selector 到底把身分收到多窄」。收窄 selector 本質上就是 Day07 的**最小權限**搬到「身分發放」這一層，開太寬就是 Day49 BFLA 那種「範圍開太大」的老毛病換個地方犯。

下面三節，就逐一看每種 selector「被同機另一個程序湊出來」的難度。

---

## 二、K8s selector 的冒領邊界

K8s workload attestor 的做法：從呼叫方 PID 找到它的 cgroup、對應到 container，再去問 kubelet「這個 container 屬於哪個 pod」，把 pod 的屬性攤成 selector：namespace、service account、pod 名、pod label、container 名、container image…

### ① 只綁 namespace＝把身分開放給整個 namespace

最常見、也最危險的寫法：

```bash
# 危險示範：只綁 namespace
spire-server entry create \
    -spiffeID spiffe://example.org/payment-service \
    -parentID spiffe://example.org/spire/agent/k8s_psat/prod-cluster/<node-uid> \
    -selector k8s:ns:production
```

`k8s:ns:production` 的意思是「**在 production namespace 裡的任何 pod**」。這條 selector 一旦是唯一條件，`production` 底下**每一個** pod——包括那個剛被 RCE 的無關服務、那個第三方 sidecar——連上 Workload API 都對得上，於是**都能拿到 `payment-service` 的 SVID**。namespace 是**部署範圍**，不是**身分**。這跟 Day49 BFLA「把授權範圍開到整個角色」是同一個錯誤：你以為綁了條件，其實那個條件涵蓋了一大票不該進來的人。

> `-parentID` 是這台 node 的 Agent SVID（來自 Day80 第一層 node attestation）。它限定「這條 entry 只在這個 node 上生效」，但**不**限定 node 上的哪個程序——收窄程序是 selector 的事，別把 parentID 當 selector 用。

### ② 加上 service account：收窄一大截，但不是終點

```bash
-selector k8s:ns:production
-selector k8s:sa:payment          # 綁到 service account
```

加上 `k8s:sa:payment` 後，條件變成「production namespace 且 service account 是 `payment`」。這砍掉了同 namespace 其他 SA 的 pod，是**必要**的收窄。但 SA 不是萬能：

- **多個工作負載共用同一個 SA**：很多團隊圖方便讓一個 namespace 底下一票 pod 共用一個 SA。那 SA 一被共用，`k8s:sa` 的鑑別力就退回接近 namespace 等級——共用者互相都能冒領。
- **誰能用這個 SA 開 pod**：如果攻擊者拿到「在 production 建立 pod 且指定 SA=payment」的 RBAC 權限（承 Day07），他就能合法地開一個掛著 payment SA 的 pod，attestation 完全通過。這時候要防的不是 SPIRE，是**K8s RBAC 別讓人隨便挑 SA 開 pod**——SPIRE 的 selector 強度，被 K8s 那層的權限邊界封頂。

### ③ pod-label：自陳資料，設 label 的人就能改身分

```bash
-selector k8s:pod-label:app:payment    # 用 pod 的 label 當身分
```

看起來很方便，但要問一句：**這個 label 是誰貼上去的？** pod label 寫在 Deployment / pod spec 裡，**任何能改那份 YAML、能 apply 那個 manifest 的人，就能把任意 pod 貼上 `app: payment`**。label 是**自我宣稱的中繼資料**，不是平台幫你驗過的事實——這跟 Day82 講 bundle endpoint「別吃動態輸入」、Day08 講「別信 client 塞的欄位」是同一種戒心。把 self-asserted 的 label 當身分，等於讓「能寫 manifest 的人」＝「能決定誰是 payment-service 的人」。可以當**輔助** selector，但不能當**唯一**或**主要**的身分依據。

### ④ container-image：綁到「跑的是哪個映像」，但要 pin digest

```bash
-selector k8s:container-image:registry.example.com/payment@sha256:<digest>
```

綁 container image 比綁 label 強，因為 image 不是隨手貼的字串、是真的跑起來的東西。但有個 Day18 的老坑：**綁 tag 等於沒綁死**。`payment:latest`、`payment:v3` 這種 mutable tag，攻擊者只要能推一個新映像蓋掉 tag、或讓 CI 重推，`container-image` 就對上了。**要綁就綁 digest（`@sha256:...`）**，把身分釘死在「這一份不可變的映像內容」上——這正是 Day18 供應鏈那條「用 digest 而非 tag 鎖依賴」搬到 attestation。

小結：K8s selector 的收窄光譜大致是 `ns`（最寬）< `sa` < `pod-label`（自陳、慎用）< `container-image@digest`（較硬）。單挑任何一條幾乎都留有冒領縫，**要疊**——這留到第五節。

---

## 三、Unix selector 的冒領邊界（裸機 / 非 K8s 場景）

沒有 K8s 的裸機、VM、或 docker-compose 場景，靠 unix workload attestor：從 socket 對端 PID，用 OS 查出 UID/GID、執行檔路徑、執行檔內容雜湊。

### ① unix:uid / gid：容器內外不對應，且 root 到處都是

```bash
-selector unix:uid:1000
```

兩個邊界：

- **UID 在容器內外不是同一回事**。容器裡的 uid 1000，映射到宿主可能是別的 uid、也可能一堆容器都用 uid 1000。用 uid 當身分，等於「同 uid 的程序互相都能冒領」。
- **一堆服務用 root（uid 0）跑**。`unix:uid:0` 幾乎等於「這台機器上任何 root 程序」，鑑別力接近零。

uid/gid 適合當**額外**條件（例如「而且不是 root」），不適合當主要身分。

### ② unix:path：路徑是字串，能被同名檔 / bind mount 混淆

```bash
-selector unix:path:/opt/app/payment
```

`path` 綁的是「執行檔的路徑字串」。冒領邊界在於**路徑不等於內容**：

- 攻擊者若能在那個路徑放一支**同名但不同內容**的執行檔（可寫的目錄、共用 volume、bind mount 把自己的檔掛到 `/opt/app/payment`），路徑就對上了——這是 Day11/Day12 那種「路徑 / 檔名可被操弄」的心智模型搬到 attestation。
- 不同容器可以各自都有 `/opt/app/payment`，路徑相同、內容天差地遠。

path 比 uid 好，但仍只是「字串相符」，不是「內容相符」。

### ③ unix:sha256：最硬的 unix selector——但對 Java 幾乎無效

```bash
-selector unix:sha256:<hex>
# 這個 hash 這樣算：
sha256sum /opt/app/payment | awk '{print $1}'
# 把輸出填進上面的 unix:sha256:<hex>
```

`unix:sha256` 綁的是**執行檔的內容雜湊**——把身分釘死在「這一份確切的 bytes」。攻擊者要冒領，得在同機跑出一支**內容一模一樣**的執行檔（那基本上就是你的程式本體了），path 那招的同名檔、bind mount 全部失效。這是 unix 系最值得用的一條。

**但這裡有一個後端工程師必須知道、且 Java / Go 待遇完全不同的關鍵：**

- **Go：一顆自帶依賴的靜態 binary。** `/opt/app/payment` 就是你的程式本體，`unix:sha256` 直接綁死它 → Go 服務可以靠 `unix:sha256` 收得很緊。
- **Java：`unix:sha256` 綁到的是 JVM，不是你的 app。** `java -jar payment.jar` 跑起來，那個**程序的執行檔是 `/usr/bin/java`（JVM launcher），不是 `payment.jar`**。於是：

  ```bash
  sha256sum "$(command -v java)"
  # 這台機器上「每一個 JVM 服務」算出來都是同一個 hash！
  ```

  也就是說，**`unix:sha256` 對 Java 服務沒有鑑別力**——你綁的是 java 這支 launcher 的雜湊，同機所有 JVM 服務（payment、order、report…）全部共用同一個值，彼此都能冒領。`unix:path:/usr/bin/java` 同理，全 JVM 共享。

  Java 場景的收窄只能靠**別的軸**：K8s 環境走 `k8s:sa` + `container-image@digest`（第二節）；純裸機多 JVM 同機時，退而求其次讓**每個 JVM 服務跑在不同的 unix user 下**（`unix:user` / `unix:uid` 給每服務一個專屬帳號），再搭配作業系統權限隔離。這是 SPIFFE 世界裡「Go 是編譯語言、Java 跑在共用 runtime」這個事實在 attestation 層的直接後果，跟 Day79 講「Java 常躲在 LB 後面 TLS 不在 JVM 終結」一樣，是**部署形態差異**、不是誰比較安全。

### ④ PID 重用 / TOCTOU：承 Day22 的老朋友

unix（乃至所有平台）attestation 的地基是「用 socket 對端 PID 反查屬性」。這裡藏著 Day22 那款 **TOCTOU**：從「程序連上 socket」到「Agent 去查這個 PID 的屬性」之間有時間差，理論上 PID 可能在這中間**結束並被回收重用**，讓 Agent 查到的屬性屬於另一個程序。SPIRE 對此有緩解（例如儘快從連線當下的憑證資訊取屬性），但**心智模型要正確**：PID 是會被重用的整數，不是永久身分。這條不是要你去實作什麼，而是提醒——attestation 的可信度，最終還是踩在 OS 給的那些屬性有多難被同機操弄之上。

---

## 四、Docker selector 的冒領邊界

非 K8s、直接用 Docker / compose 的場景，靠 docker workload attestor：從 PID 對應到 container，讀 container 的 label、env、image。

```bash
-selector docker:label:com.example.service:payment   # 用 container label 當身分
-selector docker:env:SERVICE_NAME:payment            # 用環境變數當身分
```

跟 K8s 的 pod-label 同一個病，而且更明顯：**label 和 env 都是 compose 檔 / `docker run` 參數裡自己寫的**。誰能改 `docker-compose.yml`、誰能下 `docker run --label ...`，誰就能給任意 container 貼上 `com.example.service=payment`。這是**自陳身分**，信任邊界完全落在「誰能改那份 compose 檔、誰能在這台 host 上開 container」。

比較硬的是綁映像：

```bash
-selector docker:image_id:sha256:<image-digest>   # 綁映像內容,較難偽造
```

`docker:image_id` 綁到映像的 digest，跟 K8s 的 `container-image@digest` 同精神——攻擊者得跑出**同一份映像**才對得上，比改 label 難得多。但一樣別綁可變 tag。

Docker selector 的收窄光譜：`label` / `env`（自陳、最弱）< `image_id`（綁 digest，較硬）。結論還是那句：**單條不夠，要疊。**

---

## 五、為什麼要疊加 selector：把「同機能湊齊的集合」收到只剩它自己

前三節每一種 selector 都有它自己的冒領縫。疊加的意義是**AND 的交集**：攻擊者必須在同一個程序上**同時**滿足所有 selector，縫才會一條一條被補起來。

- 只綁 `k8s:ns:production`：同 namespace 任一 pod 都行。
- `+ k8s:sa:payment`：砍到「用 payment SA 的 pod」。
- `+ k8s:container-image:...@sha256:digest`：再砍到「用 payment SA **且**跑這份確切映像的 pod」。

同機要湊齊這三條，攻擊者得「用 payment 這個 SA 開 pod、且跑的是你那份釘死 digest 的映像」——這已經逼近「他得有能力部署一個跟 payment-service 實質相同的東西」，冒領成本被拉到跟直接控制部署管線同級。

### 收窄後的 registration entry（K8s / Go 或 Java 皆適用）

```bash
# 收窄示範：SA + 映像 digest,三條 AND
spire-server entry create \
    -spiffeID spiffe://example.org/payment-service \
    -parentID spiffe://example.org/spire/agent/k8s_psat/prod-cluster/<node-uid> \
    -selector k8s:ns:production \
    -selector k8s:sa:payment \
    -selector k8s:container-image:registry.example.com/payment@sha256:<digest>
```

K8s 場景不管你的服務是 Go 還是 Java，收窄策略都靠這幾條**平台層** selector（因為第三節說過，Java 的 `unix:sha256` 綁到 JVM 沒鑑別力，要靠 SA + image digest）。

### 裸機 Go 服務：疊 unix:user + unix:sha256

```bash
# 裸機 / 非容器的 Go 服務:用專屬帳號 + binary 內容雜湊
spire-server entry create \
    -spiffeID spiffe://example.org/payment-service \
    -parentID spiffe://example.org/spire/agent/join_token/<node> \
    -selector unix:user:payment \
    -selector unix:sha256:<把 /opt/app/payment 算出來的 hash 填進來>
```

Go 靜態 binary 讓 `unix:sha256` 真的釘死你的程式本體，再加一個專屬 unix user 收窄執行身分——同機另一個程序要冒領，得「用 payment 這個帳號跑一支內容雜湊完全相同的執行檔」，縫收得很緊。

**裸機 Java 服務**沒有等價的乾淨解（`unix:sha256` 綁 JVM 無效），務實做法是：每個 JVM 服務一個專屬 unix user（`unix:user:payment`）＋作業系統層把該帳號的可執行內容與工作目錄權限鎖死，並認清「裸機同機多 JVM」本來就是 attestation 最難收窄的形態——能上 K8s / 容器用 image digest selector，就別讓多個 JVM 裸機共處一個 Agent。

一句話：**單一 selector 幾乎都能被同機另一個程序湊出來；attestation 的強度＝你疊出來那組 selector 的交集有多難被偽造。**

---

## 六、Day16 角度：稽核「attestation 通過了哪些 selector」＋ CI 攔截過寬 entry

selector 收窄是設計期的事，但**會 drift**：有人為了「先跑起來」加了一條 `k8s:ns` 的寬 entry、有人把 digest 改回 tag、有人共用了 SA。所以要把「entry 有多寬」變成**可稽核、可在 CI 攔下**的東西（承 Day16 稽核、Day07 最小權限）。

兩個層面：

1. **執行期稽核**：SPIRE Server 每次簽發 SVID 的 audit log 會記「哪個 registration entry、通過了哪些 selector、發給哪個 SPIFFE ID」。把它接進 Day16 的集中式日誌，就能事後查「payment-service 的 SVID 是不是被非預期的 selector 組合換走過」。
2. **設定期攔截**：在 CI 掃所有 registration entry，把「只綁 namespace / 只綁 uid / 綁 mutable tag」這種過寬 entry 直接擋在上線前。

下面是設定期的 CI 稽核。用 `spire-server entry show -output json` 取出所有 entry，規則是「每個 entry 至少要有一條把身分收窄到具體工作負載的強 selector」，否則 CI 紅。

Go 版（注意 SPIRE 的 selector JSON 是 `{type, value}`，type 是 attestor、value 是其餘部分）：

```go
package main

import (
	"encoding/json"
	"log"
	"os/exec"
	"strings"
)

type selector struct {
	Type  string `json:"type"`  // "k8s" / "unix" / "docker"
	Value string `json:"value"` // "ns:production" / "sha256:..." / "sa:payment"
}

type entry struct {
	SpiffeID  string     `json:"spiffe_id"`
	Selectors []selector `json:"selectors"`
}

func main() {
	out, err := exec.Command("spire-server", "entry", "show", "-output", "json").Output()
	if err != nil {
		log.Fatalf("cannot list entries: %v", err)
	}
	var res struct {
		Entries []entry `json:"entries"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		log.Fatalf("bad json: %v", err)
	}

	var bad []string
	for _, e := range res.Entries {
		if !hasStrongBinder(e.Selectors) {
			bad = append(bad, e.SpiffeID+"  selectors="+format(e.Selectors))
		}
	}
	if len(bad) > 0 {
		// CI 直接紅:別讓「只綁 namespace / 只綁 uid」的 entry 進正式環境(承 Day07/Day16)
		log.Fatalf("over-broad registration entries:\n%s", strings.Join(bad, "\n"))
	}
	log.Printf("ok: %d entries, all have a strong binder", len(res.Entries))
}

// 強 selector:能把身分收窄到「具體這個工作負載」而非「一整個範圍」的條件
func hasStrongBinder(sels []selector) bool {
	for _, s := range sels {
		switch s.Type {
		case "k8s":
			// SA 或釘 digest 的映像算強;ns / pod-label 不算
			if strings.HasPrefix(s.Value, "sa:") ||
				(strings.HasPrefix(s.Value, "container-image:") && strings.Contains(s.Value, "@sha256:")) {
				return true
			}
		case "unix":
			// binary 內容雜湊算強;uid / path 不算(承第三節:Java 的 sha256 綁 JVM 另有例外要人工覆核)
			if strings.HasPrefix(s.Value, "sha256:") {
				return true
			}
		case "docker":
			if strings.HasPrefix(s.Value, "image_id:") {
				return true
			}
		}
	}
	return false
}

func format(sels []selector) string {
	parts := make([]string, 0, len(sels))
	for _, s := range sels {
		parts = append(parts, s.Type+":"+s.Value)
	}
	return strings.Join(parts, ",")
}
```

Java 版（同樣的規則，Jackson 解 JSON，回傳過寬 entry 供 CI 斷言）：

```java
// 掃 spire-server entry show -output json,列出「缺強 selector」的過寬 entry
// 供 CI / 單元測試斷言為空(承 Day16 稽核、Day07 最小權限)
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;

public class EntryAuditor {

    public List<String> findOverBroadEntries(String entryShowJson) throws Exception {
        JsonNode root = new ObjectMapper().readTree(entryShowJson);
        List<String> bad = new ArrayList<>();
        for (JsonNode e : root.path("entries")) {
            if (!hasStrongBinder(e.path("selectors"))) {
                bad.add(e.path("spiffe_id").asText());
            }
        }
        return bad;
    }

    private boolean hasStrongBinder(JsonNode selectors) {
        for (JsonNode s : selectors) {
            String type = s.path("type").asText();
            String value = s.path("value").asText();
            switch (type) {
                case "k8s":
                    if (value.startsWith("sa:")
                        || (value.startsWith("container-image:") && value.contains("@sha256:"))) {
                        return true;
                    }
                    break;
                case "unix":
                    // 注意:Java 服務的 unix:sha256 綁到 JVM launcher,無鑑別力,
                    // 這類 entry 建議在 CI 額外標記人工覆核,別當成真的收窄(承第三節)
                    if (value.startsWith("sha256:")) return true;
                    break;
                case "docker":
                    if (value.startsWith("image_id:")) return true;
                    break;
                default:
                    // 未知 attestor:當作不強,逼人工確認
            }
        }
        return false;
    }
}
```

這支稽核本身不是 attestation 的替代，是**縱深**：attestation 在執行期擋同機冒領，這支在設定期擋「有人把 selector 開太寬」——兩層一起，才不會發生「架構圖上寫了 workload attestation、實際上每條 entry 都只綁 namespace」這種假安心。

---

## 七、常見誤區表

- **「有做 workload attestation 就擋得住同機冒領」**——擋不擋得住取決於 selector 綁多窄。只綁 `k8s:ns` 等於整個 namespace 都能冒領，attestation 形同虛設。
- **「綁了 namespace 就有隔離」**——namespace 是部署範圍不是身分；同 namespace 的惡意 pod 照樣對上。
- **「用 pod-label / docker-label 當身分很方便」**——label 是自陳資料，能改 manifest / compose 檔的人就能改身分。當輔助可以，當主要身分是把門鑰交給「能寫設定的人」。
- **「綁 container image 就釘死了」**——綁 mutable tag（`:latest` / `:v3`）沒釘死，要綁 `@sha256:digest`（承 Day18）。
- **「unix:path 綁了執行檔就安全」**——path 是字串不是內容，同名檔 / bind mount 就能混淆（承 Day11/12）。要用 `unix:sha256` 綁內容。
- **「unix:sha256 對誰都是最硬的」**——對 Go 靜態 binary 是；對 Java 綁到的是 `/usr/bin/java`，同機所有 JVM 服務共用同一個雜湊＝零鑑別力，Java 要靠 `k8s:sa` + image digest 或專屬 unix user。
- **「uid 綁了就好」**——容器內外 uid 不對應，且一堆服務用 root，`unix:uid:0` 幾乎等於「任何 root 程序」。
- **「單一 selector 綁對就夠」**——每種 selector 都有自己的冒領縫，要疊 AND 把交集收到只剩它自己。
- **「selector 是設定一次的事」**——會 drift（有人加寬 entry、把 digest 改回 tag、共用 SA）。要 CI 稽核 + 執行期 audit（承 Day16）。
- **「SPIRE 收窄了，K8s RBAC 就不用管」**——反了。若攻擊者能用 payment SA 隨便開 pod，`k8s:sa` 這條就被 RBAC 那層破了；selector 強度被 K8s 權限邊界封頂（承 Day07）。

---

## 八、Code Review / 維運 checklist

**Selector 收窄（本篇核心）**

- [ ] 正式環境**沒有**只綁 `k8s:ns` 或只綁 `unix:uid` 的 entry；每條 entry 至少一條把身分收窄到具體工作負載的強 selector（`k8s:sa` + `container-image@digest`、或 `unix:sha256`、或 `docker:image_id`）。
- [ ] container image selector 綁 **digest（`@sha256:`）不綁 mutable tag**（承 Day18）。
- [ ] pod-label / docker-label / env 這類**自陳** selector 只當輔助，不當唯一或主要身分依據。
- [ ] Java 服務**不靠** `unix:sha256`（綁到 JVM 無鑑別力）；改用 `k8s:sa` + image digest，或每 JVM 專屬 unix user。

**平台權限邊界（承 Day07）**

- [ ] K8s RBAC 收緊「誰能用某 SA 開 pod」——`k8s:sa` 的強度依賴這層；別讓人隨便挑 SA。
- [ ] 裸機 / compose 場景，「誰能改 compose 檔、誰能在 host 上開 container / 放執行檔到綁定路徑」受控（承 Day11）。

**稽核與偵測（承 Day16）**

- [ ] CI 掃 `spire-server entry show` 攔截過寬 entry（第六節腳本），過寬即 CI 紅。
- [ ] SPIRE Server audit log（哪條 entry、通過哪些 selector、發給哪個 SPIFFE ID）進集中式、防竄改日誌；非預期 selector 組合換走 SVID 要能查得到。

**範圍認知（承 Day80）**

- [ ] 清楚 selector 收窄防的是**同一 node、同一 Agent 底下的同機冒領**；跨 node 的信任由 node attestation（Day80 第一層）負責，別混為一談。

---

## 九、測試 / 演練建議

- **同機冒領測試（最重要）**：在同一個 node 上，跑一個**特徵刻意對不上** registration entry 的程序（例如錯的 SA、錯的映像、內容不同的 binary），連上 Workload API，斷言 **Agent 不發 SVID**。這是 Day80「attestation 冒領測試」的具體化——測不過代表你的 selector 是擺設。
- **selector 收窄迴歸測試**：故意把某條 entry 從「SA + image digest」放寬成「只綁 ns」，斷言第六節的 CI 稽核**會紅**。把「別開太寬」寫成看得見的迴歸案例。
- **Java sha256 無效性驗證**：在同機跑兩個不同的 JVM 服務，斷言它們的 `unix:sha256`（＝java launcher 的雜湊）**相同**，藉此在團隊內建立「Java 別靠 unix:sha256」的共識，並確認那兩個 JVM 服務的 entry 是靠 `k8s:sa` / image digest 區分、而非 unix binary selector。
- **image tag vs digest 測試**：對一條綁 `container-image:...:tag` 的 entry，重推一個同 tag 的惡意映像，斷言它**仍能**通過（暴露 mutable tag 的洞）；改綁 `@sha256:digest` 後，斷言惡意映像**無法**通過。
- **label 偽造測試**：開一個把 `pod-label` / `docker:label` 設成 payload 的無關 pod / container，斷言若 entry 靠 label 當唯一身分則被冒領成功——用這個結果說服團隊把 label 降級為輔助。
- **audit 對得上測試**：發一批 SVID 後，斷言 SPIRE audit log 記到「每次簽發通過了哪組 selector」，且能對上預期的 entry（承 Day16）；模擬「有人偷加一條寬 entry」，斷言 CI 稽核在上線前就攔下。

---

## 十、一句話總結

> Day80 把 workload attestation 講成「沒有祕密可偷、Agent 反查呼叫方核心層屬性比對 registration entry 才發 SVID」的最精妙防線，但精妙的從來不是「有做 attestation」，而是**你綁的那組 selector 有多難被同一台機器上的另一個程序湊出來**——selector 是 AND，綁越寬同機能湊齊的程序越多、冒領越容易。三個平台各有冒領邊界：**K8s** 只綁 `k8s:ns` 等於開放整個 namespace，加 `k8s:sa` 收一截但 SA 共用或 RBAC 放任挑 SA 就破，`pod-label` 是自陳資料設 label 的人就能改身分，`container-image` 要綁 `@sha256:digest` 不能綁 mutable tag（承 Day18）；**Unix** `uid` 容器內外不對應且 root 到處都是、`path` 是字串能被同名檔/bind mount 混淆（承 Day11/12）、`unix:sha256` 綁內容最硬**但對 Java 幾乎無效**因為它綁到的是 `/usr/bin/java`、同機所有 JVM 服務共用同一個雜湊——Go 靜態 binary 能靠 sha256 釘死本體、Java 只能改靠 `k8s:sa`+image digest 或專屬 unix user，這是編譯語言 vs 共用 runtime 的部署形態差異不是誰比較安全；**Docker** `label`/`env` 自陳最弱、`image_id` 綁 digest 較硬；再加上所有平台底層都踩在「PID 反查屬性」上而 PID 會被重用（Day22 TOCTOU 的心智模型）。解法就一句：**單一 selector 幾乎都能繞，要疊 AND 把交集收到只剩它自己**——K8s 疊 `ns+sa+image@digest`、裸機 Go 疊 `unix:user+unix:sha256`，把冒領成本拉到「攻擊者得有能力部署一個跟你實質相同的工作負載」。最後用 Day16 縱深：執行期把「每次簽發通過了哪組 selector」記進防竄改 audit、設定期用 CI 掃 `spire-server entry show` 攔下「只綁 namespace / 只綁 uid / 綁 mutable tag」的過寬 entry，別讓架構圖上寫了 workload attestation、實際每條 entry 都開到整個 namespace。一句話：**attestation 的強度不是布林值，是你那組 selector 的交集有多窄；selector 開太寬，Day80 那道最精妙的防線就退化成一張貼在門上、誰都能撕的名牌。**

---

## 延伸閱讀

- Day80 SPIFFE / SPIRE workload identity——本篇上游：attestation 兩層、Workload API 反查 PID、selector 概念都在這，今天只展開它的冒領邊界。
- Day83 SPIRE Server 信任根保管——另一條攻擊面：selector 收得再窄，CA 金鑰被偷一樣能簽任意 SPIFFE ID，兩篇是 attestation 與簽發金鑰兩個獨立問題。
- Day07 Broken Access Control——selector 收窄＝身分發放的最小權限；K8s RBAC「誰能用某 SA 開 pod」是 `k8s:sa` 強度的地基。
- Day49 BFLA——「範圍開太寬」的老毛病搬到 attestation：只綁 namespace 就是把身分開放給整個範圍。
- Day18 供應鏈 / 依賴——「綁 digest 不綁 tag」同一條原則，從鎖依賴搬到鎖 container image selector。
- Day22 Race Condition / TOCTOU——「PID 反查屬性」底層的時間差與 PID 重用心智模型。
- Day11 / Day12 Path Traversal / Command Injection——`unix:path` 被同名檔 / bind mount 混淆，是「路徑不等於內容」的同源思路。
- Day16 Security Logging / Monitoring——「通過了哪些 selector」的執行期 audit 與設定期 CI 攔截。

---

明天預告：**Day 85 — SPIRE node attestation 各 attestor 的冒領邊界：join token 重用、AWS IID 重放、K8s PSAT 的信任假設（延伸篇）**
（這篇是**延伸篇**，不重講 Day80 attestation 兩層的基本概念、也不重講今天的 workload selector，聚焦 Day80 的**第一層**——node attestation——那個「先確認跑 Agent 的機器可信」的動作到底信了什麼、又能被怎麼騙。今天 Day84 拆的是「同一台可信 node 上、程序層」的冒領邊界；但那整層的前提是「這台 node 真的可信」，而 node attestation 自己也有一組信任假設會漏：**① 裸機 join token**——它就是一段預先發出去的祕密，token 外洩 / 重用 / 被塞進不該加入的機器，就能讓惡意節點冒充成可信 node（承 Day15 secrets、Day26 重放）；**② AWS instance identity document（IID）**——用雲端 metadata 簽出的節點身分，若 metadata service 被 SSRF（承 Day10）或 IID 被重放到別台，node 身分就被冒領，且雲端 attestor 常需綁定「一份 IID 只能註冊一次」否則同一份文件被拿去重複 attest；**③ K8s PSAT（projected service account token）**——用 pod 的 projected SA token 證明節點身分，信任假設是「這個 token 只有那個 node 上的 Agent 拿得到」，一旦 token 投影範圍 / audience 沒綁好、或 token 外流，冒領就成立。程式面會示範 node attestor 的選型與加固：join token 的一次性與短效發放、AWS IID attestor 綁定 `assume_role` / 帳號 / instance 條件收窄、K8s PSAT 的 audience 與 `allowed_node_selectors` 收緊，並用 Day16 角度談「哪台機器用什麼 attestor 加入了 trust domain」怎麼稽核。安全主軸一句話：**Day84 收窄了「node 上哪個程序是誰」，Day85 要收窄「哪台機器憑什麼算可信 node」——這一層被冒領，你在 workload 層收得再窄，都是蓋在流沙上。** 這是延伸篇，只聚焦 node attestor 的冒領邊界與收窄，不重述 attestation 兩層的基本流程。）
