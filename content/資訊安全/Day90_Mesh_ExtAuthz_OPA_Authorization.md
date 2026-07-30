---
title: "Day 90：mesh 的 L7 細粒度授權——Envoy ext_authz 外接授權服務（OPA/Rego）、AuthorizationPolicy 的天花板、fail-open vs fail-closed 與授權服務的可用性（延伸篇）"
date: 2026-07-30
tags: ["Istio", "ext_authz", "OPA", "authorization"]
---

接續 Day89 預告：Day87 把 mesh 的授權收到 `AuthorizationPolicy` 的 `principals`／`methods`／`paths` 這一層——但那是**宣告式、無狀態**的屬性比對，做不到「使用者只能讀自己的訂單」這種**依資料而定（data-dependent）的細粒度授權**，那正是 Day07 IDOR／Day49 BFLA 的地盤。今天整篇處理那個天花板：**當授權決策需要看請求內容、看被存取物件的擁有者、看外部政策時，怎麼用 Envoy `ext_authz` 把決策外接給一個授權服務（常見是 OPA/Rego，或你自己寫的 gRPC／HTTP 服務）。**

**這篇是延伸篇，不重講 Day07 的存取控制入門、Day49 的 BFLA，也不重講 Day87 的 `AuthorizationPolicy` 接線與 Day81 的 aud 驗證。** 什麼是 IDOR、`principals` 怎麼寫、JWT 的 `aud` 怎麼驗——前面都講過，今天不重述。這篇只聚焦一件事：**授權決策從「宣告式比對」升級成「可帶業務規則的外部決策」時，機制怎麼接、政策寫在哪、以及決策服務本身變成新單點後的 fail 行為與可用性。**

延伸角度只有一條主軸：**Day87 讓 mesh 能問「你是誰」（authN）並做宣告式的 `principals`／`paths` 授權；Day90 讓 mesh 能問「這一次請求，你到底能不能做這件事」——把授權從無狀態的屬性比對，升級成一個能查擁有者、看請求內容、跑外部政策的決策。** 代價很明確：**你多了一個在關鍵路徑上的授權服務，它的可用性、fail 行為與延遲，會變成新的攻擊面與單點。** 這篇用三段把它收好：**① 天花板**——為什麼 `AuthorizationPolicy` 表達不了 per-object／business-rule 授權；**② 契約**——`ext_authz` 怎麼把決策外接給 OPA 或自寫服務（Go／Java 各一支最小實作）；**③ fail 行為**——`failure_mode_allow`／`failOpen` 一旦設成 open，就等於「授權服務一掛全部放行」＝Day07 default deny 的反面。

> ⚠️ 以下 Istio `meshConfig.extensionProviders`（`envoyExtAuthzGrpc`／`envoyExtAuthzHttp`）、`AuthorizationPolicy` `action: CUSTOM`、Envoy `ext_authz` filter（`failure_mode_allow`、`transport_api_version: V3`）與 OPA-Envoy plugin 的 Rego，都會隨你的 Istio／Envoy／OPA 版本與 mesh 形態（sidecar vs ambient）不同。實際請對照你那套的官方文件，別照抄字串與埠號。這裡示範的是**「宣告式授權的天花板在哪、外接決策怎麼接、fail 行為怎麼取捨」**的意圖，不是某一版的精確語法。

---

## 一、先定位：`AuthorizationPolicy` 的天花板——宣告式比對 vs 依資料而定的決策

Day87 把 mesh 的授權收到 `AuthorizationPolicy`，能寫「哪個 `principals`（SPIFFE ID）可以用哪些 `methods` 打哪些 `paths`」。這一層很有價值——但它有一條很硬的天花板：**它是無狀態的 L4/L7 屬性比對，只看得到「請求的靜態屬性」，看不到「這次請求牽涉的資料狀態」。**

```text
[Day87 宣告式 authZ]  請求 ─▶ Envoy ─(比對 principals / methods / paths)─▶ allow / deny
                             看得到：來源身分（SPIFFE ID）、HTTP method、path、port、header 存在與否
                             看不到：被存取「那一筆」物件的擁有者、request body 內容、DB 狀態、外部政策

[Day90 ext_authz]     請求 ─▶ Envoy ─(轉發前先問)─▶ 外部授權服務 ─(可查 owner / policy / DB)─▶ allow / deny
                                        │
                                        └─ 授權服務掛了怎麼辦？  fail-open（放行）  vs  fail-closed（拒）
```

具體講清楚天花板在哪。`AuthorizationPolicy` 能表達：

- `principals: ["cluster.local/ns/tenant-a/sa/frontend"]`——**誰**（哪個 workload 身分）可以來。
- `to.operation.methods: ["GET"]`、`paths: ["/orders/*"]`——可以用什麼**方法**打什麼**路徑樣式**。

它**表達不了**的（而這些正是後端最常見的授權需求）：

- **「使用者只能讀自己的訂單」**——`GET /orders/1001` 這條路徑的樣式對所有人都一樣，policy 比對不出「1001 這筆的 owner 是不是發請求的這個 user」。這就是 **Day07 IDOR**：路徑合法、方法合法，但**物件不屬於你**。
- **「只有 owner 或 admin 能取消訂單，且訂單狀態必須是 pending」**——這是 business rule，牽涉物件狀態與角色關係，`methods`／`paths` 的靜態比對表達不了。
- **「同一 API，依 request body 裡的欄位決定能不能過」**——例如轉帳金額超過額度要 step-up，body 的內容 `AuthorizationPolicy` 根本不看。

一句話定位：**`AuthorizationPolicy` 收的是「這類請求允不允許」（by request shape），`ext_authz` 補的是「這一次、這一筆、這個人到底能不能」（by data）。** 前者宣告式、無狀態、在 mesh config 裡；後者要跑程式、要查資料、是一個真正的決策服務。**兩者不是替代，是分層**：`AuthorizationPolicy` 先把「連進不進得來、粗粒度的 method/path」擋在前面（承 Day87），`ext_authz` 再對通過的請求做 per-object／business-rule 的細粒度決策。

> 心智矯正：很多團隊把授權「全部塞進 `AuthorizationPolicy`」，然後在應用碼裡再寫一次 owner check——結果是**兩邊各半、都不完整**，而且應用那半常常忘了寫（Day49 BFLA 的典型成因）。`ext_authz` 的價值是把「data-dependent 授權」變成一個**集中、必經、可測試**的決策點，而不是散在每個 handler 裡的 `if order.owner != user`。

---

## 二、契約：`ext_authz` 怎麼把決策外接出去

`ext_authz` 是 Envoy 的一個 HTTP filter：**Envoy 在把請求轉給後端應用之前，先暫停請求、呼叫一個外部授權服務，拿到 allow／deny 才決定要不要放行。** 兩種傳輸：

- **gRPC**：外部服務實作 Envoy 的 `envoy.service.auth.v3.Authorization/Check`，收 `CheckRequest`、回 `CheckResponse`（`OK` 放行／`PermissionDenied` 拒）。OPA-Envoy plugin 走的就是這條。
- **HTTP**：Envoy 把請求（method／path／選定的 header／可選 body）送到授權服務的一個 endpoint，**回 2xx＝放行、回 4xx（常見 403）＝拒**。自寫服務用這條最省事。

在 **Istio** 裡不用手刻 Envoy filter，用兩個物件接（這也是 Day87 同一個 `AuthorizationPolicy`，只是 `action` 從 `ALLOW`／`DENY` 換成 `CUSTOM`）：

```yaml
# ① meshConfig 宣告「有哪些外部授權服務可用」（extensionProviders）
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  meshConfig:
    extensionProviders:
      - name: "opa-ext-authz-grpc"          # ← 給 AuthorizationPolicy 用的名字
        envoyExtAuthzGrpc:
          service: "opa.tenant-a.svc.cluster.local"
          port: 9191
          timeout: 0.5s                       # 授權在關鍵路徑上，逾時要短（第五節）
          failOpen: false                     # 授權服務掛了：false=拒（fail-closed，預設就該這樣）
      - name: "my-ext-authz-http"
        envoyExtAuthzHttp:
          service: "authz.tenant-a.svc.cluster.local"
          port: 8000
          timeout: 0.5s
          failOpen: false
          includeRequestHeadersInCheck: ["authorization", "x-request-id"]  # 帶哪些 header 給授權服務
          headersToUpstreamOnAllow: ["x-authz-user"]                       # 放行時把哪些 header 帶去後端
```

```yaml
# ② AuthorizationPolicy 用 action: CUSTOM 把「符合這些 rule 的請求」交給上面的 provider
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: ext-authz-orders
  namespace: tenant-a
spec:
  selector:
    matchLabels: { app: orders }
  action: CUSTOM
  provider:
    name: "opa-ext-authz-grpc"     # 對應 meshConfig.extensionProviders[].name
  rules:
    - to:
        - operation:
            paths: ["/orders/*"]     # 只有打這些路徑才觸發外部授權；其餘走一般 ALLOW/DENY 評估
```

`CheckRequest` 大致帶這些（gRPC 版）：來源／目的的 `principal`（SPIFFE ID，承 Day87）、HTTP `method`／`path`／`host`／`headers`，以及（若開了 `include body`）部分 request body。授權服務就是拿這些屬性，**再加上它自己能查到的資料（owner、policy、DB）**，做出決策。

Istio 底層把 provider 的 `failOpen` 翻成 Envoy `ext_authz` filter 的 `failure_mode_allow`——若你是用原生 `EnvoyFilter` 手接，看到的是這個欄位（第五節整段在講它）：

```yaml
# Istio failOpen 底層＝Envoy ext_authz filter 的 failure_mode_allow
- name: envoy.filters.http.ext_authz
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
    transport_api_version: V3
    failure_mode_allow: false        # ← Istio failOpen: false 對應這個；預設該是 false
    grpc_service:
      envoy_grpc: { cluster_name: ext-authz }
      timeout: 0.5s
```

三個立刻要注意的點：

- **`CUSTOM` 只在「符合 `rules` 的請求」觸發**——沒被 `rules` 命中的請求**不會**送去 ext_authz，而是回到一般的 `ALLOW`／`DENY` 評估。所以 `ext_authz` **不是萬能兜底**：`/orders/*` 交給它做 owner check，但 `/admin/*` 若沒別的 policy 擋、又沒有預設拒絕，照樣全通。這點第六節的稽核會抓。
- **授權服務在關鍵路徑上**——每個請求都多一趟 `ext_authz` 呼叫。gRPC + 同機 sidecar（OPA-Envoy）幾乎無網路延遲；HTTP + 跨 pod 就要算進延遲預算（第五節）。
- **決策要有「可信的使用者身分」當輸入**——別讓授權服務直接信 client 可自帶的 header（承 Day38）。end-user 身分要嘛在授權服務裡驗 JWT（承 Day81），要嘛信 Istio `RequestAuthentication` 驗過後放進的 metadata，總之來源要不可偽造。

---

## 三、政策寫在 OPA/Rego：宣告式的外部政策

最常見的 `ext_authz` 後端是 **OPA（Open Policy Agent）+ Rego**，透過 OPA-Envoy plugin 當 gRPC 授權服務跑。好處是**政策即程式碼（policy-as-code）**：政策集中、可版本控管、可用 `opa test` 單元測試、跟應用解耦。OPA-Envoy 收到的 `input` 長這樣（HTTP 屬性在 `input.attributes.request.http`）：

```rego
package envoy.authz

import future.keywords.if
import future.keywords.in

default allow := false                      # 預設拒（承 Day07 default deny，這行最重要）

http_req := input.attributes.request.http
path_parts := split(trim(http_req.path, "/"), "/")

# 從已驗證的 end-user JWT 取 subject。
# 實務上 JWT 應由 Istio RequestAuthentication 先驗過（承 Day81 aud/簽章），
# 這裡示意從 bearer 取 sub；別在沒驗證的情況下信任它（承 Day38/75）。
bearer := trim_prefix(http_req.headers.authorization, "Bearer ")
claims := io.jwt.decode(bearer)[1]
user := claims.sub

# 規則：只有訂單擁有者本人能 GET 自己的訂單（這正是 Day87 principals 表達不了的 data-dependent 授權）
allow if {
    http_req.method == "GET"
    path_parts[0] == "orders"
    order_id := path_parts[1]
    data.orders[order_id].owner == user     # data.orders 來自 OPA bundle 或 http.send 查詢
}
```

`data.orders` 這一句是關鍵、也是 Rego 的天花板：**Rego 本身只在「input + 已載入的 data」上做決策。** 那「這筆訂單的 owner 是誰」從哪來？兩條路：

- **OPA bundle**：把相對靜態、可全量下載的資料（角色表、資源→擁有者對照、政策）打包成 bundle 定期同步進 OPA。適合資料量不大、變動不即時的場景。
- **`http.send` 即時查**：Rego 內用 `http.send` 去查一個 ownership／資料服務。彈性高，但**每次授權都多一趟外呼**＝延遲與可用性風險（又是第五節那件事），且要小心把它變成另一個 SSRF 面（承 Day10）。

當「owner 判斷牽涉即時 DB、複雜 join、或本來就有的領域邏輯」時，硬塞進 Rego 會很痛——這時**自寫一個 `ext_authz` 服務**、直接用你熟悉的 Go／Java 查你本來的資料層，往往更直接。這就是第四節。

一句話：**Rego 適合「宣告式、可測試、資料可預載」的政策；當決策深度依賴即時領域資料與既有邏輯時，自寫服務更順手。** 兩者用的是同一個 `ext_authz` 契約，隨時可換。

---

## 四、自寫 `ext_authz` 服務：Go 與 Java（最小可用）

自寫服務用 **HTTP 契約**（`envoyExtAuthzHttp`）最省事：Envoy 把原始 `method`／`path`／選定 header 送來，**回 200＝放行、回 403＝拒**。下面兩支都做同一件 Day87 做不到的事——**per-object owner check**。

### Go：HTTP ext_authz（做 data-dependent 授權）

```go
package main

import (
	"log"
	"net/http"
	"strings"
	"time"
)

// ownerOf：實務上查 DB／ownership 服務；這裡示意。查不到回 ("", false)。
func ownerOf(orderID string) (string, bool) {
	owners := map[string]string{"1001": "alice", "1002": "bob"}
	o, ok := owners[orderID]
	return o, ok
}

// trustedUser：從「可信來源」取 end-user 身分。
// 實務上：在這裡驗 end-user JWT 的簽章/aud（承 Day81），或讀 RequestAuthentication 驗過的 claims。
// 千萬別直接信任 client 可自帶的 header（承 Day38）——那等於沒有 authZ。
func trustedUser(r *http.Request) string {
	// …驗 JWT / 讀 filter metadata…（略）
	return r.Header.Get("x-verified-user")
}

func deny(w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) } // 403＝拒

func check(w http.ResponseWriter, r *http.Request) {
	// 1) 可信的使用者身分；沒有＝拒（fail-closed 心智，承 Day07）
	user := trustedUser(r)
	if user == "" {
		deny(w)
		return
	}
	// 2) 物件：envoyExtAuthzHttp 會把「原始 method/path」帶到授權服務
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if r.Method != http.MethodGet || len(parts) < 2 || parts[0] != "orders" {
		deny(w) // 不在本服務授權範圍的請求，一律拒（別預設放行）
		return
	}
	// 3) data-dependent 決策：只有擁有者本人能讀（Day87 的 principals/paths 表達不了這一步）
	if owner, ok := ownerOf(parts[1]); !ok || owner != user {
		deny(w)
		return
	}
	w.WriteHeader(http.StatusOK) // 200＝放行
}

func main() {
	srv := &http.Server{
		Addr:         "127.0.0.1:8000", // 只綁 loopback，由 sidecar 攔截（承 Day88）
		Handler:      http.HandlerFunc(check),
		ReadTimeout:  2 * time.Second,   // 授權在關鍵路徑上，逾時要短（第五節）
		WriteTimeout: 2 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
```

> **gRPC 版（OPA-Envoy 或效能敏感時）**：實作 `github.com/envoyproxy/go-control-plane/envoy/service/auth/v3` 的 `AuthorizationServer`，方法 `Check(ctx, *auth.CheckRequest) (*auth.CheckResponse, error)`，用 `CheckResponse{Status: &status.Status{Code: int32(codes.OK)}}` 放行、`codes.PermissionDenied` 拒。契約與上面完全一致，只是傳輸換成 gRPC、屬性從 `CheckRequest.Attributes.Request.Http` 取。

### Java：Spring HTTP ext_authz

```java
// Spring Boot 3（Java 17/21）。對授權服務而言，路徑就是「原始請求路徑」。
@RestController
public class ExtAuthzController {

    // envoyExtAuthzHttp：Envoy 把原始 method/path/選定 header 送來；200=放行、403=拒
    @GetMapping("/orders/{id}")
    public ResponseEntity<Void> check(@PathVariable String id,
                                      @RequestHeader(value = "authorization", required = false) String auth) {
        String user = trustedUser(auth);   // 驗 JWT/aud（承 Day81），別信 client 可自帶 header（承 Day38）
        if (user == null) {
            return ResponseEntity.status(403).build();       // 沒有可信身分＝拒
        }
        String owner = ownerOf(id);          // 查 DB/ownership 服務；查不到回 null
        if (owner == null || !owner.equals(user)) {
            return ResponseEntity.status(403).build();       // data-dependent：非擁有者＝拒
        }
        return ResponseEntity.ok().build();                  // 200＝放行
    }

    // 其餘不在授權範圍的請求：一律 403（別預設放行）
    @RequestMapping("/**")
    public ResponseEntity<Void> denyRest() { return ResponseEntity.status(403).build(); }
}
```

> **版本註記**：Spring Boot 3 需要 Java 17+；**Java 1.8** 請用 Spring Boot 2（`@RestController` 寫法相同）或純 Servlet。gRPC 版兩個世代都可用 grpc-java，繼承產生的 `AuthorizationGrpc.AuthorizationImplBase` 覆寫 `check(...)`。無論哪版，授權服務都要：**設短逾時、把「未涵蓋的請求」預設拒、決策所需的使用者身分來源不可偽造**。

**這兩支的重點不是程式多複雜，而是它們做到了 `AuthorizationPolicy` 結構上做不到的事**：拿「請求要碰的那一筆物件」去比「發請求的那個人」。這一步一旦集中在必經的 `ext_authz`，Day49 BFLA／Day07 IDOR 那種「某個 handler 忘了寫 owner check」的漏洞面，就從「每個 handler 各自為政」收斂成「一個可測試的決策點」。

---

## 五、fail-open vs fail-closed：授權服務掛了，Envoy 該放行還是拒？

這是 `ext_authz` 最重要、也最容易設錯的一題。你把授權決策外接出去，就多了一個問題：**當授權服務逾時／連不上／回錯時，Envoy 該怎麼辦？**

- **fail-open（`failOpen: true`／`failure_mode_allow: true`）**：授權服務不可用時**放行**。後果是——**授權服務一掛，等於全部請求繞過授權**。這是 Day07 default deny 的正面反例：**你以為有授權，實際上在授權服務故障的那段時間，門是開的。** 而且攻擊者可以主動去打垮／拖慢授權服務來「開門」，把可用性問題變成授權繞過。
- **fail-closed（`failOpen: false`／`failure_mode_allow: false`）**：授權服務不可用時**拒絕**。安全，但代價是——**授權服務變成這條路徑的可用性單點**：它掛了，被它守的請求全部 503/403。

**預設就該 fail-closed。** 授權是安全控制，不是效能優化；「拿不到決策」時保守地拒，才符合 default deny。fail-open 只在極少數、有明確理由、且範圍極窄（例如某條非敏感的唯讀路徑）時才考慮，而且要有告警（第六節）。

但 fail-closed 讓授權服務成為單點怎麼辦？**答案是用架構把可用性補回來，而不是靠 fail-open 把安全丟掉**：

- **同機 sidecar 模式（OPA-Envoy 最典型）**：把 OPA／授權服務當 **per-pod sidecar** 跑，Envoy 走 loopback gRPC 呼叫它。沒有跨 pod 網路、沒有共享單點——授權服務的生死跟著它守的那個 pod，一起活一起死，不會「一個中央授權服務掛了拖垮全 mesh」。這是讓 fail-closed 可行的關鍵設計。
- **決策快取**：對「相同輸入短時間內重複」的決策做快取（Envoy 端或授權服務端），降低每請求外呼的比例與尾延遲。快取要小心 TTL——授權狀態變更（撤權、改 owner）後,舊決策還快取多久是安全 vs 效能的取捨。
- **延遲預算（timeout）**：`ext_authz` 在關鍵路徑上，`timeout` 設太長→授權服務一慢就拖垮整條請求的 P99（承 Day72 slow 的思路，慢也是一種 DoS）；設太短→高負載下正常請求被誤判逾時，fail-closed 就變成大量誤拒。要**壓測定出 timeout**，不是拍腦袋。
- **HA**：中央模式的授權服務至少多副本 + 健康檢查，別讓單一 replica 決定全服務生死。

一個常被搞混的點要講清楚：**`failure_mode_allow` 只影響「授權服務不可用（逾時／連不上）」這種基礎設施故障，不影響「授權服務明確回 deny」。** 明確的 deny 永遠是 deny。fail-open 開的是「故障時的預設」，不是「把 deny 當 allow」。

一句話：**fail 行為是安全決策，不是效能微調——預設 fail-closed，再用同機 sidecar／快取／延遲預算／HA 把可用性補回來；用 fail-open 換可用性，等於在故障時把授權整個關掉。**

---

## 六、Day16 稽核：掃 `failOpen`／`CUSTOM` 沒兜底，執行期抓 deny 尖峰與 fail-open 啟動

`ext_authz` 幾個最危險的狀態都能靜態掃出來，寫成 CI／admission 就是 Day16「把偵測升級成預防」在授權外接的落點（承 Day87／88／89 第六節同一套心法：先在 chat／CI 跑一次看資料長相，再寫解析）。

先看資料長相：

```bash
kubectl get authorizationpolicy -A -o json
kubectl -n istio-system get configmap istio -o jsonpath='{.data.mesh}'   # extensionProviders 在這裡（YAML）
```

**Go 版**：掃 `AuthorizationPolicy`，抓兩件事——① `action: CUSTOM` 卻沒設 `provider.name`（接錯，等於沒授權）；② 有 `CUSTOM` 政策的 namespace 卻**沒有預設拒絕兜底**（`CUSTOM` 只守被 `rules` 命中的路徑，其餘會回到一般評估，沒兜底就可能全通——承 Day87 `nsHasDefaultDeny` 的同構邏輯）。

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
		Metadata struct{ Name, Namespace string } `json:"metadata"`
		Spec     struct {
			Action   string `json:"action"`             // ALLOW（預設）/ DENY / CUSTOM / AUDIT
			Provider struct {
				Name string `json:"name"`
			} `json:"provider"`
			Rules []json.RawMessage `json:"rules"`       // 無 rules 的 ALLOW＝預設拒絕（deny-all）兜底
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
	var aps apList
	kubectlJSON(&aps, "get", "authorizationpolicy", "-A", "-o", "json")

	fail := false
	nsHasDefaultDeny := map[string]bool{} // ns -> 是否有「無 rules 的 ALLOW」兜底
	nsUsesCustom := map[string]bool{}     // ns -> 是否用了 CUSTOM

	for _, ap := range aps.Items {
		ns := ap.Metadata.Namespace
		action := ap.Spec.Action
		if action == "" {
			action = "ALLOW" // Istio 預設
		}
		// 無 rules 的 ALLOW policy＝什麼都不允許＝該 ns 的預設拒絕兜底（承 Day87）
		if action == "ALLOW" && len(ap.Spec.Rules) == 0 {
			nsHasDefaultDeny[ns] = true
		}
		if action == "CUSTOM" {
			nsUsesCustom[ns] = true
			if ap.Spec.Provider.Name == "" { // 接錯：CUSTOM 沒指 provider
				fmt.Printf("FAIL %s/%s：action=CUSTOM 但未設 provider.name（外部授權沒接上）\n",
					ns, ap.Metadata.Name)
				fail = true
			}
		}
	}

	// 用了 CUSTOM 做 per-object 授權，卻沒有預設拒絕兜底＝未命中 rules 的路徑可能全通
	for ns := range nsUsesCustom {
		if !nsHasDefaultDeny[ns] {
			fmt.Printf("FAIL %s：使用 CUSTOM ext_authz 但缺預設拒絕兜底（未命中的路徑恐全通）\n", ns)
			fail = true
		}
	}

	if fail {
		os.Exit(1)
	}
	fmt.Println("OK：CUSTOM 皆有 provider，且使用 CUSTOM 的 namespace 都有預設拒絕兜底")
}
```

**Java 版**（Jackson，對稱邏輯）：

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Map;

public class ExtAuthzAudit {
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
        Map<String, Boolean> nsHasDefaultDeny = new HashMap<>();
        Map<String, Boolean> nsUsesCustom = new HashMap<>();

        for (JsonNode ap : kubectl("get", "authorizationpolicy", "-A", "-o", "json").path("items")) {
            String ns = ap.path("metadata").path("namespace").asText();
            String name = ap.path("metadata").path("name").asText();
            JsonNode spec = ap.path("spec");
            String action = spec.path("action").asText("ALLOW");     // Istio 預設 ALLOW
            boolean noRules = spec.path("rules").isMissingNode() || spec.path("rules").size() == 0;

            if ("ALLOW".equals(action) && noRules) {
                nsHasDefaultDeny.put(ns, true);                       // 無 rules 的 ALLOW＝預設拒絕兜底
            }
            if ("CUSTOM".equals(action)) {
                nsUsesCustom.put(ns, true);
                if (spec.path("provider").path("name").asText("").isEmpty()) {
                    System.out.printf("FAIL %s/%s：action=CUSTOM 但未設 provider.name%n", ns, name);
                    fail = true;
                }
            }
        }

        for (String ns : nsUsesCustom.keySet()) {
            if (!nsHasDefaultDeny.getOrDefault(ns, false)) {
                System.out.printf("FAIL %s：使用 CUSTOM ext_authz 但缺預設拒絕兜底%n", ns);
                fail = true;
            }
        }

        if (fail) System.exit(1);
        System.out.println("OK：CUSTOM 皆有 provider，且使用 CUSTOM 的 namespace 都有預設拒絕兜底");
    }
}
```

三個 CI 要補、但上面（純 `AuthorizationPolicy` JSON）沒涵蓋的角度：

- **`extensionProviders` 的 `failOpen` 是不是 `true`**：這在 `istio-system` 的 istio configmap `meshConfig` 裡（YAML 字串，不是 `AuthorizationPolicy`）。掃 `kubectl -n istio-system get configmap istio -o jsonpath='{.data.mesh}'`，判斷各 provider 的 `failOpen`／原生 `EnvoyFilter` 的 `failure_mode_allow` 是否為 `true`；是就判紅（或至少判黃、要簽核）。**這是 fail 行為的總開關，比任何 policy 都優先。**
- **授權服務「有沒有真的做 object-level 檢查」CI 看不到**——policy 接上了、provider 也設了，但授權服務裡到底有沒有那句 `owner == user`，靜態掃不出來。這只能靠第七節的測試守。
- **延遲預算與 timeout 是否壓測過**——執行期才觀察得到。

**執行期承 Day16**：把 `ext_authz` 的 allow／deny 決策與 fail-open 啟動事件打進 SIEM，對三件事告警——① **deny 尖峰**（可能是攻擊在探 IDOR，或政策改壞誤拒）；② **fail-open 實際被觸發**（代表授權服務正在故障、門正開著，這是 P1 級事件而不是雜訊）；③ **授權服務延遲逼近 timeout**（快用完延遲預算，離大量誤拒或拖垮 P99 不遠）。**因為「授權服務故障時門是不是開著」這件事，靜態掃永遠掃不到，只能靠執行期抓。**

---

## 七、常見誤區

| 誤區 | 為什麼錯 |
|---|---|
| 「授權全部用 `AuthorizationPolicy` 就夠了」 | 它是無狀態屬性比對，表達不了 per-object owner／business-rule／看 body 的授權（第一節） |
| 「`ext_authz` 是拿來取代 `AuthorizationPolicy` 的」 | 兩者分層：`AuthorizationPolicy` 收粗粒度 method/path，`ext_authz` 補 data-dependent 決策（第一、二節） |
| 「設了 `action: CUSTOM`，整個服務就被授權守住了」 | `CUSTOM` 只守被 `rules` 命中的路徑，未命中的回到一般評估；沒兜底就恐全通（第二、六節） |
| 「授權服務直接信 `x-user` header 就好」 | client 可自帶 header（承 Day38）；身分要驗 JWT（Day81）或信 RequestAuthentication 驗過的來源（第二、四節） |
| 「`failOpen: true` 比較不會影響可用性」 | 那等於「授權服務一掛全部放行」＝Day07 default deny 的反面，還能被主動打垮來開門（第五節） |
| 「fail-closed 會讓授權服務變單點，所以用 fail-open」 | 單點要用同機 sidecar／快取／HA／延遲預算補，不是靠 fail-open 把安全丟掉（第五節） |
| 「`failure_mode_allow` 會把 deny 也放行」 | 它只管「故障時的預設」，明確 deny 永遠是 deny（第五節） |
| 「Rego 能做所有授權」 | Rego 只在 input+已載入 data 上決策；即時 owner 要靠 bundle／`http.send`，複雜領域邏輯自寫服務更順（第三、四節） |
| 「`ext_authz` 延遲不用管」 | 它在關鍵路徑上，timeout 太長拖垮 P99、太短高負載誤拒；要壓測定預算（第五節，承 Day72） |
| 「授權外接了，應用就不用再管授權」 | 契約與兜底要對；未涵蓋路徑、內部呼叫繞過 mesh 的情況仍要縱深（第二、六節） |

---

## 八、Code Review / 維運 checklist

**天花板與分層（第一、二節）**

- [ ] 需要 per-object／business-rule／看 body 的授權，走 `ext_authz`；不是硬塞進 `AuthorizationPolicy` 的 `paths` 比對。
- [ ] `AuthorizationPolicy`（粗粒度）與 `ext_authz`（細粒度）分層清楚，不是二選一、也不是兩邊各半都不完整。

**契約與兜底（第二、六節，承 Day87）**

- [ ] `action: CUSTOM` 都有對應的 `provider.name`，且 `provider` 在 `meshConfig.extensionProviders` 有定義。
- [ ] 用 `CUSTOM` 做授權的 namespace 都有**預設拒絕兜底**；未被 `rules` 命中的路徑不會因此全通。
- [ ] 送進授權服務的使用者身分來源**不可偽造**（驗 JWT／信 RequestAuthentication 驗過的來源，非 client 可自帶 header，承 Day38／81）。

**fail 行為與可用性（第五節，承 Day07）**

- [ ] `failOpen`／`failure_mode_allow` 預設為 `false`（fail-closed）；任何 `true` 都有明確理由、極窄範圍、且有告警。
- [ ] 授權服務的可用性用**同機 sidecar／決策快取／HA／壓測定出的 timeout** 撐住，而不是靠 fail-open。
- [ ] `ext_authz` 的 `timeout` 是壓測定出來的延遲預算，不是拍腦袋（承 Day72）。

**稽核（第六節，承 Day16）**

- [ ] CI／admission 掃「`CUSTOM` 沒 provider／缺預設拒絕兜底／`failOpen: true`／`failure_mode_allow: true`」並判紅。
- [ ] 執行期把 allow/deny 決策、**fail-open 啟動**、授權延遲進 SIEM，對 deny 尖峰與 fail-open 觸發告警。

---

## 九、測試 / 演練建議

- **object-level 授權測試（最重要）**：用 A 的合法身分去讀 **B 的訂單**（`GET /orders/{B 的訂單}`），斷言**被拒**——這條路徑 Day87 的 `principals`／`paths` 會放行（身分合法、路徑合法），必須是 `ext_authz` 擋下。過得去＝你的 owner check 沒生效或沒接上。
- **未涵蓋路徑兜底測試（第二節）**：打一條 `CUSTOM` `rules` **沒命中**的路徑（例如 `/admin/*`），斷言**被預設拒絕擋下**，而不是因為「沒送去 ext_authz」就全通。
- **fail-closed 演練（第五節，最關鍵的可用性/安全測試）**：把授權服務**停掉**或注入逾時，斷言請求**被拒（fail-closed）**而非放行。若某條路徑刻意 fail-open，斷言**告警有觸發**。
- **`failOpen` 迴歸**：把某 provider 改成 `failOpen: true`（或 `EnvoyFilter` `failure_mode_allow: true`），斷言第六節的 CI **判紅**。測不過代表稽核是擺設。
- **延遲預算測試（第五節，承 Day72）**：對授權服務注入延遲逼近 `timeout`，量測對整體 P99 的影響、以及是否開始出現逾時誤拒——用來校準 timeout 與快取。
- **Rego 單元測試（第三節）**：用 `opa test` 對政策寫測試（owner 相符放行、不符拒、預設拒），把政策當程式碼測。
- **身分不可偽造測試（第二、四節，承 Day38）**：客戶端自帶偽造的 `x-user`/身分 header 直送，斷言授權服務**不因此認定身分**（只認驗過的 JWT／可信來源）。

---

## 十、一句話總結

> Day87 讓 mesh 能問「你是誰」並做 `principals`／`methods`／`paths` 的宣告式授權；Day90 讓 mesh 能問「這一次、這一筆、這個人到底能不能做」——把授權從無狀態的屬性比對，升級成一個能查擁有者、看請求內容、跑外部政策的決策。**天花板**：`AuthorizationPolicy` 是宣告式、無狀態的 L4/L7 比對，表達不了「使用者只能讀自己的訂單」這種 data-dependent 授權（Day07 IDOR／Day49 BFLA 的地盤），`ext_authz` 補的正是這段——它讓 Envoy 在轉發前先問一個外部授權服務（OPA/Rego 或自寫 gRPC/HTTP 服務）拿 allow/deny。**契約**：Istio 用 `meshConfig.extensionProviders`（`envoyExtAuthzGrpc`/`envoyExtAuthzHttp`）+ `AuthorizationPolicy` `action: CUSTOM` 接，但 `CUSTOM` 只守被 `rules` 命中的路徑、不是萬能兜底，未命中的仍要靠預設拒絕；政策可寫 Rego（宣告式、可 `opa test`、資料靠 bundle/`http.send`），也可自寫 Go/Java 服務直接查既有資料層做 owner check（兩支範例都做到 Day87 做不到的 per-object 授權），身分來源必須不可偽造（驗 JWT／承 Day38/81）。**fail 行為**：`failOpen`/`failure_mode_allow` 一旦設 `true`＝授權服務一掛全部放行＝Day07 default deny 的反面，還能被主動打垮來開門；預設就該 fail-closed，再用同機 sidecar／決策快取／HA／壓測定出的延遲預算把可用性補回來——而不是用 fail-open 換可用性；且 `failure_mode_allow` 只管故障時的預設，明確 deny 永遠是 deny。稽核（承 Day16）把「`CUSTOM` 沒 provider／缺兜底／`failOpen: true`」寫成 CI，執行期對 deny 尖峰與 fail-open 啟動告警。一句話：**Day90 把授權從「這類請求准不准」升級成「這一次請求你到底能不能」，但你外接出去的那個決策服務，它的可用性與 fail 行為就是新的攻擊面與單點——預設 fail-closed，用架構撐住可用性，別用 fail-open 把授權偷偷關掉。**

---

## 延伸閱讀

- Day87 SPIRE × service mesh——本篇上游：Day87 把授權收到 `AuthorizationPolicy` 的宣告式比對，今天處理它的天花板、把 data-dependent 決策外接給 `ext_authz`（同一個 `AuthorizationPolicy` 物件，`action` 換成 `CUSTOM`）。
- Day07 Broken Access Control / IDOR——`ext_authz` 補的 per-object owner check，正是防 IDOR 的那一步；fail-closed 就是 default deny 在授權外接的落點。
- Day49 BFLA——「某個 handler 忘了寫授權」的問題，靠把 data-dependent 決策集中到必經的 `ext_authz` 收斂成一個可測試的決策點。
- Day81 JWT-SVID / aud——授權要有可信的使用者身分當輸入；end-user JWT 的簽章/aud 驗證（別在授權服務裡跳過）。
- Day38 X-Forwarded-For Spoofing——授權服務別直接信 client 可自帶的身分 header，同源的偽造轉發問題。
- Day72 Slow HTTP DoS——`ext_authz` 在關鍵路徑上，逾時與延遲預算沒設好，慢的授權服務就是一種 DoS；攻擊者也可打垮它來觸發 fail-open。
- Day16 Security Logging / Monitoring——把授權決策、fail-open 啟動、延遲進 SIEM，對 deny 尖峰與 fail-open 觸發告警。

---

明天預告：**Day 91 — Kubernetes admission webhook 的信任邊界與可用性：mutating/validating webhook（sidecar injector、OPA Gatekeeper／Kyverno policy）自身加固、`failurePolicy` fail-open vs fail-closed、以及 webhook 成為叢集單點（延伸篇）**
（這是**延伸篇**，不重講 Day07 的存取控制入門、Day87 的 sidecar injector 是什麼、也不重講今天 `ext_authz` 的 data-plane 授權。今天的 fail-open vs fail-closed 是**資料面**（Envoy 對每個請求問授權服務）的取捨；明天把同一個「故障時該開還是該關」的問題，翻到 **Kubernetes 控制面的 admission webhook**——`ValidatingWebhookConfiguration`／`MutatingWebhookConfiguration` 的 `failurePolicy: Fail`（fail-closed，webhook 掛了就擋下所有 API 寫入）vs `Ignore`（fail-open，webhook 掛了就放行未經檢查的資源）。延伸角度三條：**① webhook 是高權限、爆炸半徑極大的元件**——mutating webhook 能改寫全叢集任何被攔到的資源（承 Day87 sidecar injector 那段），policy webhook（OPA Gatekeeper／Kyverno）決定「什麼資源能進叢集」，它們自身的 RBAC、`namespaceSelector`（別攔到自己與 kube-system）、憑證與端點就是控制面的信任邊界；**② `failurePolicy` 的 fail-open vs fail-closed**——跟今天 `ext_authz` 同一題在 admission 的翻版：`Ignore` 讓「webhook 一掛，未檢查的 Pod/資源就進得來」＝policy 形同虛設，`Fail` 讓 webhook 變成「所有部署都得先過它」的可用性單點；**③ 怎麼兩者兼顧**——`namespaceSelector`/`objectSelector` 縮小攔截範圍、webhook 服務 HA、`timeoutSeconds` 與 `reinvocationPolicy` 的設定。程式面會示範 `ValidatingWebhookConfiguration` YAML、Go/Java 的 admission review handler，以及一支掃「`failurePolicy: Ignore`／webhook 沒排除自身 namespace／`timeoutSeconds` 過長」的稽核。安全主軸一句話：**Day90 收資料面「每個請求該不該過」的 fail 行為，Day91 收控制面「每個資源該不該進叢集」的 fail 行為——webhook 一旦 fail-open，你所有的 admission policy 在它故障時全部失效。** 這是延伸篇，只聚焦 admission webhook 的信任邊界與 `failurePolicy`，不重述存取控制與 injector 基礎。）
