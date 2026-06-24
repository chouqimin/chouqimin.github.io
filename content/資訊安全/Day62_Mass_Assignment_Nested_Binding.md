---
title: "Day 62：Mass Assignment 延伸篇 — 巢狀／集合綁定與框架特有規則"
date: 2026-06-24
tags: ["Mass Assignment", "Nested Binding", "Spring", "Go"]
---

# Day 62：Mass Assignment 延伸篇 — 巢狀／集合綁定與框架特有規則

接續 Day61 預告：今天承 **Day08 / Day55** 的 Mass Assignment，但這是一篇**延伸篇**，不是重新介紹。

先把界線講清楚：**Mass Assignment 的本質（框架太聽話、把整包輸入綁進物件、信任邊界搞錯）Day08 與 Day55 已經完整講過，基本防禦（DTO 白名單、`@JsonIgnore`、`setAllowedFields`、Go 用獨立 model）也列過。今天不重講這些。**

這篇只聚焦一件 Day55 沒展開、而且最容易在「已經做了 DTO」之後還中招的事——**巢狀與集合屬性的自動綁定**：

1. **Spring 的 nested path binding**：`user.role.name`、`items[0].price`、`profile.address.city` 這種深層路徑為什麼能被利用，以及 `@InitBinder` 的 `setAllowedFields` / `setDisallowedFields` 在巢狀路徑下的**萬用字元陷阱**。
2. **Go 的巢狀越權面**：`json.Unmarshal` 灌進巢狀 struct，以及 `map[string]any` 合併（partial update / PATCH）時的越權寫入。
3. **Code Review 重點**：為什麼「巢狀路徑也要 allowlist」，以及怎麼用 OpenAPI schema 對照測試把這類洞擋在 CI。

一句話先講結論：**你以為頂層欄位擋住了，但物件圖（object graph）是有深度的；只要綁定能往下鑽，allowlist 就必須跟著往下鑽，否則白名單只是「第一層的假象」。**

---

## 一、為什麼「做了 DTO」還會中？問題在綁定的深度

Day55 的標準解是：別綁 entity，綁一個只含安全欄位的 DTO。這在**扁平**結構下沒問題：

```java
public record UpdateUserRequest(String name, String email) {}
```

攻擊者送 `role`、`balance` 進來，DTO 沒這欄位，直接被丟掉。乾淨俐落。

但真實世界的請求很少是扁平的。一旦 DTO 裡有**巢狀物件**或**集合**，攻擊面就跟著物件圖往下長：

```java
public class UpdateOrderRequest {
    private String note;
    private List<OrderItem> items;   // 巢狀集合
    private ShippingInfo shipping;   // 巢狀物件
}

public class OrderItem {
    private Long productId;
    private int quantity;
    private BigDecimal price;   // ⚠️ 價格本該由後端算，不該由使用者送
}
```

DTO 看起來「只收該收的」，但 `OrderItem.price` 是個由使用者可控的巢狀欄位。攻擊者送：

```json
{ "note": "x", "items": [ { "productId": 42, "quantity": 1, "price": 0.01 } ] }
```

如果後端直接拿 `item.getPrice()` 去建單，這就是一筆一分錢的訂單。**頂層 DTO 白名單完全沒被繞過——洞在第二層。** Mass Assignment 在巢狀結構下的變形，就是「白名單只做了一層」。

---

## 二、Spring：nested path binding 與 `@InitBinder` 的萬用字元陷阱

### 2.1 表單綁定（`@ModelAttribute`）的深層路徑

Spring 的 `DataBinder` 支援「巢狀路徑屬性」綁定。當你用 `@ModelAttribute`（表單／query 參數綁定）時，下面這種 request 參數是會被吃進去的：

```text
name=Edison
role.name=ADMIN
account.permissions[0]=WRITE_ALL
shipping.address.city=Taipei
```

只要目標物件的 getter 串得起來（`getRole().setName(...)`、`getAccount().getPermissions()`），Spring 就會一路鑽下去設值。這正是 Day55 提過「`user.account.permissions[0]=ADMIN` 攻擊面比你想的大」的具體機制。

防禦工具是 `@InitBinder` + `setAllowedFields` / `setDisallowedFields`，但**多數人寫錯巢狀的萬用字元**：

```java
@Controller
public class OrderController {

    // ❌ 常見錯誤：只擋第一層，巢狀路徑漏掉
    @InitBinder
    void initBinder(WebDataBinder binder) {
        binder.setDisallowedFields("price");
        // 問題：disallow 的是「頂層 price」，
        // items[0].price 是「巢狀路徑」，這條規則根本沒比對到它
    }
}
```

`setDisallowedFields("price")` 比對的是欄位**路徑字串**，`items[0].price` 並不等於 `price`，所以這條黑名單形同虛設。要涵蓋巢狀，必須用**萬用字元**：

```java
@InitBinder
void initBinder(WebDataBinder binder) {
    // ✅ 用萬用字元涵蓋任意深度／任意索引的巢狀 price
    binder.setDisallowedFields("*price*", "*.role", "*.enabled", "*permissions*");
}
```

但黑名單（disallow）天生不可靠——**漏列一個就破功**，而且 entity 之後長出新欄位時沒人會回來補。Spring 文件本身也建議優先用 allowlist：

```java
@InitBinder
void initBinder(WebDataBinder binder) {
    // ✅✅ allowlist：只允許這些路徑，其餘一律不綁
    binder.setAllowedFields("note", "items*.productId", "items*.quantity", "shipping.address.*");
    // 注意 items*.productId 這種寫法才能涵蓋 items[0]/items[1]... 的索引
}
```

`setAllowedFields` 的萬用字元規則：`*` 可出現在開頭、結尾或兩端；`items*.quantity` 能匹配 `items[0].quantity`、`items[1].quantity`。**關鍵心智模型：allowlist 比對的是「完整巢狀路徑」，所以你的白名單也必須是「路徑形狀」的，而不是「欄位名」的。**

### 2.2 `@RequestBody`（JSON）走的是另一條路——別搞混

非常重要的一個區分：`@InitBinder` / `WebDataBinder` 那套**只作用在 `@ModelAttribute` 表單／參數綁定**，對 `@RequestBody`（Jackson 反序列化 JSON）**完全無效**。

JSON 進來時，巢狀防禦的責任在 **Jackson** 與**你的 DTO 形狀**：

```java
// ✅ JSON 巢狀防禦：用「貧血但精準」的 DTO，巢狀層也只放安全欄位
public record CreateOrderRequest(
        String note,
        List<ItemLine> items,
        ShippingDto shipping) {

    public record ItemLine(Long productId, int quantity) {}   // 沒有 price！
    public record ShippingDto(AddressDto address) {}          // 不含 carrier/cost
    public record AddressDto(String city, String zip) {}      // 不含 country override 等
}
```

巢狀 DTO 不放 `price`，攻擊者送了也會被 Jackson 丟棄。若你嫌每層都建 DTO 太累而想直接綁 entity，可在巢狀類別上用 `@JsonIgnoreProperties(ignoreUnknown = true)` 配合欄位級 `@JsonProperty(access = READ_ONLY)`：

```java
public class OrderItem {
    private Long productId;
    private int quantity;

    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private BigDecimal price;   // 序列化輸出可帶、反序列化輸入忽略
}
```

`READ_ONLY` 的語意正是「這個欄位能寫到 response，但不接受從 request 反序列化」——對「後端算、不給使用者送」的巢狀欄位（價格、狀態、擁有者）剛剛好。

> Day55 已示範 `@JsonIgnore` 與 DTO 的基本用法；這裡的延伸重點是：**巢狀層也要套同一套規則**，而且要清楚 `@InitBinder`（表單）和 Jackson（JSON）是兩條不會互相覆蓋的路。

### 2.3 還有一個巢狀提權面：`readerForUpdating` 的部分更新

PATCH / 部分更新很愛用 Jackson 的 `readerForUpdating`，把 JSON 疊到既有物件上。這在巢狀結構下會把使用者的輸入**深層合併**進你從 DB 撈出的 entity：

```java
// ⚠️ 把使用者 JSON 直接疊到 DB entity 上：巢狀欄位一起被覆蓋
User dbUser = repo.findById(id).orElseThrow();
objectMapper.readerForUpdating(dbUser).readValue(requestBody);
repo.save(dbUser);   // requestBody 裡的 role.name / account.balance 都生效了
```

這其實就是 Day43（Prototype Pollution / Object Injection）提過的「`readerForUpdating` 把輸入合併進現有物件」的越權版本——只是這次目標不是污染原型，而是**改寫巢狀的權限／金額欄位**。正解一樣：先反序列化成貧血 DTO，再由後端程式碼「手動、逐欄位」把允許的值搬到 entity，**絕不把整個 request 直接疊上 entity**。

---

## 三、Go：巢狀 struct 與 `map[string]any` 合併的越權面

Go 沒有 Spring 那種自動表單路徑綁定，所以「巢狀路徑萬用字元」這類陷阱比較少。但 Go 有**它自己的兩個巢狀地雷**。

### 3.1 巢狀 struct：`json.Unmarshal` 一樣會往下灌

Day55 講過「別把 request 直接 unmarshal 進 DB model」。在巢狀情況下，這個原則要延伸到**每一層**：

```go
// ❌ 反例：DB model 被當成 request 形狀，巢狀欄位一起被灌
type Order struct {
    Note  string      `json:"note"`
    Items []OrderItem `json:"items"`
}
type OrderItem struct {
    ProductID int64           `json:"productId"`
    Quantity  int             `json:"quantity"`
    Price     decimal.Decimal `json:"price"` // ⚠️ 使用者可控
}

func handler(w http.ResponseWriter, r *http.Request) {
    var o Order
    json.NewDecoder(r.Body).Decode(&o) // items[].price 被使用者決定
    // ... 直接拿 o.Items 建單
}
```

解法是巢狀層也用**獨立的 request 型別**，價格這類欄位根本不出現在輸入型別裡，後端自己查價：

```go
// ✅ 巢狀層也分離：輸入型別不含 price
type CreateOrderReq struct {
    Note  string `json:"note"`
    Items []struct {
        ProductID int64 `json:"productId"`
        Quantity  int   `json:"quantity"`
    } `json:"items"`
}

func handler(w http.ResponseWriter, r *http.Request) {
    dec := json.NewDecoder(r.Body)
    dec.DisallowUnknownFields() // 多送欄位直接 400，連嘗試都擋掉
    var req CreateOrderReq
    if err := dec.Decode(&req); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    items := make([]OrderItem, len(req.Items))
    for i, in := range req.Items {
        price := priceService.Lookup(in.ProductID) // 後端決定價格
        items[i] = OrderItem{ProductID: in.ProductID, Quantity: in.Quantity, Price: price}
    }
    // ...
}
```

`DisallowUnknownFields()` 是 Go 特有、又便宜又有效的一道防線：使用者多塞 `price`、`role` 之類的欄位時直接報錯，等於對**整棵巢狀樹**強制「只接受已宣告欄位」。Day55 提過它，這裡的延伸重點是它**遞迴作用到每一層巢狀 struct**，所以巢狀型別只要也保持「貧血」，整棵樹都安全。

### 3.2 PATCH 的真正地雷：`map[string]any` 深層合併

Go 做部分更新時，很多人會把 body 解成 `map[string]any` 再合併進現有資料。這是巢狀 Mass Assignment 在 Go 最常見的出洞點：

```go
// ❌ 反例：把使用者 map 深層合併進 DB 撈出來的 map
func patchUser(existing map[string]any, body []byte) map[string]any {
    var patch map[string]any
    json.Unmarshal(body, &patch)
    deepMerge(existing, patch) // 巢狀 key 一起被覆蓋：profile.role、account.balance...
    return existing
}
```

`deepMerge` 不認得「哪些 key 該由使用者改」，只要 key 路徑對得上就覆蓋——這跟 Day43 的 recursive merge 風險同源。正解是**用路徑 allowlist 過濾 patch**，而不是無腦合併：

```go
// ✅ 巢狀路徑白名單：只允許這些 dotted path 被 patch
var allowedPaths = map[string]bool{
    "note":            true,
    "shipping.city":   true,
    "shipping.zip":    true,
    // 注意：沒有 "shipping.cost"、沒有 "profile.role"、沒有 "account.balance"
}

func filterPatch(patch map[string]any, prefix string, out map[string]any) {
    for k, v := range patch {
        path := k
        if prefix != "" {
            path = prefix + "." + k
        }
        if child, ok := v.(map[string]any); ok {
            filterPatch(child, path, out) // 遞迴下鑽，逐層比對完整路徑
            continue
        }
        if allowedPaths[path] {
            out[path] = v
        }
        // 不在白名單的路徑：靜默丟棄
    }
}
```

**重點同 Spring：allowlist 的 key 是「巢狀完整路徑」（`shipping.city`），不是「欄位名」（`city`）。** 用欄位名做白名單，會讓 `profile.city` 與 `shipping.city` 被一視同仁，反而放行了不該放的層。

---

## 四、Code Review / 測試重點：把巢狀洞擋在 CI

延伸篇不重列基本防禦清單，只給「針對巢狀」的審查與測試重點：

**Review 時專看深度，不只看頂層：**

- DTO 裡只要出現**巢狀物件或集合**，就追問「第二層、第三層的每個欄位，使用者都該能寫嗎？」價格、狀態、`role`、`ownerId`、`enabled`、`createdBy` 出現在任何一層，預設視為紅旗。
- 看到 `setDisallowedFields("xxx")` 而 DTO 有巢狀，直接懷疑萬用字元寫錯（少了 `*`）。優先要求改成 `setAllowedFields` 的**路徑形狀**白名單。
- 看到 `readerForUpdating` / `deepMerge` / `map[string]any` 合併進既有物件，一律要求改成「DTO → 手動逐欄位搬移」或「路徑 allowlist 過濾」。
- Go 端確認 `DisallowUnknownFields()` 有開；Spring JSON 端確認巢狀類別沒有把 `price`/`role` 這類欄位開放反序列化（`READ_ONLY` 或 DTO 不含該欄位）。

**用 OpenAPI schema 做對照測試（把白名單變成可驗證的合約）：**

如果你有 OpenAPI 規格，request schema 應該對巢狀物件設 `additionalProperties: false`，並且**只列出允許輸入的欄位**。然後在 CI 跑兩種測試：

```text
1. 合約一致性：用 schema 驗證「實際 DTO 反序列化會接受的欄位」與「schema 宣告的欄位」一致。
   → 抓出「程式碼悄悄多綁了一個巢狀欄位、但 schema 沒寫」的漂移。
2. 越權回歸測試：對每個寫入 API，送一個「合法 body + 一個被禁巢狀欄位」
   （如 items[0].price、profile.role、shipping.cost），
   斷言該欄位「沒有被寫進結果」或請求直接被拒。
```

第 2 種測試最有價值：它把「巢狀欄位不可被使用者控制」變成一條**會在 CI 失敗的斷言**，未來有人在巢狀 DTO 偷加欄位、或關掉 `DisallowUnknownFields()`，測試就會紅。這比任何 code review 都可靠。

---

## 五、一句話總結

> Mass Assignment 的基本盤 Day08 / Day55 講完了；今天的延伸結論是——**白名單必須跟著物件圖往下鑽。** 頂層 DTO 擋住了不代表第二層安全：Spring 的 `setAllowedFields` 要用**路徑形狀**的萬用字元（`items*.quantity`、`shipping.address.*`），且別忘了 `@InitBinder` 只管表單、JSON 走 Jackson（巢狀 DTO / `READ_ONLY`）；Go 要靠 `DisallowUnknownFields()` 遞迴擋整棵樹，PATCH 的 `map[string]any` 深層合併則要用**巢狀完整路徑** allowlist 過濾，而不是無腦 `deepMerge`。最後把這條規則寫成 OpenAPI `additionalProperties: false` + CI 越權回歸測試，巢狀提權才不會在某次 refactor 後悄悄復活。

---

## 延伸閱讀

- Day08 Input Validation / Mass Assignment（入門：本質、DTO、allowlist）——本篇的基礎。
- Day55 Mass Assignment / Auto-Binding（重寫：Spring 反例、`@JsonIgnore`、`setAllowedFields`、Go 獨立 model）——本篇的直接前篇。
- Day43 Prototype Pollution / Object Injection（`readerForUpdating`、recursive merge 的同源風險）。
- Day25 BOPLA / GraphQL Excessive Data Exposure（寫入面屬性層級授權，與巢狀綁定互補）。

---

明天預告：**Day 63 — ESI Injection（Edge-Side Includes 注入）：當 CDN／反向代理替你「組裝」頁面時的新攻擊面（全新主題）**
（這是全新主題，不是 SSTI / SSRF 的延伸。會說明 ESI（`<esi:include>`）標籤如何被反射進回應、Varnish／部分 CDN 預設處理 ESI 帶來的風險，並用後端情境示範：未逸出的使用者輸入被下游 ESI 處理器當成標籤解析，導致 SSRF、cookie 竊取與快取污染；同時給 Java／Go 後端「對 ESI 處理器標記回應」與輸出逸出的防禦寫法與 code review 重點。）
