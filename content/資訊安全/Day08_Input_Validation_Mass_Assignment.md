---
title: "Day 08 — Input Validation 與 Mass Assignment：別讓使用者「順便」把自己升成管理員"
date: 2026-04-30
tags: ["輸入驗證", "Mass Assignment", "API 安全"]
---

# Day 08 — Input Validation 與 Mass Assignment：別讓使用者「順便」把自己升成管理員

> 日期：2026-04-30
> 適合對象：後端工程師初學者
> 主題難度：★★★☆☆（觀念簡單，但框架的「方便」會讓你一不小心就翻車）

---

## 一、開場白：一段「看起來很乾淨」的 Spring Boot 程式

```java
// ⚠️ 有漏洞 — 千萬別這樣寫
@PostMapping("/api/users/profile")
public User updateProfile(@RequestBody User user) {
    return userRepository.save(user);
}

@Entity
public class User {
    @Id private Long id;
    private String username;
    private String email;
    private String passwordHash;
    private boolean isAdmin;          // ← 後台用的
    private BigDecimal accountBalance; // ← 錢包餘額
}
```

這段程式幾乎是 Spring Boot 教學書上的範本——簡潔、漂亮、6 行搞定使用者更新個資。

但只要前端打這個 request：

```http
POST /api/users/profile
Content-Type: application/json

{
  "id": 1,
  "username": "alice",
  "email": "alice@example.com",
  "isAdmin": true,
  "accountBalance": 99999999
}
```

**Alice 就成為管理員了，順便還幫自己加了快一億的帳戶餘額。**

這就是今天要講的兩個觀念：**Input Validation（輸入驗證）** 與 **Mass Assignment（批量賦值漏洞）**。

> 一句話：**永遠不要相信使用者送進來的任何欄位**——即使那個欄位你沒有打算開放給他改。

---

## 二、什麼是 Mass Assignment？

Mass Assignment 是一個從 Ruby on Rails 時代就被討論到爛的漏洞，但它在 Spring、Express、Gin、Laravel⋯⋯所有現代 Web 框架上**至今都還在發生**。

它的本質很簡單：

> **「把整個 request body 一口氣綁定到一個資料物件上」這個方便的功能，會把『前端不該動的欄位』也一起綁進去。**

### 著名案例：GitHub 2012 年事件

2012 年，一位俄羅斯開發者 Egor Homakov 利用 Rails 的 Mass Assignment 漏洞，把自己的 SSH public key 「順便」加到 GitHub 的 `rails/rails` 專案 admin 群組的某位成員上，然後 push 了一個 commit 到 master。GitHub 隨即修補。這之後 Rails 把 `attr_accessible` 改成預設啟用。

但同樣的問題——換到 Java 的 `@RequestBody`、Go 的 `c.BindJSON(&user)`、Node 的 `Object.assign(user, req.body)`——**到今天仍是 OWASP API Security Top 10 的常客**。（它在 2019 版獨立列為 **API6: Mass Assignment**；2023 版起被併入 **API3: Broken Object Property Level Authorization (BOPLA)**——名稱換了，但問題本質完全相同，我們 Day 25 會再深入 BOPLA。）

---

## 三、為什麼這個漏洞特別陰險？

它不像 SQL Injection 一打就壞、Log 會留下奇怪的字串。Mass Assignment：

1. **語法完全合法**——使用者只是多送了一個 JSON 欄位。
2. **Log 不會異常**——request 通過了驗證、回傳 200。
3. **程式碼看起來「乾淨」**——`save(user)` 是 ORM 的標準寫法。
4. **只有 Code Review 抓得到**——測試很難覆蓋「我多送了一個欄位」的情境。

---

## 四、修正方式（一）：用 DTO 隔離輸入與資料模型

最根本的解法是：**永遠不要把 Entity 當成 request body 直接接收**。建立一個只包含「使用者能改」欄位的 DTO（Data Transfer Object）。

### 4.1 Java（Spring Boot）— 正確寫法

```java
// ✅ 只開放 username 與 email 兩個欄位
public class UpdateProfileRequest {
    @NotBlank
    @Size(min = 3, max = 30)
    private String username;

    @NotBlank
    @Email
    private String email;

    // getters/setters
}

@PostMapping("/api/users/profile")
public UserDto updateProfile(
        @Valid @RequestBody UpdateProfileRequest req,
        @AuthenticationPrincipal UserPrincipal me) {

    User user = userRepository.findById(me.getId())
            .orElseThrow(() -> new NotFoundException("User"));

    // 只更新允許的欄位
    user.setUsername(req.getUsername());
    user.setEmail(req.getEmail());

    return UserDto.from(userRepository.save(user));
}
```

重點：

- 接收用 `UpdateProfileRequest`，**只列允許的欄位**——多送的 `isAdmin` 直接被框架忽略。
- 回傳用 `UserDto`，**不要把整個 Entity 序列化回去**——避免 `passwordHash` 這種敏感欄位外洩。
- 使用者 ID **不從 request body 拿**，從 `@AuthenticationPrincipal`（也就是 JWT / Session）拿。

> 記憶口訣：**「進來用 Request DTO，出去用 Response DTO，Entity 只活在 Service / Repository 裡。」**

### 4.2 Go（Gin）— 正確寫法

```go
// ✅ 只允許 Username 與 Email 被綁定
type UpdateProfileRequest struct {
    Username string `json:"username" binding:"required,min=3,max=30"`
    Email    string `json:"email"    binding:"required,email"`
}

func UpdateProfile(c *gin.Context) {
    var req UpdateProfileRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // 從 context 取出已驗證的使用者 ID（不要從 body 拿！）
    userID := c.GetInt64("userID")

    // 只更新允許的欄位
    if err := db.Model(&User{}).
        Where("id = ?", userID).
        Updates(map[string]any{
            "username": req.Username,
            "email":    req.Email,
        }).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "updated"})
}
```

注意 GORM 用 `map[string]any` 而不是 `Updates(req)`——後者也會把 struct 上所有有值的欄位帶進去 SQL，仍然有 Mass Assignment 風險。**用 map 把欄位明確列出來最安全。**

---

## 五、修正方式（二）：Allowlist，永遠不要 Denylist

新手常犯的錯誤是寫成這樣：

```java
// ❌ 黑名單 — 會漏
if (user.isAdmin()) user.setAdmin(false); // 把 isAdmin 重設掉
userRepository.save(user);
```

問題是：**你今天記得 `isAdmin`，明天加新欄位時呢？** 半年後 PM 加一個 `creditLimit`、Junior 加一個 `internalNotes`——你不會記得每個都過濾。

**永遠用白名單（Allowlist）**：明確寫出可以動的欄位，其它一律忽略。

| 策略 | 說法 | 結果 |
| :-- | :-- | :-- |
| Denylist（黑名單） | 「這幾個欄位不能改」 | 加新敏感欄位時很容易漏 |
| Allowlist（白名單） | 「這幾個欄位可以改」 | 加新欄位時，預設「不開放」 |

這個原則跟 Day 07 的 **Default Deny** 是一樣的精神。

---

## 六、Input Validation：不只擋型別，還要擋語意

DTO 解決了「使用者多送欄位」，但即使是允許的欄位，內容也可能不對。Input Validation 要分三層來看：

### 6.1 第一層：型別 / 格式驗證（Bean Validation / `binding` tag）

這是框架直接幫你做的：

```java
public class CreateOrderRequest {
    @NotNull
    @Min(1)
    @Max(100)
    private Integer quantity;       // 數量介於 1~100

    @NotBlank
    @Pattern(regexp = "^[A-Z0-9]{8}$")
    private String productCode;     // 8 碼大寫英數

    @NotNull
    @DecimalMin(value = "0.01")
    @Digits(integer = 10, fraction = 2)
    private BigDecimal unitPrice;   // 兩位小數的金額
}
```

```go
type CreateOrderRequest struct {
    Quantity    int     `json:"quantity"    binding:"required,min=1,max=100"`
    ProductCode string  `json:"productCode" binding:"required,len=8,alphanum,uppercase"`
    UnitPrice   float64 `json:"unitPrice"   binding:"required,gt=0"`
}
```

> ⚠️ 提醒：金額型別在 Java 用 `BigDecimal`，**不要用 `double` 或 `float`**——浮點數在金錢計算上會出現精度問題。Go 也建議用 `decimal` 套件（如 [shopspring/decimal](https://github.com/shopspring/decimal)）或以「最小貨幣單位的整數」儲存（例如美金存「分」、日圓直接存元）。

### 6.2 第二層：商業邏輯驗證

這層框架幫不了你，要自己寫：

- 數量 ≤ 100 是格式驗證；**「數量不能超過庫存」是商業邏輯驗證**。
- Email 格式對是格式驗證；**「這個 email 沒被註冊過」是商業邏輯驗證**。
- 折扣碼是 8 碼是格式驗證；**「折扣碼還在有效期內、還沒被用光」是商業邏輯驗證**。

```java
@Service
public class OrderService {
    public Order create(CreateOrderRequest req, Long userId) {
        Product product = productRepo.findByCode(req.getProductCode())
                .orElseThrow(() -> new BadRequestException("product not found"));

        if (product.getStock() < req.getQuantity()) {
            throw new BadRequestException("insufficient stock");
        }
        if (!product.getUnitPrice().equals(req.getUnitPrice())) {
            // 防止前端用舊價格下單
            throw new BadRequestException("price mismatch");
        }
        // ... 建立訂單
    }
}
```

最後一個檢查特別重要：**金額、折扣、庫存等敏感數值，永遠以伺服器端的資料為準，不要相信前端送的數字**。常見漏洞是「前端把 unitPrice 改成 0.01 送過來」，後端就照單全收。

### 6.3 第三層：跨欄位 / 跨資源檢查

例如：「結束時間必須晚於開始時間」、「這張優惠券是給 VIP 用的，但你不是 VIP」。

```java
@AssertTrue(message = "endAt must be after startAt")
public boolean isTimeRangeValid() {
    return endAt == null || startAt == null || endAt.isAfter(startAt);
}
```

---

## 七、別忘了：Validation 也是攻擊面

**Input Validation 寫錯，本身也是漏洞**。常見地雷：

1. **正則表達式 ReDoS（Regex Denial of Service）**
   `^(a+)+$` 這種正則對 `aaaaaaaaaaaaaaaaaaab` 會跑到天荒地老。寫複雜正則前先用工具（如 [safe-regex](https://github.com/davisjam/safe-regex)）檢查。

2. **錯誤訊息洩漏資訊**
   `"username 'alice' already exists"` 這種訊息直接告訴攻擊者哪個帳號存在，方便他做密碼噴灑（password spraying）。**統一錯誤訊息**：`"invalid username or email"`。

3. **驗證放在前端而已**
   前端的 `<input pattern="...">`、`required`、`type="number"` 全部都能繞過——攻擊者直接打 API。**Server-Side Validation 是必須的，前端驗證只是 UX。**

4. **長度沒設上限**
   忘記加 `@Size(max = ...)`，攻擊者可以送 100MB 的 JSON 把記憶體灌爆。所有字串欄位都要設合理上限，整個 request body 也要在 reverse proxy（如 Nginx 的 `client_max_body_size`）做總長度限制。

---

## 八、實戰檢查表（每寫一支寫入型 API 就跑一次）

1. ☐ 我是用 **DTO** 接收 request，不是直接收 Entity？
2. ☐ DTO 是**白名單**，只列出允許的欄位？
3. ☐ 我是從 **JWT / Session 拿使用者 ID**，不是從 request body 拿？
4. ☐ 所有欄位都有 **`@Valid` / `binding` tag**？包含 `min`、`max`、`pattern`、`size`？
5. ☐ 我是從 **DB 查商品價格**，不是相信前端送的金額？
6. ☐ 我有處理**跨欄位驗證**（時間順序、條件相依）？
7. ☐ 回傳是用 **Response DTO**，沒有把 Entity 直接序列化（避免 `passwordHash` 外洩）？
8. ☐ 錯誤訊息**不會洩漏帳號是否存在、檔案是否存在**？
9. ☐ 字串欄位都有 **`@Size(max = ...)`**？整體 body size 有限制？

---

## 九、進階：自動化偵測

光靠人肉 Code Review 永遠會漏。可以加這些工具：

- **OWASP Dependency-Check / Snyk**：抓使用了已知漏洞的套件版本。
- **SpotBugs + FindSecBugs（Java）**：靜態分析，會抓 `@RequestBody Entity`、未驗證輸入等樣式。
- **gosec（Go）**：Go 專用的安全 linter。
- **OWASP ZAP**：動態掃描，可以做「我多送一個 isAdmin 欄位」的 fuzz 測試。
- **API contract test**：用 OpenAPI Schema 驗證「實際接受的欄位」與「文件宣告的欄位」一致——多餘欄位應該被拒絕（很多框架預設只是「忽略」）。

Spring Boot 可以這樣設定 Jackson，讓多餘欄位直接報錯：

```java
@Bean
public Jackson2ObjectMapperBuilderCustomizer strictJacksonConfig() {
    return builder -> builder
        .featuresToEnable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
}
```

打開後，前端送了 `{"username":"alice","isAdmin":true}` 進 `UpdateProfileRequest`（沒有 isAdmin 欄位）→ 直接回 400。這比「靜默忽略」更安全，因為**你會知道有人在嘗試送多餘欄位**。

---

## 十、今日重點回顧

1. **Mass Assignment 是「框架太方便」造成的副作用**——`@RequestBody Entity` 看起來很乾淨，但會把 `isAdmin`、`balance` 全部開放給前端改。
2. **DTO 是隔離線**：進來用 Request DTO（白名單欄位），出去用 Response DTO（不洩漏敏感欄位），Entity 只活在 Service / Repository 內部。
3. **使用者 ID 永遠從 JWT / Session 拿，不要從 request body 拿。**
4. **Allowlist 不要 Denylist。** 加新欄位時的「預設值」應該是「不開放」。
5. **Input Validation 分三層**：型別格式（框架做）、商業邏輯（你做）、跨欄位（你做）。
6. **金錢、庫存、折扣等關鍵數值，伺服器端從 DB 查為準**，不相信前端傳的。
7. **錯誤訊息要統一、不洩漏**；所有字串都要設長度上限。
8. **Jackson 開 `FAIL_ON_UNKNOWN_PROPERTIES`** 把多餘欄位變成錯誤，比靜默忽略更安全。

---

## 十一、明天預告

Day 09 我們會進到 **Security Headers 與 CORS**——談 `Content-Security-Policy`、`Strict-Transport-Security`、`X-Frame-Options` 這些「設定一行就能擋掉一整類攻擊」的 HTTP header，以及大家最容易設錯的 `Access-Control-Allow-Origin: *`（搭配 `credentials: true` 是怎麼讓你的 Cookie 飛出去的）。

---

> 參考資料
> - OWASP API Security Top 10:2023 — API6: Unrestricted Access to Sensitive Business Flows / API3: Broken Object Property Level Authorization（Mass Assignment 已併入此項）
> - CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
> - OWASP Cheat Sheet — Mass Assignment
> - Jakarta Bean Validation 3.0 Specification
> - Egor Homakov, "How I hacked GitHub again", 2012
