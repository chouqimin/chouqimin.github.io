---
title: "Day 55：Mass Assignment / Auto-Binding — 當框架「貼心」地把整包 JSON 灌進你的物件"
date: 2026-06-20
tags: ["Mass Assignment", "Auto-Binding", "Java", "Go"]
---

# Day 55：Mass Assignment / Auto-Binding — 當框架「貼心」地把整包 JSON 灌進你的物件

接續 Day54 預告：昨天 XXE 是「解析格式」觸發的洞，攻擊者靠你照規格解析 XML 來讀檔、打內網；今天看一個更安靜、更常見的洞——**Mass Assignment**（又稱 Auto-Binding / Over-Posting）。這次不是你解析了什麼壞東西，而是你的框架**太聽話**：使用者在 request body 多塞一個 `isAdmin=true` 或 `role=ADMIN`，框架就忠實地把它綁到你的 entity 上，提權在無聲無息中完成。

---

## 一、漏洞的本質：方便的 auto-binding 是雙面刃

現代框架為了讓你少寫程式，提供「把整包 JSON / 表單欄位自動對應到物件欄位」的功能。Spring 的 `@RequestBody`、`@ModelAttribute`，Rails 的 `update_attributes`，Go 的 `json.Unmarshal` 直接灌進 struct——它們都在做同一件事：**收到什麼欄位，就綁什麼欄位**。

問題在於：**你想讓使用者改的欄位，跟框架願意幫你綁的欄位，往往不是同一組。**

假設使用者更新個人資料的 API，預期只該改 `name` 和 `email`：

```json
{ "name": "Edison", "email": "edison@example.com" }
```

但攻擊者把 request body 改成：

```json
{ "name": "Edison", "email": "edison@example.com", "role": "ADMIN", "isVerified": true, "balance": 999999 }
```

如果你的 entity 上**剛好有** `role`、`isVerified`、`balance` 這些欄位，而你又把整包 JSON 直接綁上去——恭喜攻擊者，他剛剛把自己升級成管理員、通過了驗證、帳戶餘額爆表。**他沒有打進任何「漏洞」，他只是填了你願意接受的欄位。**

這就是 Mass Assignment 的核心：**信任邊界搞錯了**。你以為「使用者只會送該送的欄位」，但 request body 是使用者完全掌控的，他想送什麼就送什麼。

---

## 二、為什麼這個洞特別容易中？

1. **「直接綁 entity」是最短的程式碼**：教學、範例、趕工時，大家都愛 `@RequestBody User user`，一行搞定。但 `User` entity 通常承載了所有欄位，包含 `role`、`enabled`、`createdBy` 這些絕不該由使用者控制的東西。
2. **欄位是「之後才長出來的」**：上線時 entity 只有 `name`、`email`，綁整包沒問題。半年後有人加了 `role` 欄位——那個老舊的更新 endpoint 瞬間變成提權漏洞，而且沒人會注意到。
3. **看起來完全正常**：沒有錯誤、沒有例外、沒有可疑 log。攻擊成功時，伺服器只是「照你寫的邏輯」儲存資料。Code review 也很難一眼看出。
4. **巢狀物件更危險**：有些框架支援 `user.account.permissions[0]=ADMIN` 這種深層綁定，攻擊面比你想的大。

---

## 三、Java：Spring 的反例與正解

### 反例：直接把 `@RequestBody` 綁到 entity

```java
@Entity
public class User {
    @Id @GeneratedValue
    private Long id;
    private String name;
    private String email;
    private String role;        // 危險：使用者不該能改
    private boolean enabled;     // 危險
    private BigDecimal balance;  // 危險
    // getters / setters ...
}

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserRepository repo;

    // ❌ 反例：整包 JSON 直接綁到 entity 再存
    @PutMapping("/{id}")
    public User update(@PathVariable Long id, @RequestBody User input) {
        input.setId(id);
        return repo.save(input);   // 攻擊者送的 role / balance 一起被存進去
    }
}
```

只要攻擊者在 body 多塞 `"role": "ADMIN"`，這段就直接把他提權。`repo.save` 不會知道哪些欄位「該」由使用者控制。

### 正解 1：用 DTO + 白名單欄位（最推薦）

讓「對外接收的形狀」與「資料庫 entity」徹底分離。DTO 只放使用者**被允許修改**的欄位，其餘欄位框架根本無從綁起。

```java
// 只暴露允許被修改的欄位
public class UpdateUserRequest {
    @NotBlank
    private String name;
    @Email
    private String email;
    // 沒有 role、enabled、balance —— 攻擊者就算送了也無處可綁
    // getters / setters ...
}

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserRepository repo;

    @PutMapping("/{id}")
    public UserResponse update(@PathVariable Long id,
                               @Valid @RequestBody UpdateUserRequest req) {
        User user = repo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        // 手動、逐欄位地把允許的值搬過去（allow-list）
        user.setName(req.getName());
        user.setEmail(req.getEmail());

        return UserResponse.from(repo.save(user));
    }
}
```

重點：**白名單（allow-list）而非黑名單**。你明確列出「可以改的」，新欄位預設就是不可改——這正是抵抗「欄位之後才長出來」那種陳年漏洞的關鍵。

### 正解 2：若真的要綁 entity，用 `@JsonIgnore` / `@JsonProperty(access = READ_ONLY)`

當你不得不直接序列化 entity 時，至少把敏感欄位封死，讓反序列化階段就拒絕綁定：

```java
@Entity
public class User {
    @Id @GeneratedValue
    private Long id;
    private String name;
    private String email;

    // 只能讀、不能由外部寫入：反序列化時忽略傳入值
    @JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private String role;

    @JsonIgnore   // 完全不參與 JSON 綁定
    private boolean enabled;
    // ...
}
```

但這是**黑名單**思維——你得記得替每個敏感欄位加註解，漏一個就破功。所以仍以 DTO 白名單為首選。

### 正解 3：Spring MVC 表單綁定用 `setAllowedFields`

若是用 `@ModelAttribute` 的傳統表單綁定，可在 `@InitBinder` 明確限制：

```java
@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("name", "email");      // 白名單
    // 或 binder.setDisallowedFields("role", "enabled");  // 黑名單，較不建議
}
```

---

## 四、Go：`json.Unmarshal` 直接灌進 model 的陷阱與正解

Go 沒有「自動把 request 綁進 ORM model」的魔法，但一樣容易踩到等價的洞——只要你 `json.Unmarshal` 進一個帶有敏感欄位的 model，再整包存進 DB。

### 反例：解進 model 再整包更新

```go
type User struct {
    ID      int64  `json:"id"`
    Name    string `json:"name"`
    Email   string `json:"email"`
    Role    string `json:"role"`     // 危險
    Enabled bool   `json:"enabled"`  // 危險
}

// ❌ 反例：把 request body 直接灌進 User，再整包寫回
func UpdateUser(w http.ResponseWriter, r *http.Request) {
    var u User
    if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    u.ID = idFromPath(r)
    db.Save(&u) // 攻擊者送的 role / enabled 一起被寫進去
}
```

`json.Unmarshal` 會盡責地把 body 裡的 `role`、`enabled` 填進 struct。即使你用 GORM 之類的 ORM，`Save` / `Updates(struct)` 也會把這些欄位一起更新。

### 正解：明確的 DTO + 欄位白名單

定義一個只含可改欄位的輸入型別，handler 只搬白名單欄位：

```go
// 只接受允許被修改的欄位
type UpdateUserRequest struct {
    Name  string `json:"name"`
    Email string `json:"email"`
    // 沒有 Role / Enabled —— 攻擊者送了也會被 json 丟棄
}

func UpdateUser(w http.ResponseWriter, r *http.Request) {
    var req UpdateUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }
    if req.Name == "" || !validEmail(req.Email) {
        http.Error(w, "invalid input", http.StatusBadRequest)
        return
    }

    user, err := repo.FindByID(idFromPath(r))
    if err != nil {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }

    // 逐欄位 allow-list 搬移
    user.Name = req.Name
    user.Email = req.Email

    if err := repo.Save(user); err != nil {
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }
    writeJSON(w, toUserResponse(user))
}
```

GORM 進階小撇步：若用 ORM 更新，**只更新指定欄位**而非整個 struct，避免把零值或惡意欄位一起寫入：

```go
// 只更新白名單欄位，其餘欄位 ORM 不碰
db.Model(&user).Select("name", "email").Updates(map[string]any{
    "name":  req.Name,
    "email": req.Email,
})
```

> 小提醒：Go 標準庫的 `encoding/json` 預設會**忽略**目標 struct 沒有的欄位（不會報錯）。若想在收到未知欄位時直接拒絕（更嚴格的縱深防禦），可用 `dec := json.NewDecoder(r.Body); dec.DisallowUnknownFields()`。但這只是輔助——真正的防線仍是「DTO 只放允許欄位」。

---

## 五、容易被忽略的細節

1. **白名單 > 黑名單**：黑名單要靠你記得封住每一個敏感欄位，而新欄位是會「自己長出來」的。白名單則讓未知欄位預設安全。
2. **DTO 不是樣板，是邊界**：很多人嫌 DTO 麻煩而直接綁 entity。但 DTO 的存在本身就是把「對外契約」與「內部資料模型」解耦——這正是防 Mass Assignment 的根本。
3. **巢狀與陣列欄位**：`address`、`roles[]`、`permissions` 這類巢狀結構，綁定時更要逐層檢查，別讓深層欄位漏網。
4. **建立（Create）和更新（Update）的白名單不同**：註冊時或許能設 `email`，但絕不能設 `role`；更新時連 `email` 可能都要走額外驗證流程。兩者各用各的 DTO。
5. **別只靠前端隱藏欄位**：前端沒顯示某欄位，不代表後端不會綁。攻擊者直接打 API，根本不經過你的表單。
6. **寫測試把它釘住**：寫一個「送 `role=ADMIN` 進更新 API，存完後 role 必須沒被改」的測試，確保白名單真的有效，也防止日後有人手滑改回直綁 entity。

---

## 六、後端工程師的 Checklist

- [ ] 找出所有「把 request body 綁進 entity / model 後直接儲存」的 endpoint。
- [ ] **首選**：為每個寫入 API 建立專屬 DTO，只放允許被修改的欄位（白名單）。
- [ ] Create 與 Update 用不同的 DTO，各自的白名單分開定義。
- [ ] Java：避免 `@RequestBody Entity`；若不得已，敏感欄位加 `@JsonProperty(access = READ_ONLY)` 或 `@JsonIgnore`；表單綁定用 `setAllowedFields`。
- [ ] Go：解進 DTO 而非 model；ORM 更新用 `Select(...)` 指定欄位，或 `Updates(map)` 只帶白名單欄位；視情況加 `DisallowUnknownFields()`。
- [ ] 巢狀物件、陣列欄位逐層檢查，別讓深層欄位漏綁。
- [ ] 寫單元測試：送出敏感欄位（`role`/`isAdmin`/`balance`）後，確認它們沒被寫入。
- [ ] Code review 把「直接綁 entity」列為紅旗。

---

## 七、一句話總結

> **Mass Assignment 的本質是「框架很聽話，把使用者送的每個欄位都綁上去」，而使用者完全掌控 request body。防禦核心極簡：用 DTO 把對外欄位白名單化，讓 `role`、`isAdmin`、`balance` 這類欄位根本沒有被綁定的機會。**
> 記住：白名單而非黑名單，因為敏感欄位會在你不注意時「自己長出來」。

---

## 延伸閱讀

- OWASP — Mass Assignment Cheat Sheet
- OWASP API Security Top 10 — API6:2023 Unrestricted Access to Sensitive Business Flows / 歷史上的 API3 Mass Assignment
- Spring — `@JsonProperty(access = READ_ONLY)`、`WebDataBinder.setAllowedFields` 文件
- Go — `encoding/json` 的 `Decoder.DisallowUnknownFields`、GORM `Select` 更新文件
- 前文：Day49 BFLA（同屬「授權繞過」家族，差別在綁定 vs. 功能權限）

---

明天預告：**Day 56 — Race Condition / TOCTOU（Time-of-Check to Time-of-Use）：當「檢查」與「使用」之間出現了一道縫**
（今天 Mass Assignment 是「框架替你綁了不該綁的欄位」；明天看一個時間維度上的洞——你先檢查了餘額/庫存/權限，但在真正動作前那一瞬間，並發的另一個請求把狀態改掉了，於是出現雙重提領、超賣、優惠券重複使用。會講為什麼「先查再用」在並發下天生有縫，並用 Java（`synchronized` 與資料庫樂觀鎖 `@Version`、悲觀鎖 `SELECT ... FOR UPDATE` 的對比）與 Go（用 `sync.Mutex` 與資料庫原子操作 `UPDATE ... WHERE balance >= ?` 把檢查與使用合而為一）示範如何消除那道縫。）
