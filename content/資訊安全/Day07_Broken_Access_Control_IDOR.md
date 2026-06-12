---
title: "Day 07 — Broken Access Control 與 IDOR：別讓使用者「換個 ID」就看到別人的資料"
date: 2026-04-29
tags: ["存取控制", "IDOR", "OWASP Top 10"]
---

# Day 07 — Broken Access Control 與 IDOR：別讓使用者「換個 ID」就看到別人的資料

> 日期：2026-04-29
> 適合對象：後端工程師初學者
> 主題難度：★★★★☆（觀念簡單，但要在每一支 API 都做對非常難）

---

## 一、為什麼這是 OWASP Top 10 的第一名？

OWASP 從 2017 年的第 5 名，一路把 **Broken Access Control（壞掉的存取控制）** 拉到 **2021 年的第 1 名**。原因不是它變難了，而是它**太常被忽略**——絕大多數寫 API 的人都會做 `登入檢查（authentication）`，但忘了做 `授權檢查（authorization）`。

兩件事的差別：

| 概念 | 中文 | 問的問題 | 沒做好會怎樣？ |
| :-- | :-- | :-- | :-- |
| **Authentication** | 身份驗證 | **「你是誰？」** | 任何人都能當別人 |
| **Authorization** | 授權 / 存取控制 | **「你能做什麼？」** | 你登入了，但還是能做「不屬於你」的事 |

過去 6 天我們做的（密碼、JWT、限流）都在解決前者。但只要有一支 API 寫成這樣：

```http
GET /api/orders/12345
```

而後端只檢查「這個人有沒有登入」，沒檢查「12345 這張訂單到底是不是這個人的」——那就是經典的 **IDOR (Insecure Direct Object Reference)**，攻擊者只要把網址改成 `12346`、`12347`⋯⋯就能看到別人的訂單。

> 一句話：**身份驗證告訴你「他是 Alice」，存取控制決定「Alice 能不能看這份資料」。兩件事都要做。**

---

## 二、Broken Access Control 的 5 種常見樣貌

| 編號 | 名稱 | 一句話描述 | 攻擊例子 |
| :-- | :-- | :-- | :-- |
| 1 | **IDOR** | 用 ID 直接撈資料、沒檢查擁有者 | 改 `/orders/123` → `/orders/124` |
| 2 | **Function-Level 缺漏** | 缺角色檢查的「敏感動作」 | 一般使用者打 `POST /api/admin/users/delete` 可以動 |
| 3 | **垂直越權（Privilege Escalation）** | 一般使用者升級成管理員 | 偽造 `role=admin` 的 cookie / JWT claim |
| 4 | **水平越權** | 同等級使用者互相看到對方資料 | A 使用者改 ID 看 B 使用者訂單（這是 IDOR 的另一種說法）|
| 5 | **強制瀏覽（Forced Browsing）** | 直接打你「以為沒人會找到」的 URL | `/admin`、`/debug`、`/.git/config` 直接被列舉到 |

**你只要記住兩個原則就能擋掉 80%：**

1. **Default Deny**：每個 endpoint 預設「禁止」，要明確 allowlist 才開放。
2. **Server-Side Check**：所有授權判斷都在後端做，UI 隱藏的按鈕不算數。

---

## 三、IDOR 的最小重現範例

### 3.1 一段「看起來沒問題」的 Java Spring Boot 程式

```java
// ⚠️ 有 IDOR 漏洞 — 千萬別這樣寫
@RestController
@RequestMapping("/api/orders")
public class OrderController {

    @Autowired
    private OrderRepository orderRepository;

    @GetMapping("/{orderId}")
    public Order getOrder(@PathVariable Long orderId,
                          @AuthenticationPrincipal UserDetails user) {
        // 只檢查「有沒有登入」，沒檢查「這張訂單是不是他的」
        return orderRepository.findById(orderId)
            .orElseThrow(() -> new NotFoundException("Order not found"));
    }
}
```

看起來很合理對吧？有 `@AuthenticationPrincipal`、有登入才能進來。但是：

- Alice 登入後打 `GET /api/orders/1001` → 看到自己的訂單 ✅
- Alice 把網址改成 `GET /api/orders/1002` → 看到 **Bob 的訂單** ❌

只是少了一行「這張訂單是不是 Alice 的」檢查。

### 3.2 修正版

```java
// ✅ 正確版本
@GetMapping("/{orderId}")
public Order getOrder(@PathVariable Long orderId,
                      @AuthenticationPrincipal UserDetails user) {
    Order order = orderRepository.findById(orderId)
        .orElseThrow(() -> new NotFoundException("Order not found"));

    // 授權檢查：訂單擁有者必須是當前登入者
    if (!order.getOwnerUsername().equals(user.getUsername())) {
        // 注意：故意丟「找不到」而不是「沒權限」，避免洩漏「ID 是否存在」
        throw new NotFoundException("Order not found");
    }
    return order;
}
```

更好的寫法：把這個檢查推進 Repository 層，**讓 SQL 自己過濾**：

```java
public interface OrderRepository extends JpaRepository<Order, Long> {
    // 找不到「屬於這個人」的訂單，等同找不到
    Optional<Order> findByIdAndOwnerUsername(Long id, String ownerUsername);
}

// Controller
@GetMapping("/{orderId}")
public Order getOrder(@PathVariable Long orderId,
                      @AuthenticationPrincipal UserDetails user) {
    return orderRepository.findByIdAndOwnerUsername(orderId, user.getUsername())
        .orElseThrow(() -> new NotFoundException("Order not found"));
}
```

> 為什麼推到 Repository？因為「忘了授權」這件事，**只要在一個 Controller 漏掉就破功了**。把它放在資料層，讓「只能撈自己資料」變成預設行為，更難寫錯。

### 3.3 同樣的問題在 Go 的樣子

```go
// ⚠️ 有 IDOR 漏洞
func GetOrder(w http.ResponseWriter, r *http.Request) {
    orderID := chi.URLParam(r, "orderID")

    var order Order
    if err := db.First(&order, orderID).Error; err != nil {
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(order)  // 任何登入者都能看任何訂單
}
```

```go
// ✅ 修正版
func GetOrder(w http.ResponseWriter, r *http.Request) {
    orderID := chi.URLParam(r, "orderID")
    userID := r.Context().Value(ctxUserID).(int64) // 從中介層拿到登入者

    var order Order
    err := db.Where("id = ? AND owner_id = ?", orderID, userID).
        First(&order).Error
    if err != nil {
        // 一律回 404，不告訴攻擊者「這個 ID 存在但你沒權限」
        http.Error(w, "not found", http.StatusNotFound)
        return
    }
    json.NewEncoder(w).Encode(order)
}
```

---

## 四、為什麼「換成 UUID」不是解法？

很多人以為把 `id=12345` 換成 `id=550e8400-e29b-41d4-a716-446655440000` 就安全了。

**錯。** 這只是 _security through obscurity_（依賴隱晦性的安全），原因：

1. UUID 還是會在 URL、Log、Referer header、瀏覽器歷史紀錄、第三方分析工具裡洩漏。
2. 你可能在某個列表 API 不小心把別人的 UUID 一起回傳。
3. 從前端跳轉、從 email 連結都可能被分享出去。

**UUID 防的是「猜測」，不是「洩漏」**。授權檢查永遠都要做，UUID 只是讓暴力枚舉更難而已。

---

## 五、垂直越權：把 `role` 放在客戶端的悲劇

### 5.1 反面教材

```java
// ⚠️ JWT 裡塞 role，但伺服器只看 JWT 簽章沒看資料庫
public class AdminController {
    @DeleteMapping("/api/admin/users/{id}")
    public void deleteUser(@PathVariable Long id,
                           @AuthenticationPrincipal Jwt jwt) {
        String role = jwt.getClaim("role"); // 從 JWT 讀
        if (!"ADMIN".equals(role)) {
            throw new ForbiddenException();
        }
        userRepository.deleteById(id);
    }
}
```

問題不是 JWT 簽章被偽造（那是 Day 05 的問題）。問題是：

- 使用者的 role 在「**JWT 簽發那一刻**」是 USER，後來被升等成 ADMIN——還是要等他重新登入才生效。
- 反過來：原本是 ADMIN，被降權後**舊 JWT 還沒過期前**仍然能呼叫管理員 API。
- JWT 內容如果是不可逆轉的「身份快照」，授權邏輯就跟即時資料庫脫鉤了。

### 5.2 修正方向

- 敏感操作（刪使用者、改金額、退款⋯⋯）**永遠去 DB 重查 role**，不要只信 JWT。
- 用 Spring Security 的 `@PreAuthorize("hasRole('ADMIN')")` + 實作 `UserDetailsService` 每次都查 DB。
- 或者用「短效 JWT + 撤銷清單」（Day 05 我們有提過）。

```java
// ✅ 用框架做、且資料庫為準
@PreAuthorize("hasRole('ADMIN')")
@DeleteMapping("/api/admin/users/{id}")
public void deleteUser(@PathVariable Long id) {
    userRepository.deleteById(id);
}
```

Spring Security 在進入這個方法前，會根據 `UserDetailsService.loadUserByUsername()` 拿到當前 role——你只要讓那個方法每次去查 DB（或加上短期快取），就能把延遲降到可接受範圍。

---

## 六、實戰：一張「Default Deny」檢查表

每寫完一支 API，問自己這 6 個問題：

```
┌─────────────────────────────────────────────────────────────┐
│ 1. 這支 API 需要登入嗎？           → 預設「是」                │
│ 2. 需要哪些角色？                  → 明確列出，不留白          │
│ 3. 操作的資料屬於誰？              → 在 SQL WHERE 加 owner_id │
│ 4. 失敗時回傳什麼？                → 一律 404，不要 403 透露   │
│ 5. 有沒有「批次端點」（如 /bulk）？ → 每一筆都要檢查           │
│ 6. 寫了測試嗎？                    → 用「別人的 ID」打過       │
└─────────────────────────────────────────────────────────────┘
```

第 6 點特別重要——**寫一個整合測試，模擬「Bob 用自己的 token 去打 Alice 的訂單 ID」，預期得到 404**。這個測試一旦過了，就能幫你擋住未來每一次的迴歸。

```java
// JUnit 5 + Spring Boot Test 範例
@Test
void bobCannotAccessAliceOrder() throws Exception {
    String bobToken = login("bob", "bobPassword");
    long aliceOrderId = orderRepository
        .findByOwnerUsername("alice").get(0).getId();

    mockMvc.perform(get("/api/orders/" + aliceOrderId)
            .header("Authorization", "Bearer " + bobToken))
        .andExpect(status().isNotFound());  // 不是 200 也不是 403
}
```

---

## 七、進階：多層防禦怎麼疊？

像 Day 06 一樣，授權也是多層：

```
   [Request]
     │
     ▼
  ┌──────────────────────────────────────┐
  │ 1. Gateway / Reverse Proxy            │ 擋未登入的 admin 路徑
  ├──────────────────────────────────────┤
  │ 2. Framework Auth Middleware          │ 取出 user、檢查登入
  ├──────────────────────────────────────┤
  │ 3. Method-Level Auth (@PreAuthorize)  │ 檢查角色
  ├──────────────────────────────────────┤
  │ 4. Business Logic Check               │ 檢查擁有者、檢查狀態（已退款不能再退）│
  ├──────────────────────────────────────┤
  │ 5. Data Layer (Row-Level Security)    │ DB 強制只看自己的列            │
  └──────────────────────────────────────┘
```

第 5 層在 PostgreSQL 等資料庫可以用 **Row Level Security (RLS)**，配合每次連線設定 session variable：

```sql
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
CREATE POLICY orders_owner ON orders
  FOR ALL USING (owner_id = current_setting('app.current_user_id')::bigint);
```

即使應用層忘了加 `WHERE owner_id`，DB 也會幫你擋。這是「縱深防禦」的精神。

---

## 八、今日重點回顧

1. **Authentication ≠ Authorization。** 登入只是入場券，不是萬用通行證。
2. **IDOR 是最常見的存取控制漏洞**——只要 API 收 ID 並回資料，就要問「這份資料屬於誰？」。
3. **把擁有者檢查放進 Repository / SQL `WHERE`**，不要只放在 Controller，否則只要一個地方漏寫就破功。
4. **不要靠 UUID「藏」資料**，授權檢查還是要做。
5. **垂直越權的關鍵在「JWT 是快照、DB 才是真相」**——敏感操作要重查 role。
6. **每支新 API 都跑一次 6 題檢查表**，並且寫一個「別人打我資料」的整合測試。
7. **縱深防禦**：Gateway → 中介層 → 方法層註解 → 業務邏輯 → DB Row Level Security，能疊就疊。

---

## 九、明天預告

Day 08 我們會進到 **Input Validation 與 Mass Assignment**——談「為什麼 `User user = request.toUser()` 是個地雷」、為什麼 `@RequestBody User user` 一不小心就讓使用者把自己 `isAdmin` 改成 `true`。這是另一個「框架替你做太多事」的經典翻車現場。

---

> 參考資料
> - OWASP Top 10:2021 — A01: Broken Access Control
> - OWASP API Security Top 10:2023 — API1: Broken Object Level Authorization
> - CWE-639: Authorization Bypass Through User-Controlled Key
> - PostgreSQL Documentation — Row Security Policies
