---
title: "Day 56：Race Condition / TOCTOU — 當「檢查」與「使用」之間出現了一道縫"
date: 2026-06-21
tags: ["Race Condition", "TOCTOU", "Concurrency", "Java", "Go"]
---

# Day 56：Race Condition / TOCTOU — 當「檢查」與「使用」之間出現了一道縫

接續 Day55 預告：昨天 Mass Assignment 是「框架替你綁了不該綁的欄位」，問題出在**空間**維度——你信任了不該信任的輸入欄位；今天看一個**時間**維度上的洞——**Race Condition**，更精確地說是 **TOCTOU（Time-of-Check to Time-of-Use）**。你先檢查了餘額、庫存或權限（Check），但在真正動作（Use）前那一瞬間，並發的另一個請求把狀態改掉了。於是出現雙重提領、超賣、優惠券重複使用。這次沒有任何「壞輸入」，每個請求看起來都合法——洞藏在它們**交錯執行**的縫隙裡。

---

## 一、漏洞的本質：「先查再用」在並發下天生有縫

絕大多數後端邏輯長這樣：

1. **Check**：讀出目前狀態，判斷「可不可以做」（餘額夠不夠？庫存還有沒有？優惠券用過沒？）
2. **Use**：如果可以，就執行動作並寫回新狀態（扣款、減庫存、標記已使用）

在單執行緒、序列化的世界裡這沒問題。但真實後端是**高並發**的——同一個使用者可以同時送 100 個請求，多台伺服器可以同時處理同一筆資料。問題在於：**Check 和 Use 不是原子的（atomic）**，兩者之間存在一段時間差。

```
請求 A：讀餘額=100 ─┐                          ┌─ 扣 80，寫回 20
請求 B：           └─ 讀餘額=100 ─ 扣 80，寫回 20 ┘
```

兩個請求都在對方寫回之前讀到「餘額=100」，都通過了「餘額 ≥ 80」的檢查，於是各自扣了 80。結果：使用者花了 160，帳上卻只少了 80。這就是經典的**雙重提領（double-spend）**。

核心問題一句話：**你檢查的是「過去某一刻」的狀態，但你動作時依據的卻是「現在」——而這之間，世界已經變了。**

---

## 二、為什麼這個洞特別難抓？

1. **單機測試永遠測不出來**：你本機按一下、按兩下都正常，因為請求是一個一個來的。洞只在「同時」發生時才現形。
2. **它是機率性的**：要剛好兩個請求卡在那道縫裡，時間窗可能只有幾毫秒。測 100 次可能 0 次重現，但攻擊者用腳本同時打 500 個請求，總會中。
3. **攻擊門檻極低**：不需要任何特殊技巧，一段 `for` 迴圈同時發請求（甚至 Burp 的 Turbo Intruder、curl 開背景並發）就能觸發。
4. **看起來完全合法**：每個請求都通過了你的驗證、餘額檢查、權限檢查。Log 裡看不出異常，只有對帳時才發現數字對不上。
5. **分散式環境放大問題**：多台 server、多個 worker，連「同一個 process 內的鎖」都救不了你。

典型受害場景：錢包/點數扣款、電商庫存與秒殺、優惠券/兌換碼一次性使用、邀請額度、限量報名、「只能領一次」的獎勵。

---

## 三、Java：從 `synchronized` 到資料庫鎖

### 反例：先查再用，中間有縫

```java
@Service
public class WalletService {

    private final WalletRepository repo;

    // ❌ 反例：Check 與 Use 分離，並發下會雙重提領
    @Transactional
    public void withdraw(Long userId, BigDecimal amount) {
        Wallet wallet = repo.findByUserId(userId);   // Check：讀餘額
        if (wallet.getBalance().compareTo(amount) < 0) {
            throw new IllegalStateException("餘額不足");
        }
        // ⚠️ 縫隙：另一個執行緒可能在這裡也讀到同樣的舊餘額
        wallet.setBalance(wallet.getBalance().subtract(amount));  // Use：寫回
        repo.save(wallet);
    }
}
```

### 解法 1：`synchronized`（單機、僅供理解，**不適合正式環境**）

最直覺的想法是把整段鎖起來，讓檢查與使用變成不可分割：

```java
private final Object lock = new Object();

public void withdraw(Long userId, BigDecimal amount) {
    synchronized (lock) {           // 同一時間只有一個執行緒能進來
        // ... check 再 use ...
    }
}
```

問題很明顯：(1) 這把鎖**只在單一 JVM 內有效**，一旦水平擴展成多台 server 就破功；(2) 用單一全域鎖會把所有使用者的提款都串行化，效能災難。**所以在分散式後端，真正的防線必須下沉到資料庫（或集中式如 Redis）這個唯一的共享真相來源。**

### 解法 2：樂觀鎖（Optimistic Lock）`@Version`

樂觀鎖假設「衝突很少發生」：不先上鎖，而是在更新時檢查「我讀到之後，有沒有人動過這筆資料」。JPA 用 `@Version` 欄位實現——每次更新版本號 +1，若 `WHERE version = ?` 對不上就代表被別人搶先改了，丟出 `OptimisticLockException`。

```java
@Entity
public class Wallet {
    @Id
    private Long id;
    private BigDecimal balance;

    @Version              // JPA 會自動在 UPDATE 時帶上 version 條件
    private Long version;
    // getters / setters ...
}
```

```java
@Service
public class WalletService {

    private final WalletRepository repo;

    @Transactional
    public void withdraw(Long userId, BigDecimal amount) {
        Wallet wallet = repo.findByUserId(userId);
        if (wallet.getBalance().compareTo(amount) < 0) {
            throw new IllegalStateException("餘額不足");
        }
        wallet.setBalance(wallet.getBalance().subtract(amount));
        repo.save(wallet);   // UPDATE ... SET balance=?, version=version+1 WHERE id=? AND version=?
    }                        // 若 version 不符 → OptimisticLockException，整個交易 rollback
}
```

實際發出的 SQL 類似：

```sql
UPDATE wallet SET balance = ?, version = ? WHERE id = ? AND version = ?
```

若 `affected rows = 0`，代表版本已被別人改掉，JPA 拋例外。搭配重試（retry）機制，衝突的那個請求重新讀一次最新餘額再算一次。**適合衝突率低的場景**（大多數一般 CRUD）。

```java
@Retryable(retryFor = OptimisticLockException.class, maxAttempts = 3)
public void withdrawWithRetry(Long userId, BigDecimal amount) {
    withdraw(userId, amount);
}
```

### 解法 3：悲觀鎖（Pessimistic Lock）`SELECT ... FOR UPDATE`

悲觀鎖假設「衝突很常發生」（例如秒殺）：**讀的當下就把這筆 row 鎖住**，其他想動同一筆的交易必須排隊等待，直到本交易 commit。JPA 用 `@Lock(PESSIMISTIC_WRITE)`：

```java
public interface WalletRepository extends JpaRepository<Wallet, Long> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)   // 產生 SELECT ... FOR UPDATE
    @Query("SELECT w FROM Wallet w WHERE w.userId = :userId")
    Wallet findByUserIdForUpdate(@Param("userId") Long userId);
}
```

```java
@Transactional
public void withdraw(Long userId, BigDecimal amount) {
    // SELECT ... FOR UPDATE：在交易結束前，這筆 row 被獨佔，其他請求排隊
    Wallet wallet = repo.findByUserIdForUpdate(userId);
    if (wallet.getBalance().compareTo(amount) < 0) {
        throw new IllegalStateException("餘額不足");
    }
    wallet.setBalance(wallet.getBalance().subtract(amount));
    repo.save(wallet);
}   // commit 後鎖才釋放
```

因為 row 被鎖住，第二個請求要等第一個 commit 後才讀得到，此時它讀到的已是**扣款後的最新餘額**，縫隙消失。代價是吞吐量下降、要小心鎖等待與死鎖（永遠以固定順序取鎖、設好 lock timeout）。

**樂觀 vs. 悲觀怎麼選？** 衝突少（一般帳號資料）用樂觀鎖 + 重試，效能好；衝突多（秒殺、熱門商品）用悲觀鎖直接排隊，避免大量重試空轉。

---

## 四、Go：用 `sync.Mutex`，更要用「原子的資料庫操作」

### 反例：Decode → Check → Use

```go
// ❌ 反例：讀餘額、判斷、扣款三步分離
func Withdraw(w http.ResponseWriter, r *http.Request) {
    userID := userIDFromCtx(r)
    amount := parseAmount(r)

    wallet, _ := repo.FindByUserID(userID) // Check：讀餘額
    if wallet.Balance < amount {
        http.Error(w, "餘額不足", http.StatusBadRequest)
        return
    }
    // ⚠️ 縫隙：並發請求可能也讀到同一筆舊餘額
    wallet.Balance -= amount               // Use
    repo.Save(wallet)
}
```

### 解法 1：`sync.Mutex`（單機，僅限單一 process）

同一個 process 內，可用 mutex 把臨界區鎖起來。注意要**依 key（如 userID）分鎖**，而不是一把全域鎖把所有人串行化：

```go
type WalletGuard struct {
    mu    sync.Mutex
    locks map[int64]*sync.Mutex
}

func (g *WalletGuard) lockFor(userID int64) *sync.Mutex {
    g.mu.Lock()
    defer g.mu.Unlock()
    if g.locks[userID] == nil {
        g.locks[userID] = &sync.Mutex{}
    }
    return g.locks[userID]
}

func (g *WalletGuard) Withdraw(userID int64, amount int64) error {
    m := g.lockFor(userID)
    m.Lock()
    defer m.Unlock()
    // 在這把 per-user 鎖內 check 再 use
    // ...
    return nil
}
```

但和 Java 的 `synchronized` 一樣：**`sync.Mutex` 只在單一 process 內有效**。一旦你跑多個副本（Kubernetes 多 pod、多台機器），mutex 完全擋不住跨 process 的並發。真正可靠的做法是把「檢查」與「使用」**合併成資料庫的一個原子操作**。

### 解法 2（首選）：把 Check 與 Use 合而為一的原子 UPDATE

不要「先 SELECT 判斷、再 UPDATE 扣款」。把判斷條件直接寫進 `UPDATE ... WHERE` —— 由資料庫保證**判斷與扣款在同一個原子操作裡完成**，沒有縫：

```go
// ✅ 首選：條件式原子更新。餘額判斷與扣款一次完成
func Withdraw(ctx context.Context, db *sql.DB, userID, amount int64) error {
    // 只有在 balance >= amount 時才會更新成功
    res, err := db.ExecContext(ctx,
        `UPDATE wallet
            SET balance = balance - $1
          WHERE user_id = $2
            AND balance >= $1`,   // ← 檢查與扣款原子地綁在一起
        amount, userID)
    if err != nil {
        return err
    }
    affected, _ := res.RowsAffected()
    if affected == 0 {
        // 0 列被更新 = 餘額不足（或使用者不存在）。並發下也絕不會超扣
        return ErrInsufficientBalance
    }
    return nil
}
```

關鍵在 `WHERE balance >= $1`：資料庫在執行這個 `UPDATE` 時會對 row 加鎖，**判斷餘額與扣款是不可分割的單一動作**。就算 1000 個請求同時打進來，資料庫也會逐一序列化處理它們，每個請求看到的都是上一個扣完後的最新餘額。`RowsAffected() == 0` 就是「這次沒扣成功」的權威信號。這招同樣適用於庫存（`stock = stock - 1 WHERE stock >= 1`）與一次性兌換（`UPDATE coupon SET used = true WHERE code = ? AND used = false`）。

### 解法 3：交易內 `SELECT ... FOR UPDATE`（需要先讀值再做複雜邏輯時）

若扣款前需要讀出餘額做更複雜的計算，再用 Go 的 `database/sql` 開交易並上行鎖：

```go
func Withdraw(ctx context.Context, db *sql.DB, userID, amount int64) error {
    tx, err := db.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback() // 若已 commit，Rollback 為 no-op

    var balance int64
    // FOR UPDATE：鎖住該 row，其他交易排隊
    err = tx.QueryRowContext(ctx,
        `SELECT balance FROM wallet WHERE user_id = $1 FOR UPDATE`,
        userID).Scan(&balance)
    if err != nil {
        return err
    }
    if balance < amount {
        return ErrInsufficientBalance
    }
    if _, err = tx.ExecContext(ctx,
        `UPDATE wallet SET balance = balance - $1 WHERE user_id = $2`,
        amount, userID); err != nil {
        return err
    }
    return tx.Commit() // commit 後鎖釋放
}
```

> 小提醒：分散式環境若沒有共用資料庫、或需要跨服務的互斥，可考慮 Redis 分散式鎖（如 `SET key val NX PX ttl`，搭配 Redlock 思路與租約過期），但分散式鎖本身也有它的坑（時鐘、租約、鎖失效），能用資料庫原子操作解決就優先用它。

---

## 五、容易被忽略的細節

1. **「先查再用」就是警訊**：只要程式碼是「讀一個值 → if 判斷 → 改這個值」，並發下幾乎都有縫。看到這個模式就要警惕。
2. **應用層鎖救不了分散式**：`synchronized` / `sync.Mutex` 只在單一 process 內有效。多副本部署時，唯一可靠的共享真相是資料庫（或集中式鎖服務）。
3. **首選「原子操作」而非「鎖」**：能用 `UPDATE ... WHERE 條件` 一步到位的，就別拆成 SELECT + UPDATE。讓資料庫的原子性替你消除縫隙，又快又穩。
4. **資料庫約束是最後一道防線**：餘額不可為負就加 `CHECK (balance >= 0)`；一次性兌換碼就在 `code` 上加 `UNIQUE`。即使應用層邏輯出包，DB 層也會把錯誤擋下來。
5. **冪等性（Idempotency）防重複提交**：給每筆交易一個 idempotency key，重送同一個 key 直接回上次結果，避免「使用者連點兩下」變兩筆扣款。
6. **小心 `Read Committed` 的預設隔離級別**：多數資料庫預設不是 `Serializable`，單純的 SELECT 不會擋住並發寫入。需要強一致時，要嘛升級隔離級別，要嘛明確用 `FOR UPDATE` / 原子 UPDATE。
7. **測試要「並發地」打**：寫一個同時發 N 個請求的測試（Java 用 `CountDownLatch` + thread pool，Go 用 goroutine + `sync.WaitGroup`），驗證最終餘額/庫存數字正確。這是唯一能釘住 race condition 的測法。

---

## 六、後端工程師的 Checklist

- [ ] 盤點所有「讀狀態 → 判斷 → 改狀態」的關鍵流程（扣款、減庫存、一次性兌換、限額領取）。
- [ ] **首選**：把檢查條件寫進 `UPDATE ... WHERE`，用原子操作一步完成判斷與更新，再以 `affected rows == 0` 判定失敗。
- [ ] 需要先讀值做複雜邏輯時，用 `SELECT ... FOR UPDATE`（悲觀鎖）或 `@Version`（樂觀鎖 + 重試）。
- [ ] 衝突少 → 樂觀鎖 + retry；衝突多（秒殺）→ 悲觀鎖排隊。
- [ ] 不要依賴 `synchronized` / `sync.Mutex` 作為分散式環境的唯一防線。
- [ ] 加上資料庫層約束：`CHECK (balance >= 0)`、一次性資源加 `UNIQUE`。
- [ ] 對外部寫入 API 導入冪等性 key，防重複提交。
- [ ] 寫並發測試（多執行緒/多 goroutine 同時打同一筆），驗證最終狀態正確。

---

## 七、一句話總結

> **Race Condition / TOCTOU 的本質是「你檢查的是過去的狀態，動作時依據的卻是現在，而這之間世界已經變了」。防禦核心：別把『檢查』與『使用』拆開——用資料庫的原子操作（`UPDATE ... WHERE 條件`）或行鎖（`FOR UPDATE` / `@Version`）把它們綁成不可分割的一步。**
> 記住：應用層的鎖只保得了單機，跨 process 的並發只有資料庫（或集中式鎖）守得住。

---

## 延伸閱讀

- OWASP — Race Conditions / TOCTOU
- CWE-362：Concurrent Execution using Shared Resource with Improper Synchronization（'Race Condition'）
- CWE-367：Time-of-check Time-of-use (TOCTOU) Race Condition
- Spring Data JPA — `@Lock`、`LockModeType.PESSIMISTIC_WRITE`、`@Version` 樂觀鎖文件
- PostgreSQL / MySQL — `SELECT ... FOR UPDATE` 與交易隔離級別文件
- 前文：Day55 Mass Assignment（空間維度的信任邊界）vs. 今天的時間維度信任邊界

---

明天預告：**Day 57 — JWT 常見誤用：`alg: none`、簽章未驗證與弱密鑰（當「無狀態驗證」變成「無防線驗證」）**
（今天 Race Condition 是並發時間軸上的洞；明天回到身份驗證主題，看 JSON Web Token 最容易踩的幾個雷：攻擊者把 header 的 `alg` 改成 `none` 讓你「不驗章」、用對稱演算法的 key 混淆攻擊（RS256 被當 HS256 驗）、以及把弱 secret 暴力破解。會用 Java（jjwt 函式庫的正確驗證寫法 vs. 只 decode 不 verify 的反例）與 Go（`golang-jwt/jwt` 明確指定允許的簽章演算法、拒絕 `none`）示範如何把 JWT 驗證做對。）
