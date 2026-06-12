---
title: "Day 22 — 競爭條件 (Race Condition) 與 TOCTOU 漏洞"
date: 2026-05-18
tags: ["Race Condition", "並行處理"]
---

# Day 22 — 競爭條件 (Race Condition) 與 TOCTOU 漏洞

> 「我明明檢查過餘額是 100 元，為什麼最後使用者領走了 300 元？」  
> 答案通常只有四個字：**競爭條件**。

今天的主題是後端工程師最常踩、卻最少在教科書裡看到的漏洞：**Race Condition**，特別是它的一個經典子分類 **TOCTOU（Time-of-Check to Time-of-Use）**。這類漏洞在金流、優惠券、額度、票券、抽獎、銀行轉帳等系統中幾乎一定會出現，而且通常是「平常測都好好的，正式上線被攻擊者用 100 條同時打的請求打到破產」。

---

## 一、什麼是 Race Condition？

當「兩個（或多個）執行緒/請求/程序」**同時**存取同一份資源，而最終結果取決於它們執行的**順序**時，就稱為 Race Condition（競爭條件）。

從後端工程師的角度，可以這樣理解：

- 一個 HTTP API 在同一時間可能被「多個請求」呼叫。
- 如果同一個帳號同時送 10 個請求，這 10 個請求會被 10 條執行緒同時處理。
- 如果你的程式碼是「**先讀取狀態 → 做判斷 → 寫回狀態**」，這三步之間如果沒有保護，攻擊者就可以利用這段空檔做出超乎預期的事。

這就是 TOCTOU：**檢查（Check）的當下狀態是 A，但真正使用（Use）的時候已經變成 B 了**。

```
時間軸 →

執行緒 1: [讀餘額=100] ─────── [扣 100] ─→ 餘額變成 0
執行緒 2:      [讀餘額=100] ─────── [扣 100] ─→ 餘額變成 -100 (悲劇)
```

---

## 二、真實世界的例子

這不是學術問題，是真的會被打的：

- **Starbucks（2015）**：研究人員利用儲值卡 API 的競爭條件，可以無限複製卡片餘額。
- **多家加密貨幣交易所**：提款 API 沒做好鎖，攻擊者同時送多筆提領請求，把帳戶從 1 BTC 提成 10 BTC。
- **電商優惠券**：一次性折扣碼可以被同個帳號用 50 次。
- **抽獎/秒殺活動**：庫存 100 個商品，最後賣出 150 個。

---

## 三、漏洞情境：銀行轉帳 API

我們用「使用者轉帳」當例子。商業邏輯非常自然：

1. 查詢使用者餘額  
2. 確認餘額 >= 轉帳金額  
3. 扣款、入帳、寫交易紀錄

### Java 21 版本（有漏洞）

```java
// VulnerableTransferService.java  (Java 21)
public class VulnerableTransferService {

    private final AccountRepository repo;

    public VulnerableTransferService(AccountRepository repo) {
        this.repo = repo;
    }

    public void transfer(long fromId, long toId, BigDecimal amount) {
        // (1) Check
        Account from = repo.findById(fromId);
        if (from.getBalance().compareTo(amount) < 0) {
            throw new IllegalStateException("餘額不足");
        }

        // (2) Use —— 中間這段時間，其他執行緒可能也通過了第 (1) 步！
        from.setBalance(from.getBalance().subtract(amount));
        Account to = repo.findById(toId);
        to.setBalance(to.getBalance().add(amount));

        repo.save(from);
        repo.save(to);
    }
}
```

問題很明顯：**第 (1) 步與第 (2) 步之間沒有任何同步保護**。

### Go 版本（有漏洞）

```go
// vulnerable_transfer.go
func Transfer(db *sql.DB, fromID, toID int64, amount decimal.Decimal) error {
    // (1) Check
    var balance decimal.Decimal
    err := db.QueryRow("SELECT balance FROM accounts WHERE id=?", fromID).Scan(&balance)
    if err != nil {
        return err
    }
    if balance.LessThan(amount) {
        return errors.New("餘額不足")
    }

    // (2) Use —— 這裡同樣有 TOCTOU 縫隙
    _, err = db.Exec("UPDATE accounts SET balance = balance - ? WHERE id=?", amount, fromID)
    if err != nil {
        return err
    }
    _, err = db.Exec("UPDATE accounts SET balance = balance + ? WHERE id=?", amount, toID)
    return err
}
```

---

## 四、攻擊示範：怎麼打？

攻擊者其實不需要什麼神秘的工具，**同時送 N 個一模一樣的請求**就可以了。常見作法：

```bash
# 用 curl + xargs 一次併發 50 個請求
seq 50 | xargs -n1 -P50 -I{} \
  curl -s -X POST https://api.example.com/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"from":123,"to":999,"amount":100}'
```

或用 Go 寫一個壓測小工具：

```go
var wg sync.WaitGroup
for i := 0; i < 50; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        http.Post(url, "application/json", body)
    }()
}
wg.Wait()
```

如果 API 真的有 TOCTOU 漏洞，當餘額剛好等於單次轉帳金額時，攻擊者可以「成功轉帳好幾次」，把錢無中生有出來。

---

## 五、防禦策略（重點！）

這裡有四個層次，**至少要採取其中一種**，理想是組合使用。

### 5.1 資料庫交易 + 悲觀鎖（SELECT ... FOR UPDATE）

最直接的方法：把「讀→判斷→寫」放進一個資料庫交易，並對被修改的列**加排他鎖**。

#### Java 21 + JDBC

```java
public void transfer(long fromId, long toId, BigDecimal amount) throws SQLException {
    try (Connection conn = dataSource.getConnection()) {
        conn.setAutoCommit(false);
        try {
            // 用 FOR UPDATE 鎖住此列，直到 commit
            BigDecimal balance;
            try (var ps = conn.prepareStatement(
                    "SELECT balance FROM accounts WHERE id = ? FOR UPDATE")) {
                ps.setLong(1, fromId);
                try (var rs = ps.executeQuery()) {
                    rs.next();
                    balance = rs.getBigDecimal(1);
                }
            }

            if (balance.compareTo(amount) < 0) {
                throw new IllegalStateException("餘額不足");
            }

            try (var ps = conn.prepareStatement(
                    "UPDATE accounts SET balance = balance - ? WHERE id = ?")) {
                ps.setBigDecimal(1, amount);
                ps.setLong(2, fromId);
                ps.executeUpdate();
            }
            try (var ps = conn.prepareStatement(
                    "UPDATE accounts SET balance = balance + ? WHERE id = ?")) {
                ps.setBigDecimal(1, amount);
                ps.setLong(2, toId);
                ps.executeUpdate();
            }

            conn.commit();
        } catch (Exception e) {
            conn.rollback();
            throw e;
        }
    }
}
```

#### Go + database/sql

```go
func Transfer(ctx context.Context, db *sql.DB, fromID, toID int64, amount decimal.Decimal) error {
    tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
    if err != nil {
        return err
    }
    defer tx.Rollback()

    var balance decimal.Decimal
    err = tx.QueryRowContext(ctx,
        "SELECT balance FROM accounts WHERE id=? FOR UPDATE", fromID,
    ).Scan(&balance)
    if err != nil {
        return err
    }
    if balance.LessThan(amount) {
        return errors.New("餘額不足")
    }

    if _, err = tx.ExecContext(ctx,
        "UPDATE accounts SET balance = balance - ? WHERE id=?", amount, fromID); err != nil {
        return err
    }
    if _, err = tx.ExecContext(ctx,
        "UPDATE accounts SET balance = balance + ? WHERE id=?", amount, toID); err != nil {
        return err
    }
    return tx.Commit()
}
```

> ⚠️ 注意：`FOR UPDATE` 只在「交易內」有效，**沒有 BEGIN 的單獨 SELECT FOR UPDATE 等於沒鎖**。

---

### 5.2 條件式 UPDATE（最推薦的「無鎖」做法）

把「檢查」與「寫入」合併成**一個原子操作**，讓資料庫幫你保證一致性。

```sql
UPDATE accounts
   SET balance = balance - :amount
 WHERE id = :fromId
   AND balance >= :amount;   -- 這一行是關鍵
```

然後檢查**受影響的列數**：

- 受影響 1 列 → 成功
- 受影響 0 列 → 餘額不足 / 已被別人扣走

#### Java 範例

```java
int updated = jdbcTemplate.update(
    "UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?",
    amount, fromId, amount);

if (updated == 0) {
    throw new IllegalStateException("餘額不足或已被處理");
}
```

#### Go 範例

```go
res, err := tx.ExecContext(ctx,
    `UPDATE accounts SET balance = balance - ? WHERE id=? AND balance >= ?`,
    amount, fromID, amount)
if err != nil {
    return err
}
n, _ := res.RowsAffected()
if n == 0 {
    return errors.New("餘額不足或已被處理")
}
```

這種寫法的優點是：

- 沒有 TOCTOU 縫隙（檢查與寫入是同一筆 SQL）
- 不需要顯式鎖、效能好
- 對「庫存扣減」「優惠券核銷」「點數扣抵」都適用

---

### 5.3 樂觀鎖（Optimistic Locking / Version Column）

在資料表加一個 `version` 欄位，每次更新都帶上版本號：

```sql
UPDATE accounts
   SET balance = ?, version = version + 1
 WHERE id = ? AND version = ?;
```

JPA / Hibernate 內建 `@Version` 註解就是這個原理。如果受影響列數 = 0，代表別人已經改過了，丟出例外讓客戶端重試。

適合**衝突機率低、且不想擋住其他人**的場景。

---

### 5.4 分散式鎖（多台伺服器時必備）

如果你的服務是水平擴展（多台 server），光靠資料庫鎖可能不夠（例如鎖的是 Redis 計數器，不是 DB row）。這時用 **Redis 分散式鎖**（Redisson、SETNX + EXPIRE）或 **Zookeeper**：

```java
// 使用 Redisson（Java）
RLock lock = redisson.getLock("transfer:user:" + fromId);
boolean acquired = lock.tryLock(5, 30, TimeUnit.SECONDS);
if (!acquired) {
    throw new IllegalStateException("系統繁忙，請稍後再試");
}
try {
    // 安全地執行轉帳邏輯
} finally {
    lock.unlock();
}
```

> 💡 自己用 `SETNX` 實作鎖時務必設 TTL（避免 server 掛掉後鎖永久不釋放），並用 Lua script 保證「比對 owner + 解鎖」的原子性。Redlock 演算法是其中一種設計。

---

### 5.5 冪等性（Idempotency Key）

不是直接防 race condition，但是金流類 API 必備：要求客戶端帶一個唯一的 `Idempotency-Key` header，後端用此 key 在 Redis/DB 做去重，**同一個 key 的重複請求只會被執行一次**。

Stripe、PayPal、各大金流 API 都用這個機制。實作上：

```go
// 偽代碼
key := r.Header.Get("Idempotency-Key")
if exists := redis.SetNX(ctx, "idem:"+key, "1", 24*time.Hour); !exists {
    return cachedResult(key)   // 已處理過，回放結果
}
// 第一次進來，正常處理...
```

---

## 六、其他常見的 Race Condition 場景

不只是金流。注意這幾類，全部都會有 TOCTOU：

| 場景 | 漏洞 | 防禦 |
|------|------|------|
| 限量優惠券 | 同一張被用多次 | 條件式 UPDATE：`WHERE used = 0` |
| 商品庫存 | 超賣 | 條件式 UPDATE：`WHERE stock > 0` |
| 註冊 email 唯一 | 兩人同時註冊相同 email | DB unique constraint |
| 抽獎/簽到 | 同一天簽到多次 | 唯一索引 (user_id, date) |
| 檔案上傳 | 上傳時檢查副檔名，存檔後檔名被改 | 存檔後用內容判斷、隨機重新命名 |
| 權限提升 | 檢查權限後權限被撤回，仍可使用 | 在每次操作時都重新檢查 |

---

## 七、後端工程師的檢查清單

- [ ] 所有「先讀取再寫入」的金流/額度邏輯，是否都包在資料庫交易裡？
- [ ] 是否使用 `SELECT ... FOR UPDATE`、條件式 UPDATE 或 `@Version`？
- [ ] API 是否提供 `Idempotency-Key` 機制？
- [ ] 對「限量資源」（庫存、折價券）是否有資料庫層級的 unique constraint？
- [ ] 是否做過**併發測試**（用 50 條 thread 同時打同一支 API）？
- [ ] 多台伺服器部署時，是否使用分散式鎖？
- [ ] 你的 ORM 是否預設關閉了 auto-commit？是否在 `@Transactional` 範圍內？

---

## 八、常見誤區

1. **「我加了 `synchronized` 就安全了」** —— 只對「單一 JVM」有效。Production 多台機器時完全失效。
2. **「我用 Redis INCR 來扣庫存就好」** —— 仍然要確保「扣完不為負」用 Lua script 包成原子操作。
3. **「我的 API 有 rate limit 就不會被打」** —— Rate limit 通常是「每秒 N 次」，攻擊者用毫秒級併發 5–10 次就足夠搞爆你。
4. **「我先 SELECT 再 UPDATE，反正都在同一個 transaction」** —— 預設的 Read Committed 隔離級別**不會阻止別的交易讀同一列**。仍然需要 `FOR UPDATE` 或條件式 UPDATE。

---

## 九、重點整理

- Race Condition 的本質是「**Check 與 Use 之間有時間差**」（TOCTOU）。
- 後端工程師最容易在金流、庫存、優惠券、權限這類「讀取狀態 → 判斷 → 寫回狀態」邏輯中踩雷。
- 最實用的兩個防禦工具：**條件式 UPDATE**（單機/輕量）與 **`SELECT FOR UPDATE`**（強一致性需求）。
- 多台伺服器要用**分散式鎖**；金流類 API 一定要做 **Idempotency Key**。
- **務必做併發壓測**：50 條 thread 同時打你的 API，看餘額會不會變負數。能跑通才算上線。

> 明天我們會接著聊另一個很底層、很容易被忽略的主題：**HTTP Request Smuggling（HTTP 請求走私）**——當前端代理（CDN / 反向代理）和後端伺服器對「一個請求到哪裡結束」的認知不一致時，攻擊者就能把一個請求偷渡成兩個，繞過前端的安全檢查。
