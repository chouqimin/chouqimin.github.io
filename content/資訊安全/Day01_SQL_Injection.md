---
title: "Day 01 — SQL Injection（SQL 注入攻擊）"
date: 2026-04-21
tags: ["Injection", "SQL Injection", "OWASP Top 10"]
---

# Day 01 — SQL Injection（SQL 注入攻擊）

> 日期：2026-04-21
> 適合對象：後端工程師初學者
> 主題難度：★☆☆☆☆（基礎必學）

---

## 一、什麼是 SQL Injection？

SQL Injection（SQL 注入，簡稱 SQLi）是指攻擊者**把惡意的 SQL 片段混入使用者輸入**，讓後端程式在不知情的狀況下執行攻擊者指定的查詢。

簡單說：**你以為使用者在填「帳號」，但他其實在寫「SQL」。**

這是 OWASP Top 10 中最經典的漏洞之一，長年名列前茅。一次成功的 SQLi 可能導致：

- 繞過登入驗證（不用密碼也能登入）
- 整個資料庫被下載（個資外洩）
- 資料被竄改或刪除（UPDATE / DROP TABLE）
- 某些情境下甚至能取得作業系統權限

---

## 二、經典情境：登入被繞過

假設我們有一個後端 API，使用者輸入帳號與密碼來登入：

```sql
SELECT * FROM users WHERE username = '輸入的帳號' AND password = '輸入的密碼';
```

### 錯誤示範（Java 1.8，字串拼接）

```java
// 危險！絕對不要這樣寫
public User login(String username, String password) throws SQLException {
    String sql = "SELECT * FROM users WHERE username = '" + username
               + "' AND password = '" + password + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(sql);
    return rs.next() ? mapUser(rs) : null;
}
```

攻擊者在「帳號」欄位輸入：

```
' OR '1'='1
```

實際送到資料庫的 SQL 變成：

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '任何東西';
```

`'1'='1'` 永遠為真，結果就是**不用密碼直接登入第一筆使用者（通常是管理員）**。

---

### 錯誤示範（Go，使用 fmt.Sprintf 拼 SQL）

```go
// 危險！同樣是字串拼接，一樣會中招
func Login(db *sql.DB, username, password string) (*User, error) {
    query := fmt.Sprintf(
        "SELECT id, name FROM users WHERE username = '%s' AND password = '%s'",
        username, password,
    )
    row := db.QueryRow(query)
    // ...
}
```

---

## 三、正確做法：使用「參數化查詢」（Prepared Statement）

核心觀念：**SQL 結構** 與 **使用者資料** 要分開傳給資料庫。資料庫只會把參數當成純資料，永遠不會把它解析成 SQL 語法。

### Java 正確寫法（PreparedStatement）

```java
public User login(String username, String password) throws SQLException {
    String sql = "SELECT id, name FROM users WHERE username = ? AND password = ?";
    try (PreparedStatement ps = connection.prepareStatement(sql)) {
        ps.setString(1, username);
        ps.setString(2, password);
        try (ResultSet rs = ps.executeQuery()) {
            return rs.next() ? mapUser(rs) : null;
        }
    }
}
```

即使使用者輸入 `' OR '1'='1`，對資料庫來說它就只是一串普通文字，SQL 結構不會改變。

> 如果你使用 JPA / Hibernate / MyBatis，記得：
> - JPA / Hibernate：用 `:namedParam` 或 `?1` 佔位符，**不要用字串拼接 JPQL**
> - MyBatis：使用 `#{param}`（會變成參數化查詢），**避免 `${param}`**（是直接字串代換，等同拼接）

### Go 正確寫法（database/sql 佔位符）

```go
func Login(db *sql.DB, username, password string) (*User, error) {
    const query = `SELECT id, name FROM users WHERE username = ? AND password = ?`
    row := db.QueryRow(query, username, password)

    var u User
    if err := row.Scan(&u.ID, &u.Name); err != nil {
        if errors.Is(err, sql.ErrNoRows) {
            return nil, nil
        }
        return nil, err
    }
    return &u, nil
}
```

（PostgreSQL driver 佔位符是 `$1`、`$2`，其他行為相同）

---

## 四、密碼絕對不要明文比對

上面的範例為了示範 SQLi 而留著 `password = ?`，但真正的生產環境**絕對不要在資料庫直接比對明碼密碼**。

正確流程是：
1. 只用 `WHERE username = ?` 撈出那筆使用者
2. 取出資料庫裡儲存的 **雜湊（hash）**
3. 在應用層使用 `bcrypt` / `argon2` / `scrypt` 等演算法驗證

這部分我們會在之後的章節展開。

---

## 五、縱深防禦（Defense in Depth）

參數化查詢是第一道也是最重要的一道防線，但真實世界我們會再加上：

1. **最小權限原則**：應用程式連線資料庫時使用的帳號，只給它需要的權限（例如只給 SELECT/INSERT，不要給 DROP、FILE）。
2. **輸入驗證（白名單）**：某些欄位無法用參數化處理，例如**表格名稱、排序欄位**。這種情境必須用白名單過濾，例如 `if (!List.of("created_at","id").contains(sortCol)) throw ...`。
3. **ORM / Query Builder**：使用成熟的 ORM 可以大幅降低手寫 SQL 的機率（但仍要注意 raw query API）。
4. **WAF（Web Application Firewall）**：作為最後一層網路防線，過濾常見的惡意 pattern。
5. **監控與 logging**：異常查詢次數、UNION SELECT 關鍵字等應觸發告警。

---

## 六、今日重點整理

- **SQL Injection 的本質**：把使用者輸入當作 SQL 結構的一部份拼起來。
- **唯一正確解**：使用參數化查詢（PreparedStatement / 佔位符）。
- **字串拼接是萬惡之源**：`+`、`String.format`、`fmt.Sprintf`、MyBatis 的 `${}` 都要警覺。
- **無法參數化的部分**：例如欄位名、排序方向，必須用**白名單**驗證。
- **縱深防禦**：參數化 + 最小權限 + 輸入驗證 + 監控。

---

## 七、小測驗（請先自己想，再往下看）

以下哪一段程式碼**仍然有 SQL Injection 風險**？為什麼？

```java
String sort = request.getParameter("sort"); // 使用者指定排序欄位
String sql = "SELECT * FROM orders ORDER BY " + sort;
PreparedStatement ps = conn.prepareStatement(sql);
ResultSet rs = ps.executeQuery();
```

<details>
<summary>點我看答案</summary>

**仍然有風險。** 雖然使用了 `PreparedStatement`，但**欄位名稱無法被參數化**，這裡是直接字串拼接 `sort`。攻擊者可以輸入 `id; DROP TABLE orders;--` 之類的惡意字串。

正確做法：使用白名單。

```java
Set<String> allowed = Set.of("id", "created_at", "amount");
if (!allowed.contains(sort)) {
    throw new IllegalArgumentException("Invalid sort column");
}
String sql = "SELECT * FROM orders ORDER BY " + sort;
```

</details>

---

明天預告：**Day 02 — XSS（跨站指令碼攻擊）**，以及後端在 XSS 防禦中扮演的角色。
