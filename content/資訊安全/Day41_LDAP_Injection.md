---
title: "Day 41：LDAP Injection — 被遺忘的注入漏洞"
date: 2026-06-06
tags: ["Injection", "LDAP"]
---

# Day 41：LDAP Injection — 被遺忘的注入漏洞

> 「我們有 SQL Injection 防護、有 XSS 防護，可是公司內網的登入系統怎麼會出事？」
>
> 答案常常就是：**LDAP Injection**。

當系統用 LDAP（Lightweight Directory Access Protocol）做企業內部驗證、員工目錄查詢、群組權限檢核時，如果開發者用「字串拼接」組合 LDAP filter，攻擊者就能竄改查詢條件，繞過登入、列舉所有使用者，甚至搭配權限提升攻擊整個 AD（Active Directory）。

今天就帶你從零理解 LDAP Injection。

---

## 一、為什麼後端工程師要懂 LDAP？

LDAP 是企業環境中用來儲存「樹狀結構資料」的協定，最常見的應用：

- **Microsoft Active Directory（AD）**：員工帳號、群組、權限
- **OpenLDAP / 389 Directory**：開源目錄服務
- **單一登入（SSO）**：很多 SSO 系統背後就是 LDAP
- **應用整合**：GitLab、Jenkins、Jira、Confluence 等都常用 LDAP 做帳號整合

只要你的 Java/Go 後端有「呼叫 LDAP 查詢」的地方，就有 LDAP Injection 的風險。

---

## 二、LDAP filter 長什麼樣子？

LDAP 查詢使用 **filter 語法**（RFC 4515），用括號包起來，並用前綴運算子。例如：

```
(uid=edison)                     → 查 uid 等於 edison 的人
(&(uid=edison)(userPassword=123)) → AND：uid 是 edison 且密碼是 123
(|(uid=edison)(uid=alice))       → OR：uid 是 edison 或 alice
(uid=*)                          → 萬用字元，比對任何 uid
(!(uid=edison))                  → NOT：uid 不是 edison
```

關鍵特殊字元：`(` `)` `*` `\` `NUL` `/`

**只要這些字元未經跳脫就拼進 filter，就可能被注入。**

---

## 三、漏洞情境：登入驗證

### 有問題的 Java 程式碼

```java
// ❌ 危險：字串拼接組 LDAP filter
public boolean authenticate(String username, String password) throws NamingException {
    Hashtable<String, Object> env = new Hashtable<>();
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    env.put(Context.PROVIDER_URL, "ldap://ldap.company.com:389");

    DirContext ctx = new InitialDirContext(env);

    // 把使用者輸入直接拼進 filter
    String filter = "(&(uid=" + username + ")(userPassword=" + password + "))";

    NamingEnumeration<SearchResult> results =
        ctx.search("ou=users,dc=company,dc=com", filter, new SearchControls());

    return results.hasMore();  // 有結果就視為登入成功
}
```

### 攻擊者怎麼打？

假設使用者欄位填：

```
username = *
password = *)(uid=*
```

組出來的 filter 變成：

```
(&(uid=*)(userPassword=*)(uid=*))
```

`uid=*` 比對任何使用者、`userPassword=*` 比對任何密碼，結果集**永遠不為空**，登入直接被繞過。

更可怕的是「**布林盲注**」——攻擊者可以用 `*` 一個一個字元爆密碼或帳號清單。

---

## 四、防禦做法

### 1. 用 LDAP 跳脫函式（首選）

把所有使用者輸入做跳脫，把特殊字元轉成 `\XX` 格式（兩位十六進位）。

#### Java：用 OWASP ESAPI 或自行實作

```java
// ✅ 安全：跳脫使用者輸入
public static String escapeLdapFilter(String input) {
    if (input == null) return null;
    StringBuilder sb = new StringBuilder();
    for (char c : input.toCharArray()) {
        switch (c) {
            case '\\': sb.append("\\5c"); break;
            case '*':  sb.append("\\2a"); break;
            case '(':  sb.append("\\28"); break;
            case ')':  sb.append("\\29"); break;
            case '\0': sb.append("\\00"); break;
            case '/':  sb.append("\\2f"); break;
            default:   sb.append(c);
        }
    }
    return sb.toString();
}

// 使用
String filter = "(&(uid=" + escapeLdapFilter(username) + ")"
              + "(userPassword=" + escapeLdapFilter(password) + "))";
```

#### Spring LDAP：用 `LdapQueryBuilder`

```java
// ✅ 推薦：用 LdapQuery API，框架幫你跳脫
import static org.springframework.ldap.query.LdapQueryBuilder.query;

LdapQuery q = query()
    .base("ou=users,dc=company,dc=com")
    .where("uid").is(username);

ldapTemplate.search(q, new AttributesMapper<String>() { ... });
```

#### Go：用 `go-ldap/ldap` 的 `EscapeFilter`

```go
// ✅ 安全：使用官方提供的 EscapeFilter
import "github.com/go-ldap/ldap/v3"

filter := fmt.Sprintf("(&(uid=%s)(objectClass=person))",
    ldap.EscapeFilter(username))

searchRequest := ldap.NewSearchRequest(
    "ou=users,dc=company,dc=com",
    ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
    filter, []string{"dn", "cn"}, nil,
)
sr, err := conn.Search(searchRequest)
```

> 注意：使用 `context7` 確認 `github.com/go-ldap/ldap/v3` 是目前主要維護的版本（舊版 `gopkg.in/ldap.v2` 已停止維護）。

---

### 2. 不要用 LDAP filter 比對密碼

上面那個漏洞案例還有一個根本問題：**用 filter 直接比對密碼**。正確做法是：

1. 先用「服務帳號」查 user DN（distinguished name）
2. 用查到的 DN + 使用者輸入的密碼去 **bind**
3. bind 成功代表帳密正確

```java
// ✅ 正確的 LDAP 驗證流程
public boolean authenticate(String username, String password) throws NamingException {
    // Step 1: 用服務帳號搜尋 user DN
    DirContext serviceCtx = createServiceContext();
    String safeUid = escapeLdapFilter(username);
    String filter = "(&(objectClass=person)(uid=" + safeUid + "))";

    NamingEnumeration<SearchResult> results =
        serviceCtx.search("ou=users,dc=company,dc=com", filter, new SearchControls());

    if (!results.hasMore()) return false;
    String userDn = results.next().getNameInNamespace();
    serviceCtx.close();

    // Step 2: 用使用者 DN + 密碼 bind（密碼不進 filter！）
    Hashtable<String, Object> env = new Hashtable<>();
    env.put(Context.SECURITY_AUTHENTICATION, "simple");
    env.put(Context.SECURITY_PRINCIPAL, userDn);
    env.put(Context.SECURITY_CREDENTIALS, password);
    // ... ldap URL 等設定

    try {
        new InitialDirContext(env).close();
        return true;
    } catch (AuthenticationException e) {
        return false;
    }
}
```

這樣就算沒做跳脫，密碼也不會被當作 filter 解析。

---

### 3. 限制可注入點 + 白名單驗證

如果欄位本來就只能是英數字（例如員工編號），先做格式驗證：

```java
if (!username.matches("^[a-zA-Z0-9._-]{1,32}$")) {
    throw new IllegalArgumentException("Invalid username format");
}
```

---

### 4. 最小權限原則

- 用於查詢的 **service account 只給讀取權限**，且只能讀必要的 OU。
- 不要讓應用程式拿 Domain Admin 去打 LDAP。
- 如果服務帳號被洩漏或被注入，影響範圍才有限。

---

## 五、Checklist：審查你的程式碼

開啟你公司專案，搜尋這幾個關鍵字看看：

- Java：`ctx.search(`、`new SearchControls`、`InitialDirContext`、`LdapTemplate`
- Go：`ldap.NewSearchRequest`、`conn.Search(`

每一處都自問：

1. filter 字串裡有沒有「`+ 變數 +`」或 `fmt.Sprintf` 直接帶入使用者輸入？
2. 有沒有呼叫跳脫函式（`EscapeFilter` / `escapeLdapFilter`）？
3. 密碼是否「比對」進 filter 而不是用 bind？
4. service account 的權限是不是過大？

只要任何一項回答「不確定」，就值得花時間補上防禦。

---

## 六、今日小結

| 重點 | 做法 |
|------|------|
| 不信任使用者輸入 | 所有進 LDAP filter 的字串都要跳脫 |
| 用框架 API | Spring LDAP 的 `LdapQueryBuilder`、Go 的 `ldap.EscapeFilter` |
| 密碼用 bind | 不要把密碼塞進 filter 比對 |
| 最小權限 | service account 只給必要的讀取權限 |
| 輸入驗證 | 對固定格式欄位做白名單檢查 |

LDAP Injection 雖然不像 SQL Injection 那麼有名，但在使用 AD 整合的企業環境裡其實非常常見，而且一旦被打穿，影響的常常是「全公司員工目錄」。明天見！

---

**參考資料**

- OWASP: LDAP Injection Prevention Cheat Sheet
- RFC 4515: LDAP String Representation of Search Filters
- Spring LDAP Reference Documentation
- go-ldap/ldap v3 官方文件
