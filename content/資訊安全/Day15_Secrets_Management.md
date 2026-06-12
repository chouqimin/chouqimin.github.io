---
title: "Day 15：敏感資料保護與密鑰管理（Secrets Management）"
date: 2026-05-10
tags: ["Secrets 管理", "DevSecOps"]
---

# Day 15：敏感資料保護與密鑰管理（Secrets Management）

> **適合對象**：後端工程師初學者
> **語言範例**：Java（1.8 / 21）、Go
> **OWASP 對應**：A02:2021 - Cryptographic Failures、A05:2021 - Security Misconfiguration

---

## 一、一個真實的、令人心碎的故事

2019 年，一位工程師為了測試方便，把 AWS 的 access key 直接寫進 `application.properties` 推上了公開的 GitHub 專案。

當時他想：「我等一下就會把它移除掉。」

**3 分鐘後**，攻擊者的爬蟲掃到了那個 commit。
**1 小時後**，攻擊者用這把鑰匙開了 200 台 EC2 高規機器跑加密貨幣挖礦。
**隔天早上**，公司收到一張 8 萬美金的 AWS 帳單。

更糟的是：就算他事後 force push 把 commit 移掉，**Git 歷史中那把 key 永遠存在**——任何人 clone 後 `git log -p` 都看得到。

這就是「Secrets Management」要解決的問題：**程式裡的祕密，不是寫在程式碼裡就是安全的**。

---

## 二、什麼算是「祕密（Secret）」？

只要洩漏出去就會出事的東西，都算：

- 資料庫帳號密碼、連線字串
- 第三方 API 金鑰（AWS、GCP、Stripe、SendGrid…）
- JWT 簽章用的 secret key
- OAuth client secret
- 加密用的對稱金鑰、私鑰
- TLS 憑證的 private key
- 內部服務之間的 service token

許多後端新手會直接把這些東西寫進設定檔、Dockerfile、或硬塞在程式碼字串裡，這是最常見也最致命的錯誤。

---

## 三、四種常見的錯誤做法（你正在做哪一種？）

### 錯誤 1：Hardcode 在原始碼

```java
// 反面教材
public class DbConfig {
    public static final String URL = "jdbc:mysql://prod-db:3306/app";
    public static final String USER = "root";
    public static final String PASSWORD = "P@ssw0rd1234";   // ← 災難
}
```

```go
// 反面教材
const stripeSecret = "sk_live_51HabcXyz..."  // ← 別再這樣了
```

問題：只要進過 Git，這把 key 就永遠在歷史紀錄中。內部員工、外包、實習生、被駭的開發機器都看得到。

### 錯誤 2：寫在 application.properties / config.yaml 並 commit

```properties
# application.properties（commit 上去 = 等於 hardcode）
spring.datasource.password=P@ssw0rd1234
jwt.secret=my-super-secret-key
```

很多人以為「config 檔不算 code」，但 Git 不在乎這個——它一視同仁地保留歷史。

### 錯誤 3：日誌（log）裡印出密碼或 token

```java
// 反面教材
logger.info("User login request: {}", request);   // request 裡面有 password
logger.debug("API call with token: {}", apiToken);
```

Log 通常會被收集到中央日誌系統（ELK、Splunk、Datadog），權限往往比程式碼更寬。**密碼一旦進 log，視同已洩漏**。

### 錯誤 4：把 secret 寫在 Docker image 裡

```dockerfile
# 反面教材
ENV DB_PASSWORD=P@ssw0rd1234
```

Image 會被推到 registry，每一層都可以被 `docker history` 還原。內網被打進來，所有 image 都成了攻擊者的字典。

---

## 四、正確的做法：分層防禦

### 第一層：環境變數（Environment Variables）

這是最基本、最低門檻的解法。把 secret 從程式碼分離出來，由執行環境注入。

#### Java 21 範例

```java
public class DbConfig {
    public static final String URL =
        Optional.ofNullable(System.getenv("DB_URL"))
                .orElseThrow(() -> new IllegalStateException("DB_URL not set"));

    public static final String USER = System.getenv("DB_USER");
    public static final String PASSWORD = System.getenv("DB_PASSWORD");
}
```

Spring Boot 中更直接：

```yaml
# application.yml
spring:
  datasource:
    url: ${DB_URL}
    username: ${DB_USER}
    password: ${DB_PASSWORD}
```

#### Go 範例

```go
package config

import (
    "fmt"
    "os"
)

type DBConfig struct {
    URL      string
    User     string
    Password string
}

func LoadDBConfig() (*DBConfig, error) {
    pwd := os.Getenv("DB_PASSWORD")
    if pwd == "" {
        return nil, fmt.Errorf("DB_PASSWORD is required")
    }
    return &DBConfig{
        URL:      os.Getenv("DB_URL"),
        User:     os.Getenv("DB_USER"),
        Password: pwd,
    }, nil
}
```

**注意**：環境變數不是萬靈丹，它會被 `/proc/<pid>/environ` 看到，dump core 也可能洩漏。但比 hardcode 好太多了。

### 第二層：本地開發用 `.env`，但**絕對不能 commit**

```
# .gitignore（必加）
.env
.env.local
*.pem
*.key
```

`.env` 只是給開發者本機方便用的，部署環境永遠用真正的環境變數注入機制（Kubernetes Secret、CI/CD 變數、雲端服務的 secret 注入）。

### 第三層：專業的 Secret Manager

當系統規模變大，環境變數會出現新問題：誰能看？怎麼輪替？誰用過了？這時就需要：

- **HashiCorp Vault**：開源、跨雲。
- **AWS Secrets Manager / Parameter Store**
- **GCP Secret Manager**
- **Azure Key Vault**
- **Kubernetes Secret + 加密 etcd**（最低限度）

這些工具提供的核心價值：

1. **加密儲存**：不是明文。
2. **存取控制**：哪個服務、哪個 IAM role 可以拿到。
3. **稽核日誌**：誰在何時拿了什麼。
4. **動態金鑰、自動輪替**：每 24 小時換一把資料庫密碼。

#### Java 21 從 AWS Secrets Manager 取得

```java
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

public class SecretLoader {
    private static final SecretsManagerClient client =
        SecretsManagerClient.create();

    public static String load(String name) {
        var req = GetSecretValueRequest.builder().secretId(name).build();
        return client.getSecretValue(req).secretString();
    }
}

// 啟動時呼叫一次，快取在記憶體（不要每次 query 都打 API）
String dbPassword = SecretLoader.load("prod/db/password");
```

#### Go 從 GCP Secret Manager 取得

```go
package secrets

import (
    "context"
    "fmt"

    secretmanager "cloud.google.com/go/secretmanager/apiv1"
    "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

func LoadSecret(ctx context.Context, name string) (string, error) {
    client, err := secretmanager.NewClient(ctx)
    if err != nil {
        return "", err
    }
    defer client.Close()

    req := &secretmanagerpb.AccessSecretVersionRequest{
        Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest",
            "my-project", name),
    }
    res, err := client.AccessSecretVersion(ctx, req)
    if err != nil {
        return "", err
    }
    return string(res.Payload.Data), nil
}
```

---

## 五、Log 的安全：永遠不要直接印 request / DTO

很多 framework 預設的 toString 會把所有欄位印出來，包含 password。要主動防呆。

### Java：使用 record 或自訂 toString

```java
// Java 21 record，重寫 toString 把敏感欄位遮罩
public record LoginRequest(String username, String password) {
    @Override
    public String toString() {
        return "LoginRequest{username='" + username + "', password='***'}";
    }
}
```

或使用 Lombok 時加 `@ToString.Exclude`：

```java
@ToString
public class LoginRequest {
    private String username;

    @ToString.Exclude
    private String password;
}
```

### Go：自訂 String() 方法

```go
type LoginRequest struct {
    Username string
    Password string
}

func (l LoginRequest) String() string {
    return fmt.Sprintf("LoginRequest{Username:%s, Password:***}", l.Username)
}
```

並且在 logger 設定中加入「敏感欄位過濾器」，掃描 log 內容裡像 `password=`、`token=`、`Authorization: Bearer` 等模式自動 redact。

---

## 六、檢查清單：今天就能做的 6 件事

第一，在 repo 根目錄建立或檢查 `.gitignore`，確認 `.env`、`*.pem`、`*.key` 都被排除。

第二，跑一次祕密掃描工具確認過去沒有提交過敏感資料：

```bash
# trufflehog
docker run --rm -v "$(pwd)":/repo trufflesecurity/trufflehog \
    git file:///repo --since-commit HEAD~100

# git-secrets
brew install git-secrets
git secrets --install
git secrets --register-aws
git secrets --scan-history
```

第三，把所有 `application.properties`、`config.yaml` 中的硬編碼密碼改成 `${ENV_VAR}` 注入。

第四，CI/CD 加上「禁止 commit secret」的 pre-commit hook 或 server-side hook。

第五，找出所有會印 `request` 或 DTO 的 log，確認密碼欄位已遮罩。

第六，**如果你曾經把 secret 推上 Git，立刻輪替（rotate）那把 key**。把 commit 砍掉沒用，因為攻擊者可能已經拿到——重點是讓那把 key 失效。

---

## 七、常見迷思

> 「我是 private repo，不會有事吧？」

不對。Repo 隨時可能被誤設為 public、員工帳號被盜、合作廠商離職、自動備份外洩。**祕密不該存在於 Git，無論 public 或 private**。

> 「Base64 編碼一下總可以吧？」

Base64 不是加密，是編碼。10 秒就能解開。Kubernetes Secret 預設就是 Base64，所以一定要再開啟 etcd 加密或搭配 Vault。

> 「我們是內網系統不對外，沒差吧？」

90% 的資料外洩來自「內部威脅」或「橫向移動」——攻擊者打進來第一步就是找有沒有暴露的密鑰可以擴大戰果。

---

## 八、小結

| 等級 | 做法 | 適用場景 |
|------|------|----------|
| 0（最差） | Hardcode 在程式碼 / 設定檔並 commit | **永遠不要** |
| 1 | 環境變數 + `.env`（已 gitignore） | 小型專案、本地開發 |
| 2 | CI/CD 注入環境變數 + Kubernetes Secret | 中小型團隊部署 |
| 3 | 專業 Secret Manager（Vault / AWS / GCP） | 生產環境、企業級 |
| 4 | 動態憑證、自動輪替、零信任架構 | 高敏感、合規要求 |

身為後端工程師，至少要做到等級 2；生產環境強烈建議等級 3 起跳。

> **今日金句**：你的祕密只跟你最弱的那層防線一樣安全。Hardcode 永遠是那條最弱的線。

---

明天我們會接著聊另一個後端常踩的坑：**安全日誌與監控（Security Logging & Monitoring）**——出事的時候，你的 log 能不能還原攻擊軌跡？哪些事件一定要記（登入失敗、權限變更、敏感操作），又有哪些東西（密碼、token、個資）絕對不能寫進 log？
