---
title: "Day 83：SPIRE Server 的信任根保管 — upstream CA、簽發金鑰與 HSM（延伸篇）"
date: 2026-07-23
tags: ["SPIFFE", "SPIRE", "HSM", "Upstream CA"]
---

接續 Day82 預告：Day80 說過 SPIRE Server 用來簽所有 SVID 的那把 CA 金鑰是「皇冠寶石」——被偷就能簽出任意 SPIFFE ID、整個 trust domain 淪陷；Day82 的 federation 又證明了，你的 CA 一旦被冒充，連 partner 都會信任攻擊者簽的假身分。今天就處理那把金鑰本身怎麼保管。

**這篇是延伸篇，不是重新介紹 SPIFFE / SPIRE。** SPIFFE ID 格式、node/workload attestation 兩層、X509-SVID 與 mTLS 怎麼跑（Day80）、JWT-SVID（Day81）、federation bundle 交換（Day82）通通不重講。今天只聚焦一個前面反覆點名卻沒展開的東西：**SPIRE Server 拿來簽 SVID 的那把 CA 私鑰，怎麼讓它即使 Server 主機被攻陷也偷不走。** 延伸角度只有三條軸：**① upstream CA 模式把根金鑰移出 SPIRE、② KeyManager 走 KMS/HSM 讓簽發金鑰不落地、③ 短效中繼與不中斷的 CA rotation。**

---

## 一、先定位威脅：被偷的不是 SVID，是「簽 SVID 的能力」

Day80 的三大主軸裡，短效 SVID 讓「單一 workload 憑證外洩」的爆炸半徑縮到一小時。但那套邏輯有個前提沒被保護到：**簽發鏈的根**。

把兩件事分開想：

- **一張 SVID 外洩**：活一小時就過期，攻擊者拿到也只能冒充「那一個」workload 一小時。這是 Day80 已經解掉的問題。
- **CA 簽發金鑰外洩**：攻擊者能自己簽出**任意** SPIFFE ID 的合法 SVID——`spiffe://example.org/admin`、`spiffe://example.org/payment-service`，全部你的服務都會乖乖驗過，因為簽章鏈真的通。而且 federation 之後（Day82），partner 也把你的 CA 收進 bundle，所以攻擊者簽的假身分**連 partner 都信**。短效在這裡完全幫不上忙——被偷的不是憑證，是印章。

所以威脅模型很清楚：**SPIRE Server 主機被攻陷（RCE、容器逃逸、備份外洩、供應鏈植入）時，那把 CA 私鑰能不能跟著一起被搬走？** 預設組態下答案是「能」——它就躺在 Server 的資料目錄裡。三條軸就是把這個「能」變成「不能」。

---

## 二、第一條軸：upstream CA — SPIRE 不當根，只當中繼

預設模式（`UpstreamAuthority` 不設）叫 **self-signed**：SPIRE Server 自己生一把根金鑰、自己當 root CA、直接用它簽所有 SVID。這把根金鑰**必須線上**（每次簽發都要用），又是**根**（被偷即末日），兩個最糟的性質疊在同一把金鑰上。

**upstream CA 模式**把它拆開：SPIRE Server **不自己當根**，而是向上游 CA（企業 PKI、Vault PKI、AWS Private CA）要一張**中繼憑證（intermediate）**，用這張中繼去簽 SVID。信任鏈變成：

```text
Root CA（金鑰在 Vault / AWS PCA / HSM，離線或受硬體保護，SPIRE 碰不到）
   └── Intermediate CA（SPIRE Server 持有，短效，能被輪替/撤銷）
          └── X509-SVID（workload，幾分鐘~一小時）
```

關鍵性質轉移（承 Day15 secrets management、Day19 金鑰階層）：

- **根金鑰隔離在 SPIRE 之外**。Server 主機被攻陷，攻擊者拿到的是「中繼金鑰」，不是根。
- **中繼可被撤銷/停用**。發現 SPIRE 被攻陷，去上游 CA 撤掉那張中繼、停掉它的簽發權限，攻擊者手上的中繼立刻失效——而根安然無恙，不用重建整個 trust domain。self-signed 模式下你只能把**整個 trust domain 打掉重練**，因為被偷的就是根。
- **爆炸半徑從「整個信任體系」收到「一段可替換的中繼」**。

### SPIRE Server 設定：向 Vault PKI 要中繼

> ⚠️ 以下 HCL 的 plugin 參數名會隨 SPIRE 版本演進，實際部署請對照你那版的官方 plugin 文件，別照抄。這裡示範的是**結構與意圖**。

```hcl
server {
    trust_domain = "example.org"
    # ... 其餘 server 設定省略（非本篇重點）
}

plugins {
    UpstreamAuthority "vault" {
        plugin_data {
            vault_addr      = "https://vault.internal:8200"
            pki_mount_point = "pki_spire_intermediate"
            # SPIRE 用這條路徑向 Vault 要 intermediate 憑證來簽 SVID
            # 認證方式擇一：AppRole / Kubernetes Auth / TLS cert
            approle_auth_method {
                approle_id        = "..."
                approle_secret_id = "..."   # 走 Day15：從檔案/env 注入，別寫死
            }
            # ↓ 這個開關決定「根 CA 憑證要不要一起塞進 bundle 給 workload」
            # 通常 false：根憑證只在 SPIRE 內部驗鏈用，不外流到每個 workload
            insecure_config = false
        }
    }
}
```

重點在 **Vault 才是根金鑰的保管者**。Vault PKI 的 root 金鑰可以再往下用 Vault 自己的 seal（含 HSM auto-unseal）保護，SPIRE Server 這台機器**從頭到尾碰不到根私鑰**——它只會拿到一張短效中繼。這就是「把根移出 SPIRE」。

### 換 AWS Private CA：概念一樣，換供應商

```hcl
plugins {
    UpstreamAuthority "aws_pca" {
        plugin_data {
            region                    = "ap-northeast-1"
            certificate_authority_arn = "arn:aws:acm-pca:ap-northeast-1:...:certificate-authority/xxxx"
            # SPIRE 向這張 AWS PCA 要中繼；根金鑰在 AWS 託管的 HSM 裡，你的機器永遠碰不到
            signing_algorithm         = "SHA256WITHRSA"
            # IAM 權限走最小化（Day07）：只給 IssueCertificate，別給管理 CA 的權限
        }
    }
}
```

選 Vault 還是 AWS PCA 是維運取捨（自管 vs 託管），**安全性質是一樣的：根金鑰不在 SPIRE Server 檔案系統上**。

---

## 三、第二條軸：KeyManager 走 KMS/HSM — 連中繼金鑰也不落地

upstream CA 解決了「根」，但 SPIRE Server 手上還是握著一把**中繼私鑰**在簽 SVID。預設的 `KeyManager "disk"` 會把這把金鑰**明文寫在 Server 資料目錄**（`.../keys.json` 之類）。主機被攻陷 = 中繼金鑰一起被搬走。雖然中繼可撤銷比根被偷好得多，但「金鑰落地在檔案系統」本身就是不必要的曝險。

`KeyManager` plugin 的意義：**讓簽發用的私鑰根本不出現在 Server 的檔案系統，簽章這個動作被送進 KMS/HSM 裡做，主機被拿下也拿不到金鑰本體。**

```hcl
plugins {
    # 把簽發私鑰交給 AWS KMS 保管；SPIRE 只送「請幫我簽這串 bytes」，拿回簽章
    KeyManager "aws_kms" {
        plugin_data {
            region = "ap-northeast-1"
            # KMS key 的中介資料（哪把 key 對應哪個用途）存這個檔；私鑰本體永遠在 KMS
            key_metadata_file = "/run/spire/data/kms_key_metadata"
            # 可綁 key policy / grant 限制只有 SPIRE 這個 IAM 角色能 Sign（Day07 最小權限）
        }
    }
}
```

心智模型跟 Day32 constant-time、Day48 HMAC 簽章一脈相承：**私鑰是「能力」不是「資料」**。KMS/HSM 把它變成一個你只能「請它幹活」、卻永遠複製不走的東西。攻擊者拿下 SPIRE Server 主機後，能做的是「在你發現並撤權之前，透過這台機器叫 KMS 幫他簽」——這是一個**有時間窗、可稽核、可即時斷掉**的能力，而不是「金鑰檔到手、離線隨便簽、你永遠不知道」的災難。差別就是 Day78 講的「線上能撤 vs 離線無感」搬到 CA 金鑰這一層。

搭配起來，**upstream CA（根不在 SPIRE）＋ KeyManager KMS（中繼私鑰也不落地）** 才是完整的一句話：SPIRE Server 這台機器上，**沒有任何一把可以離線複製走的簽發金鑰**。

> Java / Go 應用端這裡完全無感——你的 `X509Source` / `DefaultX509Source`（Day80）拿到的還是同樣的 SVID，鏈驗一樣過。CA 金鑰保管是**平台層**的事，這正是 SPIFFE「把身分基礎設施從應用碼抽出去」的延續。應用工程師要做的不是改程式，是**確認平台團隊把這兩條軸開了**。

---

## 四、第三條軸：短效中繼與不中斷的 CA rotation

有了 upstream 中繼，就得面對它會**過期、要輪替**。這裡的坑跟 Day79 ACME、Day82 federation refresh 是同一款：**輪替沒做好 = 靜默的全面斷線**。

### 為什麼中繼也要短效

中繼憑證效期越短，「被偷的中繼還能用多久」就越短——這是把 Day80「SVID 短效取代撤銷」的邏輯往上推一層套到中繼身上。代價一樣是：**輪替頻率變高，輪替鏈一斷就出事。** 所以中繼效期要短，但輪替必須是自動且零停機的。

### CA rotation 為什麼能「不中斷簽發」——重疊窗口

SPIRE 換 CA 金鑰時不是「舊的關掉、新的打開」的硬切，而是**新舊 CA 同時有效一段時間**，這段重疊窗口靠 **bundle 裡同時放新舊兩把 CA 公鑰** 撐住：

```text
時間 →
舊中繼:  [====== 有效 ======][== 仍在 bundle，用來驗舊 SVID ==]
新中繼:              [新的加入 bundle]===== 開始簽新 SVID =====
                     ↑ 重疊窗口：兩把都在 bundle 裡
```

- **新 CA 先進 bundle**（透過 Day80 的 `X509Source` 自動更新推給每個 workload），此時還沒開始用它簽。
- 等所有 workload 都拿到「含新 CA 的 bundle」，SPIRE 才切換用新中繼簽發。
- 舊中繼簽的 SVID 因為舊 CA 還在 bundle 裡，**驗得過**，直到它們自然過期。
- 舊 CA 最後才從 bundle 移除。

這跟 Day79 ACME 換發要「金鑰重疊窗口」、Day82 federation 要「refresh interval 明顯短於對方金鑰重疊窗口」是**同一個道理**：任何時刻在跑的 SVID，它的簽發 CA 都還在驗證方的 bundle 裡。輪替的鐵律就一句：**新的先進場、舊的最後退場，中間留足夠讓所有人更新到的重疊窗口。**

### 這條軸最容易錯的地方

跟 Day79 / Day82 完全同款的沉默失敗：

- **upstream 連不上、中繼換發失敗**——SPIRE 可能還在用快過期的舊中繼硬撐，你卻沒收到告警，直到中繼過期、**所有簽發／驗證同時崩**。
- **監控要盯的是「中繼還有多少有效期」與「上游換發成功率」**，不是等連線全掛才發現。用剩餘效期**比例**告警，別用固定天數（短效中繼設「剩 7 天告警」永遠不會觸發）——這條 Day79 講過，這裡照搬。
- **重疊窗口設太短** = 還有 workload 沒更新到新 bundle，你就把舊 CA 移除了 → 那些 workload 手上的舊 SVID 突然驗不過。窗口要**明顯長於** bundle 傳播到最慢那個 workload 的時間。

---

## 五、Day16 角度：CA「簽了什麼」要留稽核

CA 金鑰保管好了，還有一半是**可稽核性**：萬一那個「有時間窗的簽發能力」真的被濫用（攻擊者在你撤權前透過 KMS 簽了東西），你要能事後查出「簽了哪些 SPIFFE ID、發給誰、什麼 attestation 通過」。這是 Day80 主軸③「簽發決策全程在手可稽核」落到 CA 金鑰這層的具體要求。

兩個來源要接進 Day16 的日誌管線：

1. **SPIRE Server 自身的 audit log**：每次簽發 SVID 的事件（哪個 registration entry、哪個 SPIFFE ID、什麼 selector 通過 attestation）。這是「印章蓋了什麼」的第一手紀錄。
2. **KMS/upstream CA 的稽核**（CloudTrail 的 `Sign` 呼叫、Vault 的 audit device）：「印章被叫來幹活幾次、什麼時間、誰叫的」。這一層**獨立於 SPIRE Server**——即使 Server 被攻陷、它自己的 log 被竄改，KMS 側的 `Sign` 呼叫紀錄還在，這就是把稽核責任放到攻擊者碰不到的地方（承 Day16「audit log tamper resistance」）。

應用端能做一件輔助偵測：**確認自己 SVID 的簽發鏈根有沒有無預期地變動**。CA rotation 是正常的，但「根憑證換成一張我不認得的」可能代表 upstream 被動過手腳。Go 端從 `X509Source` 拿當前 bundle、記錄根憑證指紋：

```go
// 從 Day80 的 X509Source 取當前 trust domain 的 bundle，稽核根憑證指紋
bundle, err := source.GetX509BundleForTrustDomain(td)
if err != nil {
    log.Error("cannot read trust bundle", "err", err)
    return
}
for _, ca := range bundle.X509Authorities() {
    sum := sha256.Sum256(ca.Raw)
    // 承 Day16：把指紋打進安全日誌，變動時（非預期輪替）可告警
    log.Info("trust bundle CA", "fingerprint", hex.EncodeToString(sum[:]),
        "notAfter", ca.NotAfter)
}
```

Java 端對稱地從 `X509Source` 取 bundle：

```java
// java-spiffe：從 Day80 的 X509Source 讀 bundle，記錄根憑證指紋供稽核
X509Bundle bundle = x509Source.getBundleForTrustDomain(TrustDomain.parse("example.org"));
for (X509Certificate ca : bundle.getX509Authorities()) {
    byte[] fp = MessageDigest.getInstance("SHA-256").digest(ca.getEncoded());
    // 承 Day16：指紋 + NotAfter 進安全日誌；非預期變動告警
    log.info("trust bundle CA fp={} notAfter={}",
        HexFormat.of().formatHex(fp), ca.getNotAfter());
}
```

這不是替代平台稽核，是**縱深**：workload 這端獨立確認「我信的根有沒有被換」，跟 SPIRE Server audit、KMS CloudTrail 三方對得起來。

---

## 六、常見誤區表

- **「用了 SPIFFE 短效 SVID，CA 金鑰不用特別保護」**——反了。SVID 短效正是把爆炸半徑集中壓到 CA 那一把上，它被偷 = 能簽任意身分，短效完全救不了。
- **「self-signed 模式先跑起來再說」**——self-signed 的根金鑰又線上又是根，還躺在檔案系統。demo 可以，正式環境等於把皇冠寶石放桌上。
- **「upstream CA 設了就安全」**——upstream 只把「根」移走，中繼私鑰若還用 `KeyManager "disk"` 明文落地，主機被攻陷一樣被搬走中繼。要搭 KMS。
- **「KeyManager 走 KMS，金鑰就 100% 拿不走」**——拿不走**金鑰本體**，但主機被攻陷時攻擊者能在你撤權前**透過這台機器叫 KMS 簽**。所以還要 KMS 側稽核 + 能即時撤 IAM/grant，別以為 HSM 是免死金牌。
- **「中繼憑證設長一點免得一直換」**——中繼越長，被偷後可用越久。要短效 + 自動輪替，別用效期換省事（Day79 同款錯誤）。
- **「CA rotation 硬切就好」**——舊 CA 一移除，還沒更新到新 bundle 的 workload 手上舊 SVID 全部驗不過。必須新舊重疊窗口。
- **「換發失敗會報錯我會看到」**——upstream 換中繼失敗常是**靜默**的，SPIRE 用舊的硬撐到過期才全崩。要主動監控中繼剩餘效期比例與換發成功率（Day79/82 同款）。
- **「SPIRE Server 的 log 有記就夠稽核」**——Server 被攻陷後它自己的 log 可被竄改。KMS/upstream 的 `Sign` 稽核獨立於 Server，那才是動不了的一份（Day16 tamper resistance）。

---

## 七、Code Review / 維運 checklist

**信任根架構（本篇核心）**

- [ ] 正式環境**沒有**用 self-signed（`UpstreamAuthority` 有設）；根金鑰在 Vault / AWS PCA / 企業 PKI，SPIRE Server 檔案系統上**碰不到根私鑰**。
- [ ] 中繼簽發私鑰用 `KeyManager` 走 KMS/HSM，**不是** `disk` 明文落地；正式環境 grep 不到 `KeyManager "disk"`（或已確認其資料目錄有等級對應的加密與存取控制）。
- [ ] 上游 CA / KMS 的存取權限最小化（Day07）：SPIRE 的 IAM 角色只有「要中繼 / 簽章」的權限，沒有管理 CA、刪 key 的權限。

**金鑰生命週期與 rotation（承 Day79）**

- [ ] 中繼憑證短效 + 自動輪替；效期明顯短於「發現攻陷到撤權」的容忍上限。
- [ ] CA rotation 走新舊重疊窗口：新 CA 先進 bundle → 切換簽發 → 舊 CA 最後移除；重疊窗口長於 bundle 傳播到最慢 workload 的時間。
- [ ] 有監控**中繼剩餘有效期比例**與**上游換發成功率**；連續換發失敗即使此刻還能簽也告警（Day79/82 同款沉默失敗）。

**稽核與偵測（承 Day16）**

- [ ] SPIRE Server audit log（簽了哪些 SPIFFE ID / 通過哪些 selector）進集中式、防竄改的日誌管線。
- [ ] KMS `Sign` / Vault PKI 簽發的稽核（CloudTrail / audit device）獨立於 SPIRE Server 收集——Server 被攻陷也動不了這份。
- [ ] （選配縱深）workload 端記錄 trust bundle 根憑證指紋，非預期變動告警。

**範圍認知（承 Day80）**

- [ ] 清楚這是**內部 trust domain** 的信任根；對外服務仍走公開 CA + CT + CAA（Day77/79），別拿 SPIRE 內部 CA 去頂公網。

---

## 八、測試 / 演練建議

- **中繼輪替不中斷演練（最重要）**：把中繼效期設極短（例如幾分鐘），持續打跨服務 mTLS，斷言**輪替發生時連線全程不斷**、且 workload 手上 SVID 的簽發序號/鏈有換新。測不過代表你的 rotation 是硬切、正式輪替時會集體握手失敗——這是 CA 版的 Day80「SVID 自動輪替測試」。
- **upstream 斷線告警演練**：把到 Vault / AWS PCA 的連線切斷，讓中繼逼近過期，斷言**監控在中繼過期、簽發全崩之前就告警**（剩餘效期比例超標），而不是等全面斷線才發現。直接驗第三條軸的告警有沒有效（承 Day79/82）。
- **金鑰不落地驗證**：在 SPIRE Server 主機上 grep 資料目錄，斷言**找不到**中繼/根的明文私鑰檔（走 KMS 時私鑰本體不該出現在檔案系統）。這是「KeyManager 真的走 KMS」的存在證明。
- **撤權即時性演練**：模擬 SPIRE Server 被攻陷，執行你的應變手冊——撤掉那張中繼 / 收回 KMS 的 `Sign` grant，斷言**攻擊者透過該機器再也簽不出新 SVID**，且根 CA 與其他 trust domain 不受影響。驗「中繼可撤、根安全」這個 upstream 模式的核心賣點。
- **稽核完整性測試**：發一批 SVID 後，斷言 SPIRE audit log 與 KMS `Sign` 稽核**都**記到、且能對上「簽了哪些 SPIFFE ID」。再模擬「Server 端 log 被清空」，斷言 KMS 側稽核**仍在**——tamper resistance 的存在證明（承 Day16）。
- **重疊窗口過短迴歸測試**：故意把 rotation 重疊窗口設到短於 bundle 傳播時間，斷言會出現「舊 SVID 驗不過」，用這條測試把「窗口必須夠長」寫成看得見的迴歸案例。

---

## 九、一句話總結

> Day80 已經用短效 SVID 把「單一 workload 憑證外洩」的爆炸半徑壓到一小時，但那套邏輯有個沒被保護的前提——**簽 SVID 的那把 CA 金鑰**：它被偷不是漏一個身分，是能簽出**任意** SPIFFE ID 的合法 SVID，你所有服務乃至 Day82 的 partner 全都會信，短效在這層完全無效因為被偷的是印章不是憑證。今天的解法是三條軸疊起來：**① upstream CA**——SPIRE 不自己當根，向 Vault PKI / AWS PCA 要一張**短效中繼**來簽，根金鑰隔離在 SPIRE 之外，主機被攻陷攻擊者拿到的是「可撤銷的中繼」而非「不可撤的根」（承 Day15/19，發現攻陷去上游撤中繼即可，不用打掉整個 trust domain 重來）；**② KeyManager 走 KMS/HSM**——連中繼私鑰都不落地在 Server 檔案系統，簽章動作送進 KMS 做，主機被拿下也複製不走金鑰本體，攻擊者能做的只是「在你撤權前透過這台機器叫 KMS 簽」＝一個有時間窗、可稽核、可即時斷掉的能力，而非離線隨便簽的災難（Day78「線上能撤 vs 離線無感」搬到 CA 層）；**③ 短效中繼 + 不中斷 rotation**——中繼也短效化把可用窗口壓短，換 CA 時走**新舊重疊窗口**（新 CA 先進 bundle 靠 Day80 的 X509Source 自動推給每個 workload、切換簽發、舊 CA 最後移除），任何時刻在跑的 SVID 其簽發 CA 都還在 bundle 裡＝零停機（跟 Day79 換發、Day82 federation refresh 同一個「新的先進場舊的最後退場」道理），最容易錯的是 upstream 換發**靜默失敗**用舊中繼硬撐到過期才全崩，解法照搬 Day79——盯剩餘效期**比例**與換發成功率別等全斷。**程式面 workload 完全無感**（`X509Source` / `DefaultX509Source` 拿到的 SVID 一樣、鏈驗一樣過），CA 金鑰保管是純平台層的事，應用工程師的責任不是改碼是確認平台把 upstream + KMS 開了、並把 SPIRE audit 與**獨立於 Server 的 KMS `Sign` 稽核**（Server 被攻陷也動不了那份，Day16 tamper resistance）都接進日誌。一句話：**federation 讓別人信任你的 CA，所以你的 CA 金鑰保管等級，決定的不只是你自己、而是所有信任你的 trust domain 的安全上限——把根移出 SPIRE、把簽發金鑰關進 HSM、把輪替做成零停機且被監控。**

---

## 延伸閱讀

- Day80 SPIFFE / SPIRE workload identity——本篇上游：SVID 短效、CA key 是「皇冠寶石」的原始論斷就在這。
- Day82 SPIFFE Federation——你的 CA 被信任的範圍在這擴大到 partner，CA 保管等級因此決定別人的安全上限。
- Day79 ACME 自動換發——中繼輪替的「重疊窗口 + 沉默失敗 + 剩餘效期比例告警」全是這篇的思路上移一層。
- Day78 憑證撤銷 / OCSP soft-fail——「線上能撤 vs 離線無感」正是 KMS 簽發能力 vs 金鑰檔外洩的差別。
- Day15 Secrets Management——KMS/Vault 保管私鑰、最小權限注入 approle secret，都在這條線上。
- Day19 TLS / 加密失誤——金鑰階層（root → intermediate → leaf）與線上/離線金鑰的取捨。
- Day16 Security Logging / Monitoring——SPIRE audit 與獨立 KMS 稽核、tamper resistance、根指紋變動告警。
- Day07 Broken Access Control——SPIRE 對上游 CA / KMS 的權限最小化（只給簽發、不給管理）。
- Day32 / Day48 constant-time / HMAC——「私鑰是能力不是資料」的同源心智模型。

---

明天預告：**Day 84 — SPIRE workload attestation 的 selector 是怎麼被繞過的：K8s / Docker / 裸機各平台的冒領風險（延伸篇）**
（這篇是**延伸篇**，不重講 Day80 attestation 兩層的**基本概念**、也不重講今天的 CA 金鑰保管，聚焦 Day80 只點名沒展開的一個東西：**workload attestation 到底怎麼認出「來要 SVID 的這個程序是誰」——以及那些 selector 各自能被怎麼騙。** Day80 說 Agent 反過來觀察呼叫方的核心層屬性（PID → UID/GID、K8s pod/SA、binary 路徑、SELinux label）比對 registration entry 才發 SVID，聽起來很硬；但每一種 selector 都有它自己的**冒領邊界**：**① K8s selector**——用 pod 的 namespace/service account 當身分，但 selector 若只綁到 namespace 而非確切 SA，同 namespace 的惡意 pod 就能冒領（承 Day07 最小權限、Day49 BFLA 的「範圍開太寬」）；**② Unix selector（PID/UID/binary path）**——PID 重用、容器內 UID 與宿主不對應、binary path 可被同名檔或 bind mount 混淆的邊界；**③ Docker selector**——用 container label 當身分時，誰能設 label、compose 檔被改就能改身分的風險；**④ 為什麼 selector 要疊加**——單一 selector 幾乎都能繞，要多個 selector 組合（K8s SA + binary sha256 + …）才收得緊，這正是 Day80「同機惡意程序冒領」防線的實作細節。程式面會示範 registration entry 的 selector 寫法從「只綁 namespace」收窄到「SA + 具體工作負載特徵」、以及怎麼用 sha256 綁 binary、Docker label selector 的信任邊界，並用 Day16 的角度談「attestation 通過了什麼 selector」怎麼稽核。安全主軸一句話：**attestation 不是「有做就安全」，是「你綁的那組 selector 有多難被同機的另一個程序湊出來」——selector 開太寬，Day80 那道最精妙的防線就退化成擺設。** 這是延伸篇，只聚焦 selector 的冒領邊界與收窄，不重述 attestation 兩層的基本流程。）
