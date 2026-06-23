---
title: "Day 61：SSTI 延伸篇 — 模板引擎的危險用法、Sandbox 繞過與 Code Review 重點"
date: 2026-06-24
tags: ["SSTI", "Thymeleaf", "FreeMarker", "Go Template", "Code Review"]
---

接續 Day60 預告：今天談 **Server-Side Template Injection（SSTI）**。先更正一件事：Day60 的預告把今天標成「全新主題」，但 **SSTI 在 Day21 已經以入門角度完整介紹過**（原理、與 XSS 的差異、危險寫法、基本防禦、使用者可編輯模板）。所以今天**不是**重新介紹 SSTI，而是一篇**延伸篇**。

這篇的延伸角度很明確：**不講 SSTI 的定義、不重畫「使用者輸入 → 被當模板 render → RCE」的基本流程、也不重列基本防禦清單**。我們只聚焦三件 Day21 沒展開的事——

1. **各模板引擎的「危險 API vs 安全 API」實作細節**：Thymeleaf、FreeMarker、Velocity（Java）與 Go 的 `text/template` vs `html/template`。
2. **Sandbox / 受限模式為什麼會被繞過**：很多人以為「我開了 sandbox 就安全」，這篇講它為什麼不是萬靈丹。
3. **Code Review 與偵測重點**：怎麼在 PR 裡一眼看出「資料被當成模板」的反模式。

核心原則一句話先講：**資料歸資料、模板歸模板（template 是程式碼，不是使用者輸入）。** 下面都是這句話的展開。

---

## 一、先定位：SSTI 的危險，幾乎都來自「模板來源可被使用者控制」

Day21 講過本質，這裡只補一個延伸觀察：SSTI 漏洞在實務上幾乎只有兩種長相，而且第二種才是真正致命的。

- **第一種（render 階段把使用者輸入當資料）**：使用者輸入只是「填進固定模板的變數」。這在大多數引擎裡是安全的，頂多退化成 XSS（已是 Day02 範疇）。
- **第二種（compile 階段把使用者輸入當模板字串）**：使用者輸入變成「模板本身的一部分」被編譯。這才是 SSTI，能力等級直接從 XSS 跳到 RCE。

所以 Code Review 的第一個動作不是看「有沒有逸出」，而是看 **「模板字串（template source）是不是常數 / 來自受信任檔案」**。只要模板來源是使用者可控的拼接字串，後面再多逸出都救不回來。下面每個引擎的「危險 vs 安全」對照，本質都在區分這條界線。

---

## 二、Java 三大引擎的危險 API vs 安全 API

### 2.1 Thymeleaf：危險在「動態 fragment / expression 當作 view name」

Thymeleaf 最經典的 SSTI 不是來自 `${...}` 變數渲染（那是設計好的安全資料綁定），而是來自 **使用者輸入流進 view name 或 fragment 表達式**，被 Spring 當成可解析的運算式。

```java
// ❌ 危險：使用者可控字串變成 view name / fragment 運算式
@GetMapping("/page")
public String page(@RequestParam String name) {
    // 回傳值被當成 view name，Thymeleaf 會嘗試解析 name 內的表達式
    return "user/" + name;   // name = "__${T(java.lang.Runtime).getRuntime().exec(...)}__::x"
}
```

這類 payload 之所以能 RCE，是因為 Thymeleaf 的 **Standard Expression（SpringEL）** 具備呼叫任意 Java 型別與方法的能力（`T(...)` 取得型別、`new`、method invocation）。當「要解析的字串」本身被使用者污染，等於把 SpringEL 直譯器交給攻擊者。

```java
// ✅ 安全：view name 用 allowlist，使用者輸入只當「資料」傳給固定模板
private static final Set<String> ALLOWED = Set.of("profile", "settings", "billing");

@GetMapping("/page")
public String page(@RequestParam String name, Model model) {
    if (!ALLOWED.contains(name)) {
        throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
    model.addAttribute("name", name); // 進到固定模板的 ${name}，純資料
    return "user/page";               // view name 是常數
}
```

延伸重點：**Thymeleaf 安全與否的關鍵不在模板語法，而在「誰決定要解析哪個字串」。** view name、`th:insert` / `th:replace` 的 fragment 表達式、以及 `~{...}` fragment expression，只要其值可被使用者拼接，就是 SSTI 入口。`${name}` 這種把變數填進固定位置的用法本身是安全的。

### 2.2 FreeMarker：危險在「把使用者字串編譯成 Template」+ 內建危險指令

FreeMarker 的 SSTI 有兩條路，Code Review 要分開看：

```java
// ❌ 危險路 1：使用者輸入直接被 new Template 編譯
String src = request.getParameter("tpl");          // 使用者控制
Template t = new Template("inline", new StringReader(src), cfg);
t.process(dataModel, out);                          // src 內的指令會被執行
```

第二條路更隱蔽：**即使模板檔本身是你寫的，FreeMarker 預設仍允許 `?new`、`api`、`?eval` 這類能觸及任意 Java 物件的內建（built-in）**。經典 payload 透過 `freemarker.template.utility.Execute`：

```text
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

防禦的延伸細節（Day21 沒講的設定面）：

```java
Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);

// 1) 模板來源只從受信任目錄載入，不接受使用者字串
cfg.setTemplateLoader(new FileTemplateLoader(new File("/srv/templates")));

// 2) 關閉 / 限制危險的物件包裝能力（不暴露任意 Java 物件 API）
DefaultObjectWrapperBuilder owb = new DefaultObjectWrapperBuilder(Configuration.VERSION_2_3_32);
owb.setExposeFields(false);
owb.setMethodAppearanceFineTuner(/* 限制可見方法 */ null);
cfg.setObjectWrapper(owb.build());

// 3) 用 TemplateClassResolver 阻擋 ?new 取得危險類別
cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);

// 4) 關閉會執行字串的 API 介面
cfg.setAPIBuiltinEnabled(false);
```

`TemplateClassResolver.ALLOWS_NOTHING_RESOLVER` 是這裡最關鍵的一把鎖：它讓 `"...Execute"?new()` 這種透過 `?new` 取得任意類別的手法直接失敗。**注意這是「縱深」而非「根治」**——根治仍是不要讓使用者字串變成模板來源。

### 2.3 Velocity：危險在 `Velocity.evaluate` 與 `#set` 觸及 class loader

Velocity 的反模式同樣是 **把使用者字串丟進 `evaluate`**：

```java
// ❌ 危險：使用者輸入被當 VTL 模板求值
StringWriter w = new StringWriter();
Velocity.evaluate(context, w, "tag", userControlledString);
```

經典 payload 透過 `$class.inspect(...).type.forName(...)` 一路爬到 `Runtime`。Velocity 沒有像 FreeMarker 那樣現成的全域 class resolver 開關，因此防禦更要回到本質：

```java
// ✅ 安全：模板從受信任資源載入，使用者輸入只進 context 當資料
Template t = Velocity.getTemplate("emails/welcome.vm"); // 常數路徑
VelocityContext ctx = new VelocityContext();
ctx.put("username", userControlledString);              // 純資料
t.merge(ctx, writer);
```

三個引擎的共同結論：**`evaluate` / `new Template(StringReader)` / 動態 view name 這類「接受字串當模板」的 API，是 SSTI 的高危點；對應的安全做法都是「模板路徑常數化 + 使用者輸入只進 context 當資料」。**

---

## 三、Go：`text/template` vs `html/template` 的關鍵差異（以及兩者都救不了的事）

這是 Go 後端最容易誤解的一點，Day21 完全沒展開。

### 3.1 兩者差在「自動 contextual escaping」，不是差在「防 SSTI」

```go
// html/template：會根據輸出脈絡（HTML body / attribute / JS / URL）自動逸出
t := template.Must(template.New("p").Parse(`<p>{{.Name}}</p>`))
t.Execute(w, map[string]string{"Name": userInput}) // userInput 被自動逸出，防的是 XSS

// text/template：不做任何 HTML 逸出
tt := texttemplate.Must(texttemplate.New("p").Parse(`<p>{{.Name}}</p>`))
tt.Execute(w, map[string]string{"Name": userInput}) // 直接輸出，等於 XSS 破口
```

**關鍵釐清**：`html/template` 解決的是 **XSS（輸出逸出）**，不是 SSTI。把「在 HTML 輸出用 `html/template`」當成「我防了 SSTI」是常見誤區。兩者是不同 Day 的不同問題。

### 3.2 真正的 Go SSTI：把使用者輸入當成 `Parse` 的參數

```go
// ❌ 危險：使用者輸入變成模板字串本身
func render(w http.ResponseWriter, userTpl string, data any) {
    t := template.Must(template.New("x").Parse(userTpl)) // userTpl 可控 = SSTI
    t.Execute(w, data)
}
```

Go 模板的好消息是：**它沒有「呼叫任意方法 / 取得任意型別」的內建語法**，能呼叫的只有 (a) 你註冊進 `FuncMap` 的函式、(b) data 物件上「已匯出的方法」。所以 Go 的 SSTI 不像 Java 那樣容易直接 RCE。但它仍有兩個真實風險：

1. **資訊洩漏**：`{{.}}` 或 `{{.SomeField}}` 可以把你傳進去的整個 data struct（可能含密鑰、內部欄位）印出來。攻擊者用使用者可控模板探測 data model。
2. **方法副作用 / 危險 FuncMap**：如果 data 物件上有匯出方法會做危險操作，或你在 `FuncMap` 註冊了像「執行系統指令」「讀檔」的 helper，使用者模板就能呼叫它們。

```go
// ❌ 危險的 FuncMap：把能力交給模板
funcs := template.FuncMap{
    "exec": func(cmd string) string { out, _ := exec.Command("sh", "-c", cmd).Output(); return string(out) },
}
```

### 3.3 Go 的安全做法

```go
// ✅ 模板來源常數化，使用者輸入只進 data
const tpl = `<p>Hello, {{.Name}}</p>`
var t = template.Must(template.New("p").Parse(tpl))

func handler(w http.ResponseWriter, r *http.Request) {
    t.Execute(w, struct{ Name string }{Name: r.FormValue("name")}) // name 是資料
}
```

延伸原則：**Go 後端若真有「使用者自訂模板」需求（如通知模板、報表模板），不要直接 `Parse` 使用者字串。** 改用「受限的佔位符語法」（例如只允許 `{{name}}` 這種白名單變數替換，自己做字串替換而非交給 template 引擎），或在隔離程序 / 沙箱中執行並嚴格控制 `FuncMap` 與 data 暴露面。

---

## 四、為什麼「開了 Sandbox」不等於安全：繞過的本質

很多團隊的防禦是「我用了引擎的 sandbox / 受限模式」。這篇要戳破這個安全感。

Sandbox 繞過（sandbox escape）反覆出現的根因有三類：

1. **可達物件圖（reachable object graph）太大**：sandbox 通常用黑名單擋掉某些類別，但只要 context 裡放進的任一物件，能透過 getter / 反射 / class loader 一路「爬」到 `Runtime`、`ProcessBuilder`、`ClassLoader`，黑名單就會被繞。歷史上 FreeMarker、Velocity、Pebble、Groovy 的 sandbox bypass 多半是這種「找到一條沒被黑名單覆蓋的鏈」。
2. **黑名單 vs 白名單**：sandbox 預設常是黑名單心智模型，而黑名單對抗反射 / 字串拼接型別名（`"java.lang."+"Runtime"`）天生脆弱。
3. **版本與設定漂移**：sandbox 的有效性高度依賴引擎版本與正確設定，升級或設定回退就破功（呼應 Day60「版本與設定決定一切」）。

延伸結論：**Sandbox 是縱深防禦的一層，不是邊界。** 真正的邊界是「模板來源不可被使用者控制」。如果你的設計必須讓使用者提供模板，正確順序是：(1) 換成能力極小的模板語言（純變數替換、無方法呼叫）、(2) 嚴格收斂 context 暴露面（只放 render 真正需要的純資料，不放任何能爬到 class loader 的物件）、(3) 在隔離環境執行（獨立程序、最小權限、timeout、egress 控制——後者接 Day53）、(4) 才把引擎 sandbox 當最後一層保險。

---

## 五、Code Review / 偵測 Checklist（本篇重點產出）

把上面所有原則收斂成可在 PR 與 grep 階段執行的檢查：

**A. 找出「使用者輸入變成模板來源」的反模式（最高優先）**

- [ ] 搜尋 Java：`new Template(`、`Velocity.evaluate(`、`?eval`、`?new`、回傳值是字串拼接的 `@GetMapping` controller 方法（可能成為動態 view name）。
- [ ] 搜尋 Go：`template.New(...).Parse(` 的參數是否為變數而非常數；是否有 `text/template` 用在 HTML 輸出。
- [ ] 任一命中點，確認模板字串來源：**常數 / 受信任檔案 = OK；使用者可控拼接 = 立即標記為 SSTI 風險。**

**B. 引擎設定面（縱深）**

- [ ] FreeMarker：是否設 `setNewBuiltinClassResolver(ALLOWS_NOTHING_RESOLVER)`、`setAPIBuiltinEnabled(false)`、ObjectWrapper 是否關閉 `exposeFields` 並限制方法可見性？
- [ ] Thymeleaf：view name / fragment 表達式是否來自 allowlist，而非使用者拼接？
- [ ] Velocity：模板是否一律走 `getTemplate(常數路徑)`，禁止 `evaluate` 使用者字串？
- [ ] Go：`FuncMap` 是否混入了會執行指令 / 讀檔 / 網路請求的 helper？data struct 是否含不該被 `{{.}}` 印出的密鑰欄位？

**C. context / data 暴露面**

- [ ] 傳進模板 context 的物件，是否可能被一路反射爬到 `Runtime` / `ClassLoader` / `ProcessBuilder`？只放純資料 DTO。
- [ ] 是否避免把整個 domain entity（含關聯、含敏感欄位）直接塞進 model？

**D. 隔離與測試**

- [ ] 「使用者自訂模板」功能是否在隔離程序 / 最小權限 / timeout / egress 控制下執行？
- [ ] 是否有針對已知 payload 的回歸測試（`T(java.lang.Runtime)`、`?new("...Execute")`、`$class.inspect`、Go `{{.}}` 資訊洩漏）？

```java
// JUnit：FreeMarker 應拒絕 ?new 取得任意類別
@Test
void freemarkerBlocksClassResolution() {
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
    cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
    String malicious = "<#assign x=\"freemarker.template.utility.Execute\"?new()>${x(\"id\")}";
    assertThrows(Exception.class, () -> {
        Template t = new Template("t", new StringReader(malicious), cfg);
        t.process(new HashMap<>(), new StringWriter());
    });
}
```

```go
// Go：確認 HTML 輸出沒有誤用 text/template（會漏 XSS），
// 並確認沒有把使用者字串拿去 Parse
func TestNoUserControlledParse(t *testing.T) {
    // 設計層級的測試：render 函式只接受 data，不接受 template source
    var tpl = template.Must(template.New("p").Parse(`<p>{{.Name}}</p>`))
    var b strings.Builder
    if err := tpl.Execute(&b, struct{ Name string }{Name: `<script>alert(1)</script>`}); err != nil {
        t.Fatal(err)
    }
    if strings.Contains(b.String(), "<script>") {
        t.Fatal("html/template should have escaped output")
    }
}
```

---

## 六、一句話總結

> SSTI 的危險不在「模板語法」，而在 **「誰決定要編譯哪段字串」**。Day21 講了它是什麼；今天的延伸結論是：**Thymeleaf / FreeMarker / Velocity 的高危 API（動態 view name、`new Template(StringReader)`、`evaluate`）與 Go 的 `Parse(使用者字串)`，本質都是「把使用者輸入當模板來源」。** `html/template` 防的是 XSS、不是 SSTI；引擎 sandbox 是縱深、不是邊界，會被「可達物件圖 + 黑名單」這條老路繞過。真正的根治只有一句話——**資料歸資料、模板歸模板**：模板來源常數化或來自受信任檔案，使用者輸入永遠只當 context 裡的純資料。

---

## 延伸閱讀

- Day21 SSTI（入門：原理、與 XSS 差異、危險寫法、基本防禦、使用者可編輯模板）——本篇的基礎。
- Day02 XSS（`html/template` 真正解決的問題，與 SSTI 區分）。
- Day53 SSRF（使用者自訂模板在隔離環境執行時的 egress 控制）。
- Day14 / Day52 Insecure Deserialization（gadget chain 思維與 SSTI sandbox 繞過「爬物件圖到 Runtime」的共通心智模型）。
- Apache FreeMarker — `Configuration.setNewBuiltinClassResolver`、`TemplateClassResolver`、`setAPIBuiltinEnabled`、ObjectWrapper 設定。
- Go 官方文件 — `text/template` 與 `html/template`（contextual auto-escaping）的差異說明。

---

明天預告：**Day 62 — Mass Assignment / Auto-Binding 延伸篇：巢狀物件綁定與框架特有規則（延伸，承 Day08 / Day55）**
（這是延伸篇，不是重新介紹 Mass Assignment 本質。延伸角度聚焦在 **巢狀／集合屬性的自動綁定**——Spring 的 nested path binding（`user.role.name`）如何被利用、`@InitBinder` 的 `setAllowedFields` / `setDisallowedFields` 在巢狀路徑下的陷阱，以及 Go 在 `json.Unmarshal` 巢狀 struct 與 `map[string]any` 合併時的越權寫入面。會給出「巢狀路徑也要 allowlist」與 OpenAPI schema 對照測試的 code review 重點。）
