---
title: "Day 21：Server-Side Template Injection（SSTI，伺服器端模板注入）"
date: 2026-05-17
tags: ["Injection", "SSTI", "模板引擎"]
---

# Day 21：Server-Side Template Injection（SSTI，伺服器端模板注入）

> **適合對象**：後端工程師初學者
> **語言範例**：Java（1.8 / 21）、Go
> **OWASP 對應**：A03:2021 - Injection
> **CWE 編號**：CWE-1336（Improper Neutralization of Special Elements Used in a Template Engine）、CWE-94（Code Injection）

---

## 一、開場故事：一封「個人化」的問候信

阿傑在公司負責電子報系統。為了讓使用者覺得親切，他做了一個小功能：使用者可以在「個人簡介」欄位填一段話，系統會自動把它套用到歡迎信的模板裡：

```
親愛的 {{ user.bio }}，歡迎加入！
```

某位「使用者」把自己的簡介改成這串文字：

```
${T(java.lang.Runtime).getRuntime().exec("rm -rf /tmp/data")}
```

阿傑的後端用 Thymeleaf 渲染信件內容，把「使用者簡介」當成 **模板片段** 解析。下一秒，系統的 `/tmp/data` 整個被刪掉。

更糟的是，這段語法不只能執行 `rm`——它能讀任何環境變數、列出檔案、連回攻擊者的伺服器拉 webshell。

> **教訓**：當使用者輸入「進入了模板引擎的語法層」，攻擊者拿到的就不是 XSS，而是 **直接在伺服器上執行程式碼（RCE）**。

---

## 二、什麼是 SSTI？

**Server-Side Template Injection（伺服器端模板注入）** 指的是：

> 後端把 **使用者可控的字串** 當成模板（template）來解析，導致攻擊者可以注入模板語法，在伺服器端執行任意運算式甚至作業系統命令。

模板引擎（Template Engine）的設計初衷，是讓開發者把資料填進預先寫好的模板：

```
模板：Hello {{ name }}
資料：{ name: "Alice" }
結果：Hello Alice
```

但如果模板本身的內容**也來自使用者**，攻擊者就能寫出可怕的東西：

```
使用者輸入（被當成模板）：Hello {{ 7 * 7 }}
渲染結果：Hello 49     ← 這就是模板引擎被「執行」的證據
```

只要能讓 `{{ 7 * 7 }}` 變成 `49`，就有 SSTI。下一步就是想辦法跳到「執行系統命令」。

---

## 三、SSTI 跟 XSS 差在哪？

很多人會把它跟 XSS 搞混，但兩者層級完全不同：

| | XSS | SSTI |
|---|---|---|
| 執行位置 | 使用者瀏覽器 | **伺服器** |
| 能做什麼 | 偷 cookie、改畫面 | **執行系統命令、讀檔、開後門** |
| 修法 | 輸出時 HTML escape | 不要把使用者輸入當模板 |
| 嚴重程度 | 中～高 | **極高（RCE）** |

XSS 是 client-side code execution，SSTI 是 **server-side** code execution——這是兩件完全不同的事。

---

## 四、危險的後端寫法

### 危險範例 1：Java（Thymeleaf）—— 把使用者輸入當模板字串

```java
// ❌ 危險寫法：用 Thymeleaf 的 StringTemplateResolver 直接解析使用者輸入
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templateresolver.StringTemplateResolver;

@RestController
public class GreetingController {

    private final TemplateEngine engine;

    public GreetingController() {
        this.engine = new TemplateEngine();
        this.engine.setTemplateResolver(new StringTemplateResolver()); // 從字串解析模板！
    }

    @GetMapping("/greet")
    public String greet(@RequestParam("bio") String bio) {
        // bio 是使用者輸入，卻當成模板片段渲染
        Context ctx = new Context();
        return engine.process("Hello " + bio, ctx);
    }
}
```

攻擊者送出：

```
/greet?bio=__${T(java.lang.Runtime).getRuntime().exec("touch /tmp/pwned")}__::.x
```

Thymeleaf 在 expression 上下文中會解析 `${...}` 內容，呼叫 `Runtime.exec`。

### 危險範例 2：Java（Freemarker）—— 動態模板來源

```java
// ❌ 危險：使用者控制的字串被當 Freemarker 模板解析
import freemarker.template.Configuration;
import freemarker.template.Template;

public String render(String userTemplate, Map<String, Object> data) throws Exception {
    Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);
    // userTemplate 是使用者輸入
    Template tpl = new Template("inline", new StringReader(userTemplate), cfg);
    StringWriter out = new StringWriter();
    tpl.process(data, out);
    return out.toString();
}
```

攻擊 payload（Freemarker 經典）：

```
<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}
```

Freemarker 預設可以呼叫 `Execute` 工具類，直接執行系統指令。

### 危險範例 3：Go（text/template）—— 看起來無害的字串拼接

```go
// ❌ 危險：把使用者輸入直接當成模板字串
package main

import (
    "net/http"
    "text/template"
)

func handler(w http.ResponseWriter, r *http.Request) {
    bio := r.URL.Query().Get("bio")
    tpl := "Hello " + bio  // 致命的字串拼接
    t, err := template.New("greet").Parse(tpl)
    if err != nil {
        http.Error(w, "bad template", 400)
        return
    }
    t.Execute(w, map[string]any{"User": "Alice"})
}
```

Go 的 `text/template`（注意是 **text** 不是 html）雖然 **不能直接執行系統命令**（沒有暴露 `os.Exec` 之類的函式給模板使用），但攻擊者仍可以：

- 讀取程式傳進 context 的任何欄位：`{{ .DBPassword }}`、`{{ .APIKey }}`
- 列出所有可呼叫的 method：`{{ .User.Token }}`
- 引發 panic 干擾服務

**Go 的優勢**：模板沙箱比 Java 嚴格，但**依然會洩漏 context 內的所有敏感資料**。

---

## 五、為什麼會不小心寫出 SSTI？

90% 的 SSTI 都來自這幾種「自以為方便」的設計：

1. **管理後台允許自訂 Email/通知模板**：客戶能編輯模板原始碼。
2. **多語系 i18n 字串中夾帶變數**：翻譯字串支援 `{{ var }}` 但開發者把使用者名稱直接插進翻譯字串。
3. **錯誤訊息把使用者輸入回顯到模板**：`render("error.html", "找不到: " + userInput)`。
4. **「動態渲染預覽」功能**：所見即所得編輯器，後端拿前端字串去渲染預覽。
5. **CMS / 低代碼平台**：本來就是讓使用者寫模板，但忘了沙箱化。

只要看到 **「字串先拼接、再交給模板引擎」**，就要警覺。

---

## 六、正確的防禦寫法

### 防禦原則（由嚴格到寬鬆）

1. **最佳**：**模板永遠來自檔案系統**，使用者輸入只能透過 **變數** 傳入，**絕對不要把使用者輸入拼進模板字串**。
2. **次佳**：如果業務真的需要使用者寫模板（如自訂通知），用 **沙箱化的模板引擎**（如 Java 的 `Pebble` + `SandboxExtension`、或自行限制 expression）。
3. **退而求其次**：使用者輸入只允許出現在 **資料變數**，並進行嚴格的字元白名單檢查。

### 正確範例 1：Java（Thymeleaf）—— 變數而非模板

```java
// ✅ 正確：模板從 resources/templates/ 載入，使用者輸入只當變數
@Controller
public class GreetingController {

    @GetMapping("/greet")
    public String greet(@RequestParam("bio") String bio, Model model) {
        // bio 只是個變數，Thymeleaf 會 HTML escape，不會被當作 expression 執行
        model.addAttribute("bio", bio);
        return "greet"; // 對應 templates/greet.html
    }
}
```

`templates/greet.html`：

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body>
  <p>Hello <span th:text="${bio}">placeholder</span></p>
</body>
</html>
```

> **重點**：`th:text="${bio}"` 是把 `bio` 的內容當作 **文字輸出**，會自動做 HTML escape，不會解析其中的 expression。

### 正確範例 2：Java —— 強制不要用 `StringTemplateResolver`

如果你必須動態組裝模板，至少要把使用者輸入隔離成參數：

```java
// ✅ 模板字串由開發者控制，使用者輸入只當變數
String templateBody = "Hello [(${name})], 您的訂單編號是 [(${orderId})]";

Context ctx = new Context();
ctx.setVariable("name", userInput);      // 使用者輸入
ctx.setVariable("orderId", order.getId());

TemplateEngine engine = new TemplateEngine();
StringTemplateResolver resolver = new StringTemplateResolver();
resolver.setTemplateMode(TemplateMode.TEXT); // TEXT 模式，禁用 HTML expression
engine.setTemplateResolver(resolver);

String result = engine.process(templateBody, ctx);
```

關鍵：**模板字串本身不能拼接使用者輸入**。

### 正確範例 3：Java（Freemarker）—— 關掉危險功能

```java
import freemarker.template.Configuration;
import freemarker.template.TemplateClassResolver;

Configuration cfg = new Configuration(Configuration.VERSION_2_3_32);

// 1. 禁止從模板載入任意類別（擋掉 Execute、ObjectConstructor）
cfg.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);

// 2. 模板只從 classpath 載入，不接受字串
cfg.setClassForTemplateLoading(MyApp.class, "/templates");

// 3. 開啟 strict mode，遇到未定義變數直接報錯
cfg.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);

// 4. 限制 API 取用
cfg.setAPIBuiltinEnabled(false);
```

### 正確範例 4：Go —— 用 `html/template` 而非 `text/template`

```go
// ✅ 正確：模板從檔案載入，使用者輸入只當 data
package main

import (
    "html/template" // 注意：用 html/template，會自動 escape
    "net/http"
)

var tpl = template.Must(template.ParseFiles("templates/greet.html"))

type GreetData struct {
    Bio string
}

func handler(w http.ResponseWriter, r *http.Request) {
    bio := r.URL.Query().Get("bio")
    // 即使 bio 含有 <script>，html/template 會自動 escape
    if err := tpl.Execute(w, GreetData{Bio: bio}); err != nil {
        http.Error(w, "render error", 500)
    }
}
```

`templates/greet.html`：

```html
<!DOCTYPE html>
<html>
<body>
  <p>Hello {{ .Bio }}</p>
</body>
</html>
```

**Go 的關鍵差異**：

- `text/template`：純文字模板，**不會** 自動 escape，適合產生純文字/設定檔。
- `html/template`：HTML 模板，會根據上下文（HTML body、attribute、JS、URL）自動 escape，避免 XSS。

**永遠優先用 `html/template` 渲染 HTML 輸出**。

### 正確範例 5：Go —— 模板來源永不來自使用者

```go
// ❌ 危險
t, _ := template.New("x").Parse(userInput)

// ✅ 正確：模板字串是寫死的常數或從受信任的檔案載入
const greetTpl = `Hello {{ .Name }}, your code is {{ .Code }}`
t := template.Must(template.New("greet").Parse(greetTpl))
t.Execute(w, struct {
    Name string
    Code string
}{Name: userName, Code: generatedCode})
```

---

## 七、若業務真的需要使用者編輯模板？

例如：通知系統允許客戶自訂 Email 內容、CMS、報表系統。這種「模板就是產品功能」的場景，必須做以下三層防禦：

### 1. 選擇沙箱化的模板引擎

- **Java**：`Pebble` + 自訂 `SandboxExtension`、或 `Mustache`（語法不支援 expression，天生較安全）
- **Go**：`text/template` 搭配 **嚴格限制 FuncMap**，**禁止把整個 struct 暴露給模板**（只暴露需要的 string 欄位）

### 2. 限制可用的變數與函式

```go
// ✅ 只暴露安全的欄位給模板使用
type SafeContext struct {
    UserName  string
    OrderID   string
    Amount    string
}

// 不要直接傳整個 User struct，否則 .User.PasswordHash 會被讀走！
```

### 3. 渲染環境隔離

把模板渲染放到 **獨立的低權限 worker**（無檔案系統寫入權、無對外網路、無敏感環境變數），即使被攻破也限制災情。

---

## 八、快速自我檢查清單

在你的後端程式碼中搜尋這些模式：

**Java：**

- `new Template(name, new StringReader(...))` ← Freemarker 字串模板
- `StringTemplateResolver` ← Thymeleaf 字串解析器
- `"<#assign ...>" +` 或 `"${" +` 等字串拼接後給模板引擎
- `engine.process(userInput, ...)` ← 模板字串來自使用者

**Go：**

- `template.New(...).Parse(userInput)` ← 模板來自使用者
- 模板裡用了 `text/template` 卻渲染 HTML 輸出
- `template.Must(template.New("").Funcs(funcs).Parse(...))` 且 `funcs` 包含危險函式（如 `exec`、`os`）

**通用：**

- 任何「字串拼接 → 丟給模板引擎」的程式碼路徑
- i18n / 翻譯字串裡有 `{{ }}` 或 `${ }`，且翻譯內容可被使用者影響

問自己 3 個問題：
1. 模板字串的**內容**是不是來自使用者？（最危險）
2. 模板字串裡有沒有 **被 `+` 拼接過** 使用者輸入？
3. 模板引擎的 **沙箱選項** 有沒有打開？預設值通常是「不安全」。

---

## 九、加分：偵測 SSTI 的測試 payload

如果你想自我檢查（**只在自己的測試環境**），可以送這些字串到所有「會被回顯」的輸入欄位：

| Payload | 命中代表 | 對應引擎 |
|---|---|---|
| `{{7*7}}` | 回應有 `49` | Jinja2 / Handlebars / Mustache |
| `${7*7}` | 回應有 `49` | Freemarker / Spring EL |
| `#{7*7}` | 回應有 `49` | Ruby ERB / Spring EL |
| `*{7*7}` | 回應有 `49` | Thymeleaf |
| `[[${7*7}]]` | 回應有 `49` | Thymeleaf inline |
| `<%= 7*7 %>` | 回應有 `49` | JSP / ERB |
| `{{ 7*'7' }}` | Jinja2 回應 `7777777`、Twig 回應 `49` | 區分 Jinja2 / Twig |

**永遠不要把這些 payload 送到正式環境的別人系統**——這在法律上等同入侵。

---

## 十、今日總結

| 一句話重點 | |
|---|---|
| **核心觀念** | 模板字串永遠來自開發者，使用者輸入只能當變數 |
| **危險寫法** | 把使用者輸入用 `+` 拼進模板字串 |
| **正確做法** | 模板從檔案載入、使用 `html/template`、關閉危險功能 |
| **常見場景** | 客製化通知、i18n 字串、錯誤訊息回顯、低代碼平台 |
| **連動風險** | 直接 RCE、讀取環境變數與密鑰、橫向移動 |

> **明日預告**：Day 22 將介紹 **競爭條件（Race Condition）與 TOCTOU 漏洞**——「為什麼帳戶餘額會變成負的？」「為什麼同一張優惠券被用了三次？」這類詭異 bug，背後常常是多個請求同時操作同一筆資料的時序問題。我們會看後端怎麼用資料庫鎖、樂觀鎖與原子操作來防。

---

### 補充參考

- OWASP：Server-Side Template Injection（PortSwigger 原始研究）
- CWE-1336：Improper Neutralization of Special Elements Used in a Template Engine
- Freemarker 官方文件：Configuring FreeMarker for Security
- Thymeleaf 官方文件：Template Modes
- Go 官方文件：`html/template` package
