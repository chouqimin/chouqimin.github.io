#!/usr/bin/env python3
"""一次性 script：為 content/資訊安全/ 的 DayXX_*.md 加上 Hugo frontmatter。

規則：
- title：取內文第一個 H1（去掉 "# " 前綴），內文不動
- date：內文有「> 日期：YYYY-MM-DD」就用它；沒有則依 Day 編號
  在已知錨點間線性內插、最後一個錨點之後每日 +1 外推，上限 CAP_DATE
- tags：依 Day 編號查下方手工整理的對照表
- 已有 frontmatter（開頭是 ---）的檔案跳過，可重複執行
"""

import re
from datetime import date, timedelta
from pathlib import Path

CONTENT_DIR = Path(__file__).resolve().parent.parent / "content" / "資訊安全"
CAP_DATE = date(2026, 6, 12)  # 避免產生未來日期被 Hugo 略過

# 內文有日期行的檔案（執行時會直接讀取），這裡只列「錨點」供內插用
ANCHORS = {
    1: date(2026, 4, 21), 13: date(2026, 5, 8), 23: date(2026, 5, 19),
    28: date(2026, 5, 24), 32: date(2026, 5, 28), 33: date(2026, 5, 29),
}

TAGS = {
    1: ["Injection", "SQL Injection", "OWASP Top 10"],
    2: ["XSS", "前端安全", "OWASP Top 10"],
    3: ["CSRF", "Session", "前端安全"],
    4: ["密碼學", "認證", "Password"],
    5: ["JWT", "Session", "認證"],
    6: ["認證", "Rate Limiting", "Brute Force"],
    7: ["存取控制", "IDOR", "OWASP Top 10"],
    8: ["輸入驗證", "Mass Assignment", "API 安全"],
    9: ["HTTP Header", "CORS", "瀏覽器安全"],
    10: ["SSRF", "OWASP Top 10", "網路"],
    11: ["Path Traversal", "檔案上傳", "輸入驗證"],
    12: ["Injection", "Command Injection"],
    13: ["Injection", "XXE", "XML"],
    14: ["反序列化", "OWASP Top 10"],
    15: ["Secrets 管理", "DevSecOps"],
    16: ["日誌與監控", "DevSecOps", "OWASP Top 10"],
    17: ["Rate Limiting", "API 安全"],
    18: ["供應鏈安全", "相依套件", "DevSecOps"],
    19: ["TLS", "密碼學", "OWASP Top 10"],
    20: ["Open Redirect", "輸入驗證", "前端安全"],
    21: ["Injection", "SSTI", "模板引擎"],
    22: ["Race Condition", "並行處理"],
    23: ["HTTP", "Request Smuggling", "網路"],
    24: ["OAuth2", "OIDC", "認證"],
    25: ["API 安全", "GraphQL", "存取控制"],
    26: ["Webhook", "API 安全", "HMAC"],
    27: ["MFA", "TOTP", "認證"],
    28: ["WebAuthn", "Passkey", "認證"],
    29: ["Injection", "NoSQL", "MongoDB"],
    30: ["快取", "HTTP Header", "CDN"],
    31: ["ReDoS", "Regex", "DoS"],
    32: ["Timing Attack", "密碼學", "側信道"],
    33: ["Session", "認證"],
    34: ["Injection", "CRLF", "HTTP Header"],
    35: ["DNS", "Subdomain Takeover"],
    36: ["Clickjacking", "前端安全", "HTTP Header"],
    37: ["JWT", "密碼學", "認證"],
    38: ["HTTP Header", "Proxy", "Rate Limiting"],
    39: ["DNS", "SSRF", "瀏覽器安全"],
    40: ["HTTP", "輸入驗證"],
    41: ["Injection", "LDAP"],
    42: ["Cookie", "Session", "瀏覽器安全"],
    43: ["Prototype Pollution", "JavaScript", "Injection"],
    44: ["Path Traversal", "檔案上傳", "ZIP Slip"],
    45: ["WebSocket", "API 安全", "認證"],
    46: ["HTTP Header", "Injection", "網路"],
    47: ["密碼學", "CSPRNG", "Randomness"],
    48: ["HMAC", "API 安全", "Webhook", "密碼學"],
}


def fallback_date(day: int) -> date:
    keys = sorted(ANCHORS)
    lower = max((k for k in keys if k <= day), default=None)
    upper = min((k for k in keys if k >= day), default=None)
    if lower is None:  # 比第一個錨點還早，往回推
        d = ANCHORS[upper] - timedelta(days=upper - day)
    elif upper is None:  # 最後一個錨點之後，每日 +1 外推
        d = ANCHORS[lower] + timedelta(days=day - lower)
    elif lower == upper:
        d = ANCHORS[lower]
    else:  # 兩錨點間線性內插
        span = (ANCHORS[upper] - ANCHORS[lower]).days
        d = ANCHORS[lower] + timedelta(days=round(span * (day - lower) / (upper - lower)))
    return min(d, CAP_DATE)


def main() -> None:
    for path in sorted(CONTENT_DIR.glob("Day*.md")):
        day = int(re.match(r"Day(\d+)_", path.name).group(1))
        text = path.read_text(encoding="utf-8")
        if text.startswith("---"):
            print(f"skip (已有 frontmatter): {path.name}")
            continue

        m = re.search(r"^# (.+)$", text, re.MULTILINE)
        title = m.group(1).strip().replace('"', '\\"')

        dm = re.search(r"日期：(\d{4}-\d{2}-\d{2})", text)
        d = date.fromisoformat(dm.group(1)) if dm else fallback_date(day)

        tags = ", ".join(f'"{t}"' for t in TAGS[day])
        fm = f'---\ntitle: "{title}"\ndate: {d.isoformat()}\ntags: [{tags}]\n---\n\n'
        path.write_text(fm + text, encoding="utf-8")
        print(f"{path.name}: date={d.isoformat()}{'' if dm else ' (推算)'}")


if __name__ == "__main__":
    main()
