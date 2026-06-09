# InfiltraFox

A Firefox extension for web security analysis and vulnerability detection.

## Installation

1. Open Firefox and navigate to `about:debugging`
2. Click **This Firefox** → **Load Temporary Add-on**
3. Select `manifest.json` from this directory

For permanent installation, package as a signed `.xpi` via [addons.mozilla.org](https://addons.mozilla.org/developers/).

## Usage

1. Navigate to any `http://` or `https://` page
2. Click the InfiltraFox toolbar icon
3. Select a mode — **Red Team** or **Blue Team**
4. Click **Analyze Page**
5. Browse findings across the seven tabs
6. Click **Export Report** to download a JSON report

## Modes

| Mode | Focus |
|---|---|
| **Red Team** | Exploitation guidance — how an attacker would leverage each finding |
| **Blue Team** | Mitigation guidance — how to remediate each finding |

## Scan Modules

### SQLi — SQL Injection Indicators
Inspects every form on the page for inputs that lack server-side-validation signals.

Flags:
- Unvalidated text/textarea inputs (no `pattern`, no `maxlength`)
- POST forms with password fields and no CSRF token

Risk scoring:
- POST method → +2, password field → +2, no CSRF token → +2, ≥3 unsafe inputs → +1
- ≥6 = High, ≥3 = Medium, otherwise Low

### XSS — Cross-Site Scripting Indicators
Scans inline scripts and DOM elements for dangerous patterns.

Flags:
- Inline `<script>` blocks using user-controlled sources (`location`, `document.URL`, `localStorage`, etc.) feeding into sinks (`innerHTML`, `eval`, `document.write`, etc.) → **domXss / High**
- Inline scripts with only a sink or only a source → **inlineScript / Medium**
- Inline event handler attributes (`onclick`, `onload`, `onerror`, etc.) → **eventHandler / High**
- `<a href="javascript:…">` links → **javascriptUrl / Medium**

### Cookies — JavaScript-Accessible Cookies
Reads `document.cookie` to enumerate cookies exposed to JavaScript.

Flags:
- Any readable cookie implies `HttpOnly` is absent
- `Secure` and `SameSite` cannot be verified from the page; flagged as unknown
- Risk is **High** on plain HTTP, **Medium** on HTTPS

### Headers — Security Header Checks
Reads `<meta http-equiv>` tags and `<meta name="referrer">` to infer header posture.

> Note: HTTP response headers are not accessible from a content script. This module checks only what the page declares via meta tags.

| Header | Flagged when |
|---|---|
| `Content-Security-Policy` | Absent, or contains `unsafe-inline` / `unsafe-eval` / wildcard `*` |
| `X-Frame-Options` | Absent |
| `Referrer-Policy` | Absent, or set to `unsafe-url` / `no-referrer-when-downgrade` |
| `Strict-Transport-Security` | Absent on HTTPS pages |
| `Permissions-Policy` | Absent |

### Mixed Content
Only runs on HTTPS pages. Detects resources loaded over plain HTTP.

| Resource type | Risk |
|---|---|
| `<script>`, `<iframe>`, `<object>`, `<form action>` | High |
| `<link rel="stylesheet">` | Medium |
| `<img>`, `<audio>`, `<video>` | Low |

### Open Redirects
Scans `<a href>` and `<form action>` URLs for known redirect parameters.

Detected parameters: `url`, `redirect`, `redirectUrl`, `redirect_url`, `next`, `return`, `returnUrl`, `return_url`, `goto`, `dest`, `destination`, `forward`, `continue`, `target`, `redir`, `location`, `path`, `callback`, `ref`

Risk: **Medium** — requires server-side confirmation that the destination is unvalidated.

### SRI — Subresource Integrity
Checks every cross-origin `<script src>` and `<link rel="stylesheet" href>` for a missing `integrity` attribute.

| Tag | Risk |
|---|---|
| `<script>` | High |
| `<link rel="stylesheet">` | Medium |

## Risk Score

The summary card shows a weighted aggregate score across all findings.

| Severity | Weight |
|---|---|
| Critical | 10 |
| High | 6 |
| Medium | 3 |
| Low | 1 |

The bar fills from green (low risk) through orange to red. The reference ceiling is 40 points; scores above that peg the bar at 100%.

## Export Format

```json
{
  "timestamp": "2026-06-09T09:41:31.262Z",
  "url": "https://example.com/login",
  "title": "Login — Example",
  "mode": "redTeam",
  "findings": {
    "meta": { "title": "…", "url": "…", "forms": 2, "scripts": 5, "cookieCount": 1 },
    "sqli": [],
    "xss": [],
    "cookies": [],
    "headers": [],
    "mixedContent": [],
    "openRedirects": [],
    "sri": []
  }
}
```

## Permissions

| Permission | Reason |
|---|---|
| `activeTab` | Read the current tab's URL and title |
| `tabs` | Query the active tab to inject analysis |
| `storage` | Persist mode preference and scan history (last 20 scans) |
| `<all_urls>` | Allow the content script to run on any HTTP/HTTPS page |

## Limitations

- HTTP response headers (e.g., actual `Content-Security-Policy`, `Set-Cookie` flags) are not accessible from a content script. Header findings reflect only what the page exposes via `<meta>` tags.
- Cookie `Secure` and `SameSite` flags cannot be read from `document.cookie`.
- SQLi and XSS detection is heuristic — no payloads are sent and no server responses are analysed. Findings indicate attack surface, not confirmed vulnerabilities.
- Open redirect detection is pattern-based; server-side validation is not verified.
