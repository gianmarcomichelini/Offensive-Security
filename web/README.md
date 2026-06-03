# Web Exploitation

Challenges organized by vulnerability class. Each category folder contains individual writeups with methodology, payloads, and key takeaways.

## Categories

| folder | focus | challenges |
|---|---|---|
| [sqli/](sqli/) | SQL injection — authentication bypass, data extraction, blind and time-based techniques | 13 |
| [xss/](xss/) | Cross-site scripting — reflected, stored, DOM, CSP bypass, cookie theft | 11 |
| [idor/](idor/) | Insecure Direct Object Reference — predictable IDs, missing authorization checks | 5 |
| [application-logic/](application-logic/) | Business logic and input validation flaws | 4 |
| [session-management/](session-management/) | Cookie, JWT, 2FA, and session token vulnerabilities | 13 |
| [privilege-escalation/](privilege-escalation/) | Broken access control, mass assignment, header spoofing | 2 |
| [code-injection/](code-injection/) | OS command injection and server-side code evaluation | 11 |

## Challenges by Category

### sqli/

| challenge | injection type | technique |
|---|---|---|
| [Basic SQLi](sqli/basic-sqli.md) | login bypass | `' OR '1'='1` tautology |
| [Logic SQLi](sqli/logic-sqli.md) | login bypass | boolean logic manipulation |
| [SQLiLite](sqli/sqlilite.md) | login bypass | SQLite-specific logic subversion |
| [Union-Based SQLi](sqli/union-based-sqli.md) | data extraction | UNION SELECT schema enumeration |
| [Blind SQL Injection Automation](sqli/blind-sqli.md) | blind boolean | oracle construction + Python automation |
| [Time Based SQL Injection Dynamics](sqli/time-based-sqli.md) | blind time-based | SLEEP/timing delays for bit extraction |
| [ToDo](sqli/todo.md) | via cookie header | injection through session cookie |
| [BookBrew](sqli/bookbrew.md) | UNION via cookie | UNION extraction through session cookie |
| [AirlineLostFound](sqli/airline-lost-found.md) | UNION + SQLite | parenthesis escaping + full schema dump |
| [StagePass](sqli/stagepass.md) | numeric + WAF | mixed-case keywords + `/**/` space bypass |
| [DepartmentWiki](sqli/department-wiki.md) | stacked queries | semicolon-separated second query |
| [Admin's Secret](sqli/admins-secret.md) | registration form | second-order injection via signup |
| [Sn4ck sh3nan1gans](sqli/sn4ck-sh3nan1gans.md) | encoded JSON | injection hidden inside JSON-encoded parameters |

### xss/

| challenge | xss type | technique |
|---|---|---|
| [portswigger](xss/portswigger.md) | reflected | basic HTML context injection |
| [Segnalazione cinghiali cittadini](xss/segnalazione-cinghiali-cittadini.md) | reflected | breaking out of HTML attribute context |
| [ScratchPad](xss/scratchpad.md) | stored | injecting into a JavaScript string literal |
| [Guestbook](xss/guestbook.md) | stored | `javascript:` URI sanitizer bypass |
| [Curious George](xss/curious-george.md) | stored | stored XSS + proof-of-work + webhook exfiltration |
| [Bibbopedia 2](xss/bibbopedia-2.md) | stored | HttpOnly bypass via action-as-victim (CSRF via XSS) |
| [RecipeBox](xss/recipebox.md) | reflected + SSRF | SSRF chained with reflected XSS for cookie theft |
| [PigeonPost](xss/pigeonpost.md) | DOM | postMessage without origin validation |
| [PicShare](xss/picshare.md) | stored, file upload | SVG avatar upload + missing X-Content-Type-Options |
| [Virtualbank](xss/virtualbank.md) | stored | exploiting overly permissive `'self'` CSP directive |
| [Private Notes](xss/private-notes.md) | stored | predicting or reusing nonce values to bypass CSP |

### idor/

| challenge | technique |
|---|---|
| [labresults](<idor/labresults.md>) | Sequential patient record IDs in URL path (`/results/N`) |
| [med-lab](<idor/med-lab.md>) | Same IDOR pattern on a clinical lab portal |
| [easy-notes](<idor/easy-notes.md>) | Global sequential note IDs exposed in a REST API path (`/api/notes/N`) |
| [ticket-vault](<idor/ticket-vault.md>) | Role-based ticket restriction bypassed via `/api/tickets/1` |
| [make-a-wish](<idor/make-a-wish.md>) | PHP type juggling — `preg_match()` returns `FALSE` on array input, bypassing the check |

### application-logic/

| challenge | vulnerability | technique |
|---|---|---|
| [click-me](<application-logic/click-me.md>) | Client-side score tracking | Modify cookie `cookies=99999999` to fake the score |
| [flags-shop](<application-logic/flags-shop.md>) | Hidden form field price | Intercept POST and change the `costo` parameter to an affordable value |
| [password-changer](<application-logic/password-changer.md>) | Base64 token manipulation | Decode token → change username to `admin` → re-encode → inject in URL |
| [swagshop](<application-logic/swagshop.md>) | Business logic (negative quantity) | Submit quantity=-1 to subtract a negative price, inflating wallet balance |

### session-management/

| challenge | vulnerability | technique |
|---|---|---|
| [power-cookie](<session-management/power-cookie.md>) | Client-side authorization cookie | Flip `admin=0` to `admin=1` in DevTools or Burp |
| [cookie-monster-army](<session-management/cookie-monster-army.md>) | Base64 cookie forgery | Decode → replace username with `admin` → re-encode |
| [a-too-small-reminder](<session-management/a-too-small-reminder.md>) | Predictable sequential session IDs | Burp Intruder enumerates 1..10000; 200 response identifies admin session |
| [flagmail](<session-management/flagmail.md>) | Predictable token formula (timestamp + user_id) | Brute-force timestamp window ending in `001` to find admin's token |
| [bibvault-1](<session-management/bibvault-1.md>) | JWT signature not verified | Server uses `jwt.decode()` not `jwt.verify()` — tamper payload freely |
| [jwt-bypass-flawed-signature](<session-management/jwt-bypass-flawed-signature.md>) | JWT `alg:none` attack | Set `alg=none`, strip signature, keep trailing dot; server skips verification |
| [jwt-bypass-weak-keys](<session-management/jwt-bypass-weak-keys.md>) | JWT HMAC weak key | `hashcat -m 16500` cracks `secret1`; re-sign with that key as admin |
| [jwt-bypass-jwk](<session-management/jwt-bypass-jwk.md>) | JWT embedded JWK | Inject rogue RSA public key in `jwk` header; server validates attacker's signature |
| [jwt-bypass-jku](<session-management/jwt-bypass-jku.md>) | JWT `jku` header injection | Point `jku` to attacker-controlled JWKS endpoint; server fetches and trusts it |
| [jwt-bypass-kid](<session-management/jwt-bypass-kid.md>) | JWT `kid` path traversal | `kid=../../../dev/null` → server loads empty key → HMAC signed with null byte |
| [keyvault](<session-management/keyvault.md>) | JKU injection via webhook | `jku` points to webhook.site hosting attacker JWKS; real-time telemetry confirms fetch |
| [neonarcade](<session-management/neonarcade.md>) | Mass assignment + cookie | Inject `"role":"admin"` in profile PUT; server re-issues a legitimately signed cookie |
| [two-factor-flaws](<session-management/two-factor-flaws.md>) | 2FA bypass via forced browsing | Session issued after password check; navigate directly to `/my-account`, skipping 2FA |

### privilege-escalation/

| challenge | vulnerability | technique |
|---|---|---|
| [al-dente](<privilege-escalation/al-dente.md>) | Mass assignment | Inject `"role": "head_chef"` in profile PUT; server binds it to the user object |
| [mission-control](<privilege-escalation/mission-control.md>) | Broken access control via client header | Spoof `X-Clearance-Level: commander`; server trusts the client-supplied value |

### code-injection/

| challenge | injection type | technique |
|---|---|---|
| [ping1](<code-injection/ping1.md>) | OS command injection | Basic unrestricted command chaining (`; cat /flag`) |
| [ping2](<code-injection/ping2.md>) | OS command injection + filter bypass | Advanced evasion of character and keyword blacklists |
| [blind-injection](<code-injection/blind-injection.md>) | Blind OS command injection | Output redirection to a web-accessible file for exfiltration |
| [qrdrop](<code-injection/qrdrop.md>) | Command injection via QR code | Malicious command embedded in QR code content |
| [calcolatrice](<code-injection/calcolatrice.md>) | PHP `eval()` injection | Arbitrary PHP code execution via unsanitized eval |
| [spreadsheetzero](<code-injection/spreadsheetzero.md>) | PHP `eval()` injection | Formula evaluation context exploited as code execution |
| [3val](<code-injection/3val.md>) | Python sandbox escape | MRO traversal (`__subclasses__`) + string fragmentation to bypass static blacklist |
| [autograder](<code-injection/autograder.md>) | Python sandbox escape | `_ModuleLock.__init__.__globals__` + fragmented `__builtins__` to read `/flag.txt` |
| [gitpeek](<code-injection/gitpeek.md>) | Command injection via variable expansion | `$FLAG` shell variable expansion bypasses separator blacklist |
| [timp](<code-injection/timp.md>) | Command injection + filter bypass | `$(cat /flag.txt)` substitution or `${IFS}` to bypass space filter |
| [virus-vault](<code-injection/virus-vault.md>) | Blind time-based command injection | Filename parameter injected; time-based exfiltration of FLAG env variable char-by-char |
