# Web Exploitation CTF Writeups

A collection of web security challenge writeups organized by vulnerability category, each documented with methodology, exploitation steps, and key takeaways.

## Challenges by Category

### application-logic

| challenge | vulnerability | documentation |
|---|---|---|
| [click-me](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/application-logic/click-me.md) | cookie manipulation | cookie value tampering |
| [password-changer](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/application-logic/password-changer.md) | token manipulation | base64 encoded token manipulation |
| [swagshop](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/application-logic/swagshop.md) | business logic | workflow sequence circumvention |

### idor

| challenge | documentation |
|---|---|
| [easynotes](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/idor/easynotes.md) | baseline sequential parameter reference access |
| [labresults](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/idor/labresults.md) | identifier validation bypass |
| [make-a-wish](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/idor/make-a-wish.md) | high privileged object modifications via APIs |
| [ticketvault](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/idor/ticketvault.md) | structured reference extraction |

### input-validation

| challenge | documentation |
|---|---|
| [flags-shop](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/input-validation/flags-shop.md) | payload structure filter omissions |

### privilege-escalation

| challenge | documentation |
|---|---|
| [al-dente](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/privilege-escalation/al-dente.md) | roles validation processing failure |
| [mission-control](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/privilege-escalation/mission-control.md) | broken access control |

### session-management

| challenge | documentation |
|---|---|
| [a-too-small-reminder](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/session-management/a-too-small-reminder.md) | session ID brute forcing |
| [bibvault-1](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/session-management/bibvault-1.md) | JWT signature omission |
| [cookie-monster-army](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/session-management/cookie-monster-army.md) | predictability verification analysis |
| [flagmail](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/session-management/flagmail.md) | IDOR combined with predictable tokens |
| [jwt-bypass-flawed-signature](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/session-management/jwt-bypass-flawed-signature.md) | improper verification implementation |
| [jwt-bypass-weak-keys](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/session-management/jwt-bypass-weak-keys.md) | symmetric signature brute forcing |
| [jwt-bypass-jku](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/session-management/jwt-bypass-jku.md) | JKU header injection |
| [jwt-bypass-jwk](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/session-management/jwt-bypass-jwk.md) | JWK header injection |
| [jwt-bypass-kid](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/session-management/jwt-bypass-kid.md) | KID header path traversal |
| [keyvault](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/session-management/keyvault.md) | JKU injection |
| [neonarcade](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/session-management/neonarcade.md) | privilege escalation with mass assignment |
| [power-cookie](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/session-management/power-cookie.md) | authorization manipulation |
| [two-factor-flaws](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/session-management/two-factor-flaws.md) | architecture and logic flaws |

### sqli

| challenge | documentation |
|---|---|
| [airlinelostfound](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/sqli/airlinelostfound.md) | extraction and parenthesis escaping |
| [basic-sqli](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/sqli/basic-sqli.md) | authentication bypass structures |
| [blind-sqli-automation](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/sqli/blind-sqli-automation.md) | boolean oracle construction |
| [bookbrew](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/sqli/bookbrew.md) | injection via session cookie |
| [departmentwiki](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/sqli/departmentwiki.md) | stacked queries |
| [logic-sqli](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/sqli/logic-sqli.md) | logic evaluation |
| [sqli-registration](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/sqli/sqli-registration.md) | exploiting registration flows |
| [sqlilite-login-bypass](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/sqli/sqlilite-login-bypass.md) | SQLite authentication subversion |
| [sn4ck-sh3nan1gans](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/sqli/sn4ck-sh3nan1gans.md) | encoded JSON payloads |
| [stagepass](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/sqli/stagepass.md) | numeric input with WAF bypass |
| [time-based-sqli](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/sqli/time-based-sqli.md) | time delay dynamics |
| [todo-cookie-bypass](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/sqli/todo-cookie-bypass.md) | cookie bypass vectors |
| [union-based-sqli](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/sqli/union-based-sqli.md) | explicit UNION constructs |

### code-injection

| challenge | documentation |
|---|---|
| [3v-l](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/code-injection/3v-l.md) | advanced Python sandboxes |
| [autograder](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/code-injection/autograder.md) | Python sandbox evasion and hierarchy traversal |
| [calcolatrice](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/code-injection/calcolatrice.md) | PHP evaluation |
| [gitpeek](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/code-injection/gitpeek.md) | vulnerable variable expansion |
| [ping1](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/code-injection/ping1.md) | unrestricted command execution |
| [ping2](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/code-injection/ping2.md) | advanced filter evasion |
| [portswigger](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/code-injection/portswigger.md) | blind OS command injection |
| [qrdrop](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/code-injection/qrdrop.md) | standard command injection |
| [spreadsheetzero](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/code-injection/spreadsheetzero.md) | formula evaluation |
| [timp](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/code-injection/timp.md) | filter bypass |
| [virus-vault](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/web/code-injection/virus-vault.md) | blind CMD injection |