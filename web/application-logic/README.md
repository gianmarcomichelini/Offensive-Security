# Application Logic Flaws

Challenges where the application is technically implemented correctly but fails to enforce business rules, trusts client-supplied values it should never accept, or does not validate the logical boundaries of user actions.

## Challenges

| challenge | vulnerability class | root cause | technique |
|---|---|---|---|
| [click-me](<click-me.md>) | Client-side state management | Score stored in a cookie the client controls | Set `Cookie: cookies=99999999` in Burp Repeater |
| [flags-shop](<flags-shop.md>) | Client-supplied price | Hidden `<input name="costo">` field trusted by the server | Intercept POST in Burp; change `costo=1000` to `costo=1` |
| [password-changer](<password-changer.md>) | Unauthenticated token manipulation | Base64-encoded username in URL token; server decodes without verifying identity | Decode `YWRtaW4=` → `admin`; swap username; re-encode; inject in URL |
| [swagshop](<swagshop.md>) | Business logic — missing boundary check | Negative quantity accepted; subtraction of negative = credit | Submit `quantity=-1` for the $9,999 item; wallet inflates; re-buy normally |

## Key Concepts

**Never trust the client:** any value that originates in the browser — form fields, hidden inputs, cookies, URL parameters, headers — is fully under the attacker's control. The server must re-derive security-critical values (price, score, role) from its own state, not from what the client sends.

**Hidden inputs are not secret:** `<input type="hidden" name="costo" value="1000">` is invisible in the rendered UI but fully visible in the HTML source and in Burp. It can be modified freely.

**Base64 is encoding, not encryption:** any Base64 value can be decoded, modified, and re-encoded in seconds. Treat it as plaintext.

**Boundary conditions:** negative quantities, zero prices, and integer overflow are the classic business logic attack surface. Every numeric field needs a lower and upper bound enforced server-side.

**Multi-step flow trust:** security checks applied at step 1 give no protection if an attacker re-enters the flow at step 2 with manipulated state. Each step must independently validate the operation.
