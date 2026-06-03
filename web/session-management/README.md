# Session Management

Challenges covering the full range of session and authentication vulnerabilities: cookie forgery, predictable session tokens, JWT attacks across all major attack vectors, mass assignment, and 2FA bypass.

## Challenges

| challenge | category | vulnerability | technique |
|---|---|---|---|
| [power-cookie](<power-cookie.md>) | Cookie | Client-side authorization flag | Flip `admin=0` to `admin=1` in DevTools or Burp |
| [cookie-monster-army](<cookie-monster-army.md>) | Cookie | Base64 cookie forgery | Decode → replace username with `admin` → re-encode |
| [a-too-small-reminder](<a-too-small-reminder.md>) | Session ID | Predictable sequential integer session IDs | Burp Intruder enumerates 1..10000; 200 response = admin session |
| [flagmail](<flagmail.md>) | Session ID | Token formula: `unix_timestamp + user_id` | Brute-force timestamp window; token ending in `001` = admin (id=1) |
| [bibvault-1](<bibvault-1.md>) | JWT | Signature not verified (`jwt.decode` not `jwt.verify`) | Tamper payload freely; signature is never checked |
| [jwt-bypass-flawed-signature](<jwt-bypass-flawed-signature.md>) | JWT | `alg:none` accepted | Set `alg=none`, remove signature, keep trailing dot: `header.payload.` |
| [jwt-bypass-weak-keys](<jwt-bypass-weak-keys.md>) | JWT | HMAC signed with a weak secret | `hashcat -a 0 -m 16500 <JWT> jwt.secrets.list` cracks `secret1`; re-sign as admin |
| [jwt-bypass-jwk](<jwt-bypass-jwk.md>) | JWT | Embedded `jwk` header trusted without validation | Generate rogue RSA pair; embed public key in `jwk` header; sign with private key |
| [jwt-bypass-jku](<jwt-bypass-jku.md>) | JWT | `jku` header fetched without domain validation | Host attacker JWKS at own URL; inject `jku` pointing there; sign with matching private key |
| [jwt-bypass-kid](<jwt-bypass-kid.md>) | JWT | `kid` used as filesystem path without sanitization | `kid=../../../dev/null` → server reads empty file → HMAC key = null byte |
| [keyvault](<keyvault.md>) | JWT | `jku` injection via webhook | Configure webhook.site to serve attacker JWKS; inject `jku`; telemetry confirms server fetch |
| [neonarcade](<neonarcade.md>) | Mass assignment | Backend binds full JSON body to user object | Inject `"role":"admin"` in profile PUT; server re-issues a legitimately signed session |
| [two-factor-flaws](<two-factor-flaws.md>) | 2FA | Session issued before 2FA is completed | After submitting password, navigate directly to `/my-account` — 2FA screen bypassed |

## JWT Attack Reference

| attack | condition | method |
|---|---|---|
| Signature not verified | Library uses `decode()` | Tamper payload directly; signature ignored |
| `alg:none` | Library accepts `none` algorithm | Set `"alg":"none"`, remove 3rd segment, keep trailing `.` |
| Weak HMAC key | Short or dictionary-guessable secret | `hashcat -m 16500`; re-sign with recovered key |
| Embedded JWK (`jwk`) | Server trusts `jwk` header | Generate RSA pair; insert public key in `jwk`; sign with private key |
| External JWK Set (`jku`) | `jku` URL not validated | Host JWKS on attacker server; inject `jku` URL in header |
| KID path traversal (`kid`) | `kid` used to read file system | `kid=../../../dev/null` → empty key → sign HMAC with `\x00` |

**JWT structure:** `base64url(header).base64url(payload).base64url(signature)`

**Tools:** Burp Suite JWT Editor extension, jwt.io, hashcat mode 16500.

## Cookie Security Reference

| flag | purpose | missing = |
|---|---|---|
| `HttpOnly` | Prevents JS from reading the cookie | XSS can steal it with `document.cookie` |
| `Secure` | Cookie only sent over HTTPS | Transmitted in cleartext over HTTP |
| `SameSite=Strict` | Cookie not sent in cross-site requests | CSRF possible |

**Predictable token entropy:** OWASP recommends ≥128 bits of entropy. Sequential integers have ~14 bits. Brute-force becomes trivial.
