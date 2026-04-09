# Web Exploitation — CTF Writeups

A collection of web security challenge writeups organized by vulnerability category, each documented with methodology, exploitation steps and key takeaways.


## Challenges by Category

### IDOR — Insecure Direct Object Reference

Vulnerabilities where the server fails to verify that the authenticated user is authorized to access the requested resource, allowing enumeration of other users' data by manipulating identifiers.

| Challenge | Difficulty | Platform | Writeup |
|-----------|------------|----------|---------|
| MedLab | Beginner | OliCyber | [idor/med-lab.md](./idor/med-lab.md) |
| EasyNotes | Beginner | OliCyber | [idor/easy-notes.md](./idor/easy-notes.md) |
| Make a Wish | Intermediate | OliCyber | [idor/make-a-wish.md](./idor/make-a-wish.md) |

Any client-accessible identifier, whether it appears in REST API paths, query strings, or JSON bodies, is a potential IDOR vector if the server does not enforce per-request authorization checks. See [idor/easy-notes.md](./idor/easy-notes.md) for a deeper breakdown of how API-level IDOR differs from the more visible URL-parameter variant.

---

### Cookie Manipulation

Vulnerabilities arising from storing security-sensitive state, such as scores, balances or roles, in client-side cookies, which are fully readable and writable by the user.

| Challenge | Difficulty | Platform | Writeup |
|-----------|------------|----------|---------|
| Click Me | Beginner | OliCyber | [cookie-manipulation/click-me.md](./cookie-manipulation/click-me.md) |

Cookies are entirely client-controlled, so any sensitive value stored in them can be freely modified by the attacker, and server-side session state is the only reliable mechanism for tracking security-sensitive values like scores or balances.

---

### Input Validation

Vulnerabilities where the server trusts client-supplied values, such as hidden form fields or prices, without independently verifying them server-side.

| Challenge | Difficulty | Platform | Writeup |
|-----------|------------|----------|---------|
| Flags Shop | Beginner | OliCyber | [input-validation/flags-shop.md](./input-validation/flags-shop.md) |

The server should never accept security-critical values like prices from the client, since only identifiers such as an item ID should come from the client, while everything else must be looked up server-side from a trusted data source.

---

### Token Manipulation

Vulnerabilities where tokens encoding user identity or permissions are protected only by encoding, such as Base64, rather than by cryptographic signing, allowing an attacker to forge arbitrary tokens.

| Challenge | Difficulty | Platform | Writeup |
|-----------|------------|----------|---------|
| Password Changer 3000 | Intermediate | OliCyber | [token-manipulation/password-changer-3000.md](./token-manipulation/password-changer-3000.md) |

Base64 is encoding, not encryption, so tokens must be cryptographically signed, for example with HMAC or a properly configured JWT, in order for tampering to be detectable server-side.

---

### Privilege Escalation / Mass Assignment

Vulnerabilities where the server accepts user-supplied parameters that map directly to internal object attributes, allowing an attacker to set fields like `role` that should never be user-controlled.

| Challenge | Difficulty | Platform | Writeup |
|-----------|------------|----------|---------|
| Al Dente | Intermediate | OliCyber | [privilege-escalation/al-dente.md](./privilege-escalation/al-dente.md) |

API endpoints that accept JSON or form data must explicitly whitelist the fields they allow users to set, since blindly binding all request parameters to internal models enables mass assignment attacks that can silently elevate privileges.

---


## Tools Used

| Tool | Purpose |
|------|---------|
| [Burp Suite](https://portswigger.net/burp) | Intercepting proxy, Repeater, HTTP history |
| [CyberChef](https://gchq.github.io/CyberChef/) | Encoding/decoding (Base64, hex, etc.) |
| Browser DevTools | Cookie inspection, network tab, source analysis |

---

## Key Principles

Every value originating from the client, whether a form field, a cookie, a header or a URL parameter, is entirely attacker-controlled, and a server that makes decisions based on these values without independently verifying them is, by definition, vulnerable. Hidden form fields, obfuscated parameters and encoded tokens are all readable and modifiable by anyone who inspects the traffic, so the distinction between hidden and secret must never be confused. Encoding schemes like Base64 or URL encoding are reversible by anyone and provide no integrity guarantees whatsoever, which is why cryptographic signatures are required wherever tamper-evidence matters. Authorization must be enforced per-request, since checking identity at login is never sufficient, and every sensitive operation must independently verify that the requester has permission for that specific resource. Finally, a skilled attacker considers all available attack vectors, from Burp Repeater to DevTools console to direct URL manipulation, and chooses the most reliable path for the specific context.

---

## Disclaimer

All challenges documented in this repository were solved on dedicated CTF and training platforms in a legal and ethical context, and this material is intended exclusively for educational purposes. These techniques must never be applied to systems that you do not own or for which you do not have explicit written permission to test.