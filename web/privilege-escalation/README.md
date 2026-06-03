# Privilege Escalation / Broken Access Control

Challenges where an authenticated low-privilege user escalates to higher permissions by exploiting flaws in how the server enforces access control — either by accepting attacker-controlled role parameters (mass assignment) or by blindly trusting a client-supplied authorization header.

## Challenges

| challenge | vulnerability | mechanism | technique |
|---|---|---|---|
| [al-dente](<al-dente.md>) | Mass assignment | Backend binds the full JSON profile body to the user model without field whitelisting | Add `"role": "head_chef"` to the profile PUT body; 200 OK confirms escalation; GET `/api/secret-recipe` now returns the flag |
| [mission-control](<mission-control.md>) | Broken access control via client-supplied header | Authorization decision made on `X-Clearance-Level` header sent by the client | Intercept the `/api/briefings/starfall` request; change `X-Clearance-Level: operator` to `X-Clearance-Level: commander` |

## Key Concepts

**Mass assignment** occurs when a framework automatically maps incoming request fields to model attributes. If the developer does not explicitly whitelist allowed fields, an attacker can inject fields like `role`, `is_admin`, or `balance` that should never be user-settable.

**Secure fix:** use an explicit allowlist (DTO pattern):
```python
ALLOWED_FIELDS = {'username', 'bio'}
update = {k: v for k, v in request.json.items() if k in ALLOWED_FIELDS}
```

**Client-supplied authorization headers** (`X-Clearance-Level`, `X-Role`, `X-Admin`) give the client full control over its own permissions. The server must derive authorization from a server-side session or a cryptographically verified token — never from a header it reads from the request.

**Testing for mass assignment:** inspect the server's user object in any response (profile page, API endpoint). Add any additional fields you observe as keys in a write request and see if the server accepts them.

**Testing for header-based access control:** find any 403 response and check if the request includes or could include a custom header that the server might use for authorization. Burp's Param Miner extension can automate header discovery.
