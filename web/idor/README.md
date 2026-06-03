# Insecure Direct Object Reference (IDOR)

Challenges where the server exposes object identifiers (numeric IDs, UUIDs, filenames) in client-accessible locations and fails to verify that the requesting user is actually authorized to access that specific object. Authentication is present — authorization is not.

One challenge (`make-a-wish`) is a PHP type juggling flaw rather than a classic IDOR, but involves the same core idea of bypassing access validation through unexpected input.

## Challenges

| challenge | identifier location | missing check | technique |
|---|---|---|---|
| [labresults](<labresults.md>) | URL path (`/results/N`) | Authorization: anyone authenticated can read any result | Decrement N in Burp Repeater to access other patients' records |
| [med-lab](<med-lab.md>) | URL path (`/results/N`) | Same as labresults — no per-record ownership check | Same technique on a different clinic portal |
| [easy-notes](<easy-notes.md>) | REST API path (`/api/notes/N`) | Global sequential IDs shared across all users | Monitor Network tab to find the ID, then enumerate downward |
| [ticket-vault](<ticket-vault.md>) | REST API path (`/api/tickets/N`) | Role check absent on direct object access | `GET /api/tickets/1` returns the admin-only ticket |
| [make-a-wish](<make-a-wish.md>) | URL query string (`?richiesta[]=`) | `preg_match()` returns `FALSE` on array input, not `0` | Send array via `?richiesta[]=x`; FALSE is falsy, falls to the else branch |

## Exploitation Workflow

1. **Observe your own object ID** — log in and note the identifier in the request (URL path, query param, request body, API response).
2. **Understand the ID space** — is it sequential? Per-user or global? What range is plausible?
3. **Send to Repeater** — intercept the fetch request for your own object in Burp and forward it to Repeater.
4. **Enumerate** — modify the identifier to reference adjacent or privileged objects (`/api/notes/1`, `/results/1`).
5. **Confirm** — a 200 response with another user's data confirms IDOR.

## Key Concepts

**Authentication vs. Authorization:** IDOR is purely an authorization failure. The application correctly identifies who you are but fails to check whether you are allowed to access the specific resource you requested.

**Where to look for identifiers:**
- URL path segments: `/api/users/42/profile`
- Query parameters: `?order_id=1337`
- Request body JSON: `{"invoice": 5}`
- Response fields: `{"doc_id": "abc123"}` — use it to fetch `/files/abc123`
- Cookies and JWT claims

**make-a-wish — PHP type juggling:**
```php
preg_match("/.*/i", [])  // returns FALSE, not 0
if (preg_match(...))     // FALSE is falsy → else branch → flag
```
Fix: use strict comparison `=== 1` instead of a truthy check.
