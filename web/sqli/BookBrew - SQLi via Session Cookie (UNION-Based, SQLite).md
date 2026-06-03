## BookBrew - SQLi via Session Cookie (UNION-Based, SQLite)


> x Exam (29)


The BookBrew challenge presents itself as a cozy book review community where users can register, browse a catalog, and post reviews, with the vulnerability hiding not in the obvious login form but in how the session cookie is consumed after authentication. The registration flow appears entirely safe at first glance, and the login page offers no obvious injection surface, which makes the cookie the correct place to focus attention.

### Vulnerability Surface

After registering and logging in, the server issues a session cookie whose value is a base64-encoded JSON object, decoded as follows.

```json
{"uid": 9, "username": "admin_user"}
```

Because the encoding is plain base64 with no signature or integrity check of any kind, the server has no mechanism to detect tampering, which makes every field inside the JSON object a direct injection vector. The `username` field in particular is interpolated raw into a backend SQL query that drives the `/my-reviews` page, producing a classic UNION-based injection scenario.

### Reconnaissance and Column Count

The first step is to confirm the injection and establish the number of columns the vulnerable query selects, by replacing the `username` value with incrementally longer NULL-based payloads and re-encoding the entire JSON object to base64 before setting it as the session cookie.

```
' UNION SELECT null,null,null,null,null,null,null,null --
```

Eight NULLs produce a valid page response, confirming that the backend query selects exactly eight columns.

### Identifying Reflected Columns

To determine which of the eight columns are actually rendered in the HTML, the username is replaced with a payload that injects eight distinct string literals.

```
' UNION SELECT 'a','b','c','d','e','f','g','h' --
```

The page renders `h` and `g` in the review title area, `f` in the top-right corner, and `e` in the review body, confirming that columns five through eight are reflected, with column five being the most convenient output channel as it maps to the body text of each review card.

### Database Fingerprinting

Running `version()` in column one produces the error `no such function: version`, which immediately rules out MySQL and PostgreSQL. Substituting `sqlite_version()` returns a valid result, confirming the backend is SQLite, a distinction that matters because SQLite uses `sqlite_master` for schema enumeration rather than `information_schema`, and does not support MySQL-style comment syntax.

### Schema Enumeration

With the database engine confirmed, the full list of tables is retrieved by querying `sqlite_master` and reflecting the `name` column through position five.

```sql
' UNION SELECT 1,2,3,4,name,6,7,8 FROM sqlite_master WHERE type='table' --
```

The page returns five table names across five review cards, specifically `books`, `reviews`, `secrets`, `sqlite_sequence`, and `users`, where `secrets` is immediately the anomalous entry and therefore the target.

### Column Enumeration of the Target Table

The columns of the `secrets` table are retrieved using SQLite's `pragma_table_info` function, which is available inline within a UNION query.

```sql
' UNION SELECT 1,2,3,4,name,6,7,8 FROM pragma_table_info('secrets') --
```

The response reveals exactly two columns, `flag` and `id`, which makes the final extraction payload trivial to construct.

### Flag Extraction

The final cookie payload selects the `flag` column directly from the `secrets` table and reflects it through position five.

```sql
' UNION SELECT 1,2,3,4,flag,6,7,8 FROM secrets --
```

The JSON object to encode and set as the session cookie is the following.

```json
{"uid": -1, "username": "' UNION SELECT 1,2,3,4,flag,6,7,8 FROM secrets --"}
```

Reloading `/my-reviews` after setting this cookie causes the application to execute the injected query and render the flag value in the review body field.

### Full Attack Chain

The complete sequence, from cookie interception to flag retrieval, proceeds through the following stages: first, intercepting the session cookie in Burp Suite or DevTools and decoding it from base64 to reveal the JSON structure, then crafting a NULL-based payload to confirm eight reflected columns, then injecting string literals to identify positions five through eight as the visible output channels, then fingerprinting the database as SQLite via the `sqlite_version()` function, then enumerating tables via `sqlite_master` to identify `secrets` as the target, then enumerating columns via `pragma_table_info` to identify the `flag` column, and finally extracting the flag value by selecting it directly in position five of the UNION query.

### Root Cause

The vulnerability originates from the server reading the session cookie value and formatting it directly into a SQL string without parameterization, a pattern equivalent to the following vulnerable code.

```python
cursor.execute("SELECT ... WHERE username = '%s'" % username_from_cookie)
```

The correct fix is to use parameterized queries, which instruct the database driver to always treat the cookie value as pure data regardless of its contents, making injection impossible.

```python
cursor.execute("SELECT ... WHERE username = ?", (username_from_cookie,))
```

### Key Takeaways

Base64 is encoding, not encryption, and provides zero integrity protection, meaning any field inside an unsigned cookie is fully attacker-controlled. Session tokens must always be treated as untrusted user input at the SQL layer, and parameterized queries are the only reliable mitigation. The column count of the original query must be matched exactly in any UNION payload, and SQLite's schema introspection relies on `sqlite_master` and `pragma_table_info` rather than the `information_schema` tables available in MySQL and PostgreSQL.