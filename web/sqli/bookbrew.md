## BookBrew - SQLi via Session Cookie (UNION-Based, SQLite)


> x Exam (29)


The BookBrew challenge presents itself as a cozy book review community where users can register, browse a catalog, and post reviews, with the vulnerability hiding not in the obvious login form but in how the session cookie is consumed after authentication. The registration flow appears entirely safe at first glance, and the login page offers no obvious injection surface, which makes the cookie the correct place to focus attention.

### Vulnerability Surface

After registering and logging in, the server issues a session cookie whose value is a base64-encoded JSON object, decoded as follows.

```json
{"uid": 9, "username": "admin_user"}
```

Because the encoding has a signature or integrity check, the server has the mechanism to detect tampering, which does not make every field inside the JSON object a direct injection vector. The `username` field in particular must be addressed during the registration procedure

### Reconnaissance and Column Count

The first step is to confirm the injection and establish the number of columns the vulnerable query selects, by replacing the `username` value with incrementally longer NULL-based payloads and re-encoding the entire JSON object to base64 before setting it as the session cookie.

```
' UNION SELECT null,null,null,null,null,null,null,null --
```

Eight NULLs produce a valid page response, confirming that the backend query selects exactly eight columns.

### Identifying Reflected Columns

To determine which of the eight columns are actually rendered in the HTML, the username is replaced with a payload that injects eight distinct string literals.

```sql
' UNION SELECT '1','2','3','4','5','6','7','8' --
```

<img src="_attachments/BookBrew - SQLi via Session Cookie (UNION-Based, SQLite).png" width="400">
<img src="_attachments/BookBrew - SQLi via Session Cookie (UNION-Based, SQLite)_1.png" width="400">


The page renders `h` and `g` in the review title area, `f` in the top-right corner, and `e` in the review body, confirming that columns five through eight are reflected, with column five being the most convenient output channel as it maps to the body text of each review card.


### Schema Enumeration

With the database engine confirmed, the full list of tables is retrieved by querying `sqlite_master` and reflecting the `name` column through position five.

```sql
' UNION SELECT '1','2','3','4',sql,'6','7',name from sqlite_master --
```

<img src="_attachments/BookBrew - SQLi via Session Cookie (UNION-Based, SQLite)_2.png" width="400">
<img src="_attachments/BookBrew - SQLi via Session Cookie (UNION-Based, SQLite)_3.png" width="400">


The page returns five table names across five review cards, specifically `books`, `reviews`, `secrets`, `sqlite_sequence`, and `users`, where `secrets` is immediately the anomalous entry and therefore the target.

The response reveals exactly two columns, `flag` and `id`, which makes the final extraction payload trivial to construct.

### Extracting the Flag


```sql
' UNION SELECT '1','2','3','4',flag,'6','7',id FROM secrets --
```

<img src="_attachments/BookBrew - SQLi via Session Cookie (UNION-Based, SQLite)_4.png" width="400">
