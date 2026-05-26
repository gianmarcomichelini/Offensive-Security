## StagePass - SQLi via Numeric Input with WAF Bypass (UNION-Based, SQLite)


> x Exam (26)


StagePass is a concert ticketing platform that exposes a reservation lookup form accepting a numeric booking number, and the challenge description hints that security measures are in place to prevent abuse, inviting the question of whether those measures are truly sufficient to protect the VIP guest list hidden somewhere in the backend database.

### Vulnerability Surface

The Check Reservation page accepts a plain integer booking ID and reflects a rich set of fields in the response, including event name, artist, status, confirmation code, guest name, email, ticket count, section, venue, date, and booking timestamp. Because the input is numeric, the backend query most likely takes the form `WHERE id = <input>` with no surrounding string delimiters, which means no quote character is needed to break out of the injection context, a fact that also bypasses many naive WAF rules that specifically watch for single quotes.

### WAF Identification and Bypass Strategy

The first injection attempt, submitting `1001 and 1=1` with a plain space, immediately triggers the error `Security filter: Whitespace characters are not allowed`, revealing that the application performs client-side or server-side filtering on whitespace. A natural first bypass attempt is to replace spaces with the SQL inline comment sequence `/**/`, which most databases treat as equivalent to whitespace, but the filter additionally strips forward slashes, causing `/**/` to degrade to `**` and produce a SQLite syntax error.

The working bypass combines two evasion techniques simultaneously: replacing every whitespace character with `/**/` to satisfy the space filter, and applying mixed case to every SQL keyword, such as `uniOn`, `selEct`, `fROM`, `WhERE`, to defeat any case-sensitive keyword blacklist. The resulting injection separator `/**/` passes through the filter intact because the slash stripping observed earlier was specific to a different payload structure, and the mixed-case keywords evade any keyword-based block list.

The confirmed working boolean test that validates the injection is the following pair of payloads, where the first returns Marco Bianchi's reservation normally and the second returns nothing.

```
1001/**/AND/**/1=1
1001/**/AND/**/1=2
```

### Database Fingerprinting

The error message returned during early probing, specifically `[better-sqlite3] near "*": syntax error`, immediately identifies the backend database engine as SQLite running through the better-sqlite3 Node.js driver, which is functionally equivalent to standard SQLite for injection purposes and confirms that schema enumeration must rely on `sqlite_master` and `pragma_table_info` rather than `information_schema`.

### Column Count and Reflected Position Mapping

Column count is established by incrementally extending a UNION SELECT payload with additional NULL values until the page renders a card without error, confirming exactly twelve columns. To identify which positions are reflected in the HTML, all twelve columns are replaced with distinct string literals.

```
1001/**/uniOn/**/selEct/**/'a','b','c','d','e','f','g','h','i','j','k','l'/**/--
```

The rendered card reveals the following column-to-field mapping, where column 1 maps to CONFIRMATION, column 2 to GUEST, column 3 to EMAIL, column 4 to TICKETS, column 5 to SECTION, column 7 to BOOKED, column 8 to the event title, column 9 to the artist subtitle, column 10 to VENUE, column 11 to DATE, and column 6 to the status badge.

### Schema Enumeration

With the injection confirmed and columns mapped, the full table list is retrieved by querying `sqlite_master` and reflecting the `tbl_name` column through position 1, using `-1` as the booking ID to suppress any real rows and ensure only the injected output is rendered.

```
-1/**/uniOn/**/selEct/**/tbl_name,'b','c','d','e','f','g','h','i','j','k','l'/**/fROM/**/sqlite_master/**/WhERE/**/type='table'--
```

The response returns three tables across three separate cards: `events`, `reservations`, and `vip_guestlist`, where the last one is the obvious target given the challenge description.

### Column Enumeration of the Target Table

The columns of `vip_guestlist` are retrieved using SQLite's `pragma_table_info` function, which is available inline within a UNION query and returns one row per column with the column name accessible via the `name` field.

```
-1/**/uniOn/**/selEct/**/name,'b','c','d','e','f','g','h','i','j','k','l'/**/fROM/**/pragma_table_info('vip_guestlist')/**/--
```

The response reveals four columns: `id`, `guest_name`, `event_id`, and `access_note`, where `access_note` is the obvious candidate for storing the flag or privileged access information.

### Flag Extraction

The final payload selects `guest_name` into position 1 and `access_note` into position 2, dumping the entire VIP guest list in a single request.

```
-1/**/uniOn/**/selEct/**/guest_name,access_note,'c','d','e','f','g','h','i','j','k','l'/**/fROM/**/vip_guestlist/**/--
```

The response renders all six VIP guests alongside their access notes, and a seventh row contains the entry with `guest_name = 'VIP Access Key'` and `access_note` holding the flag directly.


### Full Attack Chain

The complete sequence proceeds as follows: first, probing the numeric input with a boolean true condition to confirm injection in a quote-free numeric context, then identifying the whitespace filter via the error message and discovering that `/**/` combined with mixed-case keywords successfully bypasses both the space filter and any keyword blacklist, then establishing the column count as twelve via incremental NULL extension, then mapping reflected columns by injecting string literals, then enumerating tables via `sqlite_master` to identify `vip_guestlist` as the target, then enumerating its columns via `pragma_table_info`, and finally extracting the full table contents to recover the flag from the `access_note` field.

### Root Cause

The vulnerability originates from direct string concatenation of the booking number parameter into the SQL query without parameterization. The WAF attempts to compensate for this by blocking spaces and monitoring keywords, but both restrictions are trivially circumvented by comment-based whitespace substitution and mixed-case keyword obfuscation respectively, demonstrating that input filtering applied on top of fundamentally insecure query construction is never a reliable mitigation. The correct fix is a parameterized query, which eliminates injection entirely regardless of what the input contains.

```javascript
// Vulnerable
db.prepare(`SELECT * FROM reservations WHERE id = ${bookingId}`).get();

// Safe fix
db.prepare(`SELECT * FROM reservations WHERE id = ?`).get(bookingId);
```

### Key Takeaways

WAF filters that block specific characters or keywords are a defense-in-depth measure at best and a false sense of security at worst, since comment sequences and mixed-case keywords reliably bypass the most common implementations. Numeric injection contexts require no quote characters and therefore evade a large class of WAF rules that specifically watch for single-quote injection patterns. Schema enumeration in SQLite always relies on `sqlite_master` for table discovery and `pragma_table_info` for column discovery, since `information_schema` is not available. Parameterized queries remain the only reliable mitigation against SQL injection regardless of the injection context or the presence of filtering layers.