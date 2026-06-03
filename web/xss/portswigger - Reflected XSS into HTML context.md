### Reflected XSS into HTML context - Reflected XSS

The laboratory environment, provided by the PortSwigger Web Security Academy and accessible at [https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded](https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded), consists of a simulated blog application designed to demonstrate fundamental injection principles. The architectural structure of this application includes a search form located at the top of every page, which issues a GET request with a search parameter, subsequently rendering a results page that incorporates the submitted query directly into the output string. The initial phase of exploitation requires the student to observe this reflection mechanism by submitting a benign search string, followed by a careful inspection of the HTTP response to determine precisely where the input materializes within the HTML document structure.

Before attempting to deploy a functional payload, it is necessary to confirm that the target application interprets raw HTML markup rather than securely escaping it, a verification process achieved by submitting a string containing an innocuous HTML tag, such as a bold element, and observing whether the rendered page source reflects the executed tag or the safe encoded entities. Because the injection point resides within an **HTML body** context entirely devoid of input filtering, the attacker operates within the most permissive execution environment possible, allowing for the direct insertion of executable code. The simplest payload designed to invoke the alert function and confirm code execution is an inline script block, constructed strictly as follows:



```HTML
<script>alert(1)</script>
```

> While the direct script tag efficiently demonstrates the vulnerability, several alternative tag and event handler combinations function equally well to achieve execution, such as image tags utilizing onerror handlers or scalable vector graphics leveraging onload handlers, which represent crucial alternatives to master because the standard script element is invariably the first signature targeted by defensive filters.

Although executing a simple alert function satisfies the immediate parameters of the exercise, transitioning this vulnerability into a practical real world attack requires recognizing that the payload is strictly reflected rather than stored on the server infrastructure. Because no other user will spontaneously encounter the malicious script by simply browsing the application, the attacker is forced to orchestrate an active delivery mechanism, typically involving social engineering tactics to trick the victim into visiting a specifically crafted Uniform Resource Locator that executes the payload within their trusted and authenticated browser session.

![](_attachments/portswigger%20-%20Reflected%20XSS%20into%20HTML%20context.png)