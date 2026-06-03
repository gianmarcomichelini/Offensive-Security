### Segnalazione cinghiali cittadini - Attribute Context XSS

The third practical engagement of our laboratory, accessible via the OliCyber Training platform at [https://training.olicyber.it/challenges#challenge-721](https://www.google.com/search?q=https://training.olicyber.it/challenges%23challenge-721), directs our attention toward an application designed for citizens to file boar sighting reports. This platform accepts an address alongside an optional photograph Uniform Resource Locator, and upon the successful submission of a report, the backend infrastructure immediately provisions an automated administrative bot that authenticates as an administrator and visits the specific report page at the designated endpoint. Within the Document Object Model of this administrative view, the user supplied photograph Uniform Resource Locator is embedded directly into the source attribute of an image element, and the page concurrently features an exclusive administrative approval form labeled precisely as **Approva segnalazione**. The operational logic dictates that if the administrator approves the sighting, the server dynamically replaces the original reported address with the objective flag.

The core vulnerability emerges from an incomplete sanitization implementation, as the application attempts to mitigate Cross-Site Scripting by explicitly filtering the less than and greater than angular brackets from the input fields, yet critically neglects to sanitize the quotation mark that serves to delimit the HTML attribute. Because the injection sink is situated within an existing image tag, the attacker operates within an attribute context, rendering the server-side filtration of angular brackets entirely ineffective.

```HTML
<img src="user_supplied_input">
```

First try (example of segnalazione):

![](_attachments/Segnalazione%20cinghiali%20cittadini%20-%20Attribute%20Context%20XSS.png)

The exploitation, in order to obtain the flag the segnalazione must be approved by an administrator (by submitting the button related to "Approva segnalazione", i.e. the first form of the rendered web page):

To achieve code execution, the adversary must supply a crafted string that first closes the legitimate source attribute using a quotation mark, and subsequently injects a malicious event handler, which contains the JavaScript payload necessary to programmatically submit the administrative approval form. When the input is reflected, the resulting HTML structure forces the browser to evaluate the injected code.

The resulting script processed by the browser must be (DONE using Burp Suite Interceptor): 

```HTML
<img src="https://example.com" onerror="document.forms[0].submit()">
```

The exploit is:

```plaintext
https://example.com" onerror="document.forms[0].submit()
```

Once the automated bot visits the manipulated report, the browser attempts to load the malformed image source, triggers the injected error handler, and executes the payload within the privileged administrative session, thereby approving the report and revealing the target flag upon subsequent inspection of the page.

> The context of the injection point strictly determines the appropriate exploitation strategy, and because an attribute context only requires the adversary to close the encapsulating quotation mark, defensive mechanisms relying exclusively on the filtration of angular brackets provide no security whatsoever, underscoring the absolute necessity of utilizing context aware output encoding across all application sinks.

