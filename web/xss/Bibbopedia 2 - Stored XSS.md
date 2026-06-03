### Bibbopedia 2 - Stored XSS

The formal documentation of the Bibbopedia 2 exploitation sequence illustrates the absolute necessity of transitioning from traditional token extraction methodologies toward an action as victim paradigm when confronted with modern session defenses. The architectural analysis of the collaborative wiki environment reveals that the application strictly enforces the HttpOnly attribute upon the administrative session cookies, a configuration that definitively prevents the JavaScript engine from accessing the authentication material and renders conventional exfiltration strategies entirely obsolete. To circumvent this structural limitation, the adversary must leverage the identified persistent Cross Site Scripting vulnerability within the edit proposal functionality to establish an execution foothold directly within the trusted browser session of the automated administrative bot, thereby acquiring the capability to issue authenticated requests on behalf of the highly privileged victim.

The optimal exploitation sequence requires the construction of an elegant, self approving modification proposal deployed directly upon the restricted gabibbo page, seamlessly integrating the malicious programmatic instructions within the benign informational content. To ensure reliable execution, the payload utilizes a standard image element configured with an intentionally malformed source attribute, which guarantees the invocation of the associated error handler when the browser inevitably fails to resolve the designated resource. Because the backend authorization logic explicitly demands the submission of the specific parameters associated with the approval button, the injected JavaScript must interface with the Document Object Model to locate the precise element bearing the required name attribute, subsequently simulating a native user interaction via the programmatic click function.

The complete piece of code utilized to achieve this authorization bypass is constructed precisely as follows:



```HTML
<h1>Gabibbo</h1>
<p>Belandi!</p>
<img src="http://example.com" onerror="document.getElementsByName('yes')[0].click()">
```

When the automated administrative bot navigates to the review endpoint to inspect the pending modification, the browser parses the Document Object Model, attempts to load the fictitious image source, and immediately executes the injected error handler within the context of the highly privileged session. This execution forces the browser to construct and dispatch a properly formatted POST request that inherently includes the required HttpOnly cookies, deceiving the backend infrastructure into accepting the forged authorization exactly as if the administrator had manually approved the modification. Following the successful processing of this forged request, the backend logic permanently alters the restricted page, allowing the adversary to subsequently navigate to the approved gabibbo entry utilizing their own unprivileged browser, where the successful exploitation culminates in the visible manifestation of the target flag.

![](_attachments/Bibbopedia%202%20-%20Stored%20XSS.png)

![](_attachments/Bibbopedia%202%20-%20Stored%20XSS_1.png)

![](_attachments/Bibbopedia%202%20-%20Stored%20XSS_3.png)

![](_attachments/Bibbopedia%202%20-%20Stored%20XSS_2.png)
