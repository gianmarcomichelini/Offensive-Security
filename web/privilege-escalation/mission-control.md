## Mission Control - Broken Access Control

We now direct our attention to the laboratory exercise known as Mission Control, where you are tasked with interacting with the Orbital Command web application, which serves as a platform to monitor active space missions and read crew briefings. Upon accessing the main dashboard, you will observe various system metrics alongside a notification in the upper section indicating that your current session operates under the clearance level of an operator, which inherently limits your privileges within the system. The primary objective of this assessment requires you to access a specific classified briefing that is strictly reserved for higher-ranking personnel, given that the application enforces an access check designed to prevent unauthorized viewing.

When you attempt to access the restricted Starfall briefing and intercept the resulting network traffic, you will notice that the application sends an HTTP GET request to the `/api/briefings/starfall` endpoint, which includes a custom HTTP header named `X-Clearance-Level` that is explicitly set to the value of operator. The backend server processes this request and subsequently returns a 403 Forbidden status code, where the accompanying JSON response body contains an error message stating that access is denied because Commander clearance is required. This behavior strongly suggests that the authorization mechanism relies entirely on the client-supplied header rather than a secure backend session validation, which presents a significant **Broken Access Control** vulnerability.

To successfully bypass this restriction, you must intercept the outgoing request and manipulate the `X-Clearance-Level` header, replacing the original value with commander, before allowing the modified request to reach the server. Because the application blindly trusts the input provided in the HTTP headers without performing proper server-side verification, it processes the forged request and responds with a 200 OK status code, returning the complete JSON payload of the classified Operation Starfall briefing, where you will finally uncover the authorization code.



```JSON
{
  "id": "starfall",
  "title": "Operation Starfall: Final Directive",
  "date": "2026-03-10",
  "classified": true,
  "summary": "Eyes only - Commander clearance required.",
  "content": "CLASSIFIED TRANSMISSION - COMMANDER EYES ONLY\n\nOperation Starfall is authorized for immediate execution. All orbital assets are to be repositioned per Directive 7-Alpha. The primary payload delivery window opens at 0347 UTC.\n\nAuthorization Code: offsec{cl34r4nce_byp4ss_jKOAB3Mfp3LM3VOj}\n\nThis briefing will self-destruct upon acknowledgment. Confirm receipt via secure channel OMEGA-3."
}
```

<img src="_attachments/Mission%20Control%20-%20Broken%20Access%20Control.png" width="400">