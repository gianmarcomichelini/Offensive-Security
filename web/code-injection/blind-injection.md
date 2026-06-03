### PortSwigger - Blind OS command injection with output redirection

The laboratory progresses to a critical scenario frequently encountered in modern web application assessments, specifically the exploitation of blind command injection vulnerabilities. The PortSwigger Web Security Academy provides an optimal environment for this study through the lab located at [https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection](https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection). In this simulated e-commerce architecture, a global feedback form accepts user input across several fields, submitting them via a POST request to the `/feedback/submit` endpoint. The backend mechanism incorporates these user-supplied details into a server-side shell command. Crucially, the application never returns the standard output of this command within the HTTP response, establishing the blind nature of the vulnerability where visual confirmation of execution is entirely absent.

To circumvent this limitation, the attacker must engineer a strategy to redirect the execution output to a secondary, readable location. The laboratory description reveals a structural flaw, noting that the application serves product images from the `/var/www/images/` directory through the `GET /image?filename=...` endpoint, and this specific folder is writable by the web server process.

The exploitation phase begins by identifying the `email` parameter within the intercepted request as the primary injection vector. To execute an arbitrary payload, one must carefully escape the original command structure. The injected payload relies on logical shell operators to manipulate the execution flow:


```sh
||whoami>/var/www/images/output.txt||
```

<img src="_attachments/PortSwigger%20-%20Blind%20OS%20command%20injection%20with%20output%20redirection.png" width="500">

The mechanics of this payload are highly precise. The initial double pipe constitutes a shell short-circuit OR operator. By providing an invalid email format, the attacker guarantees the failure of the initial mail command, which forces the shell to execute the subsequent `whoami` command. The output of `whoami` is then redirected via the greater-than operator into a text file within the writable image directory. Finally, the trailing double pipe absorbs any residual arguments from the original command line, ensuring they do not cause syntax errors that would halt execution.

During this exploitation, it is imperative to retain the original CSRF token and session cookie within the request, as omitting them will trigger an HTTP error or initiate a fresh session. Upon submission, the server returns an empty JSON object, offering no direct confirmation, which aligns perfectly with the expected behavior for a blind vulnerability. The exfiltrated data is subsequently retrieved by issuing a direct GET request to the image endpoint for the newly created text file.

<img src="_attachments/PortSwigger%20-%20Blind%20OS%20command%20injection%20with%20output%20redirection_1.png" width="400">

> Blind command injection requires the attacker to leverage observable side effects to confirm execution and extract data. When writable directories are unavailable, professionals rely on out-of-band channels to trigger external network requests, or they utilize time-based payloads to infer success through measurable application delays.