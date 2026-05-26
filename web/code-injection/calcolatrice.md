### Calcolatrice - The Transition to Code Injection via PHP Evaluation

#### Conceptualizing the Interpreter Sink

We now pivot our focus from the operating system shell to a strictly more powerful attack surface. Up to this point in our laboratory session, we have examined command injection, where user input is ultimately parsed and executed by utilities like Bash or sh. In Exercise 5, titled "Calcolatrice" and accessible via the OliCyber Training platform at [https://training.olicyber.it/challenges#challenge-555](https://www.google.com/search?q=https://training.olicyber.it/challenges%23challenge-555), we encounter a scenario where the receiving component is the language interpreter itself.

The application presents a simplified web calculator designed to accept complex mathematical expressions, such as `5+2*pow(3,6)-126`, submitted through a POST request parameter logically named `expression`. To process this mathematical input dynamically, the backend application relies on the PHP `eval()` function, which evaluates a given string as raw PHP code. This architectural choice transforms the vulnerability from command injection into pure code injection.

How to discover it (let it crash):
![[ff.png]]

#### The Mechanics and Severity of the `eval()` Vulnerability

> Code injection is strictly more dangerous than command injection because the attacker is no longer constrained by the limited syntax and available binaries of the initial shell environment, but rather gains the full semantic power of the host language to interact directly with internal filesystem operations, network sockets, and database connections.

Your immediate objective is to craft a payload that breaks out of the expected arithmetic context, allowing you to inject and execute arbitrary PHP instructions. While the application's source code is not provided to you initially, the `index.php` file is the only file residing in the web root, meaning you can read its contents programmatically once you achieve initial code execution.

However, the laboratory guidelines provide a critical piece of intelligence regarding your ultimate objective. Once you possess the ability to execute arbitrary PHP, you will discover that the target flag is not located in a standard file on the filesystem. You must consider the architecture of modern web applications and determine where else a running process maintains state and stores secrets. In PHP environments, sensitive configuration data is frequently loaded directly into memory upon execution, making it accessible through environment variables, globally defined constants, or active session arrays. To retrieve the flag, you will need to utilize native PHP functions capable of dumping these internal memory structures rather than relying on standard file reading utilities.



![[Calcolatrice - The Transition to Code Injection via PHP Evaluation_2.png | 500 ]]

```php
show_source('index.php'); // 
```

![[Calcolatrice - The Transition to Code Injection via PHP Evaluation_3.png | 500]]

```php
phpinfo(); // 
```

And then search for the flag in the env variables:

![[Calcolatrice - The Transition to Code Injection via PHP Evaluation_4.png | 500 ]]



#### Structural Mitigation for Code Execution

The theoretical defense against this vulnerability is identical in spirit to the mitigations we discussed for command injection, dictating that user-supplied data must never be passed directly to an execution interpreter. In practical software engineering, the safest and most absolute rule is to categorically avoid invoking functions like `eval()`, `exec()`, JavaScript's `Function()`, or any insecure deserialization routines on data that has originated from, or been influenced by, an end user. If a mathematical calculator is required, the developer should utilize a dedicated, safe parsing library that tokenizes the math rather than executing the raw string as application code.

