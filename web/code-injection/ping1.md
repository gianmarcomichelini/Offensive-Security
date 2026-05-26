### Ping1 - Unrestricted Command Execution via Ping Interface

The foundational scenario involves a basic command injection vulnerability located within a web-based network utility. This specific environment is hosted on the root-me platform, accessible at [https://www.root-me.org/en/Challenges/Web-Server/PHP-Command-injection](https://www.root-me.org/en/Challenges/Web-Server/PHP-Command-injection). The application presents a simplified form containing a single text field designed to accept an IP address, which subsequently sends a POST request containing the parameter `ip` to the backend script `index.php`. The backend server executes a `ping` command against the provided address and displays the standard output directly within a `<pre>` HTML block.

Because the application implements absolutely no input filtering, the user-supplied string is appended verbatim into the executing shell command. An attacker can terminate the initial `ping` operation by utilizing standard shell control operators. The shell interprets the semicolon character as an unconditional command separator, allowing the subsequent string to be evaluated as a distinct, new command. Other logical operators, including the double ampersand for conditional execution based on success, the double pipe for conditional execution based on failure, and the single pipe for redirecting standard output, are equally viable in this unrestricted context.



```Bash
127.0.0.1; ls -r /
```
![[Foundations of Command and Code Injection Vulnerabilities.png | 300]]


```sh
127.0.0.1; find  / -name "ch*"
```

![[Foundations of Command and Code Injection Vulnerabilities_1.png | 300]]

```sh
127.0.0.1; ls -la ./
```

![[Foundations of Command and Code Injection Vulnerabilities_2.png | 300]]

The password is in the file `.passwd`

Submitting this payload forces the shell to execute the network diagnostic, immediately followed by listing the contents of the current working directory. This exposes the fundamental mental model for exploiting these flaws, which requires identifying the execution sink, breaking out of the original command structure, and appending the malicious payload.