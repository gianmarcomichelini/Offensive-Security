### GitPeek - Vulnerable Variable Expansion


> x Exam (28)


#### Vulnerability Context and Architecture

The GitPeek application presents an online interface designed to allow users to browse repository commits by supplying a branch or tag name. The underlying architecture dynamically constructs a system shell command, specifically appending the user-supplied reference directly to a `git log` invocation. By placing excessive trust in the user input without implementing parameterized execution arrays or rigorous sanitization routines, the application inadvertently creates a direct pathway for command injection, exposing the host container's execution environment. Furthermore, intelligence gathered regarding the target architecture indicates that the objective secret is maintained strictly within the `FLAG` environment variable inside the container, necessitating an exfiltration strategy capable of dumping active memory states rather than reading static filesystem artifacts.

#### Defensive Mechanisms and Shell Parsing

The application employs a rudimentary defensive mechanism utilizing a blacklist filter designed to intercept standard command separators, such as semicolons or ampersands. When an attacker attempts to break out of the initial execution context to run a secondary standalone command, the application gracefully halts execution and returns a validation error indicating that forbidden characters were detected. To circumvent this static filter, the exploitation strategy must pivot away from command chaining and instead leverage the native parsing sequence of the operating system shell. The Unix shell performs variable expansion prior to passing arguments to the invoked binary, allowing an attacker to reference environment variables utilizing the dollar sign prefix, which the developer failed to include in the restricted character set.

#### Error-Based Data Exfiltration

The final phase of the exploit synthesizes the shell expansion bypass with an error-based exfiltration technique. By injecting the carefully crafted payload into the repository search field, the shell intercepts the input, expands the environment variable into its literal string value, and constructs the final command string.



```sh
main $FLAG
```

Upon execution, the shell evaluates the `FLAG` variable and passes the resulting string to the `git log` utility alongside the valid `main` branch reference. Because the expanded flag constitutes a highly unique and invalid Git revision, the `git` binary naturally encounters a fatal exception. The resulting standard error message explicitly complains about the ambiguous argument and directly echoes the unknown revision string back to the user interface. By capturing this diagnostic output in the frontend error console, the application inadvertently leaks the highly sensitive internal environment variable, successfully revealing the target artifact `offsec{g1t_p33k_cmd_sub_7Re5CU3FVsiyJJov}` without ever executing a secondary shell command.