### SpreadSheetZero - Formula Evaluation


> x Exam (29)

Analyzing the provided visual evidence reveals a critical architectural flaw within the SpreadSheet Zero application. The spreadsheet interface allows users to input mathematical formulas prefixed with an equals sign, which are subsequently transmitted to the backend server for dynamic computation. The defining diagnostic clue regarding the backend technology lies in the specific error message returned in cell D6. The string **#ERR: invalid syntax (, line 1)** is a classic and unmodified exception trace generated natively by the Python interpreter when it encounters malformed input within an `eval()` execution sink. This definitively categorizes the underlying vulnerability as a Python code injection rather than a standard operating system command injection.

The payload attempted in the screenshot utilized the dollar sign prefix to reference the target variable. This resulted in a syntax error because that specific notation is exclusive to shell environments like Bash or sh. The Python interpreter strictly expects valid Python syntax, rendering the shell variable reference unparseable and causing the evaluation process to fail immediately before any underlying logic could be executed.

### Exploiting the Python Execution Context for Memory Introspection

To successfully exfiltrate the target artifact, the payload must be formulated using native Python syntax capable of introspecting the environment variables of the hosting container. The objective is to force the spreadsheet's formula engine to evaluate a Python expression that reads the memory state and returns the secret string back to the frontend cell.

> The most direct method for accessing operating system level environment variables within a dynamic Python evaluation sink involves utilizing the built-in `__import__` function to dynamically load the `os` module during runtime execution.

Once the module is dynamically loaded into the execution context, the payload can access the `environ` dictionary, which contains all environment variables currently mapped to the active process. By requesting the specific key corresponding to the target secret, the interpreter will extract the string and return it as the definitive mathematical result of the formula evaluation.



```Python
=__import__('os').environ['FLAG']
```

![](_attachments/Calcolatrice%20-%20The%20Transition%20to%20Code%20Injection%20via%20PHP%20Evaluation_5.png)

In the event that the developer has implemented a basic static blacklist filtering the `import` keyword or the literal `os` string, the advanced evasion techniques explored in the prior Python sandbox module must be deployed. This alternative approach would involve traversing the object hierarchy utilizing `().__class__.__base__.__subclasses__()` to locate a previously loaded module with access to the global built-ins, subsequently extracting the environment dictionary without ever relying on direct import statements. Absent such a strict filter, the direct dynamic import remains the most efficient and reliable exploitation vector to reveal the hidden flag within the spreadsheet interface.