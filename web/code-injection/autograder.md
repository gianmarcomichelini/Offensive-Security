### AutoGrader - Python Sandbox Evasion and Object Hierarchy Traversal


> x Exam (30)

#### Vulnerability Context and Environmental Constraints

The AutoGrader platform, deployed by the Computer Science department, introduces a highly restrictive Python evaluation environment designed to safely execute untrusted student submissions. To enforce this architectural isolation, the application implements a stringent static blacklist, categorically denying access to essential system operations by explicitly blocking keywords and functions such as `import`, `open()`, `read()`, `exec()`, `eval()`, `system()`, `getattr()`, and the foundational `__builtins__` dictionary. The fundamental vulnerability within this defensive posture lies in its reliance on static string matching to secure a dynamic, object-oriented interpreter, allowing an attacker to leverage Python's native introspection capabilities to bypass the lexical filters entirely and access the targeted `/flag.txt` artifact.

#### Navigating the Minimalist Memory Space

The initial exploitation vector in Python sandbox evasion typically involves instantiating a primitive object and traversing its inheritance tree via `().__class__.__base__.__subclasses__()` to locate functional modules like `FileIO` or `catch_warnings`. However, the AutoGrader environment presents an additional layer of complexity through its extreme minimalism, as standard peripheral modules are deliberately excluded from the initial bootstrapping sequence to reduce the attack surface. Attempting to target these conventional classes results in an empty array and a subsequent `IndexError`, necessitating a strategic pivot toward core initialization components that are universally guaranteed to reside within the interpreter's memory space, such as the `_ModuleLock` class utilized by Python's internal import machinery.

#### Traversing the Global Namespace and Evading the Lexical Filter

Once the ubiquitous `_ModuleLock` class is successfully identified within the subclass array, the execution flow must traverse into its internal structures to recover the restricted global namespace. Because the class requires specific, unknown arguments for standard instantiation, the payload bypasses the constructor entirely by accessing the uninstantiated `__init__` method directly and extracting its `__globals__` dictionary.

With access to the global environment secured, the payload must circumvent the static analyzer's prohibition of the `__builtins__` and `open` keywords. This is achieved dynamically by fragmenting the forbidden strings and utilizing standard concatenation, such as `'__built' + 'ins__'`, forcing the interpreter to reassemble the critical access pathways during runtime execution without ever triggering the static blacklist.

#### Synthesizing the Final Exfiltration Payload

The final phase of the exploit requires executing the reconstructed file reading operation while evading the explicit block placed on the `read()` method. By substituting the forbidden method with the unrestricted `.readlines()` function, the payload achieves the identical objective of extracting the complete file contents into memory.

The synthesized code perfectly adheres to the expected structural constraints of the homework assignment, acting as a functional algorithmic wrapper that covertly maps the core memory space, bypasses all static character filters, and returns the hidden flag directly to the automated grading interface.



```Python
def fibonacci(n):
    return [c for c in ().__class__.__base__.__subclasses__() if c.__name__ == '_ModuleLock'][0].__init__.__globals__['__built' + 'ins__']['op' + 'en']('/flag.txt').readlines()
```