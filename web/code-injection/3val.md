### Advanced Python Sandboxes and Code Execution Evasion

#### Vulnerability Analysis and Environmental Constraints

The target application for this exercise is a Bank-Loan Calculator operating on a Python Flask backend. The core vulnerability stems from the application accepting a mathematical formula via a POST parameter and passing it directly to Python's `eval()` function, which inherently transforms the application into an arbitrary code execution vector.

To mitigate this risk, the developers implemented a custom sandbox utilizing a dual-layer filtering mechanism. The first layer consists of a strict keyword blacklist that actively rejects inputs containing essential operational substrings such as `os`, `eval`, `exec`, `bind`, `connect`, `python`, `socket`, `ls`, `cat`, and `shell`. The second layer is a regular expression designed to block alternative encoding techniques, forbidding hexadecimal literals, Unicode escapes, percent encoding, standard file extensions, and all forward or backward path slashes.

> The fundamental flaw in this defensive architecture is the reliance on static text analysis to secure a dynamic interpreter, as the Python engine can express identical semantic operations through a vast array of syntactical constructions that evade simple pattern matching.

#### Bypassing Static Path Restrictions via Dynamic Construction

The primary objective is to read the contents of a hidden file located at `/flag.txt`. However, the regular expression filter explicitly blocks both the forward slash required for directory traversal and the `.txt` extension required to target the specific file. Because the static analyzer only evaluates the raw text submitted in the HTTP request, the restriction can be circumvented by dynamically constructing the targeted string within the interpreter's memory during runtime.

By utilizing the native `chr()` function, which converts integer ASCII values back into their corresponding string characters, the forbidden characters can be generated synthetically. These individual characters are then concatenated with the permissible alphabetical strings to formulate the complete file path.



```Python
chr(47) + "flag" + chr(46) + "txt"
```

#### Navigating the Object Hierarchy to Access Built-in Functions

With the file path successfully constructed, the next requirement is to execute a file read operation without utilizing any of the blacklisted keywords like `os` or invoking functions directly that might trigger the static analysis. This is achieved by exploiting the dynamic nature of Python's object model to traverse the memory hierarchy and locate globally loaded modules.

The traversal begins by instantiating a basic empty tuple. From this foundational object, the internal memory hierarchy is navigated using the `__class__` and `__base__` attributes to reach the root object class. Subsequently, the `__subclasses__()` method is invoked to generate an array of all subclasses currently loaded within the Flask application's memory space.

To access the restricted execution environment, the attacker must locate a specific class within this array that maintains references to the global namespace. The `catch_warnings` class, a component of the standard `warnings` module, is an ideal target as it is almost universally present and its instantiated wrapper contains a pathway back to the global `__builtins__` dictionary.

#### Synthesizing the Final Payload and Mitigating Substring Collisions

A critical complication arises during the synthesis of the final payload due to the behavior of the keyword blacklist. While attempting to target the `catch_warnings` class, the contiguous substring `cat` triggers the blacklist, generating a false positive for a Unix command injection attempt. To evade this substring collision, the target class name is split and dynamically concatenated during the evaluation phase, utilizing a list comprehension to isolate the correct class reference.

Once the `catch_warnings` class is successfully isolated and instantiated, the payload navigates through its `_module` attribute to access the `__builtins__` dictionary. This dictionary houses the raw, unblocked reference to the native `open` function. The dynamically constructed file path is then passed as an argument to this function, and the `read()` method is appended to extract the file contents.



```Python
[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'c' + 'atch_warnings'][0]()._module.__builtins__['open'](chr(47) + "flag" + chr(46) + "txt").read()
```

Submitting this precise formula completely bypasses both the regular expression sanitization layer and the keyword blacklist, forcing the Python interpreter to read the targeted file from the underlying filesystem and render the hidden flag directly to the web interface.

<img src="_attachments/3v%40l%20-%20Advanced%20Python%20Sandboxes%20and%20Code%20Execution%20Evasion.png" width="300">

<img src="_attachments/3v%40l%20-%20Advanced%20Python%20Sandboxes%20and%20Code%20Execution%20Evasion_1.png" width="300">


<img src="_attachments/3v%40l%20-%20Advanced%20Python%20Sandboxes%20and%20Code%20Execution%20Evasion_2.png" width="400">

<img src="_attachments/3v%40l%20-%20Advanced%20Python%20Sandboxes%20and%20Code%20Execution%20Evasion_3.png" width="400">




