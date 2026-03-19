# Binary Exploitation

Challenges organized by the mitigation layer being bypassed or technique being applied.
Each folder contains the binary, a `solve.py`, and a `README.md` per challenge.

---

## Structure

| folder | technique | protections bypassed |
|---|---|---|
| [`stack-basics/`](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/stack-basics) | ret2win, variable overwrite, function pointer overwrite | none |
| [`bof-canaries/`](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/bof-canaries) | stack buffer overflow with canary bypass | stack canary |
| [`bof-pie/`](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/bof-pie) | stack overflow with canary + PIE leak | stack canary, ASLR/PIE |
| [`shellcode/`](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/shellcode) | injected shellcode via leaked stack address | NX disabled |

---

## Challenges

### stack-basics/

| challenge | type |
|---|---|
| [guestbook](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/stack-basics/guestbook) | ret2win |
| [whispering-wall](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/stack-basics/whispering-wall) | ret2win |
| [escape-room](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/stack-basics/escape-room) | ret2win + ROP args (pop rdi / pop rsi) |
| [lemonade-stand](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/stack-basics/lemonade-stand) | variable overwrite |
| [cosmic-burger](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/stack-basics/cosmic-burger) | two adjacent variable overwrites |
| [mini-game](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/stack-basics/mini-game) | function pointer overwrite |
| [canary-callback](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/stack-basics/canary-callback) | function pointer overwrite |
| [cafe-menu](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/stack-basics/cafe-menu) | off-by-one index corruption |

### bof-canaries/

| challenge | type |
|---|---|
| [pastry-shop](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/bof-canaries/pastry-shop) | canary leak via format string |
| [secret-library](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/bof-canaries/secret-library) | canary leak via format string |
| [parrot-cage](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/bof-canaries/parrot-cage) | canary leak via overflow echo (puts) |
| [fortune-cookie](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/bof-canaries/fortune-cookie) | canary brute-force (byte-by-byte) |
| [lighthouse](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/bof-canaries/lighthouse) | canary brute-force (byte-by-byte) |
| [weather-station](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/bof-canaries/weather-station) | canary brute-force (byte-by-byte) |

### bof-pie/

| challenge | type |
|---|---|
| [space-station](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/bof-pie/space-station) | canary + PIE base leak via format string |

### shellcode/

| challenge | type |
|---|---|
| [whispered-secrets](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/binary/shellcode/whispered-secrets) | leaked stack address → injected shellcode |

