# Binary Exploitation

Challenges organized by the mitigation layer being bypassed or technique being applied.
Each folder contains the binary, a solve.py, and a README.md per challenge.

## Structure

| folder | technique | protections bypassed |
|---|---|---|
| [stack-basics/](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/stack-basics) | ret2win, variable overwrite, function pointer overwrite | none |
| [bof-canaries/](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/bof-canaries) | stack buffer overflow with canary bypass | stack canary |
| [bof-pie/](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/bof-pie) | stack overflow with canary + PIE leak | stack canary, ASLR/PIE |
| [shellcode/](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/shellcode) | injected shellcode via leaked stack address | NX disabled |
| [ret2libc/](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/ret2libc) | control flow redirection to shared library functions | NX enabled, No static wins |
| [rop/](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/rop) | gadget chaining for arbitrary execution / syscalls | NX enabled, ASLR enabled |

## Challenges

### stack-basics/

| challenge | type |
|---|---|
| [guestbook](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/stack-basics/guestbook) | ret2win |
| [whispering-wall](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/stack-basics/whispering-wall) | ret2win |
| [escape-room](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/stack-basics/escape-room) | ret2win + ROP args (pop rdi / pop rsi) |
| [lemonade-stand](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/stack-basics/lemonade-stand) | variable overwrite |
| [cosmic-burger](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/stack-basics/cosmic-burger) | two adjacent variable overwrites |
| [mini-game](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/stack-basics/mini-game) | function pointer overwrite |
| [enchanted-forest](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/stack-basics/enchanted-forest) | function pointer overwrite |
| [cafe-menu](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/stack-basics/cafe-menu) | off-by-one index corruption |

### bof-canaries/

| challenge | type |
|---|---|
| [pastry-shop](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/bof-canaries/pastry-shop) | canary leak via format string |
| [secret-library](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/bof-canaries/secret-library) | canary leak via format string |
| [parrot-cage](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/bof-canaries/parrot-cage) | canary leak via overflow echo (puts) |
| [fortune-cookie](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/bof-canaries/fortune-cookie) | canary brute-force (byte-by-byte) |
| [lighthouse](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/bof-canaries/lighthouse) | canary brute-force (byte-by-byte) |
| [weather-station](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/bof-canaries/weather-station) | canary brute-force (byte-by-byte) |

### bof-pie/

| challenge | type |
|---|---|
| [space-station](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/bof-pie/space-station) | canary + PIE base leak via format string |

### shellcode/

| challenge | type |
|---|---|
| [whispered-secrets](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/shellcode/whispered-secrets) | leaked stack address → injected shellcode |

### ret2libc/

| challenge | type |
|---|---|
| [aquabank-atm](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/ret2libc/aquabank-atm) | format string and BOF |
| [aquabank-vault](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/ret2libc/aquabank-vault) | out of bounds read and buffer overflow |
| [crystal-ball](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/ret2libc/crystal-ball) | basic BOF |
| [digital-postcard-writer](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/ret2libc/digital-postcard-writer) | 2 stage execution |
| [dusty-scrolls](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/ret2libc/dusty-scrolls) | standard ret2libc |
| [feedback-portal](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/ret2libc/feedback-portal) | format string vulnerability |
| [neon-dinner](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/ret2libc/neon-dinner) | ret2plt technique |

### rop/

| challenge | type |
|---|---|
| [aquabank-armory](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/rop/aquabank-armory) | buffer overflow |
| [aquabank-safe](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/rop/aquabank-safe) | information exposure and stack pivoting |
| [arsenal](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/rop/arsenal) | stack buffer overflow |
| [chain-reactor](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/rop/chain-reactor) | stack buffer overflow |
| [forge](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/rop/forge) | stack buffer overflow |
| [padlock](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/rop/padlock) | global offset table overwrite |
| [toolkit](https://github.com/gianmarcomichelini/Offensive-Security/tree/main/pwn/rop/toolkit) | basic stack BOF |