# Binary Exploitation

Challenges organized by mitigation layer and technique. Each category builds on the previous, introducing new protections to bypass. Every challenge folder contains the binary artifacts, a `solve.py` exploit, and a `README.md` writeup.

## Categories

| folder | technique | protections bypassed |
|---|---|---|
| [stack-basics/](stack-basics/) | ret2win, variable overwrite, function pointer overwrite | none |
| [bof-canaries/](bof-canaries/) | canary leak and byte-by-byte brute-force | stack canary |
| [bof-pie/](bof-pie/) | canary + PIE base leak via format string | stack canary, ASLR/PIE |
| [shellcode/](shellcode/) | injected shellcode via leaked stack address | NX disabled |
| [ret2libc/](ret2libc/) | control flow redirection to libc functions | NX, no static win function |
| [rop/](rop/) | gadget chaining for arbitrary execution and raw syscalls | NX, ASLR, partial RELRO |
| [heap/](heap/) | heap metadata corruption and tcache exploitation | heap mitigations |

## Challenges

### stack-basics/

| challenge | technique | key concept |
|---|---|---|
| [guestbook](stack-basics/guestbook/) | ret2win | gets() into 64-byte buf, 72-byte offset to RIP, ret gadget for alignment |
| [whispering-wall](stack-basics/whispering-wall/) | ret2win | gets() into 16-byte buf, 24-byte offset to RIP |
| [escape-room](stack-basics/escape-room/) | ret2win + ROP args | pop rdi / pop rsi gadgets to satisfy win(0xdeadbeef, 0xcafebabe) |
| [lemonade-stand](stack-basics/lemonade-stand/) | stack variable overwrite | volatile int target at offset 76, overwrite with p32(0x1337) |
| [cosmic-burger](stack-basics/cosmic-burger/) | multi-variable overwrite | cheese at offset 40 + sauce at offset 44, both in one payload |
| [mini-game](stack-basics/mini-game/) | function pointer overwrite | func_ptr declared after buf[64], PIE off, replace with p64(win()) |
| [enchanted-forest](stack-basics/enchanted-forest/) | struct function pointer overwrite | struct { incantation[64]; void(*cast)(); }; read() overwrites cast |
| [cafe-menu](stack-basics/cafe-menu/) | loop index corruption canary skip | struct idx at offset 48 overwritten to 71 → next write lands on RIP |

### bof-canaries/

| challenge | technique | canary bypass method |
|---|---|---|
| [parrot-cage](bof-canaries/parrot-cage/) | canary leak via puts echo | overflow the null LSB → puts prints past canary, recover 7 bytes |
| [pastry-shop](bof-canaries/pastry-shop/) | canary leak via format string | printf(name) format string → %23$lx leaks canary |
| [secret-library](bof-canaries/secret-library/) | format string + BOF | printf(buf) → %23$lx leak, then 512-byte overflow into 128-byte buf |
| [fortune-cookie](bof-canaries/fortune-cookie/) | canary brute-force (fork oracle) | fork() preserves canary per-run, byte-by-byte oracle, 1792 max attempts |
| [lighthouse](bof-canaries/lighthouse/) | canary brute-force (fork oracle) | "recorded" response as oracle signal, 128-byte buf, 136-byte offset |
| [weather-station](bof-canaries/weather-station/) | canary brute-force (fork oracle) | two-prompt protocol per probe, "Forecast sent!" oracle, 56-byte offset |

### bof-pie/

| challenge | technique | key concept |
|---|---|---|
| [space-station](bof-pie/space-station/) | canary + PIE leak via format string | %15$lx = canary, %17$lx = saved RIP; win() = PIE_base + static_offset |

### shellcode/

| challenge | technique | key concept |
|---|---|---|
| [whispered-secrets](shellcode/whispered-secrets/) | ret2shellcode | NX disabled, printf leaks buf addr at runtime, shellcraft.sh() at buf[0] |

### ret2libc/

| challenge | technique | leak primitive |
|---|---|---|
| [neon-dinner](ret2libc/neon-dinner/) | ret2plt | No ASLR bypass needed — system() + /bin/sh already in binary |
| [dusty-scrolls](ret2libc/dusty-scrolls/) | 2-stage ret2libc | puts(puts@GOT) → libc base, then system("/bin/sh"), 72-byte offset |
| [digital-postcard-writer](ret2libc/digital-postcard-writer/) | 2-stage ret2libc | Same two-stage pattern, 136-byte offset, Ubuntu 24.04 libc |
| [crystal-ball](ret2libc/crystal-ball/) | 2-stage ret2libc | gets() overflow, puts(puts@GOT) leak, gifted pop_rdi_ret symbol |
| [feedback-portal](ret2libc/feedback-portal/) | format string + BOF | %15$s dereferences GOT pointer via stack-resident addr; libc gadgets |
| [aquabank-atm](ret2libc/aquabank-atm/) | format string + BOF | %1$p leaks _IO_2_1_stdout_ + 131 → libc base, fgets 256 into 64-byte buf |
| [aquabank-vault](ret2libc/aquabank-vault/) | OOB read + BOF + canary | fwrite(buf, 1, 256) leaks canary + libc ptr, then BOF with restored canary |

### rop/

| challenge | technique | key concept |
|---|---|---|
| [toolkit](rop/toolkit/) | ROP with 3 register args | Named pop rdi/rsi/rdx gadgets; win(0x111..., 0x222..., 0x333...) |
| [chain-reactor](rop/chain-reactor/) | ROP without symbol names | ROPgadget finds pop rdi/rsi; win(0xc0ffee, 0xbadc0de) |
| [forge](rop/forge/) | shellcode + mprotect ROP | Shellcode in BSS, mprotect(page, 0x1000, 7) grants RWX, then jump |
| [arsenal](rop/arsenal/) | syscall ROP chain | read(0, BSS, 8) writes "/bin/sh"; execve(BSS, 0, 0) via syscall 59 |
| [aquabank-armory](rop/aquabank-armory/) | syscall ROP chain | Same read + execve chain with named pop_rdi/rsi/rdx/rax gadget symbols |
| [padlock](rop/padlock/) | GOT overwrite | add [rdi], rsi gadget converts atoi@GOT → system; next input = "/bin/sh" |
| [aquabank-safe](rop/aquabank-safe/) | info leak + stack pivot | diagnostics() leaks printf + PIE; ROP chain in vault[]; leave;ret pivot |

### heap/

> Work in progress — challenges under active development.

| challenge | technique |
|---|---|
| account-vault | heap exploitation |
| recycler | heap exploitation |
| notebook | heap exploitation |
