# Return Oriented Programming (ROP)

Advanced exploitation using gadget chains for precise register control, raw syscall invocation, GOT manipulation, and stack pivoting. These challenges go beyond a simple libc redirect and require constructing purpose-built execution chains from existing binary instructions.

## Challenges

| challenge | technique | core mechanism |
|---|---|---|
| [toolkit](toolkit/) | ROP with 3 register args | Named pop rdi/rsi/rdx gadgets; call win(0x111..., 0x222..., 0x333...) |
| [chain-reactor](chain-reactor/) | ROP without symbol names | ROPgadget discovers unlabeled pop rdi/rsi; win(0xc0ffee, 0xbadc0de) |
| [forge](forge/) | shellcode + mprotect ROP | Shellcode written to BSS; mprotect(page, 0x1000, 7) marks it RWX; jump in |
| [arsenal](arsenal/) | syscall ROP chain | read(0, BSS, 8) writes "/bin/sh\0"; execve(BSS, NULL, NULL) via syscall 59 |
| [aquabank-armory](aquabank-armory/) | syscall ROP chain | Same read+execve chain with explicitly exported pop_rdi/rsi/rdx/rax+syscall symbols |
| [padlock](padlock/) | GOT overwrite | `add [rdi], rsi` gadget increments atoi@GOT by delta(system−atoi); next call to atoi becomes system |
| [aquabank-safe](aquabank-safe/) | info leak + stack pivot | diagnostics() leaks printf (libc) and &diagnostics (PIE); ROP chain staged in vault[]; leave;ret pivots stack |

## Key Concepts

**Gadget discovery:**
```bash
ROPgadget --binary ./binary | grep "pop rdi"
ROPgadget --binary ./binary | grep ": ret$"
ropper --file ./binary --search "pop rdi"
```

**Syscall numbers (x86-64 Linux):**
| syscall | RAX | RDI | RSI | RDX |
|---|---|---|---|---|
| read | 0 | fd (0=stdin) | buf addr | count |
| execve | 59 | path ptr | argv ptr (0) | envp ptr (0) |
| mprotect | 10 | addr (page-aligned) | len | prot (7=RWX) |

**Page alignment for mprotect:**
```python
page = elf.sym.shellcode & ~0xfff   # mask lower 12 bits
```

**GOT overwrite (padlock pattern):**
```python
delta = (libc.sym.system - libc.sym.atoi) & 0xffffffffffffffff
# then: add [atoi_got], delta → atoi_got now points to system
# send "/bin/sh" as next input → system("/bin/sh")
```

**Stack pivot (aquabank-safe pattern):**
```
leave  = mov rsp, rbp; pop rbp
ret    = pop rip
```
Overwrite saved RBP with `target_stack − 8` and saved RIP with `leave;ret`. When the function returns, `leave` sets RSP to the fake stack address and `ret` begins executing the chain there.

**Statically linked binaries** (arsenal-type): the entire libc is compiled in, providing thousands of gadgets. Find `pop rax; ret`, `pop rdx; ret`, and `syscall; ret` with ROPgadget.
