## Enchanted Forest - Function Pointer Overwrite

The `enchanted_forest` binary presents itself with a name that implies a canary bypass is required, but the actual exploitation path is more direct: a stack-resident struct in `vuln()` places a `void (*cast)(void)` function pointer immediately after a 64-byte character buffer, and an unchecked `read()` call allows overwriting that pointer with the address of `win()`, causing a shell to spawn when `spell.cast()` is invoked.

### Phase 0 - Challenge Triage

The binary sub-category is a stack buffer overflow targeting a function pointer embedded in a local struct, with no canary bypass required because the write stops before the canary slot. The artifacts provided are the `enchanted_forest` ELF binary and its C source `main.c`. The initial hypothesis is: this challenge looks like a function pointer overwrite because `vuln()` declares a struct with `char incantation[64]` followed immediately by `void (*cast)(void)`, and `read(STDIN_FILENO, spell.incantation, 128)` allows writing 128 bytes into that 64-byte field, meaning 64 bytes of padding followed by 8 bytes of `win()`'s address land precisely on `cast`, which is then called directly by `spell.cast()`.

### Phase 1 - Reconnaissance & Enumeration

```bash
checksec --file=./enchanted_forest
```

The exploit script loads the binary with `checksec=False`, so no live output was captured, but the protections can be confidently inferred from the source and the exploit's behavior.

|Protection|Status|Implication|
|---|---|---|
|Stack Canary|❓ Possibly present|Irrelevant: the payload is exactly 72 bytes and overwrites `cast` at struct offset 64, never reaching the canary slot higher in the frame|
|NX|✅ Enabled|Shellcode injection into `incantation` is not possible, but `win()` already exists in `enchanted_forest` and requires no injected code|
|PIE|❌ Not present|`win()` resolves to a static address via `exe.sym.win`, and `GADGET` is defined as a full static address `0x000000000040101a`, confirming position-independent loading is off|
|RELRO|❓ Unknown|No GOT writes are performed in this exploit, so RELRO status has no bearing on the approach|

Reading `main.c`, the binary defines four functions: `setup()`, which disables buffering on all three standard streams; `default_spell()`, which prints a flavour-text message; `win()`, which spawns `/bin/sh` via `execve("/bin/sh", argv, NULL)` and is marked `__attribute__((noreturn))`; and `vuln()`, which contains the vulnerable struct and the unchecked `read()`. The `main()` function calls `setup()` and then immediately calls `vuln()`, so there is no additional logic to navigate.

### Phase 2 - Vulnerability Identification

The vulnerability is a stack buffer overflow into a function pointer, produced by `vuln()`. Inside that function, a struct is declared on the stack with two fields in adjacent memory: `char incantation[64]` at struct offset 0, and `void (*cast)(void)` at struct offset 64. The pointer is initialised to `default_spell` before any input is read. The call `read(STDIN_FILENO, spell.incantation, 128)` then accepts up to 128 bytes of input starting at the base of the 64-byte `incantation` field, meaning any input longer than 64 bytes overflows into `cast`. Since the compiler places the struct fields contiguously with no padding between a 64-byte array and an 8-byte pointer on a 64-bit target, writing 64 bytes of fill followed by an 8-byte address puts an attacker-controlled value directly into `cast`. The line `spell.cast()` immediately after the `read()` then performs an indirect call through the corrupted pointer, transferring control to wherever it now points. The challenge name is a deliberate misdirection: the word "canary" evokes a stack canary bypass, but because the overwrite stops at struct offset 72 (64 fill plus 8 for the pointer), it never reaches the canary slot further up in the stack frame, making canary handling entirely unnecessary.

### Phase 3 - Exploitation Plan

```
TARGET VULNERABILITY: Stack buffer overflow into struct function pointer in vuln()
GOAL: Redirect the spell.cast() indirect call to win() and obtain a shell
APPROACH:
  Step 1: Send 64 bytes of padding to fill spell.incantation[64] completely
  Step 2: Append p64(exe.sym.win) to overwrite the cast pointer at struct offset 64
  Step 3: The read() returns, spell.cast() fires, execve("/bin/sh", ...) runs
TOOLS: pwntools
```

### Phase 4 - Exploit Development

#### Mapping the Struct Layout and Identifying the Overflow

Reading `main.c`, `vuln()` declares:

```c
struct {
    char incantation[64];
    void (*cast)(void);
} spell;
```

On a 64-bit system the compiler lays these fields out with no padding: `incantation` occupies bytes 0–63 of the struct, and `cast` occupies bytes 64–71. The `read()` call accepts 128 bytes into `spell.incantation`, so writing exactly 72 bytes places the last 8 bytes directly into `cast` and stays well within the 128-byte read limit, meaning neither the canary nor the saved RIP is disturbed.

#### Confirming the win() Address and Building the Payload

Since PIE is disabled, `exe.sym.win` resolves to a fixed address at load time. The payload is constructed as 64 bytes of `b'A'` to fill `incantation`, followed by `p64(exe.sym.win)` to overwrite `cast`. When `spell.cast()` executes, control transfers to `win()`, which calls `execve("/bin/sh", argv, NULL)` and delivers the shell.

|What|Value|
|---|---|
|`incantation` buffer size|64 bytes|
|Offset to `cast` pointer|64 bytes from start of struct|
|Total payload length|72 bytes|
|`win()` address|`exe.sym.win` (resolved at runtime, PIE off)|

### The Exploit

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./enchanted_forest", checksec=False)
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_CAST = 64   # size of incantation[64]; cast pointer sits here

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── exploit phase ─────────────────────────────────────────────────────────
    r.recvuntil(b'Whisper your incantation:\n')

    payload = flat(
        b'A' * OFFSET_TO_CAST,
        p64(exe.sym.win),
    )
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()
```

`r.send()` is used instead of `r.sendline()` because appending a trailing `0x0a` newline byte would corrupt the least-significant byte of the `win()` address packed into the function pointer slot.