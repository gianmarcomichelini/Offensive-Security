## Secret Library - ret2win with Canary Leak 

### Phase 0 - Challenge Triage

The binary sub-category here is a combination of format string vulnerability and stack buffer overflow, where the format string is used as an info-leak primitive to recover the stack canary and the overflow is used to redirect execution. A `win()` function is present in the binary, so no libc leak or ROP chain is needed beyond a single alignment gadget.

The artifacts provided are the C source (`main.c`), the compiled ELF (`secret_library`), and the final working exploit (`solve.py`).

Initial hypothesis: this challenge is a classic canary-leak-then-overflow scenario, because the source exposes a direct `printf(buf)` call that leaks arbitrary stack values and a subsequent unchecked `read()` that overflows the same buffer well past its declared size.

### Phase 1 - Reconnaissance and Enumeration

From the source, the binary is a 64-bit Linux ELF. The protections that matter here are the stack canary, which is confirmed by the exploit reading it at format string index 23, and NX, which is implied by the use of a `ret` gadget for stack alignment rather than any injected shellcode. PIE is disabled, since the exploit uses a static hardcoded gadget address (`0x000000000040101a`) and calls `exe.sym.win` directly without any base-address calculation.

The `setup()` function disables buffering on all three standard streams, which is standard CTF scaffolding and has no security relevance. The interesting functions are `vuln()`, which contains both vulnerabilities, and `win()`, which calls `system("/bin/sh")` and is the target of the redirect.

### Phase 2 - Vulnerability Identification

Two distinct vulnerabilities are present in `vuln()`, and they must be chained together.

The first is a format string vulnerability on the line `printf(buf)`, where `buf` is filled directly by `read(0, buf, 127)` with no sanitization. Because the format string is user-controlled and passed as the first argument to `printf`, the attacker can use positional specifiers such as `%N$lx` to read arbitrary 64-bit values off the stack, including the stack canary sitting at index 23.

The second is a classic stack buffer overflow: `buf` is declared as `char buf[128]`, but the second `read()` call in the same function reads up to 512 bytes into it, giving 384 bytes of overflow space, which is more than enough to reach and overwrite the saved return address after restoring the canary.

The root cause of the format string bug is that the developer passed user input directly as the format string rather than as an argument, i.e., `printf(buf)` instead of `printf("%s", buf)`. The root cause of the overflow is the mismatch between the declared buffer size (128 bytes) and the read limit (512 bytes).

### Phase 3 - Exploitation Plan

```
TARGET VULNERABILITY: Format string (canary leak) + stack buffer overflow (ret2win)
GOAL: Redirect execution to win() and get a shell
APPROACH:
  Step 1 — Send a format string payload (%23$lx) in the first read to leak the canary
  Step 2 — Parse the leaked value from the printf output
  Step 3 — Build an overflow payload: buffer fill → restored canary → RBP filler → ret gadget → win()
TOOLS: pwntools
RISK OF FAILURE: Wrong canary index (off by one in the format string); incorrect OFFSET_TO_CANARY (would corrupt the canary slot); missing ret gadget causing stack misalignment before the call to system() inside win()
```

### Phase 4 - Exploit Development

The stack layout inside `vuln()` is as follows: `buf` occupies 128 bytes, but `OFFSET_TO_CANARY` is 136, meaning there are 8 bytes of compiler-inserted padding between the end of the declared array and the canary slot. `OFFSET_TO_RIP` is computed as `OFFSET_TO_CANARY + 16`, i.e., 152 bytes, because after the canary come 8 bytes of saved RBP and then the saved return address.

The leak phase sends `%23$lx` as a format string, then reads back the response after the `Hello,` prefix and parses the hexadecimal canary value. The overflow phase then builds the payload using `flat()`, filling the buffer up to the canary offset with `A` bytes, placing the recovered canary, filling the RBP slot with `B` bytes, inserting a `ret` gadget for 16-byte stack alignment (required because `system()` uses SSE instructions that fault on a misaligned stack), and finally placing the address of `win()`.

One minor style note with respect to the canonical template: the exploit uses `HOST, PORT` as variable names instead of the required `HOSTNAME, PORT`, and passes `checksec=False` to the `ELF()` constructor. These are small deviations from the house style but do not affect correctness.

### Phase 6 - Writeup

**Category:** Binary Pwn **Difficulty:** Easy/Medium **Flag:** obtained via interactive shell after redirect to `win()`

**Vulnerability:** `vuln()` contains two bugs used in sequence. The first is a format string vulnerability (`printf(buf)`) that exposes the stack canary at format string argument index 23. The second is a stack buffer overflow (`read(0, buf, 512)` into a 128-byte buffer) that allows overwriting the saved return address after the canary is known and can be restored correctly.

**Exploit:** The exploit connects to the remote service, sends `%23$lx` during the guestbook prompt to leak the canary, then sends a crafted 152-byte payload during the review prompt that fills the buffer, restores the canary, pads the RBP slot, aligns the stack with a bare `ret` gadget, and redirects execution to `win()`, which calls `system("/bin/sh")`.

**Fix:** The format string bug is fixed by replacing `printf(buf)` with `printf("%s", buf)`, eliminating the ability to use the input as a format string. The overflow is fixed by changing the second `read()` call to read at most `sizeof(buf)` bytes, i.e., `read(0, buf, sizeof(buf))`. Enabling PIE would additionally prevent the use of static gadget addresses, making the overflow significantly harder to exploit even if the canary were somehow bypassed by other means.