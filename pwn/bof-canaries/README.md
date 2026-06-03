# BOF with Stack Canary Bypass

Stack buffer overflow challenges where a canary guard sits between the buffer and the saved RIP. Two bypass strategies appear across these challenges: **leak the canary** (from a format string or an echo primitive) and **brute-force the canary** (possible only when the server uses `fork()` rather than `exec()`).

All binaries have: **canary enabled, NX enabled, PIE disabled**.

## Challenges

| challenge | technique | canary bypass |
|---|---|---|
| [parrot-cage](parrot-cage/) | canary leak via puts echo | Overflow the null LSB → puts keeps printing past the canary boundary, exposing 7 random bytes |
| [pastry-shop](pastry-shop/) | canary leak via format string | greet() calls printf(name) → inject %23$lx to read the canary off the stack |
| [secret-library](secret-library/) | format string + BOF | printf(buf) exposes the canary at index 23; a second 512-byte read into 128-byte buf delivers the ROP chain |
| [fortune-cookie](fortune-cookie/) | canary brute-force (fork oracle) | fork() child shares the parent's canary; wrong byte crashes the child silently, correct byte returns "OK" |
| [lighthouse](lighthouse/) | canary brute-force (fork oracle) | fork() server; "recorded" in the response confirms survival; 128-byte buf, 136-byte offset to canary |
| [weather-station](weather-station/) | canary brute-force (fork oracle) | Two-prompt protocol per probe; "Forecast sent!" as oracle; 56-byte offset to canary |

## Exploit Template

Once the canary is known the payload structure is always the same:

```python
payload = flat(
    b'A' * OFFSET_TO_CANARY,                      # fill up to the canary slot
    p64(canary),                                   # restore the canary intact
    b'B' * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8), # overwrite saved RBP
    p64(GADGET),                                   # ret — 16-byte stack alignment
    p64(exe.sym.win),                              # redirect RIP to win()
)
```

## Key Concepts

**Stack canary position:** always at `rbp - 0x8`. Measure offset from buffer start with cyclic + GDB:
```
pwndbg> print $rbp - 0x8     # address of canary slot
pwndbg> print *<addr>         # read value there (cyclic bytes if overflowed)
pwndbg> cyclic -l <value>     # offset from buffer start
```

**Canary structure:** the least-significant byte (lowest address on x86-64 little-endian) is always `0x00`, acting as a null terminator to stop string leaks. When brute-forcing, start `known = b"\x00"` and recover 7 bytes.

**Why fork() matters:** `fork()` copies the parent's address space, preserving the canary. `exec()` re-randomizes it. Byte-by-byte brute-force is only feasible against fork-based servers.

**Format string canary leak:** the canary consistently appears at argument index 23 of printf in these binaries (`%23$lx`). Confirm empirically by sending `%1$lx.%2$lx...` and identifying the value ending in `00`.
