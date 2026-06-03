# BOF with Canary and PIE Bypass

Stack buffer overflow challenges where both a stack canary and PIE (Position Independent Executable) are active. PIE randomizes the binary's load address on every run, making all code pointers — including `win()` and any ROP gadgets — unpredictable without a runtime leak.

Both the canary and the PIE base are recovered from the stack through a single format string vulnerability before the overflow is triggered.

## Challenges

| challenge | technique | key concept |
|---|---|---|
| [space-station](space-station/) | format string dual leak + BOF | %15$lx = canary; %17$lx = saved RIP (main+62); PIE_base = leak − 0x139e; win() = PIE_base + 0x1275 |

## Exploit Flow

1. **Map the stack** — send a `%lx.%lx...` chain to the format string vulnerable input to identify which stack indices hold the canary and a code pointer.
2. **Leak in one shot** — use `%15$lx.%17$lx` to extract both values in a single request.
3. **Compute addresses** — `pie_base = leaked_rip - static_offset`; `win_addr = pie_base + exe.sym.win`; `ret_gadget = pie_base + 0x101a`.
4. **Overflow** — standard payload: `A * 72 + canary + B * 8 + ret_gadget + win_addr`.

## Key Concepts

**Finding the static offset of the leaked pointer:** attach GDB to the binary, break at the vulnerable function, inspect the saved return address on the stack (`$rbp + 0x8`), and compare it to the binary's known base address with `info proc mappings`.

**PIE-relative addressing:** `exe.sym.win` in pwntools returns the symbol's offset from the binary base. Add the leaked `pie_base` to compute the runtime address:
```python
pie_base = pie_leak - PIE_OFFSET
win_addr = pie_base + exe.sym.win
gadget   = pie_base + GADGET_OFFSET
```

**Input budget:** if the format string input is capped (e.g., 63 bytes), use direct-parameter-access specifiers (`%15$lx.%17$lx`) instead of a long sequential chain to stay within the limit.
