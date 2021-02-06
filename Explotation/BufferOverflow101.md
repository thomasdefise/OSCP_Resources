
# Concepts

## Assemby

### Assembly Syntax

x86 assembly language has two main syntax branches:

- **Intel Syntax**: Originally used for documentation of the x86 platform. The Intel syntax is dominant in the DOS and Windows world.
- **AT&T Syntax**:  AT&T syntax is dominant in the Unix world, since Unix was created at AT&T Bell Labs.

Here below is a comparaison between the two

||AT&T|Intel|
|-|-|-|
|Parameter order|Source before the destination|Destination before source|
|Parameter size|Mnemonics are suffixed with a letter indicating the size of the operands: q for qword, l for long (dword), w for word, and b for byte.|Derived from the name of the register that is used (e.g. rax, eax, ax, al imply q, l, w, b, respectively).|

To show that, we will use [objdump](https://linux.die.net/man/1/objdump) which displays information about one or more object files.

```bash
# Print 10 lines of trailing context after  matching lines containing "<main>:"
objdump -D a.out | grep -A10 "<main>:"
0000000000001135 <main>:
    1135:       55                      push   %rbp
    1136:       48 89 e5                mov    %rsp,%rbp
    1139:       48 83 ec 10             sub    $0x10,%rsp
    113d:       c7 45 fc 00 00 00 00    movl   $0x0,-0x4(%rbp)
    1144:       eb 10                   jmp    1156 <main+0x21>
    1146:       48 8d 3d b7 0e 00 00    lea    0xeb7(%rip),%rdi        # 2004 <_IO_stdin_used+0x4>
    114d:       e8 de fe ff ff          callq  1030 <puts@plt>
    1152:       83 45 fc 01             addl   $0x1,-0x4(%rbp)
    1156:       83 7d fc 09             cmpl   $0x9,-0x4(%rbp)
    115a:       7e ea                   jle    1146 <main+0x11>

# Print 10 lines of trailing context after  matching lines containing "<main>:"
objdump -D -M intel a.out | grep -A10 "<main>:"
0000000000001135 <main>:
    1135:       55                      push   rbp
    1136:       48 89 e5                mov    rbp,rsp
    1139:       48 83 ec 10             sub    rsp,0x10
    113d:       c7 45 fc 00 00 00 00    mov    DWORD PTR [rbp-0x4],0x0
    1144:       eb 10                   jmp    1156 <main+0x21>
    1146:       48 8d 3d b7 0e 00 00    lea    rdi,[rip+0xeb7]        # 2004 <_IO_stdin_used+0x4>
    114d:       e8 de fe ff ff          call   1030 <puts@plt>
    1152:       83 45 fc 01             add    DWORD PTR [rbp-0x4],0x1
    1156:       83 7d fc 09             cmp    DWORD PTR [rbp-0x4],0x9
    115a:       7e ea                   jle    1146 <main+0x11>
```
