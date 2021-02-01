




Entry point is set by the compiler 

The SFP is used to restore EBP to its previous value, and the
return address is used to restore EIP to the next instruction found after the
function call

procedure prologue or function prologue:  save the frame pointer on the stack, and they save stack memory for the local function variables.




The where command will
sometimes show a useful backtrace of the stack

(gdb) where




NOP is an
assembly instruction that is short for no operation. It is a single-byte instruction
that does absolutely nothing.

NOP is an
assembly instruction that is short for no operation. It is a single-byte instruction
that does absolutely nothing.

The environment variables are located near the bottom of the stack

 x/24s $esp + 0x240

### Vulnerable C function

static variables retain their values, but also because
they are only initialized once


strcpy(), strcmp(), strcat() do not check the length of the variable and can overwrite later memory addresses

No op 





gcc -g -fno-stack-protector -z execstack -o overflowtest overflowtest.c

- **-g**: Tells GCC to add extra debugging information for GDB, the GNU debugger.
- **-fno-stack-protector**: Turn off GCC’s stack-protection mechanism
- **-z execstack**: Makes the stack executable (buffer overflow prevention method)


return-to-libc" attack : https://en.wikipedia.org/wiki/Return-to-libc_attack



gef allows you to search for a specific pattern at runtime in all the segments of your process memory layout. 
gef➤ search-pattern MyPattern

gef➤  pattern search 0x6161616161616167
[+] Searching '0x6161616161616167'
[+] Found at offset 48 (little-endian search) likely
[+] Found at offset 41 (big-endian search)


Return-oriented programming (ROP) is a computer security exploit technique that allows an attacker to execute code in the presence of security defenses[1] such as executable space protection and code signing.

https://github.com/sashs/Ropper

gef➤ info functions # Dislays the list of functions in the debugged program
gef➤ disassemble # Disassembles a specified function or a function fragment.



rbp is the frame pointer on x86_64.
rdi

sp (r13), lr (r14), and pc (r15)

https://0xrick.github.io/hack-the-box/safe/


To defeat ASLR our first rop chain will leak __libc_start_main by calling puts() with __libc_start_main@plt address as an argument. Then by subtracting __libc_start_main@@GLIBC address from the leaked address we will get the base address of libc. https://github.com/sashs/Ropper

https://0xrick.github.io/hack-the-box/ellingson/



If Gidhra don't work, use currer.re



- - - 



- [heap]: The heap of the program, which is a segment of memory we can control
The heap don't have a fixed size.
- [stack]: The stack of the main process. It is used as a temporary scratch pad to store local function variables and context during function calls.
- [vdso]: the "virtual dynamic shared object", the kernel system call handler


Stack Pointer (SP), and the other is called the Frame Pointer (FP). SP always points to the "top" of the stack, and FP always points to the "top" of the frame. Additionally

https://www.youtube.com/watch?v=qSnPayW6F7U&list=PLLKT__MCUeix3O0DPbmuaRuR_4Hxo4m3G



 In C’s standard
library there is a function called getenv(), which accepts the name of an environment variable as its only argument and returns that variable’s memory address.

When compiled and run, this program will display the location of a given
environment variable in its memory. This provides a much more accurate
prediction of where the same environment variable will be when the target
program is run.

The fork() function starts a new process, 

The use of system() can sometimes cause problems. If a setuid program
uses system(), the privileges won’t be transferred, because /bin/sh has been
dropping privileges since version two.

The execl() function belongs to a family of functions that execute commands by replacing the current process with the new one.

The execl() function has a sister function called execle(), which has one
additional argument to specify the environment under which the executing
process should run.

With execl(), the existing environment is used, but if you use execle(),
the entire environment can be specified.  If the environment array is just the
shellcode as the first string (with a NULL pointer to terminate the list), the
only environment variable will be the shellcode. 

### A Basic Heap-Based Overflow

ln -s /bin/bash /tmp/etc/passwd
myroot:XXq2wKiyI43A2:0:0:me:/root:/tmp/etc/passwd

### Overflowing Function Pointers

The nm command lists symbols in object files.