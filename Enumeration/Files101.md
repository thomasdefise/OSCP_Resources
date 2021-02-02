### File analysis on Linux

1. file *file.extension*
The [file](https://man7.org/linux/man-pages/man1/file.1.html) command is used to determine the type of a file.
2. strings *file.extension*
The [strings](https://man7.org/linux/man-pages/man1/strings.1.html) command the sequences of printable characters in files
3. ent *file.extension*
The more to 8 you get, the most random it is 

If you have an entropy between 4 and 5, there is a high chance that it is a ASCII file

### .kdbx

The **KDBX** file type is primarily associated with KeePass

```bash
for i in $(ls .); do keepass2john -k $i MyPasswords.kdbx | sed "d/MyPasswords/$i/g; done

keepass2john -k IMG_0547.JPG ./MyPasswords.kdbx > hash.tx
```

kpcli: https://www.youtube.com/watch?v=CO_g3wtC7rk

### .git

Within the .git directory we have interesting files

```bash
git log                  # Displays the commit history
git log --patch          # Shows the difference introduced in each commit.
git log --pretty=oneline # Displays the commit history (only the commit comment)
git log -3               # Display only the 3 most recent commits.
```

You can also use the following tools:

- [repo-security-scanner](https://github.com/UKHomeOffice/repo-security-scanner) is CLI tool that finds secrets accidentally committed to a git repo, eg passwords, private keys.
- [earlybird](https://github.com/americanexpress/earlybird) is a sensitive data detection tool capable of scanning source code repositories for clear text password violations, PII, outdated cryptography methods, key files and more.
- [git-hound](https://github.com/ezekg/git-hound) is a Git plugin that helps prevent sensitive data from being committed into a repository by sniffing potential commits against PCRE regular expressions.
- [truffleHog](https://github.com/dxa4481/truffleHog) searches through git repositories for secrets, digging deep into commit history and branches.

```bash
git log -p | scanrepo
# Launch EarlyBird scan against a directory
go-earlybird --path=/path/to/directory
# Scan a remote git repo
go-earlybird --git=https://github.com/victim/victim
# Sniff changes since last commit
git hound sniff HEAD
# Sniff entire codebase
git hound sniff
# Sniff entire repo history
git log -p | git hound sniff
# Searches through git repositories for secrets, digging deep into commit history and branches.
truffleHog --regex --entropy=False https://github.com/victim/victim 
```

### .vmdk

[vmdkReader](https://github.com/leftp/VmdkReader) is a .Net 4.0 Console App to read and extract files from vmdk images.

```bash
vmdk.exe --command dir --source \backupserver\dc01\dc01.vmdk --directory \Users\
```

### .pcap

[Pcapreader](https://github.com/raioramalho/Pcapreader) find passwords in .pcap files from wireshark and other apps

```bash
Pcapreader -f file.pcap
```

### .Exe

#### Strings

On Linux, you can use [strings](https://linux.die.net/man/1/strings) print the strings of printable characters in files.

```bash
strings64.exe
cmd /c "strings64.exe -accepteula firefox.exe_191129_211531.dmp > firefox.exe_191129_211531.txt"
findstr "password" ./firefox.exe_191129_211531.txt
```

#### Checksec

[checksec](https://www.trapkit.de/tools/checksec/) is a tool to check common security that mitigates binairies exploitation

```bash
checksec.sh --file /bin/file
```

- **Relocation Read-Only**: Make the relocation sections that are used to resolve dynamically loaded functions read-only.
- **NoExecute (NX)**: Technology used in CPUs to segregate areas of memory for use by either storage of processor instructions (code) or for storage of data.
An operating system with support for the NX bit may mark certain areas of memory as non-executable.
- **Stack Canaries**: Place a random integer at the program start just before the stack return pointer.
They are used to detect a stack buffer overflow before execution of malicious code can occur.
*Note that stack canaries suffer from the the following weaknesses:*

1) Rely on canary value(s) that are fixed for a given run of a program,
2) Store the reference canary in insecure memory, where an attacker can read or overwrite it,

- **Position Independent Executable (PIE)**: Executable binaries made entirely from position-independent code.
A PIE binary and all of its dependencies are loaded into random locations within virtual memory each time the application is executed,
- **Address Space Layout Randomization (ASLR)**: Randomly position the base address of an executable and the position of libraries

###### *If you don't know, now you know: [ELF Relocation Sections](https://medium.com/@HockeyInJune/relro-relocation-read-only-c8d0933faef3)*

A dynamically linked ELF binary uses a look-up table called Global Offset Table (GOT) to dynamically resolve functions that are located in shared libraries.

1) It call the Procedure Linkage Table (PLT), which exists in the .plt section of the binary.

```bash
objdump -M intel -d YOUR_BINARY
80484da:       e8 95 fe ff ff        call   8048374 <printf@plt>
```

2) That .plt section contains x86 instructions that points to the Global Offset Table *.got.plt*

```bash
08048374 <printf@plt>:
 8048374:       ff 25 54 97 04 08      jmp    DWORD PTR ds:0x8049754
 804837a:       68 20 00 00 00         push   0x20
 804837f:       e9 a0 ff ff ff         jmp    8048324 <_init+0x30>
```

3) This section contains binary data, either back to the Procedure Linkage Table or to the location of the dynamically linked function

```bash
Contents of section .got.plt:
 8049738 6c960408 00000000 00000000 3a830408  l...........:...
 8049748 4a830408 5a830408 6a830408 7a830408  J...Z...j...z...
 8049758 8a830408 9a830408                    ........
```

By default, the Global Offset Table is populated dynamically while the program is running.
The first time a function is called, the Global Offset Table contains a pointer back to the Procedure Linkage Table,
The location found is then **written** to the Global Offset Table.

The second time a function is called, the Global Offset Table contains the known location of the function. This is called “lazy binding.”
> *When generating an executable or shared library, mark it to tell the dynamic linker to defer function call resolution to the point when the function is called (lazy binding), rather than at load time. Lazy binding is the default.*

Since we know that the Global Offset Table lives in a predefined place and is writable, all that is needed is a bug that lets an attacker write four bytes anywhere.

To prevent the above exploitation technique, we can tell the linker to resolve all dynamically linked functions at the beginning of execution and make the Global Offset Table read-only.

### 7zip

[7z-BruteForce](https://github.com/Seyptoo/7z-BruteForce) is a python script to bruteforce 7z files

```bash
python server.py --files backup.7z --wordlist lists.txt
```

### Microsoft Outlook email folder

Outlook saves backup information in a variety of different locations. Depending on what type of account you have, you can back up your emails, your personal address book, your navigation pane settings, your signatures, templates, and more.

[readpst](https://linux.die.net/man/1/readpst) convert PST (MS Outlook Personal Folders) files to mbox and other formats

```bash
readpst file.ost
```

If there is a .mbox, it can be opened with evolution

### LUKS encrypted file

[LUKS](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup) implements a platform-independent standard on-disk format for use in various tools.
LUKS operates on Linux and is based on an enhanced version of cryptsetup, using dm-crypt as the disk encryption backend

[bruteforce-luks](https://github.com/glv2/bruteforce-luks) tries to find the password of a LUKS encrypted volume

```bash
bruteforce-luks -f ./PASSWORD ./FILE.img
cryptsetup open --type luks FILE.img test
```

#### Interesting file types

|Extension|Attached program|how to analyse the content|
|-|---------- | ----------- |
|.bundle|Git|git clone *file.bundle*|
|.db|SQlite|sqlite3 *user.db*|
|.zip|Zip Archive|du -hs *file.zip*<BR > nano file.zip.b64<BR > base64 -d backup.zip.b64 > backup.zip|
|.exe||strings -e l file.exe<br>strings -e L file.exe<br>strings -e b file.exe<br>strings -e s file.exe<br>strings -e S file.exe<br>|

References:

For the thanks to @HockeyInJune for the "ELF Relocation Sections" : <https://medium.com/@HockeyInJune/relro-relocation-read-only-c8d0933faef3>