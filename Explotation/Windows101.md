vssadmin


Plink is a command-line connection tool similar to UNIX ssh.

### ASEPs

#### Registry

##### Run & RunOnce

Run and RunOnce registry keys cause programs to run each time that a user logs on.
The data value for a key is a command line no longer than 260 characters.

reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

# reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v 1 /d "C:\temp\evil[.]dll"


reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunService
reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService
reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService

##### Service Runs

HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices 
HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices

##### RunOnceEx

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx


#### BootExecute 



#### Keys used by WinLogon Process

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify

https://pentestlab.blog/tag/userinit/

#### Startup Keys



Thanks to

- https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries#runs