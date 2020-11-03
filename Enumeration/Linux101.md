### System Information

##### Distribution 

- cat [/etc/issue](https://man7.org/linux/man-pages/man5/issue.5.html): text file which contains a message or system identification to be printed before the login prompt.
- cat /etc/*-release
- cat [/etc/lsb-release](https://linux.die.net/man/1/lsb_release): contain the LSB_VERSION field. The value of the field should be a colon separated list of supported module versions indicating the LSB specification modules to which the installation is compliant. 
- cat /etc/redhat-release
- [lsb_release](https://linux.die.net/man/1/lsb_release) -all: Prints certain LSB (Linux Standard Base) and Distribution information

##### Kernel Version

- at [/proc/version](https://docs.fedoraproject.org/en-US/Fedora/14/html/Deployment_Guide/s2-proc-version.html): This file specifies the version of the Linux kernel, the version of gcc used to compile the kernel, and the time of kernel compilation.
- [uname -a](https://linux.die.net/man/1/uname): Print all system information
- [uname -mrs](https://linux.die.net/man/1/uname): Print the machine hardware name *m*, kernel release *r* and the kernel-name *s*
- rpm -q kernel: Print the kernel version using the RPM Package Manager
- [dmesg](https://man7.org/linux/man-pages/man1/dmesg.1.html) | grep Linux: Print or control the kernel ring buffer
- ls /boot | grep vmlinuz-: Grep the name the Linux kernel executable within the boot partition

### Cron Jobs

Since Cron runs as root when executing /etc/crontab, any commands or scripts that are called by the crontab will also run as root. 

```bash
crontab -e # Edit the current crontab using the  editor specified by the VISUAL or EDITOR environment variables.
crontab -l # Display all user's jobs in cron / crontab
```

- /etc/crontab: System crontab. Cron will run as the **root** user when executing scripts and commands in this file.
- /etc/anacrontab: Cron will run as the **root** user when executing scripts and commands in this file.
*Nowadays the file is empty by default.
Originally it was usually used to run daily, weekly, monthly jobs. By default these jobs are now run through anacron which reads /etc/anacrontab configuration file.*
- /var/spool/cron: *Directory that contains user crontables created by the crontab command.*
- /etc/cron.d: *Directory that contains system cronjobs stored for different users.*

Cron examines all stored crontabs and checks each job to see if it needs to be run in the current minute.

1. Search if there are script executed that you can write
2. Search for wildcard injection vulnerability
   
   **Chown** has a *--reference=some-reference-file* flag, which specifies that the owner of the file should be the same as the owner of the reference file. An example should help:



##### Sudoers

```bash
echo "vickie ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
```

##### $PATH
```bash
echo $PATH
```
If you notice '.' in environment PATH variable it means that the logged user can execute binaries/scripts from the current directory and it can be an excellent technique for an attacker to escalate root privilege.

```bash
find / -perm -u=s -type f # Search for program with the SUID
find / -perm -g=s -type f # Search for program with the SGID
```



###### *If you don't know, now you know: [PATH]()*

PATH is an environmental variable in Linux and Unix-like operating systems which specifies all bin and sbin directories that hold all executable programs are stored.
When the user run any command on the terminal, its request to the shell to search for executable files with the help of PATH Variable in response to commands executed by a user. 

###### *If you don't know, now you know: [SUID & SGID]()*

- **SUID** (**S**et owner **U**ser **ID** up on execution) is defined as giving temporary permissions to a user to run a program/file with the permissions of the file owner rather that the user who runs
- **SGID** (**S**et owner **G**roup **ID** up on execution) same as SUID for groups.

### Linux Processes
1. pspy

[pspy](https://github.com/DominicBreuker/pspy#how-it-works) is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. 
It heavily uses the [inotify API](https://man7.org/linux/man-pages/man7/inotify.7.html) provides a mechanism for monitoring filesystem events.
Inotify can be used to monitor individual files, or to monitor directories.


### Linux Capabilities 
1. getcap

The [getcap](https://www.man7.org/linux/man-pages/man8/getcap.8.html) command displays the name and capabilities of each specified file.
To recursively check the capabilities of all files you have access, use the following command **getcap -r / 2>/dev/null**
For instance, you can find Python or Perl that are assigned to root and you can do the following then:
- ./python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
- ./perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'


###### *If you don't know, now you know: [Capabilities](https://linux.die.net/man/7/capabilities)*

Starting with kernel 2.2, Linux divides the privileges traditionally associated with superuser into distinct units, known as *capabilities*, which can be independently enabled and disabled. Capabilities are a per-thread attribute.

Some capabilities to look for are:
- **CAP_CHOWN**: Make arbitrary changes to file UIDs and GIDs (SUIDs and SGIDs as well) 
- **CAP_DAC_OVERRID**: Bypass file read, write, and execute permission checks.
- **CAP_DAC_READ_SEARCH**: Bypass file read permission checks and directory read and execute permission checks
- **CAP_SETGID**: Make arbitrary manipulations of process GIDs and supplementary GID list
- **CAP_SETUID**: Make arbitrary manipulations of process UIDs


#### Sources:

https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/
https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/

##### Temp:

ip addr

-> docker0


Sources:

https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/