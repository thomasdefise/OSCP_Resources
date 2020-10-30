### Linux version

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


###### *If you don't know, now you know: [Capabilities](https://linux.die.net/man/7/capabilities)*

Starting with kernel 2.2, Linux divides the privileges traditionally associated with superuser into distinct units, known as *capabilities*, which can be independently enabled and disabled. Capabilities are a per-thread attribute.

Some capabilities to look for are:
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