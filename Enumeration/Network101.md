# Network Enumeration

#### DNS

##### Public IPS, CIDRs & ASNs

[Amass](https://github.com/OWASP/Amass) is backed by OWASP, which should provide prestige and confidence in the results. It is actively maintained and will likely be supported for a long time, meaning any future bugs will be resolved. Additionally, the adoption rate of Amass is high which potentially means better data consistency and integration with other tools

```bash
amass intel -addr 192.168.1.1-254 # Collect OSINT for the given IP Addresses
amass intel -asn 8911,50313,394161 # Collect OSINT for the given ASNs
amass intel -cidr 104.154.0.0/15 # Collect OSINT for the given CIDRs
```

- **intel**: Collect open source intelligence for investigation of the target organization

In the example below, we don't use OSINT but we use Google's DNS with a list in a "Brute-forcing way"

```bash
gobuster dns -d <domain> -t 8 -r 8.8.8.8 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

##### Reverse DNS

DNRecon support DNSSEC and mDNS

```bash
dnsrecon -r *ip-address-range* -n *DNS*
```

- **-n**: Domain server to use.
- **-r**: IP range for reverse lookup brute force in formats (first-last) or in (range/bitmask).

##### Attempt a DNS Zone Transfer

DNS zone transfer, also known as AXFR, is a type of DNS transaction. It is a mechanism designed to replicate the databases containing the DNS data across a set of DNS servers.

```bash
dig @IP hostname -t axfr
```

*Note that Nmap has a NSE script for testing that vulnerability with --script=dns-zone-transfer*

##### Bind Version (If DNS Server)

```bash
dig @IP version.bind chaos txt
#                   Example                    #
#dig @192.168.1.1 version.bind txt chaos
#;; ANSWER SECTION:
#version.bind.       0   CH  TXT "dnsmasq-2.47"
```

##### (Side Note) Using Metaspoit

```bash
auxiliary/gather/dns_brutefore       # Perform a brute force dictionary DNS Scan
auxiliary/gather/dns_cache_scraper   # Queries DNS cache for previously resolved named
auxiliary/gather/dns_info            # Gathers general DNS information
auxiliary/gather/dns_reverse_lookup  # Perform a reverse DNS (PTR) scan of a netblock
auxiliary/gather/dns_srv_enum        # Enumerates SRV (Server) records
```

#### OS Guessing (without Nmap)

```bash
ping *ip*
```

- TTL is inferior than 64 -> high chance that it's a UNIX system
- TTL is around 128 -> high chance that it's a Windows system

#### WHOIS

The WHOIS protocol provdes client/server access to information about internet domains and IPv4/IPv6 blocks

```bash
whois -h IP -p PORT DOMAIN # Get all the information that a whois service has about a domain
```

Note that WHOIS relies on databases to store. SQLi maybe possible with the following

```bash
whois -h IP -p PORT "a') or 1=1#"
```

#### Port Scan

```bash
nmap -p- -oA nmap/allports -v *ip* # 1) Perform a scan on all ports with the verbose mode
cat nmap/allports.nmap | grep open | awk -F/ '{print $1}' ORS="," # 2) Get all opened ports separated by commas
nmap -sC -sV -oA nmap/specificports -p *ports* -v *ip* # 3) Run a Script scan on open ports
nmap -sY *ip* -v # Perform a SCTP scan
```

- **-p-**: Run on all ports (except port 0 within some version)
- **-oA**: Output
- **-sC**: Script Scan
- **-sV**: Probe open ports to determine service/version info
- **-p**: Run only on those ports (eg: )
- **-sY**: SCTP INIT/COOKIE-ECHO scans. SCTP sits alongside TCP and UDP. Intended to provide transport of telephony data over IP, the protocol duplicates many of the reliability features of Signaling System 7 (SS7), and underpins a larger protocol family known as SIGTRAN. SCTP is supported by operating systems including IBM AIX, Oracle Solaris, HP-UX, Linux, Cisco IOS, and VxWorks.

If there are a lot of systems, you may need to use zenmap

#### Nmap IDS & IPS Evasion

- **TTL Manipulation**: --ttl *value*
 Send some packets with a TTL enough to arrive to the IDS/IPS but not enough to arrive to the final system. And then, send another packets with the same sequences as the other ones so the IPS/IDS will think that they are repetitions and won't check them, but indeed they are carrying the malicious content.
 *OS detection (-O) packets are not affected because accuracy there requires probe consistency, but most pinging and portscan packets support this.*
- **Avoiding signatures**: --data-length 25
Just add garbage data to the packets so the IPS/IDS signature is avoided.
- **Decoy Scal**: -D *decoy1[,decoy2][,your-own-ip]*
  Causes a decoy scan to be performed, which makes it appear to the remote host that the host(s) you specify as decoys are scanning the target network too. Thus their IDS might report 5–10 port scans from unique IP addresses
- **Fragmented Packets**: -f
  Some packet filters have trouble dealing with IP packet fragments due to the fact that:
  - Packet filters could reassemble the packets themselves, but that requires extra resources.
  - Fragments may take different paths, preventing reassembly.
  *Note that some source systems defragment outgoing packets in the kernel. Linux with the iptables connection tracking module is one such example. Do a scan while a sniffer such as Wireshark is running to ensure that sent packets are fragmented*
  *Features such as version detection and the Nmap Scripting Engine generally don't support fragmentation because they rely on your host's TCP stack to communicate with target services.*

If you see those following message, it means that for some packets, Nmap it is getting neither a udp nor icmp (destination unreachable) response from the host..
*Increasing send delay for 5.6.7.8 from 0 to 50 due to max_successful_tryno increase to 4*
*Increasing send delay for 5.6.7.8 from 50 to 100 due to max_successful_tryno increase to 5*
*Increasing send delay for 5.6.7.8 from 100 to 200 due to max_successful_tryno increase to 6*
*Increasing send delay for 5.6.7.8 from 200 to 400 due to 11 out of 11 dropped probes since last increase.*

By doing this, Nmap can differentiate between ports that are **blocked by firewalls** (no response regardless of sending interval) or **closed, but rate limited** (able to receive icmp destination unreachable response if the sending interval is sufficiently large).

### DNS Server

-> You can change your host file /etc/resolv.conf

### FTP Server

```bash
# Test for anonymous connection
ftp IP
Name: anomymous
Password:

ls # Displays all files
mget # Retreive all files
```

### SNMP

There are multiple version of SNMP we may encounter:

|Version|Usage|Authentication|Encryption usage for Authentication|
|-|-|-|-|
|V1|Most Frequent|Bases on a **string** called **commmunity**|No (**plain-text**)|
|V2,V2C|Frequent|Bases on a **string** called **commmunity**|No (**plain-text**)|
|V3|Less Frequent|Bases **credentials**|Yes|

There are multiple tools to enumerate SNMP:

- [snmpcheck](https://linux.die.net/man/1/snmpcheck) is a *native* tool on Linux systems used to enumerate information via SNMP protocol.
- [snmpwalk](https://linux.die.net/man/1/snmpwalk)  is a *native* tool on Linux systems used to retrieve a subtree of management values using SNMP GETNEXT requests.
- [onesixtyone](https://github.com/trailofbits/onesixtyone) is a program that sends SNMP requests to multiple IP addresses, trying different community strings and waiting for a reply.

```bash
onesixtyone -c /Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt -i FILE_HOSTS # Bruteforce SNMP community strings

# Once we have the community
snmpcheck -t IP -c COMMUNITY -v X # Enumerate the SNMP community
snmpwalk -c COMMUNITY -v X # Enumerate the SNMP community
```

If it's SNMP v3, use the following 

https://github.com/raesene/TestingScripts/blob/main/snmpv3enum.rb

```bash
# Note that snmpv3enum requires snmp-mibs-downloader
snmpv3enum.rb -i IP -u /usr/share/metasploit-framework/data/wordlists/snmp_default_pass.txt
```

#### Analyse the output

- **Devices**: grep ".1.3.6.1.2.1.1.1.0" *.snmp
- **Usernames/passwords**: grep -i "login\|fail" *.snmp
- **Emails Addresses**: grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" *.snmp

### SMTP

#### Basic Information

```bash
# Banner Grabbing
nc -vn <IP> 25
openssl s_client -crlf -connect smtp.mailgun.org:465
openssl s_client -starttls smtp -crlf -connect smtp.mailgun.org:587

# MX server(s)
dig +short mx victim.com

# Attempts to use EHLO and HELP to gather the Extended commands supported by an SMTP server.
nmap -pT:25,465,587 --script smtp-commands victim.com

# Try to extract information using NTLM
nmap -p 25,465,587 --script smtp-ntlm-info victim.com
```

#### Enumerate users (VRFY, EXPN and RCPT)

```bash
smtp-user-enum -U USERS_DICT -t IP
```

#### Send a fake mail to try to get information

```bash
sendEmail -t ciso@victim.com -f thomas@google.com -s 192.168.8.131 -u "Wanna Join Google ?"
```

sendMail options:

- **-f**: from (sender) email address
- **-t**: to email address(es)
- **-s**: smtp mail relay
- **-u**: message subject

Some usefull information about SMTP

The SMTP **HELO** clause is the stage of the SMTP protocol where a SMTP server introduce them selves to each other.
Clients learn a server's supported options by using the **EHLO** (Extended HELLO)
Within HELO, **HELP** supply helpful information	

**Delivery Status Notifications**: This has been setup in order to inform human beings of the status of message delivery processing, as well as the reasons for any delivery problems or outright failures, in a manner that is largely independent of human language and media

Note that smtp-user-enum (Python) is currently not by default on Kali. For installing it use the following command: /root/.local/bin/pip3.8 install smtp-user-enum

### TFTP

TFTP requires no authentication, so ...

```bash
nmap -n -Pn -sU -p 69 -sV --script tftp-enum IP # Brute-force default paths
```

Python can be used to interact with it

```Python
import tftpy
client = tftpy.TftpClient(<ip>, <port>)
client.download("filename in server", "/tmp/filename", timeout=5)
client.upload("filename to upload", "/local/path/file", timeout=5)
```

### Finger Service

Finger is an old user information protocol are simple network protocols for the exchange of human-oriented status and user information that was created in ... 1977.

You can use the [finger-user-enum](https://github.com/pentestmonkey/finger-user-enum) Perl script to bruteforce username

```bash
finger @VICTIM-IP # List users
finger USERNAME@VICTIM-IP # Get info of user
finger-user-enum.pl -U users.txt -t IP # Brute force to guess users
finger "|/bin/ls -a /@IP" # Perform an RCE
```

### Network Ports

|Port(s)|Protocol(s)|Services|
|-|---------- | ----------- |
|25||SMTP
|53|TCP/UDP|DNS|
|79|TCP|Finger|
|69|UDP|TFTP|
|88|UDP|Kerberos|
|389|TCP|LDAP|
|465||SMTPS|
|587||
|8000||[Java Debug Wire Protocol](Applications/Tomcat.md)|
|8009||[AJP Connector](Applications/Tomcat.md)|
|11211|TCP|[Memcached](Applications/memcached.md)|
