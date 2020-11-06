#### DNS

##### Public IPS, CIDRs & ASNs

[Amass](https://github.com/OWASP/Amass) is backed by OWASP, which should provide prestige and confidence in the results. It is actively maintained and will likely be supported for a long time, meaning any future bugs will be resolved. Additionally, the adoption rate of Amass is high which potentially means better data consistency and integration with other tools

```bash
amass intel -addr 192.168.1.1-254 # Collect OSINT for the given IP Addresses
amass intel -asn 8911,50313,394161 # Collect OSINT for the given ASNs
amass intel -cidr 104.154.0.0/15 # Collect OSINT for the given CIDRs
``` 
- **intel**: Collect open source intelligence for investigation of the target organization

##### Reverse DNS

```bash
dnsrecon -r *ip-address-range* -n *DNS*
```

- **-n**: Domain server to use.
- **-r**: IP range for reverse lookup brute force in formats (first-last) or in (range/bitmask).

#### OS Guessing (without Nmap)

```bash
ping *ip*
```

- TTL is inferior than 64 -> high chance that it's a UNIX system 
- TTL is around 128 -> high chance that it's a Windows system 

#### Port Scan

```bash
nmap -p- -oA nmap/allports -v *ip* # 1) Perform a scan on all ports with the verbose mode
cat nmap/allports.nmap | grep open | awk -F/ '{print $1}' ORS="," # 2) Get all opened ports separated by commas
nmap -sC -sV -oA nmap/specificports -p *ports* -v *ip* # 3) Run a Script scan on open ports
nmap -sY *ip* -v # Perform a SCTP scan
```

- **-p-**: Run on all ports
- **-oA**: Output
- **-sC**: Script Scan
- **-sV**: Probe open ports to determine service/version info
- **-p**: Run only on those ports (eg: )
- **-sY**: SCTP INIT/COOKIE-ECHO scans. SCTP sits alongside TCP and UDP. Intended to provide transport of telephony data over IP, the protocol duplicates many of the reliability features of Signaling System 7 (SS7), and underpins a larger protocol family known as SIGTRAN. SCTP is supported by operating systems including IBM AIX, Oracle Solaris, HP-UX, Linux, Cisco IOS, and VxWorks.


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


### Found DNS Server
-> You can change your host file /etc/resolv.conf

### Network Ports

|Port(s)|Protocol(s)|Services|
|-|---------- | ----------- |
|53|TCP/UDP|DNS|
|88|UDP|Kerberos|
|389|TCP|LDAP|
|11211|TCP|Memcached|
