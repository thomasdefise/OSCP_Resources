#### Discovery



1. nmap -p- -oA nmap/allports -v  
Run nmap on all ports with the verbose mode
**-p-**: Run on all ports
**-oA**: Output

2. cat nmap/allports.nmap | grep open | awk -F/ '{print $1}' ORS=","
Get all opened ports separated by commas

3.  nmap -sC -sV -oA 
**-sC**: Script Scan
**-sV**: Probe open ports to determine service/version info


### Fuzzing

wfuzz -w 
-w: wordlist 
-u:
--hw: Hide result where 


### Network Ports

|Port(s)|Protocol(s)|Services|
|-|---------- | ----------- |
|11211|TCP| Memcached |
