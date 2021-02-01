mimikatz program is well-known for the ability to extract passwords in plain text, hashes, PIN codes and kerberos tickets from memory.

#### Crack Password Gathered from the HKLM


impacket-secretsdump : Tool to perform various techniques to dump hashes from the remote machine without executing any agent there.  For SAM and LSA Secrets

```bash
impacket-secretsdump -sam *sam.hive* -system *system.hive* -security *security.hive* LOCAL
```


*If you don't know, now you know : [LSA secrets](https://docs.microsoft.com/en-us/windows/win32/services/service-user-accounts)*

LSA stored secrets used by the operating system in its process memory.

To make the hashes harder to decrypt, Microsoft introduced SysKey, an additional layer of obfuscation SysKey is on by default in Windows 2000 and above, and can be enabled in Windows NT 4.0 using the SysKey utility.
In this scheme, a key stored in the **system hive** is used to further encrypt the hashes in the SAM.
The key, known as the **boot key** is taken from four separate keys: SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}.


The NL$KM secret contains the cached domain password encryption key
L$HYDRAENCKEY stores the public RSA2 key used in the Remote Desktop Protocol. 

NTLMv1
NTLMv2

*If you don't know, now you know : [Data Protection API](https://docs.microsoft.com/en-us/windows/win32/services/service-user-accounts)*

Beginning with Windows 2000, Microsoft ships their operating systems with a special data protection interface, known as Data Protection Application Programming Interface

Data Protection API is utilized to protect the following personal data:

- Passwords and form auto-completion data in Internet Explorer, Google Chrome
- E-mail account passwords in Outlook, Windows Mail, Windows Mail, etc.
- Shared folders and resources access passwords
- Wireless network account keys and passwords
- Remote desktop connection passwords, .NET Passport
- Private keys for Encrypting File System (EFS), encrypting mail S-MIME, other
- User's certificates, SSL/TLS in Internet Information Services
- EAP/TLS and 802.1x (VPN and WiFi authentication)
- ...

To use it, use the following Windows API calls:
- CryptProtectData
- CryptUnprotectData

Within Data Protection API, secrets are based on:
- users password
- *master keys*: Those master keys are stored in *blobs* which contains:
  - One GUID
  - One salt
  - The master key structure


Source: http://moyix.blogspot.com/2008/02/syskey-and-sam.html


*If you don't know, now you know : [Credential Guard](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)*

Previous versions of Windows stored secrets in the Local Security Authority (LSA)

Credential Guard uses virtualization-based security to isolate secrets so that only privileged system software can access them.
Credential Guard protects NTLM password hashes, Kerberos Ticket Granting Tickets, and credentials stored by applications as domain credentials.

By enabling Credential Guard, the following features and solutions are provided:

- **Hardware security**: NTLM, Kerberos, and Credential Manager take advantage of platform security features, including Secure Boot and virtualization, to protect credentials.
- **Virtualization-based security**: Windows NTLM and Kerberos derived credentials and other secrets run in a protected environment that is isolated from the running operating system.
- **Better protection**: When Credential Manager domain credentials, NTLM, and Kerberos derived credentials are protected using virtualization-based security, the credential theft attack techniques and tools used in many targeted attacks are blocked. Malware running in the operating system with administrative privileges cannot extract secrets that are protected by virtualization-based security. 

With Credential Guard enabled, the LSA process in the operating system talks to a new component called the *isolated LSA process* that stores and protects those secrets. Data stored by the isolated LSA process is protected using virtualization-based security and is not accessible to the rest of the operating system.

Note that Credential Guard on domain controllers is not supported