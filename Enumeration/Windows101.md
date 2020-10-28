# CLI Enumeration

#### CMD Commands

| Commands      | Description |
| ----------- | ----------- |
| whoami      | Displays the current domain and user name. |
| whoami /all   | Displays all information in the current access token, including the current user name, security identifiers (SID), privileges, and groups that the current user belongs to.|
| sc stop ""  | Stop a Windows Service|
| sc start ""  | Stop a Windows Service|


#### WMI Commands

|N°| Commands      | Description |
|-|---------- | ----------- |
|1| wmic service get pathname,startname      | Displays all service and user name. |
|2| wmic service get name,displayname,pathname,startmode \|findstr /i "auto" \|findstr /i /v "c:\windows\\\\" \|findstr /i /v """ | Search for "Unquoted Service Path" vulnerable services

02) If there is are path that contains whitespace and run as *LocalSystem*, <span style="color:red">Unquoted Service Path vulnerability</span> 
When Windows starts a service, it looks for the PATH where that services is locating. If any unquoted (has space) in the PATH the service can be manipulating.
Here below is an example of a Windows Service that is vulnerable:

![](Unquoted_Example.PNG)
NIHardwareService is vulnerable as:
- *C:\Program Files\Common Files\Native Instruments\Hardware\NIHardwareService.exe* contain a whitespace and is not quoted
- The service has an *AUTO_START* start type
- The service is runnig whith high privilege, *LocalSystem*


#####*If you don't know, now you know : [Service Accounts](https://docs.microsoft.com/en-us/windows/win32/services/service-user-accounts)*

- The **[NT AUTHORITY\LocalService](https://docs.microsoft.com/en-us/windows/win32/services/localservice-account)** account is a predefined local account used by the service control manager. It has minimum privileges on the local computer and presents anonymous credentials on the network. 
- The **[NetworkService](https://docs.microsoft.com/en-us/windows/win32/services/networkservice-account)** account is a predefined local account used by the service control manager. It has minimum privileges on the local computer and acts as the computer on the network. A service that runs in the context of the NetworkService account presents the computer's credentials to remote servers. 
- The **[LocalSystem account](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account)** is a predefined local account used by the service control manager. It has extensive privileges on the local computer, Local System acts as the machine account on the network. Its token includes the **NT AUTHORITY\SYSTEM** and **BUILTIN\Administrators** SIDs; these accounts have access to most system objects. The name of the account in all locales is .\LocalSystem. The name, LocalSystem or ComputerName\LocalSystem can also be used. Localsystem is the most privileged account in a system, it's the only account that is able to access the security database (HKLM\Security).

#### Source: 
http://mysoftwarelab.blogspot.com/2010/12/localservice-vs-networkservice-vs.html#:~:text=The%20LocalService%20account%20is%20a,anonymous%20credentials%20on%20the%20network.&text=The%20LocalSystem%20account%20is%20a,by%20the%20service%20control%20manager.