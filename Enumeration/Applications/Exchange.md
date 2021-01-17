

## MAPI

Messaging Application Programming Interface (MAPI) is an API for Microsoft Windows which allows programs to become email-aware.

The MAPI application is known as a client application because it is a client of the MAPI subsystem.

### Address lists

An address list is a collection of mail-enabled recipient objects from Active Directory.

- **Global address lists (GALs)**: The built-in GAL that's automatically created by Exchange includes every mail-enabled object in the Active Directory forest.
You can create additional GALs to separate users by organization or location, but a user can only see and use one GAL.

- **Address lists**: Address lists are subsets of recipients that are grouped together in one list, which makes them easier to find by users. Exchange comes with several built-in address lists, and you can create more based on you organization's needs.

- **Offline address books (OABs)**: OABs contain address lists and GALs. OABs are used by Outlook clients in cached Exchange mode to provide local access to address lists and GALs for recipient look-ups.

### Outlook Forms

Forms provide a user/organisation with email customisation options on how it is presented or composed.

It is possible to change the way a message appears or what fields are available to a user when composing a new message.

Forms has a VBA script engine that is **separate from the VBA Macro script engine**, which means that if you disabled macros, you can still leverage VBA in Outlook through Forms.

When a form gets published into a folder such as the Inbox, it automatically gets synchronised with the Exchange server, and all instances of Outlook associated to that account.

### Autodiscover service

The Autodiscover service minimizes user configuration and deployment steps by providing clients access to Exchange features.


### Spray

[Spray](https://github.com/Greenwolf/Spray) is a password spraying tool for Active Directory credentials.

This script will password spray a target over a period of time It requires password policy as input so accounts are not locked out

```bash
# Usage: spray.sh -owa <targetIP> <usernameList> <passwordList> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <RequestsFile>
spray.sh -owa IP USERNAME.txt PASSWORDS.txt 1 35 post-request.txt
```

### Ruler

[Ruler](https://github.com/sensepost/ruler) is a tool that allows you to interact with Exchange servers remotely, through either the MAPI/HTTP or RPC/HTTP protocol.

The main aim is abuse the client-side Outlook features and gain a shell remotely.

- **Display**: View existing rules. Rules allow you to move, flag, and respond to email messages automatically.

```bash
# Dump the Global Address List
./ruler --email user@targetdomain.com abk dump --output /tmp/gal.txt
```




*Note that it may be possible that Ruler don't discover the necessary settings automatically. Common scenarios are have the autodiscover services deployed over HTTP instead of HTTPS, no autodiscover DNS record or an authentication failing*

```bash
./ruler --url http://autodiscover.somedomain.com/autodiscover/autodiscover.xml --verbose
```

#### Forms

Options of the "form" mode:

- **add**: Creates a new form.
- **send**: Send an email to an existing form and trigger it
- **delete**: Delete an existing form
- **display**: Display all existing forms

https://sensepost.com/blog/2017/outlook-forms-and-shells/

#### Brute-Force

Ruler can be used to brute-force mailbox credentials.

Options of the "brute" mode:

- **--stop**: Stop on the first valid username:password combo
- **--delay**: How long to wait between multiple password guesses
- **--attempts**: How many attempts before we delay (attempts per user)
- **--insecure**: If the Exchange server has a bad SSL cerificate
- **--verbose**: Be verbose and show failed attempts

```bash
# Brute-force for credentials
./ruler --domain targetdomain.com brute --users /path/to/user.txt --passwords /path/to/passwords.txt
```