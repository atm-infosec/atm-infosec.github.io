---
layout: post
title:  Academy
categories: hackthebox
tags: [hackthebox, linux, enumeration, laravel, metasploit, composer, easy, egre55 & mrb3n]
lang: "en"
image:
    path: assets/images/hackthebox/academy/preview.png
    width: 300
    height: 300
---

![Academy](../../../../assets/images/hackthebox/academy/academy.jpg)

# Abstract

Academy is a box by [egre55](https://twitter.com/egre55){:target="_blank"} and [mrb3n](https://twitter.com/mrb3n813){:target="_blank"} classified as easy.
The box is about enumeration. To master the box, you have to create a new user account with admin privileges. 
As admin you have the possibility to access the application laravel and so you can create a shell.

With this initial access you get the user password of ``cry0l1t3`` by enumeration. After that more enumeration is needed to find the password of user ``mrb3n``.

mrb3n is able to use the application ``composer`` with root rights, so I use this to create a root shell.

# Enumeration

## nmap

First, as always, the nmap scan.

```
# Nmap 7.91 scan initiated Mon Dec 28 18:53:29 2020 as: nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN /home/kali/htb/results/academy.htb/scans/_full_tcp_nmap.txt -oX /home/kali/htb/results/academy.htb/scans/xml/_full_tcp_nmap.xml academy.htb
Nmap scan report for academy.htb (10.10.10.215)
Host is up, received user-set (0.031s latency).
Scanned at 2020-12-28 18:53:30 EST for 555s
Not shown: 65532 closed ports
Reason: 65532 conn-refused
PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/0BA3dU0ygKCvP7G3GklCeOqxb17vxMCsugN05RA9Fhj7AzkPiMLrrKRY656gBuscH23utAWAhRXzV1SyU37bbFzEbfaqYAlh1ggHEuluLgbf9QsYZe76zCx2SRPOzoI9Q40klVvuu9E92pNLe80dvUZj644EwhJTGw4KGxeOqeuo/nXnYfiNAbWvOe9Qp+djDbEvP5lHwIDMTAtgggoSC1chubC3jFC4hihuYjtitjUr4+5fROomhJAo/GEvdBj2CYNHIFEvmuvb32cgul5ENQS4fJXpcI7fbP9/+b/cfA9oRxG2k+k1M8mUld2h5mHEVBE5Z9WKS3cRYu97oVKnRRCoDY/55mZw6lngIdH4drpYwzCrZcCWgviXRfCeOwmZ8sucap6qN/nFYnPoF7fd+LGaQOhz9MkAZCTMmLqSiZGSistAIPzHtABH0VQDbo2TqJ+kGWr9/EamCcYBbVVPaFj/XQqujoEjLYW+igihwrPEQ7zxlleQHwg91oSVy38=
|   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAIMsz8qKL1UCyrPmpM5iTmoy3cOsk+4L7oFdcPjBXwAcUVvnti7nXHlNqMfgsapbGSIl7AWTOeXLZmw2J6JWvE=
|   256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHBP1E2rWeTShvyJKxC5Brv1Do3OwvWIzlZHWVw/bD0R
80/tcp    open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Hack The Box Academy
33060/tcp open  socks5  syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe: 
|     Invalid message"
|     HY000
|   Radmin: 
|     authentication.mechanisms
|     MYSQL41
|     SHA256_MEMORY
|     doc.formats
|     text
|     client.interactive
|     compression
|     algorithm
|     deflate_stream
|     lz4_message
|     zstd_stream
|     node_type
|     mysql
|_    client.pwd_expire_ok
| socks-auth-info: 
|   No authentication
|   No authentication
|_  No authentication
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.91%I=9%D=12/28%Time=5FEA71DD%P=x86_64-pc-linux-gnu%r(
SF:NULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPO
SF:ptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0
SF:b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVer
SF:sionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,
SF:2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0f
SF:Invalid\x20message\"\x05HY000")%r(Hello,9,"\x05\0\0\0\x0b\x08\x05\x1a\0
SF:")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SSLSessionReq,2B,"\x05\0\
SF:0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20
SF:message\"\x05HY000")%r(TerminalServerCookie,9,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x
SF:08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(SSLv23SessionR
SF:eq,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0")%r(SMBProgNeg,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B
SF:,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fIn
SF:valid\x20message\"\x05HY000")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08
SF:\x05\x1a\0")%r(LPDString,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearch
SF:Req,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a
SF:\x0fInvalid\x20message\"\x05HY000")%r(LDAPBindReq,9,"\x05\0\0\0\x0b\x08
SF:\x05\x1a\0")%r(SIPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-R
SF:C,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(NCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"
SF:\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInva
SF:lid\x20message\"\x05HY000")%r(DistCCD,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")
SF:%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(Radmin,15D,"\x05\0\0\0\x
SF:0b\x08\x05\x1a\0P\x01\0\0\x02\n\x0f\n\x03tls\x12\x08\x08\x01\x12\x04\x0
SF:8\x07@\0\nM\n\x19authentication\.mechanisms\x120\x08\x03\",\n\x11\x08\x
SF:01\x12\r\x08\x08J\t\n\x07MYSQL41\n\x17\x08\x01\x12\x13\x08\x08J\x0f\n\r
SF:SHA256_MEMORY\n\x1d\n\x0bdoc\.formats\x12\x0e\x08\x01\x12\n\x08\x08J\x0
SF:6\n\x04text\n\x1e\n\x12client\.interactive\x12\x08\x08\x01\x12\x04\x08\
SF:x07@\0\nn\n\x0bcompression\x12_\x08\x02\x1a\[\nY\n\talgorithm\x12L\x08\
SF:x03\"H\n\x18\x08\x01\x12\x14\x08\x08J\x10\n\x0edeflate_stream\n\x15\x08
SF:\x01\x12\x11\x08\x08J\r\n\x0blz4_message\n\x15\x08\x01\x12\x11\x08\x08J
SF:\r\n\x0bzstd_stream\n\x1c\n\tnode_type\x12\x0f\x08\x01\x12\x0b\x08\x08J
SF:\x07\n\x05mysql\n\x20\n\x14client\.pwd_expire_ok\x12\x08\x08\x01\x12\x0
SF:4\x08\x07@\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Dec 28 19:02:45 2020 -- 1 IP address (1 host up) scanned in 555.39 seconds
```

## 22 - SSH

The SSH version is unremarkable.

## 80 - HTTP

### Gobuster

A quick Gobuster scan provides:

```
/.hta (Status: 403) [Size: 276]
/.hta.txt (Status: 403) [Size: 276]
/.hta.html (Status: 403) [Size: 276]
/.hta.php (Status: 403) [Size: 276]
/.hta.asp (Status: 403) [Size: 276]
/.hta.aspx (Status: 403) [Size: 276]
/.hta.jsp (Status: 403) [Size: 276]
/.htpasswd (Status: 403) [Size: 276]
/.htpasswd.php (Status: 403) [Size: 276]
/.htpasswd.asp (Status: 403) [Size: 276]
/.htpasswd.aspx (Status: 403) [Size: 276]
/.htpasswd.jsp (Status: 403) [Size: 276]
/.htpasswd.txt (Status: 403) [Size: 276]
/.htpasswd.html (Status: 403) [Size: 276]
/.htaccess (Status: 403) [Size: 276]
/.htaccess.txt (Status: 403) [Size: 276]
/.htaccess.html (Status: 403) [Size: 276]
/.htaccess.php (Status: 403) [Size: 276]
/.htaccess.asp (Status: 403) [Size: 276]
/.htaccess.aspx (Status: 403) [Size: 276]
/.htaccess.jsp (Status: 403) [Size: 276]
/admin.php (Status: 200) [Size: 2633]
/admin.php (Status: 200) [Size: 2633]
/config.php (Status: 200) [Size: 0]
/home.php (Status: 302) [Size: 55034]
/images (Status: 301) [Size: 311]
/index.php (Status: 200) [Size: 2117]
/index.php (Status: 200) [Size: 2117]
/login.php (Status: 200) [Size: 2627]
/register.php (Status: 200) [Size: 3003]
/server-status (Status: 403) [Size: 276]
```

### Website

On the start page you will find a link to register.

![427dc20a82ec75916e0df50e4c419fa6.png](../../../../assets/images/hackthebox/academy/2f33b22509084f8fa1069136e6b9af90.png)

Create a new account there.

![c12c0c60d9d146f49e677aeb03912625.png](../../../../assets/images/hackthebox/academy/c12c0c60d9d146f49e677aeb03912625.png)

Use this account as login.

![9f03f82b717aea7d5b5c189ba1ada86a.png](../../../../assets/images/hackthebox/academy/9f03f82b717aea7d5b5c189ba1ada86a.png)

Done, you are logged in. One special feature is that you are logged in as egre55 and not with your created user. Maybe a bug?

![abcf165605586bc4389d36d449f29b36.png](../../../../assets/images/hackthebox/academy/d17b5dd1038b434284c440d465889ff1.png)

After some searching I didn't find anything special, so I looked in my Burp HTTP history and saw that my account was created with the roleid 0.

What happens if you set this to 1? 

Since I already created my account, I also changed the uid to atm2.

![cd4c807988f01f3ff83f8e4e9b1ce152.png](../../../../assets/images/hackthebox/academy/015bc43230654c08aeefc0f5bf3b81c8.png)

In the Gobuster scan I have already found the admin.php, there I'm now trying to log in with the new account atm2.

![d57b784a7cca41e2266f1ef49009bd83.png](../../../../assets/images/hackthebox/academy/173a7f6bb6724fda8eedc5f915332a44.png)

The login is successful and an overview with todos appears. In this overview you can find the domain dev-staging-01.academy.htb.

This must be entered in the /etc/hosts.

In the upper left corner you see an error message which tells you the name of the application. It is laravel.

![08d596136a2800d91513c8929686f50e.png](../../../../assets/images/hackthebox/academy/817236f9d0984daa9aaa7763542ffe93.png)

# Exploitation

For Laravel there is a Metasploit module. But this requires that I have an APP_KEY, this is fortunately delivered in the error message.

![3b2a1c3cde1f8611d153e0d07ac6305b.png](../../../../assets/images/hackthebox/academy/3b2a1c3cde1f8611d153e0d07ac6305b.png)

Here is an overview of the set variables:

![e9e9120ee7153081c6f6cdb1af67d1b8.png](../../../../assets/images/hackthebox/academy/964b13e77c7d48fcaf50756b684c49de.png)

The reverse shell opens. I'm user www-data, let's see what I can find in the directory.

# Privilege Escalation

## www-data to cry0l1t3

The shell itself is a bit inconvenient, but if you use the full path the access works.

This way I found a .env file.

![1808ec7f0208ca3de23771e92bc3f7aa.png](../../../../assets/images/hackthebox/academy/1808ec7f0208ca3de23771e92bc3f7aa.png)

In this file variables for the application are defined, fortunately also a password. 

![c17c8c531f3df2a7c339ec3d6c7f4888.png](../../../../assets/images/hackthebox/academy/ed18e54df7764cdd9fd91286e0cb6928.png)

Since many users use the same password multiple times, I take a quick look around /home for the username and then try to log in as cry0l1t3 via SSH.

Login: cry0l1t3 : mySup3rP4s5w0rd!!

![4cde0eea46597020cb8d0055c7f77813.png](../../../../assets/images/hackthebox/academy/dad1aacc910e480c932978e387fa5c64.png)

## cry0l1t3 to mrb3n

With a recent linpeas version it has been possible to find a password in the audit logs.

mrb3n : mrb3n_Ac@d3my!

![3b1ae2405bee1bb3cb71b1288ddb9e68.png](../../../../assets/images/hackthebox/academy/8de40360cdc849989e0afa5d70197009.png)

Since I haven't had the opportunity to go down a root user path, maybe I'll have better luck with the user mrb3n.

## mrb3n to root

mrb3n is allowed to run the composer application with root privileges.

![bde7d640745bbaa29a5a21a4c75fca7f.png](../../../../assets/images/hackthebox/academy/c57a94c6524b4d5fb9d3f54791a945cf.png)

At [https://gtfobins.github.io/gtfobins/composer/](https://gtfobins.github.io/gtfobins/composer/){:target="_blank"} you can find the appropriate instructions to create a root shell with the composer application.

![65e7100eccdb542d77558bf725b6b6c7.png](../../../../assets/images/hackthebox/academy/c4114c95f4a54e889e20e4d3b2db8c46.png)

And that was it, a shell with root privileges is started.

![08f843a0c4d5d92b8558df049d979193.png](../../../../assets/images/hackthebox/academy/3dc71f7eff87433f887d1389c1a4705d.png)

# Lessons Learned

- When developing software, make sure that the client application cannot set critical parameters such as the role itself.
- Never reuse the same password.
- Applications should not be run with root privileges unless absolutely necessary.
- Never assume that you are in a secure environment. Zero Trust...