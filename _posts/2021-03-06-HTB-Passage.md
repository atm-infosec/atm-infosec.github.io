---
layout: post
title:  Passage
categories: hackthebox
tags: [hackthebox, linux, medium, cutenews, usbcreator, ChefByzen]
lang: "en"
image:
    path: assets/images/hackthebox/passage/preview.png
    width: 300
    height: 300
---

![passage](../../../../assets/images/hackthebox/passage/passage.jpg)

# Overview

Creator: [ChefByzen](https://twitter.com/ChefByzen){:target="_blank"}

IP: 10.10.10.206

Rated: medium

Release Date: 05.09.2020

Retired: 06.03.2021

# Enumeration

## nmap

```
# Nmap 7.91 scan initiated Wed Jan  6 11:34:05 2021 as: nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN /home/kali/htb/results/passage.htb/scans/_full_tcp_nmap.txt -oX /home/kali/htb/results/passage.htb/scans/xml/_full_tcp_nmap.xml passage.htb
Nmap scan report for passage.htb (10.10.10.206)
Host is up, received user-set (0.035s latency).
Scanned at 2021-01-06 11:34:06 EST for 33s
Not shown: 65533 closed ports
Reason: 65533 conn-refused
PORT   STATE SERVICE    REASON  VERSION
22/tcp open  ssh        syn-ack OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVnCUEEK8NK4naCBGc9im6v6c67d5w/z/i72QIXW9JPJ6bv/rdc45FOdiOSovmWW6onhKbdUje+8NKX1LvHIiotFhc66Jih+AW8aeK6pIsywDxtoUwBcKcaPkVFIiFUZ3UWOsWMi+qYTFGg2DEi3OHHWSMSPzVTh+YIsCzkRCHwcecTBNipHK645LwdaBLESJBUieIwuIh8icoESGaNcirD/DkJjjQ3xKSc4nbMnD7D6C1tIgF9TGZadvQNqMgSmJJRFk/hVeA/PReo4Z+WrWTvPuFiTFr8RW+yY/nHWrG6LfldCUwpz0jj/kDFGUDYHLBEN7nsFZx4boP8+p52D8F
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCdB2wKcMmurynbHuHifOk3OGwNcZ1/7kTJM67u+Cm/6np9tRhyFrjnhcsmydEtLwGiiY5+tUjr2qeTLsrgvzsY=
|   256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGRIhMr/zUartoStYphvYD6kVzr7TDo+gIQfS2WwhSBd
80/tcp open  tcpwrapped syn-ack
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jan  6 11:34:39 2021 -- 1 IP address (1 host up) scanned in 34.10 seconds
```

# 22 - SSH

Not quite up to date but rather not a gateway.

# 80 - HTTP

A simple web page appears on the home page.

![27b7b2c3d8f6eefbb0637b145c2d35e1.png](../../../../assets/images/hackthebox/passage/2e41258b56b041c3a5b5d5ef0402aa83.png)

The application appears to be powered by the `CuteNews` software.

![7ddab7469ca0cf22f71a2bb668294cd5.png](../../../../assets/images/hackthebox/passage/8fcadf28353d48599d4ae6c2cc9e893c.png)

# Exploitation

There is an RCE exploit for cutephp on [exploit-db.com](https://www.exploit-db.com/exploits/48800){:target="_blank"}.

![6b799062e18099b87bea17341a3ac49e.png](../../../../assets/images/hackthebox/passage/a46bbd95cfa74a5196a09974860fd906.png)

This was quick, this way I have an easy way to execute commands on the server.

## Upgrade Shell

But next I need a real shell, so I build a reverse shell with netcat and then upgrade with python.

![02a376b16395c6b7139c5e603b65cbf0.png](../../../../assets/images/hackthebox/passage/7f2f7046ce554ae5bb6f5bce999f0a25.png)

# Privilege Escalation

Currently I am the user `www-data` and using [LinPeas.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS){:target="_blank"} I did not find anything interesting at first sight.

But the CuteNews exploit has also extracted hashes, maybe you can crack them.

![32bd789c48223bdeede77b4e07828eed.png](../../../../assets/images/hackthebox/passage/cf8ad3bedf4447bbbda8c13da1c6e46f.png)

## www-data to paul

You can now try to crack the hashes with john, I tested them at [crackstation.net](https://crackstation.net/){:target="_blank"} in advance. Maybe they are already known.

![e073b46e38a29e458984ef05f5f2d953.png](../../../../assets/images/hackthebox/passage/baaed3ffd63b4f40b639602aef4fb01a.png)

Fortunately, 2 hashes are already known. So now I can try if I can become paul or nadav using one of these passwords.

paul : atlanta1 works.

![6e41646a7755a3c631c1be90d525f4b7.png](../../../../assets/images/hackthebox/passage/466e6272a913448998873fd737e0a241.png)

### Userflag

![0a08bdecdf0eddb7a1f37a5577a4eef4.png](../../../../assets/images/hackthebox/passage/7c8c828338434f2c806b72771eb255b7.png)

## paul to nadav

The files `/home/paul/.ssh/authorized_keys` and `/home/paul/.ssh/id_rsa.pub` are identical and the comment there is nadav@passage.

![7af903ce950b910a9a9de08e4494e0d3.png](../../../../assets/images/hackthebox/passage/3f01ea275ba34adfbdbb939d98c618d1.png)

So it is obvious to download the keys and try to log in as nadav.

![8541f88c285da77bb1200da027fb2559.png](../../../../assets/images/hackthebox/passage/72b24a9999e7497bb9b1fd854a8f89e6.png)

Login successful.

## nadav to root

As nadav, I run the linpeas script again to find out if there are any new attack possibilities for a privilege escalation.

linpeas provides among other things:

![852ea886e074906114863a8c532933eb.png](../../../../assets/images/hackthebox/passage/3f672e6836364176938ad1a0ba85c9cf.png)

Interesting. 

I have here the link to [hacktricks.xyz](https://book.hacktricks.xyz/linux-unix/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation){:target="_blank"} there is linked to an article from [Palo Alto](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/){:target="_blank"}.

Following this I can now try to copy a secret key from root and use it for an access.

For this I use the following command as nadav:

```sh
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /tmp/secret true
```

Try to copy the private key:

![d3deec4bf10e4f89459076ff9159793b.png](../../../../assets/images/hackthebox/passage/7a5b10bf472f413b9b2d1dfc055a4e76.png)

That worked.

![1d29a2612d36057ab32592182cc54941.png](../../../../assets/images/hackthebox/passage/6877d7879c864c89b18def524d650d3d.png)

# Root Flag

Now I can log in to the server via SSH as root.

![eee5fec524d6afb80e8dc35b7ad69320.png](../../../../assets/images/hackthebox/passage/774c8090b2164f288258108597eee4b0.png)

That's it.