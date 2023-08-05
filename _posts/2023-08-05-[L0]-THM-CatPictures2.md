---
layout: post
author: L0
---

# THM-CatPictures2

![image](/images/Pasted image 20230714220325.png)

## Enumeration

### nmap

```shell
$ sudo nmap -sV -p- catpictures2
Starting Nmap 7.92 (https://nmap.org) at 2023-07-14 16:05 EDT
Nmap scan report for catpictures2 (10.10.203.85)
Host is up (0.037s latency).
rDNS record for 10.10.203.85: catpictures2.thm

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.4.6 (Ubuntu)
222/tcp  open  ssh     OpenSSH 9.0 (protocol 2.0)
1337/tcp open  waste?
3000/tcp open  ppp?
8080/tcp open  http    SimpleHTTPServer 0.6 (Python 3.6.9)
```

nmap findings:
- Port 22: OpenSSH Service
- Port 80: Nginx webserver
- Port 222: OpenSSH Service
- Port 1337: Unknown Service
- Port 3000: Unknown Service
- Port 8080: Simple Python webserver

### dirbusting

We started by performing dirbusting on the web server running on port 80. During this process, we discovered a git repository.

```shell
$ ffuf -w `fzf-wordlist` -u http://catpictures2/FUZZ

.git/HEAD               [Status: 200, Size: 23, Words: 2, Lines: 2, Duration: 140ms]
.htaccess               [Status: 200, Size: 630, Words: 63, Lines: 19, Duration: 152ms]
                        [Status: 200, Size: 60906, Words: 4711, Lines: 144, Duration: 152ms]
data                    [Status: 301, Size: 193, Words: 7, Lines: 8, Duration: 37ms]
dist                    [Status: 301, Size: 193, Words: 7, Lines: 8, Duration: 37ms]
docs                    [Status: 301, Size: 193, Words: 7, Lines: 8, Duration: 36ms]
favicon.ico             [Status: 200, Size: 33412, Words: 62, Lines: 62, Duration: 37ms]
index.html              [Status: 200, Size: 60906, Words: 4711, Lines: 144, Duration: 37ms]
LICENSE                 [Status: 200, Size: 1105, Words: 156, Lines: 22, Duration: 37ms]
php                     [Status: 301, Size: 193, Words: 7, Lines: 8, Duration: 42ms]
plugins                 [Status: 301, Size: 193, Words: 7, Lines: 8, Duration: 36ms]
robots.txt              [Status: 200, Size: 136, Words: 9, Lines: 8, Duration: 36ms]
src                     [Status: 301, Size: 193, Words: 7, Lines: 8, Duration: 36ms]
uploads                 [Status: 301, Size: 193, Words: 7, Lines: 8, Duration: 35ms]
```

We proceeded to dump the repository using git-dumper. However, we encountered permission restrictions that limited our access, and we didn't find anything significant.

![image](/images/Pasted image 20230715133407.png)

While browsing through the site, we stumbled upon an interesting description that mentioned "strip metadata." Intrigued, we downloaded the associated picture and inspected it using `exiftool`.

![image](/images/Pasted image 20230714231802.png)

The "title" field of the picture revealed a partial URL on port 8080. We downloaded the corresponding file, which contained the following information:

```shell
└─$ cat 764efa883dda1e11db47671c4a3bbd9e.txt
note to self:

I setup an internal gitea instance to start using IaC for this server. It's at a quite basic state, but I'm putting the password here because I will definitely forget.
This file isn't easy to find anyway unless you have the correct URL...

gitea: port 3000
user: samarium
password: TU**********hP

ansible runner (olivetin): port 1337
```

We obtained credentials for the *gitea* service on port 3000 and discovered a repository containing configuration files for an ansible runner named *olivetin*, which could be accessed via the service on port 1337.

*gitea*
![image](/images/Pasted image 20230714232028.png)

*olivetin*
![image](/images/Pasted image 20230715133330.png)

Within the repository, we also found the first flag.

![image](/images/Pasted image 20230714232008.png)

The most intriguing discovery was that the ansible runner executed shell commands listed in the configuration file.

![image](/images/Pasted image 20230714230137.png)

We attempted to change the command to `id`.

![image](/images/Pasted image 20230714232310.png)

To our delight, it worked.

![image](/images/Pasted image 20230714232246.png)

### Reverse Shell
Our next step involved obtaining a reverse shell. We initiated a listener and committed the modified configuration file to the repository.

![image](/images/Pasted image 20230714232614.png)

![image](/images/Pasted image 20230714232625.png)

As a result, we gained a shell and found a private key in the `.ssh` directory.

![image](/images/Pasted image 20230714233033.png)

By adjusting the permissions with `chmod 600 ./key.txt` and using the `ssh` command with the key, `ssh bismuth@catpictures2 -i key.txt`, we successfully accessed the server and acquired the second flag located in the home directory.

![image](/images/Pasted image 20230715133618.png)

## Privilege Escalation

We followed our usual procedure and, with the assistance of `linpeas.sh`, we discovered a vulnerability in the version of `sudo` installed on the system.

![image](/images/Pasted image 20230715132746.png)

Taking advantage of this vulnerability, we utilized the exploit available at [https://github.com/blasty/CVE-2021-3156]. After cloning the repository to our machine, we transferred the files to the compromised server using a simple Python web server and built the exploit using the `make` command on the victim's machine.

Executing the command resulted in gaining `root` privileges.

![image](/images/Pasted image 20230715132519.png)

In the `root` directory, we located the third and final flag.

Done [L0]
