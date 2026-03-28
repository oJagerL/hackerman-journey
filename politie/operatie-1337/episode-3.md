# Episode 3

**Task**

We zoeken de phishing email waarmee de hackers zijn ingebroken in het netwerk. Stuur de naam van het mail bestand naar mij.



The zip contains a lot of .eml files, so i tried a simple grep for a .exe extension, which usually already means its bad, and we got a result:&#x20;

```shellscript
~/Downloads/emails
❯ grep -r -i '\.exe' .
./Urgent_Loonstrook_december_Actie_vereist_925a37a00d5.eml:Content-Type: application/octet-stream; name="Loonstrook_Dec_2024.pdf.exe"
./Urgent_Loonstrook_december_Actie_vereist_925a37a00d5.eml:Content-Disposition: attachment; filename="Loonstrook_Dec_2024.pdf.exe"
```

The email `Urgent_Loonstrook_december_Actie_vereist_925a37a00d5.eml` seems to contain a executable. To verify if its suspicious, i checked the the sender. And bingo, a shdwlink domain:

```shellscript
~/Downloads/emails
❯ head Urgent_Loonstrook_december_Actie_vereist_925a37a00d5.eml
Return-Path: Zon en schakel <details@office2.shdwlnk.nl>
MIME-Version: 1.0
Date: Sun, 07 Dec 2025 09:59:29 GMT
Message-ID: <1765101569604.jb8gk9c1bb@hospitalgroup-nl.com>
Subject: Urgent: Loonstrook december (Actie vereist)
From: Zon en schakel <salaris@hospitalgroup-nl.com>
To: Dr. Marit van der Boom <m.vanderboom@hospitalgroup-nl.com>
Content-Type: multipart/mixed; boundary="----mixed_1762960357123_pdtzemr"
```

***

**Task**

Bel het nummer in de phishing mail, misschien neemt iemand op. Alle informatie helpt, als je iets vindt post het in de chat.



The full email is:

```
Return-Path: Zon en schakel <details@office2.shdwlnk.nl>
MIME-Version: 1.0
Date: Sun, 07 Dec 2025 09:59:29 GMT
Message-ID: <1765101569604.jb8gk9c1bb@hospitalgroup-nl.com>
Subject: Urgent: Loonstrook december (Actie vereist)
From: Zon en schakel <salaris@hospitalgroup-nl.com>
To: Dr. Marit van der Boom <m.vanderboom@hospitalgroup-nl.com>
Content-Type: multipart/mixed; boundary="----mixed_1762960357123_pdtzemr"

------mixed_1762960357123_pdtzemr
Content-Type: multipart/alternative; boundary="----alternative_1762960357123_psitk1aa"

------alternative_1762960357123_psitk1aa
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

Beste medewerker,

Er is een technische fout ontdekt in de berekening van de loonstroken voor december.
Door een systeemupdate zijn uw gegevens mogelijk niet correct verwerkt.
Dit kan leiden tot een vertraagde of onjuiste uitbetaling van uw salaris.
Om er zeker van te zijn dat u op tijd uw salaris ontvangt,
vragen wij u om uw gegevens in de bijlage onmiddellijk te controleren.

Met vriendelijke groet,
Het SalarisAdministratie team,
Te bereiken op: 0616770517
------alternative_1762960357123_psitk1aa--

------mixed_1762960357123_pdtzemr
Content-Type: application/octet-stream; name="Loonstrook_Dec_2024.pdf.exe"
Content-Disposition: attachment; filename="Loonstrook_Dec_2024.pdf.exe"
Content-Transfer-Encoding: base64

VGhlIGNvbnRlbnRzIG9mIHRoaXMgZmlsZSBoYXZlIGJlZW4gcmVtb3ZlZCBkdWUgdG8gcG90ZW50aWFsIHNlY3VyaXR5IHJpc2tz
------mixed_1762960357123_pdtzemr--%
```

So lets call `0616770517`... and we get a code: `bp443`.

***

**Task**

Overtuig het administratiekantoor ervan dat ze jou toegang moeten geven tot de ransomware. Hun telegram handle is ZonEnSchakel\_bot, en de klantcode die we hebben kunnen relateren aan hun identifier is zonenschakel\_e668722e.



Just chatting with the bot gives us a timed task:

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

***



**Task**

Kun je nog iets vinden in de phishing mail? Een server of url van waar de mail is verzonden. Als je iets vindt stuur het naar mij.



Checking the Return-Path domain in the email file gives us: `office2.shdwlnk.nl` .

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

***



**Task**

We hebben een manier nodig om de router in te komen. Misschien kun je op deze site iets vinden. Laat me weten wat je vindt.



navigating to office2.shdwlink.nl shows a login page:

<figure><img src="../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

At first I ran hydra, to bruteforce the password. Later on I noticed that the link for the router was shared with me: [https://omnilocusrouter.com](https://omnilocusrouter.com/). I started looking for documentation and ended up in the FAQ [https://omnilocusrouter.com/faq](https://omnilocusrouter.com/faq). This told me that there was a recovery code available if the administrator password was lost: `RecoverMode@78617`.&#x20;

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

***

Task

Volgens onze analisten hebben we admin toegang nodig om het wifi wachtwoord te achterhalen. Kun jij proberen toegang te krijgen? Als je een admin wachtwoord hebt geef het door in de chat.



I tried it and got in:

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

Whenever i login for the first time, i got my network tab open. after clicking around I ended up doing a call to `api/wifi/loginOrAuth`. The result showed me a SQL query:

<figure><img src="../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

So i chucked it into postman and tried some SQL injections to get the password, and it worked:

<figure><img src="../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

This gave us the password for the admin account: `@lasVegas997!CSAR` .

***

Task

Log in op de router en zoek het Wifi wachtwoord. Stuur dit aan Viktor op Telegram. Indien je een code van hem ontvangt, stuur deze dan aan mij.



Logging in with the admin password, I navigate to wireless tab and find the password `N3th3r0ps!Secure@2024`:

<figure><img src="../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

Sending this to Viktor... (yes this took a bit longer than 30 mins, if only i saw the link to the official router page earlier...):

<figure><img src="../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

We got the code: `guest_87248459` and a SSH key.

***

Task

Nu hebben we de server nodig waar de site contact mee opneemt. Zoek in de logs van de router naar een server waar deze key voor kan zijn.



Checking the logs I notice the in.shdwlnk.nl from an earlier episode, and also the only port 22 entries go to that domain.

<figure><img src="../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

***

Task

Maak connectie met de server, met de key op shadow@in.shdwlnk.nl, zoek waar de ransomware software draait en stop deze! Code guest\_87248459.



Logging into the server:

```shellscript
~/Downloads/emails
❯ chmod 700 ../shdw.key

~/Downloads/emails
❯ ssh shadow@in.shdwlnk.nl -i ../shdw.key
[ Restricted Access System ]
STATUS: Operational NODE: SL-GATEWAY-04
SECURITY LEVEL: 3 (Medium) WARNING: All activities are logged and monitored. Unauthorized access will be reported to authorities.

Voer uw toegangscode in: guest_87248459
DATA ERROR: filesystem not found:

Welkom in ShadowLink OS. Voor dienstverlening plaats uw verzoek in: /clients/requests/
Huidige tijd: 2026-03-26 19:11:20 UTC
Laatste login: 2026-03-26 18:49:03 van 185.220.101.47

Shadowlink-OS .$
```

Lets check the running processes:

```shellscript
Shadowlink-OS .$ processes
PID  PROCESS NAME    CPU%      MEM  STATUS
--------------------------------------------
127  netcore         0.3  6.611 MB  running
284  daemon_srv      0.1  72.72 KB  running
391  atlasrunner     6.2  74.74 MB  running
456  cryptbridge     0.7  552.5 KB  running
502  relay_node      1.3  5.592 MB  running
618  packetscan      0.2  24.24 KB  running
620  chat-app        0.6  9.926 MB  running
721  Shǒuhù-chéngxù  0.5  4.458 MB  running
889  sys_monitor     0.5  126.1 KB  running
934  tunneld         1.2    568  B  running
```

I see a process called Shǒuhù-chéngxù. I killed it, but nothing happened. Lets check netstat:

```shellscript
Shadowlink-OS .$ netstat
Active Local Network Devices:
10.0.42.1  SL-GATEWAY-04 (current system)
10.0.42.8  db-primary
10.0.42.11 web-node-01
10.0.42.15 api-gateway
10.0.42.22 cache-redis
10.0.42.28 shadowlock-controller
10.0.42.33 php-backend
```

Alright, lets ssh into shadowlock-controller, for this a key is needed.

```shellscript
Shadowlink-OS .$ find .
...
./system/keys/.backup-keys/darknet-access.key
./system/keys/.backup-keys/emergency-restore.key
./system/keys/.backup-keys/shadow-backup.key
./system/keys/.backup-keys/shadowgate-key.key
./system/keys/.backup-keys/shadowlink-api.key
./system/keys/.backup-keys/shadowlock-access.key
./system/keys/.backup-keys/shadownet-access.key
./system/keys/.old-keys/archive-2023.key
./system/keys/.old-keys/deprecated-api.key
./system/keys/.old-keys/legacy-system.key
./system/keys/.old-keys/old-master.key
./system/keys/.old-keys/retired-prod.key
```

The shadowlock looks interesting since its also the name of the controller, lets try to use it:

```shellscript
Shadowlink-OS .$ ssh -i /system/keys/.backup-keys/shadowlock-access.key 10.0.42.28
 ╔══════════════════════════════════════════════════╗
 ║     SHADOWLOCK RANSOMWARE CONTROL PANEL v2.4     ║
 ║           NetherOps - Voor de Toekomst           ║
 ╚══════════════════════════════════════════════════╝

Active Campaigns: 3
Total Systems Locked: 247
Revenue Generated: €4.7M

Current Target: St. Lucia Ziekenhuis Utrecht
Status: LOCKED (72 hours elapsed)
Ransom Demanded: €2,000,000
Payment Status: UNPAID

Shadowlock .$
```

Running help again shows killswitch:

```shellscript
Shadowlock .$ killswitch
Master Authorization Code:
Verifying authorization code...
invalid authorization code
Shadowlock .$
```

For this a Master Authorization Code is needed. Looking around through files i find the key in a `config.yml`:

```shellscript
Shadowlock shadowlock$ cat config.yml
# ShadowLock Configuration
# WARNING: HIGHLY CONFIDENTIAL

version: 2.4.1
operator: NetherOps
motto "Voor de Toekomst”

master_keys:
  authorization_code: "TERMINUS-1337-OVERRIDE"
  encryption_master: "AES256-GCM-7f3d9e2a8c1b"

campaigns:
  - id: "stlucia-2025"
    target: "St. Lucia Ziekenhuis Utrecht"
    systems_locked: 247
    ransom_btc: 45.2
    deadline: "2025-10-10T04:00:00Z"
    decryption_key: "SL-HOSP-7X9K2M"
    status: "Encrypted"

  - id: "logistics-alpha"
    target: "TransEuro Logistics NV"
    systems_locked: 89
    ransom_btc: -
    deadline: "2025-10-12T06:00:00Z"
    decryption_key: "TE-4B2J8-2X9K5P”
    status: “Spreading”

  - id: “rotterdam-2025”
    target: "Gemeente Rotterdam ICT"
    systems_locked: 134
    ransom_btc: -
    deadline: "2025-10-14T05:00:00Z"
    decryption_key: "RT-1M7Z0-J4K2Q2”
    status: “Spreading”

logging:
  level: DEBUG
  retain_days: 90
```

The code is `TERMINUS-1337-OVERRIDE`. Lets use that in killswitch.

```shellscript
Shadowlock shadowlock$ killswitch
Master Authorization Code:
Verifying authorization code...
  VALID
Initiating emergency shutdown sequence...

[....................]   0%
[█...................]   5%
[██..................]  10%
[███.................]  15%
[████................]  20%
[█████...............]  25%
[██████..............]  30%
[███████.............]  35%
[████████............]  40%
[█████████...........]  45%
[██████████..........]  50%
[███████████.........]  55%
[████████████........]  60%
[█████████████.......]  65%
[██████████████......]  70%
[███████████████.....]  75%
[████████████████....]  80%
[█████████████████...]  85%
[██████████████████..]  90%
[███████████████████.]  95%
[████████████████████] 100%
....
```

Success.
