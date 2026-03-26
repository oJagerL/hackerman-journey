# Episode 1

**Task**

Ik heb je een link gegeven naar een platform dat de criminelen gebruiken. Ik verwacht dat je transacties vindt, het archief downloadt, en mij de filename van dit archief (ik vermoed een zip) in de chat geeft.



We start with the provided link to CryptoPizza: [https://crypto-pizza.nl/](https://crypto-pizza.nl/)

The site opens up to a dashboard. Very fancy. Very shady. Very “we definitely sell pizza and not crime.”

<figure><img src=".gitbook/assets/image (7) (1).png" alt=""><figcaption></figcaption></figure>

Registration appears to be disabled, which is usually the website’s way of saying:\
“You are not welcome here unless you already know too much.”

<figure><img src=".gitbook/assets/image (8) (1).png" alt=""><figcaption></figcaption></figure>

Clicking on dashboard leads to a login page. Naturally, the sacred ritual begins: `admin:admin`

<figure><img src=".gitbook/assets/image (9) (1).png" alt=""><figcaption></figcaption></figure>

No luck. We get a 401. Even better, the payload doesn’t seem to be filled in correctly. Either the devs were incompetent, or they were _artistically insecure_. In CTFs, both are valid attack surfaces.\
\
Time to poke at the URL:\
`https://crypto-pizza.nl/dashboard?view=public&filter=none&accesskey=undefined`

Interesting. Changing `view=public` to `view=private` gives us: “The accesskey parameter is not set or invalid.”

<figure><img src=".gitbook/assets/image (10) (1).png" alt=""><figcaption></figcaption></figure>

That is basically the application whispering:\
“Come back with the secret sauce.”

Checked `robots.txt` too, but it had absolutely nothing useful. A tragic waste of perfectly good optimism.

<figure><img src=".gitbook/assets/image (11) (1).png" alt=""><figcaption></figcaption></figure>

Back to the login page then. Time to inspect the source, because if web developers are going to leave secrets in comments, it would be rude not to read them.

<figure><img src=".gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

And there it is: `bbksss22` . A lovely little access key, just sitting in the comments like it wanted to be found.

So naturally, we stuff it into the URL:\
`https://crypto-pizza.nl/dashboard?view=private&filter=overview&accesskey=bbksss22`&#x20;

Boom, “secure dashboard” unlocked.

<figure><img src=".gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

Inside, we see the message: “Transactions not accessible in overview mode.”

The filter is set to `overview`, and changing it manually to `none` in the URL doesn’t help. So I went spelunking through the code again, looking for how the filter is handled... and instead found something even better: code that revealed how to download the transactions directly.

<figure><img src=".gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

So I tried:\
`https://crypto-pizza.nl/downloadTrans?userId=443b545bbab17ef4888306f3fc2c047bdede91ee6476e14c51f192c7849f158d&accesskey=bbksss2`

And it worked. The downloaded file was: `transaction-export-a2d00efbaaba.zip`

***

**Task**

Wil jij het wachtwoord van de zip kraken? Dan het bestand uitpakken en de bestandsnaam die je dan hebt in de chat naar mij sturen?



Time to summon the patron saint of password cracking: John. First, extract the hash and then feed it to John:

```shellscript
┌──(jagerr㉿kali)-[~/Downloads]
└─$ zip2john transaction-export-a2d00efbaaba.zip > zip_hash.txt
ver 2.0 transaction-export-a2d00efbaaba.zip/do_not_open.zip PKZIP Encr: cmplen=8980, decmplen=8987, crc=04B56EFF ts=54F3 cs=04b5 type=8
                                                                                                                                                                                         
┌──(jagerr㉿kali)-[~/Downloads]
└─$ john zip_hash.txt -w /usr/share/seclists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Proceeding with wordlist:/usr/share/john/password.lst
Press 'q' or Ctrl-C to abort, almost any other key for status
karla            (transaction-export-a2d00efbaaba.zip/do_not_open.zip)     
1g 0:00:00:00 DONE (2026-03-24 11:42) 100.0g/s 354600p/s 354600c/s 354600C/s 123456..sss
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

Password found: `karla` , Excellent. Karl(a), if you’re reading this, please choose violence less often and better passwords more often.

Now unzip the archive:

```shellscript
┌──(jagerr㉿kali)-[~/Downloads]
└─$ unzip -P karla transaction-export-a2d00efbaaba.zip 
Archive:  transaction-export-a2d00efbaaba.zip
  inflating: do_not_open.zip                                                                                                                                                                                 
```

Very reassuring filename. Definitely not suspicious at all. Open the inner zip:

```shellscript
┌──(jagerr㉿kali)-[~/Downloads]
└─$ unzip do_not_open.zip                             
Archive:  do_not_open.zip
  inflating: Transactions-263779c3eeff.csv  
```

And there we have it: `Transactions-263779c3eeff.csv`

***

**Task**

Analyseer dit transactiebestand. Stuur mij het adres van de verdachte wallet.



Now we pivot from zip archaeology to transaction analysis.

Looking at the `from address` column, two wallets stand out because they appear multiple times:

* `...E413341` (19 times)
* `...A19FE69` (13 times)

`...A19FE69` consistently appears to act as an entry point, feeding transactions onward to `...E413341`. Then `...E413341` fans the funds out to a bunch of different wallets.

That pattern is a giant flashing neon sign reading: “I am definitely not laundering crypto, please stop looking at me.” So the suspicious wallet is: `E413341`

***

**Task**

Bekijk de pizza-code. Ga naar hun Discord-kanaal, gedraag je als legitieme klant en verzamel informatie over ShadowLink. Maar wees heel subtiel. Oh, en als ze om een klant code vragen, dit is klant\_6E39759D . Als je iets hebt ontvangen, plaats het in deze chat.



This part felt less like forensics and more like undercover improv theatre. After some conversational PvP with Maxim and some name dropping, I managed to successfully pose as a legitimate customer and order a pepperoni pizza — because apparently the path to cybercrime intel runs through processed meat.

Maxim then handed over a coupon code: `B3-A1-5D-45` . He said I was supposed to give it to Markovic:

<figure><img src=".gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

So the answer here is: `B3-A1-5D-45`

***

**Task**

Download de disk-image. Ik verwacht dat je de informatie met betrekking tot 'ShadowLink' en hun mixer operaties vindt en mij de code stuurt.



Now for the disk image. Time to rummage through digital drawers like a forensic raccoon.

Before manually inspecting files one by one, I ran a recursive grep for “Shadow” and quickly hit gold in the Trash: `./Trash/.shadow_mixer.log` :

```shellscript
/Volumes/markovic_disk🔒
❯ grep "Shadow" -R .
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
./Trash/.shadow_mixer.log:  Mixer Engine:        Shadow Mixer Framework
```

Because of course the criminals threw the evidence in the trash instead of deleting it properly. Thank you for your continued contribution to incident response.

The file contains logs from something called the Shadow Mixer Framework:

```shellscript
============================================================
        SHADOW MIXER
        System Boot & Initialization
============================================================
User: 739
Startup Timestamp: 2024-02-03 00:00:00
LOGfile Name: shadow_mixer.log

SYSTEM:
  Mixer Engine:        Shadow Mixer Framework
  Build ID:            SMF-81c97723edac
  Session Token:       3606d7dc81959322091450864aef9243
  Virtual Node Count:  12
  Runtime Mode:        For Real

CLUSTER encryption
    key: pG9r3a+ZkVt1r2c9xQF+q9j6zN8fQ2v1Rk9aD1XjGxU=
    Algorithm: GOST 28147 (1989)
    sBox: E-TEST
    Blockmode: ECB
    Key meshing mode: NO
    Padding: NO

MODULE LOAD CHECKS:
  [OK] NetworkListener
  [OK] BlockchainScanner
  [OK] EntropyPoolEngine
  [OK] FluxCapacitor
  [OK] WalletHasher
  [OK] RoutingSimulator
  [OK] PseudoNodeMesh
  [OK] Flux capacitor
  [OK] UTX AI Modeler

SYSTEM DIAGNOSTICS:
  Entropy Pool Level:  98%
  Active Wallet Cache: 452 entries
  Latency:   48ms

------------------------------------------------------------
....
2024-07-09 04:38:12 User 739 Initialization sequence started
2024-07-09 04:38:13 User 739 cluster IV set: shadow42
2024-07-09 04:38:16 User 739 Loading configuration
2024-07-09 04:38:18 User 739 Finding configured Cluster to join...
2024-07-09 04:38:23 User 739 Cluster found
2024-07-09 04:38:28 User 739 Joining cluster: fb8b9430c7cbdd37f51f66d5c85b8a0d0aca2c5e9e8c0569a467bf101ec2326c
2024-07-09 04:38:31 User 739 Ready for mixing
2024-07-09 04:43:22 User 739 Routing path generation | TXID=f7666f4383faac095a6e854ebd7b19f973525d20e6b365d8c905612b9791f8b7
2024-07-09 04:43:22 User 739 Wallet verification cycle | Wallet=bc1j0fujlxuwdvy2ruxxzmvsy3g76n7t085xauyxt5r0ftl0kdfhv
2024-07-09 04:43:22 User 739 Node rotation cycle
2024-07-09 04:44:17 User 739 Routing pipeline delay injected
2024-07-09 04:45:13 User 739 Deposit detected | TXID=27e29fb7b07a0cb2bab69decb6740485b741f72df67c4731863fa686b6098834 | SourceWallet=bc1whnu6nrknxc0jl0e32kugq7wmnn9fpxvqu08rkdewdym8rae6chwdlq
2024-07-09 04:45:35 User 739 Routing path generation | TXID=baf1a6ac1fb3475d518b1bd62bc5bad8208543e6b2ab460d4f75d51cd9ef6a04
2024-07-09 04:45:58 User 739 Withdrawal request | TXID=4cb5ac52d3aa046d04003b21ca66b9aa34bed4479a2801cfa4328fb96f460ca8 | TargetWallet=bc1lmfryvg8dcd6gxe4zjmd2v9szdwtaak2ynlru8n7p7ycygl9mm0
2024-07-09 04:46:03 User 739 Routing pipeline delay injected
2024-07-09 04:46:13 User 739 Mixer node warm-up sequence
2024-07-09 04:46:52 User 739 Mix round triggered | Batch=3e68e43b5a3aa6521a6ca8b191f208616e6cbda6ed4b129323afd40f4266b9d2
2024-07-09 04:46:57 User 739 Heartbeat: system operational
2024-07-09 04:47:24 User 739 Heartbeat: system operational
2024-07-09 04:48:09 User 739 Deposit detected | TXID=f31555c113ddaa3430a16220286e69c229a8f0023e39bd8be4361140f4ca0095 | SourceWallet=bc1j0dp2scwsajjmffd33a6fkzm273ums9tp856tlm2t9402dwahn7f5wcmhpy6
2024-07-09 04:48:34 User 739 Routing pipeline delay injected
2024-07-09 04:49:31 User 739 Wallet activity randomizer applied to bc1tfz6h02h6ay7v8j5rryyds3md69gf7jdqgw63defjeyly
2024-07-09 04:50:17 User 739 Mix round triggered | Batch=bcc0886fab786f9291905731594fd5f7e9728d4aa7880d62ba4a8d3207667256
2024-07-09 04:51:12 User 739 Mixer node warm-up sequence
2024-07-09 04:51:50 User 739 Routing pipeline delay injected
2024-07-09 04:52:02 User 739 Routing pipeline delay injected
2024-07-09 04:52:54 User 739 Mix round triggered | Batch=8f006f1aad9ba8f88bb0f488f84f639ba35c05e686494c737d27f000f717c40f
2024-07-09 04:53:05 User 739 Heartbeat: system operational
2024-07-09 04:53:47 User 739 Wallet verification cycle | Wallet=bc1q3lmqtecnmzhl0fyupmejmuels8ptv549q46djnj7glgllpyqqrf
2024-07-09 04:54:19 User 739 Node rotation cycle
2024-07-09 04:54:35 User 739 Routing path generation | TXID=69d70a9c9aa274e02b9271107b0630fcefb120006c37e2a29a1c5c2b292c6e20
2024-07-09 04:54:45 User 739 Mixer node warm-up sequence
2024-07-09 04:55:05 User 739 Wallet activity randomizer applied to bc19v9pyzf8vrmfrm44up9a6pht3xv3x8s60s2vnnf3zkq8r9c4rrkar3
2024-07-09 04:56:03 User 739 Mixer node warm-up sequence
2024-07-09 04:56:44 User 739 Wallet activity randomizer applied to bc1wrv9tef3cxqu9f27ukqd8ztap464yrwpelsarkv8vydqpc93a
2024-07-09 04:57:11 User 739 Routing pipeline delay injected
2024-07-09 04:58:00 User 739 Wallet verification cycle | Wallet=bc1ry0v9gwe82jfpjc35tamrwfx6nsed2hkx0xs4euyf74t2famxvtukuu
2024-07-09 04:58:44 User 739 Wallet activity randomizer applied to bc1497lw9fp9c3hctnmx9gt008auryjucw4f5dw6g685n9pa
2024-07-09 04:58:49 User 739 Wallet verification cycle | Wallet=bc1pfnptmtveellnuxg5ueejzrg6uz2pyamg209jund
2024-07-09 04:59:34 User 739 Mixer node warm-up sequence
2024-07-09 04:59:43 User 739 Mixer node warm-up sequence
2024-07-09 05:00:33 User 739 Routing pipeline delay injected
```

Later in the log, we find this: `Joining cluster: fb8b9430c7cbdd37f51f66d5c85b8a0d0aca2c5e9e8c0569a467bf101ec2326c`

That looked promising, but apparently the required answer wasn’t just the hostname or a random hash.

I also found an SSH config entry:

```shellscript
/Volumes/markovic_disk🔒
❯ cat .ssh/config
# SSH Configuration
Host shdwlnk
    HostName in.shdwlnk.nl
    User amarkovic
    Port 22
    IdentityFile ~/.ssh/id_rsa
    StrictHostKeyChecking no

Host pemoth
    HostName internal.pemoth.local
    User a.markovic
    Port 22
    IdentityFile ~/.ssh/id_rsa_work

Host github
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_rsa
```

At first I tried `in.shdwlnk.nl` as the answer, but that turned out to be a decoy — useful infrastructure info, yes, but not the actual requested code.

The feedback made it clear they wanted the specific cluster name hidden in the disk image.

I wasn't sure what "de code" meant, so i just entered `in.shdwlnk.nl`, which was wrong but I got the message:

```
Interessant, in.shdwlnk.nl is inderdaad een adres dat we kunnen linken aan de infrastructuur 
van Markovic. Maar dat is niet wat ik nodig heb om toegang te krijgen. 
Ik zoek de specifieke cluster-naam van de server die in dat disk image verborgen zit.
```

At that point, the earlier log details became much more interesting:

* encryption key
* algorithm: GOST 28147
* sBox: E-TEST
* mode: ECB
* IV mention: `shadow42`

That strongly suggested the cluster identifier had been stored in encrypted form and that the log conveniently included all the ingredients needed to decrypt it. Very considerate of them, really.

Using those parameters in CyberChef:

<figure><img src=".gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

The encrypted value resolves to: `SHADOWLINK_CLUSTER_47B829X`
