# Episode 2

**Task**

Ik ben op zoek naar een kwetsbaarheid, heb je die gevonden. Stuur die aan mij.



Starting off with a lot of messages:

<figure><img src="../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

The first thing that pops out is the qr code of course, so lets get that virus!&#x20;

It gives `RGlmZGwgYnN1amRtZiAyMjczODghCgpCbSBwdnMgY3Zzb2ZzdCBic2YgYnUgc2p0bCEgRWZ0dXNweiB1aWYgZWZ3amRmdCE=` as result, this is base64 encoded. Lets put it in cyberchef:

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

It gives:

```
Difdl bsujdmf 227388!

Bm pvs cvsofst bsf bu sjtl! Eftuspz uif efwjdft!
```

This seems to be caeser cipher, so lets chuck it into a decoder:

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

This gives us:

```
check article 227388!

al our burners are at risk! destroy the devices!
```

What is article 227388? Maybe on tweakers? Since this is made by the police thats the first place it popped up into my head after double checking the browser history on markovics laptop, since i saw some articles there as well.

And bingo, we find [https://tweakers.net/nieuws/227388/android-telefoons-bevatten-lek-dat-remotecode-execution-mogelijk-maakt.html](https://tweakers.net/nieuws/227388/android-telefoons-bevatten-lek-dat-remotecode-execution-mogelijk-maakt.html). This shows that there is a vulnerability `CVE-2024-40673`.

***

**Task**

Ik ben op zoek naar iets wat ons verder helpt. Een code, een url, iets. Stuur die in de chat zodra je hem hebt.



We got a github repository: [https://github.com/netherops-dev/shadowlink-recovery-tool](https://github.com/netherops-dev/shadowlink-recovery-tool)

It seems to contain a python script that can decrypt a .shadow file. Theyre also nice to provide a sample, but for this a .env is needed with key SHADOW\_KEY. Luckily for us, when looking through the commits, a .env seems to be accidently commited containing the key `SHADOW_KEY=Y3KW0D4H5`: [https://github.com/netherops-dev/shadowlink-recovery-tool/commit/888ab8eb1b9bb17f9487d816d12f0c9f43fd2e67](https://github.com/netherops-dev/shadowlink-recovery-tool/commit/888ab8eb1b9bb17f9487d816d12f0c9f43fd2e67)

lets use it on the sample:

```shellscript
shadowlink-recovery-tool on  main [!] via 🐍 v3.10.16
❯ cat .env
SHADOW_KEY=Y3KW0D4H5

shadowlink-recovery-tool on  main [!] via 🐍 v3.10.16
❯ python3 decrypt.py samples/backup_sample.shadow
[00:12:05] Vince: Yo, you got what we need?
[00:12:22] Rico: Yeah. Packed. Moving in 10.
[00:13:01] Vince: Don’t mess this up, man.
[00:13:44] Rico: Chill. It’s locked down. You got the spot?
[00:14:10] Vince: Same as last time. Low-key.
[00:14:36] Rico: Copy. Who’s on lookout?
[00:15:02] Vince: Nobody this time. Just keep it quiet and quick.
[00:16:18] Rico: Traffic’s clear. Pulling out now, won’t be long.
[00:17:05] Vince: Bring the black bag. Nothing extra.
[00:17:29] Vince: Delivery pending, contact on Insta @netherops_logistics
[00:17:45] Rico: Bag’s strapped in. Phone on silent.
[00:18:12] Vince: Pull up on the left I’ll flash once. Don’t stop.
[00:19:03] Rico: See you in 4. Keep eyes on the street.
[00:20:10] Vince: On my way. Don’t move until I’m near.
[00:21:07] Rico: Clean swap. Text if anything goes sideways.
```

We got some chat messages, is this key the answer as well? It is not. We continue the search. Reading the chat messages gives us an instagram handle `@netherops_logistics` : [https://www.instagram.com/netherops\_logistics/](https://www.instagram.com/netherops_logistics/)

This shows pictures of trucks with the url `shdwlnk.nl`.

***

**Task**

Ik weet niet precies wat we zoeken, maar als je iets kan vinden wat ons verder helpt zou het geweldig zijn. Een naam, email of andere contactgegevens. Zet het in de chat zodra je het hebt.



Navigating to shdwlnk.nl gives us a big screen with 418 page not available. I start looking through the console and logs and find:

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

There is a nice log showing us the api endpoint: `/api/v2/phonelog` . A GET request is not allowed on this endpoint, but a POST is Invalid request. We need something as payload. Scrolling a bit up in the code we find the payload, how nice:

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

We need to provide a phone number, lucky i have a good memory and remember a phone number was used in the chat messages. Lets try it with that one:

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

We got a response, `+7 (949) 299-61` .

***

**Task**

Kan jij iets van gegevens uit deze call log halen? Heb je iets? Plaats het in de chat.



We get a mp3 file with keyboard tones, using a DTMF tone decoder we get `344408922555333088044288833660777` , but this translates to `di twblf u haven r` . Not really of use. So next step is to finally use our new friend Claude, surely that will give us the right key strokes right? Well after some Claude came up with: `2344408922555333088044288833660777`  this translates to `di twaalf u haven r` , sounding a bit more like dutch than the previous one, but it was very close.

