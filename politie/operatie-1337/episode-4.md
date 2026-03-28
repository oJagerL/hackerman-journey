# Episode 4

**Task**

Maak wederom connectie met shadow@in.shdwlnk.nl, met de key die ik je net gestuurd heb. Je toegangscode is guest\_23dff48a. Vind een bestand met mogelijke doelwitten voor project atlas.



Lets reconnect to the server:

```shellscript
❯ ssh shadow@in.shdwlnk.nl -i shdw.key
[ Restricted Access System ]
STATUS: Operational NODE: SL-GATEWAY-04
SECURITY LEVEL: 3 (Medium) WARNING: All activities are logged and monitored. Unauthorized access will be reported to authorities.

Voer uw toegangscode in: guest_23dff48a

Welkom in ShadowLink OS. Voor dienstverlening plaats uw verzoek in: /clients/requests/
Huidige tijd: 2026-03-28 08:00:55 UTC
Laatste login: 2026-03-28 07:38:38 van 185.220.101.47

Shadowlink-OS .$
```

lets start with using find right away, maybe a filename will point to the answer already:

```shellscript
Shadowlink-OS .$ find . | grep atlas
./projects/atlas/.backup_link
./projects/atlas/targets_BD1E65A684.txt
./projects/atlas/notes.txt
```

`/projects/atlas/targets_BD1E65A684.txt` sounds promising

***

**Task**

Zoek in de foto's of je iets kan vinden wat te maken heeft met project Aibo. Misschien iets om het bestand te decoderen?



We got a zip full supposidly full of images, but I notice a .docx as well. However, this file is not a real docx it seems to be a jpeg:

```shellscript
❯ file doggie.docx
doggie.docx: JPEG image data, Exif standard: [TIFF image data, little-endian, direntries=0], baseline, precision 8, 300x419, components 3
```

changing the extension to .jpeg and checking the metadata using exiftool does not give anything useful. Lets try exiftool on all files and just grep the description!

```shellscript
❯ exiftool . | grep -i description
Image Description               : target_pw_fba14cb0
Image Description               : remote-hub-access-ea297481
```

Checking out `IMG_7296.jpg` which has `target_pw_fba14cb0` as description, shows a dog with the dogtag Aibo. This seems right.

***

**Task**

Decrypt het document met dit wachtwoord. Die woordcombinaties moeten locaties zijn. Zoek het eerste doelwit op in het document en stuur me de coördinaten (lat, lng).



Checking out the available commands with help on the server, i see we can use decrypt for this.

```shellscript
Shadowlink-OS atlas$ decrypt targets_BD1E65A684.txt target_pw_fba14cb0
targets_BD1E65A684.txt succesfully decrypted
Shadowlink-OS atlas$ ls
targets_BD1E65A684.txt
notes.txt
Shadowlink-OS atlas$ cat targets_BD1E65A684.txt
kanon.dienst.aankijken.zoutste.ververs
mes.hoofd.figuur.knijp.bieders
lijst.iemand.advies.oogwenk.subtiel
glas.verdieping.voldoet.mentaal.directie
das.quatsch.stoep.oerknal.gewoontes
yeti.ziekenhuis.voeren.rijping.bles
citroen.koffie.inloop.fietsslot.nationaal
ei.schip.gedoken.dambord.windvlaag
pen.hoofd.tred.troosten.zeemeeuw
dropsleutel.schip.opleukt.zogende.vestjes
ketting.heuvel.volledig.meereizen.bobbelig
steen.school.kraagje.gloeit.zakt
zakdoek.telefoon.nagerechten.draven.benut
tijd.dienst.vlotten.filmset.snurk
vlag.xantippe.galmend.meemaken.broodmes
stoel.quatsch.bonkte.klusser.blazend
cake.yoghurt.jurk.zwijgzaam.schuif
aap.hoofd.herroep.kringen.opwelt
thee.yoghurt.tramrit.benen.mier
zon.foto.bezoek.baars.treinstel
muis.hoofd.zonuren.schurend.werpt
boom.toegang.bijkomen.doek.kassa
geit.quatsch.uiterlijk.zalf.dansparen
inkt.quatsch.rolkoffer.kalkte.vervullen
gitaar.onderzoek.broos.kubieke.gymles
ruit.onderzoek.oproepen.juiste.invulling
vuur.winkel.bijbenen.puntje.overleg
wolk.heuvel.decaan.krak.verftube
fles.quatsch.benen.zovelen.hoofdwas
noot.xantippe.koorzang.woont.degelijk
paard.iemand.geweekt.examens.aanbraden
xylofoon.heuvel.visvoer.piepend.gesneeuwd
aarde.periode.heenreis.kloven.veenbes
hart.januari.theesoort.loslaten.producties
zebra.mening.buurmannen.mededeling.strekt
jurk.winkel.omloop.verloving.doeken
bloem.heuvel.onderwijs.hagelde.premies
fiets.hoofd.gezicht.buslijn.armsteun
quiz.school.dimmen.aanbod.oliebad
yoghurt.hoofd.groeien.lessen.zeevis
tafel.nacht.zingen.etentje.notie
hond.yoga.rondlopen.uitrusting.haardos
molen.dienst.bosgrond.bekroning.fruitschaal
kerstbal.school.innemen.snaren.spandoek
neus.camping.terugreis.heus.voorvak
oog.winkel.zoutig.luwte.wassen
oceaan.telefoon.vorken.inkopen.opvalt
uil.mening.werkweek.afwisseling.bakje
radio.telefoon.rationeel.gesprek.opzeggen
vis.telefoon.wegnemen.overmaat.rumoer
```

the first target seems to be `kanon.dienst.aankijken.zoutste.ververs`. These words look like the words in `notes.txt`.

```shellscript
Shadowlink-OS atlas$ cat notes.txt
Decrypt: Project Aibo


-----------------------------------

jas: 2026-03-28 15:40:29
muis: 2026-03-28 12:36:15
noot: 2026-03-28 12:21:42
verdieping: Perfect gepositioneerd
dropsleutel: 2026-03-28 13:12:37
yeti: 2026-03-28 12:45:57
theater: Zeer geschikt
idool: Goede keuze
kanon: 2026-03-28 12:33:49
nacht: Afgeraden
koekje: Ideaal
steen: 2026-03-28 12:50:48
raadsel: Optimale ligging
iemand: Te veel omstanders
winkel: Te gevaarlijk
xantippe: Onvoldoende dekking
quatsch: Onvoldoende voorbereiding
zebra: 2026-03-28 12:07:09
oog: 2026-03-28 12:14:26
hart: 2026-03-28 13:07:46
schip: Teveel cameratoezicht
dienst: Ontoelaatbaar
groente: Essentieel
mening: Onveilige positie
januari: Aanbevolen
aarde: 2026-03-28 12:58:04
school: Verhoogd risico
das: 2026-03-28 13:17:28
ketting: 2026-03-28 12:53:13
cirkel: 2026-03-28 14:30:11
ziekenhuis: Suboptimaal
boom: 2026-03-28 13:53:49
broek: 2026-03-28 14:32:37
papier: 2026-03-28 14:13:13
tijd: 2026-03-28 13:15:02
lijst: 2026-03-28 13:19:53
neus: 2026-03-28 11:57:28
gitaar: 2026-03-28 13:00:29
urn: 2026-03-28 15:47:46
cake: 2026-03-28 13:22:19
yoga: Onpraktisch
aap: 2026-03-28 13:46:33
olifant: 2026-03-28 14:25:20
quiz: 2026-03-28 12:41:06
wiel: 2026-03-28 14:42:19
deken: 2026-03-28 15:04:08
inkt: 2026-03-28 11:59:53
hamer: 2026-03-28 14:56:51
leeuw: 2026-03-28 14:18:04
stoel: 2026-03-28 13:36:51
bloem: 2026-03-28 13:24:44
camping: Slecht bereikbaar
jas: 2026-03-28 15:06:33
vork: 2026-03-28 14:44:44
paard: 2026-03-28 12:12:00
uil: 2026-03-28 13:39:17
appel: 2026-03-28 14:47:09
oceaan: 2026-03-28 13:41:42
gras: 2026-03-28 15:11:24
fles: 2026-03-28 12:16:51
ring: 2026-03-28 15:45:20
idee: 2026-03-28 14:39:53
jurk: 2026-03-28 13:29:35
maan: 2026-03-28 15:13:49
huis: 2026-03-28 15:28:22
stoel: 2026-03-28 14:35:02
deur: 2026-03-28 14:08:22
lamp: 2026-03-28 14:22:55
iglo: 2026-03-28 14:49:35
zon: 2026-03-28 13:48:59
zakdoek: 2026-03-28 13:44:08
boot: 2026-03-28 14:59:17
fiets: 2026-03-28 12:55:39
eend: 2026-03-28 14:10:48
vis: 2026-03-28 12:28:59
trein: 2026-03-28 14:27:46
ruit: 2026-03-28 13:05:20
urn: 2026-03-28 15:16:15
yoghurt: 2026-03-28 12:43:31
ui: 2026-03-28 15:55:02
citroen: 2026-03-28 12:09:35
foto: Niet geschikt
geluk: Hoogste prioriteit
droom: Slechte timing
yoghurt: 2026-03-28 15:08:59
oever: Definitief
ijzer: 2026-03-28 15:18:40
water: 2026-03-28 15:38:04
vuur: 2026-03-28 13:51:24
raam: 2026-03-28 15:30:48
hoofd: Te drukke omgeving
koffie: Inadequaat
nest: 2026-03-28 14:05:57
balkon: Uitstekende dekking
aardbei: Ligging niet optimaal
cultuur: Voorkeur van Volkov
foto: 2026-03-28 15:25:57
ei: 2026-03-28 13:27:09
otter: 2026-03-28 14:20:29
computer: 2026-03-28 15:52:37
kerstbal: 2026-03-28 13:34:26
uitgang: Doen!
telefoon: Afwijzen
auto: 2026-03-28 14:15:39
kamer: 2026-03-28 15:57:28
film: 2026-03-28 14:52:00
toegang: Ongunstig
zadel: 2026-03-28 15:42:55
periode: Top keuze
plant: 2026-03-28 15:50:11
heuvel: Te veel verlichting
yoghurt: Te ver van doelwit
jas: 2026-03-28 15:21:06
pauze: Prima locatie
thee: 2026-03-28 12:31:24
dier: 2026-03-28 13:58:40
kaars: 2026-03-28 15:01:42
yoghurt: Te riskant
wolk: 2026-03-28 12:38:40
radio: 2026-03-28 13:56:15
vlag: 2026-03-28 12:24:08
mes: 2026-03-28 12:04:44
geit: 2026-03-28 12:19:17
sleutel: 2026-03-28 14:03:31
xerox: 2026-03-28 15:33:13
lepel: 2026-03-28 14:01:06
hond: 2026-03-28 13:32:00
molen: 2026-03-28 12:48:22
glas: 2026-03-28 13:02:55
pen: 2026-03-28 12:26:33
nacht: 2026-03-28 14:37:28
xylofoon: 2026-03-28 13:10:11
tafel: 2026-03-28 12:02:19
quiz: 2026-03-28 15:35:39
ezel: 2026-03-28 14:54:26
onderzoek: Strategisch voordelig
emmer: 2026-03-28 15:23:31
```

Combining the two files, we get:

```
2026-03-28 12:33:49.Ontoelaatbaar.aankijken.zoutste.ververs
2026-03-28 12:04:44.Te drukke omgeving.figuur.knijp.bieders
2026-03-28 13:19:53.Te veel omstanders.advies.oogwenk.subtiel
2026-03-28 13:02:55.Perfect gepositioneerd.voldoet.mentaal.directie
2026-03-28 13:17:28.Onvoldoende voorbereiding.stoep.oerknal.gewoontes
2026-03-28 12:45:57.Suboptimaal.voeren.rijping.bles
2026-03-28 12:09:35.Inadequaat.inloop.fietsslot.nationaal
2026-03-28 13:27:09.Teveel cameratoezicht.gedoken.dambord.windvlaag
2026-03-28 12:26:33.Te drukke omgeving.tred.troosten.zeemeeuw
2026-03-28 13:12:37.Teveel cameratoezicht.opleukt.zogende.vestjes
2026-03-28 12:53:13.Te veel verlichting.volledig.meereizen.bobbelig
2026-03-28 12:50:48.Verhoogd risico.kraagje.gloeit.zakt
2026-03-28 13:44:08.Afwijzen.nagerechten.draven.benut
2026-03-28 13:15:02.Ontoelaatbaar.vlotten.filmset.snurk
2026-03-28 12:24:08.Onvoldoende dekking.galmend.meemaken.broodmes
2026-03-28 13:36:51.Onvoldoende voorbereiding.bonkte.klusser.blazend
2026-03-28 13:22:19.2026-03-28 12:43:31.2026-03-28 13:29:35.zwijgzaam.schuif
2026-03-28 13:46:33.Te drukke omgeving.herroep.kringen.opwelt
2026-03-28 12:31:24.2026-03-28 12:43:31.tramrit.benen.mier
2026-03-28 13:48:59.Niet geschikt.bezoek.baars.treinstel
2026-03-28 12:36:15.Te drukke omgeving.zonuren.schurend.werpt
2026-03-28 13:53:49.Ongunstig.bijkomen.doek.kassa
2026-03-28 12:19:17.Onvoldoende voorbereiding.uiterlijk.zalf.dansparen
2026-03-28 11:59:53.Onvoldoende voorbereiding.rolkoffer.kalkte.vervullen
2026-03-28 13:00:29.Strategisch voordelig.broos.kubieke.gymles
2026-03-28 13:05:20.Strategisch voordelig.oproepen.juiste.invulling
2026-03-28 13:51:24.Te gevaarlijk.bijbenen.puntje.overleg
2026-03-28 12:38:40.Te veel verlichting.decaan.krak.verftube
2026-03-28 12:16:51.Onvoldoende voorbereiding.benen.zovelen.hoofdwas
2026-03-28 12:21:42.Onvoldoende dekking.koorzang.woont.degelijk
2026-03-28 12:12:00.Te veel omstanders.geweekt.examens.aanbraden
2026-03-28 13:10:11.Te veel verlichting.visvoer.piepend.gesneeuwd
2026-03-28 12:58:04.Top keuze.heenreis.kloven.veenbes
2026-03-28 13:07:46.Aanbevolen.theesoort.loslaten.producties
2026-03-28 12:07:09.Onveilige positie.buurmannen.mededeling.strekt
2026-03-28 13:29:35.Te gevaarlijk.omloop.verloving.doeken
2026-03-28 13:24:44.Te veel verlichting.onderwijs.hagelde.premies
2026-03-28 12:55:39.Te drukke omgeving.gezicht.buslijn.armsteun
```

Picking out the positives, gives:

```
2026-03-28 13:02:55.Perfect gepositioneerd.voldoet.mentaal.directie
2026-03-28 13:00:29.Strategisch voordelig.broos.kubieke.gymles
2026-03-28 13:05:20.Strategisch voordelig.oproepen.juiste.invulling
2026-03-28 12:58:04.Top keuze.heenreis.kloven.veenbes
2026-03-28 13:07:46.Aanbevolen.theesoort.loslaten.producties
```

According to the hints i need to sort those:

```
2026-03-28 12:58:04.Top keuze.heenreis.kloven.veenbes
2026-03-28 13:00:29.Strategisch voordelig.broos.kubieke.gymles
2026-03-28 13:02:55.Perfect gepositioneerd.voldoet.mentaal.directie
2026-03-28 13:05:20.Strategisch voordelig.oproepen.juiste.invulling
2026-03-28 13:07:46.Aanbevolen.theesoort.loslaten.producties
```

Also from the help of the hints, i learned about [https://what3words.com/](https://what3words.com/). I did not know this existed, very cool.

After a while, playing around with this website and putting in all 5 locations in what3words, i only saw one building, a school. but this was not it. So i started checking tweakers for hints, and someone mentioned to use bing. So i did, and then i suddenly saw little buildings pop up and the answers started rolling in.

First coordinates: `52.891669, 6.474942`\
Second coordinates: `52.547879, 6.225129`\
Third coordinates: `52.772356, 6.886921`\
Fourth coordinates: `52.804374, 6.038343`\
Fifth coordinates: `52.542273, 6.68293`&#x20;

***

Task

Kun je nog eens naar de metadata van de foto's kijken naar iets wat met transport te maken heeft? als je wat vindt plaats het in de chat.



In a previous task we already saw a second code in the metadata. Thats probably this answer:

```shellscript
❯ exiftool . | grep -i description
Image Description               : target_pw_fba14cb0
Image Description               : remote-hub-access-ea297481
```

Answer: `remote-hub-access-ea297481`&#x20;

***

Task:

Ga naar Hoofdstraat 54 in Driebergen, en laat weten dat je komt voor operatie 1337. Haal de envelop op, en geef mij de code die je in de envelop gevonden hebt.



To the policestation we go! We got a letter and a tshirt, the letter contained the code `7K52TYS5Z6`.

***

Task

Jouw toegangscode is guest\_23dff48a, verstuur de bestanden naar onze server op: datatransfer.operatie1337.nl



We ssh into the server, lets transfer:

```shellscript
❯ ssh shadow@in.shdwlnk.nl -i shdw.key
[ Restricted Access System ]
STATUS: Operational NODE: SL-GATEWAY-04
SECURITY LEVEL: 3 (Medium) WARNING: All activities are logged and monitored. Unauthorized access will be reported to authorities.

Voer uw toegangscode in: guest_23dff48a

Welkom in ShadowLink OS. Voor dienstverlening plaats uw verzoek in: /clients/requests/
Huidige tijd: 2026-03-28 14:20:18 UTC
Laatste login: 2026-03-28 13:58:01 van 185.220.101.47

Shadowlink-OS .$ transfer . datatransfer.operatie1337.nl 400
connecting to "datatransfer.operatie1337.nl"
transmitting data...

0/89336
200/89336
400/89336
600/89336
800/89336
1000/89336
1200/89336
1400/89336
...
88400/89336
88600/89336
88800/89336
89000/89336
89200/89336
89336/89336
transfer complete
```

***

Task

Schakel nu de software van Project Atlas uit.



Lets kill atlas!

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
Shadowlink-OS .$ kill 391
ERROR: Permission denied
Process 'atlasrunner' (PID 391) requires root privileges to terminate.
Shadowlink-OS .$
```

It seems we need root privileges, according to Sara we can use the code for this.

```shellscript
Shadowlink-OS .$ su
Password:
Access granted. You are now operating as superuser.
WARNING: You have elevated privileges. Exercise caution.
Shadowlink-OS .$ kill 391
Terminating process 'atlasrunner' (PID 391) ...
Process terminated successfully.
WARNING: Critical system process stopped. Dependencies may be affected
Shadowlink-OS .$
```

***

Task

Zorg dat er niets meer te herstarten valt!



In the help command I already noticed there was an overclock command, so lets see how to use it:

```shellscript
Shadowlink-OS .$ overclock
NAME
       overclock - force hardware component beyond safe operational limits

SYNOPSIS
       overclock [device] [wattage]

DESCRIPTION
       Overrides safety protocols and forces the specified hardware device
       to operate at dangerously elevated power levels. Sustained operation
       beyond manufacturer specifications will cause permanent physical
       damage to the component and connected systems.

       WARNING: This command bypasses all thermal and electrical safeguards.
       System instability, hardware failure, and fire hazard are expected
       outcomes.

PARAMETERS
       device
              Target hardware component identifier. Available devices:

              CPU      - Central Processing Unit
              GPU      - Graphics Processing Unit
              MEMORY   - RAM modules and memory controller
              NETWORK  - Network interface and routing hardware

       wattage
              Power level in watts to force through the device. Values
              exceeding rated capacity will cause cascading failure.
              Manufacturer limits are intentionally ignored.

              Typical safe ranges (DO NOT EXCEED):
              CPU:     65-125W
              GPU:     150-350W
              MEMORY:  10-25W
              NETWORK: 5-50W

EXAMPLES
       overclock CPU 65
              Forces CPU to draw 65W

       overclock NETWORK 10
              Pushes 10W through network hardware

       overclock GPU 200
              Overloads GPU with 200W


NOTES
       This command is irreversible. Once initiated, the overload process
       cannot be stopped until hardware destruction occurs.

       Cascading failures may propagate to connected infrastructure.

       This operation leaves forensic evidence and is detectable by
       monitoring systems.

       Root privileges required.
WARNINGS
       - Permanent equipment damage
       - Risk of electrical fire
       - Potential harm to personnel near affected hardware
       - Legal consequences for infrastructure sabotage
​
       Use only in authorized testing environments or emergency scenarios.
```

perfect, lets overload the network!

```shellscript
​Shadowlink-OS .$ overclock NETWORK 60
Initializing overclock sequence...
Target: NETWORK
Power level: 60W (120.00001% of rated capacity)
WARNING: This operation could cause permanent hardware damage.
Are you sure you wish to continue? y/n:
​
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
Bypassing thermal limiters... DONE
Disabling safety protocols... DONE
Routing power to NETWORK hardware...
​
10%  Temperature: 47°C - Normal
25%  Temperature: 68°C - Elevated
40%  Temperature: 89°C - Warning
55%  Temperature: 112°C - CRITICAL
70%  Temperature: 138°C - DANGER
85%  Temperature: 167°C - FAILURE IMMINENT
​
ERROR: NETWORK hardware failure detected
ERROR: Cascading failure in connected systems
ERROR: Router banks 1-4 offline
ERROR: Switch array thermal runaway
ERROR: Fiber optic relays melted
ERROR: Power supply failure
​
​
████████ ██████ ███████
CRITICAL SYSTEM FAILURE
████████ ██████ ███████
CRITICAL SYSTEM FAILURE
████████ ██████ ███████
CRITICAL SYSTEM FAILURE
Network infrastructure destroyed
Connection to remote systems lost
Local system instability detected
​
[Connection terminated]
Connection to in.shdwlnk.nl closed.
```

Nice, we stopped them.
