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



To the policestation we go!







