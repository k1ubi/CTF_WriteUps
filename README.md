<div align="center">

```
 _____ ___________   _    _______ _____ _____ _____ _   _______  _____ 
/  __ \_   _|  ___| | |  | | ___ \_   _|_   _|  ___| | | | ___ \/  ___|
| /  \/ | | | |_    | |  | | |_/ / | |   | | | |__ | | | | |_/ /\ `--. 
| |     | | |  _|   | |/\| |    /  | |   | | |  __|| | | |  __/  `--. \
| \__/\ | | | |     \  /\  / |\ \ _| |_  | | | |___| |_| | |    /\__/ /
 \____/ \_/ \_|      \/  \/\_| \_|\___/  \_/ \____/ \___/\_|    \____/
```

`[ HackTheBox :: recon -> foothold -> root, logged ]`

![hackthebox](https://img.shields.io/badge/HACKTHEBOX-ff00c8?style=for-the-badge&logo=hackthebox&logoColor=00fff9&labelColor=0a0014)
![linux](https://img.shields.io/badge/TARGETS-LINUX_%2F_AD-00fff9?style=for-the-badge&logo=linux&logoColor=0a0014&labelColor=0a0014)
![hashcat](https://img.shields.io/badge/CRACKING-HASHCAT-ff00c8?style=for-the-badge&logo=hashcat&logoColor=00fff9&labelColor=0a0014)

</div>

<br>

```
▓▒░ 0x00 // LOG INDEX ░▒▓
```

Every entry below is a real box, worked start to finish (or as far as the log currently goes).
The actual commands, screenshots and dead ends are kept in, this is not a cleaned-up victory lap.

<br>

| target | vector | status | log |
|---|---|---|---|
| **Cap** | IDOR on a packet-capture download endpoint leaks FTP creds → `python3.8` capability abuse (`cap_setuid`) for root | `► rooted` | [Cap Writeup.md](<HackTheBox/Cap/Cap Writeup.md>) |
| **Dog** | Exposed `.git` on Backdrop CMS → hardcoded DB creds → tar-upload RCE → mysql hash dump → password reuse over SSH → `sudo bee ev` to root | `► rooted` | [Dog Writeup.md](<HackTheBox/Dog/Dog Writeup.md>) |
| **UnderPass** | SNMP leaks a username + daloRADIUS install → default creds on `/operators/` → cracked `svcMosh` hash → `mosh`-based sudo privesc | `► rooted` | [UnderPass WriteUp.md](<HackTheBox/UnderPass/UnderPass WriteUp.md>) |
| **EscapeTwo** | AD/MSSQL box (`sequel.htb`), shared `.xlsx` leaks `sa` creds → `xp_cmdshell` RCE via MSHTA → hunting `sql_svc` cred reuse | `► in progress` | [EscapeTwo.md](<HackTheBox/EscapeTwo/EscapeTwo.md>) |
| **Nexus** | Static decoy site hides two real vhosts → git history leaks a redacted DB password → CRM cred reuse → CVE-2026-38526 upload RCE → `.env` on disk → SSH cred reuse → root via git-tree path traversal in a root-run sync timer | `► rooted` | [Nexus WriteUp.md](<HackTheBox/Nexus/Nexus WriteUp.md>) |

<br>

```
▓▒░ 0x01 // FIELD NOTES ░▒▓
```

- `►` write-ups are written as they happened, commands, screenshots and wrong turns included
- `►` `EscapeTwo` is a live AD engagement log, not a finished report. Expect it to grow
- `►` credentials/hashes shown in these logs are lab-only, tied to disposable HackTheBox targets

<br>

<div align="center">

`.: . . : <[ hack the planet ]> : . :.`

</div>
