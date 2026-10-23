# am-i-infected

Read-only compromise assessment for **PHP2Shell** (CVE-2026-109618 / CVE-2026-109619).

Run it **on a server you administer**. It checks whether the host is still exposed (vulnerable PHP,
processes not restarted after patching, tampered packages) and looks for evidence that the bugs were
attempted or abused: exploitation-attempt markers and crash patterns in logs, post-exploitation artefacts
(shells spawned by PHP workers, new webshells, persistence), and cross-source correlation of the two.

> **"No indicators found" is not proof that a host is clean.** PHP's own advisories publish no IOCs; the
> indicators here are behavioural and come from public vendor write-ups. See [Limitations](#limitations).

- One file, **standard library only**, Linux, root recommended. Python 3.8+ (static analysis says 3.7 suffices; tested on 3.12)
- **Read-only.** Never sends requests, never runs exploit probes, never modifies the system
- Executes only: `php -n -v` on PHP binaries that pass safety checks (root-owned ELF file in root-owned,
  non-writable directories; run as `nobody` with a clean environment — see [Security](#security-considerations);
  `--no-exec` disables), read-only package-manager queries (`dpkg -S/-V`, `rpm -qf/-V/--changelog`),
  `journalctl`, `coredumpctl`, and — only with `--docker` — `docker inspect/top/exec php -v`
- Makes **no network connections**
- Writes only what you ask for: `-o FILE` and `--collect FILE.tar.gz` (both created with mode 600)

## Quick start

This tool runs as root, so install a **pinned release and verify it** instead of fetching `main`:

```sh
VER=v0.1.0
curl -fsSLO https://github.com/Senturkselim/Am-I-Infected/releases/download/$VER/am_i_infected.py
curl -fsSLO https://github.com/Senturkselim/Am-I-Infected/releases/download/$VER/am_i_infected.py.sha256
sha256sum -c am_i_infected.py.sha256
less am_i_infected.py        # single file, stdlib only: read it before running it as root
sudo python3 am_i_infected.py
```

During an incident wave fake "PHP2Shell checkers" are likely. Only use releases from the official repository.

```sh
sudo python3 am_i_infected.py --since 2026-10-01             # time window (default 2026-10-01)
sudo python3 am_i_infected.py --timeline                     # merged chronological timeline
sudo python3 am_i_infected.py --docker                       # also inspect running containers
sudo python3 am_i_infected.py --collect /root/evidence.tar.gz   # incident-response bundle
sudo python3 am_i_infected.py --json -o report.json
sudo python3 am_i_infected.py --log-path /srv/logs --webroot /srv/app
```

All switches: `--no-logs --no-journal --no-fs --no-procs --no-persistence --no-integrity --no-exec
--trust-exec PATH --max-evidence N --no-color --version`. (`--trust-exec` lets you vouch for a PHP binary
that failed the safety checks, e.g. a self-compiled PHP in a group-writable directory.)

## What it checks

| Area | Checks |
| --- | --- |
| **Exposure** | PHP version per binary **and** per mod_php library; **distro backport detection** (`dpkg`/`rpm` changelog must mention *both* CVEs, otherwise the upstream version decides — fixed upstream: 8.2.35, 8.3.36, 8.4.27, 8.5.12); SAPI inventory (mod_php is rated highest risk); processes still running pre-upgrade binaries; **package integrity** (`dpkg -V` / `rpm -V` on PHP packages); interim-mitigation posture from `php.ini`, FPM pools and Apache config; services listening on non-loopback addresses |
| **Logs** (Apache, nginx, PHP, FPM, syslog, journald, ModSecurity, auth, auditd; `.gz/.bz2/.xz`) | `PHP_SESSION_UPLOAD_PROGRESS` markers (**including a custom `session.upload_progress.name`** read from your config); the public PoC's / scanners' **User-Agents** (`php2shell-*`); oversized `PHPSESSID` (redacted); POST 500/502 bursts per IP; worker crashes (FPM signals, segfaults in kernel journal, `coredumpctl`); memory-exhaustion / timeout spikes; illegal-session-ID warnings; **web-user SSH logins and sudo**; **auditd** `execve` of shells/recon tools by web accounts; attacker source-IP summary |
| **Processes / network** | Shells, recon tools, downloaders spawned by web/PHP workers; reverse-shell / pipe-to-shell command lines; web-user processes running from `/tmp`, `/dev/shm`, `/var/tmp` or deleted binaries; **bind-shell pattern** (non-web process of a web user listening); outbound connections from workers to public IPs on unusual ports; processes referencing the public PoC |
| **Docker** (`--docker`) | Per container: PHP version (image `PHP_VERSION` env, or `docker exec php -v`) and the same worker-child-process analysis via `docker top` |
| **Files** | Web roots: changed PHP files, **webshell heuristics** (including request data decoded into `eval`), PHP in upload/cache dirs, `auto_prepend_file`/`auto_append_file` and PHP-handler overrides in `.htaccess`/`.user.ini`, **timestomp detection** (mtime forged, ctime recent — still content-scanned); **PHP session files** (oversized IDs/files, upload-progress entries; IDs redacted); **system PHP config** (`auto_prepend_file`, extensions loaded from temp/web/home paths, recently modified unowned `.so` files); PoC/tooling file names |
| **Persistence** | Cron files, extra UID-0 accounts, web users with login shells, `authorized_keys`, `ld.so.preload`, systemd units |
| **Correlation** | Attempt markers → new PHP files / cron / SSH keys / web-user logins / shell execution within 6 h = **HIGH**; attempt markers + crash/memory symptoms within ±1 h = MEDIUM |

## Output

Findings have a severity (`info`, `low`, `medium`, `high`) and a category (`exposure`, `indicator`). The
exit code is a **bitmask** for automation:

| Bit | Meaning |
| --- | --- |
| `1` | Exposure: PHP likely vulnerable (no backport evidence) and/or stale pre-upgrade processes |
| `2` | Suspicious indicators (medium) |
| `4` | High-confidence indicators |

`0` means nothing was found *in the data the tool could see*. Each finding shows its evidence; log lines
are trimmed and PHP session IDs are redacted.

### Evidence bundle (`--collect`)

One `.tar.gz` for incident response: `report.json`, `timeline.txt`, matched log excerpts, process and TCP
snapshots, and **copies of flagged files** — stored with a `.quarantine` suffix and mode `0400` so they cannot
be executed or served by accident — plus `MANIFEST.sha256` (hash, original path, reason, mtime). Treat the
archive as sensitive and possibly malicious; analyse it off the host.

### SIEM rules (`sigma/`)

Six experimental Sigma rules (validated with pySigma): PoC/scanner User-Agents, the upload-progress field in
WAF/body logs, shell/recon tool spawned by a PHP worker, reverse-shell command lines from a worker, FPM
crash/OOM messages, oversized `PHPSESSID`. Field names for cookie/UA sources may need mapping for your pipeline.

## Security considerations

The tool runs as root over **attacker-influenced input** (logs, file names, the process table, web-root files),
so it is hardened accordingly and covered by regression tests (`SecurityTests`):

- **Never executes untrusted binaries.** A local attacker can start a process named `php-fpm` from `/tmp`;
  executing that path as root would be a privilege escalation (found and fixed during pre-release security review). Such
  look-alikes are not executed — they are reported as `proc.php_masquerade`. Trusted binaries are still run
  as `nobody`, with a clean environment, no stdin and `cwd=/`. `PATH` is reset to system directories.
- **Terminal-injection safe.** Control characters in log lines and file names are escaped, so crafted data
  cannot clear the screen, hide findings or forge report lines.
- **Cannot be stalled by crafted files.** Regexes over attacker-controlled data are linear-time (a 64 KB
  `.htaccess` used to stall the scan for over a minute); log lines are read in bounded chunks.
- **Symlink / FIFO safe.** Attacker-writable files are opened with `O_NOFOLLOW|O_NONBLOCK` and verified on the
  open descriptor; evidence copies are stored as `.quarantine`, mode `0400`.

Things the tool cannot fix for you:

- **Reports are sensitive** (hostnames, versions, paths, IPs, log excerpts). The `--collect` bundle may also
  contain secrets and attacker code. Don't post them publicly; store them off the host.
- **Log poisoning.** Attackers can write fake markers or spoofed source IPs into logs. Treat the report as
  leads and **never auto-block IPs** from it.
- **The detection logic is public**, so attackers can read it and try to evade it (change User-Agents, stay
  under thresholds, avoid watched paths). Use this tool alongside EDR/eBPF sensors, a WAF and off-host log
  shipping, not instead of them.
- It contains **no exploit code or technique**; it only reads. Found a vulnerability in the tool itself? See
  [SECURITY.md](SECURITY.md).

## Limitations

- It only sees this machine. An attacker with code execution can tamper with files and logs; a root-level compromise can hide almost anything.
- PHP's advisories publish no IOCs, and vendor guidance partly **disagrees** (e.g. which CVE `session.upload_progress.enabled=0` covers; whether PHP 8.1 and older get fixes — one vendor reports minimal source backports for 7.4/8.0/8.1, another says never). The tool reports this uncertainty instead of guessing.
- Access logs normally don't record POST bodies, so exploit payloads are mostly invisible. A failure can happen before PHP writes any message, and patched PHP intentionally exits on a hard-OOM threshold.
- The memory-disclosure variant may leave **no trace**. If a vulnerable, internet-facing host ran between ~2026-10-17 and patching, rotating secrets is prudent even when nothing is found.
- Process, network and container checks are point-in-time snapshots.
- Version verdicts rely on upstream numbers plus package changelogs; custom builds and vendor-bundled PHP can be mis-classified (reported as UNKNOWN where possible).
- Heuristics (webshell patterns, timestomp, auditd/auth) produce false positives on busy or customised hosts; the auditd check needs an `execve` audit rule.
- If logs were rotated away, the report states how far back it could see. Linux only; Windows/IIS hosts are not covered.

## If you found something

1. Preserve evidence: snapshot the VM/disk, run with `--collect`, copy logs off the host.
2. Patch PHP and **restart every PHP SAPI** (php-fpm, apache2/mod_php, lsphp, …). A patched file on disk doesn't help if the old code is still in memory; restarting also clears shared OPcache state, which one of the bugs can corrupt. For containers, rebuild/pull the image and recreate the container.
3. Rotate everything PHP processes could read: database passwords, API keys, session secrets, tokens, certificates.
4. Remove persistence and consider rebuilding from a known-good image.

## Sources

| Source | Used for |
| --- | --- |
| PHP security advisory 2026-10-21 (as relayed by CybaVerse, AlmaLinux, VulnCheck) | Fixed releases, interim settings, "updating is the only complete fix" |
| CybaVerse PHP2Shell checker & hunt guide | mod_php highest risk, backport/changelog approach, worker-child-process hunt, interim config |
| Kela (underground response) | Public-PoC and scanner User-Agents |
| Indusface, Sophos, Armis, SOCRadar | Upload-progress marker (incl. custom name), POST/500 bursts, memory/crash logs, new PHP files, outbound connections |
| Wiz (via Recorded Future, Prophet Security) | Oversized `PHPSESSID`, upload-progress paths, exploitation against WordPress/Drupal/Joomla images |
| Abstract Security | Upload filename written into the session file (session-file check) |
| `php2shell-checker` project | Vulnerable version ranges as of 2026-10-20 |

Indicators and version data change quickly: update `VULN_MAX`, `FIXED` and the patterns in the script as
advisories evolve. Contributions welcome.

## Changelog

- **0.1.0** — first public release (experimental; not yet validated on real compromised hosts). Exposure checks
  (version, distro backports, package integrity, stale processes, mitigation posture, Docker); log analysis
  (web, error, auth, auditd, kernel, coredump, ModSecurity); process, network, file and persistence checks;
  cross-source correlation, timeline and `--collect` evidence bundle; Sigma rules; hardened against
  attacker-controlled input (see Security considerations).

## Tests

```sh
python3 -m unittest -v test_am_i_infected
```

Tests use synthetic fixtures and mocks only; no exploit code is included or needed.

## Disclaimer

Provided as-is, without warranty. Use only on systems you own or are authorised to assess.
