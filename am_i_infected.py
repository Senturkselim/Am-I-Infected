#!/usr/bin/env python3
"""
am-i-infected -- read-only compromise assessment for PHP2Shell
(CVE-2026-109618 / CVE-2026-109619).

Run it ON the server you administer (root recommended). It only READS logs,
files, /proc, package databases and the output of `php -n -v` (only for root-owned ELF
binaries in root-owned directories, run as `nobody`; never for files in temp/home/web
directories). It never sends exploit traffic and never modifies the system. Two opt-in exceptions:
  --collect FILE   writes ONE evidence archive to a path you choose
  --docker         runs read-only `docker inspect / top / exec php -v`

PHP's own advisories publish no IOCs. The indicators here are behavioural and
come from public vendor / researcher write-ups (Wiz, Sophos, Armis, SOCRadar,
Cybaverse, Kela, Indusface, Abstract Security, ...). A result of "no indicators
found" is NOT proof that a host is clean -- see LIMITATIONS in the report.

Exit code is a bitmask:
    1  exposure   (vulnerable / unverifiable PHP, or stale pre-upgrade process)
    2  suspicious indicators (medium severity)
    4  high-confidence indicators
    0  nothing found in the data this tool could see
"""
from __future__ import annotations

import argparse
import bz2
import datetime as dt
import glob
import gzip
import hashlib
import io
import ipaddress
import json
import lzma
import os
import re
import shutil
import socket
import stat as statmod
import subprocess
import sys
import tarfile
import textwrap
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field

try:
    import pwd
except ImportError:  # non-Unix
    pwd = None

__version__ = "0.1.0"

# Exploitation attempts were seen from at least 2026-10-17 and the first
# reports reached the PHP project in August; scan from a margin before that.
DEFAULT_SINCE = "2026-10-01"
MAX_EVENTS = 20000

CVES = ("CVE-2026-109618", "CVE-2026-109619")

# Highest *upstream* patch level still vulnerable, per branch (ranges published
# by the php2shell-checker project as of 2026-10-20).
VULN_MAX = {
    (5, 4): 45, (5, 5): 38, (5, 6): 40,
    (7, 0): 33, (7, 1): 33, (7, 2): 34, (7, 3): 33, (7, 4): 33,
    (8, 0): 30, (8, 1): 34, (8, 2): 34, (8, 3): 35, (8, 4): 26, (8, 5): 11,
}
# Fixed upstream releases (PHP security advisory, 2026-10-21).
FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}
BURST_THRESHOLD = 10          # POST 500/502 per IP per hour
DAY_SPIKE_MEDIUM = 50         # memory/timeouts per day before we call it medium
KILLCHAIN_HOURS = 6           # post-exploitation artefacts this long after an attempt marker

# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass
class Finding:
    id: str
    severity: str          # info | low | medium | high
    category: str          # exposure | indicator | info
    title: str
    detail: str = ""
    evidence: list = field(default_factory=list)


class Report:
    def __init__(self, since: dt.datetime, max_evidence: int):
        self.since = since
        self.max_evidence = max_evidence
        self.findings: list[Finding] = []
        self.coverage: dict = {}
        self.notes: list[str] = []
        self.events: list[tuple] = []     # (datetime, kind, source, text)
        self.flagged: dict[str, str] = {}  # path -> reason (candidates for --collect)

    def add(self, fid, severity, category, title, detail="", evidence=None):
        ev = [printable(e) for e in (evidence or [])]
        title, detail = printable(title), printable(detail)
        if len(ev) > self.max_evidence:
            extra = len(ev) - self.max_evidence
            ev = ev[: self.max_evidence] + [f"... and {extra} more (raise --max-evidence)"]
        self.findings.append(Finding(fid, severity, category, title, detail, ev))

    def note(self, msg: str):
        self.notes.append(msg)

    def add_event(self, ts, kind, source, text):
        if ts is not None and len(self.events) < MAX_EVENTS:
            self.events.append((ts, kind, printable(source), printable(text)[:200]))

    def flag(self, path, reason):
        self.flagged.setdefault(path, reason)


def run_module(rep: Report, name: str, fn, *args, **kwargs):
    """Run one check; a crash in one module must never abort the whole assessment."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - deliberate catch-all for field robustness
        rep.note(f"Module '{name}' failed and was skipped: {type(exc).__name__}: {exc}")
        return None


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_RE_CLF = re.compile(r"\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})")
_RE_SLASH = re.compile(r"(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})")
_RE_ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})")
_RE_PHP = re.compile(r"\[(\d{2})-([A-Za-z]{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2})")
_RE_APACHE_ERR = re.compile(
    r"\[[A-Za-z]{3} ([A-Za-z]{3}) (\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)? (\d{4})\]")
_RE_SYSLOG = re.compile(r"([A-Za-z]{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})")


def parse_ts(line: str, now: dt.datetime):
    """Best-effort timestamp parse for Apache/nginx/PHP/FPM/syslog/journald lines."""
    try:
        m = _RE_CLF.search(line)
        if m:
            d, mon, y, hh, mm, ss = m.groups()
            return dt.datetime(int(y), MONTHS[mon.title()], int(d), int(hh), int(mm), int(ss))
        c = line[:1]
        if c.isdigit():
            m = _RE_ISO.match(line) or _RE_SLASH.match(line)
            if m:
                return dt.datetime(*map(int, m.groups()))
        elif c == "[":
            m = _RE_PHP.match(line)
            if m:
                d, mon, y, hh, mm, ss = m.groups()
                return dt.datetime(int(y), MONTHS[mon.title()], int(d), int(hh), int(mm), int(ss))
            m = _RE_APACHE_ERR.match(line)
            if m:
                mon, d, hh, mm, ss, y = m.groups()
                return dt.datetime(int(y), MONTHS[mon.title()], int(d), int(hh), int(mm), int(ss))
        elif c.isalpha():
            m = _RE_SYSLOG.match(line)
            if m:
                mon, d, hh, mm, ss = m.groups()
                t = dt.datetime(now.year, MONTHS[mon.title()], int(d), int(hh), int(mm), int(ss))
                if t > now + dt.timedelta(days=2):
                    t = t.replace(year=now.year - 1)
                return t
    except (ValueError, KeyError):
        return None
    return None


def parse_since(value: str) -> dt.datetime:
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M"):
        try:
            return dt.datetime.strptime(value, fmt)
        except ValueError:
            pass
    raise argparse.ArgumentTypeError(f"invalid --since value: {value!r} (use YYYY-MM-DD)")


def open_log(path: str):
    low = path.lower()
    if low.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    if low.endswith(".bz2"):
        return bz2.open(path, "rt", errors="replace")
    if low.endswith(".xz"):
        return lzma.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def run_rc(cmd, timeout=15):
    """Run a read-only command; returns (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return r.returncode, r.stdout or "", r.stderr or ""
    except (OSError, subprocess.SubprocessError):
        return 127, "", ""


def run_cmd(cmd, timeout=15) -> str:
    _rc, out, err = run_rc(cmd, timeout)
    return out + err


def read_small(path: str, limit: int = 65536) -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def hour_of(ts: dt.datetime) -> dt.datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def prune_nested(paths):
    paths = sorted({os.path.realpath(p) for p in paths})
    out = []
    for p in paths:
        if not any(p == q or p.startswith(q.rstrip("/") + "/") for q in out):
            out.append(p)
    return out


def short_id(s: str) -> str:
    """Session IDs are credentials: never print them in full."""
    return f"{s[:6]}...({len(s)} chars)"


_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def printable(s) -> str:
    """Neutralise control characters. Log lines and file names are attacker-controlled; raw ESC bytes could
    clear the screen, hide findings or forge report lines in the administrator's terminal."""
    return _CTRL_RE.sub(lambda m: "\\x%02x" % ord(m.group()), str(s))


def read_nofollow(path: str, limit: int = 1 << 20) -> bytes:
    """Read a regular file WITHOUT following symlinks (for attacker-writable locations). Opening with
    O_NOFOLLOW|O_NONBLOCK and checking the opened descriptor also closes the lstat->open race and
    cannot hang on a FIFO that was swapped in."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not statmod.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        chunks, n = [], 0
        while n < limit:
            b = os.read(fd, min(65536, limit - n))
            if not b:
                break
            chunks.append(b)
            n += len(b)
        return b"".join(chunks)
    finally:
        os.close(fd)


# --------------------------------------------------------------------------
# Process table (Linux /proc)
# --------------------------------------------------------------------------

WEB_COMM_RE = re.compile(
    r"^(?:php-fpm[\d.]*|php-cgi[\d.]*|lsphp[\d.]*|frankenphp|apache2|httpd[\w.-]*|lshttpd|litespeed|nginx|caddy)$")
PHP_EXE_COMM_RE = re.compile(r"^(?:php-fpm[\d.]*|php-cgi[\d.]*|lsphp[\d.]*|frankenphp)$")
APACHE_COMM_RE = re.compile(r"^(?:apache2|httpd[\w.-]*)$")
DEFAULT_WEB_USERS = {"www-data", "apache", "nginx", "nobody", "www", "http", "httpd", "wwwrun"}


def read_procs() -> dict:
    procs: dict = {}
    if not os.path.isdir("/proc"):
        return procs
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        base = f"/proc/{name}"
        try:
            with open(f"{base}/stat") as fh:
                st = fh.read()
            rp = st.rfind(")")
            comm = st[st.find("(") + 1: rp]
            ppid = int(st[rp + 2:].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        uid = None
        try:
            with open(f"{base}/status") as fh:
                for ln in fh:
                    if ln.startswith("Uid:"):
                        uid = int(ln.split()[1])
                        break
        except (OSError, ValueError):
            pass
        try:
            with open(f"{base}/cmdline", "rb") as fh:
                cmd = fh.read(2048).replace(b"\0", b" ").decode(errors="replace").strip()
        except OSError:
            cmd = ""
        try:
            exe = os.readlink(f"{base}/exe")
        except OSError:
            exe = None
        procs[int(name)] = {"comm": comm, "ppid": ppid, "uid": uid, "cmd": cmd, "exe": exe}
    return procs


def uid_name(uid):
    if isinstance(uid, str):
        return uid
    if uid is None or pwd is None:
        return str(uid)
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def web_identities(procs: dict):
    """Names and numeric UIDs of accounts that run web/PHP workers."""
    names, uids = set(DEFAULT_WEB_USERS), set()
    for p in procs.values():
        if WEB_COMM_RE.match(p["comm"]) and isinstance(p["uid"], int) and p["uid"] != 0:
            uids.add(p["uid"])
            names.add(uid_name(p["uid"]))
    if pwd is not None:
        for n in list(names):
            try:
                uids.add(pwd.getpwnam(n).pw_uid)
            except KeyError:
                pass
    return names, uids


def socket_inodes(pid: int) -> set:
    out = set()
    try:
        fds = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        return out
    for fd in fds:
        try:
            tgt = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            continue
        if tgt.startswith("socket:["):
            out.add(tgt[8:-1])
    return out


# --------------------------------------------------------------------------
# 1. Exposure: PHP installs, distro backports, package integrity
# --------------------------------------------------------------------------

PHP_BIN_GLOBS = [
    "/usr/bin/php", "/usr/bin/php[0-9]*", "/usr/sbin/php-fpm*", "/usr/bin/php-cgi*",
    "/usr/local/bin/php", "/usr/local/sbin/php-fpm", "/usr/local/bin/php-cgi",
    "/opt/remi/php*/root/usr/bin/php", "/opt/remi/php*/root/usr/sbin/php-fpm",
    "/opt/plesk/php/*/bin/php", "/opt/plesk/php/*/sbin/php-fpm",
    "/opt/cpanel/ea-php*/root/usr/bin/php", "/opt/cpanel/ea-php*/root/usr/sbin/php-fpm",
    "/usr/local/php*/bin/php", "/usr/local/lsws/lsphp*/bin/lsphp",
]
MODPHP_GLOBS = [
    "/usr/lib/apache2/modules/libphp*.so", "/usr/lib64/httpd/modules/libphp*.so",
    "/usr/lib/httpd/modules/libphp*.so", "/usr/local/apache2/modules/libphp*.so",
    "/opt/remi/php*/root/usr/lib64/httpd/modules/libphp*.so",
    "/opt/cpanel/ea-php*/root/usr/lib64/httpd/modules/libphp*.so",
]


def classify_version(ver: str, suffix: str = "") -> str:
    """'vulnerable' | 'ok' | 'unknown' judged on the UPSTREAM version number only."""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", ver or "")
    if not m:
        return "unknown"
    major, minor, patch = map(int, m.groups())
    cutoff = VULN_MAX.get((major, minor))
    if cutoff is None:
        return "unknown"
    if re.search(r"(?i)(?:^|[-+~.])(?:alpha|beta|rc|dev)\d*", suffix or ""):
        return "unknown"    # pre-release / dev builds may not contain the final fix
    return "vulnerable" if patch <= cutoff else "ok"


def verdict_for(ver, suffix, backported) -> str:
    base = classify_version(ver, suffix) if ver else "unknown"
    if base == "ok":
        return "patched"
    if backported and len(backported) == len(CVES):
        return "patched (distro backport)"
    if backported:
        return "unknown"          # only one of the two CVEs is mentioned in the changelog
    return "likely vulnerable" if base == "vulnerable" else "unknown"


def fixed_hint(ver) -> str:
    m = re.match(r"(\d+)\.(\d+)\.", ver or "")
    if m and (int(m.group(1)), int(m.group(2))) in FIXED:
        k = (int(m.group(1)), int(m.group(2)))
        return f"fixed in {k[0]}.{k[1]}.{FIXED[k]}"
    return "no upstream fixed release for this branch; needs a vendor/source backport or an upgrade"


def pkg_owner(path: str):
    """(manager, package) that owns `path`, or (None, None)."""
    if shutil.which("dpkg"):
        rc, out, _ = run_rc(["dpkg", "-S", path])
        if rc == 0:
            m = re.match(r"^([^:,\s]+)(?::[\w-]+)?(?:,[^:]*)?: ", out)
            if m:
                return "dpkg", m.group(1)
    if shutil.which("rpm"):
        rc, out, _ = run_rc(["rpm", "-qf", "--qf", "%{NAME}\n", path])
        if rc == 0 and out.strip() and "not owned" not in out:
            return "rpm", out.strip().splitlines()[0]
    return None, None


def pkg_version(pm: str, pkg: str):
    """(upstream version or None, full package version string)."""
    if pm == "dpkg":
        _rc, out, _ = run_rc(["dpkg-query", "-W", "-f=${Version}", pkg])
    elif pm == "rpm":
        _rc, out, _ = run_rc(["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg])
    else:
        return None, ""
    full = out.strip()
    m = re.match(r"(?:\d+:)?(\d+\.\d+\.\d+)", full)
    return (m.group(1) if m else None), full


def changelog_cves(pm: str, pkg: str, ids=CVES) -> list:
    """Which of `ids` are mentioned in the package changelog (distro backports)."""
    text = ""
    if pm == "dpkg":
        for p in glob.glob(f"/usr/share/doc/{pkg}/changelog*"):
            try:
                with open_log(p) as fh:
                    text += fh.read(8_000_000)
            except (OSError, EOFError):
                pass
    elif pm == "rpm":
        _rc, out, _ = run_rc(["rpm", "-q", "--changelog", pkg], timeout=30)
        text = out
    return [c for c in ids if c in text]


VERIFY_RE = re.compile(r"^([A-Za-z0-9.?]{8,9})\s+(?:([cdglr])\s+)?(/\S.*)$")


def verify_package(pm: str, pkg: str) -> list:
    """Files whose checksum differs from the package manifest (config files excluded)."""
    cmd = ["dpkg", "-V", pkg] if pm == "dpkg" else ["rpm", "-V", pkg] if pm == "rpm" else None
    if not cmd:
        return []
    _rc, out, _ = run_rc(cmd, timeout=180)
    bad = []
    for ln in out.splitlines():
        m = VERIFY_RE.match(ln.strip())
        if m:
            flags, attr, path = m.groups()
            if len(flags) >= 3 and flags[2] == "5" and attr != "c":
                bad.append(path)
    return bad


def kind_of(path: str) -> str:
    b = os.path.basename(path).lower()
    if b.startswith("frankenphp"):
        return "frankenphp"
    if "libphp" in b:
        return "mod_php"
    if b.startswith("lsphp"):
        return "lsphp"
    if "fpm" in b:
        return "php-fpm"
    if "cgi" in b:
        return "php-cgi"
    return "php-cli"


def discover_php_installs(procs: dict) -> dict:
    found: dict = {}
    for pat in PHP_BIN_GLOBS:
        for p in glob.glob(pat):
            if os.path.isfile(p) and os.access(p, os.X_OK):
                found.setdefault(os.path.realpath(p), {"kind": kind_of(p), "source": "installed"})
    for p in procs.values():
        if PHP_EXE_COMM_RE.match(p["comm"]) and p["exe"]:
            path = p["exe"].replace(" (deleted)", "")
            if os.path.isfile(path):
                found[os.path.realpath(path)] = {"kind": kind_of(path), "source": "running"}
    for pat in MODPHP_GLOBS:
        for p in glob.glob(pat):
            found.setdefault(os.path.realpath(p), {"kind": "mod_php", "source": "installed (check if enabled)"})
    return found


def apache_maps(procs: dict):
    """(libphp paths loaded by Apache, {path: pids} whose on-disk file was replaced)."""
    loaded, stale, seen = set(), defaultdict(set), 0
    for pid, p in procs.items():
        if not APACHE_COMM_RE.match(p["comm"]):
            continue
        seen += 1
        if seen > 20:
            break
        try:
            fh = open(f"/proc/{pid}/maps")
        except OSError:
            continue
        with fh:
            for ln in fh:
                if "libphp" in ln:
                    parts = ln.split(None, 5)
                    if len(parts) >= 6:
                        path = parts[5].strip()
                        deleted = path.endswith(" (deleted)")
                        path = path.replace(" (deleted)", "")
                        loaded.add(path)
                        if deleted:
                            stale[path].add(pid)
    return loaded, stale


UNTRUSTED_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/", "/home/", "/var/www/", "/srv/", "/mnt/", "/media/",
                      "/run/user/", "/proc/")
TRUSTED_EXEC: set = set()          # paths the administrator explicitly vouches for (--trust-exec)
ELF_MAGIC = b"\x7fELF"


def untrusted_reason(path: str) -> str:
    """Why this tool must NOT execute `path` ('' if it looks safe).

    The tool usually runs as root, and the list of PHP binaries partly comes from the process table, which any
    local attacker can influence (start a process named php-fpm from /tmp). Executing such a path as root would
    be a local privilege escalation, so only root-owned ELF files in root-owned, non-writable directories pass."""
    real = os.path.realpath(path)
    if real in TRUSTED_EXEC or path in TRUSTED_EXEC:
        return ""
    if real.startswith(UNTRUSTED_PREFIXES):
        return "located in a temp/home/web directory"
    me = os.geteuid() if hasattr(os, "geteuid") else -1

    def unsafe(p):
        st = os.stat(p)
        if st.st_uid not in (0, me):
            return f"{p} is owned by uid {st.st_uid}"
        if st.st_mode & statmod.S_IWOTH:
            return f"{p} is world-writable"
        if st.st_mode & statmod.S_IWGRP and st.st_gid != 0:
            return f"{p} is writable by group {st.st_gid}"
        return ""
    try:
        node = real
        while True:
            reason = unsafe(node)
            if reason:
                return reason
            parent = os.path.dirname(node)
            if parent == node:
                break
            node = parent
        with open(real, "rb") as fh:
            if fh.read(4) != ELF_MAGIC:
                return "not an ELF executable"
    except OSError as exc:
        return f"cannot be inspected ({exc.strerror})"
    return ""


def run_php_version(path: str) -> str:
    """`php -n -v` with a clean environment, no stdin, cwd=/ and -- when we are root -- as `nobody`, so even a
    binary that passed untrusted_reason() cannot act with our privileges."""
    def to_nobody():
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
    drop = to_nobody if (hasattr(os, "geteuid") and os.geteuid() == 0) else None
    try:
        r = subprocess.run([path, "-n", "-v"], capture_output=True, text=True, timeout=10, errors="replace",
                           env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}, cwd="/",
                           stdin=subprocess.DEVNULL, preexec_fn=drop)
        return (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return ""


def check_php_installs(rep: Report, procs: dict, no_exec: bool):
    installs = discover_php_installs(procs)
    loaded, _stale = apache_maps(procs)
    for lib in loaded:
        installs[os.path.realpath(lib)] = {"kind": "mod_php", "source": "loaded by Apache"}

    rows, pkgs, refused = [], set(), []
    for path, meta in sorted(installs.items()):
        kind = meta["kind"]
        ver = suffix = vsrc = None
        if kind not in ("mod_php", "frankenphp") and not no_exec:
            blocked = untrusted_reason(path)
            if blocked:
                refused.append(f"{path}: NOT executed ({blocked}); version taken from the package database if any")
            else:
                m = re.search(r"PHP (\d+\.\d+\.\d+)(\S*)", run_php_version(path))
                if m:
                    ver, suffix, vsrc = m.group(1), m.group(2), "binary -v"
        pm, pkg = pkg_owner(path)
        found = []
        if pkg:
            pkgs.add((pm, pkg))
            if ver is None:
                ver, _full = pkg_version(pm, pkg)
                if ver:
                    vsrc = f"{pm} package"
            found = changelog_cves(pm, pkg)
        rows.append({"path": path, "kind": kind, "run": meta["source"], "version": ver,
                     "version_source": vsrc, "package": pkg, "backported_cves": found,
                     "verdict": verdict_for(ver, suffix, found)})

    masq = []
    for pid, p in procs.items():
        if PHP_EXE_COMM_RE.match(p["comm"]) and p["exe"]:
            why = untrusted_reason(p["exe"].replace(" (deleted)", ""))
            if why and not (p["exe"].endswith(" (deleted)") and why.startswith("cannot be inspected")):
                masq.append((why.startswith("located in"), f"pid {pid} '{p['comm']}' (user {uid_name(p['uid'])}) "
                                                          f"runs {p['exe']}: {why}"))
    if masq:
        rep.add("proc.php_masquerade", "high" if any(h for h, _ in masq) else "medium", "indicator",
                "A process named like PHP/FPM runs from an untrusted location or an unsafe file",
                "Real PHP runtimes live in root-owned system directories. A look-alike running from /tmp, a home or "
                "web directory (or owned/writable by non-root users) is a classic way to hide a payload. "
                "This tool does NOT execute such files.", [t for _h, t in masq])
    if refused:
        rep.add("exposure.exec_refused", "info", "info",
                "PHP binaries that were deliberately not executed", "Vouch for a path with --trust-exec PATH "
                "if you know it is genuine.", refused)

    # SAPI inventory (PHP rates mod_php as the highest-risk deployment)
    saps = {r["kind"] for r in rows}
    for p in procs.values():
        if PHP_EXE_COMM_RE.match(p["comm"]):
            saps.add(kind_of(p["comm"]))
    if saps:
        rep.add("exposure.sapi", "info", "info", "PHP SAPIs detected: " + ", ".join(sorted(saps)),
                "Every SAPI that serves web requests is affected (php-fpm, mod_php, php-cgi, FrankenPHP, "
                "LiteSpeed). The PHP project rates Apache mod_php as the highest-risk deployment: patch it first.")

    if not rows:
        rep.add("exposure.php_version", "info", "info", "No PHP binary or library could be inspected",
                "PHP may be containerised (try --docker), bundled in an appliance, or installed in a "
                "non-standard path. Confirm the version of the PHP that actually serves your sites.")
        return rows, pkgs

    def fmt(r):
        extra = f"; {fixed_hint(r['version'])}" if r["verdict"] in ("likely vulnerable", "unknown") and r["version"] else ""
        bp = f"; changelog mentions {len(r['backported_cves'])}/2 CVEs" if r["package"] else ""
        return (f"{r['path']} [{r['kind']}, {r['run']}] PHP {r['version'] or '?'} "
                f"(from {r['version_source'] or 'n/a'}); package {r['package'] or 'none'}{bp} "
                f"-> {r['verdict'].upper()}{extra}")

    bad = [r for r in rows if r["verdict"] == "likely vulnerable"]
    unk = [r for r in rows if r["verdict"] == "unknown"]
    detail = ("Verdicts: PATCHED = at/above the fixed release for its branch, or the distro changelog mentions "
              "both CVEs (backport). LIKELY VULNERABLE = below the fixed release and no backport evidence. "
              "UNKNOWN = version unreadable, pre-release/dev build, only one CVE in the changelog, or vendor-bundled PHP. "
              "PHP 8.1 and older have no upstream fixed release: sources disagree on whether the PHP project issued "
              "source backports (one vendor reports minimal ones for 7.4/8.0/8.1), so confirm with whoever built "
              "your PHP.")
    if any(r["kind"] == "mod_php" and r["verdict"] != "patched" for r in rows):
        detail += " mod_php is the highest-risk setup -- prioritise it."
    sev = "high" if bad else "low" if unk else "info"
    cat = "exposure" if (bad or unk) else "info"
    title = ("PHP is within the vulnerable range and no distro backport was found" if bad else
             "PHP patch status could not be confirmed" if unk else "All inspected PHP installs look patched")
    rep.add("exposure.php_version", sev, cat, title, detail, [fmt(r) for r in rows])
    rep.coverage["php_installs"] = [
        {k: r[k] for k in ("path", "kind", "version", "package", "verdict")} for r in rows]
    return rows, pkgs


def check_integrity(rep: Report, pkgs):
    """dpkg -V / rpm -V on PHP packages: detects tampered binaries and libraries."""
    bad = []
    for pm, pkg in sorted(pkgs):
        for path in verify_package(pm, pkg):
            bad.append(f"{path} (package {pkg}: checksum differs from the package manifest)")
            rep.flag(path, "package-owned PHP file with modified checksum")
    rep.coverage["packages_verified"] = sorted(p for _m, p in pkgs)
    if bad:
        rep.add("exposure.package_integrity", "high", "indicator",
                "PHP package files differ from the package manifest",
                "A modified PHP binary or library can hide an implant (it can also lie about its own version). "
                "Reinstall the package from a trusted source and investigate how it changed.", bad)


def check_stale_processes(rep: Report, procs: dict):
    stale_exe = defaultdict(list)
    for pid, p in procs.items():
        if PHP_EXE_COMM_RE.match(p["comm"]) and (p["exe"] or "").endswith(" (deleted)"):
            stale_exe[p["exe"]].append(pid)
    _loaded, stale_maps = apache_maps(procs)
    ev = [f"{exe}: pids {pids[:8]}" for exe, pids in stale_exe.items()]
    ev += [f"{lib}: apache pids {sorted(pids)[:8]}" for lib, pids in stale_maps.items()]
    if ev:
        rep.add("exposure.stale_process", "medium", "exposure",
                "Running processes still use pre-upgrade PHP binaries/libraries",
                "A patched file on disk does not protect a process that still has the old code in memory. "
                "Restart php-fpm / apache2 / httpd (and any other PHP SAPI) after updating.", ev)


# --------------------------------------------------------------------------
# 1b. PHP configuration audit (mitigation posture + tampering)
# --------------------------------------------------------------------------

INI_GLOBS = [
    "/etc/php/*/fpm/php.ini", "/etc/php/*/fpm/conf.d/*.ini", "/etc/php/*/fpm/pool.d/*.conf",
    "/etc/php/*/apache2/php.ini", "/etc/php/*/apache2/conf.d/*.ini", "/etc/php/*/cgi/php.ini",
    "/etc/php.ini", "/etc/php.d/*.ini", "/etc/php-fpm.d/*.conf", "/etc/php-fpm.conf",
    "/usr/local/etc/php/php.ini", "/usr/local/etc/php/conf.d/*.ini", "/usr/local/etc/php-fpm.d/*.conf",
    "/opt/remi/php*/root/etc/php.ini", "/opt/remi/php*/root/etc/php.d/*.ini",
    "/opt/remi/php*/root/etc/php-fpm.d/*.conf",
]
CONFIG_GLOBS = INI_GLOBS + [
    "/etc/apache2/*.conf", "/etc/apache2/conf-enabled/*.conf", "/etc/apache2/sites-enabled/*.conf",
    "/etc/httpd/conf/*.conf", "/etc/httpd/conf.d/*.conf",
]
SETTING_NAMES = ("session.upload_progress.enabled", "session.upload_progress.name", "session.save_path",
                 "post_max_size", "upload_max_filesize", "memory_limit", "fatal_error_backtraces")
_NAMES_ALT = "|".join(re.escape(n) for n in SETTING_NAMES)
INI_LINE = re.compile(
    r"^\s*(?:php_(?:admin_)?(?:value|flag)(?:\[|\s+))?\s*(" + _NAMES_ALT +
    r")\]?\s*[=\s]\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s;\"']+))", re.I)
PREPEND_CFG = re.compile(
    r"^\s*(?:php_(?:admin_)?value(?:\[|\s+))?\s*auto_(?:prepend|append)_file\]?\s*[=\s]\s*[\"']?([^\s;\"']+)", re.I)
EXTENSION_CFG = re.compile(r"^\s*(?:zend_)?extension\s*=\s*[\"']?(/[^\"'\s;]+)", re.I)
TMP_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/")
OFF_VALUES = {"0", "off", "no", "false", "none", ""}


def audit_php_config(rep: Report) -> dict:
    values, prepend, ext_bad, files = defaultdict(list), [], [], set()
    for pat in CONFIG_GLOBS:
        files.update(glob.glob(pat))
    for path in sorted(files):
        if not os.path.isfile(path):
            continue
        for ln in read_small(path, 1 << 20).splitlines():
            s = ln.strip()
            if not s or s.startswith((";", "#")):
                continue
            m = INI_LINE.match(s)
            if m:
                val = next((g for g in m.groups()[1:] if g is not None), "")
                values[m.group(1).lower()].append((path, val))
            m = PREPEND_CFG.match(s)
            if m and m.group(1).lower() not in OFF_VALUES:
                prepend.append(f"{path}: {s[:140]}")
            m = EXTENSION_CFG.match(s)
            if m:
                target = m.group(1)
                if target.startswith(TMP_PREFIXES) or target.startswith(("/var/www/", "/srv/", "/home/")):
                    ext_bad.append(f"{path}: loads {target} (temp/web/home location)")
                elif not target.startswith(("/usr/", "/opt/", "/lib", "/lib64/")):
                    ext_bad.append(f"{path}: loads {target} (non-standard location)")
    rep.coverage["php_config_files_read"] = len(files)

    lines = []
    up = values.get("session.upload_progress.enabled", [])
    if not files:
        lines.append("No PHP configuration files were found in the common paths: settings could not be assessed")
    elif up:
        lines += [f"{p}: session.upload_progress.enabled = {v}" for p, v in up]
    else:
        lines.append("session.upload_progress.enabled: not set explicitly in the files read (PHP default is On)")
    for name in ("post_max_size", "upload_max_filesize", "memory_limit", "fatal_error_backtraces"):
        for p, v in values.get(name, []):
            lines.append(f"{p}: {name} = {v}")
    rep.add("exposure.mitigation_posture", "info", "info",
            "Interim-mitigation settings found in configuration (NOT a fix)",
            "PHP's interim guidance: session.upload_progress.enabled=0, low post_max_size (8M; 32M if uploads are "
            "needed), upload_max_filesize below it, fatal_error_backtraces=0 on PHP 8.5, memory_limit enforced as -1 "
            "via php_admin_value paired with a container/cgroup limit -- set in php.ini / the FPM pool, not via "
            "ini_set() or .user.ini. Vendors disagree about which CVE the upload-progress switch covers; the PHP "
            "project states that updating is the only complete fix. Only common config paths are read; CLI, FPM "
            "and Apache may use different files.", lines)
    if prepend:
        rep.add("config.auto_prepend_system", "medium", "indicator",
                "auto_prepend_file / auto_append_file set in system PHP or web-server configuration",
                "Persistence trick; legitimate uses exist (e.g. WAF plugins). Confirm every target file.", prepend)
    if ext_bad:
        high = any("temp/web/home" in e for e in ext_bad)
        rep.add("config.extension_path", "high" if high else "medium", "indicator",
                "PHP extension loaded from an unusual path",
                "A malicious extension (.so) loaded by PHP gives code execution inside every worker.", ext_bad)
    names = {v for _p, v in values.get("session.upload_progress.name", [])}
    sess = {v for _p, v in values.get("session.save_path", [])}
    return {"upload_progress_names": names, "session_paths": sess}


EXT_DIR_GLOBS = [
    "/usr/lib/php/*", "/usr/lib/php*/modules", "/usr/lib64/php/modules", "/usr/lib64/php*/modules",
    "/usr/local/lib/php/extensions/*", "/opt/remi/php*/root/usr/lib64/php/modules",
    "/opt/cpanel/ea-php*/root/usr/lib64/php/modules", "/opt/plesk/php/*/lib/php/modules",
]


def check_extensions(rep: Report, since: dt.datetime):
    ts, recent, unowned, pkgs = since.timestamp(), [], [], set()
    dirs = set()
    for pat in EXT_DIR_GLOBS:
        dirs.update(d for d in glob.glob(pat) if os.path.isdir(d))
    for d in sorted(dirs):
        for path in glob.glob(os.path.join(d, "*.so")):
            try:
                st = os.stat(path)
            except OSError:
                continue
            if st.st_mtime < ts:
                continue
            recent.append(f"{path} (mtime {iso(st.st_mtime)})")
            pm, pkg = pkg_owner(path)
            if pkg:
                pkgs.add((pm, pkg))
            elif pm is None and (shutil.which("dpkg") or shutil.which("rpm")):
                unowned.append(f"{path} (mtime {iso(st.st_mtime)})")
                rep.flag(path, "PHP extension .so not owned by any package")
    rep.coverage["php_extension_dirs"] = sorted(dirs)
    if unowned:
        rep.add("config.extension_unowned", "high", "indicator",
                "PHP extension (.so) modified since the cutoff and not owned by any package",
                "Packaged extensions are installed by the package manager. An unowned, recently changed .so in "
                "PHP's extension directory is a strong implant signal (unless you compile extensions yourself).",
                unowned)
    return pkgs


# --------------------------------------------------------------------------
# 1c. Docker (opt-in): Wiz demonstrated exploitation against container images
# --------------------------------------------------------------------------


def parse_docker_top(text: str) -> dict:
    procs = {}
    for ln in text.strip().splitlines()[1:]:
        parts = ln.split(None, 4)
        if len(parts) < 4:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        procs[pid] = {"comm": parts[3], "ppid": ppid, "uid": parts[2],
                      "cmd": parts[4] if len(parts) > 4 else "", "exe": None}
    return procs


def check_docker(rep: Report, no_exec: bool, no_procs: bool):
    if not shutil.which("docker"):
        rep.note("--docker given but the docker CLI was not found.")
        return
    rc, out, err = run_rc(["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}"], timeout=30)
    if rc != 0:
        rep.note(f"docker ps failed ({err.strip()[:120] or 'permission denied?'}).")
        return
    rows, container_procs = [], []
    for ln in out.strip().splitlines():
        parts = ln.split("\t")
        if len(parts) < 3:
            continue
        cid, name, image = parts[:3]
        ver = suffix = src = None
        _rc, env, _ = run_rc(["docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", cid],
                             timeout=30)
        m = re.search(r"^PHP_VERSION=(\d+\.\d+\.\d+)(\S*)", env, re.M)
        if m:
            ver, suffix, src = m.group(1), m.group(2), "image env PHP_VERSION"
        elif not no_exec:
            for binary in ("php", "php-fpm"):
                _rc, o, e = run_rc(["docker", "exec", cid, binary, "-n", "-v"], timeout=30)
                m = re.search(r"PHP (\d+\.\d+\.\d+)(\S*)", o + e)
                if m:
                    ver, suffix, src = m.group(1), m.group(2), f"docker exec {binary} -v"
                    break
        if ver is None:
            continue            # container without PHP
        verdict = {"ok": "patched", "vulnerable": "likely vulnerable"}.get(classify_version(ver, suffix), "unknown")
        rows.append((name, image, ver, src, verdict))
        if not no_procs:
            _rc, top, _ = run_rc(["docker", "top", cid, "-eo", "pid,ppid,user,comm,args"], timeout=30)
            container_procs.append((name, parse_docker_top(top)))
    rep.coverage["containers_with_php"] = len(rows)
    if rows:
        bad = [r for r in rows if r[4] == "likely vulnerable"]
        unk = [r for r in rows if r[4] == "unknown"]
        rep.add("exposure.docker_php", "high" if bad else "low" if unk else "info",
                "exposure" if (bad or unk) else "info",
                "Containers with a PHP runtime" + (" below the fixed release" if bad else ""),
                "Official php/wordpress/drupal images carry upstream builds, so the version in the image is what "
                "counts: rebuild/pull images with PHP 8.5.12, 8.4.27, 8.3.36 or 8.2.35 and recreate the containers "
                "(a restart alone does not change the image). Distro-based images may carry backports this check "
                "cannot see.",
                [f"{n} ({img}): PHP {v or '?'} via {s or 'n/a'} -> {vd.upper()}" for n, img, v, s, vd in rows])
    for name, cprocs in container_procs:
        check_process_indicators(rep, cprocs, label=f"container {name}")


# --------------------------------------------------------------------------
# 2. Process / network indicators (point-in-time)
# --------------------------------------------------------------------------

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "ash", "busybox"}
STRONG_TOOLS = {"nc", "ncat", "netcat", "socat", "nmap", "telnet", "whoami", "id", "uname", "ifconfig", "tftp"}
WEAK_TOOLS = {"curl", "wget", "python", "perl", "ruby", "base64", "chmod", "crontab", "ssh", "scp"}
BAD_CMD = re.compile(
    r"(?:/dev/tcp/|bash\s+-i|\bnc\s+(?:-\w*[ec])|ncat\s.{0,100}-e|mkfifo|"
    r"curl[^|;]{0,200}\|\s*(?:ba)?sh|wget[^|;]{0,200}\|\s*(?:ba)?sh|base64\s+(?:-d|--decode)|"
    r"python\w*\s+-c.{0,200}socket|perl\s+-e.{0,200}socket|chmod\s+\+x\s+/(?:tmp|dev/shm|var/tmp)|/dev/shm/|/var/tmp/\.)",
    re.I)
BENIGN_SHELL_CMD = re.compile(r"sendmail|msmtp|ssmtp|postdrop", re.I)
ARTIFACT_RE = re.compile(r"php2shell|poc\d*_1096(?:18|19)", re.I)
ARTIFACT_IGNORE_EXT = (".yml", ".yaml", ".md", ".rst", ".txt", ".rules", ".json", ".kql")
SELF_DIR_RE = re.compile(r"am[-_]i[-_]infected", re.I)
COMMON_PORTS = {80, 443, 53, 25, 465, 587}


def find_worker_ancestor(procs, pid, depth=6):
    cur = procs.get(pid)
    for _ in range(depth):
        if not cur:
            return None
        par = procs.get(cur["ppid"])
        if not par:
            return None
        if WEB_COMM_RE.match(par["comm"]):
            return par
        cur = par
    return None


def check_process_indicators(rep: Report, procs: dict, label: str = "", web_uids=()):
    where = f" [{label}]" if label else ""
    sfx = f".{label.split()[-1]}" if label else ""
    high, medium, low = [], [], []
    for pid, p in procs.items():
        base = re.sub(r"[\d.]+$", "", p["comm"])
        if base not in SHELLS and base not in STRONG_TOOLS and base not in WEAK_TOOLS:
            continue
        par = find_worker_ancestor(procs, pid)
        if not par:
            continue
        line = (f"pid {pid} {p['comm']} (user {uid_name(p['uid'])}) <- {par['comm']} "
                f"(user {uid_name(par['uid'])}): {p['cmd'][:160]}")
        if BAD_CMD.search(p["cmd"]):
            high.append(line)
        elif base in SHELLS and BENIGN_SHELL_CMD.search(p["cmd"]):
            low.append(line)
        elif base in WEAK_TOOLS:
            low.append(line)
        else:
            medium.append(line)
    if high:
        rep.add("proc.worker_child_malicious" + sfx, "high", "indicator",
                "Web/PHP worker has a child process with reverse-shell / downloader characteristics" + where,
                "A process tree like this is the classic post-exploitation signature of PHP RCE.", high)
    if medium:
        rep.add("proc.worker_child_shell" + sfx, "medium", "indicator",
                "Web/PHP worker has a shell or recon tool as child process" + where,
                "Some applications legitimately shell out (e.g. via sh -c). Verify each command line.", medium)
    if low:
        rep.add("proc.worker_child_tool" + sfx, "low", "indicator",
                "Web/PHP worker has an interpreter/downloader/mail child process" + where,
                "Often legitimate (CGI scripts, mail(), update jobs). Review if unexpected.", low)
    if label:
        return

    # processes owned by web users that run from temp dirs / deleted binaries
    web_uids = set(web_uids) | {p["uid"] for p in procs.values()
                                if WEB_COMM_RE.match(p["comm"]) and p["uid"] not in (None, 0)}
    suspicious = []
    for pid, p in procs.items():
        if p["uid"] not in web_uids or WEB_COMM_RE.match(p["comm"]):
            continue
        exe = p["exe"] or ""
        if exe.startswith(TMP_PREFIXES) or exe.endswith(" (deleted)") or p["cmd"].startswith(TMP_PREFIXES):
            suspicious.append(f"pid {pid} user {uid_name(p['uid'])} exe={exe or '?'} cmd={p['cmd'][:120]}")
    if suspicious:
        rep.add("proc.web_user_tmp_exec", "high", "indicator",
                "Process owned by a web-server user runs from a temp directory or a deleted binary",
                "Dropped payloads typically run from /tmp, /dev/shm or /var/tmp.", suspicious)

    me = os.getpid()
    art = [f"pid {pid} {p['comm']}: {p['cmd'][:140]}" for pid, p in procs.items()
           if pid != me and ARTIFACT_RE.search(p["cmd"] or "") and "am_i_infected" not in p["cmd"]]
    if art:
        rep.add("proc.poc_artifact", "medium", "indicator",
                "A running process references php2shell / PoC naming",
                "Could be your own checker tool or an attacker/researcher running the public PoC on this host.", art)


def _addr(hexs: str, v6: bool):
    h, p = hexs.split(":")
    port = int(p, 16)
    if v6:
        raw = b"".join(int(h[i:i + 8], 16).to_bytes(4, "little") for i in range(0, 32, 8))
        ip = ipaddress.IPv6Address(raw)
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
    else:
        ip = ipaddress.IPv4Address(int(h, 16).to_bytes(4, "little"))
    return ip, port


def load_tcp():
    """({inode: (ip, port)} of LISTEN sockets, [(inode, lport, rip, rport)] of ESTABLISHED)."""
    listening, conns = {}, []
    for fn, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            with open(fn) as fh:
                rows = fh.read().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            f = row.split()
            if len(f) < 10:
                continue
            try:
                lip, lport = _addr(f[1], v6)
                rip, rport = _addr(f[2], v6)
            except ValueError:
                continue
            if f[3] == "0A":
                listening[f[9]] = (lip, lport)
            elif f[3] == "01":
                conns.append((f[9], lport, rip, rport))
    return listening, conns


def check_network(rep: Report, procs: dict, web_uids: set):
    listening, conns = load_tcp()
    listen_ports = {port for (_ip, port) in listening.values()}
    by_inode = defaultdict(list)
    for c in conns:
        by_inode[c[0]].append(c)
    interesting = {pid: p for pid, p in procs.items() if WEB_COMM_RE.match(p["comm"]) or p["uid"] in web_uids}
    inodes = {pid: socket_inodes(pid) for pid in interesting}

    outbound, listeners, exposed = defaultdict(set), [], defaultdict(set)
    for pid, p in interesting.items():
        is_web = bool(WEB_COMM_RE.match(p["comm"]))
        for ino in inodes[pid]:
            if is_web:
                for (_i, lport, rip, rport) in by_inode.get(ino, []):
                    if lport not in listen_ports and rip.is_global:
                        outbound[(str(rip), rport)].add(pid)
                if ino in listening and not listening[ino][0].is_loopback:
                    ip, port = listening[ino]
                    exposed[(str(ip), port)].add(p["comm"])
            elif ino in listening:      # non-web process of a web user is listening: bind-shell pattern
                ip, port = listening[ino]
                listeners.append(f"pid {pid} {p['comm']} (user {uid_name(p['uid'])}) listens on {ip}:{port}: "
                                 f"{p['cmd'][:100]}")
    odd = [f"{ip}:{port} (pids {sorted(pids)[:5]})" for (ip, port), pids in outbound.items()
           if port not in COMMON_PORTS]
    common = [f"{ip}:{port}" for (ip, port) in outbound if port in COMMON_PORTS]
    if listeners:
        rep.add("net.web_user_listener", "medium", "indicator",
                "A non-web process owned by a web-server user is listening on a TCP port",
                "Bind shells and tunnels run as the compromised web account. Verify each listener.", listeners)
    if odd:
        rep.add("net.worker_outbound_unusual", "medium", "indicator",
                "Web/PHP worker holds an outbound connection to a public IP on an unusual port",
                "Snapshot only. Could be a remote database/API or a reverse shell -- verify each destination.", odd)
    if common:
        rep.add("net.worker_outbound_common", "info", "info",
                f"{len(common)} outbound connection(s) from web/PHP workers to public IPs on common ports",
                "Snapshot only; listed for context.", common)
    if exposed:
        rep.add("exposure.listening", "info", "info",
                "Web/PHP services listening on non-loopback addresses (reachable from the network)",
                "Context for prioritisation. PHP-FPM FastCGI should listen on a unix socket or loopback only.",
                [f"{ip}:{port} <- {', '.join(sorted(c))}" for (ip, port), c in sorted(exposed.items())])


# --------------------------------------------------------------------------
# 3. Logs
# --------------------------------------------------------------------------

LOG_GLOBS = [
    "/var/log/apache2/*", "/var/log/httpd/*", "/var/log/nginx/*", "/var/log/php*", "/var/log/php*/*",
    "/var/log/php-fpm/*", "/var/log/syslog*", "/var/log/messages*", "/var/log/daemon.log*", "/var/log/kern.log*",
    "/usr/local/apache/logs/*", "/usr/local/lsws/logs/*", "/var/log/litespeed/*", "/var/log/lsws/*",
    "/var/www/vhosts/*/logs/*", "/var/www/vhosts/system/*/logs/*", "/home/*/logs/*",
    "/home/*/access-logs/*", "/var/log/caddy/*", "/var/log/virtualmin/*",
    # WAF audit logs (these DO contain request details/bodies, unlike most access logs)
    "/var/log/modsec_audit*", "/var/log/modsecurity/*", "/var/log/apache2/modsec*", "/var/log/nginx/modsec*",
    # authentication and audit trail
    "/var/log/auth.log*", "/var/log/secure*", "/var/log/audit/audit.log*",
]
SKIP_LOG_NAMES = ("wtmp", "btmp", "lastlog", ".journal", ".sqlite", ".db", ".pid", ".sock")

ACCESS_RE = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "([A-Z]+) (\S+)[^"]*" (\d{3}) ')
OVERSIZE_SID = re.compile(r"PHPSESSID=([^;\"\s&]{257,})", re.I)
SID_REDACT = re.compile(r"(PHPSESSID=)([^;\"\s&]+)", re.I)
# Self-identifying User-Agents of the public PoC and of scanners seen in live traffic (Kela / ELLIO reports):
# php2shell-109618, php2shell-109619, php2shell-scan/109618, php2shell-verify/1.0
UA_IOC = re.compile(r"php2shell[-/\w.]*", re.I)
MEM_RE = re.compile(r"Allowed memory size of \d+ bytes exhausted|PHP Fatal error:\s+Out of memory", re.I)
TIMEOUT_RE = re.compile(r"Maximum execution time of \d+ seconds? exceeded", re.I)
SIGNAL_RE = re.compile(
    r"child \d+ exited on signal \d+|"
    r"exit signal (?:Segmentation fault|Aborted|Bus error|Illegal instruction)|"
    r"(?:php|lsphp|apache2|httpd)[^\s\[]*\[\d+\]: segfault at", re.I)
BADSID_RE = re.compile(r"Session ID is too long or contains illegal characters|illegal session id|invalid session id", re.I)
AUTH_ACCEPT = re.compile(r"Accepted \S+ for (\S+) from (\S+)")
AUTH_SUDO = re.compile(r"\bsudo(?:\[\d+\])?:\s+(\S+)\s+:.*COMMAND=")
AUDIT_HEAD = re.compile(r"type=SYSCALL msg=audit\((\d+)\.\d+:\d+\):")
EXEC_SYSCALLS = {59, 322, 221, 281, 11, 358}   # execve/execveat on x86_64, aarch64, i386

LINE_CAP = 1 << 16        # longest log line we buffer; longer ones are processed in chunks
ATTACK_KINDS = {"marker", "ua_ioc", "oversize_sid", "post5xx_burst"}
SYMPTOM_KINDS = {"mem_exhausted", "worker_signal", "exec_timeout"}
POST_KINDS = {"audit_web_exec", "web_user_login", "web_user_sudo",
              "fs_php_new", "fs_webshell", "fs_cron", "fs_ssh_key"}


class LogScanner:
    def __init__(self, since, now, web_names=(), web_uids=(), extra_markers=(), sample_cap=200):
        self.since_margin = since - dt.timedelta(days=1)   # tolerate timezone differences
        self.now = now
        self.cap = sample_cap
        self.web_names, self.web_uids = set(web_names), set(web_uids)
        self.markers = ["session_upload_progress"] + [m.lower() for m in extra_markers
                                                       if "session_upload_progress" not in m.lower()]
        self.mode = "generic"
        self.counts = defaultdict(int)
        self.samples = defaultdict(list)
        self.per_day = defaultdict(lambda: defaultdict(int))
        self.hours = defaultdict(set)
        self.post5xx = defaultdict(list)
        self.ip_kinds = defaultdict(set)
        self.ip_count = Counter()
        self.events = []
        self.lines = 0
        self.files = 0
        self.min_ts = None

    # -- recording ---------------------------------------------------------
    def _hit(self, kind, ts, src, line, ip=None):
        self.counts[kind] += 1
        clean = SID_REDACT.sub(lambda m: f"{m.group(1)}<{len(m.group(2))} chars>", printable(line.strip()))
        if ts:
            self.per_day[kind][ts.strftime("%Y-%m-%d")] += 1
            self.hours[hour_of(ts)].add(kind)
            if len(self.events) < MAX_EVENTS:
                self.events.append((ts, kind, src, clean[:200]))
        if ip and kind in ATTACK_KINDS:
            self.ip_kinds[ip].add(kind)
            self.ip_count[ip] += 1
        if len(self.samples[kind]) < self.cap:
            self.samples[kind].append(f"{src}: {clean[:220]}")

    # -- line handlers -----------------------------------------------------
    def feed(self, src: str, line: str):
        self.lines += 1
        if self.mode == "audit":
            return self._feed_audit(src, line)
        ts = parse_ts(line, self.now)
        if ts:
            if self.min_ts is None or ts < self.min_ts:
                self.min_ts = ts
            if ts < self.since_margin:
                return
        if self.mode == "auth":
            return self._feed_auth(src, line, ts)
        self._feed_generic(src, line, ts)

    def _feed_generic(self, src, line, ts):
        low = line.lower()
        m = ACCESS_RE.match(line)
        ip = m.group(1) if m else None
        if any(mk in low for mk in self.markers):
            self._hit("marker", ts, src, line, ip)
        if "php2shell" in low and UA_IOC.search(line):
            self._hit("ua_ioc", ts, src, line, ip)
        if "phpsessid=" in low and OVERSIZE_SID.search(line):
            self._hit("oversize_sid", ts, src, line, ip)
        if m:
            _ip, method, path, status = m.groups()
            if ts and method == "POST" and status in ("500", "502"):
                self.post5xx[(_ip, hour_of(ts))].append(path.split("?", 1)[0])
            return
        if "memory size" in low or "out of memory" in low:
            if MEM_RE.search(line):
                self._hit("mem_exhausted", ts, src, line)
        elif "execution time" in low and TIMEOUT_RE.search(line):
            self._hit("exec_timeout", ts, src, line)
        elif ("signal" in low or "segfault" in low) and SIGNAL_RE.search(line):
            self._hit("worker_signal", ts, src, line)
        elif "session" in low and BADSID_RE.search(line):
            self._hit("bad_session_id", ts, src, line)

    def _feed_auth(self, src, line, ts):
        m = AUTH_ACCEPT.search(line)
        if m and m.group(1) in self.web_names:
            self._hit("web_user_login", ts, src, line)
            return
        m = AUTH_SUDO.search(line)
        if m and m.group(1) in self.web_names:
            self._hit("web_user_sudo", ts, src, line)

    def _feed_audit(self, src, line):
        """auditd SYSCALL records: needs an execve audit rule to be useful."""
        h = AUDIT_HEAD.match(line)
        if not h:
            return
        ts = dt.datetime.fromtimestamp(int(h.group(1)))
        if ts < self.since_margin:
            return
        sc = re.search(r"\bsyscall=(\d+)", line)
        if sc and int(sc.group(1)) not in EXEC_SYSCALLS:
            return
        auid, uid = re.search(r"\bauid=(\S+)", line), re.search(r"\buid=(\d+)", line)
        exe = re.search(r'\bexe="([^"]*)"', line)
        if not (auid and uid and exe):
            return
        if auid.group(1) not in ("4294967295", "unset") or int(uid.group(1)) not in self.web_uids:
            return
        base = re.sub(r"[\d.]+$", "", os.path.basename(exe.group(1)))
        if base in SHELLS or base in STRONG_TOOLS:
            self._hit("audit_web_exec", ts, src, line)
        elif base in WEAK_TOOLS:
            self._hit("audit_web_exec_weak", ts, src, line)

    # -- sources -----------------------------------------------------------
    def scan_file(self, path: str):
        b = os.path.basename(path).lower()
        self.mode = ("auth" if b.startswith(("auth.log", "secure")) else
                     "audit" if b.startswith("audit.log") else "generic")
        try:
            with open_log(path) as fh:
                while True:
                    line = fh.readline(LINE_CAP)
                    if not line:
                        break
                    self.feed(path, line)
            self.files += 1
        except (OSError, EOFError, lzma.LZMAError):
            pass
        finally:
            self.mode = "generic"

    def _stream(self, cmd) -> int:
        n, start = 0, time.time()
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, errors="replace")
        except OSError:
            return 0
        for line in proc.stdout:
            self.feed("journalctl", line)
            n += 1
            if time.time() - start > 120:
                proc.kill()
                break
        proc.wait()
        return n

    def scan_journal(self, since: dt.datetime) -> int:
        jc = shutil.which("journalctl")
        if not jc:
            return 0
        base = [jc, "--no-pager", "-o", "short-iso", "--since", since.strftime("%Y-%m-%d %H:%M:%S")]
        units = list(base)
        for unit in ("apache2", "httpd", "nginx", "php*-fpm*", "php-fpm*", "lshttpd", "lsws"):
            units += ["-u", unit]
        return self._stream(units) + self._stream(base + ["-k"])      # services + kernel (segfault lines)

    def scan_coredumps(self, since: dt.datetime):
        cc = shutil.which("coredumpctl")
        if not cc:
            return
        _rc, out, _ = run_rc([cc, "list", "--no-pager", "--no-legend", "--since", since.strftime("%Y-%m-%d")],
                             timeout=60)
        for row in out.splitlines():
            if re.search(r"(?:php|lsphp|apache2|httpd)", row, re.I) and re.search(r"SIG[A-Z]+", row):
                m = re.search(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})", row)
                ts = dt.datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S") if m else None
                self._hit("worker_signal", ts, "coredumpctl", row)

    # -- reporting ---------------------------------------------------------
    def _top_days(self, kind, n=5):
        d = self.per_day.get(kind, {})
        return [f"{day}: {cnt} events" for day, cnt in sorted(d.items(), key=lambda kv: -kv[1])[:n]]

    def finalize(self, rep: Report):
        for (ip, hour), paths in self.post5xx.items():
            if len(paths) >= BURST_THRESHOLD:
                self.counts["post5xx_burst"] += 1
                self.hours[hour].add("post5xx_burst")
                self.ip_kinds[ip].add("post5xx_burst")
                self.ip_count[ip] += len(paths)
                self.samples["post5xx_burst"].append(
                    f"{ip} {hour:%Y-%m-%d %H}:00 -> {len(paths)} POSTs answered 500/502 (e.g. {paths[0]})")
        c, s = self.counts, self.samples

        if c["marker"]:
            rep.add("log.upload_progress_marker", "medium", "indicator",
                    f"PHP_SESSION_UPLOAD_PROGRESS found in logs ({c['marker']} lines)",
                    "Vendors list this multipart field as an exploitation-attempt marker, anomalous when sent to "
                    "endpoints that do not handle uploads. It shows an ATTEMPT, not success (legitimate "
                    "upload-progress features use it too). Access logs normally do not contain request bodies, "
                    "so most attempts are invisible here.", s["marker"])
        if c["ua_ioc"]:
            rep.add("log.poc_user_agent", "medium", "indicator",
                    f"php2shell PoC/scanner User-Agent fingerprints in logs ({c['ua_ioc']} lines)",
                    "The public PoC and scanners seen on 2026-10-21 hard-code User-Agents such as php2shell-109618, "
                    "php2shell-scan/109618 or php2shell-verify/1.0. Trivially changed, so absence means little; "
                    "presence shows an attempt, not success. Your own scanners/checkers may match too.", s["ua_ioc"])
        if c["oversize_sid"]:
            rep.add("log.oversize_phpsessid", "medium", "indicator",
                    f"Oversized PHPSESSID values in logs ({c['oversize_sid']} lines)",
                    "PHP session IDs are at most 256 characters; larger values are anomalous. "
                    "Session values are redacted in this report.", s["oversize_sid"])
        if c["post5xx_burst"]:
            rep.add("log.post_5xx_burst", "medium", "indicator",
                    f"Bursts of POST requests answered 500/502 from one IP ({c['post5xx_burst']} IP/hour buckets)",
                    f"Threshold: {BURST_THRESHOLD}+ per IP per hour. Can also be a buggy client or a scanner.",
                    s["post5xx_burst"])
        if c["worker_signal"]:
            rep.add("log.worker_crash", "medium", "indicator",
                    f"PHP/web worker crashes (segfault/abort) found ({c['worker_signal']} entries)",
                    "Memory-corruption exploitation commonly crashes workers; buggy extensions can too. "
                    "Sources: logs, kernel journal, coredumpctl. Note: PHP's advisory warns a failure can happen "
                    "before PHP writes any message, and patched PHP intentionally _exit()s on hard OOM.",
                    self._top_days("worker_signal") + s["worker_signal"])
        for kind, fid, label in (("mem_exhausted", "log.memory_exhausted", "memory-exhausted errors"),
                                 ("exec_timeout", "log.exec_timeout", "execution-timeout errors")):
            if c[kind]:
                peak = max(self.per_day[kind].values(), default=0)
                sev = "medium" if peak >= DAY_SPIKE_MEDIUM else "low"
                rep.add(fid, sev, "indicator", f"PHP {label} in logs ({c[kind]} lines, peak {peak}/day)",
                        "Exploitation relies on controllable out-of-memory conditions, but busy applications "
                        "produce these too. Look for SPIKES around Oct 17-21 2026.",
                        self._top_days(kind) + s[kind])
        if c["bad_session_id"]:
            sev = "medium" if c["bad_session_id"] >= 50 else "low"
            rep.add("log.bad_session_id", sev, "indicator",
                    f"Illegal/invalid session ID warnings ({c['bad_session_id']} lines)",
                    "Bots with garbage cookies cause these as well; relevant mainly in combination with other signals.",
                    self._top_days("bad_session_id") + s["bad_session_id"])
        if c["web_user_login"]:
            rep.add("log.web_user_login", "high", "indicator",
                    f"Interactive SSH login by a web-server account ({c['web_user_login']} entries)",
                    "Web accounts normally never log in over SSH.", s["web_user_login"])
        if c["web_user_sudo"]:
            rep.add("log.web_user_sudo", "high", "indicator",
                    f"sudo used by a web-server account ({c['web_user_sudo']} entries)", "", s["web_user_sudo"])
        if c["audit_web_exec"]:
            rep.add("log.audit_web_exec", "medium", "indicator",
                    f"auditd: shell/recon tool executed by a web-server user outside any login session "
                    f"({c['audit_web_exec']} records)",
                    "Needs an auditd execve rule. Historical equivalent of the live 'worker spawned a shell' "
                    "check; some applications legitimately exec shells.",
                    self._top_days("audit_web_exec") + s["audit_web_exec"])
        if c["audit_web_exec_weak"]:
            rep.add("log.audit_web_exec_weak", "low", "indicator",
                    f"auditd: curl/wget/interpreter executed by a web-server user ({c['audit_web_exec_weak']} records)",
                    "Often legitimate (updaters, CGI). Review around attempt windows.", s["audit_web_exec_weak"])

        corr = []
        for h, kinds in sorted(self.hours.items()):
            att = kinds & ATTACK_KINDS
            if not att:
                continue
            sym = set()
            for dh in (-1, 0, 1):
                sym |= self.hours.get(h + dt.timedelta(hours=dh), set()) & SYMPTOM_KINDS
            if sym:
                corr.append(f"{h:%Y-%m-%d %H}:00  attempt-signals={sorted(att)}  symptoms={sorted(sym)}")
        if corr:
            rep.add("log.correlated", "medium", "indicator",
                    "Attempt markers and PHP crash/memory symptoms occur within the same time window",
                    "The strongest log-only evidence this tool can give: manual review of those hours is "
                    "strongly recommended (full WAF/reverse-proxy logs, process accounting, file changes).", corr)

        if self.ip_count:
            top = [f"{ip}: {n} events {sorted(self.ip_kinds[ip])}" for ip, n in self.ip_count.most_common(15)]
            rep.add("log.attempt_sources", "info", "info",
                    f"Source addresses of attempt signals ({len(self.ip_count)} distinct)",
                    "Behind a CDN/reverse proxy these may be the proxy's addresses -- check X-Forwarded-For in the "
                    "proxy logs. Scanners are noisy: an attempt source is not proof of a successful compromise.", top)

        rep.events.extend(self.events[: max(0, MAX_EVENTS - len(rep.events))])
        rep.coverage["log_files"] = self.files
        rep.coverage["log_lines"] = self.lines
        rep.coverage["log_earliest_timestamp"] = self.min_ts.isoformat() if self.min_ts else None
        if self.lines and self.min_ts and self.min_ts > rep.since + dt.timedelta(days=1):
            rep.note(f"Available logs only go back to {self.min_ts:%Y-%m-%d}; activity between "
                     f"{rep.since:%Y-%m-%d} and then cannot be assessed (rotated away?).")
        if not self.lines:
            rep.note("No web/PHP log lines were scanned. Pass log locations with --log-path.")


def discover_logs(extra_paths, since: dt.datetime):
    files = set()
    patterns = list(LOG_GLOBS)
    for p in extra_paths:
        patterns.append(os.path.join(p, "*") if os.path.isdir(p) else p)
    ts = since.timestamp() - 86400
    for pat in patterns:
        for path in glob.glob(pat):
            if not os.path.isfile(path) or path.lower().endswith(SKIP_LOG_NAMES):
                continue
            try:
                if os.stat(path).st_mtime < ts:
                    continue
            except OSError:
                continue
            files.add(os.path.realpath(path))
    return sorted(files)


# --------------------------------------------------------------------------
# 4. Filesystem: web roots, sessions, tooling artefacts
# --------------------------------------------------------------------------

WEBROOT_GLOBS = [
    "/var/www", "/srv/www", "/srv/http", "/usr/share/nginx/html", "/usr/local/apache2/htdocs",
    "/home/*/public_html", "/home/*/www", "/home/*/htdocs", "/home/*/domains/*/public_html",
    "/var/www/vhosts/*/httpdocs",
]
PHP_EXT = (".php", ".phtml", ".phar", ".php3", ".php4", ".php5", ".php7", ".php8", ".pht")
SKIP_DIRS = {"node_modules", ".git", ".svn"}
RISKY_DIRS = ("/uploads/", "/upload/", "/tmp/", "/cache/", "/images/", "/img/", "/files/", "/media/", "/sessions/")

WEBSHELL_SIGS = [
    ("high", "request variable passed to a command-execution function",
     re.compile(rb"\b(?:system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b")),
    ("high", "request variable passed to eval/assert",
     re.compile(rb"\b(?:eval|assert)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b")),
    ("high", "request variable decoded and passed to eval/assert",
     re.compile(rb"\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|urldecode)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b")),
    ("high", "dynamic call of a request-supplied function name",
     re.compile(rb"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b")),
    ("high", "well-known webshell marker",
     re.compile(rb"(?i)\b(?:c99shell|r57shell|wso\s*shell|b374k|weevely|filesman)\b")),
    ("medium", "eval of a decoded/compressed payload",
     re.compile(rb"\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode)\s*\(")),
    ("medium", "preg_replace with /e modifier",
     re.compile(rb"preg_replace\s*\(\s*(['\"]).{1,80}/[a-z]*e[a-z]*\1")),
]
# NOTE: [ \t] instead of \s at line starts -- \s also matches newlines, which made these O(n^2) on a crafted
# file of blank lines (a 64 KB .htaccess stalled the scan for over a minute).
PREPEND_RE = re.compile(
    r"^[ \t]*(?:php_(?:admin_)?value[ \t]+)?auto_(?:prepend|append)_file[ \t]*[= ][ \t]*(\S+)", re.I | re.M)
HANDLER_RE = re.compile(
    r"^[ \t]*Add(?:Handler|Type)[ \t]+\S*php\S*[ \t]+[^\n]*\.(?:jpe?g|png|gif|txt|ico|css|js|svg|webp)\b",
    re.I | re.M)


def discover_webroots(extra):
    roots = []
    for pat in WEBROOT_GLOBS:
        roots += [p for p in glob.glob(pat) if os.path.isdir(p)]
    roots += [p for p in extra if os.path.isdir(p)]
    return prune_nested(roots)


def scan_webroots(rep: Report, roots, since: dt.datetime):
    ts = since.timestamp()
    recent, risky, sigs, ctime_only, cfg_prepend, cfg_handler = [], [], {}, [], [], []
    scanned = 0
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                low = fn.lower()
                is_php = low.endswith(PHP_EXT)
                is_cfg = low in (".htaccess", ".user.ini")
                if not (is_php or is_cfg):
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if not statmod.S_ISREG(st.st_mode):
                    continue
                scanned += 1
                if is_cfg:
                    try:
                        txt = read_nofollow(path, 65536).decode("utf-8", "replace")
                    except OSError:
                        continue
                    for m in PREPEND_RE.finditer(txt):
                        cfg_prepend.append(f"{path}: {m.group(0).strip()[:140]} (mtime {iso(st.st_mtime)})")
                        rep.flag(path, "auto_prepend_file/auto_append_file in per-directory config")
                    if HANDLER_RE.search(txt):
                        cfg_handler.append(f"{path} (mtime {iso(st.st_mtime)})")
                        rep.flag(path, "PHP handler mapped to non-PHP extensions")
                    continue
                m_recent, c_recent = st.st_mtime >= ts, st.st_ctime >= ts
                if not (m_recent or c_recent):
                    continue
                desc = f"{path} (mtime {iso(st.st_mtime)}, ctime {iso(st.st_ctime)}, {st.st_size} B)"
                if m_recent:
                    recent.append((st.st_mtime, desc))
                    rep.add_event(dt.datetime.fromtimestamp(st.st_mtime), "fs_php_new", path, "PHP file modified")
                else:
                    ctime_only.append((desc, path))     # content changed/attrs touched but mtime looks old
                rel = "/" + os.path.relpath(path, root).lower()      # judge the path inside the web root only
                if any(d in rel for d in RISKY_DIRS):
                    risky.append((desc, path))
                if st.st_size <= 1_048_576:
                    try:
                        data = read_nofollow(path, 1_048_576)
                    except OSError:
                        continue
                    for sev, label, rx in WEBSHELL_SIGS:
                        if rx.search(data):
                            cur = sigs.get(path)
                            if cur is None or SEV_RANK[sev] > SEV_RANK[cur[0]]:
                                sigs[path] = (sev, label, desc)
    rep.coverage["webroots"] = roots
    rep.coverage["php_and_config_files_checked"] = scanned

    for path, (sev, _label, _desc) in sigs.items():
        rep.flag(path, "webshell heuristic match")
        if sev == "high":
            try:
                rep.add_event(dt.datetime.fromtimestamp(max(os.lstat(path).st_mtime, os.lstat(path).st_ctime)),
                              "fs_webshell", path, "webshell heuristic (high)")
            except OSError:
                pass
    for sev in ("high", "medium"):
        hits = [f"{d}  <- {label}" for (s, label, d) in sigs.values() if s == sev]
        if hits:
            rep.add(f"fs.webshell_signature_{sev}", sev, "indicator",
                    "PHP files changed since the cutoff match webshell heuristics",
                    "Heuristic signature match on files whose mtime OR ctime is newer than the cutoff. Inspect each "
                    "file; obfuscated-but-legitimate code exists." if sev == "medium" else
                    "These patterns directly hand request input to code/command execution.", hits)
    sig_paths = set(sigs)
    risky_only = [d for d, p in risky if p not in sig_paths]
    for _d, p in risky:
        if p not in sig_paths:
            rep.flag(p, "PHP file in upload/cache/media-style directory")
    if risky_only:
        rep.add("fs.php_in_risky_dir", "medium", "indicator",
                "PHP files created/modified since the cutoff inside upload/cache/media-style directories",
                "Upload and cache directories normally should not receive new executable PHP "
                "(some caching plugins do write PHP there).", risky_only)
    if cfg_prepend:
        rep.add("fs.auto_prepend", "medium", "indicator",
                "auto_prepend_file / auto_append_file configured in .htaccess or .user.ini",
                "A common persistence trick. Legitimate uses exist (e.g. Wordfence WAF) -- confirm each target file.",
                cfg_prepend)
    if cfg_handler:
        rep.add("fs.handler_override", "medium", "indicator",
                ".htaccess maps non-PHP extensions (jpg/png/txt/...) to the PHP handler",
                "Lets an attacker hide PHP code inside 'image' files.", cfg_handler)
    if ctime_only:
        any_risky = any(p in {rp for _d, rp in risky} for _d, p in ctime_only)
        rep.add("fs.timestomp_suspect", "medium" if any_risky else "low", "indicator",
                f"{len(ctime_only)} PHP file(s) with a recent ctime but an old mtime",
                "Timestamps can be forged (touch -r) but ctime cannot be set directly. Deployments that preserve "
                "mtimes (rsync -t, cp -p, tar x) also cause this, so treat it as a lead, not a verdict.",
                [d for d, _p in ctime_only])
    if recent:
        recent.sort(reverse=True)
        rep.add("fs.recent_php", "low", "indicator",
                f"{len(recent)} PHP file(s) created/modified since {since:%Y-%m-%d}",
                "Expected after deployments and updates -- review the list for files you do not recognise.",
                [d for _, d in recent])


def scan_sessions(rep: Report, since: dt.datetime, cfg: dict):
    """PHP session files: upload-progress writes attacker-influenced names into session data."""
    ts = since.timestamp()
    dirs = {"/var/lib/php/sessions", "/var/lib/php/session", "/tmp", "/var/tmp"}
    dirs.update(glob.glob("/var/lib/php/sess*"))
    for sp in cfg.get("session_paths", ()):
        dirs.add(sp.split(";")[-1])
    checked, long_names, huge, with_progress = 0, [], [], 0
    for d in sorted(dirs):
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for entry in it:
                if not entry.name.startswith("sess_") or checked >= 50000:
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if not statmod.S_ISREG(st.st_mode) or st.st_mtime < ts:
                    continue
                checked += 1
                sid = entry.name[5:]
                if len(sid) > 128:      # PHP default is 32; file names cap at 255, so 256 could never occur on disk
                    long_names.append(f"{d}/sess_{short_id(sid)} (mtime {iso(st.st_mtime)})")
                if st.st_size > 1_048_576:
                    huge.append(f"{d}/sess_{short_id(sid)}: {st.st_size} bytes (mtime {iso(st.st_mtime)})")
                try:
                    if b"upload_progress_" in read_nofollow(entry.path, 65536):
                        with_progress += 1
                except OSError:
                    pass
    rep.coverage["session_files_checked"] = checked
    if long_names:
        rep.add("fs.session_oversize_id", "medium", "indicator",
                "Session files whose ID is far longer than normal (>128 characters; PHP default is 32)",
                "IDs are redacted. Ordinary clients do not produce these.", long_names)
    if huge:
        rep.add("fs.session_huge", "medium", "indicator", "Unusually large session files (>1 MiB)",
                "Upload-progress data is attacker-influenced (the file name is written into the session).", huge)
    if with_progress:
        rep.add("fs.session_upload_progress", "low", "indicator",
                f"{with_progress} session file(s) contain upload-progress entries",
                "Legitimate progress-bar features leave these too; relevant mainly if your sites do not use "
                "upload progress at all.")


def scan_artifacts(rep: Report, roots, since: dt.datetime):
    """Files named like the public PoC / tooling in temp, home and web directories."""
    bases = ["/tmp", "/var/tmp", "/dev/shm", "/root"] + glob.glob("/home/*") + list(roots)
    hits = []
    for base in bases:
        for dirpath, dirnames, filenames in os.walk(base, onerror=lambda e: None):
            if dirpath[len(base):].count(os.sep) >= 4:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            if SELF_DIR_RE.search(dirpath):
                dirnames[:] = []
                continue                      # this tool's own checkout (rules, docs, tests)
            for name in dirnames + filenames:
                if ARTIFACT_RE.search(name) and not name.lower().endswith(ARTIFACT_IGNORE_EXT):
                    p = os.path.join(dirpath, name)
                    try:
                        hits.append(f"{p} (mtime {iso(os.lstat(p).st_mtime)})")
                    except OSError:
                        hits.append(p)
    if hits:
        rep.add("fs.poc_artifact", "medium", "indicator",
                "Files or directories named like the php2shell PoC / tooling",
                "Public PoCs circulate under names such as php2shell-poc and poc*_109618. Could also be your own "
                "checker tool or a researcher's download -- verify who placed them and when.", sorted(set(hits)))


# --------------------------------------------------------------------------
# 5. Persistence
# --------------------------------------------------------------------------


def read_passwd():
    users = []
    try:
        with open("/etc/passwd") as fh:
            for ln in fh:
                p = ln.rstrip("\n").split(":")
                if len(p) >= 7:
                    try:
                        users.append({"name": p[0], "uid": int(p[2]), "home": p[5], "shell": p[6]})
                    except ValueError:
                        continue
    except OSError:
        pass
    return users


def check_persistence(rep: Report, web_users: set, since: dt.datetime):
    ts = since.timestamp()
    users = read_passwd()

    cron_files = {"/etc/crontab", "/etc/anacrontab"}
    for pat in ("/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*",
                "/etc/cron.monthly/*", "/var/spool/cron/*", "/var/spool/cron/crontabs/*"):
        cron_files.update(glob.glob(pat))
    modified, bad = [], []
    for path in sorted(cron_files):
        try:
            st = os.stat(path)
        except OSError:
            continue
        if not statmod.S_ISREG(st.st_mode):
            continue
        owner_web = os.path.basename(path) in web_users
        if BAD_CMD.search(read_small(path)):
            bad.append(path)
            rep.flag(path, "cron file with reverse-shell/downloader pattern")
        if st.st_mtime >= ts:
            modified.append(f"{path} (mtime {iso(st.st_mtime)}){'  <- web user crontab' if owner_web else ''}")
            rep.add_event(dt.datetime.fromtimestamp(st.st_mtime), "fs_cron", path, "cron file modified")
            rep.flag(path, "cron file modified since cutoff")
    if bad:
        rep.add("persist.cron_malicious", "high", "indicator",
                "Cron entries contain reverse-shell/downloader patterns", "", bad)
    if modified:
        rep.add("persist.cron_modified", "medium" if any("web user" in m for m in modified) else "low",
                "indicator", f"Cron files modified since {since:%Y-%m-%d}",
                "Expected for admin changes; a modified crontab of a web user is unusual.", modified)

    uid0 = [u["name"] for u in users if u["uid"] == 0 and u["name"] != "root"]
    if uid0:
        rep.add("persist.uid0_account", "high", "indicator", "Additional account with UID 0", "", uid0)
    login_web = [f"{u['name']} (shell {u['shell']})" for u in users
                 if u["name"] in web_users and u["shell"] not in
                 ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "/bin/sync", "")]
    if login_web:
        rep.add("persist.web_user_shell", "medium", "indicator",
                "Web-server user has a login shell",
                "Web users normally use nologin; a real shell enables SSH logins for that account.", login_web)
    try:
        if os.stat("/etc/passwd").st_mtime >= ts:
            rep.add("persist.passwd_modified", "low", "indicator",
                    f"/etc/passwd modified since {since:%Y-%m-%d}", "Review recent account changes.")
    except OSError:
        pass

    homes = {u["home"]: u["name"] for u in users if u["home"]}
    homes.setdefault("/root", "root")
    homes.setdefault("/var/www", "www-data")
    keys, sev = [], "medium"
    for home, name in homes.items():
        for path in glob.glob(os.path.join(home, ".ssh", "authorized_keys*")):
            try:
                st = os.stat(path)
            except OSError:
                continue
            if st.st_mtime >= ts:
                keys.append(f"{path} (user {name}, mtime {iso(st.st_mtime)})")
                rep.add_event(dt.datetime.fromtimestamp(st.st_mtime), "fs_ssh_key", path, "authorized_keys modified")
                rep.flag(path, "authorized_keys modified since cutoff")
                if name in web_users or home.startswith(("/var/www", "/srv")):
                    sev = "high"
    if keys:
        rep.add("persist.ssh_keys", sev, "indicator",
                f"authorized_keys modified since {since:%Y-%m-%d}",
                "Verify every key. Keys added to web-user accounts are a strong indicator.", keys)

    try:
        if os.path.getsize("/etc/ld.so.preload") > 0:
            rep.add("persist.ld_preload", "medium", "indicator",
                    "/etc/ld.so.preload is present and non-empty",
                    "Used by some rootkits to hook every process.", [read_small("/etc/ld.so.preload", 500)])
    except OSError:
        pass
    units = []
    for path in glob.glob("/etc/systemd/system/*.service") + glob.glob("/etc/systemd/system/*/*.service"):
        try:
            if os.stat(path).st_mtime >= ts:
                units.append(path)
        except OSError:
            pass
    if units:
        rep.add("persist.systemd_units", "low", "indicator",
                f"systemd service units modified since {since:%Y-%m-%d}", "Review unfamiliar units.", units)


# --------------------------------------------------------------------------
# 6. Cross-source correlation and evidence handling
# --------------------------------------------------------------------------


def correlate_killchain(rep: Report):
    """Attempt markers in logs followed shortly by post-exploitation artefacts = much stronger signal."""
    attempts = {hour_of(e[0]) for e in rep.events if e[1] in ("marker", "ua_ioc", "oversize_sid")}
    if not attempts:
        return
    hits = []
    for ts, kind, src, _text in sorted(rep.events, key=lambda e: e[0]):
        if kind not in POST_KINDS:
            continue
        h = hour_of(ts)
        if any(h - dt.timedelta(hours=k) in attempts for k in range(KILLCHAIN_HOURS + 1)):
            hits.append(f"{ts:%Y-%m-%d %H:%M}  {kind}: {src}")
    if hits:
        rep.add("correlate.killchain", "high", "indicator",
                f"Post-exploitation artefacts appear within {KILLCHAIN_HOURS} h after exploitation-attempt markers",
                "Attempt markers (PHP_SESSION_UPLOAD_PROGRESS / php2shell User-Agent / oversized PHPSESSID) were "
                "followed by new PHP files, cron or SSH-key changes, web-user logins/sudo or shell execution. "
                "Coincidence is possible on busy sites, but this is the pattern to investigate first. "
                "(Timestamps from different sources may differ by the server's timezone offset.)", hits)


def timeline_lines(rep: Report, limit: int):
    evs = sorted(rep.events, key=lambda e: e[0])
    lines = [f"{ts:%Y-%m-%d %H:%M:%S}  {kind:<20} {os.path.basename(src) if kind.startswith('fs_') else src}  "
             f"{text[:110]}" for ts, kind, src, text in evs]
    if limit and len(lines) > limit:
        lines = lines[:limit] + [f"... {len(lines) - limit} more events (see --json for up to {MAX_EVENTS})"]
    return lines


def collect_evidence(out_path: str, rep: Report, scanner, procs: dict, json_text: str,
                     max_files: int = 200, max_size: int = 2_000_000):
    """One read-only-sourced .tar.gz for incident response. Flagged files are stored with a
    .quarantine suffix and mode 0400 so they cannot be executed or served by accident."""
    manifest, added, skipped = [], 0, 0
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz") as tar:
        def add_bytes(name, data: bytes, mode=0o600):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(data), int(time.time()), mode
            tar.addfile(ti, io.BytesIO(data))
            manifest.append(f"{hashlib.sha256(data).hexdigest()}  {len(data)}  {name}")

        add_bytes("README.txt", (
            "am-i-infected evidence bundle\n"
            "- report.json: full assessment\n- timeline.txt: merged chronological events\n"
            "- log_excerpts.txt: matched log lines (session IDs redacted)\n"
            "- snapshots/: process table and TCP tables at collection time\n"
            "- flagged/: copies of flagged files. They carry a .quarantine suffix and mode 0400.\n"
            "  They may be MALICIOUS: never execute them, never extract into a web root, analyse offline.\n"
            "- MANIFEST.sha256: SHA-256 of every member plus original path/reason for flagged files.\n"
            "Handle this archive as sensitive: it can contain secrets, IP addresses and attacker code.\n").encode())
        add_bytes("report.json", json_text.encode())
        add_bytes("timeline.txt", "\n".join(timeline_lines(rep, 0)).encode())
        excerpt = []
        if scanner is not None:
            for kind, lines in sorted(scanner.samples.items()):
                excerpt.append(f"== {kind} ({scanner.counts[kind]} total, first {len(lines)} shown) ==")
                excerpt += lines
        add_bytes("log_excerpts.txt", "\n".join(excerpt).encode())
        add_bytes("snapshots/processes.txt", "\n".join(
            f"pid={pid} ppid={p['ppid']} uid={p['uid']} comm={p['comm']} exe={p['exe']} cmd={p['cmd'][:300]}"
            for pid, p in sorted(procs.items())).encode())
        net = ""
        for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
            net += f"== {fn} ==\n{read_small(fn, 1 << 20)}\n"
        add_bytes("snapshots/net_tcp.txt", net.encode())

        for path, reason in sorted(rep.flagged.items()):
            if added >= max_files:
                skipped += 1
                continue
            try:
                st = os.lstat(path)
                if not statmod.S_ISREG(st.st_mode) or st.st_size > max_size:
                    skipped += 1
                    continue
                data = read_nofollow(path, max_size + 1)
                if len(data) > max_size:
                    skipped += 1
                    continue
            except OSError:
                skipped += 1
                continue
            arc = "flagged/" + printable(path.lstrip("/")).replace("..", "__") + ".quarantine"
            ti = tarfile.TarInfo(arc)
            ti.size, ti.mtime, ti.mode = len(data), int(st.st_mtime), 0o400
            tar.addfile(ti, io.BytesIO(data))
            manifest.append(f"{hashlib.sha256(data).hexdigest()}  {len(data)}  {arc}  original={printable(path)}  "
                            f"reason={printable(reason)}  mtime={iso(st.st_mtime)}")
            added += 1
        add_bytes("MANIFEST.sha256", "\n".join(manifest).encode())
    return added, skipped


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

LIMITATIONS = [
    "This tool only sees what is on THIS machine. An attacker with code execution can tamper with files and "
    "logs; a root-level compromise can hide almost anything.",
    "PHP's own advisories publish no IOCs. Indicators are behavioural and come from vendor write-ups that "
    "partly disagree (e.g. which CVE session.upload_progress.enabled=0 covers); treat every hit as a lead.",
    "Access logs normally do not record POST bodies, so exploit payloads are mostly invisible. Detection relies "
    "on side effects (crashes, memory errors, post-exploitation artefacts). A failure can occur before PHP "
    "writes any message.",
    "The memory-disclosure variant of the bugs may leave no trace at all.",
    "Process, network and container checks are point-in-time snapshots.",
    "Version verdicts use upstream numbers plus package changelogs; custom builds and vendor-bundled PHP "
    "can be mis-classified.",
    "Heuristics (webshell patterns, timestomp, auditd/auth correlation) produce false positives on busy or "
    "heavily customised hosts.",
]
NEXT_STEPS = [
    "Preserve evidence first: snapshot the VM/disk, run with --collect, copy logs off the host.",
    "Patch PHP and RESTART every PHP SAPI (php-fpm, apache2/mod_php, lsphp, ...). Restarting also clears "
    "shared OPcache state, which one of the bugs can corrupt.",
    "Rotate every secret PHP processes could read: DB passwords, API keys, session secrets, tokens, certificates.",
    "Remove persistence (cron, SSH keys, .user.ini/.htaccess changes, unknown PHP files and extensions) and "
    "consider rebuilding the host from a known-good image.",
]

COLORS = {"high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[90m",
          "bold": "\033[1m", "end": "\033[0m"}


def exit_code(rep: Report) -> int:
    code = 0
    for f in rep.findings:
        if f.category == "exposure" and SEV_RANK[f.severity] >= SEV_RANK["medium"]:
            code |= 1
        elif f.category == "indicator" and f.severity == "medium":
            code |= 2
        elif f.category == "indicator" and f.severity == "high":
            code |= 4
    return code


def render_text(rep: Report, meta: dict, color: bool, timeline: int = 0) -> str:
    c = (lambda k: COLORS[k]) if color else (lambda k: "")
    out = []
    w = out.append
    w(f"{c('bold')}am-i-infected {__version__}{c('end')} -- PHP2Shell (CVE-2026-109618 / CVE-2026-109619) "
      "compromise assessment")
    w(f"Host: {meta['host']}   Time: {meta['time']}   Since: {rep.since:%Y-%m-%d %H:%M}   Running as: {meta['user']}")
    w("=" * 100)

    exposure = [f for f in rep.findings if f.category == "exposure"]
    indicators = sorted([f for f in rep.findings if f.category == "indicator"],
                        key=lambda f: -SEV_RANK[f.severity])
    infos = [f for f in rep.findings if f.category == "info"]
    code = exit_code(rep)

    if code & 4:
        w(f"{c('high')}RESULT: HIGH-CONFIDENCE INDICATORS FOUND -- treat this host as potentially compromised.{c('end')}")
    elif code & 2:
        w(f"{c('medium')}RESULT: SUSPICIOUS SIGNALS FOUND -- manual review recommended.{c('end')}")
    else:
        w("RESULT: No medium/high indicators found in the data this tool could see.")
        w("        This is NOT proof that the system is clean (see LIMITATIONS).")
    if code & 1:
        w(f"{c('high')}EXPOSURE: this host appears exposed (vulnerable/unverified PHP and/or stale processes). "
          f"If it was internet-facing, rotate secrets even if nothing was found.{c('end')}")
    w("")

    def emit(f: Finding):
        tag = f"[{f.severity.upper()}]"
        w(f"{c(f.severity)}{tag:<9}{c('end')}{f.title}  ({f.id})")
        if f.detail:
            w(textwrap.fill(f.detail, width=100, initial_indent="         ", subsequent_indent="         "))
        for e in f.evidence:
            w(textwrap.fill(f"- {e}", width=100, initial_indent="         ", subsequent_indent="           "))
        w("")

    for title, group in (("EXPOSURE", exposure), ("INDICATORS (highest severity first)", indicators),
                         ("INFORMATION", infos)):
        if group:
            w(f"{c('bold')}{title}{c('end')}")
            for f in group:
                emit(f)

    if timeline:
        w(f"{c('bold')}TIMELINE (merged, chronological){c('end')}")
        for ln in timeline_lines(rep, timeline):
            w("  " + ln)
        w("")

    w(f"{c('bold')}COVERAGE{c('end')}")
    for k, v in rep.coverage.items():
        w(textwrap.fill(f"{k}: {v}", width=100, initial_indent="  ", subsequent_indent="      "))
    for n in rep.notes:
        w(textwrap.fill(f"NOTE: {n}", width=100, initial_indent="  ", subsequent_indent="        "))
    w("")
    w(f"{c('bold')}LIMITATIONS{c('end')}")
    for item in LIMITATIONS:
        w(textwrap.fill(f"- {item}", width=100, initial_indent="  ", subsequent_indent="    "))
    if code & 6:
        w("")
        w(f"{c('bold')}IF YOU FOUND SOMETHING{c('end')}")
        for i, item in enumerate(NEXT_STEPS, 1):
            w(textwrap.fill(f"{i}. {item}", width=100, initial_indent="  ", subsequent_indent="     "))
    w("")
    w(f"Exit code {code} (bitmask: 1=exposure, 2=suspicious indicators, 4=high-confidence indicators)")
    return "\n".join(out)


def build_json(rep: Report, meta: dict, code: int, since: dt.datetime) -> str:
    evs = sorted(rep.events, key=lambda e: e[0])[:2000]
    return json.dumps({
        "tool": "am-i-infected", "version": __version__, "cve": list(CVES),
        "fixed_versions": [f"{a}.{b}.{c}" for (a, b), c in sorted(FIXED.items())],
        "meta": meta, "since": since.isoformat(), "exit_code": code,
        "findings": [asdict(f) for f in rep.findings],
        "timeline": [{"time": ts.isoformat(), "kind": k, "source": s, "text": t} for ts, k, s, t in evs],
        "coverage": rep.coverage, "notes": rep.notes, "limitations": LIMITATIONS,
    }, indent=2, default=str)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def build_parser():
    ap = argparse.ArgumentParser(
        prog="am-i-infected",
        description="Read-only compromise assessment for PHP2Shell (CVE-2026-109618 / CVE-2026-109619). "
                    "Run on the server you administer, preferably as root.")
    ap.add_argument("--since", type=parse_since, default=parse_since(DEFAULT_SINCE),
                    help=f"only consider activity since this date (default {DEFAULT_SINCE})")
    ap.add_argument("--log-path", action="append", default=[], metavar="PATH",
                    help="extra log file or directory to scan (repeatable)")
    ap.add_argument("--webroot", action="append", default=[], metavar="DIR",
                    help="extra web root to scan (repeatable)")
    ap.add_argument("--docker", action="store_true",
                    help="also inspect running Docker containers (docker inspect/top; `docker exec php -v` unless --no-exec)")
    ap.add_argument("--collect", metavar="FILE.tar.gz",
                    help="write an evidence bundle (report, timeline, log excerpts, snapshots, flagged files)")
    ap.add_argument("--timeline", nargs="?", const=100, type=int, metavar="N",
                    help="print a merged chronological timeline (default 100 lines)")
    ap.add_argument("--no-logs", action="store_true", help="skip log analysis")
    ap.add_argument("--no-journal", action="store_true", help="skip journalctl and coredumpctl")
    ap.add_argument("--no-fs", action="store_true", help="skip web root / session / artefact file scans")
    ap.add_argument("--no-procs", action="store_true", help="skip process/network checks")
    ap.add_argument("--no-persistence", action="store_true", help="skip cron/users/ssh-key checks")
    ap.add_argument("--no-integrity", action="store_true", help="skip dpkg -V / rpm -V package verification")
    ap.add_argument("--trust-exec", action="append", default=[], metavar="PATH",
                    help="allow `php -v` on this binary even though it failed the safety checks (repeatable)")
    ap.add_argument("--no-exec", action="store_true",
                    help="never execute PHP binaries (`php -n -v`); versions come from the package database instead")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE (mode 600)")
    ap.add_argument("--max-evidence", type=int, default=10, help="evidence lines per finding (default 10)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"   # no PATH hijacking
    TRUSTED_EXEC.update(os.path.realpath(x) for x in args.trust_exec)
    now = dt.datetime.now()
    rep = Report(args.since, args.max_evidence)

    euid = os.geteuid() if hasattr(os, "geteuid") else -1
    if euid != 0:
        rep.note("Not running as root: process inspection, protected logs, package verification and other users' "
                 "files may be incomplete. Re-run with sudo for full coverage.")
    linux = sys.platform.startswith("linux")
    if not linux:
        rep.note("Non-Linux platform: /proc based checks are unavailable.")

    procs = read_procs() if linux else {}
    rep.coverage["processes_seen"] = len(procs)
    web_names, web_uids = web_identities(procs)

    # -- exposure ----------------------------------------------------------
    res = run_module(rep, "php-installs", check_php_installs, rep, procs, args.no_exec)
    pkgs = set(res[1]) if res else set()
    if procs:
        run_module(rep, "stale-processes", check_stale_processes, rep, procs)
    cfg = run_module(rep, "php-config", audit_php_config, rep) or {"upload_progress_names": set(), "session_paths": set()}
    pkgs |= run_module(rep, "php-extensions", check_extensions, rep, args.since) or set()
    if not args.no_integrity and pkgs:
        run_module(rep, "package-integrity", check_integrity, rep, pkgs)
    if args.docker:
        run_module(rep, "docker", check_docker, rep, args.no_exec, args.no_procs)

    # -- live system -------------------------------------------------------
    if not args.no_procs and procs:
        run_module(rep, "process-indicators", check_process_indicators, rep, procs, web_uids=web_uids)
        run_module(rep, "network", check_network, rep, procs, web_uids)

    # -- logs --------------------------------------------------------------
    scanner = None
    if not args.no_logs:
        def do_logs():
            sc = LogScanner(args.since, now, web_names, web_uids, cfg["upload_progress_names"])
            for path in discover_logs(args.log_path, args.since):
                sc.scan_file(path)
            if not args.no_journal:
                sc.scan_journal(args.since)
                sc.scan_coredumps(args.since)
            sc.finalize(rep)
            return sc
        scanner = run_module(rep, "logs", do_logs)

    # -- filesystem / persistence -----------------------------------------
    if not args.no_fs:
        roots = discover_webroots(args.webroot)
        run_module(rep, "webroots", scan_webroots, rep, roots, args.since)
        run_module(rep, "sessions", scan_sessions, rep, args.since, cfg)
        run_module(rep, "artifacts", scan_artifacts, rep, roots, args.since)
    if not args.no_persistence:
        run_module(rep, "persistence", check_persistence, rep, web_names, args.since)

    run_module(rep, "correlation", correlate_killchain, rep)

    # -- output ------------------------------------------------------------
    code = exit_code(rep)
    meta = {"host": socket.gethostname(), "time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "user": uid_name(euid) if euid >= 0 else "?"}
    json_text = build_json(rep, meta, code, args.since)
    if args.json:
        text = json_text
    else:
        text = render_text(rep, meta, color=sys.stdout.isatty() and not args.no_color and not args.output,
                           timeline=args.timeline or 0)

    if args.collect:
        try:
            added, skipped = collect_evidence(args.collect, rep, scanner, procs, json_text)
            print(f"Evidence bundle written to {args.collect} ({added} flagged file(s) copied, {skipped} skipped). "
                  "Handle it as sensitive and possibly malicious.", file=sys.stderr)
        except OSError as exc:
            print(f"Could not write evidence bundle: {exc}", file=sys.stderr)

    if args.output:
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(text + "\n")
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(text)
    return code


if __name__ == "__main__":
    sys.exit(main())
