# Security policy

`am-i-infected` runs as root on production servers and processes attacker-influenced data, so vulnerabilities
in the tool itself matter. Examples: executing or following attacker-controlled paths, privilege escalation,
output/terminal injection, denial of service by crafted files or logs, evidence-bundle tampering.

## Reporting

Please **do not open a public issue**. Use GitHub's *Report a vulnerability* button (Security tab →
Advisories → Report a vulnerability). Include the version (`--version`), what you did and the impact.

## Supported versions

Only the latest release receives fixes. Always run a pinned release whose SHA-256 you have verified.

## Scope notes

- The tool is read-only and contains no exploit code. Reports of "it can detect X / can be evaded by Y" are
  welcome as ordinary issues: detection logic is public by design.
- False positives/negatives on real systems are expected in a young project; please attach (redacted) evidence.
