# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| `main` (latest commit) | Yes |
| Latest tagged release | Yes |
| Older releases | No |

## Reporting a vulnerability

Please do not report security vulnerabilities in public issues, discussions, or
pull requests.

Use GitHub private vulnerability reporting:

https://github.com/artur282/Antivirus/security/advisories/new

Include:

- A description of the issue and the affected version or commit.
- Reproduction steps or a proof of concept.
- The impact you believe it has.
- Any suggested fix or mitigation.

If private reporting is unavailable, open a public issue that only asks for a
private contact channel. Do not include exploit details in that issue.

## Scope

In scope:

- Signature database parsing and hash lookup.
- Path handling in scans, quarantine, restore, delete, and report export.
- Command construction and any place where a scanned file name or hash reaches
  a privileged operation.
- Local database handling (`antivirus.db`) and export files.
- The Tauri shell commands exposed to the frontend.

Out of scope:

- A scanner missing a malicious file (a false negative) unless it is caused by
  a parsing or logic defect that can be reproduced. Detection coverage is a
  product limitation, not a vulnerability.
- Vulnerabilities in Tauri, WebView2, WebKitGTK, or other dependencies that are
  already fixed upstream.
- Attacks that require a compromised local account, physical access, or an
  already-root shell, unless the application is supposed to cross that
  privilege boundary.
- Social engineering, spam, and denial-of-service against GitHub.

## Response

This is a personal open-source project maintained on a best-effort basis. We aim
to acknowledge reports within 7 days and to publish a fix or mitigation as soon
as practical. We will credit reporters in the advisory unless you ask us not to.

## Safe harbor

We will not pursue legal action for good-faith security research that follows
this policy, stays within the scope above, and avoids privacy violations, data
destruction, and service disruption.
