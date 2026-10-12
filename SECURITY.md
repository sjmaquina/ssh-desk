# Security

SSH Desk stores connection credentials in an authenticated, encrypted vault.
This project has not undergone an independent security audit. Version 0.1.0 is
an initial release for Linux; review the README for the storage format and limits.

Verify first-connection fingerprints through a trusted channel. Scanned keys
alone do not prove a server's identity. Never publish your vault, passwords,
private keys, known_hosts file, or live runtime/session files in an issue.

For a suspected security problem, use the repository's private vulnerability
reporting feature if enabled. Otherwise contact its maintainer privately before
opening a public issue. Include a minimal reproduction with invented credentials.
