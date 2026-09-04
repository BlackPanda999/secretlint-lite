Just built SecretLint Lite — a lightweight way to catch likely exposed credentials before they reach Git.

The problem: API keys, tokens, passwords, and private keys still end up in repositories through simple mistakes. Finding them after a push is already too late: credentials may be copied, cached, or exposed in history.

SecretLint Lite scans a project locally and flags common patterns including AWS access keys, GitHub and Slack tokens, JWTs, private-key headers, and risky password/token assignments.

What makes it useful:
• No external dependencies — just Python 3.9+
• Redacts matches instead of printing sensitive values
• Produces text or JSON reports
• Returns a CI-friendly exit code when findings are present
• Skips common virtual-environment, cache, and binary paths

I also included safe test fixtures, remediation guidance, and a GitHub Actions example. It is intentionally a defensive pattern scanner, so findings should still be reviewed manually and any real exposed credential should be rotated immediately.

Built with Python, pathlib, argparse, regular expressions, and JSON.

GitHub: https://github.com/BlackPanda999/secretlint-lite

#Cybersecurity #Python #DevSecOps #SecretScanning #CloudSecurity
