# SecretLint Lite

A small, dependency-free Python scanner that catches likely exposed credentials before they reach Git. It is designed for local checks, pre-commit hooks, and CI pipelines.

Inspired by the growing use of secret scanners such as Gitleaks and TruffleHog, this project focuses on being easy to inspect, run, and extend.

## Features

- AWS access keys, GitHub tokens, Slack tokens, JWTs, private-key headers, and risky assignments
- Redacts matches in output
- Deterministic fingerprints for triage
- Skips `.git`, virtual environments, caches, and binary-like files
- Text or JSON reports
- Exit code `1` when findings exist, making CI blocking simple
- No dependencies; Python 3.9+

## Usage

```bash
python3 secretlint.py ./my-project
python3 secretlint.py . --format json --output secret-report.json
python3 secretlint.py . --exclude docs --exclude fixtures
```

For an intentional safe fixture, add `# secretlint: ignore` on the line. Do not put real credentials in test files.

## CI example

```yaml
- name: Scan for exposed secrets
  run: python3 secretlint.py . --format json --output secret-report.json
```

## Safety notes

This is a defensive pattern scanner, not proof that a repository is safe. Rotate any real credential that may have been exposed, remove it from history, and use your provider's revocation tools. Review findings manually because regex-based detection can produce false positives.

## License

MIT. See `LICENSE`.

Run locally before pushing credentials.
