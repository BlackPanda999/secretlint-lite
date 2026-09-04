#!/usr/bin/env python3
"""SecretLint Lite: dependency-free local secret exposure scanner."""
import argparse, hashlib, json, math, os, re, sys
from pathlib import Path

PATTERNS = [
    ("AWS_ACCESS_KEY", re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("PASSWORD_ASSIGNMENT", re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*[\"']?[^\s\"']{8,}")),
]
DEFAULT_EXCLUDES = {".git", ".venv", "venv", "node_modules", "__pycache__"}
TEXT_EXTENSIONS = {".py", ".js", ".ts", ".java", ".go", ".rs", ".rb", ".php", ".json", ".yaml", ".yml", ".env", ".ini", ".cfg", ".conf", ".txt", ".md", ".sh", ".toml", ".xml", ".tf"}


def entropy(value):
    counts = {c: value.count(c) for c in set(value)}
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values()) if length else 0


def fingerprint(path, line, kind):
    raw = f"{path}:{line}:{kind}".encode()
    return hashlib.sha256(raw).hexdigest()[:12]


def redact(text):
    if len(text) <= 8:
        return "[REDACTED]"
    return text[:3] + "…" + text[-3:]


def scan_file(path, root):
    findings = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeError):
        return findings
    if "\x00" in text:
        return findings
    rel = str(path.relative_to(root))
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("# secretlint: ignore") or stripped.startswith("// secretlint: ignore"):
            continue
        for kind, pattern in PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            value = match.group(0)
            # Ignore obvious placeholders and documentation examples.
            if any(x in value.lower() for x in ("example", "changeme", "your_", "replace_me", "dummy")):
                continue
            findings.append({
                "id": fingerprint(rel, number, kind), "type": kind,
                "file": rel, "line": number, "severity": "HIGH" if kind in {"PRIVATE_KEY", "AWS_ACCESS_KEY", "GITHUB_TOKEN"} else "MEDIUM",
                "match": redact(value), "message": f"Possible {kind.replace('_', ' ').lower()} detected"
            })
    return findings


def files_to_scan(root, excludes):
    for path in root.rglob("*"):
        if not path.is_file() or any(part in excludes for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_EXTENSIONS or path.name.startswith("."):
            yield path


def scan(root, excludes):
    findings = []
    for path in files_to_scan(root, excludes):
        findings.extend(scan_file(path, root))
    return findings


def main():
    parser = argparse.ArgumentParser(description="Find likely exposed secrets before they reach Git.")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--output")
    parser.add_argument("--exclude", action="append", default=[], help="Directory name to skip (repeatable)")
    parser.add_argument("--no-entropy", action="store_true", help="Reserved for compatibility; regex checks remain deterministic")
    args = parser.parse_args()
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path not found: {root}", file=sys.stderr); return 2
    findings = scan(root, DEFAULT_EXCLUDES | set(args.exclude))
    report = {"tool": "SecretLint Lite", "path": str(root), "files_scanned": sum(1 for _ in files_to_scan(root, DEFAULT_EXCLUDES | set(args.exclude))), "findings": findings, "total_findings": len(findings), "high": sum(f["severity"] == "HIGH" for f in findings), "medium": sum(f["severity"] == "MEDIUM" for f in findings)}
    output = json.dumps(report, indent=2)
    if args.format == "json":
        print(output)
    else:
        print(f"SecretLint Lite — scanned {report['files_scanned']} file(s)")
        if findings:
            for f in findings: print(f"[{f['severity']}] {f['file']}:{f['line']} {f['message']} ({f['match']})")
            print(f"\nFound {len(findings)} possible secret(s). Review before committing.")
        else: print("No likely secrets found.")
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
        print(f"Report saved to {args.output}")
    return 1 if findings else 0

if __name__ == "__main__": sys.exit(main())
