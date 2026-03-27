#!/usr/bin/env python3
"""Skill Security Auditor — scans skill directories for security risks."""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# --- Pattern definitions ---

CRITICAL_PATTERNS = [
    (r'rm\s+-rf\s+/', "Destructive command: rm -rf /"),
    (r'curl\s+[^\|]*\|\s*(ba)?sh', "Pipe-to-shell: curl | sh"),
    (r'wget\s+[^\|]*\|\s*(ba)?sh', "Pipe-to-shell: wget | sh"),
    (r'mkfs\.\w+\s+/dev/', "Destructive command: mkfs on device"),
    (r'dd\s+.*of=/dev/[sh]d', "Destructive command: dd to disk device"),
    (r':(){ :\|:& };:', "Fork bomb"),
    (r'\b(AKIA[0-9A-Z]{16})\b', "Hardcoded AWS access key"),
    (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', "Embedded private key"),
    (r'\b(ghp_[A-Za-z0-9_]{36,})\b', "Hardcoded GitHub personal access token"),
    (r'\b(sk-[A-Za-z0-9]{20,})\b', "Hardcoded API secret key (sk-...)"),
    (r'password\s*=\s*["\'][^"\']{8,}["\']', "Hardcoded password in assignment"),
]

HIGH_PATTERNS = [
    (r'eval\s*\(\s*["\']', "Direct eval() with string literal"),
    (r'exec\s*\(\s*["\']', "Direct exec() with string literal"),
    (r'subprocess\.call\s*\(\s*["\'].*shell\s*=\s*True', "subprocess with shell=True and string"),
    (r'os\.system\s*\(\s*f["\']', "os.system() with f-string (injection risk)"),
    (r'<script[^>]*>.*document\.(cookie|location)', "XSS payload accessing sensitive DOM"),
    (r'chmod\s+[47]77\s+/', "World-writable permission on system path"),
    (r'--no-check-certificate', "SSL verification disabled"),
    (r'verify\s*=\s*False', "SSL verification disabled in Python"),
]

INFO_PATTERNS = [
    (r'TODO|FIXME|HACK|XXX', "Code annotation found"),
]

FRONTMATTER_CHECKS = {
    'license': 'Missing license field in frontmatter',
    'allowed-tools': 'Missing allowed-tools field in frontmatter',
    'name': 'Missing name field in frontmatter',
    'description': 'Missing description field in frontmatter',
}


def parse_frontmatter(content: str) -> dict:
    """Extract YAML frontmatter fields (simple key: value parsing)."""
    fm = {}
    if not content.startswith('---'):
        return fm
    end = content.find('---', 3)
    if end == -1:
        return fm
    block = content[3:end]
    for line in block.strip().splitlines():
        if ':' in line:
            key, _, val = line.partition(':')
            fm[key.strip()] = val.strip()
    return fm


def scan_file(filepath: Path) -> list:
    """Scan a single file and return findings."""
    findings = []
    try:
        content = filepath.read_text(encoding='utf-8', errors='replace')
    except Exception as e:
        findings.append({
            'severity': 'HIGH',
            'file': str(filepath),
            'line': 0,
            'rule': 'unreadable_file',
            'message': f'Could not read file: {e}',
        })
        return findings

    lines = content.splitlines()

    # Check code blocks only (between ``` markers) for dangerous patterns
    in_code_block = False
    for i, line in enumerate(lines, 1):
        if line.strip().startswith('```'):
            in_code_block = not in_code_block
            continue

        # Critical patterns — check everywhere
        for pattern, message in CRITICAL_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'severity': 'CRITICAL',
                    'file': str(filepath),
                    'line': i,
                    'rule': pattern[:40],
                    'message': message,
                    'context': line.strip()[:120],
                })

        # High patterns — only in code blocks (technique docs legitimately discuss these)
        if in_code_block:
            for pattern, message in HIGH_PATTERNS:
                if re.search(pattern, line):
                    findings.append({
                        'severity': 'HIGH',
                        'file': str(filepath),
                        'line': i,
                        'rule': pattern[:40],
                        'message': message,
                        'context': line.strip()[:120],
                    })

    return findings


def scan_skill(skill_dir: Path) -> dict:
    """Scan an entire skill directory."""
    findings = []

    skill_md = skill_dir / 'SKILL.md'
    if not skill_md.exists():
        findings.append({
            'severity': 'HIGH',
            'file': str(skill_md),
            'line': 0,
            'rule': 'missing_skill_md',
            'message': 'SKILL.md not found in skill directory',
        })
    else:
        content = skill_md.read_text(encoding='utf-8', errors='replace')
        fm = parse_frontmatter(content)
        for key, message in FRONTMATTER_CHECKS.items():
            if key not in fm:
                findings.append({
                    'severity': 'INFO',
                    'file': str(skill_md),
                    'line': 0,
                    'rule': f'missing_{key}',
                    'message': message,
                })

    # Scan all markdown files
    md_files = sorted(skill_dir.rglob('*.md'))
    for md_file in md_files:
        findings.extend(scan_file(md_file))

    # Determine verdict
    crit = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    high = sum(1 for f in findings if f['severity'] == 'HIGH')
    info = sum(1 for f in findings if f['severity'] == 'INFO')

    if crit > 0:
        verdict = 'FAIL'
    elif high > 0:
        verdict = 'WARN'
    else:
        verdict = 'PASS'

    return {
        'skill': str(skill_dir),
        'verdict': verdict,
        'summary': {
            'critical': crit,
            'high': high,
            'info': info,
            'total': crit + high + info,
        },
        'findings': findings,
    }


def main():
    parser = argparse.ArgumentParser(description='Skill Security Auditor')
    parser.add_argument('skill_dir', help='Path to skill directory to audit')
    parser.add_argument('--strict', action='store_true',
                        help='Exit non-zero on CRITICAL or HIGH findings')
    parser.add_argument('--json', action='store_true', dest='json_output',
                        help='Output results as JSON')
    args = parser.parse_args()

    skill_path = Path(args.skill_dir)
    if not skill_path.is_dir():
        print(f"Error: {args.skill_dir} is not a directory", file=sys.stderr)
        sys.exit(2)

    result = scan_skill(skill_path)

    if args.json_output:
        print(json.dumps(result, indent=2))
    else:
        v = result['verdict']
        s = result['summary']
        print(f"Skill: {result['skill']}")
        print(f"Verdict: {v}")
        print(f"Critical: {s['critical']}  High: {s['high']}  Info: {s['info']}")
        if result['findings']:
            print("\nFindings:")
            for f in result['findings']:
                print(f"  [{f['severity']}] {f['file']}:{f['line']} — {f['message']}")
                if 'context' in f:
                    print(f"    > {f['context']}")

    if args.strict and result['verdict'] == 'FAIL':
        sys.exit(1)


if __name__ == '__main__':
    main()
