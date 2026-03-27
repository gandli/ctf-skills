---
name: ctf-writeup
description: Generates standardized CTF challenge writeups with metadata, solution steps, code, and lessons learned. Use after solving a challenge to create a writeup suitable for blog posts, team archives, or competition submission to organizers.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash and Python 3.
allowed-tools: Bash Read Write Edit Glob Grep Task
metadata:
  user-invocable: "true"
  argument-hint: "[challenge-name] [--format blog|submission|brief]"
---

# CTF Writeup Generator

Generate a standardized, high-quality writeup for a solved CTF challenge.

## Workflow

### Step 1: Gather Information

Collect the following from the current session, challenge files, and user input:

1. **Challenge metadata** — name, CTF event, category, difficulty, points, flag format
2. **Solution artifacts** — exploit scripts, payloads, screenshots, command output
3. **Timeline** — key steps taken, dead ends, pivots

```bash
# Scan for exploit scripts and artifacts
find . -name '*.py' -o -name '*.sh' -o -name 'exploit*' -o -name 'solve*' | head -20
# Check for flags in output files
grep -rniE '(flag|ctf|eno|htb|pico)\{' . 2>/dev/null
```

### Step 2: Choose Format

| Format | Use Case | Audience |
|--------|----------|----------|
| `submission` | Submit to competition organizers for review | Judges — concise, steps + payload + flag |
| `blog` | Publish on blog or CTFtime | Community — detailed, educational, with background |
| `brief` | Team internal archive | Teammates — one-liner + key commands |

Default to `blog` if not specified.

### Step 3: Generate Writeup

Write the writeup file as `writeup.md` (or `writeup-<challenge-name>.md`) using the template below matching the chosen format.

---

## Templates

### Format: `submission`

```markdown
---
title: "<Challenge Name>"
ctf: "<CTF Event Name>"
date: YYYY-MM-DD
category: web|pwn|crypto|reverse|forensics|osint|malware|misc
difficulty: easy|medium|hard
points: <number>
flag_format: "flag{...}"
author: "<your name or team>"
---

# <Challenge Name>

## Summary

<1-2 sentences: what the challenge was and the core vulnerability/technique.>

## Solution

### Step 1: <Action>

<What you did and why.>

\`\`\`bash
<command or code>
\`\`\`

### Step 2: <Action>

<Continue for each step.>

## Flag

\`\`\`
flag{example_flag_here}
\`\`\`
```

### Format: `blog`

```markdown
---
title: "<Challenge Name> — <CTF Event> Writeup"
ctf: "<CTF Event Name>"
date: YYYY-MM-DD
category: web|pwn|crypto|reverse|forensics|osint|malware|misc
difficulty: easy|medium|hard
points: <number>
flag_format: "flag{...}"
author: "<your name or team>"
tags: [ctf, <category>, <specific-technique>]
---

# <Challenge Name>

> **CTF:** <Event> | **Category:** <cat> | **Difficulty:** <diff> | **Points:** <pts>

## Challenge Description

<Original challenge description, quoted or paraphrased.>

## Reconnaissance

<What you saw first. Initial analysis, file types, service behavior, first impressions.>

\`\`\`bash
file *
checksec --file=binary
curl -v http://target/
\`\`\`

## Analysis

<Deep dive into the vulnerability or puzzle. Explain **why** the technique works, not just **what** you did. Include relevant background knowledge for readers who may not know the technique.>

## Exploitation

### Step 1: <Action>

<Detailed explanation with code.>

\`\`\`python
# exploit.py
from pwn import *
# ... exploit code with comments explaining each step
\`\`\`

### Step 2: <Action>

<Continue for each step.>

## Flag

\`\`\`
flag{example_flag_here}
\`\`\`

## Lessons Learned

- <What was new or interesting about this challenge?>
- <What technique will you remember for next time?>
- <What tools or approaches did you discover?>

## References

- [Tool/technique documentation](https://example.com)
- [Related writeup or resource](https://example.com)
```

### Format: `brief`

```markdown
# <Challenge Name> (<CTF>, <category>, <points>pts)

**TL;DR:** <One sentence describing the vulnerability and exploit.>

**Key commands:**
\`\`\`bash
<the 2-5 most important commands/lines that solve it>
\`\`\`

**Flag:** `flag{...}`
```

---

## Best Practices Checklist

Before finalizing the writeup, verify:

- [ ] **Metadata complete** — title, CTF, date, category, difficulty, points, author all filled
- [ ] **Flag redacted if needed** — some competitions require flag redaction during the event
- [ ] **Reproducible steps** — a reader can follow your writeup and reproduce the solution
- [ ] **Code is runnable** — exploit scripts include all imports, correct variable names, and comments
- [ ] **No sensitive data** — no real credentials, API keys, or private infrastructure details
- [ ] **Screenshots referenced** — if you took screenshots, reference them with `![description](path)`
- [ ] **Dead ends documented** (blog format) — mention what you tried that didn't work and why
- [ ] **Tools and versions noted** — mention specific tool versions if behavior depends on them
- [ ] **Proper attribution** — credit teammates, referenced writeups, or tools that were essential
- [ ] **Grammar and formatting** — consistent heading levels, code blocks have language tags

## Quality Guidelines

**DO:**
- Explain the "why" behind each step, not just the "what"
- Include the full exploit script, not just fragments
- Show actual output (truncated if very long) to prove the approach worked
- Use diagrams or ASCII art for complex attack flows
- Tag code blocks with language (`python`, `bash`, `sql`, etc.)

**DON'T:**
- Copy-paste raw terminal dumps without explanation
- Skip the reconnaissance phase — show how you identified the vulnerability
- Leave placeholder text in the final writeup
- Include irrelevant tangents that don't contribute to the solution
- Assume the reader knows the specific challenge setup

## Challenge

$ARGUMENTS
