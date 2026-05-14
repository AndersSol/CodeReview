# CodeReview — Multi-AI Security Review Framework releases

Public release artefacts for the Multi-AI Security Review Framework.
Source is private at `AndersSol/multi-ai-security-review`.

- **Landing page:** https://anderssol.github.io/CodeReview/
- **Install (oneliner):**
  ```bash
  curl -fsSL https://anderssol.github.io/CodeReview/install.sh | bash
  ```
- **Releases:** https://github.com/AndersSol/CodeReview/releases

## What this is

This repository hosts:
- `docs/index.html` — landing page (served via GitHub Pages)
- `docs/install.sh` — install script
- `docs/latest.json` — release manifest with current version, wheel URL, SHA-256
- GitHub Releases (wheel artefacts per version)

The Python wheel installs `atea-security-review` and `atea-preflight` CLIs and
the Claude Code skill at `~/.claude/skills/security-review`.

## Verifying a release

Each release publishes:
- `atea_security_review-<version>-py3-none-any.whl` (Python wheel)
- `atea_security_review-<version>-py3-none-any.whl.sha256` (sha256 checksum)

The `docs/latest.json` manifest is authoritative for the current version
and SHA-256.
