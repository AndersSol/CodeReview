# CodeReview — Agentic Security Review releases

Public release artefacts for **Agentic Security Review** — a multi-agent
security code review framework with deterministic consolidation, evidence-first
pipeline, severity rubric, 5-state assessment, and 8-rule release policy.

Source is private at `AndersSol/agentic-security-review`.

- **Landing page:** https://anderssol.github.io/CodeReview/
- **Install (oneliner):**
  ```bash
  curl -fsSL https://anderssol.github.io/CodeReview/install.sh | bash
  ```
- **Releases:** https://github.com/AndersSol/CodeReview/releases

## What this is

This repository hosts:
- `docs/index.html` — landing page (served via GitHub Pages)
- `docs/install.sh` — install script (Ed25519-signed-manifest verification)
- `docs/latest.json` — release manifest with current version, wheel URL, SHA-256
- GitHub Releases (wheel artefacts per version)

The Python wheel installs four CLIs and a Claude Code skill:
- `agentic-security-review` — pipeline consolidator
- `agentic-security-preflight` — deterministic preflight (sandbox + scanners)
- `agentic-evidence-verify` — standalone evidence-verifier
- `agentic-security-claude-adapter` — EXPERIMENTAL Claude adapter for CI/scripts
- Skill: `~/.claude/skills/security-review`

## Verifying a release

Each release publishes:
- `agentic_security_review-<version>-py3-none-any.whl` (Python wheel)
- `agentic_security_review-<version>-py3-none-any.whl.sha256` (sha256 checksum)

The `docs/latest.json` manifest is authoritative for the current version
and SHA-256. It is signed with Ed25519 (key_id `codereview-2026-key-1`); the
install script verifies the signature via an inline pure-Python verifier
before downloading the wheel.
