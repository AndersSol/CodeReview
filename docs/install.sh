#!/usr/bin/env bash
# Agentic Code Review — install script
# Usage: curl -fsSL https://anderssol.github.io/CodeReview/install.sh | bash
#
# Hardened per Codex publish-review (2026-05-14, two rounds):
# - HTTPS-only curl with strict TLS, redirect-host validation
# - hardcoded EXPECTED_WHEEL_HOST + path-prefix; rejects query/fragment
# - strict manifest validation (version regex, sha256 64hex, size range)
# - SHA-256 verification BEFORE pipx install (shasum or sha256sum)
# - downgrade-policy via env-var (CODEREVIEW_ALLOW_DOWNGRADE=1)
# - dynamic pipx venv discovery (no hardcoded python3.13)
# - safe symlink (CODEREVIEW_FORCE_SKILL_LINK=1 for force-replace)
# - bash 3.2 compatible (no readarray; macOS default)
# - pipx list --json for robust version-detection
# - trap cleanup for tempdir
# - no interactive prompts (curl|bash-safe)
#
# Env-var override flags:
#   CODEREVIEW_ALLOW_DOWNGRADE=1   permit installing older version
#   CODEREVIEW_FORCE_SKILL_LINK=1  overwrite existing skill dir
#   CODEREVIEW_SKIP_SMOKE_TEST=1   skip final smoke test
#
# Exit codes:
#   0 = success
#   2 = validation / configuration failure (hard-fail)
#   3 = transient / network failure

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────
# Ed25519 public key for manifest signature verification (32-byte hex).
# To rotate: change here AND re-sign manifest with new private key.
PUBKEY_HEX="4fd4611d32c934a4d2ce1d715f56d9c7e22f9841b26e4e0919e18cc2b3e4f4a9"
EXPECTED_KEY_ID="codereview-2026-key-1"
# This installer's own version. Manifest's min_installer_version must be <=
# this for the install to proceed. Bump when adding new validation steps.
INSTALLER_VERSION="5.1.0rc1"
MANIFEST_URL="https://anderssol.github.io/CodeReview/latest.json"
EXPECTED_WHEEL_HOST="github.com"
EXPECTED_WHEEL_PATH_PREFIX="/AndersSol/CodeReview/releases/download/v"
SKILL_DIR="${HOME}/.claude/skills"
SKILL_NAME="security-review"
# Wheel size sanity range (1 KiB to 100 MiB)
MIN_WHEEL_SIZE=1024
MAX_WHEEL_SIZE=104857600

# ── Tempdir + cleanup ────────────────────────────────────────────────
TMP_DIR="$(mktemp -d -t agentic-security-review-install.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

# ── Logging helpers ──────────────────────────────────────────────────
log() { printf "\033[36m[acr]\033[0m %s\n" "$*"; }
warn() { printf "\033[33m[acr]\033[0m %s\n" "$*" >&2; }
err() { printf "\033[31m[acr]\033[0m %s\n" "$*" >&2; }
die() { err "$*"; exit 2; }

# ── curl wrapper ─────────────────────────────────────────────────────
curl_safe() {
  curl --proto '=https' --tlsv1.2 --location --fail \
       --silent --show-error --max-time 60 "$@"
}

# ── 1. Python 3.13+ ──────────────────────────────────────────────────
log "Checking Python 3.13+ …"
if ! command -v python3 >/dev/null 2>&1; then
  die "python3 not found. Install Python 3.13+ first (e.g. brew install python@3.13)."
fi
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 13 ]; }; then
  die "Python $PY_VERSION found; framework requires 3.13+. Install python@3.13."
fi
log "  ✓ Python $PY_VERSION"

# ── 2. pipx ──────────────────────────────────────────────────────────
log "Checking pipx …"
if ! command -v pipx >/dev/null 2>&1; then
  die "pipx not found. Install first, then re-run:
    macOS:  brew install pipx && pipx ensurepath
    Linux:  python3 -m pip install --user pipx && python3 -m pipx ensurepath
  Open a new shell after pipx is installed so it's on PATH."
fi
log "  ✓ pipx $(pipx --version)"

# ── 3. Determine SHA tool ────────────────────────────────────────────
# Explicit command-v checks so `set -e` doesn't kill us mid-assignment.
if command -v shasum >/dev/null 2>&1; then
  SHA_CMD="shasum -a 256"
elif command -v sha256sum >/dev/null 2>&1; then
  SHA_CMD="sha256sum"
else
  die "Neither 'shasum' nor 'sha256sum' available. Install coreutils."
fi
log "  ✓ SHA tool: $SHA_CMD"

# ── 4. Fetch + validate manifest ─────────────────────────────────────
log "Fetching release manifest …"
MANIFEST_FILE="$TMP_DIR/latest.json"
if ! curl_safe -o "$MANIFEST_FILE" "$MANIFEST_URL"; then
  err "Failed to fetch manifest from $MANIFEST_URL"
  exit 3
fi

# Parse + validate manifest STRICTLY + verify Ed25519 signature.
# Pure-python Ed25519 verifier inlined — no extra Python deps.
MANIFEST_PARSED="$TMP_DIR/manifest-fields.txt"
python3 - "$MANIFEST_FILE" "$EXPECTED_WHEEL_HOST" "$EXPECTED_WHEEL_PATH_PREFIX" \
  "$MIN_WHEEL_SIZE" "$MAX_WHEEL_SIZE" "$PUBKEY_HEX" "$EXPECTED_KEY_ID" "$INSTALLER_VERSION" > "$MANIFEST_PARSED" <<'PYEOF'
"""Manifest validator + Ed25519 verifier (pure-python, RFC 8032).

The Ed25519 verifier is adapted from D. J. Bernstein's public-domain
reference Python implementation. ~50 LOC of cryptographic code; auditable
inline. No Python package dependencies required.
"""
import base64, hashlib, json, re, sys, urllib.parse
from datetime import datetime, timezone

manifest_file, expected_host, expected_prefix, min_size, max_size, pubkey_hex, expected_key_id, installer_version = sys.argv[1:9]
min_size, max_size = int(min_size), int(max_size)

# ── Pure-python Ed25519 verifier ──────────────────────────────────
_q = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493
def _h(m): return hashlib.sha512(m).digest()
def _hint(m): return int.from_bytes(_h(m), "little")
def _expmod(b, e, m):
    if e == 0: return 1
    t = _expmod(b, e // 2, m) ** 2 % m
    return (t * b) % m if e & 1 else t
def _inv(x): return _expmod(x, _q - 2, _q)
_d = -121665 * _inv(121666) % _q
_I = _expmod(2, (_q - 1) // 4, _q)
def _xrec(y):
    xx = (y*y - 1) * _inv(_d*y*y + 1)
    x = _expmod(xx, (_q + 3) // 8, _q)
    if (x*x - xx) % _q != 0: x = (x * _I) % _q
    if x % 2 != 0: x = _q - x
    return x
def _edwards(P, Q):
    x1, y1 = P; x2, y2 = Q
    x3 = (x1*y2 + x2*y1) * _inv(1 + _d*x1*x2*y1*y2)
    y3 = (y1*y2 + x1*x2) * _inv(1 - _d*x1*x2*y1*y2)
    return (x3 % _q, y3 % _q)
def _scalarmult(P, e):
    if e == 0: return (0, 1)
    Q = _scalarmult(P, e // 2); Q = _edwards(Q, Q)
    return _edwards(Q, P) if e & 1 else Q
_By = 4 * _inv(5); _Bx = _xrec(_By); _B = (_Bx % _q, _By % _q)
def _decodepoint(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrec(y)
    if (x & 1) != ((s[31] >> 7) & 1): x = _q - x
    P = (x, y)
    if (-x*x + y*y - 1 - _d*x*x*y*y) % _q != 0:
        raise ValueError("decoded point off curve")
    return P
def ed25519_verify(pk32, msg, sig64):
    if len(sig64) != 64 or len(pk32) != 32: return False
    try:
        R = _decodepoint(sig64[:32]); A = _decodepoint(pk32)
    except (ValueError, IndexError):
        return False  # malformed point on either side
    S = int.from_bytes(sig64[32:], "little")
    if S >= _l: return False  # malleability check (RFC 8032)
    h = _hint(sig64[:32] + pk32 + msg) % _l
    return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))

# ── Manifest parsing + validation ─────────────────────────────────
try:
    m = json.load(open(manifest_file))
except Exception as e:
    sys.stderr.write(f"manifest is not valid JSON: {e}\n"); sys.exit(2)

required_types = {
    "version": str, "wheel_url": str, "sha256": str, "size_bytes": int,
    "filename": str, "created_at": str, "valid_until": str,
    "min_installer_version": str, "key_id": str, "signature_alg": str,
    "signature": str,
}
for k, _t in required_types.items():
    if k not in m:
        sys.stderr.write(f"manifest missing required key: {k}\n"); sys.exit(2)
    if not isinstance(m[k], _t):
        sys.stderr.write(f"manifest key {k} wrong type\n"); sys.exit(2)
# Reject unknown fields (strict manifest schema)
extra = set(m) - set(required_types)
if extra:
    sys.stderr.write(f"manifest has unknown field(s): {sorted(extra)}\n"); sys.exit(2)

if m["key_id"] != expected_key_id:
    sys.stderr.write(f"manifest key_id {m['key_id']!r} != expected {expected_key_id!r}\n"); sys.exit(2)

if m["signature_alg"] != "Ed25519":
    sys.stderr.write(f"unsupported signature_alg: {m['signature_alg']!r}\n"); sys.exit(2)

# Canonical bytes = manifest MINUS signature field
unsigned = {k: v for k, v in m.items() if k != "signature"}
canon = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
try:
    sig_bytes = base64.b64decode(m["signature"], validate=True)
except Exception as e:
    sys.stderr.write(f"signature base64 invalid: {e}\n"); sys.exit(2)
try:
    pk_bytes = bytes.fromhex(pubkey_hex)
except Exception:
    sys.stderr.write("PUBKEY_HEX invalid\n"); sys.exit(2)
if not ed25519_verify(pk_bytes, canon, sig_bytes):
    sys.stderr.write("Ed25519 signature verification FAILED\n"); sys.exit(2)
sys.stderr.write("[acr]   Ed25519 signature verified\n")

# min_installer_version: manifest can require a newer installer
def parse_ver(v):
    import re as r
    m = r.match(r"^(\d+)\.(\d+)\.(\d+)(rc(\d+)|a(\d+)|b(\d+))?$", v)
    if not m: return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    pre = m.group(4) or ""
    rank = 1 if pre.startswith("a") else (2 if pre.startswith("b") else (3 if pre.startswith("rc") else 4))
    num = int(m.group(5) or m.group(6) or m.group(7) or 0)
    return (major, minor, patch, rank, num)
required = parse_ver(m["min_installer_version"])
have = parse_ver(installer_version)
if required is None or have is None:
    sys.stderr.write("min_installer_version or installer_version unparseable\n"); sys.exit(2)
if have < required:
    sys.stderr.write(f"this installer ({installer_version}) is too old; manifest requires >= {m['min_installer_version']}\n"); sys.exit(2)

# Validity window
now = datetime.now(timezone.utc)
try:
    valid_until = datetime.fromisoformat(m["valid_until"].replace("Z", "+00:00"))
except Exception as e:
    sys.stderr.write(f"valid_until parse failed: {e}\n"); sys.exit(2)
if now > valid_until:
    sys.stderr.write(f"manifest EXPIRED at {m['valid_until']}\n"); sys.exit(2)

# version: restricted release-version
if not re.match(r"^\d+\.\d+\.\d+(rc\d+|a\d+|b\d+)?$", m["version"]):
    sys.stderr.write("manifest version format invalid\n"); sys.exit(2)
# sha256: 64 hex
if not re.match(r"^[a-fA-F0-9]{64}$", m["sha256"]):
    sys.stderr.write("sha256 not 64 hex\n"); sys.exit(2)
# size sanity
if not (min_size <= m["size_bytes"] <= max_size):
    sys.stderr.write(f"size_bytes outside [{min_size}, {max_size}]\n"); sys.exit(2)
# wheel_url validation
u = urllib.parse.urlparse(m["wheel_url"])
if u.scheme != "https":
    sys.stderr.write("wheel_url not HTTPS\n"); sys.exit(2)
if u.hostname != expected_host:
    sys.stderr.write(f"wheel_url host {u.hostname!r} != {expected_host!r}\n"); sys.exit(2)
if not u.path.startswith(expected_prefix):
    sys.stderr.write(f"wheel_url path bad prefix\n"); sys.exit(2)
if u.query or u.fragment or u.username or u.password:
    sys.stderr.write("wheel_url has forbidden query/fragment/userinfo\n"); sys.exit(2)
if "/v" + m["version"] + "/" not in u.path:
    sys.stderr.write(f"wheel_url path lacks /v{m['version']}/\n"); sys.exit(2)
expected_suffix = f"-{m['version']}-py3-none-any.whl"
if not u.path.endswith(expected_suffix):
    sys.stderr.write(f"wheel_url filename suffix mismatch\n"); sys.exit(2)
if m["filename"] != f"agentic_security_review{expected_suffix}":
    sys.stderr.write(f"manifest.filename {m['filename']!r} unexpected\n"); sys.exit(2)

print(m["version"])
print(m["wheel_url"])
print(m["sha256"])
print(m["size_bytes"])
print(m["filename"])
PYEOF

# Bash 3.2 compatible field extraction
VERSION=$(sed -n '1p' "$MANIFEST_PARSED")
WHEEL_URL=$(sed -n '2p' "$MANIFEST_PARSED")
EXPECTED_SHA=$(sed -n '3p' "$MANIFEST_PARSED")
EXPECTED_SIZE=$(sed -n '4p' "$MANIFEST_PARSED")
WHEEL_FILENAME=$(sed -n '5p' "$MANIFEST_PARSED")
if [ -z "$VERSION" ] || [ -z "$WHEEL_URL" ] || [ -z "$EXPECTED_SHA" ] || [ -z "$WHEEL_FILENAME" ]; then
  die "Manifest parsing failed (empty fields)"
fi
log "  ✓ Manifest: version=$VERSION size=$EXPECTED_SIZE"

# ── 5. Downgrade policy (via pipx list --json) ───────────────────────
log "Checking installed version …"
INSTALLED_VERSION=""
PIPX_JSON=$(pipx list --json 2>/dev/null) || {
  die "pipx list --json failed. Upgrade pipx (>=1.0) so we can reliably check installed version:
    macOS:  brew upgrade pipx
    Linux:  python3 -m pip install --user --upgrade pipx"
}
if [ -z "$PIPX_JSON" ]; then
  die "pipx list --json returned empty output. Cannot verify downgrade-policy. Aborting."
fi
INSTALLED_VERSION=$(printf '%s' "$PIPX_JSON" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    venvs = data.get('venvs', {})
    if 'agentic-security-review' in venvs:
        pkg = venvs['agentic-security-review']['metadata']['main_package']
        print(pkg.get('package_version', ''))
except Exception as e:
    sys.stderr.write(f'pipx JSON parse failed: {e}\n')
    sys.exit(2)
")

if [ -n "$INSTALLED_VERSION" ]; then
  log "  Installed: $INSTALLED_VERSION; target: $VERSION"
  # restricted release-version compare (NOT full PEP 440)
  CMP=$(python3 - "$INSTALLED_VERSION" "$VERSION" <<'PYEOF'
import re, sys
def parse(v):
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)(rc(\d+)|a(\d+)|b(\d+))?$', v)
    if not m: sys.exit(2)
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    pre = m.group(4) or ''
    pre_rank = 1 if pre.startswith('a') else (2 if pre.startswith('b') else (3 if pre.startswith('rc') else 4))
    pre_num = int(m.group(5) or m.group(6) or m.group(7) or 0)
    return (major, minor, patch, pre_rank, pre_num)
inst = parse(sys.argv[1])
new = parse(sys.argv[2])
print('downgrade' if new < inst else ('same' if new == inst else 'upgrade'))
PYEOF
)
  case "$CMP" in
    downgrade)
      if [ "${CODEREVIEW_ALLOW_DOWNGRADE:-0}" = "1" ]; then
        warn "Downgrade $INSTALLED_VERSION → $VERSION (CODEREVIEW_ALLOW_DOWNGRADE=1)"
      else
        die "Refusing downgrade $INSTALLED_VERSION → $VERSION. Set CODEREVIEW_ALLOW_DOWNGRADE=1 to override."
      fi
      ;;
    same)
      log "  Same version already installed"
      ;;
    upgrade)
      log "  Upgrade $INSTALLED_VERSION → $VERSION"
      ;;
  esac
else
  log "  Not installed yet"
fi

# ── 6. Download wheel ────────────────────────────────────────────────
WHEEL_FILE="$TMP_DIR/$WHEEL_FILENAME"
log "Downloading wheel …"
if ! curl_safe -o "$WHEEL_FILE" "$WHEEL_URL"; then
  err "Failed to download wheel from $WHEEL_URL"
  exit 3
fi

# Size check before SHA (cheap pre-filter)
ACTUAL_SIZE=$(stat -f %z "$WHEEL_FILE" 2>/dev/null || stat -c %s "$WHEEL_FILE" 2>/dev/null || echo 0)
if [ "$ACTUAL_SIZE" != "$EXPECTED_SIZE" ]; then
  die "Wheel size mismatch: expected $EXPECTED_SIZE got $ACTUAL_SIZE"
fi

# ── 7. SHA-256 verification ──────────────────────────────────────────
ACTUAL_SHA=$($SHA_CMD "$WHEEL_FILE" | awk '{print $1}')
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  err "SHA-256 MISMATCH"
  err "  expected: $EXPECTED_SHA"
  err "  actual:   $ACTUAL_SHA"
  err "Possible: in-transit tampering, manifest staleness, or compromise."
  exit 2
fi
log "  ✓ SHA-256 verified"

# ── 8. pipx install ──────────────────────────────────────────────────
log "Installing agentic-security-review via pipx …"
if ! pipx install --force "$WHEEL_FILE" >/dev/null 2>&1; then
  err "pipx install failed. Re-run manually: pipx install --force $WHEEL_FILE"
  exit 3
fi
log "  ✓ pipx install complete"

# ── 9. Locate package data (dynamic; no hardcoded python version) ────
log "Locating installed package data …"
PIPX_VENV_DIR=$(pipx environment --value PIPX_LOCAL_VENVS 2>/dev/null || echo "$HOME/.local/pipx/venvs")
PKG_VENV="$PIPX_VENV_DIR/agentic-security-review"
if [ ! -d "$PKG_VENV" ]; then
  die "Cannot find pipx venv at $PKG_VENV"
fi
VENV_PY="$PKG_VENV/bin/python"
if [ ! -x "$VENV_PY" ]; then
  die "Cannot find pipx venv python at $VENV_PY"
fi
PKG_DATA_DIR=$("$VENV_PY" -c "
from importlib.resources import files
print(files('agentic_security_review') / 'data')
")
if [ ! -d "$PKG_DATA_DIR" ]; then
  die "Cannot find agentic_security_review/data inside pipx venv"
fi
log "  ✓ Package data: $PKG_DATA_DIR"

# ── 10. Skill symlink (safe) ─────────────────────────────────────────
log "Installing Claude Code skill …"
mkdir -p "$SKILL_DIR"
TARGET_SKILL="$SKILL_DIR/$SKILL_NAME"
SOURCE_SKILL="$PKG_DATA_DIR/skills/$SKILL_NAME"

if [ ! -d "$SOURCE_SKILL" ]; then
  die "Source skill dir missing: $SOURCE_SKILL"
fi

if [ -e "$TARGET_SKILL" ] || [ -L "$TARGET_SKILL" ]; then
  if [ -L "$TARGET_SKILL" ]; then
    rm "$TARGET_SKILL"
  elif [ -d "$TARGET_SKILL" ]; then
    if [ "${CODEREVIEW_FORCE_SKILL_LINK:-0}" = "1" ]; then
      warn "Removing existing skill directory (CODEREVIEW_FORCE_SKILL_LINK=1)"
      rm -rf "$TARGET_SKILL"
    else
      die "$TARGET_SKILL exists and is NOT a symlink. Refusing to overwrite.
       Set CODEREVIEW_FORCE_SKILL_LINK=1 to force replacement."
    fi
  fi
fi
ln -s "$SOURCE_SKILL" "$TARGET_SKILL"
log "  ✓ Skill linked: $TARGET_SKILL → $SOURCE_SKILL"

# Verify PROMPT_TEMPLATE.md is present inside the skill dir (it should be
# baked into the wheel's data/skills/security-review/ — no install-time copy
# needed; the symlink target already contains it).
if [ ! -f "$SOURCE_SKILL/PROMPT_TEMPLATE.md" ]; then
  die "Bundled PROMPT_TEMPLATE.md missing inside skill dir: $SOURCE_SKILL"
fi
log "  ✓ Prompt template available at $TARGET_SKILL/PROMPT_TEMPLATE.md (via symlink)"

# ── 11. Smoke test ───────────────────────────────────────────────────
if [ "${CODEREVIEW_SKIP_SMOKE_TEST:-0}" != "1" ]; then
  log "Smoke test …"
  if ! agentic-security-review --help >/dev/null 2>&1; then
    die "agentic-security-review CLI not responding (PATH issue? Try: pipx ensurepath; exec \$SHELL)"
  fi
  if ! agentic-preflight --help >/dev/null 2>&1; then
    warn "agentic-preflight CLI not responding (non-blocking)"
  fi
  log "  ✓ CLIs respond"
fi

cat <<DONE

$(printf "\033[32m✓ Installed agentic-security-review %s\033[0m" "$VERSION")

Next steps:
  • CLI:               agentic-security-review --help
  • Preflight:         agentic-preflight <target-dir>
  • Via Claude Code:   /security-review <path>
  • Prompt template:   $TARGET_SKILL/PROMPT_TEMPLATE.md

Docs:    https://github.com/AndersSol/CodeReview
SHA-256: $ACTUAL_SHA

DONE
