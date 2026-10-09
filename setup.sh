#!/bin/bash
# EC2 setup: clone all cyberlab tool repos, install deps, patch for umbrella mounting
set -e

LABS_DIR="/var/www/labs"
TOOLS_DIR="$LABS_DIR/tools"
ORG="Quatech01"

mkdir -p "$TOOLS_DIR"
cd "$LABS_DIR"

# Install umbrella dependencies
npm install --production

# ── Tool repos to clone ────────────────────────────────────────────────────────
declare -A TOOLS=(
  [xss-reflection-scanner]="cyberlab-xss-reflection-scanner"
  [port-scanner-service-fingerprinting]="cyberlab-port-scanner-service-fingerprinting"
  [sql-injection-detector]="cyberlab-sql-injection-detector"
  [hash-collision-demonstrator]="cyberlab-hash-collision-demonstrator"
  [brute-force-rate-limiter-demo]="cyberlab-brute-force-rate-limiter-demo"
  [file-entropy-analyzer]="cyberlab-file-entropy-analyzer"
  [csrf-token-validator]="cyberlab-csrf-token-validator"
  [aes-encryption-mode-comparison]="cyberlab-aes-encryption-mode-comparison"
  [input-sanitization-library]="cyberlab-input-sanitization-library"
  [log-file-anomaly-detector]="cyberlab-log-file-anomaly-detector"
  [jwt-vulnerability-scanner]="cyberlab-jwt-vulnerability-scanner"
  [http-security-header-auditor]="cyberlab-http-security-header-auditor"
  [keylogger-detection-and-flagging]="cyberlab-keylogger-detection-and-flagging"
  [dns-record-analyzer]="cyberlab-dns-record-analyzer"
  [email-header-analyzer]="cyberlab-email-header-analyzer"
  [oauth-pkce-flow-analyzer]="cyberlab-oauth-pkce-flow-analyzer"
  [timing-attack-demonstrator]="cyberlab-timing-attack-demonstrator"
  [open-redirect-checker]="cyberlab-open-redirect-checker"
  [soc-tier1-alert-triage-simulator]="cyberlab-soc-tier1-alert-triage-simulator"
  [directory-traversal-detector]="cyberlab-directory-traversal-detector"
  [session-fixation-demonstrator]="cyberlab-session-fixation-demonstrator"
  [subdomain-enumerator]="cyberlab-subdomain-enumerator"
  [gp-appointment-booking-system]="cyberlab-gp-appointment-booking-system"
  [hash-generator-authenticator]="cyberlab-hash-generator-authenticator"
  [form-platform]="cyberlab-form-platform"
  [totp-demo]="cyberlab-totp-demo"
  [tls-inspector]="cyberlab-tls-inspector"
)

for slug in "${!TOOLS[@]}"; do
  repo="${TOOLS[$slug]}"
  dest="$TOOLS_DIR/$slug"

  echo "── $slug ──"

  # Clone if not already present
  if [ ! -d "$dest" ]; then
    git clone "https://github.com/$ORG/$repo.git" "$dest" || {
      echo "  WARN: could not clone $repo, skipping"
      continue
    }
  else
    echo "  exists, pulling latest"
    git -C "$dest" pull --ff-only || true
  fi

  cd "$dest"

  # Node.js tool
  if [ -f "package.json" ] && [ -f "server.js" ]; then
    echo "  npm install..."
    npm install --production 2>&1 | tail -3

    echo "  patching server.js..."
    node "$LABS_DIR/scripts/patch-server.js" server.js

    # Patch index.html: convert absolute /api/ paths to relative api/
    if [ -f "public/index.html" ]; then
      echo "  patching public/index.html..."
      # All common patterns: fetch('/api/, url: '/api/, axios.get('/api/
      sed -i "s|'/api/|'api/|g"  public/index.html
      sed -i 's|"/api/|"api/|g'  public/index.html
      sed -i 's|`/api/|`api/|g'  public/index.html
    fi
  fi

  # Python tool
  if [ -f "main.py" ] || [ -f "requirements.txt" ]; then
    echo "  pip install..."
    pip3 install -r requirements.txt -q 2>&1 | tail -3 || true

    # Patch HTML similarly
    if [ -f "public/index.html" ]; then
      echo "  patching public/index.html..."
      sed -i "s|'/api/|'api/|g"  public/index.html
      sed -i 's|"/api/|"api/|g'  public/index.html
      sed -i 's|`/api/|`api/|g'  public/index.html
    fi
  fi

  cd "$LABS_DIR"
done

echo ""
echo "All tools set up. Start with: pm2 start server.js --name labs"
