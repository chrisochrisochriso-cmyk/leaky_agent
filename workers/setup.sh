#!/usr/bin/env bash
# leaky_agent — Cloudflare Worker setup script
# Run from the repo root: bash workers/setup.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "════════════════════════════════════════════════"
echo "  leaky_agent — Cloudflare Worker Setup"
echo "════════════════════════════════════════════════"
echo ""

# 0. Check wrangler
if ! command -v wrangler &>/dev/null; then
  echo "wrangler not found. Install with: npm install -g wrangler"
  exit 1
fi

# 1. Login
echo "Step 1: Cloudflare login"
wrangler login

# 2. Create KV namespace
echo ""
echo "Step 2: Creating KV namespace 'EVENTS'…"
KV_OUTPUT=$(wrangler kv namespace create "EVENTS" 2>&1)
echo "$KV_OUTPUT"

# Try to extract the id automatically
KV_ID=$(echo "$KV_OUTPUT" | grep -oE 'id = "[^"]+"' | grep -oE '"[^"]+"' | tr -d '"' | head -1)

if [ -z "$KV_ID" ]; then
  echo ""
  echo "Could not extract KV ID automatically."
  read -rp "Paste the 'id' value from the output above: " KV_ID
fi

echo ""
echo "KV namespace ID: $KV_ID"

# 3. Patch wrangler.toml
echo ""
echo "Step 3: Updating wrangler.toml…"
sed -i.bak "s/REPLACE_WITH_YOUR_KV_NAMESPACE_ID/$KV_ID/" wrangler.toml
rm -f wrangler.toml.bak
echo "Done."

# 4. Deploy
echo ""
echo "Step 4: Deploying worker…"
wrangler deploy

echo ""
echo "════════════════════════════════════════════════"
echo "  Worker deployed!"
echo ""
echo "  Next: copy your Worker URL from the output"
echo "  above (e.g. https://leaky-agent.YOUR.workers.dev)"
echo "  and set CANARY_WORKER_URL in config.js."
echo "════════════════════════════════════════════════"
echo ""
