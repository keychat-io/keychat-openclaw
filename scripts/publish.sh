#!/bin/bash
# Publish @keychat-io/keychat to npm
# Usage: ./scripts/publish.sh [--dry-run]

set -e
cd "$(dirname "$0")/.."

# Load .env
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

if [ -z "$NPM_TOKEN" ]; then
  echo "❌ NPM_TOKEN not set. Create .env with: NPM_TOKEN=npm_xxxxx"
  exit 1
fi

# Set token for this publish
echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc.tmp

echo "📦 Publishing @keychat-io/keychat v$(node -p "require('./package.json').version")..."
npm publish --access public --tag latest --userconfig .npmrc.tmp "$@"

rm -f .npmrc.tmp
echo "✅ Published!"
