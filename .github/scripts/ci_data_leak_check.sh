#!/usr/bin/env bash
# CI data-leak validation — safe public version (no customer-specific patterns)
# Checks for: IPs, credentials, scan data, binary files in tracked paths
# Local version with sensitive patterns lives at: private/bin/validate_data_leak.sh
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
FAIL=0

echo "=== CI Data-Leak Check ==="

# ── 1. Scan result files in tracked paths ──────
echo -n "[1] Scan result files... "
LEAKS=$(git ls-files | grep -iE 'results_.*\.json$|dc-.*\.json$|\.pcap$' || true)
[ -n "$LEAKS" ] && { echo -e "${RED}FAIL${NC}"; echo "$LEAKS"; FAIL=1; } || echo -e "${GREEN}OK${NC}"

# ── 2. Private IP ranges in strings ──────
#    Allowed: test files, docstrings, comments, example domains, GUI dashboard IPs
echo -n "[2] IP addresses in code... "
LEAKS=$(git ls-files | xargs grep -lP '192\.168\.|10\.\d{1,3}\.|172\.(1[6-9]|2\d|3[01])\.' 2>/dev/null | \
  grep -v '^\.gitignore\|^CONTEXT\.md\|^README\.md' | \
  grep -v '^tests/\|^src/istrix/gui/' | \
  grep -v '^config/tiers\.yaml' | \
  grep -v '^src/istrix/cli/plan\.py\|^src/istrix/cli/scan\.py' | \
  grep -v '^src/istrix/reporting/generator\.py' || true)
[ -n "$LEAKS" ] && { echo -e "${RED}FAIL${NC}"; echo "$LEAKS"; FAIL=1; } || echo -e "${GREEN}OK${NC}"

# ── 3. API keys / tokens ──────────────────────
echo -n "[3] API keys... "
LEAKS=$(git ls-files | xargs grep -lP '(?i)(api[_-]?key|api[_-]?secret|auth[_-]?token)\s*[=:]\s*['\''\"]?[A-Za-z0-9_\-]{20,}' 2>/dev/null | \
  grep -v '^\.env\.example\|^private/' || true)
[ -n "$LEAKS" ] && { echo -e "${RED}FAIL${NC}"; echo "$LEAKS"; FAIL=1; } || echo -e "${GREEN}OK${NC}"

# ── 4. Email addresses ──────────────────────
#    Allowed: about page, vulndb contact
echo -n "[4] Email addresses... "
LEAKS=$(git ls-files | xargs grep -lP '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b' 2>/dev/null | \
  grep -v '^\.env\.example\|^private/\|^CONTEXT\.md\|^README\.md' | \
  grep -v '^src/istrix/reporting/generator\.py\|^config/vulndb\.yaml' || true)
[ -n "$LEAKS" ] && { echo -e "${RED}FAIL${NC}"; echo "$LEAKS"; FAIL=1; } || echo -e "${GREEN}OK${NC}"

# ── 5. Home directory paths ─────────────────
echo -n "[5] Home directory paths... "
LEAKS=$(git ls-files | xargs grep -lP '/home/[a-z]' 2>/dev/null | grep -v '^private/' || true)
[ -n "$LEAKS" ] && { echo -e "${RED}FAIL${NC}"; echo "$LEAKS"; FAIL=1; } || echo -e "${GREEN}OK${NC}"

# ── 6. Large binary files ──────────────────
echo -n "[6] Large binary files... "
LEAKS=""
while IFS= read -r f; do
    [ ! -f "$f" ] && continue
    size=$(wc -c < "$f" 2>/dev/null || echo 0)
    [ "$size" -gt 500000 ] 2>/dev/null && ! file "$f" 2>/dev/null | grep -q 'text' && LEAKS="$LEAKS$f ($size)\n"
done <<< "$(git ls-files)"
[ -n "$LEAKS" ] && { echo -e "${RED}FAIL${NC}"; echo -e "$LEAKS"; } || echo -e "${GREEN}OK${NC}"

echo ""
[ "$FAIL" -eq 0 ] && { echo -e "${GREEN}All data-leak checks passed.${NC}"; exit 0; } || { echo -e "${RED}BLOCKED: data leaks detected.${NC}"; exit 1; }
