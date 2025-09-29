cat > public-scripts/header-check.sh <<'EOF'
#!/usr/bin/env bash
# header-check.sh — print HTTP status and headers for a URL
# Usage: ./header-check.sh https://example.com
#        ./header-check.sh   (interactive)

URL="$1"
if [ -z "$URL" ]; then
  read -rp "Enter URL (e.g. https://example.com): " URL
fi

if [ -z "$URL" ]; then
  echo "No URL provided. Exiting."
  exit 1
fi

echo "Checking: $URL"
# follow redirects but limit depth, show headers
curl -IsL --max-redirs 5 --connect-timeout 10 "$URL" | sed -n '1,200p'
EOF
chmod +x public-scripts/header-check.sh
