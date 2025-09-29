cat > public-scripts/dedupe-wordlist.sh <<'EOF'
#!/usr/bin/env bash
# dedupe-wordlist.sh — sort and dedupe lines from stdin or file
# Usage:
#   ./dedupe-wordlist.sh wordlist.txt > wordlist.clean.txt
#   cat list.txt | ./dedupe-wordlist.sh > clean.txt
#   ./dedupe-wordlist.sh        # interactive: paste then Ctrl-D

if [ $# -eq 1 ] && [ -f "$1" ]; then
  sort -u "$1"
else
  if [ $# -gt 0 ]; then
    # treat args as files
    sort -u "$@"
  else
    echo "Paste lines (or pipe in). Press Ctrl-D when done:"
    sort -u
  fi
fi
EOF
chmod +x public-scripts/dedupe-wordlist.sh
