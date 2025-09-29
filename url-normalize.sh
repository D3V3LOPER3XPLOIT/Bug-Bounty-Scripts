cat > public-scripts/url-normalize.sh <<'EOF'
#!/usr/bin/env bash
# url-normalize.sh — normalize URLs from stdin or a file
# Usage:
#   ./url-normalize.sh urls.txt
#   cat urls.txt | ./url-normalize.sh
#   ./url-normalize.sh         # interactive mode: paste lines, Ctrl-D to finish

process_line() {
  local url="$1"
  url="$(echo "$url" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [ -z "$url" ] && return
  if ! echo "$url" | grep -qE '^https?://'; then
    url="http://$url"
  fi
  proto="$(echo "$url" | awk -F:// '{print tolower($1)}')"
  rest="$(echo "$url" | sed -E 's#^[a-zA-Z]+://##')"
  host="$(echo "$rest" | awk -F/ '{print $1}' | tr '[:upper:]' '[:lower:]')"
  path="/$(echo "$rest" | cut -d/ -f2-)"
  [ "$path" = "/" ] && path=""
  host="$(echo "$host" | sed -E 's/:80$//;s/:443$//')"
  echo "${proto}://${host}${path}"
}

if [ $# -eq 1 ] && [ -f "$1" ]; then
  while IFS= read -r line; do
    process_line "$line"
  done < "$1"
else
  if [ $# -gt 0 ]; then
    for arg in "$@"; do
      process_line "$arg"
    done
  else
    echo "Enter URLs (one per line). Press Ctrl-D when done:"
    while IFS= read -r line; do
      process_line "$line"
    done
  fi
fi
EOF
chmod +x public-scripts/url-normalize.sh
