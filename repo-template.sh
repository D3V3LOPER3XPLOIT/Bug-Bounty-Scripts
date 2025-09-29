#!/usr/bin/env bash
# repo-template.sh — create skeleton for a new helper script project
# Usage: ./repo-template.sh ProjectName

NAME="$1"
if [ -z "$NAME" ]; then
  echo "Usage: $0 <ProjectName>"
  exit 1
fi

mkdir -p "$NAME"
cat > "$NAME/README.md" <<EOF
# $NAME

Short description: what this helper does and usage.
EOF

cat > "$NAME/.gitignore" <<EOF
# generic
*.log
*.env
EOF

cat > "$NAME/main.sh" <<'EOF'
#!/usr/bin/env bash
# main.sh — entry point for the helper
echo "Hello from $NAME"
EOF

chmod +x "$NAME/main.sh"
echo "Created skeleton project $NAME"
