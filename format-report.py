#!/usr/bin/env python3
# format-report.py — convert JSON summary (title, severity, notes) to Markdown
# Usage: python3 format-report.py summary.json

import sys, json

def to_markdown(data):
    out = []
    out.append(f"# {data.get('title','No Title')}\n")
    out.append(f"**Severity:** {data.get('severity','n/a')}\n")
    if 'tags' in data and data['tags']:
        out.append("**Tags:** " + ", ".join(data['tags']) + "\n")
    out.append("## Notes\n")
    out.append(data.get('notes','No notes provided') + "\n")
    return "\n".join(out)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 format-report.py <summary.json>")
        sys.exit(1)
    with open(sys.argv[1], 'r') as f:
        data = json.load(f)
    print(to_markdown(data))

if __name__ == "__main__":
    main()
