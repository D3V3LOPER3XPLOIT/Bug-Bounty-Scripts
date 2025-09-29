#!/usr/bin/env python3
"""
extract-domains.py — extract domains from files or stdin, optionally resolve/check/fetch title and write to output.

Usage examples:
  # extract domains from file(s) and print
  ./extract-domains.py input1.txt input2.html

  # extract from stdin
  cat page.html | ./extract-domains.py

  # write unique sorted domains to output file
  ./extract-domains.py input.txt -o domains.txt

  # resolve DNS and show HTTP status (best-effort)
  ./extract-domains.py input.txt -c -s

  # fetch HTML title (may be slower)
  ./extract-domains.py input.txt -t -o out.md

  # show help
  ./extract-domains.py -h
"""
from __future__ import annotations
import argparse
import re
import sys
import socket
import urllib.parse
import urllib.request
import ssl
from typing import Iterable, Set, List, Tuple

# Optional: try to use requests if available (simpler HTTP)
try:
    import requests  # type: ignore
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

# Domain regex: matches domain names like example.com, sub.example.co.uk (case-insensitive)
DOMAIN_RE = re.compile(
    r"\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,}|xn--[a-z0-9]+))\b",
    re.IGNORECASE,
)

# Helper: sanitize domain (strip surrounding punctuation, trailing slashes/ports)
def clean_domain(raw: str) -> str:
    d = raw.strip().strip(" ,;:()[]{}<>\"'`")
    # remove trailing slash or path
    d = d.split("/")[0]
    # remove trailing port
    d = re.sub(r":\d+$", "", d)
    return d.lower()

def extract_domains_from_text(text: str) -> Set[str]:
    domains: Set[str] = set()
    # First find any URLs and extract netlocs
    for url_match in re.finditer(r'https?://[^\s\'"<>]+', text, flags=re.IGNORECASE):
        url = url_match.group(0)
        try:
            p = urllib.parse.urlparse(url)
            if p.hostname:
                domains.add(p.hostname.lower())
        except Exception:
            pass

    # Also run domain regex for bare domains
    for m in DOMAIN_RE.finditer(text):
        domains.add(clean_domain(m.group(0)))
    return domains

def read_inputs(files: List[str]) -> str:
    if not files:
        # read from stdin
        return sys.stdin.read()
    parts: List[str] = []
    for fname in files:
        try:
            with open(fname, "r", encoding="utf-8", errors="ignore") as f:
                parts.append(f.read())
        except Exception as e:
            print(f"[!] Warning: cannot read {fname}: {e}", file=sys.stderr)
    return "\n".join(parts)

def resolve_domain(domain: str, timeout: float = 5.0) -> str:
    try:
        # simple resolution
        return socket.gethostbyname(domain)
    except Exception:
        try:
            # try gethostbyname_ex for multiple IPs
            a = socket.gethostbyname_ex(domain)
            if a and len(a) >= 3 and a[2]:
                return a[2][0]
        except Exception:
            pass
    return "UNRESOLVED"

# HTTP status code fetch (HEAD then GET fallback)
def http_status_and_title(domain: str, timeout: float = 8.0) -> Tuple[str, str]:
    url = f"https://{domain}/"
    headers = {"User-Agent": "extract-domains-tool/1.0 (+https://example)"}
    # try requests if available (handles redirects/tls easily)
    if HAVE_REQUESTS:
        try:
            r = requests.head(url, headers=headers, allow_redirects=True, timeout=timeout, verify=False)
            code = str(r.status_code)
            title = ""
            if r.status_code >= 400 or r.headers.get("Content-Type","").lower().startswith("text/html"):
                # Try GET to grab a title if HEAD didn't return content
                try:
                    r2 = requests.get(url, headers=headers, allow_redirects=True, timeout=timeout, verify=False)
                    code = str(r2.status_code)
                    title = extract_title_from_html(r2.text)
                except Exception:
                    pass
            return code, title
        except Exception:
            # fallback to http
            try:
                url2 = f"http://{domain}/"
                r = requests.get(url2, headers=headers, allow_redirects=True, timeout=timeout, verify=False)
                return str(r.status_code), extract_title_from_html(r.text)
            except Exception:
                return "ERR", ""
    # fallback to urllib
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers=headers, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            code = str(getattr(resp, "status", resp.getcode()))
            # HEAD usually no body; try GET for title
            try:
                req2 = urllib.request.Request(url, headers=headers, method="GET")
                with urllib.request.urlopen(req2, timeout=timeout, context=ctx) as r2:
                    body = r2.read(65536).decode("utf-8", errors="ignore")
                    title = extract_title_from_html(body)
                    return code, title
            except Exception:
                return code, ""
    except Exception:
        # try http
        try:
            url2 = f"http://{domain}/"
            req2 = urllib.request.Request(url2, headers=headers, method="GET")
            with urllib.request.urlopen(req2, timeout=timeout) as r2:
                body = r2.read(65536).decode("utf-8", errors="ignore")
                title = extract_title_from_html(body)
                return str(getattr(r2, "status", r2.getcode())), title
        except Exception:
            return "ERR", ""

def extract_title_from_html(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    if m:
        t = m.group(1).strip()
        # collapse whitespace
        t = re.sub(r"\s+", " ", t)
        return t
    return ""

def main(argv: Iterable[str] = None) -> int:
    p = argparse.ArgumentParser(prog="extract-domains", description="Extract domains from files or stdin and optionally resolve/check them.")
    p.add_argument("files", nargs="*", help="Input files (if none, reads stdin)")
    p.add_argument("-o", "--output", help="Write extracted domains (and info) to FILE")
    p.add_argument("-u", "--unique", action="store_true", help="Output unique domains only (default: dedupe)")
    p.add_argument("-n", "--no-sort", action="store_true", help="Do not sort output")
    p.add_argument("-c", "--check", action="store_true", help="DNS-resolve each domain (show IP) — may be slow")
    p.add_argument("-s", "--status", action="store_true", help="Fetch HTTP status code for each domain (HEAD/GET) — may be slow")
    p.add_argument("-t", "--title", action="store_true", help="Fetch HTML <title> for each domain (implies --status)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output while processing")
    args = p.parse_args(list(argv) if argv is not None else None)

    text = read_inputs(args.files)
    if not text:
        print("[!] No input found (files empty or stdin closed).", file=sys.stderr)
        return 1

    domains = extract_domains_from_text(text)
    if args.verbose:
        print(f"[i] Found {len(domains)} raw domain(s).", file=sys.stderr)

    # dedupe (set already) and optionally sort
    dom_list = sorted(domains) if not args.no_sort else list(domains)
    # --unique doesn't change result (we already dedup). kept for CLI parity.
    if args.verbose:
        print(f"[i] Preparing output (count={len(dom_list)}).", file=sys.stderr)

    out_lines: List[str] = []
    header = []
    if args.check:
        header.append("IP")
    if args.status or args.title:
        header.append("HTTP")
    if args.title:
        header.append("TITLE")

    # process each domain
    for d in dom_list:
        ip = ""
        status = ""
        title = ""
        if args.check:
            if args.verbose:
                print(f"[i] Resolving {d}...", file=sys.stderr)
            ip = resolve_domain(d)
        if args.title:
            # title implies status
            args.status = True
        if args.status:
            if args.verbose:
                print(f"[i] Fetching HTTP status for {d}...", file=sys.stderr)
            status, title = http_status_and_title(d)
        # build output line
        parts = [d]
        if args.check:
            parts.append(ip)
        if args.status or args.title:
            parts.append(status)
        if args.title:
            parts.append(title)
        out_lines.append("\t".join(parts))

    # default output: print to stdout and optionally write to file
    output_text = "\n".join(out_lines)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output_text + ("\n" if output_text and not output_text.endswith("\n") else ""))
            print(f"[+] Wrote {len(out_lines)} lines to {args.output}")
        except Exception as e:
            print(f"[!] Failed to write output file {args.output}: {e}", file=sys.stderr)
            print(output_text)
            return 1
    else:
        print(output_text)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
