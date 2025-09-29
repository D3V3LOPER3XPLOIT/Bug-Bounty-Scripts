# HTB Writeups 🕵️‍♂️

This repository contains my personal writeups of Hack The Box machines. I do **not** reveal any flags — the focus is on **methodology, tools used, and key learning points**.

## 📌 Machines Covered

| Name     | Difficulty | Techniques Used                 |
|----------|------------|---------------------------------|
| Blue     | Easy       | SMB Enumeration, EternalBlue    |
| Optimum  | Easy       | HttpFileServer Exploit          |
| Legacy   | Easy       | SMBv1, Metasploit               |

## 🛠️ Tools Used

- Nmap
- Nikto
- Metasploit
- Netcat
- Burp Suite
- Gobuster

## 📚 Learning Goals

- Internalize enumeration mindset
- Practice real-world exploit chains
- Automate repetitive scanning tasks

> ⚠️ All writeups are for educational purposes only.


# Extract Domains Tool

A simple Python tool to extract domains from any file or stdin, with options to resolve DNS, fetch HTTP status codes, and page titles.

---

## 🔧 Installation & Running

1. **Save the script**  
   Place `extract-domains.py` inside your repo (e.g. `public-scripts/`).

2. **Make it executable**  
   ```bash
   chmod +x public-scripts/extract-domains.py
   ```

3. **Run the tool**  
   - Extract domains from a file:  
     ```bash
     ./public-scripts/extract-domains.py input.txt
     ```
   - From stdin:  
     ```bash
     cat input.txt | ./public-scripts/extract-domains.py
     ```
   - Write results to a file:  
     ```bash
     ./public-scripts/extract-domains.py input.txt -o domains.txt
     ```
   - Resolve DNS and fetch HTTP status:  
     ```bash
     ./public-scripts/extract-domains.py input.txt -c -s
     ```
   - Show help:  
     ```bash
     ./public-scripts/extract-domains.py -h
     ```

---
