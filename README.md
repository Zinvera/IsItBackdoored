# IsItBackdoored

Static analysis tool for detecting backdoors, malware, and suspicious code patterns in source files.

## What It Does

Scans codebases for common backdoor indicators:
- Obfuscated code (base64/hex encoding, high entropy strings)
- Command/SQL injection vulnerabilities
- Unsafe deserialization
- Hardcoded credentials and crypto keys
- Suspicious network activity (C2 patterns, reverse shells)
- Malicious file operations
- Cryptocurrency mining code

## Quick Start

```bash
pip install -r requirements.txt
python main.py
```

Drag and drop a folder or file, adjust confidence threshold, and scan. Results open automatically in your browser.

## Supported Languages

Python • JavaScript • TypeScript • PHP • Go • Java • C • C++

## Detection Engines

**ObfuscationDetector**  
Catches base64+eval, hex encoding, character code obfuscation, high entropy strings, unicode tricks

**NetworkDetector**  
Flags hardcoded IPs, suspicious TLDs, pastebin/Tor usage, reverse shells, raw sockets, data exfiltration

**FileOperationDetector**  
Detects writes to /etc/, ~/.ssh/, registry manipulation, environment tampering, log tampering, persistence mechanisms

**CryptoDetector**  
Identifies MD5/SHA1/DES usage, hardcoded keys, custom crypto, mining pools

**SuspiciousPatternDetector**  
Finds eval/exec abuse, SQL/command injection, unsafe deserialization, XXE, SSRF, path traversal, anti-debugging, process injection

**CppDetector** (C/C++ specific)  
Buffer overflows (strcpy, strcat, sprintf, gets), format string vulnerabilities, memory issues (double free, use-after-free), integer overflows, race conditions (TOCTOU), unsafe functions

## Report Features

- Risk score (0-100)
- Severity classification (CRITICAL/HIGH/MEDIUM/LOW)
- Confidence scoring
- Code snippets with context
- Remediation recommendations
- Interactive filtering by file/severity
- Visual charts

## Configuration

- **Minimum Confidence**: Filter out low-confidence findings (0-100%)
- **Include Hidden Files**: Scan dotfiles
- **Follow Symlinks**: Traverse symbolic links
- **Scan Dependencies**: Check node_modules, vendor, etc.

## Requirements

- Python 3.8+
- PyQt6
- tree-sitter + language parsers
- Jinja2

## False Positives

The tool prioritizes detection over precision. Review findings with context:
- Low confidence (<70%) may be legitimate code
- Check if patterns match your use case
- Adjust confidence threshold to reduce noise

## Contributing

Found a bypass or false positive? Open an issue with:
- Sample code that should/shouldn't trigger
- Expected vs actual behavior
- Language and file type

## License

MIT - See LICENSE file

## Disclaimer

This tool performs static analysis only. It cannot detect runtime behavior, polymorphic malware, or zero-days. Use as part of a defense-in-depth strategy, not as sole security measure.
