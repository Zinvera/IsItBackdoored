# IsItBackdoored

Static analysis tool for detecting backdoors, malware, and suspicious code patterns in source files.

## What It Does

Scans codebases for 150+ backdoor indicators across 8 languages:
- **Code Execution**: eval/exec with obfuscation, dynamic imports, variable functions
- **Injection Attacks**: SQL injection, command injection, XXE, SSRF, path traversal
- **Memory Corruption**: Buffer overflows, format strings, double free, use-after-free
- **Obfuscation**: Base64+eval, hex encoding, high entropy, unicode tricks, string reversals
- **Network Threats**: C2 IPs, reverse shells, data exfiltration, Tor usage, suspicious domains
- **Crypto Issues**: Weak algorithms (MD5/DES), hardcoded keys, crypto mining
- **Persistence**: Registry manipulation, cron jobs, startup scripts, log tampering
- **Unsafe Functions**: gets(), strcpy(), system(), pickle.loads(), unserialize()

## Quick Start

```bash
pip install -r requirements.txt
python main.py
```

Drag and drop a folder or file, adjust confidence threshold (default: 50%), and scan. Interactive HTML report opens automatically in your browser.

## Supported Languages

Python • JavaScript • TypeScript • PHP • Go • Java • C • C++

## Detection Engines

### ObfuscationDetector
- Base64/hex encoding with eval/exec
- Character code obfuscation (chr(), fromCharCode)
- High entropy strings (>5.0 entropy)
- Unicode tricks (zero-width, homoglyphs)
- String reversals with execution
- PHP variable functions

### NetworkDetector
- Hardcoded IPs (excludes localhost, private ranges, DNS)
- Suspicious TLDs (.tk, .ml, .ga, .cf, .gq, .top, .pw)
- Pastebin services (pastebin.com, hastebin, dpaste)
- Tor hidden services (.onion)
- Reverse/bind shells
- Raw sockets and packet capture
- Data exfiltration patterns
- Port binding on suspicious ports (4444, 31337, etc.)

### FileOperationDetector
- Writes to /etc/, ~/.ssh/, system directories
- Registry manipulation (HKLM, HKCU, Run keys)
- Environment variable tampering
- Log file deletion/truncation
- Persistence mechanisms (crontab, .bashrc, systemd)
- Secret file reads (.env, credentials, SSH keys)

### CryptoDetector
- Weak algorithms (MD5, SHA1, DES, RC4, ECB mode)
- Hardcoded passwords, API keys, tokens
- Private keys in source code
- Custom crypto implementations
- Cryptocurrency mining (XMRig, Coinhive, Stratum, wallet addresses)

### SuspiciousPatternDetector (Language-Aware)
- **Python**: eval(), exec(), __import__(), pickle.loads(), marshal.loads()
- **PHP**: eval(), create_function(), assert(), preg_replace /e, unserialize()
- **JavaScript**: eval(), new Function(), setTimeout with strings
- **SQL Injection**: String concatenation with user input, unsafe queries
- **Command Injection**: shell=True, system() with user input
- **Deserialization**: pickle, YAML, PHP unserialize, Java ObjectInputStream
- **XXE**: XML external entities, disabled security features
- **SSRF**: HTTP requests with user-controlled URLs
- **Path Traversal**: ../ with file operations
- **Anti-Debugging**: ptrace, IsDebuggerPresent, sys.gettrace
- **Process Injection**: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread

### CppDetector (C/C++ Specific)
- **Buffer Overflows**: strcpy(), strcat(), sprintf(), gets(), scanf("%s")
- **Format Strings**: printf(user_input), fprintf(user_input)
- **Memory Issues**: Double free, unchecked malloc/new, sizeof(pointer)
- **Integer Overflows**: malloc(a*b), new Type[a*b]
- **Unsafe Functions**: strtok(), tmpnam(), system(), ctime()
- **Race Conditions**: TOCTOU (access() then open(), stat() then open())

## Report Features

- **Risk Score**: 0-100 calculated from severity × confidence
- **Severity Levels**: CRITICAL (RCE, injection) / HIGH (crypto, memory) / MEDIUM (unsafe functions) / LOW (warnings)
- **Confidence Scoring**: 50-100% based on context and pattern specificity
- **Code Snippets**: 2 lines context before/after
- **Remediation**: Specific recommendations for each finding
- **Interactive UI**: Filter by file, severity, detector; search findings
- **Visual Charts**: Severity distribution, detector breakdown
- **File Tree**: Navigate findings by file with issue counts

## Configuration

- **Minimum Confidence**: 0-100% (default: 50%) - Higher = fewer false positives
- **Include Hidden Files**: Scan dotfiles and hidden directories
- **Follow Symlinks**: Traverse symbolic links (disabled by default)
- **Scan Dependencies**: Check node_modules, vendor, venv (disabled by default)
- **Target Languages**: Select specific languages to scan

## Test Results

Tested on complex malicious and legitimate samples:

**Detection Rate**: 43/43 malicious patterns detected (100%)  
**False Positive Rate**: 3/43 legitimate patterns flagged (7%)  
**Precision**: 93.5%

Detects:
- ✅ Obfuscated backdoors (base64, hex, ROT13)
- ✅ SQL/Command injection with user input
- ✅ Hardcoded credentials and API keys
- ✅ C2 communication (IPs, domains, ports)
- ✅ Memory corruption (buffer overflows, double free)
- ✅ Unsafe deserialization (pickle, YAML, PHP)
- ✅ Format string vulnerabilities
- ✅ Race conditions (TOCTOU)

## Requirements

```
Python 3.8+
PyQt6 >= 6.6.0
tree-sitter >= 0.21.1
tree-sitter-python >= 0.21.0
tree-sitter-javascript >= 0.21.0
tree-sitter-php >= 0.22.0
tree-sitter-go >= 0.21.0
tree-sitter-java >= 0.21.0
tree-sitter-c >= 0.21.0
tree-sitter-cpp >= 0.22.0
Jinja2 >= 3.1.0
```

## False Positives

The tool uses language-aware detection to minimize false positives:
- PHP patterns only trigger on .php files
- Python patterns only trigger on .py files
- C++ function names don't trigger PHP detections
- Comments and documentation are filtered out
- Legitimate use cases (MD5 for checksums, localhost IPs) are excluded

Low confidence findings (<70%) should be reviewed carefully.

## Architecture

```
isitbackdoored/
├── main.py                 # Entry point
├── src/
│   ├── gui/               # PyQt6 interface
│   ├── scanner/           # Core scanning engine
│   │   ├── detectors/    # 6 specialized detectors
│   │   └── parsers/      # tree-sitter integration
│   ├── reporter/          # HTML report generation
│   └── models/            # Data structures
└── tests/                 # Test suite with samples
```

## Contributing

Found a bypass or false positive? Open an issue with:
- Sample code that should/shouldn't trigger
- Expected vs actual behavior
- Language and file type
- Confidence level and severity

Pull requests welcome for:
- New detection patterns
- Language support
- False positive fixes
- Performance improvements

## License

MIT - See LICENSE file

## Disclaimer

This tool performs static analysis only. It cannot detect:
- Runtime behavior or dynamic code loading
- Polymorphic or metamorphic malware
- Zero-day exploits
- Encrypted or packed payloads
- Time-based or conditional backdoors

Use as part of a defense-in-depth strategy, not as sole security measure. Always review findings in context before taking action.
