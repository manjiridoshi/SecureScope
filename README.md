# 🔒 SecureScope

**Comprehensive Web Security Scanner & Vulnerability Assessment Tool**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-scanner-red.svg)](https://github.com/manjiridoshi/SecureScope)

SecureScope is a powerful, industry-grade security scanning tool designed to identify vulnerabilities and assess the security posture of web applications. Built with Python, it provides comprehensive analysis including SSL/TLS configuration, security headers, port scanning, and DNS security checks.

## 🎯 Features

### Core Security Checks
- **🔐 SSL/TLS Analysis** - Certificate validation, cipher strength, protocol version
- **🛡️ Security Headers** - HSTS, CSP, X-Frame-Options, and more
- **🔍 Port Scanning** - Identify open ports and running services
- **🌐 DNS Security** - SPF, DMARC, DNSSEC validation
- **⚠️ Vulnerability Detection** - Automatic identification of common security issues
- **📊 Detailed Reporting** - JSON output with comprehensive scan results

### Key Capabilities
✅ Multi-threaded port scanning for speed  
✅ Real-time vulnerability assessment  
✅ Security grade calculation  
✅ Professional JSON reports  
✅ Easy-to-use CLI interface  
✅ Extensible architecture  

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/manjiridoshi/SecureScope.git
cd SecureScope

# Install dependencies
pip install -r requirements.txt
```

### Usage

```bash
# Basic scan
python scanner.py https://example.com

# Scan with automatic protocol detection
python scanner.py example.com
```

### Example Output

```
============================================================
SecureScope - Security Scanner
Target: https://example.com
============================================================

[*] Analyzing SSL/TLS for example.com...
[✓] SSL/TLS: TLSv1.3 with TLS_AES_256_GCM_SHA384

[*] Checking security headers...
[✓] Security Headers Score: 5/7

[*] Scanning ports on example.com...
[✓] Found 2 open ports

[*] Checking DNS security...
[✓] DNS Security Check Complete

============================================================
Scan Complete!
============================================================

SECURITY SCAN SUMMARY
============================================================

[SSL/TLS] Status: SECURE
  Protocol: TLSv1.3
  Cipher: TLS_AES_256_GCM_SHA384

[Security Headers] Score: 5/7
  Grade: B

[Port Scan] Open Ports: 2
  - Port 80: HTTP
  - Port 443: HTTPS

[Vulnerabilities] Found: 1
  - [MEDIUM] Clickjacking: Missing X-Frame-Options header

[✓] Report saved to report.json
```

## 📋 Security Checks Explained

### SSL/TLS Analysis
- Certificate validity and expiration
- Protocol version (TLS 1.2, 1.3)
- Cipher suite strength
- Certificate issuer and subject
- Subject Alternative Names (SAN)

### Security Headers
- **Strict-Transport-Security** - Enforces HTTPS
- **Content-Security-Policy** - Prevents XSS attacks
- **X-Frame-Options** - Prevents clickjacking
- **X-Content-Type-Options** - Prevents MIME sniffing
- **X-XSS-Protection** - Browser XSS filter
- **Referrer-Policy** - Controls referrer information
- **Permissions-Policy** - Feature policy control

### Port Scanning
Scans common ports including:
- 80 (HTTP), 443 (HTTPS)
- 21 (FTP), 22 (SSH)
- 25 (SMTP)
- 3306 (MySQL), 5432 (PostgreSQL)
- 8080, 8443 (Alternative HTTP/HTTPS)

### DNS Security
- **SPF** - Email sender authentication
- **DMARC** - Email authentication policy
- **DNSSEC** - DNS response validation

## 🎓 Use Cases

### For Security Professionals
- Quick security audits
- Vulnerability assessments
- Compliance checking
- Penetration testing reconnaissance

### For Developers
- Pre-deployment security checks
- CI/CD integration
- Security header validation
- SSL/TLS configuration testing

### For DevOps
- Infrastructure security monitoring
- Automated security scanning
- Configuration validation
- Security posture tracking

## 📊 Report Format

SecureScope generates detailed JSON reports containing:

```json
{
  "target": "https://example.com",
  "scan_time": "2025-12-02T15:24:53",
  "ssl_analysis": { ... },
  "security_headers": { ... },
  "port_scan": { ... },
  "dns_security": { ... },
  "vulnerabilities": [ ... ]
}
```

## 🛠️ Technical Details

### Architecture
- **Language**: Python 3.8+
- **Concurrency**: ThreadPoolExecutor for parallel port scanning
- **Libraries**: requests, dnspython, ssl, socket
- **Output**: JSON format for easy integration

### Performance
- Multi-threaded port scanning
- Configurable timeouts
- Efficient SSL/TLS handshake
- Minimal resource usage

## 🔧 Advanced Usage

### Custom Port Scanning
Modify the `scan_ports()` method to scan custom ports:

```python
scanner.scan_ports(ports=[80, 443, 8080, 8443, 3000])
```

### Integration
Use SecureScope as a library:

```python
from scanner import SecureScope

scanner = SecureScope('https://example.com')
results = scanner.run_full_scan()
scanner.generate_report('custom_report.json')
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**Important**: This tool is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning any systems you don't own. Unauthorized scanning may be illegal in your jurisdiction.

## 👤 Author

**Manjiri Doshi**

- GitHub: [@manjiridoshi](https://github.com/manjiridoshi)
- Project: [SecureScope](https://github.com/manjiridoshi/SecureScope)

## 🌟 Acknowledgments

- Built with industry-standard security practices
- Inspired by professional penetration testing tools
- Designed for real-world security assessments

---

**⭐ Star this repository if you find it useful!**

Made with ❤️ for the cybersecurity community
