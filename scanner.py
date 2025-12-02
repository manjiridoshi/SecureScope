#!/usr/bin/env python3
"""
SecureScope - Comprehensive Web Security Scanner
Author: Manjiri Doshi
"""

import socket
import ssl
import requests
import json
import sys
from datetime import datetime
from urllib.parse import urlparse
import concurrent.futures
import dns.resolver

class SecureScope:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.netloc or self.parsed_url.path
        self.results = {
            'target': self.target_url,
            'scan_time': datetime.now().isoformat(),
            'ssl_analysis': {},
            'security_headers': {},
            'port_scan': {},
            'dns_security': {},
            'vulnerabilities': []
        }

    def analyze_ssl(self):
        """Analyze SSL/TLS certificate and configuration"""
        print(f"[*] Analyzing SSL/TLS for {self.hostname}...")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    self.results['ssl_analysis'] = {
                        'status': 'SECURE',
                        'protocol': version,
                        'cipher': cipher[0] if cipher else 'Unknown',
                        'cipher_strength': cipher[2] if cipher else 0,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'valid_from': cert['notBefore'],
                        'valid_until': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
                    print(f"[✓] SSL/TLS: {version} with {cipher[0] if cipher else 'Unknown'}")
        except Exception as e:
            self.results['ssl_analysis'] = {'status': 'FAILED', 'error': str(e)}
            print(f"[✗] SSL/TLS Analysis Failed: {e}")

    def check_security_headers(self):
        """Check HTTP security headers"""
        print(f"[*] Checking security headers...")
        try:
            response = requests.get(self.target_url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'MISSING'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'MISSING'),
                'X-Frame-Options': headers.get('X-Frame-Options', 'MISSING'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'MISSING'),
                'X-XSS-Protection': headers.get('X-XSS-Protection', 'MISSING'),
                'Referrer-Policy': headers.get('Referrer-Policy', 'MISSING'),
                'Permissions-Policy': headers.get('Permissions-Policy', 'MISSING')
            }
            
            score = sum(1 for v in security_headers.values() if v != 'MISSING')
            self.results['security_headers'] = {
                'headers': security_headers,
                'score': f"{score}/7",
                'grade': self._calculate_grade(score, 7)
            }
            
            print(f"[✓] Security Headers Score: {score}/7")
            
            # Check for vulnerabilities
            if security_headers['X-Frame-Options'] == 'MISSING':
                self.results['vulnerabilities'].append({
                    'type': 'Clickjacking',
                    'severity': 'MEDIUM',
                    'description': 'Missing X-Frame-Options header - vulnerable to clickjacking attacks'
                })
            
            if security_headers['Content-Security-Policy'] == 'MISSING':
                self.results['vulnerabilities'].append({
                    'type': 'XSS',
                    'severity': 'HIGH',
                    'description': 'Missing Content-Security-Policy - increased XSS risk'
                })
                
        except Exception as e:
            self.results['security_headers'] = {'error': str(e)}
            print(f"[✗] Security Headers Check Failed: {e}")

    def scan_ports(self, ports=[80, 443, 21, 22, 25, 3306, 5432, 8080, 8443]):
        """Scan common ports"""
        print(f"[*] Scanning ports on {self.hostname}...")
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.hostname, port))
                sock.close()
                if result == 0:
                    service = self._get_service_name(port)
                    return {'port': port, 'status': 'OPEN', 'service': service}
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(check_port, ports)
            open_ports = [r for r in results if r is not None]
        
        self.results['port_scan'] = {
            'total_scanned': len(ports),
            'open_ports': open_ports,
            'open_count': len(open_ports)
        }
        
        print(f"[✓] Found {len(open_ports)} open ports")
        
        # Check for risky open ports
        risky_ports = [21, 23, 3306, 5432]
        for port_info in open_ports:
            if port_info['port'] in risky_ports:
                self.results['vulnerabilities'].append({
                    'type': 'Exposed Service',
                    'severity': 'HIGH',
                    'description': f"Port {port_info['port']} ({port_info['service']}) is publicly accessible"
                })

    def check_dns_security(self):
        """Check DNS security records"""
        print(f"[*] Checking DNS security...")
        try:
            dns_results = {}
            
            # Check SPF
            try:
                spf = dns.resolver.resolve(self.hostname, 'TXT')
                spf_records = [str(r) for r in spf if 'spf' in str(r).lower()]
                dns_results['SPF'] = 'CONFIGURED' if spf_records else 'MISSING'
            except:
                dns_results['SPF'] = 'MISSING'
            
            # Check DMARC
            try:
                dmarc = dns.resolver.resolve(f'_dmarc.{self.hostname}', 'TXT')
                dns_results['DMARC'] = 'CONFIGURED' if dmarc else 'MISSING'
            except:
                dns_results['DMARC'] = 'MISSING'
            
            # Check DNSSEC
            try:
                dnskey = dns.resolver.resolve(self.hostname, 'DNSKEY')
                dns_results['DNSSEC'] = 'ENABLED' if dnskey else 'DISABLED'
            except:
                dns_results['DNSSEC'] = 'DISABLED'
            
            self.results['dns_security'] = dns_results
            print(f"[✓] DNS Security Check Complete")
            
        except Exception as e:
            self.results['dns_security'] = {'error': str(e)}
            print(f"[✗] DNS Security Check Failed: {e}")

    def _get_service_name(self, port):
        """Get common service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 
            5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')

    def _calculate_grade(self, score, total):
        """Calculate letter grade"""
        percentage = (score / total) * 100
        if percentage >= 90: return 'A'
        elif percentage >= 80: return 'B'
        elif percentage >= 70: return 'C'
        elif percentage >= 60: return 'D'
        else: return 'F'

    def run_full_scan(self):
        """Execute complete security scan"""
        print(f"\n{'='*60}")
        print(f"SecureScope - Security Scanner")
        print(f"Target: {self.target_url}")
        print(f"{'='*60}\n")
        
        self.analyze_ssl()
        self.check_security_headers()
        self.scan_ports()
        self.check_dns_security()
        
        print(f"\n{'='*60}")
        print(f"Scan Complete!")
        print(f"{'='*60}\n")
        
        return self.results

    def generate_report(self, output_file='report.json'):
        """Generate JSON report"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[✓] Report saved to {output_file}")

    def print_summary(self):
        """Print scan summary"""
        print("\n" + "="*60)
        print("SECURITY SCAN SUMMARY")
        print("="*60)
        
        # SSL Status
        ssl_status = self.results['ssl_analysis'].get('status', 'UNKNOWN')
        print(f"\n[SSL/TLS] Status: {ssl_status}")
        if ssl_status == 'SECURE':
            print(f"  Protocol: {self.results['ssl_analysis'].get('protocol', 'N/A')}")
            print(f"  Cipher: {self.results['ssl_analysis'].get('cipher', 'N/A')}")
        
        # Security Headers
        if 'score' in self.results['security_headers']:
            print(f"\n[Security Headers] Score: {self.results['security_headers']['score']}")
            print(f"  Grade: {self.results['security_headers']['grade']}")
        
        # Open Ports
        open_count = self.results['port_scan'].get('open_count', 0)
        print(f"\n[Port Scan] Open Ports: {open_count}")
        for port_info in self.results['port_scan'].get('open_ports', []):
            print(f"  - Port {port_info['port']}: {port_info['service']}")
        
        # Vulnerabilities
        vuln_count = len(self.results['vulnerabilities'])
        print(f"\n[Vulnerabilities] Found: {vuln_count}")
        for vuln in self.results['vulnerabilities']:
            print(f"  - [{vuln['severity']}] {vuln['type']}: {vuln['description']}")
        
        print("\n" + "="*60 + "\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <target_url>")
        print("Example: python scanner.py https://example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    scanner = SecureScope(target)
    scanner.run_full_scan()
    scanner.print_summary()
    scanner.generate_report()


if __name__ == "__main__":
    main()
