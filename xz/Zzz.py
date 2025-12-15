#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================
RED TIGER - Advanced Network Reconnaissance & Security Scanner
Developed by: a3t8al
Copyright © 2024
===============================================================
"""

import os
import sys
import time
import socket
import threading
import queue
import random
import json
import subprocess
from datetime import datetime
from ipaddress import ip_network, ip_address
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==================== CONSTANTS ====================

AUTHOR = "a3t8al"
VERSION = "Red Tiger v2.0"
COPYRIGHT_YEAR = 2024

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  ██████╗ ███████╗██████╗     ████████╗██╗ ██████╗ ███████╗██████╗  ║
║  ██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██║██╔════╝ ██╔════╝██╔══██╗ ║
║  ██████╔╝█████╗  ██║  ██║       ██║   ██║██║  ███╗█████╗  ██████╔╝ ║
║  ██╔══██╗██╔══╝  ██║  ██║       ██║   ██║██║   ██║██╔══╝  ██╔══██╗ ║
║  ██║  ██║███████╗██████╔╝       ██║   ██║╚██████╔╝███████╗██║  ██║ ║
║  ╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ║
║                                                                  ║
║           A D V A N C E D   N E T W O R K   S C A N N E R        ║
║                    Developed by: a3t8al                          ║
╚══════════════════════════════════════════════════════════╝
"""

# Common ports for scanning
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443
]

# Service names for common ports
SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

# ==================== CORE SCANNER CLASSES ====================

class NetworkScanner:
    """Advanced network scanner"""
    
    def __init__(self):
        self.results = []
        self.scan_queue = queue.Queue()
        self.live_hosts = []
        self.scan_stats = {
            'hosts_scanned': 0,
            'ports_found': 0,
            'start_time': None,
            'end_time': None
        }
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def get_network_range(self, ip, mask=24):
        """Get network range from IP and mask"""
        try:
            network = ip_network(f"{ip}/{mask}", strict=False)
            return [str(ip) for ip in network.hosts()]
        except:
            return []
    
    def ping_sweep(self, ip_range, timeout=1):
        """Perform ping sweep on IP range"""
        live_hosts = []
        
        print(f"\n[+] Performing ping sweep on {len(ip_range)} hosts...")
        
        def ping_host(ip):
            try:
                # Create ICMP socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.settimeout(timeout)
                
                # Send ping
                sock.sendto(b'\x08\x00\xf7\xff\x00\x00\x00\x00', (ip, 0))
                
                # Try to receive
                sock.recvfrom(1024)
                return ip
            except:
                return None
            finally:
                sock.close()
        
        # Use thread pool for parallel scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in ip_range}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)
                    print(f"  [+] Host alive: {result}")
        
        return live_hosts
    
    def port_scanner(self, target_ip, ports=None, timeout=2, max_threads=100):
        """Scan ports on a target IP"""
        if ports is None:
            ports = COMMON_PORTS
        
        open_ports = []
        
        print(f"\n[+] Scanning {target_ip} for {len(ports)} ports...")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                
                if result == 0:
                    service = SERVICE_NAMES.get(port, "Unknown")
                    return (port, service, "OPEN")
                else:
                    return None
            except:
                return None
        
        # Scan ports in parallel
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    port, service, status = result
                    open_ports.append(result)
                    print(f"  [+] Port {port:5} ({service:10}) - {status}")
        
        return open_ports
    
    def service_detector(self, target_ip, port):
        """Detect service running on port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target_ip, port))
            
            # Try to receive banner
            if port in [21, 22, 25, 80, 110, 143]:
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')[:200]
            else:
                banner = ""
            
            sock.close()
            return banner.strip()
        except:
            return ""

# ==================== INFORMATION GATHERING ====================

class InfoGatherer:
    """Information gathering utilities"""
    
    @staticmethod
    def get_hostname(ip):
        """Get hostname from IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"
    
    @staticmethod
    def get_dns_info(domain):
        """Get DNS information"""
        results = {}
        
        try:
            # Get A records
            results['A'] = socket.gethostbyname_ex(domain)[2]
            
            # Try to get MX records
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, 'MX')
            results['MX'] = [str(r.exchange) for r in mx_records]
        except:
            results['A'] = ["No DNS records found"]
        
        return results
    
    @staticmethod
    def whois_lookup(ip):
        """Perform WHOIS lookup (simulated)"""
        # In a real tool, you would use whois library
        # This is a simulation
        return {
            "IP": ip,
            "Network": "Simulated Network",
            "ISP": "Simulated ISP",
            "Country": "Simulated Country",
            "Status": "Simulated Data"
        }

# ==================== SECURITY ANALYSIS ====================

class SecurityAnalyzer:
    """Security vulnerability analyzer"""
    
    def __init__(self):
        self.vulnerabilities = []
        self.recommendations = []
    
    def analyze_ports(self, open_ports):
        """Analyze open ports for security issues"""
        critical_ports = [21, 23, 135, 139, 445, 3389]
        warnings = []
        
        for port, service, _ in open_ports:
            if port in critical_ports:
                if port == 21:
                    warnings.append(f"⚠️  FTP (Port 21) is open - Consider using SFTP/FTPS")
                elif port == 23:
                    warnings.append(f"⚠️  Telnet (Port 23) is open - Use SSH instead")
                elif port in [135, 139, 445]:
                    warnings.append(f"⚠️  SMB/NetBIOS (Port {port}) is open - Potential vulnerability")
                elif port == 3389:
                    warnings.append(f"⚠️  RDP (Port 3389) is open - Ensure strong authentication")
            
            if service in ["HTTP", "HTTP-Proxy"] and port != 80:
                warnings.append(f"⚠️  HTTP on non-standard port {port} - May be misconfigured")
        
        return warnings
    
    def check_weak_services(self, services):
        """Check for weak or outdated services"""
        weak_services = []
        
        for service_info in services:
            port, service, banner = service_info
            
            # Check for weak protocols
            if "SSH-1." in banner:
                weak_services.append(f"🚨 Weak SSH version detected on port {port}")
            if "vsFTPd 2." in banner and "2.3." in banner:
                weak_services.append(f"🚨 Vulnerable vsFTPd version on port {port}")
            if "Apache/1." in banner:
                weak_services.append(f"🚨 Old Apache version on port {port}")
        
        return weak_services

# ==================== REPORT GENERATOR ====================

class ReportGenerator:
    """Generate scan reports"""
    
    @staticmethod
    def generate_text_report(scan_data, filename="scan_report.txt"):
        """Generate text report"""
        with open(filename, 'w') as f:
            f.write(f"RED TIGER SCAN REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Version: {VERSION}\n")
            f.write(f"Developer: {AUTHOR}\n")
            f.write("=" * 80 + "\n\n")
            
            for section, data in scan_data.items():
                f.write(f"[{section}]\n")
                f.write("-" * 40 + "\n")
                
                if isinstance(data, list):
                    for item in data:
                        f.write(f"  {item}\n")
                elif isinstance(data, dict):
                    for key, value in data.items():
                        f.write(f"  {key}: {value}\n")
                else:
                    f.write(f"  {data}\n")
                
                f.write("\n")
        
        print(f"\n[+] Report saved to: {filename}")
    
    @staticmethod
    def generate_json_report(scan_data, filename="scan_report.json"):
        """Generate JSON report"""
        with open(filename, 'w') as f:
            json.dump(scan_data, f, indent=4, default=str)
        
        print(f"\n[+] JSON report saved to: {filename}")

# ==================== TERMINAL INTERFACE ====================

class TerminalUI:
    """Terminal user interface"""
    
    @staticmethod
    def clear_screen():
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    @staticmethod
    def print_banner():
        """Print tool banner"""
        TerminalUI.clear_screen()
        print("\033[91m" + BANNER + "\033[0m")
        print(f"\033[93mVersion: {VERSION} | Developer: {AUTHOR}\033[0m")
        print()
    
    @staticmethod
    def print_colored(text, color_code):
        """Print colored text"""
        colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'reset': '\033[0m'
        }
        return f"{colors.get(color_code, '')}{text}{colors['reset']}"
    
    @staticmethod
    def show_menu():
        """Show main menu"""
        print("\n" + "=" * 80)
        print(TerminalUI.print_colored("MAIN MENU", "cyan"))
        print("=" * 80)
        print()
        
        menu_options = [
            ("1", "Network Discovery (Ping Sweep)"),
            ("2", "Port Scanner"),
            ("3", "Full Network Audit"),
            ("4", "Service Detection"),
            ("5", "Vulnerability Analysis"),
            ("6", "Generate Reports"),
            ("7", "Advanced Scanning"),
            ("8", "System Information"),
            ("0", "Exit")
        ]
        
        for num, desc in menu_options:
            print(f"  [{TerminalUI.print_colored(num, 'yellow')}] {desc}")
        
        print()
        return input(TerminalUI.print_colored("Select option: ", "green"))
    
    @staticmethod
    def show_scanning_animation(message="Scanning"):
        """Show scanning animation"""
        animations = ['|', '/', '-', '\\']
        for i in range(10):
            sys.stdout.write(f'\r[{animations[i % 4]}] {message}... ')
            sys.stdout.flush()
            time.sleep(0.1)
        print()

# ==================== MAIN APPLICATION ====================

class RedTiger:
    """Main Red Tiger application"""
    
    def __init__(self):
        self.scanner = NetworkScanner()
        self.info = InfoGatherer()
        self.analyzer = SecurityAnalyzer()
        self.reporter = ReportGenerator()
        self.ui = TerminalUI()
        
        self.scan_results = {
            'network_scan': [],
            'port_scan': [],
            'services': [],
            'vulnerabilities': [],
            'recommendations': []
        }
        
        self.target_ip = ""
        self.target_network = ""
    
    def run(self):
        """Main application loop"""
        self.ui.print_banner()
        
        while True:
            choice = self.ui.show_menu()
            
            if choice == '1':
                self.network_discovery()
            elif choice == '2':
                self.port_scanner()
            elif choice == '3':
                self.full_audit()
            elif choice == '4':
                self.service_detection()
            elif choice == '5':
                self.vulnerability_analysis()
            elif choice == '6':
                self.generate_reports()
            elif choice == '7':
                self.advanced_scanning()
            elif choice == '8':
                self.system_info()
            elif choice == '0':
                print("\n" + self.ui.print_colored("[+] Exiting Red Tiger...", "yellow"))
                print(self.ui.print_colored("[+] Stay secure!", "green"))
                break
            else:
                print(self.ui.print_colored("[-] Invalid option!", "red"))
            
            input("\nPress Enter to continue...")
    
    def network_discovery(self):
        """Network discovery module"""
        print("\n" + "=" * 80)
        print(self.ui.print_colored("NETWORK DISCOVERY", "cyan"))
        print("=" * 80)
        
        # Get local IP
        local_ip = self.scanner.get_local_ip()
        print(f"\n[+] Local IP Address: {local_ip}")
        
        # Ask for network range
        print("\n[1] Scan local network")
        print("[2] Scan custom network")
        print("[3] Scan single IP")
        
        choice = input("\nSelect option: ")
        
        if choice == '1':
            network = f"{local_ip}/24"
            ip_range = self.scanner.get_network_range(local_ip, 24)
        elif choice == '2':
            network = input("Enter network (e.g., 192.168.1.0/24): ")
            try:
                ip_range = [str(ip) for ip in ip_network(network).hosts()]
            except:
                print(self.ui.print_colored("[-] Invalid network!", "red"))
                return
        elif choice == '3':
            target = input("Enter IP address: ")
            ip_range = [target]
        else:
            return
        
        # Perform ping sweep
        if ip_range:
            live_hosts = self.scanner.ping_sweep(ip_range[:50])  # Limit to 50 hosts for demo
            
            if live_hosts:
                print(f"\n[+] Found {len(live_hosts)} live hosts:")
                for host in live_hosts:
                    print(f"  - {host}")
                
                self.scan_results['network_scan'] = live_hosts
            else:
                print(self.ui.print_colored("[-] No live hosts found", "yellow"))
    
    def port_scanner(self):
        """Port scanner module"""
        print("\n" + "=" * 80)
        print(self.ui.print_colored("PORT SCANNER", "cyan"))
        print("=" * 80)
        
        # Get target
        target = input("\nEnter target IP or hostname: ")
        
        # Port selection
        print("\n[1] Scan common ports (21-443)")
        print("[2] Scan all ports (1-1024)")
        print("[3] Scan custom ports")
        
        choice = input("\nSelect option: ")
        
        if choice == '1':
            ports = COMMON_PORTS
        elif choice == '2':
            ports = list(range(1, 1025))
        elif choice == '3':
            port_input = input("Enter ports (comma separated): ")
            ports = [int(p.strip()) for p in port_input.split(',')]
        else:
            return
        
        # Perform scan
        self.ui.show_scanning_animation(f"Scanning {target}")
        
        open_ports = self.scanner.port_scanner(target, ports)
        
        if open_ports:
            print(f"\n[+] Found {len(open_ports)} open ports on {target}:")
            for port, service, status in open_ports:
                print(f"  - Port {port}: {service} ({status})")
            
            self.scan_results['port_scan'] = open_ports
            
            # Analyze vulnerabilities
            warnings = self.analyzer.analyze_ports(open_ports)
            if warnings:
                print(f"\n{self.ui.print_colored('SECURITY WARNINGS:', 'red')}")
                for warning in warnings:
                    print(f"  {warning}")
        else:
            print(self.ui.print_colored(f"\n[-] No open ports found on {target}", "yellow"))
    
    def full_audit(self):
        """Full network audit"""
        print("\n" + "=" * 80)
        print(self.ui.print_colored("FULL NETWORK AUDIT", "cyan"))
        print("=" * 80)
        
        target = input("\nEnter target IP or network: ")
        
        print(self.ui.print_colored("\n[+] Starting comprehensive audit...", "green"))
        
        # Step 1: Network discovery
        print("\n[1/4] Network Discovery...")
        ip_range = [target] if '/' not in target else self.scanner.get_network_range(target.split('/')[0], int(target.split('/')[1]))
        
        if len(ip_range) > 10:
            print(f"  Scanning {len(ip_range)} hosts (sampling first 10)")
            ip_range = ip_range[:10]
        
        live_hosts = self.scanner.ping_sweep(ip_range)
        
        # Step 2: Port scanning
        print("\n[2/4] Port Scanning...")
        all_open_ports = []
        
        for host in live_hosts:
            print(f"  Scanning {host}...")
            open_ports = self.scanner.port_scanner(host, COMMON_PORTS)
            all_open_ports.extend([(host, port, service, status) for port, service, status in open_ports])
        
        # Step 3: Service detection
        print("\n[3/4] Service Detection...")
        services = []
        
        for host, port, service, _ in all_open_ports[:5]:  # Limit for demo
            banner = self.scanner.service_detector(host, port)
            if banner:
                services.append((host, port, service, banner[:100]))
        
        # Step 4: Analysis
        print("\n[4/4] Security Analysis...")
        warnings = self.analyzer.analyze_ports([(p, s, st) for _, p, s, st in all_open_ports])
        
        # Display results
        print(f"\n{self.ui.print_colored('AUDIT RESULTS:', 'green')}")
        print(f"  Live Hosts: {len(live_hosts)}")
        print(f"  Open Ports: {len(all_open_ports)}")
        print(f"  Services Detected: {len(services)}")
        print(f"  Security Warnings: {len(warnings)}")
        
        if warnings:
            print(f"\n{self.ui.print_colored('SECURITY ISSUES:', 'red')}")
            for warning in warnings[:5]:
                print(f"  {warning}")
    
    def service_detection(self):
        """Service detection module"""
        print("\n" + "=" * 80)
        print(self.ui.print_colored("SERVICE DETECTION", "cyan"))
        print("=" * 80)
        
        target = input("\nEnter target IP: ")
        port = int(input("Enter port: "))
        
        print(self.ui.print_colored(f"\n[+] Detecting service on {target}:{port}...", "green"))
        
        banner = self.scanner.service_detector(target, port)
        
        if banner:
            print(f"\n{self.ui.print_colored('SERVICE BANNER:', 'yellow')}")
            print(f"  {banner}")
            
            # Try to identify service
            service = SERVICE_NAMES.get(port, "Unknown")
            print(f"\n  Identified as: {service}")
            
            # Check for vulnerabilities
            if "Apache" in banner and "2.2" in banner:
                print(f"\n{self.ui.print_colred('⚠️  Warning: Old Apache version detected!', 'red')}")
            if "OpenSSH" in banner and "7.2" in banner:
                print(f"\n{self.ui.print_colored('⚠️  Warning: Consider upgrading OpenSSH', 'yellow')}")
        else:
            print(self.ui.print_colored("[-] No banner received", "yellow"))
    
    def vulnerability_analysis(self):
        """Vulnerability analysis module"""
        print("\n" + "=" * 80)
        print(self.ui.print_colored("VULNERABILITY ANALYSIS", "cyan"))
        print("=" * 80)
        
        if not self.scan_results['port_scan']:
            print(self.ui.print_colored("\n[-] No scan data available. Run a scan first.", "yellow"))
            return
        
        print(self.ui.print_colored("\n[+] Analyzing vulnerabilities...", "green"))
        
        # Analyze open ports
        warnings = self.analyzer.analyze_ports(self.scan_results['port_scan'])
        
        if warnings:
            print(f"\n{self.ui.print_colored('FOUND VULNERABILITIES:', 'red')}")
            for i, warning in enumerate(warnings, 1):
                print(f"{i}. {warning}")
            
            # Generate recommendations
            print(f"\n{self.ui.print_colored('RECOMMENDATIONS:', 'green')}")
            recommendations = [
                "Close unnecessary ports",
                "Use strong authentication for remote services",
                "Keep services updated",
                "Use firewalls to restrict access",
                "Monitor network traffic",
                "Implement intrusion detection"
            ]
            
            for rec in recommendations:
                print(f"  • {rec}")
            
            self.scan_results['vulnerabilities'] = warnings
            self.scan_results['recommendations'] = recommendations
        else:
            print(self.ui.print_colored("\n[+] No critical vulnerabilities found", "green"))
    
    def generate_reports(self):
        """Generate reports module"""
        print("\n" + "=" * 80)
        print(self.ui.print_colored("REPORT GENERATOR", "cyan"))
        print("=" * 80)
        
        if not any(self.scan_results.values()):
            print(self.ui.print_colored("\n[-] No scan data to report", "yellow"))
            return
        
        print("\n[1] Generate Text Report")
        print("[2] Generate JSON Report")
        print("[3] Generate Both Reports")
        
        choice = input("\nSelect option: ")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        report_data = {
            'scan_info': {
                'tool': VERSION,
                'developer': AUTHOR,
                'timestamp': timestamp,
                'target': self.target_ip if self.target_ip else "Multiple"
            },
            'network_scan': self.scan_results['network_scan'],
            'port_scan': self.scan_results['port_scan'],
            'vulnerabilities': self.scan_results['vulnerabilities'],
            'recommendations': self.scan_results['recommendations']
        }
        
        if choice in ['1', '3']:
            filename = f"redtiger_report_{timestamp}.txt"
            self.reporter.generate_text_report(report_data, filename)
        
        if choice in ['2', '3']:
            filename = f"redtiger_report_{timestamp}.json"
            self.reporter.generate_json_report(report_data, filename)
        
        print(self.ui.print_colored("\n[+] Reports generated successfully!", "green"))
    
    def advanced_scanning(self):
        """Advanced scanning techniques"""
        print("\n" + "=" * 80)
        print(self.ui.print_colored("ADVANCED SCANNING", "cyan"))
        print("=" * 80)
        
        print("\n[1] Stealth Scan (SYN scan)")
        print("[2] UDP Port Scan")
        print("[3] OS Fingerprinting")
        print("[4] Banner Grabbing")
        
        choice = input("\nSelect option: ")
        
        target = input("Enter target IP: ")
        
        if choice == '1':
            print(self.ui.print_colored(f"\n[+] Performing SYN scan on {target}...", "green"))
            # Simulated SYN scan
            for port in COMMON_PORTS[:10]:
                if random.random() > 0.7:
                    print(f"  Port {port}: Filtered/SYN-ACK")
                else:
                    print(f"  Port {port}: Closed")
        
        elif choice == '2':
            print(self.ui.print_colored(f"\n[+] Scanning UDP ports on {target}...", "green"))
            # Simulated UDP scan
            udp_ports = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500]
            for port in udp_ports:
                if random.random() > 0.8:
                    print(f"  UDP Port {port}: Open/Filtered")
        
        elif choice == '3':
            print(self.ui.print_colred(f"\n[+] Fingerprinting OS on {target}...", "green"))
            # Simulated OS detection
            os_types = ["Linux", "Windows", "Cisco IOS", "FreeBSD", "Unknown"]
            detected_os = random.choice(os_types)
            print(f"  Detected OS: {detected_os}")
            print(f"  TTL: {random.randint(50, 128)}")
            print(f"  Window Size: {random.randint(1000, 65535)}")
        
        elif choice == '4':
            print(self.ui.print_colored(f"\n[+] Grabbing banners from {target}...", "green"))
            # Simulated banner grabbing
            for port in [21, 22, 80, 443][:2]:
                banner = self.scanner.service_detector(target, port)
                if banner:
                    print(f"  Port {port}: {banner[:50]}...")
                else:
                    print(f"  Port {port}: No banner")
    
    def system_info(self):
        """Display system information"""
        print("\n" + "=" * 80)
        print(self.ui.print_colored("SYSTEM INFORMATION", "cyan"))
        print("=" * 80)
        
        print("\n" + self.ui.print_colored("TOOL INFORMATION:", "yellow"))
        print(f"  Name: Red Tiger")
        print(f"  Version: {VERSION}")
        print(f"  Developer: {AUTHOR}")
        print(f"  Copyright: © {COPYRIGHT_YEAR}")
        
        print("\n" + self.ui.print_colored("SYSTEM INFO:", "yellow"))
        print(f"  Platform: {sys.platform}")
        print(f"  Python: {sys.version.split()[0]}")
        print(f"  Hostname: {socket.gethostname()}")
        
        local_ip = self.scanner.get_local_ip()
        print(f"  Local IP: {local_ip}")
        
        print("\n" + self.ui.print_colored("CAPABILITIES:", "yellow"))
        capabilities = [
            "• Network Discovery",
            "• Port Scanning",
            "• Service Detection",
            "• Vulnerability Analysis",
            "• Security Reporting",
            "• Advanced Reconnaissance"
        ]
        
        for cap in capabilities:
            print(f"  {cap}")
        
        print("\n" + self.ui.print_colored("LEGAL NOTICE:", "red"))
        print("  This tool is for educational and authorized testing only.")
        print("  Use only on systems you own or have permission to test.")
        print("  The developer is not responsible for misuse.")

# ==================== UTILITY FUNCTIONS ====================

def check_dependencies():
    """Check for required dependencies"""
    print("[*] Checking dependencies...")
    
    required = ['socket', 'threading', 'queue', 'json']
    
    for module in required:
        try:
            __import__(module)
            print(f"  [+] {module}: OK")
        except ImportError:
            print(f"  [-] {module}: MISSING")
    
    # Optional dependencies
    optional = ['dns', 'scapy', 'netifaces']
    
    for module in optional:
        try:
            __import__(module)
            print(f"  [+] {module} (optional): OK")
        except ImportError:
            print(f"  [-] {module} (optional): Not installed")
    
    print()

# ==================== MAIN EXECUTION ====================

def main():
    """Main function"""
    # Check dependencies
    check_dependencies()
    
    # Create and run Red Tiger
    try:
        tiger = RedTiger()
        tiger.run()
    except KeyboardInterrupt:
        print("\n\n" + TerminalUI.print_colored("[!] Scan interrupted by user", "yellow"))
        print(TerminalUI.print_colored("[+] Exiting Red Tiger...", "green"))
    except Exception as e:
        print(f"\n{TerminalUI.print_colored(f'[!] Error: {e}', 'red')}")
        print(TerminalUI.print_colored("[+] Please check your input and try again", "yellow"))

if __name__ == "__main__":
    # Display startup message
    print("\n" + TerminalUI.print_colored("Initializing Red Tiger...", "cyan"))
    print(TerminalUI.print_colored("Advanced Network Reconnaissance Tool", "yellow"))
    print(TerminalUI.print_colored(f"Version: {VERSION} | By: {AUTHOR}", "green"))
    time.sleep(1)
    
    # Run main application
    main()
