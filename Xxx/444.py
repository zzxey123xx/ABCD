#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================
نظام المراقبة الإلكترونية المتقدم - نسخة الطرفية النصية
تم التطوير بواسطة: a3t8al
حقوق الملكية محفوظة © 2024
===============================================================
"""

import time
import random
import os
import sys
import math
import hashlib
import json
import threading
from datetime import datetime
from collections import deque

# ==================== الثوابت والتهيئة ====================

AUTHOR = "a3t8al"
VERSION = "Terminal v3.0"
COPYRIGHT_YEAR = 2024

# ==================== الأنظمة الأساسية ====================

class SecuritySystem:
    """نظام الأمان المتقدم"""
    
    def __init__(self):
        self.start_time = time.time()
        self.threat_log = deque(maxlen=100)
        self.encryption_keys = []
        
    def generate_key(self):
        """توليد مفتاح تشفير"""
        key = hashlib.sha256(str(time.time()).encode()).hexdigest()[:32]
        self.encryption_keys.append({
            'key': key,
            'time': datetime.now().strftime('%H:%M:%S')
        })
        return key
    
    def detect_threats(self):
        """كشف التهديدات"""
        threats = []
        
        if random.random() > 0.9:
            threat_types = [
                "DDoS Attack Detected",
                "Unauthorized Access Attempt",
                "Malware Signature Found",
                "Port Scanning Detected",
                "Data Exfiltration Attempt"
            ]
            
            threat = {
                'id': f"THR-{len(self.threat_log):04d}",
                'type': random.choice(threat_types),
                'severity': random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
                'time': datetime.now().strftime('%H:%M:%S'),
                'source': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            }
            
            threats.append(threat)
            self.threat_log.append(threat)
        
        return threats

class NetworkMonitor:
    """مراقبة الشبكة"""
    
    def __init__(self):
        self.packets = 0
        self.bandwidth = {'in': 0, 'out': 0}
        self.nodes = []
        
    def scan_network(self):
        """مسح الشبكة"""
        self.nodes = []
        node_count = random.randint(3, 8)
        
        for i in range(node_count):
            self.nodes.append({
                'id': f"NODE-{i:03d}",
                'ip': f"192.168.{random.randint(1,255)}.{random.randint(1,254)}",
                'type': random.choice(['SERVER', 'WORKSTATION', 'ROUTER', 'FIREWALL']),
                'status': random.choice(['ONLINE', 'PROTECTED', 'WARNING', 'OFFLINE']),
                'ports': random.randint(1, 20)
            })
        
        return self.nodes
    
    def get_traffic(self):
        """حصول على حركة المرور"""
        self.packets += random.randint(100, 1000)
        self.bandwidth['in'] = random.randint(50, 500)
        self.bandwidth['out'] = random.randint(30, 300)
        
        return {
            'packets': self.packets,
            'bandwidth': self.bandwidth,
            'protocols': {
                'TCP': random.randint(40, 70),
                'UDP': random.randint(20, 40),
                'HTTP': random.randint(5, 20),
                'HTTPS': random.randint(10, 30)
            }
        }

class SystemMetrics:
    """مقاييس النظام"""
    
    def __init__(self):
        self.metrics = {
            'cpu': random.uniform(5, 80),
            'ram': random.uniform(20, 90),
            'network': random.uniform(50, 500),
            'temperature': random.uniform(30, 45),
            'security': random.uniform(60, 100)
        }
        
        self.history = {
            'cpu': deque([0.0] * 20, maxlen=20),
            'ram': deque([0.0] * 20, maxlen=20)
        }
    
    def update(self):
        """تحديث المقاييس"""
        # تغييرات عشوائية
        self.metrics['cpu'] += random.uniform(-5, 5)
        self.metrics['ram'] += random.uniform(-3, 4)
        self.metrics['network'] = random.uniform(50, 500)
        self.metrics['temperature'] += random.uniform(-1, 1)
        self.metrics['security'] += random.uniform(-3, 3)
        
        # تطبيق الحدود
        self.metrics['cpu'] = max(1, min(self.metrics['cpu'], 100))
        self.metrics['ram'] = max(5, min(self.metrics['ram'], 100))
        self.metrics['temperature'] = max(25, min(self.metrics['temperature'], 50))
        self.metrics['security'] = max(10, min(self.metrics['security'], 100))
        
        # تحديث السجلات
        self.history['cpu'].append(self.metrics['cpu'])
        self.history['ram'].append(self.metrics['ram'])
        
        return self.metrics

# ==================== نظام العرض ====================

class TerminalDisplay:
    """عرض في الطرفية النصية"""
    
    @staticmethod
    def clear_screen():
        """مسح الشاشة"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    @staticmethod
    def print_header():
        """طباعة رأس الصفحة"""
        print("═" * 80)
        print(f"🚀 iSH CYBER MONITOR - {VERSION}".center(80))
        print(f"📍 Developed by: {AUTHOR} | Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(80))
        print("═" * 80)
        print()
    
    @staticmethod
    def print_section(title):
        """طباعة قسم"""
        print(f"╔{'═' * 78}╗")
        print(f"║ {title.center(76)} ║")
        print(f"╚{'═' * 78}╝")
    
    @staticmethod
    def print_metrics(metrics):
        """طباعة مقاييس النظام"""
        print("\n📊 SYSTEM METRICS:")
        print("─" * 80)
        
        # CPU
        cpu_bar = TerminalDisplay.create_progress_bar(metrics['cpu'], 30)
        print(f"   CPU Usage:    {metrics['cpu']:6.1f}% {cpu_bar}")
        
        # RAM
        ram_bar = TerminalDisplay.create_progress_bar(metrics['ram'], 30)
        print(f"   RAM Usage:    {metrics['ram']:6.1f}% {ram_bar}")
        
        # Network
        net_val = metrics['network']
        print(f"   Network I/O:  {net_val:6.1f} KB/s")
        
        # Temperature
        temp_bar = TerminalDisplay.create_progress_bar(metrics['temperature'] * 2, 30)
        print(f"   Temperature:  {metrics['temperature']:6.1f}°C {temp_bar}")
        
        # Security
        sec_bar = TerminalDisplay.create_progress_bar(metrics['security'], 30)
        print(f"   Security:     {metrics['security']:6.1f}% {sec_bar}")
        
        # Threat Level
        if metrics['security'] > 80:
            level = "🟢 LOW"
        elif metrics['security'] > 60:
            level = "🟡 MEDIUM"
        elif metrics['security'] > 40:
            level = "🟠 HIGH"
        else:
            level = "🔴 CRITICAL"
        
        print(f"   Threat Level: {level}")
        print()
    
    @staticmethod
    def create_progress_bar(value, length=20):
        """إنشاء شريط تقدم"""
        filled = int(length * value / 100)
        bar = '█' * filled + '░' * (length - filled)
        return f"[{bar}]"
    
    @staticmethod
    def print_network(network_data):
        """طباعة معلومات الشبكة"""
        print("🌐 NETWORK STATUS:")
        print("─" * 80)
        
        traffic = network_data['get_traffic']()
        nodes = network_data['get_nodes']()
        
        print(f"   Active Nodes: {len(nodes)}")
        print(f"   Total Packets: {traffic['packets']:,}")
        print(f"   Bandwidth In:  {traffic['bandwidth']['in']} KB/s")
        print(f"   Bandwidth Out: {traffic['bandwidth']['out']} KB/s")
        print()
        
        print("   Network Protocols:")
        for proto, percent in traffic['protocols'].items():
            bar = TerminalDisplay.create_progress_bar(percent, 20)
            print(f"     {proto:6}: {percent:3}% {bar}")
        
        print()
        
        if nodes:
            print("   Network Nodes:")
            for node in nodes[:5]:  # عرض 5 عقد فقط
                status_icon = "🟢" if node['status'] == 'ONLINE' else "🟡" if node['status'] == 'PROTECTED' else "🔴"
                print(f"     {status_icon} {node['id']}: {node['ip']} ({node['type']})")
        print()
    
    @staticmethod
    def print_threats(threats, total_blocked):
        """طباعة التهديدات"""
        print("⚠️  SECURITY THREATS:")
        print("─" * 80)
        
        print(f"   Threats Blocked: {total_blocked}")
        
        if threats:
            for threat in threats[-5:]:  # آخر 5 تهديدات
                severity_color = {
                    'LOW': '🟢',
                    'MEDIUM': '🟡',
                    'HIGH': '🟠',
                    'CRITICAL': '🔴'
                }.get(threat['severity'], '⚪')
                
                print(f"   {severity_color} [{threat['time']}] {threat['type']}")
                print(f"      Source: {threat['source']} | Severity: {threat['severity']}")
        else:
            print("   ✅ No active threats detected")
        print()
    
    @staticmethod
    def print_logs(logs):
        """طباعة سجلات النظام"""
        print("📋 SYSTEM LOGS:")
        print("─" * 80)
        
        if logs:
            for log in logs[-8:]:  # آخر 8 سجلات
                print(f"   [{log['time']}] {log['event']}")
        else:
            print("   No logs available")
        print()
    
    @staticmethod
    def print_stats(stats):
        """طباعة الإحصائيات"""
        print("📈 SYSTEM STATISTICS:")
        print("─" * 80)
        
        print(f"   Uptime:          {stats['uptime']} seconds")
        print(f"   Threats Detected: {stats['threats_detected']}")
        print(f"   Scans Performed:  {stats['scans_performed']}")
        print(f"   Encryptions:      {stats['encryptions']}")
        print(f"   Data Processed:   {stats['data_processed']:,} KB")
        print()
    
    @staticmethod
    def print_footer():
        """طباعة تذييل الصفحة"""
        print("═" * 80)
        print("🎮 CONTROLS: [S] Scan Network  [E] Encrypt  [R] Reset  [Q] Quit".center(80))
        print(f"© {COPYRIGHT_YEAR} {AUTHOR} | {VERSION}".center(80))
        print("═" * 80)
    
    @staticmethod
    def print_graph(data, title, height=10):
        """طباعة رسم بياني"""
        if not data:
            return
        
        print(f"   {title}:")
        
        # إيجاد القيم القصوى والدنيا
        max_val = max(data)
        min_val = min(data)
        
        if max_val == min_val:
            max_val = min_val + 1
        
        # رسم الرسم البياني
        for i in range(height, 0, -1):
            threshold = min_val + (max_val - min_val) * i / height
            line = ""
            
            for value in data[-40:]:  # آخر 40 قيمة
                if value >= threshold:
                    line += "█"
                else:
                    line += " "
            
            print(f"   │{line}")
        
        # المحور السيني
        print(f"   └{'─' * 40}")
        
        # القيم
        print(f"   Min: {min_val:.1f} | Max: {max_val:.1f} | Current: {data[-1]:.1f}")
        print()

# ==================== النظام الرئيسي ====================

class CyberMonitorTerminal:
    """نظام المراقبة للطرفية"""
    
    def __init__(self):
        self.running = True
        self.paused = False
        
        # الأنظمة
        self.security = SecuritySystem()
        self.network = NetworkMonitor()
        self.metrics = SystemMetrics()
        
        # البيانات
        self.system_logs = deque(maxlen=20)
        self.stats = {
            'uptime': 0,
            'threats_detected': 0,
            'scans_performed': 0,
            'encryptions': 0,
            'data_processed': 0
        }
        
        # مسح أولي للشبكة
        self.network.scan_network()
        self.stats['scans_performed'] += 1
        
        # إضافة سجلات أولية
        self.add_log("System initialized")
        self.add_log("Network scan completed")
        self.add_log("Security systems online")
    
    def add_log(self, event):
        """إضافة سجل جديد"""
        self.system_logs.append({
            'time': datetime.now().strftime('%H:%M:%S'),
            'event': event
        })
    
    def update_system(self):
        """تحديث حالة النظام"""
        if self.paused:
            return
        
        # تحديث المقاييس
        self.metrics.update()
        
        # تحديث الإحصائيات
        self.stats['uptime'] = int(time.time() - self.security.start_time)
        self.stats['data_processed'] += random.randint(100, 1000)
        
        # كشف التهديدات
        threats = self.security.detect_threats()
        if threats:
            self.stats['threats_detected'] += len(threats)
            for threat in threats:
                self.add_log(f"Threat detected: {threat['type']}")
        
        # أحداث عشوائية
        if random.random() > 0.85:
            events = [
                "System optimization running",
                "Memory cache cleared",
                "Firewall rules updated",
                "Security audit in progress",
                "Data backup initiated",
                "Network traffic analysis",
                "Encryption key rotation",
                "Intrusion detection active"
            ]
            self.add_log(random.choice(events))
    
    def display_dashboard(self):
        """عرض لوحة التحكم"""
        TerminalDisplay.clear_screen()
        TerminalDisplay.print_header()
        
        # عرض المقاييس
        current_metrics = self.metrics.metrics
        TerminalDisplay.print_metrics(current_metrics)
        
        # عرض الرسوم البيانية
        TerminalDisplay.print_graph(list(self.metrics.history['cpu'])[-40:], "CPU Usage History")
        TerminalDisplay.print_graph(list(self.metrics.history['ram'])[-40:], "RAM Usage History")
        
        # عرض الشبكة
        TerminalDisplay.print_network({
            'get_traffic': self.network.get_traffic,
            'get_nodes': lambda: self.network.nodes
        })
        
        # عرض التهديدات
        TerminalDisplay.print_threats(list(self.security.threat_log), self.stats['threats_detected'])
        
        # عرض السجلات
        TerminalDisplay.print_logs(list(self.system_logs))
        
        # عرض الإحصائيات
        TerminalDisplay.print_stats(self.stats)
        
        # التذييل
        TerminalDisplay.print_footer()
    
    def handle_input(self):
        """معالجة إدخال المستخدم"""
        import select
        import tty
        import termios
        
        # إعداد الطرفية للإدخال غير المتزامن
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        
        try:
            tty.setraw(fd)
            
            if select.select([sys.stdin], [], [], 0.1)[0]:
                key = sys.stdin.read(1).lower()
                
                if key == 'q':
                    self.running = False
                    self.add_log("System shutdown initiated")
                
                elif key == 'p':
                    self.paused = not self.paused
                    status = "paused" if self.paused else "resumed"
                    self.add_log(f"Monitoring {status}")
                
                elif key == 'r':
                    self.reset_system()
                    self.add_log("System reset to default")
                
                elif key == 's':
                    self.network.scan_network()
                    self.stats['scans_performed'] += 1
                    self.add_log("Network security scan performed")
                
                elif key == 'e':
                    key = self.security.generate_key()
                    self.stats['encryptions'] += 1
                    self.add_log(f"Encryption key generated: {key[:8]}...")
                
                elif key == 'c':
                    self.system_logs.clear()
                    self.add_log("All logs cleared")
                
                elif key == 'h':
                    self.show_help()
        
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    
    def reset_system(self):
        """إعادة تعيين النظام"""
        self.metrics = SystemMetrics()
        self.stats['threats_detected'] = 0
        self.stats['data_processed'] = 0
    
    def show_help(self):
        """عرض شاشة المساعدة"""
        TerminalDisplay.clear_screen()
        
        print("═" * 80)
        print("📖 iSH CYBER MONITOR - HELP MENU".center(80))
        print("═" * 80)
        print()
        
        print("🎮 CONTROL KEYS:")
        print("─" * 80)
        
        controls = [
            ("S / s", "Perform network security scan"),
            ("E / e", "Generate encryption key"),
            ("R / r", "Reset all system metrics"),
            ("P / p", "Pause/Resume monitoring"),
            ("C / c", "Clear all system logs"),
            ("Q / q", "Quit application"),
            ("H / h", "Show this help screen")
        ]
        
        for key, desc in controls:
            print(f"  {key:10} - {desc}")
        
        print()
        print("📊 DISPLAYED INFORMATION:")
        print("─" * 80)
        
        info = [
            "• Real-time system metrics (CPU, RAM, Network, etc.)",
            "• Historical graphs of CPU and RAM usage",
            "• Network traffic analysis and protocols",
            "• Security threat detection and alerts",
            "• System logs and events history",
            "• Comprehensive system statistics"
        ]
        
        for item in info:
            print(f"  {item}")
        
        print()
        print("🔧 SYSTEM INFORMATION:")
        print("─" * 80)
        
        sys_info = [
            f"Version: {VERSION}",
            f"Developer: {AUTHOR}",
            f"Python: {sys.version.split()[0]}",
            f"Platform: {sys.platform}",
            f"Start Time: {datetime.fromtimestamp(self.security.start_time).strftime('%Y-%m-%d %H:%M:%S')}"
        ]
        
        for item in sys_info:
            print(f"  {item}")
        
        print()
        print("Press any key to continue...")
        
        import select
        import tty
        import termios
        
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        
        try:
            tty.setraw(fd)
            sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    
    def show_startup(self):
        """عرض شاشة البداية"""
        TerminalDisplay.clear_screen()
        
        # شعار النظام
        logo = [
            "╔══════════════════════════════════════════════════════════╗",
            "║                                                          ║",
            "║     ██╗███████╗██╗  ██╗    ██████╗██╗   ██╗██████╗      ║",
            "║     ██║██╔════╝██║  ██║   ██╔════╝╚██╗ ██╔╝██╔══██╗     ║",
            "║     ██║███████╗███████║   ██║      ╚████╔╝ ██████╔╝     ║",
            "║     ██║╚════██║██╔══██║   ██║       ╚██╔╝  ██╔══██╗     ║",
            "║     ██║███████║██║  ██║   ╚██████╗   ██║   ██████╔╝     ║",
            "║     ╚═╝╚══════╝╚═╝  ╚═╝    ╚═════╝   ╚═╝   ╚═════╝      ║",
            "║                                                          ║",
            "║             C Y B E R   M O N I T O R                    ║",
            "║                    Terminal Edition                      ║",
            "║                                                          ║",
            "╚══════════════════════════════════════════════════════════╝"
        ]
        
        for line in logo:
            print(line)
        
        print()
        print(f"Version: {VERSION}".center(80))
        print(f"Developed by: {AUTHOR}".center(80))
        print()
        print("Initializing security systems...".center(80))
        print()
        
        # شريط التحميل المتحرك
        for i in range(51):
            bar = '█' * i + '░' * (50 - i)
            percent = i * 2
            print(f"\r  [{bar}] {percent:3}%", end='', flush=True)
            time.sleep(0.03)
        
        print("\n\n" + "System ready! Starting monitoring...".center(80))
        print("\n" + "Press any key to continue...".center(80))
        
        # انتظار الضغط على مفتاح
        import select
        import tty
        import termios
        
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        
        try:
            tty.setraw(fd)
            sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    
    def show_exit(self):
        """عرض شاشة الخروج"""
        TerminalDisplay.clear_screen()
        
        print("═" * 80)
        print("🚀 CYBER MONITOR - SYSTEM SHUTDOWN".center(80))
        print("═" * 80)
        print()
        
        # الإحصائيات النهائية
        final_stats = [
            f"Total Uptime: {self.stats['uptime']} seconds",
            f"Threats Detected: {self.stats['threats_detected']}",
            f"Network Scans: {self.stats['scans_performed']}",
            f"Encryptions: {self.stats['encryptions']}",
            f"Data Processed: {self.stats['data_processed']:,} KB"
        ]
        
        for stat in final_stats:
            print(stat.center(80))
        
        print()
        print("═" * 80)
        print(f"© {COPYRIGHT_YEAR} {AUTHOR} | {VERSION}".center(80))
        print("Thank you for using iSH Cyber Monitor!".center(80))
        print("═" * 80)
        
        time.sleep(3)
    
    def run(self):
        """تشغيل النظام"""
        # عرض شاشة البداية
        self.show_startup()
        
        # الحلقة الرئيسية
        while self.running:
            try:
                # تحديث النظام
                self.update_system()
                
                # عرض لوحة التحكم
                self.display_dashboard()
                
                # معالجة الإدخال
                self.handle_input()
                
                # تأخير للتحكم في السرعة
                if not self.paused:
                    time.sleep(0.5)
                else:
                    time.sleep(1)
                
            except KeyboardInterrupt:
                self.running = False
                self.add_log("System interrupted by user")
            except Exception as e:
                # تسجيل الخطأ والمتابعة
                error_msg = f"System error: {str(e)[:50]}"
                self.add_log(error_msg)
                time.sleep(1)
        
        # عرض شاشة الخروج
        self.show_exit()

# ==================== تشغيل النظام ====================

def main():
    """الدالة الرئيسية"""
    print(f"Starting iSH Cyber Monitor {VERSION}...")
    print(f"Developed by: {AUTHOR}")
    print("Initializing...")
    time.sleep(1)
    
    # التحقق من متطلبات النظام
    try:
        import select
        import tty
        import termios
        
        # إنشاء وتشغيل النظام
        monitor = CyberMonitorTerminal()
        monitor.run()
        
    except ImportError as e:
        print(f"Error: Missing required module - {e}")
        print("Please install required modules:")
        print("  The system uses standard Python modules only.")
        print("  Make sure you're using Python 3.6 or higher.")
    except Exception as e:
        print(f"Fatal error: {e}")
        print("Please check your terminal settings and try again.")

if __name__ == "__main__":
    main()
