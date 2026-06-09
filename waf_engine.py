#!/usr/bin/env python3
"""
SentinelShield WAF Engine - Core Detection Module
Separate module for request inspection and threat detection
"""

from datetime import datetime, timedelta
from collections import defaultdict
import json
import os

class WAFEngine:
    def __init__(self, log_dir=None):
        self.log_dir = log_dir or os.path.expanduser("~")
        self.activity_log = os.path.join(self.log_dir, "waf_activity.log")
        self.alert_log = os.path.join(self.log_dir, "waf_alerts.log")
        self.stats_file = os.path.join(self.log_dir, "waf_stats.json")
        
        self.rate_limit_threshold = 10
        self.rate_limit_window = 60
        self.request_count = defaultdict(list)
        
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'allowed_requests': 0,
            'sql_injection': 0,
            'xss': 0,
            'lfi': 0,
            'command_injection': 0,
            'path_traversal': 0,
            'rate_limit': 0,
            'malicious_ips': [],
            'start_time': datetime.now().isoformat()
        }
        
        self.attack_signatures = {
            'SQL_INJECTION': ["' OR ", "'; DROP", "UNION SELECT", "--", "/*", "*/", "xp_", "sp_", "exec"],
            'XSS': ["<script", "javascript:", "onerror=", "onclick=", "<img", "alert("],
            'LFI': ["../", "/etc/passwd", "file://", "\\..\\"],
            'COMMAND_INJECTION': ["; ", "| ", "&&", "`", "$("],
            'PATH_TRAVERSAL': ["../../../", "..\\..\\.."]
        }
    
    def log_activity(self, message):
        """Log normal activity"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        print(log_entry)
        with open(self.activity_log, 'a') as f:
            f.write(log_entry + "\n")
    
    def log_alert(self, severity, message):
        """Log security alert"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_entry = f"[{timestamp}] [{severity}] {message}"
        print(f"\033[91m{alert_entry}\033[0m")
        with open(self.alert_log, 'a') as f:
            f.write(alert_entry + "\n")
    
    def detect_attack(self, request_data):
        """Identify attack type from signatures"""
        for attack_type, patterns in self.attack_signatures.items():
            for pattern in patterns:
                if pattern.lower() in request_data.lower():
                    return attack_type
        return None
    
    def check_rate_limit(self, ip):
        """Check if IP exceeded rate limit"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.rate_limit_window)
        self.request_count[ip] = [ts for ts in self.request_count[ip] if ts > cutoff]
        
        if len(self.request_count[ip]) >= self.rate_limit_threshold:
            return True
        
        self.request_count[ip].append(now)
        return False
    
    def analyze_request(self, method, path, args, data, ip):
        """Main analysis function"""
        full_request = f"{method} {path} {args} {data}"
        self.stats['total_requests'] += 1
        
        # Check rate limit
        if self.check_rate_limit(ip):
            self.log_alert("CRITICAL", f"RATE LIMIT EXCEEDED: {ip}")
            self.stats['blocked_requests'] += 1
            self.stats['rate_limit'] += 1
            if ip not in self.stats['malicious_ips']:
                self.stats['malicious_ips'].append(ip)
            return False, "RATE_LIMIT"
        
        # Check for attacks
        attack_type = self.detect_attack(full_request)
        
        if attack_type:
            self.log_alert("HIGH", f"{attack_type} from {ip}: {full_request[:80]}")
            self.stats['blocked_requests'] += 1
            if ip not in self.stats['malicious_ips']:
                self.stats['malicious_ips'].append(ip)
            
            # Update attack counters
            if attack_type == "SQL_INJECTION":
                self.stats['sql_injection'] += 1
            elif attack_type == "XSS":
                self.stats['xss'] += 1
            elif attack_type == "LFI":
                self.stats['lfi'] += 1
            elif attack_type == "COMMAND_INJECTION":
                self.stats['command_injection'] += 1
            elif attack_type == "PATH_TRAVERSAL":
                self.stats['path_traversal'] += 1
            
            return False, attack_type
        
        # Safe request
        self.stats['allowed_requests'] += 1
        self.log_activity(f"ALLOWED: {method} {path} from {ip}")
        return True, "SAFE"
    
    def get_stats(self):
        """Return current statistics"""
        return self.stats.copy()
    
    def save_stats(self):
        """Save statistics to file"""
        with open(self.stats_file, 'w') as f:
            json.dump(self.stats, f, indent=2)
    
    def generate_report(self):
        """Generate security report"""
        total = self.stats['total_requests']
        blocked = self.stats['blocked_requests']
        
        if total == 0:
            detection_rate = 0
        else:
            detection_rate = (blocked / total) * 100
        
        report = f"""
{'='*70}
SENTINELSHIELD WAF - SECURITY REPORT
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
{'='*70}

TRAFFIC STATISTICS
------------------
Total Requests: {total}
Allowed Requests: {self.stats['allowed_requests']}
Blocked Requests: {blocked}
Detection Rate: {detection_rate:.1f}%

ATTACK BREAKDOWN
----------------
SQL Injection: {self.stats['sql_injection']}
XSS: {self.stats['xss']}
LFI: {self.stats['lfi']}
Command Injection: {self.stats['command_injection']}
Path Traversal: {self.stats['path_traversal']}
Rate Limit Violations: {self.stats['rate_limit']}

MALICIOUS IPs
-------------
{', '.join(self.stats['malicious_ips']) if self.stats['malicious_ips'] else 'None detected'}

LOG FILES
---------
Activity Log: {self.activity_log}
Alert Log: {self.alert_log}
Stats File: {self.stats_file}

{'='*70}
END OF REPORT
{'='*70}
"""
        return report
