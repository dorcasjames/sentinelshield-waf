#!/usr/bin/env python3
"""
SentinelShield Dashboard
Real-time statistics and visualization
"""

import json
import os
from datetime import datetime

class WAFDashboard:
    def __init__(self, stats_file=None):
        self.stats_file = stats_file or os.path.expanduser("~/waf_stats.json")
    
    def load_stats(self):
        """Load statistics from file"""
        if os.path.exists(self.stats_file):
            with open(self.stats_file, 'r') as f:
                return json.load(f)
        return None
    
    def display_dashboard(self):
        """Display real-time dashboard"""
        stats = self.load_stats()
        
        if not stats:
            print("No statistics available yet")
            return
        
        total = stats['total_requests']
        blocked = stats['blocked_requests']
        allowed = stats['allowed_requests']
        
        if total == 0:
            detection_rate = 0
        else:
            detection_rate = (blocked / total) * 100
        
        print("\n" + "="*70)
        print("SENTINELSHIELD WAF - LIVE DASHBOARD")
        print("="*70)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Traffic Statistics
        print("TRAFFIC STATISTICS")
        print("-" * 70)
        print(f"Total Requests:      {total}")
        print(f"Allowed Requests:    {allowed}")
        print(f"Blocked Requests:    {blocked}")
        print(f"Detection Rate:      {detection_rate:.1f}%\n")
        
        # Attack Types
        print("ATTACK DETECTION BREAKDOWN")
        print("-" * 70)
        print(f"SQL Injection:       {stats['sql_injection']}")
        print(f"XSS:                 {stats['xss']}")
        print(f"LFI:                 {stats['lfi']}")
        print(f"Command Injection:   {stats['command_injection']}")
        print(f"Path Traversal:      {stats['path_traversal']}")
        print(f"Rate Limit:          {stats['rate_limit']}\n")
        
        # Malicious IPs
        print("MALICIOUS IPs DETECTED")
        print("-" * 70)
        if stats['malicious_ips']:
            for ip in stats['malicious_ips']:
                print(f"• {ip}")
        else:
            print("• None detected")
        
        print("\n" + "="*70)
    
    def display_summary(self):
        """Quick summary"""
        stats = self.load_stats()
        if not stats:
            print("No statistics available")
            return
        
        print(f"\nRequests: {stats['total_requests']} | "
              f"Blocked: {stats['blocked_requests']} | "
              f"IPs: {len(stats['malicious_ips'])}\n")

if __name__ == '__main__':
    dashboard = WAFDashboard()
    dashboard.display_dashboard()
