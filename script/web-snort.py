#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🛡️ Attack Monitor System
Web page to display attack logs from .log files
All code in one file - OOP design with improvements
"""

from flask import Flask, render_template_string, jsonify, request
import os
import re
from datetime import datetime, timedelta
import glob
import json
from collections import Counter


class LogParser:
    """Class for parsing log files"""
    
    def __init__(self):
        self.attack_type_map = {
            'UDP': 'UDP Attack',
            'TCP': 'DDOS',
            'ICMP': 'ICMP Attack',
            'HTTP': 'HTTP Attack',
            'HTTPS': 'HTTPS Attack',
            'DNS': 'DNS Attack',
            'UNKNOWN': 'Malformed Packet'
        }
    
    def parse_log_file(self, filepath):
        """Parse log file and extract attack information"""
        attacks = []
        filename = os.path.basename(filepath)
        
        # New pattern: IP timestamp protocol
        pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d+)\s+(\w+)$'
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    match = re.match(pattern, line)
                    if match:
                        attacks.append(self._parse_new_format(match, filename))
                    else:
                        attacks.extend(self._parse_old_formats(line, filename))
        except Exception as e:
            print(f"Error reading file {filepath}: {e}")
        
        return attacks
    
    def _parse_new_format(self, match, filename):
        """Process new log format"""
        ip = match.group(1)
        timestamp = int(match.group(2))
        protocol = match.group(3)
        
        formatted_time, attack_date, attack_hour = self._parse_timestamp(timestamp)
        
        attack_type = self.attack_type_map.get(protocol.upper(), 'Attack ' + protocol)
        
        return {
            'ip': ip,
            'time': formatted_time,
            'packet_type': protocol,
            'attack_type': attack_type,
            'status': 'Blocked',
            'source': filename,
            'timestamp': timestamp,
            'date': attack_date,
            'hour': attack_hour
        }
    
    def _parse_old_formats(self, line, filename):
        """Process old log formats"""
        attacks = []
        
        old_patterns = [
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[-|]\s*(\d{4}[-/]\d{2}[-/]\d{2}\s*\d{2}:\d{2}:\d{2})\s*[-|]\s*(\w+)\s*[-|]\s*(\w+)',
            r'\[(\d{4}[-/]\d{2}[-/]\d{2}\s*\d{2}:\d{2}:\d{2})\]\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\w+)\s+(\w+)',
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(\d{2}:\d{2}:\d{2})',
        ]
        
        for old_pattern in old_patterns:
            old_match = re.search(old_pattern, line)
            if old_match:
                groups = old_match.groups()
                if len(groups) >= 4:
                    attacks.append(self._create_attack_from_groups(groups, old_patterns.index(old_pattern), filename))
                    break
                elif len(groups) >= 2:
                    attacks.append(self._create_basic_attack(groups, filename))
                    break
        
        # If no pattern matches, look for IP only
        if not attacks:
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if ip_match:
                attacks.append(self._create_ip_only_attack(ip_match.group(1), filename))
        
        return attacks
    
    def _parse_timestamp(self, timestamp):
        """Convert timestamp to readable time"""
        try:
            if timestamp > 1000000000 and timestamp < 10000000000:
                dt = datetime.fromtimestamp(timestamp)
            elif timestamp > 1000000000000 and timestamp < 10000000000000:
                dt = datetime.fromtimestamp(timestamp / 1000)
            else:
                dt = datetime.now()
            
            formatted_time = dt.strftime('%Y-%m-%d %I:%M:%S %p')
            attack_date = dt.date()
            attack_hour = dt.hour
        except:
            formatted_time = str(timestamp)
            attack_date = datetime.now().date()
            attack_hour = datetime.now().hour
        
        return formatted_time, attack_date, attack_hour
    
    def _create_attack_from_groups(self, groups, pattern_index, filename):
        """Create attack from group data"""
        return {
            'ip': groups[0] if pattern_index == 0 else groups[1],
            'time': groups[1] if pattern_index == 0 else groups[0],
            'packet_type': groups[2],
            'attack_type': groups[3] if len(groups) > 3 else 'Unknown',
            'status': 'Blocked',
            'source': filename,
            'timestamp': datetime.now().timestamp(),
            'date': datetime.now().date(),
            'hour': datetime.now().hour
        }
    
    def _create_basic_attack(self, groups, filename):
        """Create attack with basic data"""
        return {
            'ip': groups[0],
            'time': groups[1] if len(groups) > 1 else datetime.now().strftime('%H:%M:%S'),
            'packet_type': 'TCP/UDP',
            'attack_type': 'Unknown',
            'status': 'Monitored',
            'source': filename,
            'timestamp': datetime.now().timestamp(),
            'date': datetime.now().date(),
            'hour': datetime.now().hour
        }
    
    def _create_ip_only_attack(self, ip, filename):
        """Create attack using IP only"""
        return {
            'ip': ip,
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'packet_type': 'Undefined',
            'attack_type': 'Undefined',
            'status': 'Monitored',
            'source': filename,
            'timestamp': datetime.now().timestamp(),
            'date': datetime.now().date(),
            'hour': datetime.now().hour
        }


class SnortLogAnalyzer:
    """Class for analyzing Snort log files"""
    
    def __init__(self, snort_log_path):
        self.snort_log_path = snort_log_path
        self.ip_counter = Counter()
        self.last_analysis_time = None
        self.cached_top_attackers = []
        # List of internal IPs to hide
        self.internal_ips = ['192.168.1.3', '255.255.255.255', '192.168.1.1', '224.0.0.22']
    
    def is_internal_ip(self, ip):
        """Check if IP is internal"""
        for internal_ip in self.internal_ips:
            if ip == internal_ip:
                return True
        return False
    
    def extract_ips_from_line(self, line):
        """Extract IP addresses from Snort log line"""
        ips = []
        
        # Typical Snort pattern: {TCP} 10.0.0.13:11942 -> 192.168.1.3:80
        patterns = [
            # Pattern: {TCP} 10.0.0.13:11942 -> 192.168.1.3:80
            r'\{(\w+)\}\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+\s*->\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+',
            # Other possible patterns
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*->\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'SRC:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'DST:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            # Search for any IP in line
            r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, line)
            if matches:
                for match in matches:
                    if isinstance(match, tuple):
                        for ip in match:
                            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip):
                                # Hide internal IP
                                
                                    ips.append(ip)
                    else:
                        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', match):
                            # Hide internal IP
                            if not self.is_internal_ip(match):
                                ips.append(match)
        
        return list(set(ips))  # Remove duplicates
    
    def sanitize_log_line(self, line):
        """Clean log line and hide internal IP"""
        
        return line
    
    def analyze_snort_log(self, force_refresh=False):
        """Analyze Snort log to find most active IPs"""
        current_time = datetime.now()
        
        # Check if analysis is recent (last 30 seconds) unless forced refresh
        if (not force_refresh and self.last_analysis_time and 
            (current_time - self.last_analysis_time).total_seconds() < 30):
            return self.cached_top_attackers
        
        if not os.path.exists(self.snort_log_path):
            return []
        
        try:
            self.ip_counter.clear()
            
            with open(self.snort_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Analyze each line
            for line in lines:
                ips = self.extract_ips_from_line(line)
                for ip in ips:
                    self.ip_counter[ip] += 1
            
            # Get top 10 attackers (exclude internal IPs)
            top_attackers = []
            for ip, count in self.ip_counter.most_common():
                if not self.is_internal_ip(ip):
                    top_attackers.append((ip, count))
                if len(top_attackers) >= 10:
                    break
            
            # Format results
            formatted_results = []
            for ip, count in top_attackers:
                formatted_results.append({
                    'ip': ip,
                    'count': count,
                    'percentage': round((count / len(lines)) * 100, 2) if lines else 0
                })
            
            self.cached_top_attackers = formatted_results
            self.last_analysis_time = current_time
            
            return formatted_results
            
        except Exception as e:
            print(f"Error analyzing Snort log: {e}")
            return []
    
    def get_top_attacker(self):
        """Get most active attacker"""
        top_attackers = self.analyze_snort_log()
        if top_attackers:
            return top_attackers[0]
        return {'ip': 'None', 'count': 0, 'percentage': 0}
    
    def read_snort_log(self):
        """Read original Snort alerts file - FIXED to show complete lines"""
        if not os.path.exists(self.snort_log_path):
            return [], "Not available", 0, 0
        
        try:
            with open(self.snort_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Get file last modified time
            last_modified = datetime.fromtimestamp(os.path.getmtime(self.snort_log_path)).strftime('%Y-%m-%d %H:%M:%S')
            
            # Return cleaned lines without truncating
            cleaned_lines = []
            for line in lines:
                cleaned_line = self.sanitize_log_line(line.rstrip('\n'))
                # Keep the full line without truncation
                cleaned_lines.append(cleaned_line)
            
            # Calculate today's alerts (last 24 hours)
            snort_alerts_today = len(lines)  # Simple estimate
            
            return cleaned_lines, last_modified, len(lines), snort_alerts_today
        
        except Exception as e:
            print(f"Error reading Snort file: {e}")
            return [], f"Error: {str(e)}", 0, 0
    
    def search_ip_in_log(self, ip_address):
        """Search for specific IP in Snort log"""
        if not os.path.exists(self.snort_log_path):
            return []
        
        try:
            results = []
            with open(self.snort_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if ip_address in line and not self.is_internal_ip(ip_address):
                        results.append({
                            'line_number': line_num,
                            'content': self.sanitize_log_line(line.strip()),
                            'timestamp': self.extract_timestamp_from_line(line)
                        })
            return results[:100]  # Limit to 100 results
        except Exception as e:
            print(f"Error searching IP in Snort log: {e}")
            return []
    
    def extract_timestamp_from_line(self, line):
        """Extract timestamp from Snort line"""
        # Pattern: 01/13-20:50:36.804696
        pattern = r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)'
        match = re.search(pattern, line)
        if match:
            return match.group(1)
        return "Unknown"


class AttackAnalyzer:
    """Class for analyzing attacks and generating statistics"""
    
    def __init__(self, snort_analyzer):
        self.log_parser = LogParser()
        self.snort_analyzer = snort_analyzer
    
    def get_all_attacks(self, log_directory, log_pattern, snort_log_file):
        """Collect all attacks from all log files"""
        all_attacks = []
        
        # Create logs directory if not exists
        if not os.path.exists(log_directory):
            os.makedirs(log_directory)
        
        # Search for log files (excluding Snort file)
        log_files = glob.glob(os.path.join(log_directory, log_pattern))
        
        for log_file in log_files:
            # Skip Snort file
            if os.path.basename(log_file) == snort_log_file:
                continue
                
            attacks = self.log_parser.parse_log_file(log_file)
            all_attacks.extend(attacks)
        
        return all_attacks, len(log_files)
    
    def analyze_attacks(self, attacks):
        """Analyze attacks and output useful statistics"""
        today = datetime.now().date()
        yesterday = today - timedelta(days=1)
        now = datetime.now()
        
        # Filter attacks by date
        recent_attacks = [a for a in attacks if 'date' in a]
        
        # Attacks in last 24 hours
        if recent_attacks:
            last_24h = [a for a in recent_attacks 
                       if (now - datetime.fromtimestamp(a['timestamp'])).total_seconds() <= 86400]
        else:
            last_24h = attacks
        
        active_attacks = len(last_24h)
        
        # Today's attacks vs yesterday (for trend calculation)
        today_attacks = [a for a in recent_attacks if a.get('date') == today]
        yesterday_attacks = [a for a in recent_attacks if a.get('date') == yesterday]
        
        if yesterday_attacks:
            attacks_trend = ((len(today_attacks) - len(yesterday_attacks)) / len(yesterday_attacks)) * 100
            attacks_trend = round(attacks_trend, 1)
        else:
            attacks_trend = 0
        
        # Get most active attacker from Snort
        top_attacker = self.snort_analyzer.get_top_attacker()
        
        # Blocked attacks percentage
        blocked_count = len([a for a in attacks if a['status'] == 'Blocked'])
        total_attacks = len(attacks)
        
        if total_attacks > 0:
            block_rate = round((blocked_count / total_attacks) * 100, 1)
        else:
            block_rate = 0
        
        return {
            'active_attacks': active_attacks,
            'attacks_trend': attacks_trend,
            'top_attacker': top_attacker,
            'block_rate': block_rate,
            'blocked_count': blocked_count,
            'total_attacks': total_attacks,
        }


class AttackMonitorApp:
    """Main class for Attack Monitor Application"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.log_directory = "./logs"
        self.log_pattern = "/home/ubuntu/Desktop/snort_blocked.log"
        self.snort_log_file = "/home/ubuntu/Desktop/snort.log"
        
        self.snort_analyzer = SnortLogAnalyzer(self.snort_log_file)
        self.attack_analyzer = AttackAnalyzer(self.snort_analyzer)
        
        self.setup_routes()
    
    def setup_routes(self):
        """Setup application routes"""
        @self.app.route('/')
        def index():
            """Single homepage"""
            attacks, log_files_count = self.attack_analyzer.get_all_attacks(
                self.log_directory, self.log_pattern, self.snort_log_file
            )
            unique_ips = len(set(a['ip'] for a in attacks))
            blocked = len([a for a in attacks if a['status'] == 'Blocked'])
            
            # Read Snort log and analyze attackers
            snort_log, snort_last_modified, snort_line_count, snort_alerts_today = self.snort_analyzer.read_snort_log()
            top_attackers = self.snort_analyzer.analyze_snort_log()
            
            # Analyze statistics
            stats = self.attack_analyzer.analyze_attacks(attacks)
            
            return render_template_string(HTML_TEMPLATE,
                attacks=attacks,
                total_attacks=len(attacks),
                unique_ips=unique_ips,
                blocked_count=blocked,
                log_files=log_files_count,
                snort_log=snort_log,
                snort_last_modified=snort_last_modified,
                snort_line_count=snort_line_count,
                top_attackers=top_attackers[:5],  # Top 5 attackers for display
                # New statistics
                active_attacks=stats['active_attacks'],
                attacks_trend=stats['attacks_trend'],
                top_attacker=stats['top_attacker'],
                block_rate=stats['block_rate'],
            )
        
        @self.app.route('/api/attacks')
        def api_attacks():
            """API to get data in JSON format"""
            attacks, _ = self.attack_analyzer.get_all_attacks(
                self.log_directory, self.log_pattern, self.snort_log_file
            )
            return jsonify(attacks)
        
        @self.app.route('/api/stats')
        def api_stats():
            """API for statistics"""
            attacks, log_files_count = self.attack_analyzer.get_all_attacks(
                self.log_directory, self.log_pattern, self.snort_log_file
            )
            stats = self.attack_analyzer.analyze_attacks(attacks)
            top_attackers = self.snort_analyzer.analyze_snort_log()
            
            stats_data = {
                'total_attacks': len(attacks),
                'unique_ips': len(set(a['ip'] for a in attacks)),
                'blocked_count': len([a for a in attacks if a['status'] == 'Blocked']),
                'log_files': log_files_count,
                'detailed_stats': stats,
                'top_attackers': top_attackers[:10]
            }
            return jsonify(stats_data)
        
        @self.app.route('/api/snort')
        def api_snort():
            """API to get Snort alerts"""
            snort_log, last_modified, line_count, alerts_today = self.snort_analyzer.read_snort_log()
            return jsonify({
                'log': snort_log,
                'last_modified': last_modified,
                'line_count': line_count,
                'alerts_today': alerts_today
            })
        
        @self.app.route('/api/snort/top_attackers')
        def api_snort_top_attackers():
            """API to get most active attackers"""
            force_refresh = request.args.get('refresh', 'false').lower() == 'true'
            top_attackers = self.snort_analyzer.analyze_snort_log(force_refresh)
            return jsonify(top_attackers[:10])
        
        @self.app.route('/api/snort/search/<ip_address>')
        def api_snort_search(ip_address):
            """API to search IP in Snort log"""
            results = self.snort_analyzer.search_ip_in_log(ip_address)
            return jsonify(results)
    
    def run(self):
        """Run application"""
        self.app.run(debug=True, host='11.0.0.1', port=5000)


# ===== Single Page HTML Template with improvements =====
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Attack Monitor System</title>
    <style>
        /* CSS simplified for browser compatibility */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Tahoma, Arial, sans-serif;
            background: #1a1a2e;
            min-height: 100vh;
            color: #fff;
            padding: 10px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        
        /* Header */
        .header {
            text-align: center;
            padding: 20px;
            background: rgba(0,0,0,0.3);
            border-radius: 10px;
            margin-bottom: 20px;
            border: 1px solid rgba(255,255,255,0.1);
        }
        .header h1 {
            font-size: 2em;
            margin-bottom: 10px;
            color: #00d4ff;
        }
        .header p { color: #888; font-size: 1em; }
        
        /* Stats Cards - using float for browser compatibility */
        .stats {
            width: 100%;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .stat-card {
            float: left;
            width: 24%;
            margin: 0.5%;
            background: rgba(255,255,255,0.05);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.1);
            cursor: pointer;
            position: relative;
            min-height: 180px;
        }
        .stat-card:hover {
            background: rgba(255,255,255,0.08);
        }
        .stat-card .number {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
            display: block;
        }
        .stat-card .label { 
            color: #888; 
            font-size: 0.9em;
            margin-bottom: 5px;
            display: block;
        }
        .stat-card .subtext {
            color: #aaa;
            font-size: 0.8em;
            margin-top: 5px;
            display: block;
        }
        .stat-card .trend {
            font-size: 0.8em;
            padding: 3px 8px;
            border-radius: 10px;
            display: inline-block;
            margin-top: 5px;
        }
        .trend-up { background: rgba(46,213,115,0.2); color: #2ed573; }
        .trend-down { background: rgba(255,71,87,0.2); color: #ff4757; }
        .trend-neutral { background: rgba(255,165,2,0.2); color: #ffa502; }
        
        .stat-card.danger { border-color: rgba(255,71,87,0.3); }
        .stat-card.danger .number { color: #ff4757; }
        .stat-card.danger .label { color: #ff6b81; }
        
        .stat-card.warning { border-color: rgba(255,165,2,0.3); }
        .stat-card.warning .number { color: #ffa502; }
        .stat-card.warning .label { color: #ffb732; }
        
        .stat-card.success { border-color: rgba(46,213,115,0.3); }
        .stat-card.success .number { color: #2ed573; }
        .stat-card.success .label { color: #5fe48e; }
        
        .stat-card.purple { border-color: rgba(123,44,191,0.3); }
        .stat-card.purple .number { color: #7b2cbf; }
        .stat-card.purple .label { color: #9a5bdd; }
        
        /* Fixed icons */
        .icon-fixed {
            font-size: 2em;
            margin-bottom: 10px;
            display: block;
            height: 40px;
            line-height: 40px;
        }
        
        /* Tabs */
        .tabs {
            background: rgba(255,255,255,0.05);
            border-radius: 10px 10px 0 0;
            overflow: hidden;
            margin-bottom: 0;
        }
        .tab {
            float: left;
            width: 50%;
            padding: 15px;
            text-align: center;
            cursor: pointer;
            font-weight: 600;
            font-size: 1em;
            border-left: 1px solid rgba(255,255,255,0.1);
        }
        .tab.active {
            background: #00d4ff;
            color: white;
        }
        .tab.snort.active {
            background: #ffa502;
        }
        .clear { clear: both; }
        
        /* Tab Content */
        .tab-content {
            display: none;
            padding: 0;
            background: rgba(255,255,255,0.05);
            border-radius: 0 0 10px 10px;
            border: 1px solid rgba(255,255,255,0.1);
            border-top: none;
        }
        .tab-content.active {
            display: block;
        }
        
        /* Controls */
        .controls {
            padding: 15px;
            overflow: hidden;
        }
        .search-box {
            float: left;
            width: 70%;
            padding: 10px 15px;
            border: 2px solid rgba(255,255,255,0.1);
            border-radius: 5px;
            background: rgba(255,255,255,0.05);
            color: #fff;
            font-size: 1em;
            margin-right: 10px;
        }
        .search-box:focus { outline: none; border-color: #00d4ff; }
        .btn {
            float: right;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1em;
        }
        .btn-primary {
            background: #00d4ff;
            color: #fff;
        }
        .btn-snort {
            background: #ffa502;
            color: #fff;
        }
        .btn-refresh {
            background: #2ed573;
            color: #fff;
            margin-right: 5px;
        }
        
        /* Table */
        .table-container {
            padding: 0 15px 15px 15px;
            overflow-x: auto;
        }
        table { width: 100%; border-collapse: collapse; }
        th {
            background: rgba(0,212,255,0.2);
            padding: 12px 10px;
            text-align: left;
            font-weight: 600;
            color: #00d4ff;
            border-bottom: 2px solid rgba(0,212,255,0.3);
        }
        td {
            padding: 10px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        tr:hover { background: rgba(255,255,255,0.05); }
        
        /* Snort Log Container */
        .snort-container {
            padding: 15px;
        }
        .snort-header {
            background: rgba(255,165,2,0.2);
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 15px;
            border: 1px solid rgba(255,165,2,0.3);
        }
        .snort-header h2 {
            color: #ffa502;
            margin-bottom: 5px;
        }
        .snort-header p {
            color: #ffd166;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        
        /* Log Content - FIXED for complete lines */
        .log-content {
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            word-wrap: break-word;
            overflow-wrap: break-word;
            max-height: 600px;
            overflow-y: auto;
            line-height: 1.6;
            background: rgba(0,0,0,0.2);
            padding: 15px;
            border-radius: 10px;
            border: 1px solid rgba(255,255,255,0.1);
            word-break: break-all;
        }
        .log-line {
            padding: 5px 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            white-space: pre-wrap;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        .log-line:last-child {
            border-bottom: none;
        }
        .log-line:hover {
            background: rgba(255,165,2,0.05);
        }
        
        /* Badges */
        .badge {
            padding: 3px 8px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: 500;
            display: inline-block;
        }
        .badge-danger { background: rgba(255,71,87,0.2); color: #ff4757; }
        .badge-warning { background: rgba(255,165,2,0.2); color: #ffa502; }
        .badge-info { background: rgba(0,212,255,0.2); color: #00d4ff; }
        .badge-success { background: rgba(46,213,115,0.2); color: #2ed573; }
        .badge-purple { background: rgba(123,44,191,0.2); color: #9a5bdd; }
        
        /* IP styling */
        .ip-address {
            font-family: 'Courier New', monospace;
            background: rgba(0,0,0,0.3);
            padding: 3px 8px;
            border-radius: 3px;
            color: #ffa502;
        }
        
        /* Empty state */
        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: #666;
        }
        .empty-state .icon { font-size: 3em; margin-bottom: 15px; }
        
        /* Auto refresh indicator */
        .refresh-indicator {
            text-align: center;
            padding: 10px;
            color: #888;
            font-size: 0.9em;
            margin-top: 20px;
            clear: both;
        }
        
        /* Attack Info Tooltip */
        .attack-info {
            display: none;
            position: absolute;
            background: rgba(0,0,0,0.9);
            color: white;
            padding: 8px;
            border-radius: 5px;
            z-index: 100;
            font-size: 0.8em;
            max-width: 200px;
            text-align: left;
            bottom: 100%;
            left: 0;
            margin-bottom: 5px;
        }
        .stat-card:hover .attack-info {
            display: block;
        }
        
        /* Top Attackers Table */
        .top-attackers {
            margin-bottom: 20px;
        }
        .top-attackers h3 {
            color: #ffa502;
            margin-bottom: 10px;
            padding: 0 15px;
        }
        
        /* Progress Bar */
        .progress-bar {
            width: 100%;
            height: 8px;
            background: rgba(255,255,255,0.1);
            border-radius: 4px;
            margin-top: 5px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #ffa502, #ffd166);
            border-radius: 4px;
        }
        
        /* Notification (no popups) */
        .notification {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(46,213,115,0.9);
            color: white;
            padding: 10px 20px;
            border-radius: 5px;
            z-index: 1000;
            display: none;
            font-size: 0.9em;
        }
        
        /* Responsive for old browsers */
        @media screen and (max-width: 1200px) {
            .stat-card {
                width: 48%;
                margin: 1%;
            }
        }
        
        @media screen and (max-width: 768px) {
            .header h1 { font-size: 1.5em; }
            .stat-card {
                width: 98%;
                margin: 1%;
            }
            th, td { padding: 8px 6px; font-size: 0.9em; }
            .tab { width: 100%; float: none; }
            .search-box { width: 60%; }
            .btn { width: 35%; }
        }
        
        @media screen and (max-width: 480px) {
            body { padding: 5px; }
            .header { padding: 15px; }
            .header h1 { font-size: 1.3em; }
            .stat-card { padding: 10px; min-height: 150px; }
            .icon-fixed { font-size: 1.5em; }
            .number { font-size: 1.5em; }
            .search-box, .btn { float: none; width: 100%; margin: 0 0 10px 0; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Attack Monitor System - Snort Analytics</h1>
            <p>Advanced real-time Snort alert analysis</p>
        </div>
        
        <div class="stats">
            <!-- Card 1: Active Attacks -->
            <div class="stat-card danger" onclick="switchTab('attacks')">
                <div class="icon-fixed">⚡</div>
                <span class="number">{{ active_attacks }}</span>
                <span class="label">Active Attacks</span>
                <span class="subtext">Last 24 hours</span>
                <div class="attack-info">
                    Number of attacks detected in the last 24 hours
                </div>
            </div>
            
            <!-- Card 2: Most Active Attacker from Snort -->
            <div class="stat-card warning" onclick="showTopAttackerSnort()">
                <div class="icon-fixed">👑</div>
                <span class="number" style="font-size: 1.3em; color: #ffa502;">{{ top_attacker.ip }}</span>
                <span class="label">Most Active Attacker</span>
                <span class="subtext">{{ top_attacker.count }} alerts</span>
                {% if top_attacker.percentage > 0 %}
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {{ top_attacker.percentage }}%"></div>
                </div>
                {% endif %}
                <div class="attack-info">
                    Most frequent external IP address in Snort alerts recently
                </div>
            </div>
            
            <!-- Card 3: Block Rate Percentage -->
            <div class="stat-card success">
                <div class="icon-fixed">🛡️</div>
                <span class="number">{{ block_rate }}%</span>
                <span class="label">Block Rate</span>
                <span class="subtext">{{ blocked_count }} / {{ total_attacks }}</span>
                <div class="attack-info">
                    Percentage of attacks successfully blocked from total attacks
                </div>
            </div>
            
            <!-- Card 4: Snort Alerts -->
            <div class="stat-card purple" onclick="switchTab('snort')">
                <div class="icon-fixed">🚨</div>
                <span class="number">{{ snort_line_count }}</span>
                <span class="label">Snort Alerts</span>
                <span class="subtext">Total Alerts</span>
                <div class="attack-info">
                    Number of lines in snort.log file (internal IPs hidden)
                </div>
            </div>
            <div class="clear"></div>
        </div>
        
        <!-- Top 5 Attackers from Snort List -->
        {% if top_attackers %}
        <div class="top-attackers">
            <h3>🏆 Top 5 Most Dangerous External Attackers in Snort Log</h3>
            <div class="table-container">
                <table id="topAttackersTable">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>🌐 Attacker IP</th>
                            <th>📊 Alert Count</th>
                            <th>📈 Percentage</th>
                            <th>🔍 Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for attacker in top_attackers %}
                        <tr class="attacker-row" data-ip="{{ attacker.ip }}">
                            <td>{{ loop.index }}</td>
                            <td><span class="ip-address">{{ attacker.ip }}</span></td>
                            <td>{{ attacker.count }}</td>
                            <td>
                                <div style="display: flex; align-items: center;">
                                    <span style="min-width: 40px;">{{ attacker.percentage }}%</span>
                                    <div class="progress-bar" style="margin-left: 10px; flex-grow: 1;">
                                        <div class="progress-fill" style="width: {{ attacker.percentage }}%"></div>
                                    </div>
                                </div>
                            </td>
                            <td>
                                <button class="badge badge-info" onclick="filterByIP('{{ attacker.ip }}')">🔍 Search</button>
                                <button class="badge badge-warning" onclick="searchIPInSnort('{{ attacker.ip }}')">📋 Filter</button>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
        {% endif %}
        
        <div class="tabs">
            <div class="tab active" onclick="switchTab('attacks')">📊 Analyzed Attacks</div>
            <div class="tab snort" onclick="switchTab('snort')">🚨 Original Snort Alerts</div>
            <div class="clear"></div>
        </div>
        
        <!-- Tab 1: Analyzed Attacks -->
        <div id="attacksTab" class="tab-content active">
            <div class="controls">
                <input type="text" class="search-box" id="searchInput" 
                       placeholder="🔍 Search by IP or attack type..." onkeyup="filterAttacks()">
                <button class="btn btn-primary" onclick="refreshData()">🔄 Refresh Data</button>
                
                <div class="clear"></div>
            </div>
            
            <div class="table-container">
                <table id="attacksTable">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>🌐 Attacker IP</th>
                            <th>⏰ Attack Time</th>
                            <th>📦 Packet Type</th>
                            <th>⚠️ Attack Type</th>
                            <th>📊 Status</th>
                            <th>📁 Source</th>
                        </tr>
                    </thead>
                    <tbody id="attacksTableBody">
                        {% if attacks %}
                            {% for attack in attacks %}
                            <tr>
                                <td>{{ loop.index }}</td>
                                <td><span class="ip-address">{{ attack.ip }}</span></td>
                                <td>{{ attack.time }}</td>
                                <td><span class="badge badge-info">{{ attack.packet_type }}</span></td>
                                <td><span class="badge badge-danger">{{ attack.attack_type }}</span></td>
                                <td><span class="badge badge-{{ 'success' if attack.status == 'Blocked' else 'warning' }}">{{ attack.status }}</span></td>
                                <td>{{ attack.source }}</td>
                            </tr>
                            {% endfor %}
                        {% else %}
                            <tr>
                                <td colspan="7">
                                    <div class="empty-state">
                                        <div class="icon">📂</div>
                                        <h3>No Data Available</h3>
                                        <p>Add .log files in the logs folder</p>
                                    </div>
                                </td>
                            </tr>
                        {% endif %}
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Tab 2: Original Snort Alerts -->
        <div id="snortTab" class="tab-content">
            <div class="snort-container">
                <div class="snort-header">
                    <h2>📄 Contents of snort.log file</h2>
                    <p>🕐 Last Modified: {{ snort_last_modified }}</p>
                    <p>📊 Line Count: {{ snort_line_count }}</p>
                    <p>🎯 Top External Attacker: {{ top_attacker.ip }} ({{ top_attacker.count }} alerts)</p>
                </div>
                
                <div class="controls">
                    <input type="text" class="search-box" id="snortSearchInput" 
                           placeholder="🔍 Search in Snort alerts..." onkeyup="filterSnortLog()">
                    <button class="btn btn-snort" onclick="refreshSnortLog()">🔄 Refresh Snort</button>
                    <div class="clear"></div>
                </div>
                
                <div class="log-content" id="snortLogContent">
                    {% if snort_log %}
                        {% for line in snort_log %}
                        <div class="log-line">{{ line }}</div>
                        {% endfor %}
                    {% else %}
                        <div class="empty-state">
                            <div class="icon">📂</div>
                            <h3>No Alerts Found</h3>
                            <p>snort.log file doesn't exist or is empty</p>
                        </div>
                    {% endif %}
                </div>
            </div>
        </div>
        
        <div class="refresh-indicator">
            ⏱️ Auto refresh in <span id="countdown">60</span> seconds
            <br>
            <small>Last attackers update: <span id="lastUpdateTime">{{ snort_last_modified }}</span></small>
        </div>
        
        <!-- Fixed notification (no popups) -->
        <div id="notification" class="notification"></div>
    </div>
    
    <script>
        // Tabs - compatible with old browsers
        function switchTab(tabName) {
            // Hide all contents
            var contents = document.getElementsByClassName('tab-content');
            for (var i = 0; i < contents.length; i++) {
                contents[i].className = contents[i].className.replace(' active', '');
            }
            
            // Remove active from all tabs
            var tabs = document.getElementsByClassName('tab');
            for (var j = 0; j < tabs.length; j++) {
                tabs[j].className = tabs[j].className.replace(' active', '');
            }
            
            // Show selected content
            document.getElementById(tabName + 'Tab').className += ' active';
            
            // Activate selected tab
            for (var k = 0; k < tabs.length; k++) {
                if (tabs[k].textContent.indexOf(tabName === 'attacks' ? 'Analyzed' : 'Snort') !== -1) {
                    tabs[k].className += ' active';
                }
            }
            
            // Save active tab in localStorage if available
            try {
                localStorage.setItem('activeTab', tabName);
            } catch(e) {
                // localStorage not available in old browsers
            }
        }
        
        // Search in attacks table
        function filterAttacks() {
            var input = document.getElementById('searchInput').value.toLowerCase();
            var table = document.getElementById('attacksTable');
            var rows = table.getElementsByTagName('tr');
            
            for (var i = 1; i < rows.length; i++) { // Start from 1 to skip table header
                var cells = rows[i].getElementsByTagName('td');
                var found = false;
                
                for (var j = 0; j < cells.length; j++) {
                    var cellText = cells[j].textContent || cells[j].innerText;
                    if (cellText.toLowerCase().indexOf(input) > -1) {
                        found = true;
                        break;
                    }
                }
                
                rows[i].style.display = found ? '' : 'none';
            }
        }
        
        // Search in Snort log - FIXED for complete lines
        function filterSnortLog() {
            var input = document.getElementById('snortSearchInput').value.toLowerCase();
            var logContent = document.getElementById('snortLogContent');
            var lines = logContent.getElementsByClassName('log-line');
            
            for (var i = 0; i < lines.length; i++) {
                var lineText = lines[i].textContent || lines[i].innerText;
                if (lineText.toLowerCase().indexOf(input) > -1) {
                    lines[i].style.display = '';
                    lines[i].style.backgroundColor = 'rgba(255,165,2,0.1)';
                } else {
                    lines[i].style.display = 'none';
                    lines[i].style.backgroundColor = '';
                }
            }
        }
        
        // Show most active attacker from Snort (no popup notifications)
        function showTopAttackerSnort() {
            var attackerIP = "{{ top_attacker.ip }}";
            if (attackerIP && attackerIP !== 'None') {
                // Fill search box in Snort tab
                switchTab('snort');
                document.getElementById('snortSearchInput').value = attackerIP;
                filterSnortLog();
                
                // Fixed notification (no popup)
                showNotification('Showing alerts for attacker: ' + attackerIP);
            }
        }
        
        // Search for IP in Snort log - FIXED FUNCTION
        function searchIPInSnort(ip) {
            // Switch to Snort tab
            switchTab('snort');
            
            // Set search value and filter
            var searchInput = document.getElementById('snortSearchInput');
            searchInput.value = ip;
            filterSnortLog();
            
            // Show notification
            showNotification('Searching for IP: ' + ip + ' in Snort log');
            
            // Scroll to first result
            var logContent = document.getElementById('snortLogContent');
            var visibleLines = logContent.getElementsByClassName('log-line');
            for (var i = 0; i < visibleLines.length; i++) {
                if (visibleLines[i].style.display !== 'none') {
                    logContent.scrollTop = visibleLines[i].offsetTop - logContent.offsetTop;
                    break;
                }
            }
        }
        
        // Filter attacks by IP - FIXED FUNCTION
        function filterByIP(ip) {
            // Switch to attacks tab
            switchTab('attacks');
            
            // Set search value and filter
            var searchInput = document.getElementById('searchInput');
            searchInput.value = ip;
            filterAttacks();
            
            // Show notification
            showNotification('Filtering attacks by IP: ' + ip);
        }
        
        // Show fixed notification (no popup)
        function showNotification(message) {
            var notification = document.getElementById('notification');
            notification.textContent = message;
            notification.style.display = 'block';
            
            // Hide notification after 3 seconds
            setTimeout(function() {
                notification.style.display = 'none';
            }, 3000);
        }
        
        // Refresh data
        function refreshData() {
            showNotification('Refreshing data...');
            setTimeout(function() {
                window.location.reload();
            }, 500);
        }
        
        // Refresh Snort log only
        function refreshSnortLog() {
            showNotification('Refreshing Snort log...');
            setTimeout(function() {
                window.location.reload();
            }, 500);
        }
        
        // Refresh attackers list only
        function refreshTopAttackers() {
            showNotification('Refreshing attackers list...');
            setTimeout(function() {
                window.location.reload();
            }, 500);
        }
        
        // Countdown for auto refresh
        var seconds = 60;
        function updateCountdown() {
            var countdownElement = document.getElementById('countdown');
            if (countdownElement) {
                countdownElement.textContent = seconds;
                seconds--;
                
                if (seconds < 0) {
                    seconds = 60;
                    refreshData();
                }
            }
        }
        
        // Restore active tab from localStorage
        function initPage() {
            try {
                var activeTab = localStorage.getItem('activeTab') || 'attacks';
                switchTab(activeTab);
            } catch(e) {
                switchTab('attacks');
            }
            
            // Start countdown
            setInterval(updateCountdown, 1000);
            
            // Auto scroll to bottom of Snort log if there are many lines
            var snortContent = document.getElementById('snortLogContent');
            if (snortContent && snortContent.scrollHeight > snortContent.clientHeight) {
                snortContent.scrollTop = snortContent.scrollHeight;
            }
            
            // Initialize search/filter functionality for top attackers table
            initTopAttackersTable();
        }
        
        // Initialize top attackers table search functionality
        function initTopAttackersTable() {
            // Add keyboard navigation for top attackers table
            var attackerRows = document.querySelectorAll('.attacker-row');
            attackerRows.forEach(function(row) {
                row.addEventListener('dblclick', function() {
                    var ip = this.getAttribute('data-ip');
                    if (ip) {
                        searchIPInSnort(ip);
                    }
                });
            });
        }
        
        // Initialize page when DOM is loaded
        if (document.addEventListener) {
            document.addEventListener('DOMContentLoaded', initPage);
        } else if (document.attachEvent) {
            document.attachEvent('onreadystatechange', function() {
                if (document.readyState === 'complete') {
                    initPage();
                }
            });
        } else {
            window.onload = initPage;
        }
        
        // Auto refresh every 60 seconds
        setInterval(refreshData, 60000);
        
        // Refresh attackers list every 60 seconds
        setInterval(refreshTopAttackers, 60000);
        
        // Improved keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            // Ctrl+F for search
            if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
                e.preventDefault();
                var activeTab = localStorage.getItem('activeTab') || 'attacks';
                if (activeTab === 'attacks') {
                    document.getElementById('searchInput').focus();
                } else {
                    document.getElementById('snortSearchInput').focus();
                }
            }
            // Escape to clear search
            if (e.key === 'Escape') {
                document.getElementById('searchInput').value = '';
                document.getElementById('snortSearchInput').value = '';
                filterAttacks();
                filterSnortLog();
            }
        });
    </script>
</body>
</html>
"""

# ===== Starting point =====
if __name__ == '__main__':
    # Create and run application
    app = AttackMonitorApp()
    app.run()
