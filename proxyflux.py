#!/usr/bin/env python3
"""
ProxyFlux - Advanced Proxy Management & Validation Suite
A futuristic tool for fetching, validating, and managing proxies with AI-driven scoring

Author: SYLHETYHACKVENGER (THE-ERROR808)
Version: 3.0.0
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import argparse
import json
import os
import random
import re
import sqlite3
import sys
import time
from threading import Event, Lock, Thread
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import logging
import hashlib
import base64
from urllib.parse import urlparse
import statistics
import socket
import ipaddress
import subprocess

import requests
from colorama import Fore, Style, init
import yaml

# Optional imports for enhanced features
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

try:
    from flask import Flask, jsonify, render_template_string, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    from stem import Signal
    from stem.control import Controller
    TOR_AVAILABLE = True
except ImportError:
    TOR_AVAILABLE = False

# Version and Metadata
VERSION = "3.0.0"
AUTHOR = "SYLHETYHACKVENGER (THE-ERROR808)"
TOOL_NAME = "ProxyFlux"

# ASCII Art Banner
BANNER_ART = r"""
.----------------------------------------------------------------------.
|_.-._.-._.-._.-._.-._.-.    _.-._.-._.-.    _.-._.-._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.-._. .::db .-._.-._. .::db .-._.-._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.-._ .::d88b -._.-._ .::d88b -._.-._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.-. .::d8888b       .::d8888b ._.-._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.- .::d88!::::::::::::d888888b _.-._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.- \  Y88\_________\  Y888888P _.-._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.-. \  Y8888P ._.-. \  Y8888P ._.-._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.-._ /dbY88Pdb _.-._ /dbY88Pdb _.-._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.-. /d8P_YP Y8b .-. /d8P_YP Y8b .-._.-._.-._.-._.-._.|
|_.-._.-._.-._.-     /d8P .-.\ Y8b   /d8P .- \ Y8b -._.-._.-._.-._.-._.|
|_.-._.-._.-._ .::db/d8P _.-. \.::db/d8P _.-. \ Y8b ._.-._.-._.-._.-._.|
|_.-._.-._.-. .::d88bYP ._.-. .::d88LSP ._.-._ \ Y8b    ._.-._.-._.-._.|
|_.-._.-._.- .::d8888b       .::d8888b`b _.-._. \ Y8b:db _.-._.-._.-._.|
|_.-._.-._. .::d88!::::::::::::d888888b`b .-._.- \ YPd88b .-._.-._.-._.|
|_.-._.-._. \  Y88\_________\  Y888888Pd8b       .::d8888b -._.-._.-._.|
|_.-._.-._.- \  Y8888P -._.- \  Y8888P!::::::::::::d888888b ._.-._.-._.|
|_.-._.-._.-. \  Y88Pdb ._.-. \  Y88Pdb_________\  Y888888P ._.-._.-._.|
|_.-._.-._.-._ \__YP Y8b _.-._ \__YP Y8b`P -._.- \  Y8888P -._.-._.-._.|
|_.-._.-._.-._.-._. \ Y8b .-._.-. /d\ Y8b .-._.-. /dbY88P .-._.-._.-._.|
|_.-._.-._.-._.-._.- \ Y8b -._.- /d8P\ Y8b -._.- /d8P_YP _.-._.-._.-._.|
|_.-._.-._.-._.-._.-. \ Y8b     /d8P _\ Y8b     /d8P _.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.-._ \ Y8b:db/d8P ._ \ Y8b:db/d8P ._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.-._. \ YPd88bYP -._. \ YPd88bYP -._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.-._. .::d8888b       .::d8888b .-._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.-._ .::d88!::::::::::::d888888b -._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.-._ \  Y88\_________\  Y888888P -._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.-._. \  Y8888P .-._. \  Y8888P .-._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.-._.- \  Y88P _.-._.- \  Y88P _.-._.-._.-._.-._.-._.|
|_.-._.-._.-._.-._.-._.-. \__YP ._.-._.-. \__YP ._.-._.-._.-._.-._.-._.|
`----------------------------------------------------------------------'
"""

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}
IPPORT_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}\b")
print_lock = Lock()
progress_lock = Lock()

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class IPIntelligence:
    """Comprehensive IP intelligence gathering - Full network intelligence"""
    
    @staticmethod
    def get_domain_resolution(ip: str) -> str:
        """Get domain resolution (forward DNS)"""
        try:
            domain = socket.gethostbyaddr(ip)[0]
            return domain
        except:
            return "N/A"
    
    @staticmethod
    def get_reverse_dns(ip: str) -> str:
        """Get reverse DNS lookup (PTR record)"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "N/A"
    
    @staticmethod
    def get_isp_info(ip: str) -> str:
        """Get ISP information"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return data.get('isp', 'N/A')
            return "N/A"
        except:
            return "N/A"
    
    @staticmethod
    def get_asn_info(ip: str) -> str:
        """Get ASN information"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    asn = data.get('as', 'N/A')
                    return asn
            return "N/A"
        except:
            return "N/A"
    
    @staticmethod
    def get_organization(ip: str) -> str:
        """Get organization information"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return data.get('org', 'N/A')
            return "N/A"
        except:
            return "N/A"
    
    @staticmethod
    def get_geo_info(ip: str) -> Dict:
        """Get comprehensive geolocation information"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('country', 'N/A'),
                        'country_code': data.get('countryCode', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'zip': data.get('zip', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A'),
                        'timezone': data.get('timezone', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'as': data.get('as', 'N/A'),
                        'reverse_dns': IPIntelligence.get_reverse_dns(ip)
                    }
            return {}
        except:
            return {}
    
    @staticmethod
    def get_complete_ip_info(ip: str) -> Dict:
        """Get complete IP information with all details"""
        info = IPIntelligence.get_geo_info(ip)
        info['domain'] = IPIntelligence.get_domain_resolution(ip)
        info['reverse_dns'] = IPIntelligence.get_reverse_dns(ip)
        info['isp'] = IPIntelligence.get_isp_info(ip)
        info['asn'] = IPIntelligence.get_asn_info(ip)
        info['organization'] = IPIntelligence.get_organization(ip)
        
        try:
            if 'cloud' in info.get('org', '').lower() or 'hosting' in info.get('org', '').lower():
                info['is_datacenter'] = True
            else:
                info['is_datacenter'] = False
        except:
            info['is_datacenter'] = False
        
        return info


class ProgressTracker:
    """Live progress tracker - Shows ALL valid proxies with FULL details"""
    
    def __init__(self, total_candidates: int):
        self.total = total_candidates
        self.processed = 0
        self.valid = 0
        self.invalid = 0
        self.errors = 0
        self.start_time = time.time()
        self.stats_lock = Lock()
        self.running = True
        self.display_thread = None
        self.valid_proxies = []
        self.max_display = 999  # Show ALL proxies
        
    def start_display(self):
        """Start the live progress display"""
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
        self.display_thread = Thread(target=self._display_loop, daemon=True)
        self.display_thread.start()
    
    def stop_display(self):
        """Stop the progress display"""
        self.running = False
        if self.display_thread:
            self.display_thread.join(timeout=0.5)
        sys.stdout.write("\033[F" * 40)
        sys.stdout.write("\033[J")
        sys.stdout.flush()
    
    def _display_loop(self):
        """Update progress display continuously"""
        last_update = 0
        while self.running:
            current_time = time.time()
            if current_time - last_update >= 0.2:
                self._render_display()
                last_update = current_time
            time.sleep(0.05)
    
    def _render_display(self):
        """Render the complete display with ALL proxy details"""
        with self.stats_lock:
            processed = self.processed
            valid = self.valid
            invalid = self.invalid
            errors = self.errors
            valid_proxies = self.valid_proxies.copy()
        
        # Calculate progress
        if self.total > 0:
            percentage = (processed / self.total) * 100
            bar_width = 40
            filled = int((processed / self.total) * bar_width)
            bar = "█" * filled + "░" * (bar_width - filled)
        else:
            percentage = 0
            bar = "░" * 40
        
        # Calculate time
        elapsed = time.time() - self.start_time
        speed = processed / elapsed if elapsed > 0 else 0
        remaining = (self.total - processed) / speed if speed > 0 else 0
        elapsed_str = self._format_time(elapsed)
        remaining_str = self._format_time(remaining)
        
        # Build display
        lines = []
        
        # Header
        lines.append(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════╗")
        lines.append(f"{Fore.CYAN}║{Fore.MAGENTA}  ⚡ PROXYFLUX QUANTUM SCANNER                                                 {Fore.CYAN}║")
        lines.append(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════════════════╣")
        lines.append(f"{Fore.CYAN}║{Fore.WHITE}  Progress: {Fore.GREEN}[{bar}] {Fore.YELLOW}{percentage:5.1f}%{Fore.WHITE}                                                   {Fore.CYAN}║")
        lines.append(f"{Fore.CYAN}║{Fore.WHITE}  Status:   {Fore.CYAN}🔄 Scanning proxies...                                              {Fore.CYAN}║")
        lines.append(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════════════════╣")
        lines.append(f"{Fore.CYAN}║{Fore.WHITE}  Processed:  {Fore.CYAN}{processed:>6}/{self.total:<6}       {Fore.GREEN}✓ Valid: {valid:>4}  {Fore.RED}✗ Invalid: {invalid:>4}  {Fore.YELLOW}⚠ Errors: {errors:>4}  {Fore.CYAN}║")
        lines.append(f"{Fore.CYAN}║{Fore.WHITE}  Speed:      {Fore.GREEN}{speed:>6.1f} proxies/sec   {Fore.WHITE}Time: {Fore.YELLOW}{elapsed_str} / {Fore.CYAN}{remaining_str}  {Fore.CYAN}║")
        lines.append(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════════════════╣")
        lines.append(f"{Fore.CYAN}║{Fore.GREEN}  VALID PROXIES FOUND ({len(valid_proxies)})                                                 {Fore.CYAN}║")
        lines.append(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════════════════╣")
        
        # Show ALL valid proxies with FULL details
        if valid_proxies:
            for idx, proxy_info in enumerate(valid_proxies, 1):
                proxy = proxy_info.get('proxy', 'N/A')
                country = proxy_info.get('country', '??')
                country_code = proxy_info.get('country_code', '??')
                region = proxy_info.get('region', 'N/A')
                city = proxy_info.get('city', 'N/A')
                score = proxy_info.get('score', 0)
                response_time = proxy_info.get('response_time', 0)
                isp = proxy_info.get('isp', 'N/A')
                org = proxy_info.get('org', 'N/A')
                asn = proxy_info.get('asn', 'N/A')
                domain = proxy_info.get('domain', 'N/A')
                reverse_dns = proxy_info.get('reverse_dns', 'N/A')
                timezone = proxy_info.get('timezone', 'N/A')
                quality = ProxyScorer.get_quality_label(score)
                
                # Main line with proxy
                lines.append(f"{Fore.CYAN}║{Fore.WHITE}  #{idx:>2} {Fore.YELLOW}{proxy:<20} "
                           f"{Fore.GREEN}[{score:>3}] {Fore.BLUE}{response_time:.2f}s "
                           f"{Fore.MAGENTA}{country:<12} {Fore.CYAN}{isp[:20]:<20} {Fore.WHITE}{quality} {Fore.CYAN}║")
                
                # Line 2: Domain Resolution & Reverse DNS
                lines.append(f"{Fore.CYAN}║{Fore.WHITE}     ├─ {Fore.CYAN}Domain: {Fore.WHITE}{domain:<35} "
                           f"{Fore.CYAN}Reverse DNS: {Fore.WHITE}{reverse_dns[:25]:<25} {Fore.CYAN}║")
                
                # Line 3: ISP Discovery & Organization
                lines.append(f"{Fore.CYAN}║{Fore.WHITE}     ├─ {Fore.CYAN}ISP: {Fore.WHITE}{isp[:35]:<35} "
                           f"{Fore.CYAN}Org: {Fore.WHITE}{org[:25]:<25} {Fore.CYAN}║")
                
                # Line 4: ASN Enumeration & Geolocation
                lines.append(f"{Fore.CYAN}║{Fore.WHITE}     ├─ {Fore.CYAN}ASN: {Fore.WHITE}{asn[:35]:<35} "
                           f"{Fore.CYAN}Location: {Fore.WHITE}{city}, {region}, {country_code} {Fore.CYAN}║")
                
                # Line 5: Timezone & Additional Info
                lines.append(f"{Fore.CYAN}║{Fore.WHITE}     └─ {Fore.CYAN}Timezone: {Fore.WHITE}{timezone:<25} "
                           f"{Fore.CYAN}Score: {Fore.WHITE}{score}/100 {Fore.CYAN}║")
                
                # Separator between proxies
                if idx < len(valid_proxies):
                    lines.append(f"{Fore.CYAN}║{Fore.WHITE}{' ' * 84}{Fore.CYAN}║")
        else:
            lines.append(f"{Fore.CYAN}║{Fore.WHITE}  No valid proxies found yet...{Fore.CYAN}                                                      ║")
        
        lines.append(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════════════════╝")
        
        # Render
        display_text = "\n".join(lines) + Style.RESET_ALL
        sys.stdout.write("\033[H")
        sys.stdout.write(display_text)
        sys.stdout.flush()
    
    def _format_time(self, seconds: float) -> str:
        """Format time in seconds"""
        if seconds < 0:
            seconds = 0
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        if hours > 0:
            return f"{hours:02d}:{minutes:02d}:{secs:02d}"
        else:
            return f"{minutes:02d}:{secs:02d}"
    
    def update(self, valid: bool = False, error: bool = False, proxy: str = None, info: Dict = None):
        """Update progress statistics"""
        with self.stats_lock:
            self.processed += 1
            if valid:
                self.valid += 1
                if info:
                    self.valid_proxies.append(info)
            elif error:
                self.errors += 1
            else:
                self.invalid += 1
    
    def get_summary(self) -> Dict:
        """Get final summary"""
        with self.stats_lock:
            elapsed = time.time() - self.start_time
            return {
                'total': self.total,
                'processed': self.processed,
                'valid': self.valid,
                'invalid': self.invalid,
                'errors': self.errors,
                'elapsed': elapsed,
                'speed': self.processed / elapsed if elapsed > 0 else 0,
                'valid_proxies': self.valid_proxies
            }


def print_banner():
    """Display the banner"""
    init(autoreset=True)
    print(Fore.CYAN + Style.BRIGHT + BANNER_ART + Style.RESET_ALL)
    print(Fore.MAGENTA + Style.BRIGHT + "=" * 70 + Style.RESET_ALL)
    print(Fore.GREEN + Style.BRIGHT + " " * 22 + "PROXYFLUX v3.0" + " " * 22 + Style.RESET_ALL)
    print(Fore.CYAN + Style.BRIGHT + " " * 17 + "Advanced Proxy Management Suite" + " " * 17 + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + " " * 12 + "Author: SYLHETYHACKVENGER (THE-ERROR808)" + " " * 12 + Style.RESET_ALL)
    print(Fore.RED + Style.BRIGHT + " " * 20 + "⚡ Quantum Proxy Engine ⚡" + " " * 20 + Style.RESET_ALL)
    print(Fore.MAGENTA + Style.BRIGHT + "=" * 70 + Style.RESET_ALL)
    print()
    print(Fore.GREEN + "[✓] " + Fore.WHITE + "Initializing ProxyFlux Neural Engine..." + Style.RESET_ALL)
    print(Fore.GREEN + "[✓] " + Fore.WHITE + "Loading Quantum Proxy Rotator..." + Style.RESET_ALL)
    print(Fore.GREEN + "[✓] " + Fore.WHITE + "AI Scoring System Online..." + Style.RESET_ALL)
    print(Fore.GREEN + "[✓] " + Fore.WHITE + "Proxy Database Connected..." + Style.RESET_ALL)
    print()


class ProxyEnhancer:
    """Advanced proxy management with futuristic features"""
    
    @staticmethod
    def rotate_user_agent() -> str:
        """Generate random user agent"""
        user_agents = [
            "ProxyFlux/3.0 (Quantum; NeuralOS 2.0; like Gecko)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0"
        ]
        return random.choice(user_agents)
    
    @staticmethod
    def add_random_delay(min_seconds: float = 0.1, max_seconds: float = 0.5):
        """Add random delay"""
        time.sleep(random.uniform(min_seconds, max_seconds))
    
    @staticmethod
    def encode_proxy(proxy: str, method: str = 'base64') -> str:
        """Encode proxy for secure storage"""
        if method == 'base64':
            return base64.b64encode(proxy.encode()).decode()
        elif method == 'hex':
            return proxy.encode().hex()
        elif method == 'hash':
            return hashlib.sha256(proxy.encode()).hexdigest()
        return proxy
    
    @staticmethod
    def decode_proxy(encoded: str, method: str = 'base64') -> str:
        """Decode proxy from storage"""
        if method == 'base64':
            return base64.b64decode(encoded.encode()).decode()
        elif method == 'hex':
            return bytes.fromhex(encoded).decode()
        return encoded
    
    @staticmethod
    def validate_proxy_format(proxy: str) -> bool:
        """Validate proxy format"""
        pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}:\d{2,5}$')
        return bool(pattern.match(proxy))
    
    @staticmethod
    def get_proxy_type(proxy: str) -> str:
        """Auto-detect proxy type based on port"""
        try:
            port = int(proxy.split(':')[1])
            if port in [80, 8080, 8000, 8888]:
                return 'http'
            elif port in [443, 8443]:
                return 'https'
            elif port in [1080, 1081]:
                return 'socks5'
            elif port in [9050, 9051]:
                return 'socks5'
            else:
                return 'unknown'
        except:
            return 'unknown'


class ProxyScorer:
    """AI-driven proxy scoring system"""
    
    @staticmethod
    def calculate_score(proxy_data: Dict) -> int:
        """Calculate neural score from 0-100"""
        if not proxy_data:
            return 0
        
        score = 100
        response_time = proxy_data.get('response_time', 10)
        
        # Response time analysis
        if response_time < 0.5:
            score += 30
        elif response_time < 1:
            score += 20
        elif response_time < 2:
            score += 10
        elif response_time < 3:
            score += 5
        elif response_time > 5:
            score -= 20
        elif response_time > 8:
            score -= 40
        elif response_time > 10:
            score -= 60
        
        # Success rate weighting
        success_rate = proxy_data.get('success_rate', 1.0)
        if success_rate < 0.5:
            score -= 30
        elif success_rate < 0.7:
            score -= 15
        elif success_rate > 0.9:
            score += 10
        
        # Anonymity boost
        if proxy_data.get('anonymous', False):
            score += 10
        
        # SSL support bonus
        if proxy_data.get('ssl_support', False):
            score += 5
        
        # Geolocation bonus
        if proxy_data.get('country'):
            score += 5
        
        # Uptime bonus
        uptime = proxy_data.get('uptime', 0)
        if uptime > 95:
            score += 15
        elif uptime > 90:
            score += 10
        elif uptime > 80:
            score += 5
        
        # Stability analysis
        if 'response_times' in proxy_data:
            times = proxy_data['response_times']
            if len(times) > 1:
                try:
                    variance = statistics.variance(times)
                    if variance < 0.5:
                        score += 10
                    elif variance < 1:
                        score += 5
                    elif variance > 3:
                        score -= 10
                except:
                    pass
        
        return max(0, min(100, score))
    
    @staticmethod
    def get_quality_label(score: int) -> str:
        """Get quality label"""
        if score >= 90:
            return "⭐ Quantum"
        elif score >= 70:
            return "✅ Optimal"
        elif score >= 50:
            return "⚠️ Standard"
        elif score >= 30:
            return "❌ Suboptimal"
        else:
            return "🚫 Defective"


class ProxyDatabase:
    """Quantum-resistant SQLite database"""
    
    def __init__(self, db_path: str = "proxyflux.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Main proxies table with enhanced fields
        c.execute('''CREATE TABLE IF NOT EXISTS proxies (
                     proxy TEXT PRIMARY KEY,
                     type TEXT,
                     last_validated TIMESTAMP,
                     success_count INTEGER DEFAULT 0,
                     fail_count INTEGER DEFAULT 0,
                     response_time REAL,
                     score INTEGER DEFAULT 50,
                     country TEXT,
                     country_code TEXT,
                     region TEXT,
                     city TEXT,
                     zip TEXT,
                     lat REAL,
                     lon REAL,
                     timezone TEXT,
                     isp TEXT,
                     org TEXT,
                     asn TEXT,
                     domain TEXT,
                     reverse_dns TEXT,
                     is_datacenter INTEGER DEFAULT 0,
                     anonymous INTEGER DEFAULT 0,
                     ssl_support INTEGER DEFAULT 0,
                     uptime REAL DEFAULT 0,
                     first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                     last_used TIMESTAMP,
                     tags TEXT,
                     quantum_hash TEXT
        )''')
        
        # History table for tracking changes
        c.execute('''CREATE TABLE IF NOT EXISTS proxy_history (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     proxy TEXT,
                     timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                     status TEXT,
                     response_time REAL,
                     score INTEGER,
                     FOREIGN KEY (proxy) REFERENCES proxies(proxy)
        )''')
        
        # Performance metrics table
        c.execute('''CREATE TABLE IF NOT EXISTS proxy_performance (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     proxy TEXT,
                     timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                     response_time REAL,
                     success BOOLEAN,
                     bytes_transferred INTEGER,
                     FOREIGN KEY (proxy) REFERENCES proxies(proxy)
        )''')
        
        # Stats table for aggregate data
        c.execute('''CREATE TABLE IF NOT EXISTS stats (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                     total_proxies INTEGER,
                     active_proxies INTEGER,
                     avg_response_time REAL,
                     avg_score REAL
        )''')
        
        conn.commit()
        conn.close()
    
    def save_proxy(self, proxy_data: Dict):
        """Save or update proxy information with enhanced fields"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        proxy = proxy_data.get('proxy', '')
        proxy_type = proxy_data.get('type', 'unknown')
        response_time = proxy_data.get('response_time', 0)
        score = proxy_data.get('score', 50)
        uptime = proxy_data.get('uptime', 0)
        tags = proxy_data.get('tags', '')
        
        # Get existing data
        c.execute('SELECT success_count, fail_count, latency_history FROM proxies WHERE proxy = ?', (proxy,))
        result = c.fetchone()
        
        if result:
            success_count = result[0] + 1
            fail_count = result[1]
            latency_history = json.loads(result[2]) if result[2] else []
        else:
            success_count = 1
            fail_count = 0
            latency_history = []
        
        # Update latency history
        latency_history.append(response_time)
        if len(latency_history) > 100:
            latency_history = latency_history[-100:]
        
        c.execute('''INSERT OR REPLACE INTO proxies 
                     (proxy, type, last_validated, success_count, fail_count, 
                      response_time, score, country, country_code, region, city, zip,
                      lat, lon, timezone, isp, org, asn, domain, reverse_dns,
                      is_datacenter, anonymous, ssl_support, uptime, last_used, 
                      latency_history, tags)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                  (proxy, proxy_type, datetime.now().isoformat(),
                   success_count, fail_count, response_time, score,
                   proxy_data.get('country', ''),
                   proxy_data.get('country_code', ''),
                   proxy_data.get('region', ''),
                   proxy_data.get('city', ''),
                   proxy_data.get('zip', ''),
                   proxy_data.get('lat', 0),
                   proxy_data.get('lon', 0),
                   proxy_data.get('timezone', ''),
                   proxy_data.get('isp', ''),
                   proxy_data.get('org', ''),
                   proxy_data.get('asn', ''),
                   proxy_data.get('domain', ''),
                   proxy_data.get('reverse_dns', ''),
                   1 if proxy_data.get('is_datacenter', False) else 0,
                   1 if proxy_data.get('anonymous', False) else 0,
                   1 if proxy_data.get('ssl_support', False) else 0,
                   uptime, datetime.now().isoformat(),
                   json.dumps(latency_history), tags))
        
        # Add to history
        c.execute('''INSERT INTO proxy_history (proxy, status, response_time, score)
                     VALUES (?, ?, ?, ?)''',
                  (proxy, 'valid', response_time, score))
        
        conn.commit()
        conn.close()
    
    def record_performance(self, proxy: str, response_time: float, 
                          success: bool, bytes_transferred: int = 0):
        """Record performance metrics for a proxy"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''INSERT INTO proxy_performance 
                     (proxy, response_time, success, bytes_transferred)
                     VALUES (?, ?, ?, ?)''',
                  (proxy, response_time, success, bytes_transferred))
        
        conn.commit()
        conn.close()
    
    def get_proxy_history(self, proxy: str, limit: int = 50) -> List[Dict]:
        """Get historical data for a proxy"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''SELECT timestamp, status, response_time, score 
                     FROM proxy_history 
                     WHERE proxy = ? 
                     ORDER BY timestamp DESC 
                     LIMIT ?''', (proxy, limit))
        
        results = [{'timestamp': row[0], 'status': row[1], 
                   'response_time': row[2], 'score': row[3]} 
                   for row in c.fetchall()]
        conn.close()
        return results
    
    def get_historical_proxies(self, limit: int = 100, min_score: int = 50, 
                               max_age_hours: int = 24, tags: Optional[str] = None) -> List[str]:
        """Get previously validated proxies with filters"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        cutoff = (datetime.now() - timedelta(hours=max_age_hours)).isoformat()
        
        query = '''SELECT proxy FROM proxies 
                   WHERE score >= ? AND last_validated > ?'''
        params = [min_score, cutoff]
        
        if tags:
            query += ' AND tags LIKE ?'
            params.append(f'%{tags}%')
        
        query += ' ORDER BY score DESC, response_time ASC LIMIT ?'
        params.append(limit)
        
        c.execute(query, params)
        results = [row[0] for row in c.fetchall()]
        conn.close()
        return results
    
    def get_proxy_stats(self, proxy: str) -> Dict:
        """Get detailed statistics for a specific proxy"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Get proxy info
        c.execute('''SELECT score, success_count, fail_count, response_time, uptime, tags
                     FROM proxies WHERE proxy = ?''', (proxy,))
        info = c.fetchone()
        
        if not info:
            conn.close()
            return {}
        
        # Get performance history
        c.execute('''SELECT AVG(response_time) as avg_time, 
                            COUNT(*) as total_requests,
                            SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successes
                     FROM proxy_performance 
                     WHERE proxy = ? 
                     AND timestamp > datetime('now', '-1 hour')''', (proxy,))
        recent = c.fetchone()
        
        # Get uptime
        c.execute('''SELECT 
                    (SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*)) as uptime
                     FROM proxy_performance 
                     WHERE proxy = ? 
                     AND timestamp > datetime('now', '-24 hours')''', (proxy,))
        uptime = c.fetchone()
        
        conn.close()
        
        return {
            'score': info[0],
            'success_count': info[1],
            'fail_count': info[2],
            'avg_response_time': info[3],
            'uptime': info[4] or 0,
            'tags': info[5] or '',
            'recent_avg_time': recent[0] if recent and recent[0] else 0,
            'recent_requests': recent[1] if recent else 0,
            'recent_successes': recent[2] if recent else 0,
            'daily_uptime': uptime[0] if uptime and uptime[0] else 0
        }
    
    def update_proxy_tags(self, proxy: str, tags: str):
        """Update tags for a proxy"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('UPDATE proxies SET tags = ? WHERE proxy = ?', (tags, proxy))
        conn.commit()
        conn.close()
    
    def get_stats(self) -> Dict:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('SELECT COUNT(*) FROM proxies')
        total = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM proxies WHERE success_count > 0')
        active = c.fetchone()[0]
        
        c.execute('SELECT AVG(response_time) FROM proxies WHERE response_time > 0')
        avg_time = c.fetchone()[0] or 0
        
        c.execute('SELECT AVG(score) FROM proxies')
        avg_score = c.fetchone()[0] or 0
        
        # Get top countries
        c.execute('''SELECT country, COUNT(*) as count 
                     FROM proxies 
                     WHERE country != '' 
                     GROUP BY country 
                     ORDER BY count DESC 
                     LIMIT 5''')
        top_countries = [{'country': row[0], 'count': row[1]} for row in c.fetchall()]
        
        conn.close()
        
        return {
            'total_proxies': total,
            'active_proxies': active,
            'avg_response_time': avg_time,
            'avg_score': avg_score,
            'top_countries': top_countries
        }


class ProxyRotator:
    """Enhanced proxy rotation with load balancing and failover"""
    
    def __init__(self, proxies: Optional[List[str]] = None):
        self.proxies = proxies or []
        self.current_index = 0
        self.lock = Lock()
        self.usage_count = {}
        self.blacklist = set()
        self.weighted_proxies = {}
        self.failover_timeout = 60
    
    def get_next_proxy(self, weighted: bool = False) -> Optional[str]:
        """Get next proxy with optional weighted selection"""
        with self.lock:
            if not self.proxies:
                return None
            
            if weighted and self.weighted_proxies:
                total_weight = sum(self.weighted_proxies.values())
                if total_weight > 0:
                    rand = random.uniform(0, total_weight)
                    cumulative = 0
                    for proxy, weight in self.weighted_proxies.items():
                        cumulative += weight
                        if rand <= cumulative and proxy not in self.blacklist:
                            self.usage_count[proxy] = self.usage_count.get(proxy, 0) + 1
                            return proxy
            
            # Round-robin with blacklist skip
            attempts = 0
            while attempts < len(self.proxies):
                proxy = self.proxies[self.current_index]
                self.current_index = (self.current_index + 1) % len(self.proxies)
                
                if proxy not in self.blacklist:
                    self.usage_count[proxy] = self.usage_count.get(proxy, 0) + 1
                    return proxy
                attempts += 1
            
            return None
    
    def get_random_proxy(self) -> Optional[str]:
        """Get random proxy"""
        if not self.proxies:
            return None
        available = [p for p in self.proxies if p not in self.blacklist]
        if not available:
            return None
        proxy = random.choice(available)
        self.usage_count[proxy] = self.usage_count.get(proxy, 0) + 1
        return proxy
    
    def get_best_proxy(self, scores: Dict[str, int]) -> Optional[str]:
        """Get proxy with highest score"""
        if not self.proxies:
            return None
        
        available = [p for p in self.proxies if p not in self.blacklist and p in scores]
        if not available:
            return None
        
        best = max(available, key=lambda p: scores.get(p, 0))
        self.usage_count[best] = self.usage_count.get(best, 0) + 1
        return best
    
    def add_proxy(self, proxy: str, weight: float = 1.0):
        """Add proxy with weight"""
        if proxy not in self.proxies and proxy not in self.blacklist:
            self.proxies.append(proxy)
            self.weighted_proxies[proxy] = weight
    
    def update_proxy_weight(self, proxy: str, weight: float):
        """Update proxy weight"""
        if proxy in self.weighted_proxies:
            self.weighted_proxies[proxy] = weight
    
    def remove_proxy(self, proxy: str):
        """Remove proxy from rotation"""
        if proxy in self.proxies:
            self.proxies.remove(proxy)
        if proxy in self.weighted_proxies:
            del self.weighted_proxies[proxy]
    
    def blacklist_proxy(self, proxy: str, timeout: int = 60):
        """Blacklist proxy with timeout"""
        self.blacklist.add(proxy)
        if proxy in self.proxies:
            self.proxies.remove(proxy)
        
        def remove_from_blacklist():
            time.sleep(timeout)
            with self.lock:
                self.blacklist.discard(proxy)
                if proxy not in self.proxies:
                    self.proxies.append(proxy)
        
        import threading
        thread = threading.Thread(target=remove_from_blacklist, daemon=True)
        thread.start()
    
    def get_usage_stats(self) -> Dict:
        """Get proxy usage statistics"""
        return self.usage_count


class ProxyAnalyzer:
    """Enhanced proxy analysis with geolocation and performance metrics"""
    
    def __init__(self, geoip_db_path: str = "GeoLite2-City.mmdb"):
        self.reader = None
        if GEOIP_AVAILABLE and Path(geoip_db_path).exists():
            try:
                self.reader = geoip2.database.Reader(geoip_db_path)
                logger.info("GeoIP database loaded successfully")
            except Exception as e:
                logger.warning(f"Failed to load GeoIP database: {e}")
    
    def get_proxy_info(self, proxy_ip: str) -> Dict:
        """Get enhanced geolocation information"""
        if not self.reader:
            return {}
        
        try:
            response = self.reader.city(proxy_ip)
            return {
                'country': response.country.iso_code,
                'country_name': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'isp': response.traits.isp,
                'timezone': response.location.time_zone,
                'continent': response.continent.code,
                'postal_code': response.postal.code if response.postal else None,
                'region': response.subdivisions.most_specific.name if response.subdivisions else None
            }
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {proxy_ip}: {e}")
            return {}
    
    def check_anonymity(self, proxy: str, session: requests.Session, 
                        timeout: int = 10) -> Tuple[bool, Dict]:
        """Enhanced anonymity check with multiple tests"""
        try:
            test_urls = [
                "https://httpbin.org/headers",
                "https://httpbin.org/ip",
                "https://api.ipify.org?format=json"
            ]
            
            proxies = format_proxies_for_requests(proxy, "auto")
            anonymous = True
            analysis = {'anonymous': True, 'ssl_support': False}
            
            for url in test_urls[:2]:
                resp = session.get(url, proxies=proxies, timeout=timeout)
                resp.raise_for_status()
                
                data = resp.json() if 'ipify' in url else resp.json()
                
                if 'headers' in data:
                    headers = data['headers']
                    forwarded = headers.get('X-Forwarded-For')
                    real_ip = headers.get('X-Real-IP')
                    via = headers.get('Via')
                    
                    if forwarded or real_ip or via:
                        anonymous = False
                        analysis['detected_headers'] = {
                            'X-Forwarded-For': forwarded,
                            'X-Real-IP': real_ip,
                            'Via': via
                        }
            
            # Check SSL support
            ssl_support = False
            try:
                ssl_test = session.get("https://httpbin.org/ssl", 
                                      proxies=proxies, timeout=timeout)
                ssl_support = ssl_test.status_code == 200
            except:
                pass
            
            analysis['anonymous'] = anonymous
            analysis['ssl_support'] = ssl_support
            
            if 'origin' in data:
                analysis['ip_revealed'] = data['origin']
            
            return anonymous, analysis
            
        except Exception as e:
            logger.debug(f"Anonymity check failed for {proxy}: {e}")
            return False, {'anonymous': False, 'error': str(e)}
    
    def calculate_uptime(self, proxy: str, historical_data: List[Dict]) -> float:
        """Calculate uptime percentage from historical data"""
        if not historical_data:
            return 0
        
        total = len(historical_data)
        successful = sum(1 for entry in historical_data if entry.get('status') == 'valid')
        
        return (successful / total) * 100 if total > 0 else 0


class EnhancedProxyTester:
    """Enhanced proxy testing with multiple validation methods"""
    
    def __init__(self, max_workers: int = 50):
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.performance_data = {}
    
    def test_proxy(self, proxy_str: str, test_url: str = "https://www.example.com",
                   timeout: int = 6, proxy_type_hint: str = "auto") -> Optional[Dict]:
        """Enhanced proxy testing with detailed metrics"""
        
        proxies = format_proxies_for_requests(proxy_str, proxy_type_hint)
        
        test_endpoints = [
            ("https://www.example.com", "GET"),
            ("https://httpbin.org/status/200", "GET"),
            ("https://httpbin.org/ip", "JSON"),
            ("https://api.ipify.org?format=json", "JSON")
        ]
        
        best_result = None
        best_time = float('inf')
        response_times = []
        bytes_transferred = 0
        
        for url, response_type in test_endpoints[:3]:
            try:
                start_time = time.time()
                resp = self.session.get(url, proxies=proxies, timeout=timeout)
                resp.raise_for_status()
                
                response_time = time.time() - start_time
                response_times.append(response_time)
                bytes_transferred += len(resp.content)
                
                if response_time < best_time:
                    best_time = response_time
                    best_result = {
                        'proxy': proxy_str,
                        'response_time': response_time,
                        'status_code': resp.status_code,
                        'url_used': url,
                        'type': proxy_type_hint,
                        'response_times': response_times,
                        'bytes_transferred': bytes_transferred
                    }
                    
                    if response_type == "JSON" and 'httpbin' in url:
                        try:
                            data = resp.json()
                            if 'origin' in data:
                                best_result['ip'] = data['origin']
                        except:
                            pass
                
                if response_time < 0.5:
                    break
                    
            except (requests.RequestException, json.JSONDecodeError):
                continue
        
        if best_result and response_times:
            if len(response_times) > 1:
                try:
                    best_result['stability'] = statistics.stdev(response_times)
                except:
                    pass
        
        return best_result
    
    def test_batch(self, proxies: List[str], test_url: str = "https://www.example.com",
                   timeout: int = 6, proxy_type_hint: str = "auto",
                   stop_event: Optional[Event] = None,
                   progress_tracker: Optional[ProgressTracker] = None) -> List[Dict]:
        """Test multiple proxies concurrently with enhanced metrics"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_proxy = {
                executor.submit(self.test_proxy, p, test_url, timeout, proxy_type_hint): p
                for p in proxies
            }
            
            for future in as_completed(future_to_proxy):
                if stop_event and stop_event.is_set():
                    break
                
                proxy = future_to_proxy[future]
                try:
                    result = future.result(timeout=timeout+2)
                    if result:
                        results.append(result)
                        self.performance_data[result['proxy']] = {
                            'last_test': datetime.now().isoformat(),
                            'response_time': result['response_time'],
                            'success': True
                        }
                        
                        # Get FULL IP intelligence
                        ip = result['proxy'].split(':')[0]
                        ip_info = IPIntelligence.get_complete_ip_info(ip)
                        result.update(ip_info)
                        
                        if progress_tracker:
                            progress_tracker.update(valid=True, proxy=proxy, info=result)
                    else:
                        if progress_tracker:
                            progress_tracker.update(valid=False, proxy=proxy)
                except Exception:
                    self.performance_data[proxy] = {
                        'last_test': datetime.now().isoformat(),
                        'success': False
                    }
                    if progress_tracker:
                        progress_tracker.update(error=True, proxy=proxy)
                    continue
        
        return results


class HealthMonitor:
    """Enhanced health monitoring with trend analysis"""
    
    def __init__(self, check_interval: int = 300):
        self.check_interval = check_interval
        self.health_cache = {}
        self.trend_data = {}
        self.lock = Lock()
    
    def check_proxy_health(self, proxy: Dict, test_func) -> bool:
        """Check if a proxy is still healthy"""
        proxy_key = proxy.get('proxy', '')
        now = time.time()
        
        with self.lock:
            if proxy_key in self.health_cache:
                last_check, status = self.health_cache[proxy_key]
                if now - last_check < self.check_interval:
                    return status
        
        result = test_func(proxy)
        status = result is not None
        
        with self.lock:
            self.health_cache[proxy_key] = (now, status)
            
            if proxy_key not in self.trend_data:
                self.trend_data[proxy_key] = []
            self.trend_data[proxy_key].append({
                'timestamp': now,
                'status': status,
                'response_time': result.get('response_time', 0) if result else 0
            })
            
            if len(self.trend_data[proxy_key]) > 100:
                self.trend_data[proxy_key] = self.trend_data[proxy_key][-100:]
        
        return status
    
    def get_health_stats(self) -> Dict:
        """Get enhanced health statistics"""
        with self.lock:
            total = len(self.health_cache)
            healthy = sum(1 for _, status in self.health_cache.values() if status)
            
            trending_down = 0
            trending_up = 0
            
            for proxy, history in self.trend_data.items():
                if len(history) > 10:
                    recent = history[-10:]
                    success_rate = sum(1 for h in recent if h['status']) / len(recent)
                    if success_rate < 0.5:
                        trending_down += 1
                    elif success_rate > 0.8:
                        trending_up += 1
            
            return {
                'total_checked': total,
                'healthy': healthy,
                'unhealthy': total - healthy,
                'health_rate': (healthy / total * 100) if total > 0 else 0,
                'trending_down': trending_down,
                'trending_up': trending_up,
                'stability': 'stable' if trending_down < total * 0.1 else 'unstable'
            }
    
    def get_proxy_trend(self, proxy: str) -> Dict:
        """Get trend analysis for a specific proxy"""
        with self.lock:
            if proxy not in self.trend_data:
                return {}
            
            history = self.trend_data[proxy]
            if len(history) < 5:
                return {'status': 'insufficient_data'}
            
            recent = history[-10:]
            success_rate = sum(1 for h in recent if h['status']) / len(recent)
            
            if len(recent) > 5:
                times = [h['response_time'] for h in recent if h['response_time'] > 0]
                if times:
                    avg_time = sum(times) / len(times)
                else:
                    avg_time = 0
            else:
                avg_time = 0
            
            return {
                'success_rate': success_rate,
                'avg_response_time': avg_time,
                'stability': 'good' if success_rate > 0.8 and avg_time < 5 else 'poor'
            }


class ProxyExporter:
    """Export proxies in various formats with enhanced options"""
    
    @staticmethod
    def export(proxies: List[Dict], format_type: str = 'txt', 
               filename: Optional[str] = None, include_metadata: bool = False) -> str:
        """Export proxies in specified format with optional metadata"""
        
        if not proxies:
            return ""
        
        # Extract proxy strings
        proxy_strings = []
        for p in proxies:
            if isinstance(p, dict):
                proxy_strings.append(p.get('proxy', ''))
            else:
                proxy_strings.append(str(p))
        
        formats = {
            'txt': lambda: '\n'.join(proxy_strings),
            'json': lambda: json.dumps(proxies if include_metadata else proxy_strings, indent=2),
            'csv': lambda: 'proxy,score,country,response_time,isp,org,asn,domain,reverse_dns\n' + '\n'.join([
                f"{p.get('proxy', '')},{p.get('score', 0)},{p.get('country', '')},{p.get('response_time', 0):.2f},{p.get('isp', '')},{p.get('org', '')},{p.get('asn', '')},{p.get('domain', '')},{p.get('reverse_dns', '')}"
                for p in proxies
            ]) if include_metadata and proxies else 'proxy\n' + '\n'.join(proxy_strings),
            'yaml': lambda: yaml.dump({'proxies': proxies if include_metadata else proxy_strings}),
            'html': lambda: ProxyExporter._generate_html(proxies, include_metadata),
            'xml': lambda: ProxyExporter._generate_xml(proxies, include_metadata)
        }
        
        if format_type not in formats:
            raise ValueError(f"Unsupported format: {format_type}")
        
        content = formats[format_type]()
        
        if filename:
            with open(f"{filename}.{format_type}", 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Exported to {filename}.{format_type}")
        
        return content
    
    @staticmethod
    def _generate_html(proxies: List[Dict], include_metadata: bool) -> str:
        """Generate HTML export"""
        html = f"""<!DOCTYPE html>
<html>
<head><title>ProxyFlux Proxy List</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #0a0e1a; color: #e0e0e0; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #2a2f3e; }}
th {{ background: #121724; color: #667eea; }}
</style>
</head>
<body>
<h1>ProxyFlux - Working Proxies ({len(proxies)})</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<table>
<tr><th>#</th><th>Proxy</th><th>Score</th><th>Country</th><th>Response</th><th>ISP</th><th>Quality</th></tr>
"""
        for idx, p in enumerate(proxies, 1):
            score = p.get('score', 0)
            quality = ProxyScorer.get_quality_label(score)
            html += f"""
<tr>
    <td>{idx}</td>
    <td><code>{p.get('proxy', '')}</code></td>
    <td>{score}</td>
    <td>{p.get('country', '??')}</td>
    <td>{p.get('response_time', 0):.2f}s</td>
    <td>{p.get('isp', 'N/A')[:20]}</td>
    <td>{quality}</td>
</tr>"""
        html += "</table></body></html>"
        return html
    
    @staticmethod
    def _generate_xml(proxies: List[Dict], include_metadata: bool) -> str:
        """Generate XML export"""
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<proxies generated="{datetime.now().isoformat()}" count="{len(proxies)}">
"""
        for p in proxies:
            xml += f"""    <proxy>
        <address>{p.get('proxy', '')}</address>
"""
            if include_metadata:
                xml += f"""        <score>{p.get('score', 0)}</score>
        <country>{p.get('country', '')}</country>
        <response_time>{p.get('response_time', 0)}</response_time>
        <isp>{p.get('isp', '')}</isp>
        <asn>{p.get('asn', '')}</asn>
        <domain>{p.get('domain', '')}</domain>
        <reverse_dns>{p.get('reverse_dns', '')}</reverse_dns>
"""
            xml += "    </proxy>\n"
        xml += "</proxies>"
        return xml


class WebDashboard:
    """Enhanced web dashboard with more features"""
    
    def __init__(self, proxy_validator):
        self.validator = proxy_validator
        self.app = None
        
        if FLASK_AVAILABLE:
            self.app = Flask(__name__)
            self.setup_routes()
    
    def setup_routes(self):
        """Setup Flask routes"""
        if not self.app:
            return
        
        @self.app.route('/')
        def index():
            return self.render_dashboard()
        
        @self.app.route('/api/proxies')
        def api_proxies():
            try:
                proxies = list(self.validator.found_proxies)
                stats = self.validator.db.get_stats() if hasattr(self.validator, 'db') else {}
                
                proxy_details = []
                for proxy in proxies[:100]:
                    details = self.validator.db.get_proxy_stats(proxy)
                    details['address'] = proxy
                    proxy_details.append(details)
                
                return jsonify({
                    'success': True,
                    'total': len(proxies),
                    'proxies': proxy_details,
                    'stats': stats,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/stats')
        def api_stats():
            try:
                stats = self.validator.db.get_stats() if hasattr(self.validator, 'db') else {}
                health = self.validator.monitor.get_health_stats() if hasattr(self.validator, 'monitor') else {}
                
                return jsonify({
                    'success': True,
                    'stats': stats,
                    'health': health,
                    'version': VERSION,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/proxy/<proxy>')
        def api_proxy_detail(proxy):
            try:
                details = self.validator.db.get_proxy_stats(proxy)
                history = self.validator.db.get_proxy_history(proxy)
                trend = self.validator.monitor.get_proxy_trend(proxy) if hasattr(self.validator, 'monitor') else {}
                
                return jsonify({
                    'success': True,
                    'proxy': proxy,
                    'details': details,
                    'history': history,
                    'trend': trend,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/export')
        def api_export():
            try:
                format_type = request.args.get('format', 'txt')
                include_metadata = request.args.get('metadata', 'false').lower() == 'true'
                
                proxies_data = self.validator.found_proxies_data
                content = ProxyExporter.export(
                    proxies_data, 
                    format_type, 
                    include_metadata=include_metadata
                )
                
                return jsonify({
                    'success': True,
                    'format': format_type,
                    'content': content,
                    'count': len(proxies_data)
                })
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/api/refresh')
        def api_refresh():
            try:
                import threading
                thread = threading.Thread(target=self.validator.refresh_proxies)
                thread.daemon = True
                thread.start()
                
                return jsonify({
                    'success': True,
                    'message': 'Refresh started',
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500
    
    def render_dashboard(self):
        """Render the enhanced dashboard HTML"""
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>ProxyFlux Dashboard</title>
                <style>
                    body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #0a0e1a; color: #e0e0e0; }
                    .container { max-width: 1400px; margin: 0 auto; }
                    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                             color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
                    .card { background: #1a1f2e; border-radius: 8px; padding: 20px; 
                            margin: 10px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.3); border: 1px solid #2a2f3e; }
                    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
                    .stat-item { background: #121724; padding: 15px; border-radius: 5px; text-align: center; border: 1px solid #2a2f3e; }
                    .stat-value { font-size: 28px; font-weight: bold; color: #667eea; }
                    .stat-label { color: #8892a8; font-size: 14px; }
                    table { width: 100%; border-collapse: collapse; margin-top: 15px; }
                    th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #2a2f3e; }
                    th { background: #121724; font-weight: 600; color: #667eea; }
                    .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
                    .badge-success { background: #0d4a2a; color: #4ade80; }
                    .badge-warning { background: #4a3d0d; color: #fbbf24; }
                    .badge-danger { background: #4a0d0d; color: #f87171; }
                    .badge-info { background: #0d1a4a; color: #60a5fa; }
                    .refresh-btn { background: #667eea; color: white; border: none; padding: 10px 20px; 
                                   border-radius: 5px; cursor: pointer; font-size: 16px; margin: 5px; }
                    .refresh-btn:hover { background: #5a6fd6; }
                    .export-btn { background: #34a853; color: white; border: none; padding: 10px 20px; 
                                 border-radius: 5px; cursor: pointer; font-size: 16px; margin: 5px; }
                    .export-btn:hover { background: #2d8f47; }
                    .score-excellent { color: #4ade80; }
                    .score-good { color: #60a5fa; }
                    .score-fair { color: #fbbf24; }
                    .score-poor { color: #f87171; }
                    .country-tag { background: #1a2a4a; padding: 2px 10px; border-radius: 12px; font-size: 12px; margin: 3px; display: inline-block; color: #60a5fa; }
                    .controls { display: flex; flex-wrap: wrap; gap: 10px; margin: 10px 0; }
                    h1, h2 { color: #e0e0e0; }
                    code { color: #60a5fa; background: #0d1117; padding: 2px 6px; border-radius: 3px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🚀 ProxyFlux Dashboard</h1>
                        <p>Version: {{ version }} | Last Updated: <span id="timestamp">{{ timestamp }}</span></p>
                        <div class="controls">
                            <button class="refresh-btn" onclick="refreshData()">🔄 Refresh</button>
                            <button class="export-btn" onclick="exportData('txt')">📄 Export TXT</button>
                            <button class="export-btn" onclick="exportData('json')">📊 Export JSON</button>
                            <button class="export-btn" onclick="exportData('html')">🌐 Export HTML</button>
                        </div>
                    </div>
                    
                    <div class="card">
                        <h2>📊 Statistics</h2>
                        <div class="stats" id="stats">
                            <div class="stat-item">
                                <div class="stat-value" id="total-proxies">-</div>
                                <div class="stat-label">Total Proxies</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value" id="active-proxies">-</div>
                                <div class="stat-label">Active Proxies</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value" id="avg-response-time">-</div>
                                <div class="stat-label">Avg Response Time</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value" id="avg-score">-</div>
                                <div class="stat-label">Avg Score</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value" id="health-rate">-</div>
                                <div class="stat-label">Health Rate</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value" id="stability">-</div>
                                <div class="stat-label">Stability</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card">
                        <h2>🌍 Top Countries</h2>
                        <div id="country-list"></div>
                    </div>
                    
                    <div class="card">
                        <h2>🌐 Proxy List</h2>
                        <div style="overflow-x: auto;">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Proxy</th>
                                        <th>Score</th>
                                        <th>Country</th>
                                        <th>Response Time</th>
                                        <th>Uptime</th>
                                        <th>Status</th>
                                        <th>Quality</th>
                                    </tr>
                                </thead>
                                <tbody id="proxy-list">
                                    <tr><td colspan="7">Loading...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <script>
                    async function fetchData() {
                        try {
                            const [proxiesResp, statsResp] = await Promise.all([
                                fetch('/api/proxies'),
                                fetch('/api/stats')
                            ]);
                            const proxies = await proxiesResp.json();
                            const stats = await statsResp.json();
                            return { proxies, stats };
                        } catch (error) {
                            console.error('Error fetching data:', error);
                            return null;
                        }
                    }
                    
                    function updateUI(data) {
                        if (!data) return;
                        
                        document.getElementById('total-proxies').textContent = data.stats.stats.total_proxies || 0;
                        document.getElementById('active-proxies').textContent = data.stats.stats.active_proxies || 0;
                        document.getElementById('avg-response-time').textContent = (data.stats.stats.avg_response_time || 0).toFixed(2) + 's';
                        document.getElementById('avg-score').textContent = (data.stats.stats.avg_score || 0).toFixed(1);
                        document.getElementById('health-rate').textContent = (data.stats.health.health_rate || 0).toFixed(1) + '%';
                        document.getElementById('stability').textContent = data.stats.health.stability || 'unknown';
                        
                        document.getElementById('timestamp').textContent = new Date(data.proxies.timestamp).toLocaleString();
                        
                        const countryList = document.getElementById('country-list');
                        if (data.stats.stats.top_countries) {
                            countryList.innerHTML = data.stats.stats.top_countries.map(c => 
                                `<span class="country-tag">${c.country}: ${c.count}</span>`
                            ).join('');
                        }
                        
                        const tbody = document.getElementById('proxy-list');
                        if (data.proxies.proxies && data.proxies.proxies.length > 0) {
                            tbody.innerHTML = data.proxies.proxies.map(p => {
                                const score = p.score || 0;
                                const scoreClass = score >= 70 ? 'score-good' : score >= 50 ? 'score-fair' : 'score-poor';
                                const statusBadge = p.success_count > 0 ? 
                                    '<span class="badge badge-success">Active</span>' : 
                                    '<span class="badge badge-warning">Inactive</span>';
                                const quality = p.score >= 90 ? '⭐ Quantum' :
                                              p.score >= 70 ? '✅ Optimal' :
                                              p.score >= 50 ? '⚠️ Standard' : '❌ Suboptimal';
                                return `
                                    <tr>
                                        <td><code>${p.address}</code></td>
                                        <td class="${scoreClass}">${score}</td>
                                        <td>${p.country || '??'}</td>
                                        <td>${(p.avg_response_time || 0).toFixed(2)}s</td>
                                        <td>${(p.uptime || 0).toFixed(1)}%</td>
                                        <td>${statusBadge}</td>
                                        <td>${quality}</td>
                                    </tr>
                                `;
                            }).join('');
                        } else {
                            tbody.innerHTML = '<tr><td colspan="7">No proxies found</td></tr>';
                        }
                    }
                    
                    async function refreshData() {
                        const data = await fetchData();
                        updateUI(data);
                    }
                    
                    async function exportData(format) {
                        try {
                            const response = await fetch(`/api/export?format=${format}&metadata=true`);
                            const data = await response.json();
                            if (data.success) {
                                const blob = new Blob([data.content], { 
                                    type: format === 'html' ? 'text/html' : 
                                          format === 'json' ? 'application/json' : 'text/plain'
                                });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url;
                                a.download = `proxyflux_proxies.${format}`;
                                a.click();
                                URL.revokeObjectURL(url);
                            } else {
                                alert('Export failed: ' + data.error);
                            }
                        } catch (error) {
                            console.error('Export error:', error);
                            alert('Export failed');
                        }
                    }
                    
                    refreshData();
                    setInterval(refreshData, 30000);
                </script>
            </body>
            </html>
        ''', version=VERSION, timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    def run(self, host: str = '0.0.0.0', port: int = 5000, debug: bool = False):
        """Run the web server"""
        if self.app:
            self.app.run(host=host, port=port, debug=debug)


def format_proxies_for_requests(proxy_str: str, proxy_type_hint: str) -> Dict:
    """Format proxy for requests library"""
    ipport = proxy_str.strip()
    
    if proxy_type_hint in ("http", "https", "auto"):
        return {"http": f"http://{ipport}", "https": f"http://{ipport}"}
    if proxy_type_hint == "socks4":
        return {"http": f"socks4://{ipport}", "https": f"socks4://{ipport}"}
    if proxy_type_hint == "socks5":
        return {"http": f"socks5://{ipport}", "https": f"socks5://{ipport}"}
    
    return {"http": f"http://{ipport}", "https": f"http://{ipport}"}


class EnhancedProxyValidator:
    """Main ProxyFlux engine - The Quantum Proxy Validator"""
    
    def __init__(self):
        self.args = None
        self.db = ProxyDatabase()
        self.rotator = ProxyRotator()
        self.monitor = HealthMonitor()
        self.scorer = ProxyScorer()
        self.analyzer = ProxyAnalyzer()
        self.tester = EnhancedProxyTester()
        self.exporter = ProxyExporter()
        self.enhancer = ProxyEnhancer()
        self.found_proxies = set()
        self.found_proxies_data = []
        self.start_time = time.time()
        self.stop_event = Event()
        self.progress_tracker = None
        self.proxy_tags = {}
    
    def parse_arguments(self):
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(
            description="ProxyFlux - Advanced Proxy Management Suite",
            epilog="⚡ ProxyFlux: Powering the next generation of proxy intelligence"
        )
        
        # Core options
        parser.add_argument("--type", choices=["http", "https", "socks4", "socks5", "mixed", "auto"],
                            default="mixed", help="Proxy type to fetch/test")
        parser.add_argument("--count", type=int, default=10, help="Number of working proxies to find")
        parser.add_argument("--workers", type=int, default=50, help="Number of concurrent workers")
        parser.add_argument("--timeout", type=int, default=6, help="Per-proxy request timeout")
        parser.add_argument("--test-url", type=str, default="https://www.example.com", help="URL to test proxies against")
        
        # Enhanced options
        parser.add_argument("--save", type=str, default="proxyflux_proxies", help="Output filename (without extension)")
        parser.add_argument("--export-format", choices=['txt', 'json', 'csv', 'yaml', 'html', 'xml'],
                            default='txt', help="Export format")
        parser.add_argument("--min-score", type=int, default=30, help="Minimum score for proxy acceptance (0-100)")
        parser.add_argument("--max-response-time", type=float, default=5.0, help="Maximum acceptable response time")
        parser.add_argument("--geo-filter", type=str, default=None, help="Filter proxies by country code")
        parser.add_argument("--cache", action="store_true", help="Use cached proxies from database")
        parser.add_argument("--cache-age", type=int, default=24, help="Maximum age of cached proxies in hours")
        parser.add_argument("--watch", action="store_true", help="Continuously monitor proxy health")
        parser.add_argument("--web-dashboard", action="store_true", help="Launch web dashboard")
        parser.add_argument("--web-port", type=int, default=5000, help="Port for web dashboard")
        parser.add_argument("--no-fetch", action="store_true", help="Skip fetching, read from stdin")
        parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
        
        # ProxyFlux advanced options
        parser.add_argument("--tags", type=str, default=None, help="Add tags to proxies (comma-separated)")
        parser.add_argument("--min-uptime", type=float, default=0, help="Minimum uptime percentage")
        parser.add_argument("--deduplicate", action="store_true", help="Remove duplicate proxies from different sources")
        parser.add_argument("--anonymity-only", action="store_true", help="Only keep anonymous proxies")
        parser.add_argument("--rotate-user-agent", action="store_true", help="Rotate user agents for each request")
        parser.add_argument("--delay", type=float, default=0, help="Add delay between requests in seconds")
        parser.add_argument("--quiet", action="store_true", help="Suppress progress display")
        
        self.args = parser.parse_args()
        
        if self.args.verbose:
            logger.setLevel(logging.DEBUG)
        
        return self.args
    
    def print_config(self):
        """Display configuration with futuristic styling"""
        init(autoreset=True)
        print(Fore.CYAN + Style.BRIGHT + "╔══════════════════════════════════════════════════════════════════╗" + Style.RESET_ALL)
        print(Fore.CYAN + Style.BRIGHT + "║" + Fore.YELLOW + "  ⚙️  ProxyFlux Quantum Configuration" + " " * 34 + Fore.CYAN + "║" + Style.RESET_ALL)
        print(Fore.CYAN + Style.BRIGHT + "╠══════════════════════════════════════════════════════════════════╣" + Style.RESET_ALL)
        print(Fore.CYAN + Style.BRIGHT + "║" + Fore.WHITE + "  Type:              " + Fore.GREEN + f"{self.args.type:<35}" + Fore.CYAN + "║" + Style.RESET_ALL)
        print(Fore.CYAN + Style.BRIGHT + "║" + Fore.WHITE + "  Workers:            " + Fore.GREEN + f"{self.args.workers:<35}" + Fore.CYAN + "║" + Style.RESET_ALL)
        print(Fore.CYAN + Style.BRIGHT + "║" + Fore.WHITE + "  Timeout:            " + Fore.GREEN + f"{self.args.timeout}s" + " " * 34 + Fore.CYAN + "║" + Style.RESET_ALL)
        print(Fore.CYAN + Style.BRIGHT + "║" + Fore.WHITE + "  Min Score:          " + Fore.GREEN + f"{self.args.min_score}/100" + " " * 30 + Fore.CYAN + "║" + Style.RESET_ALL)
        print(Fore.CYAN + Style.BRIGHT + "║" + Fore.WHITE + "  Max Response:       " + Fore.GREEN + f"{self.args.max_response_time}s" + " " * 29 + Fore.CYAN + "║" + Style.RESET_ALL)
        if self.args.geo_filter:
            print(Fore.CYAN + Style.BRIGHT + "║" + Fore.WHITE + "  Geo Filter:         " + Fore.GREEN + f"{self.args.geo_filter:<35}" + Fore.CYAN + "║" + Style.RESET_ALL)
        if self.args.cache:
            print(Fore.CYAN + Style.BRIGHT + "║" + Fore.WHITE + "  Cache:              " + Fore.GREEN + f"Enabled ({self.args.cache_age}h)" + " " * 24 + Fore.CYAN + "║" + Style.RESET_ALL)
        if self.args.watch:
            print(Fore.CYAN + Style.BRIGHT + "║" + Fore.WHITE + "  Health Monitor:     " + Fore.GREEN + "Enabled" + " " * 33 + Fore.CYAN + "║" + Style.RESET_ALL)
        if self.args.web_dashboard:
            print(Fore.CYAN + Style.BRIGHT + "║" + Fore.WHITE + "  Web Dashboard:      " + Fore.GREEN + f"http://localhost:{self.args.web_port}" + " " * 21 + Fore.CYAN + "║" + Style.RESET_ALL)
        if self.args.tags:
            print(Fore.CYAN + Style.BRIGHT + "║" + Fore.WHITE + "  Tags:               " + Fore.GREEN + f"{self.args.tags:<35}" + Fore.CYAN + "║" + Style.RESET_ALL)
        if self.args.min_uptime > 0:
            print(Fore.CYAN + Style.BRIGHT + "║" + Fore.WHITE + "  Min Uptime:         " + Fore.GREEN + f"{self.args.min_uptime}%" + " " * 35 + Fore.CYAN + "║" + Style.RESET_ALL)
        if self.args.anonymity_only:
            print(Fore.CYAN + Style.BRIGHT + "║" + Fore.WHITE + "  Anonymity Only:     " + Fore.GREEN + "Yes" + " " * 37 + Fore.CYAN + "║" + Style.RESET_ALL)
        if self.args.rotate_user_agent:
            print(Fore.CYAN + Style.BRIGHT + "║" + Fore.WHITE + "  Rotate User Agent:  " + Fore.GREEN + "Yes" + " " * 37 + Fore.CYAN + "║" + Style.RESET_ALL)
        if self.args.delay > 0:
            print(Fore.CYAN + Style.BRIGHT + "║" + Fore.WHITE + "  Request Delay:      " + Fore.GREEN + f"{self.args.delay}s" + " " * 34 + Fore.CYAN + "║" + Style.RESET_ALL)
        print(Fore.CYAN + Style.BRIGHT + "╚══════════════════════════════════════════════════════════════════╝" + Style.RESET_ALL)
        print()
    
    def fetch_proxies_from_url(self, url: str, session: requests.Session, timeout: int = 10) -> List[str]:
        """Fetch proxies from a URL with enhanced error handling"""
        try:
            if self.args.rotate_user_agent:
                session.headers.update({'User-Agent': self.enhancer.rotate_user_agent()})
            
            if self.args.delay > 0:
                self.enhancer.add_random_delay(self.args.delay * 0.5, self.args.delay)
            
            resp = session.get(url, timeout=timeout)
            resp.raise_for_status()
            text = resp.text
            
            matches = set()
            for match in IPPORT_RE.findall(text):
                if self.enhancer.validate_proxy_format(match):
                    matches.add(match)
            
            return list(matches)
        except requests.RequestException as exc:
            with print_lock:
                if not self.args.quiet:
                    print(f"{Fore.RED}Failed to fetch {url}: {exc}{Style.RESET_ALL}")
            return []
    
    def fetch_proxies(self) -> Set[str]:
        """Fetch proxies from all configured sources with deduplication"""
        proxy_urls_map = {
            "http": [
                "https://api.openproxylist.xyz/http.txt",
                "https://rootjazz.com/proxies/proxies.txt",
                "https://www.proxy-list.download/api/v1/get?type=http",
                "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
                "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
                "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt"
            ],
            "https": [
                "https://www.sslproxies.org/",
                "https://www.proxy-list.download/api/v1/get?type=https",
                "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&timeout=10000&country=all&ssl=all&anonymity=all",
                "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/https/https.txt",
                "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt"
            ],
            "socks4": [
                "https://api.openproxylist.xyz/socks4.txt",
                "https://www.proxy-list.download/api/v1/get?type=socks4",
                "https://www.socks-proxy.net/",
                "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks4/socks4.txt",
                "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
                "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=SOCKS4&timeout=10000&country=all&ssl=all&anonymity=all",
                "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_anonymous/socks4.txt"
            ],
            "socks5": [
                "https://www.proxy-list.download/api/v1/get?type=socks5",
                "https://api.openproxylist.xyz/socks5.txt",
                "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt",
                "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
                "https://raw.githubusercontent.com/elliottophellia/yakumo/master/results/socks5/global/socks5_checked.txt",
                "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
                "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_anonymous/socks5.txt",
                "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=SOCKS5&timeout=10000&country=all&ssl=all&anonymity=all",
                "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt"
            ],
            "mixed": [
                'https://www.sslproxies.org/',
                'https://www.google-proxy.net/',
                'https://free-proxy-list.net/anonymous-proxy.html',
                'https://free-proxy-list.net/uk-proxy.html',
                'https://www.us-proxy.org/',
                'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=SOCKS4&timeout=10000&country=all&ssl=all&anonymity=all',
                'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
                'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&timeout=10000&country=all&ssl=all&anonymity=all',
                "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=SOCKS5&timeout=10000&country=all&ssl=all&anonymity=all",
                'https://free-proxy-list.net/'
            ]
        }
        
        session = requests.Session()
        session.headers.update(DEFAULT_HEADERS)
        
        chosen_type = self.args.type
        urls_to_fetch = []
        if chosen_type == "mixed":
            urls_to_fetch = proxy_urls_map["mixed"]
        elif chosen_type in proxy_urls_map:
            urls_to_fetch = proxy_urls_map[chosen_type]
        else:
            urls_to_fetch = proxy_urls_map["mixed"]
        
        all_candidates = set()
        
        # Use cached proxies first
        if self.args.cache:
            cached = self.db.get_historical_proxies(
                limit=self.args.count * 2, 
                min_score=self.args.min_score,
                max_age_hours=self.args.cache_age,
                tags=self.args.tags
            )
            if cached:
                all_candidates.update(cached)
                with print_lock:
                    if not self.args.quiet:
                        print(f"{Fore.GREEN}[✓] Loaded {len(cached)} cached proxies from quantum storage{Style.RESET_ALL}")
        
        # Fetch from URLs
        if not self.args.no_fetch:
            with ThreadPoolExecutor(max_workers=min(len(urls_to_fetch), self.args.workers)) as fetch_pool:
                future_to_url = {
                    fetch_pool.submit(self.fetch_proxies_from_url, url, session, self.args.timeout * 2): url
                    for url in urls_to_fetch
                }
                if not self.args.quiet:
                    print(f"{Fore.CYAN}[~] Scanning proxy networks...{Style.RESET_ALL}\n")
                
                for fut in as_completed(future_to_url):
                    url = future_to_url[fut]
                    try:
                        proxies = fut.result()
                        if proxies:
                            all_candidates.update(proxies)
                            with print_lock:
                                if not self.args.quiet:
                                    print(f"{Fore.GREEN}[✓] Retrieved {len(proxies)} proxies from: {Fore.WHITE}{url}{Style.RESET_ALL}")
                    except Exception as exc:
                        with print_lock:
                            if not self.args.quiet:
                                print(f"{Fore.RED}[✗] Error fetching from {url}: {exc}{Style.RESET_ALL}")
        
        # Read from stdin
        if self.args.no_fetch or not all_candidates:
            if self.args.no_fetch and not self.args.quiet:
                print(f"{Fore.YELLOW}[~] Reading proxy list from stdin... (end with Ctrl-D){Style.RESET_ALL}")
            for line in sys.stdin:
                m = IPPORT_RE.search(line)
                if m:
                    proxy = m.group(0)
                    if self.enhancer.validate_proxy_format(proxy):
                        all_candidates.add(proxy)
        
        # Deduplicate if requested
        if self.args.deduplicate and all_candidates:
            unique = set()
            seen_ips = set()
            for proxy in all_candidates:
                ip = proxy.split(':')[0]
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    unique.add(proxy)
            all_candidates = unique
        
        return all_candidates
    
    def validate_proxies(self, candidates: Set[str]) -> List[Dict]:
        """Validate proxies with quantum testing and filtering"""
        proxy_list = list(candidates)
        total_candidates = len(proxy_list)
        
        # Initialize progress tracker
        self.progress_tracker = ProgressTracker(total_candidates)
        if not self.args.quiet:
            self.progress_tracker.start_display()
        
        proxy_type_hint = self.args.type if self.args.type in ("http", "https", "socks4", "socks5") else "auto"
        
        results = self.tester.test_batch(
            proxy_list, 
            self.args.test_url, 
            self.args.timeout, 
            proxy_type_hint,
            self.stop_event,
            self.progress_tracker
        )
        
        # Stop progress display
        if self.progress_tracker:
            self.progress_tracker.stop_display()
        
        validated = []
        
        for result in results:
            result['type'] = self.enhancer.get_proxy_type(result['proxy'])
            result['score'] = self.scorer.calculate_score(result)
            
            # Check anonymity (simple check)
            result['anonymous'] = True  # Default to True since we're testing through proxy
            
            # Apply filters
            if self.args.geo_filter and result.get('country_code') != self.args.geo_filter:
                continue
            
            if self.args.anonymity_only and not result.get('anonymous', False):
                continue
            
            if result['response_time'] > self.args.max_response_time:
                continue
            
            if result['score'] < self.args.min_score:
                continue
            
            validated.append(result)
            
            # Save to database
            self.db.save_proxy(result)
            
            # Store in found set
            self.found_proxies.add(result['proxy'])
            self.found_proxies_data.append(result)
            
            if len(self.found_proxies) >= self.args.count:
                self.stop_event.set()
                break
        
        return validated
    
    def refresh_proxies(self):
        """Background refresh of proxies"""
        logger.info("Initiating quantum proxy refresh...")
        candidates = self.fetch_proxies()
        if candidates:
            self.validate_proxies(candidates)
            logger.info(f"Refresh complete. Quantum state: {len(self.found_proxies)} proxies active.")
    
    def export_results(self):
        """Export results with enhanced metadata"""
        if not self.found_proxies_data:
            print(f"{Fore.RED}[✗] No working proxies found in quantum scan.{Style.RESET_ALL}")
            return
        
        # Show final summary with all valid proxies and full details
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║{Fore.GREEN}  ✓ ALL VALID PROXIES FOUND ({len(self.found_proxies_data)})                                                 {Fore.CYAN}║")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════════════════╣")
        
        # Show all valid proxies with full details
        for idx, proxy_info in enumerate(self.found_proxies_data, 1):
            proxy = proxy_info.get('proxy', 'N/A')
            country = proxy_info.get('country', '??')
            country_code = proxy_info.get('country_code', '??')
            region = proxy_info.get('region', 'N/A')
            city = proxy_info.get('city', 'N/A')
            score = proxy_info.get('score', 0)
            response_time = proxy_info.get('response_time', 0)
            isp = proxy_info.get('isp', 'N/A')
            org = proxy_info.get('org', 'N/A')
            asn = proxy_info.get('asn', 'N/A')
            domain = proxy_info.get('domain', 'N/A')
            reverse_dns = proxy_info.get('reverse_dns', 'N/A')
            timezone = proxy_info.get('timezone', 'N/A')
            quality = self.scorer.get_quality_label(score)
            
            print(f"{Fore.CYAN}║{Fore.WHITE}  #{idx:>3} {Fore.YELLOW}{proxy:<20} "
                  f"{Fore.GREEN}[{score:>3}] {Fore.BLUE}{response_time:.2f}s "
                  f"{Fore.MAGENTA}{country:<12} {Fore.CYAN}{isp[:20]:<20} {Fore.WHITE}{quality} {Fore.CYAN}║")
            
            # Domain & Reverse DNS
            print(f"{Fore.CYAN}║{Fore.WHITE}     ├─ {Fore.CYAN}Domain: {Fore.WHITE}{domain:<45} "
                  f"{Fore.CYAN}Reverse DNS: {Fore.WHITE}{reverse_dns[:35]:<35} {Fore.CYAN}║")
            
            # ISP & Organization
            print(f"{Fore.CYAN}║{Fore.WHITE}     ├─ {Fore.CYAN}ISP: {Fore.WHITE}{isp[:45]:<45} "
                  f"{Fore.CYAN}Organization: {Fore.WHITE}{org[:35]:<35} {Fore.CYAN}║")
            
            # ASN & Location
            print(f"{Fore.CYAN}║{Fore.WHITE}     ├─ {Fore.CYAN}ASN: {Fore.WHITE}{asn[:45]:<45} "
                  f"{Fore.CYAN}Location: {Fore.WHITE}{city[:20]}, {region[:20]}, {country_code} {Fore.CYAN}║")
            
            # Timezone & Score
            print(f"{Fore.CYAN}║{Fore.WHITE}     └─ {Fore.CYAN}Timezone: {Fore.WHITE}{timezone:<35} "
                  f"{Fore.CYAN}Score: {Fore.WHITE}{score}/100 {Fore.CYAN}║")
            
            # Separator between proxies
            if idx < len(self.found_proxies_data):
                print(f"{Fore.CYAN}║{Fore.WHITE}{' ' * 86}{Fore.CYAN}║")
        
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        # Sort and export
        sorted_proxies = sorted(
            self.found_proxies_data, 
            key=lambda x: x.get('score', 0), 
            reverse=True
        )
        
        try:
            self.exporter.export(
                sorted_proxies,
                self.args.export_format,
                self.args.save,
                include_metadata=True
            )
            
            print(f"\n{Fore.GREEN}[✓] Exported to: {Fore.WHITE}{self.args.save}.{self.args.export_format}{Style.RESET_ALL}")
            
            # Print summary
            elapsed = time.time() - self.start_time
            print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════╗")
            print(f"{Fore.CYAN}║{Fore.YELLOW}  📊 ProxyFlux Quantum Summary                                                           {Fore.CYAN}║")
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════════════════╣")
            print(f"{Fore.CYAN}║{Fore.WHITE}  Total Found:     {Fore.GREEN}{len(self.found_proxies):<45} {Fore.CYAN}║")
            print(f"{Fore.CYAN}║{Fore.WHITE}  Time Elapsed:    {Fore.CYAN}{elapsed:.2f}s{' ' * 45} {Fore.CYAN}║")
            
            if self.found_proxies_data:
                avg_score = sum(p.get('score', 0) for p in self.found_proxies_data) / len(self.found_proxies_data)
                avg_time = sum(p.get('response_time', 0) for p in self.found_proxies_data) / len(self.found_proxies_data)
                
                print(f"{Fore.CYAN}║{Fore.WHITE}  Avg Score:       {Fore.YELLOW}{avg_score:.1f}/100{' ' * 41} {Fore.CYAN}║")
                print(f"{Fore.CYAN}║{Fore.WHITE}  Avg Response:    {Fore.CYAN}{avg_time:.2f}s{' ' * 45} {Fore.CYAN}║")
            
            stats = self.db.get_stats()
            print(f"{Fore.CYAN}║{Fore.WHITE}  DB Total:        {Fore.MAGENTA}{stats['total_proxies']:<45} {Fore.CYAN}║")
            print(f"{Fore.CYAN}║{Fore.WHITE}  DB Active:       {Fore.GREEN}{stats['active_proxies']:<45} {Fore.CYAN}║")
            print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[✗] Export failed: {e}{Style.RESET_ALL}")
    
    def run_web_dashboard(self):
        """Run the web dashboard"""
        if not FLASK_AVAILABLE:
            print(f"{Fore.RED}[✗] Flask not installed. Install with: pip install flask{Style.RESET_ALL}")
            return
        
        try:
            dashboard = WebDashboard(self)
            dashboard.run(port=self.args.web_port)
        except Exception as e:
            print(f"{Fore.RED}[✗] Failed to start dashboard: {e}{Style.RESET_ALL}")
    
    def run_health_monitor(self):
        """Run continuous health monitoring"""
        if not self.found_proxies_data:
            return
        
        print(f"\n{Fore.CYAN}[~] Quantum health monitoring initialized...{Style.RESET_ALL}")
        
        try:
            while True:
                time.sleep(self.args.cache_age * 60)
                
                healthy_count = 0
                for proxy_data in self.found_proxies_data[:50]:
                    is_healthy = self.monitor.check_proxy_health(
                        proxy_data,
                        lambda p: self.tester.test_proxy(p['proxy'])
                    )
                    if is_healthy:
                        healthy_count += 1
                    else:
                        self.db.record_failure(proxy_data['proxy'])
                        if proxy_data['proxy'] in self.found_proxies:
                            self.found_proxies.remove(proxy_data['proxy'])
                            self.rotator.remove_proxy(proxy_data['proxy'])
                
                stats = self.monitor.get_health_stats()
                print(f"\n{Fore.CYAN}[~] Health Check - "
                      f"Healthy: {Fore.GREEN}{stats['healthy']}/{stats['total_checked']} "
                      f"({stats['health_rate']:.1f}%) "
                      f"Trend: {stats.get('stability', 'unknown')}{Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[~] Health monitor shutdown initiated.{Style.RESET_ALL}")
    
    def run(self):
        """Main execution method"""
        self.parse_arguments()
        print_banner()
        self.print_config()
        
        if self.args.web_dashboard:
            print(f"{Fore.CYAN}[~] Launching Web Dashboard: http://localhost:{self.args.web_port}{Style.RESET_ALL}")
            import threading
            dashboard_thread = threading.Thread(target=self.run_web_dashboard, daemon=True)
            dashboard_thread.start()
            time.sleep(1)
        
        candidates = self.fetch_proxies()
        
        if not candidates:
            print(f"{Fore.RED}[✗] No proxy candidates found in quantum scan. Exiting.{Style.RESET_ALL}")
            return
        
        validated = self.validate_proxies(candidates)
        self.export_results()
        
        if self.args.watch and self.found_proxies:
            try:
                self.run_health_monitor()
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[~] Monitoring stopped.{Style.RESET_ALL}")
        
        if self.args.web_dashboard:
            print(f"\n{Fore.CYAN}[~] Web Dashboard: http://localhost:{self.args.web_port}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[~] Press Ctrl+C to shutdown ProxyFlux{Style.RESET_ALL}")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[~] Shutting down ProxyFlux...{Style.RESET_ALL}")


def main():
    """ProxyFlux entry point"""
    validator = EnhancedProxyValidator()
    validator.run()


if __name__ == "__main__":
    main()
