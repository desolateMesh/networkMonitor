from collections import defaultdict, deque
from datetime import datetime, timedelta
import sqlite3
import json
import logging
from scapy.all import IP, TCP, UDP, ICMP
import threading
import time
import asyncio

class IntrusionDetector:
    def __init__(self, db_path='devices.db', websocket_broadcast=None):
        self.db_path = db_path
        self.connection_attempts = defaultdict(lambda: deque(maxlen=100))
        self.port_scan_threshold = 20
        self.failed_login_threshold = 5
        self.suspicious_ips = set()
        self.alerts = deque(maxlen=1000)  # Store last 1000 alerts
        self.websocket_broadcast = websocket_broadcast  # Function to broadcast to WebSocket clients
        self.setup_database()
        self.setup_logging()
        
        # Traffic patterns for detection
        self.ip_traffic = defaultdict(int)
        self.port_scans = defaultdict(set)
        self.failed_logins = defaultdict(int)
        
        # Start background tasks
        self.cleanup_thread = threading.Thread(target=self._cleanup_old_data, daemon=True)
        self.cleanup_thread.start()
        
        # Start stats broadcast thread
        self.stats_thread = threading.Thread(target=self._broadcast_stats_periodically, daemon=True)
        self.stats_thread.start()

    def _broadcast_stats_periodically(self):
        """Periodically broadcast statistics to connected clients"""
        while True:
            try:
                stats = {
                    'total_alerts': len(self.alerts),
                    'active_threats': sum(1 for alert in self.alerts if alert.get('status') == 'active'),
                    'blocked_ips': len(self.suspicious_ips),
                    'port_scans': sum(1 for alert in self.alerts 
                                    if alert.get('alert_type') == 'Port Scan Detected')
                }
                
                if self.websocket_broadcast:
                    self.websocket_broadcast(json.dumps({
                        'type': 'stats_update',
                        'stats': stats
                    }))
            except Exception as e:
                logging.error(f"Error broadcasting stats: {str(e)}")
            
            time.sleep(5)  # Update every 5 seconds

    def _create_alert(self, alert_type, severity, source_ip, destination_ip, details):
        """Create and broadcast a new alert"""
        alert = {
            'id': len(self.alerts) + 1,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'alert_type': alert_type,
            'severity': severity,
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'details': details,
            'status': 'active'
        }
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            INSERT INTO intrusion_alerts 
            (alert_type, severity, source_ip, destination_ip, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (alert_type, severity, source_ip, destination_ip, details))
        conn.commit()
        conn.close()
        
        # Add to memory queue
        self.alerts.append(alert)
        
        # Broadcast alert to WebSocket clients
        if self.websocket_broadcast:
            self.websocket_broadcast(json.dumps({
                'type': 'intrusion_alert',
                'alert': alert
            }))
        
        # Log the alert
        logging.warning(f"Security Alert: {alert_type} from {source_ip}")
        
        return alert

    def get_stats(self):
        """Get current statistics"""
        return {
            'total_alerts': len(self.alerts),
            'active_threats': sum(1 for alert in self.alerts if alert.get('status') == 'active'),
            'blocked_ips': len(self.suspicious_ips),
            'port_scans': sum(1 for alert in self.alerts 
                            if alert.get('alert_type') == 'Port Scan Detected')
        }

    # Add this to your existing methods
    def get_recent_alerts_json(self):
        """Get recent alerts in JSON format"""
        alerts = self.get_recent_alerts()
        return json.dumps([{
            'id': alert[0],
            'timestamp': alert[1],
            'alert_type': alert[2],
            'severity': alert[3],
            'source_ip': alert[4],
            'destination_ip': alert[5],
            'details': alert[6],
            'status': alert[7]
        } for alert in alerts])

    def get_blocked_ips_json(self):
        """Get blocked IPs in JSON format"""
        blocked = self.get_blocked_ips()
        return json.dumps([{
            'ip_address': ip[0],
            'block_reason': ip[1],
            'timestamp': ip[2],
            'expiry': ip[3]
        } for ip in blocked])

    def setup_database(self):
        """Initialize the database tables for intrusion detection"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Alerts table
        c.execute('''
            CREATE TABLE IF NOT EXISTS intrusion_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                alert_type TEXT,
                severity TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                details TEXT,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # Blocked IPs table
        c.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip_address TEXT PRIMARY KEY,
                block_reason TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                expiry DATETIME
            )
        ''')
        
        conn.commit()
        conn.close()

    def setup_logging(self):
        """Configure logging for the intrusion detector"""
        logging.basicConfig(
            filename='intrusion_detection.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def analyze_packet(self, packet):
        """Analyze a single packet for potential security threats"""
        if IP not in packet:
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check if IP is already blocked
        if self._is_ip_blocked(src_ip):
            self._log_blocked_attempt(src_ip, dst_ip)
            return
        
        # Increment IP traffic counter
        self.ip_traffic[src_ip] += 1
        
        # Analyze based on protocol
        if TCP in packet:
            self._analyze_tcp_packet(packet, src_ip, dst_ip)
        elif UDP in packet:
            self._analyze_udp_packet(packet, src_ip, dst_ip)
        elif ICMP in packet:
            self._analyze_icmp_packet(packet, src_ip, dst_ip)

    def _analyze_tcp_packet(self, packet, src_ip, dst_ip):
        """Analyze TCP packets for potential threats"""
        # Port scanning detection
        dst_port = packet[TCP].dport
        self.port_scans[src_ip].add(dst_port)
        
        if len(self.port_scans[src_ip]) > self.port_scan_threshold:
            self._create_alert(
                "Port Scan Detected",
                "high",
                src_ip,
                dst_ip,
                f"Multiple ports scanned: {len(self.port_scans[src_ip])} ports"
            )
            self._block_ip(src_ip, "Port Scanning")
        
        # SYN flood detection
        if packet[TCP].flags & 0x02:  # SYN flag
            self.connection_attempts[src_ip].append(datetime.now())
            recent_attempts = len(self.connection_attempts[src_ip])
            
            if recent_attempts > 50:  # More than 50 SYN packets in short period
                self._create_alert(
                    "Possible SYN Flood",
                    "critical",
                    src_ip,
                    dst_ip,
                    f"High rate of SYN packets: {recent_attempts} attempts"
                )

    def _analyze_udp_packet(self, packet, src_ip, dst_ip):
        """Analyze UDP packets for potential threats"""
        if packet[UDP].dport == 53:  # DNS
            # Check for DNS tunneling/amplification
            if len(packet) > 512:  # Unusually large DNS packet
                self._create_alert(
                    "Suspicious DNS Traffic",
                    "medium",
                    src_ip,
                    dst_ip,
                    "Unusually large DNS packet detected"
                )

    def _analyze_icmp_packet(self, packet, src_ip, dst_ip):
        """Analyze ICMP packets for potential threats"""
        # ICMP flood detection
        if src_ip in self.ip_traffic and self.ip_traffic[src_ip] > 100:
            self._create_alert(
                "ICMP Flood",
                "medium",
                src_ip,
                dst_ip,
                f"High ICMP traffic rate: {self.ip_traffic[src_ip]} packets"
            )

    def _create_alert(self, alert_type, severity, source_ip, destination_ip, details):
        """Create and store a new alert"""
        alert = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'alert_type': alert_type,
            'severity': severity,
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'details': details
        }
        
        # Store in database
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''
            INSERT INTO intrusion_alerts 
            (alert_type, severity, source_ip, destination_ip, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (alert_type, severity, source_ip, destination_ip, details))
        conn.commit()
        conn.close()
        
        # Add to memory queue
        self.alerts.append(alert)
        
        # Log the alert
        logging.warning(f"Security Alert: {alert_type} from {source_ip}")
        
        return alert

    def _block_ip(self, ip, reason, duration_hours=24):
        """Block an IP address"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        expiry = datetime.now() + timedelta(hours=duration_hours)
        
        c.execute('''
            INSERT OR REPLACE INTO blocked_ips 
            (ip_address, block_reason, expiry)
            VALUES (?, ?, ?)
        ''', (ip, reason, expiry))
        
        conn.commit()
        conn.close()
        
        self.suspicious_ips.add(ip)
        logging.info(f"Blocked IP {ip} for {reason} until {expiry}")

    def _is_ip_blocked(self, ip):
        """Check if an IP is currently blocked"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            SELECT 1 FROM blocked_ips 
            WHERE ip_address = ? AND expiry > CURRENT_TIMESTAMP
        ''', (ip,))
        
        is_blocked = c.fetchone() is not None
        conn.close()
        
        return is_blocked

    def _log_blocked_attempt(self, src_ip, dst_ip):
        """Log an attempt from a blocked IP"""
        logging.warning(f"Blocked attempt from {src_ip} to {dst_ip}")

    def _cleanup_old_data(self):
        """Periodically clean up old data"""
        while True:
            try:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                
                # Clean up old alerts (keep last 30 days)
                c.execute('''
                    DELETE FROM intrusion_alerts 
                    WHERE timestamp < datetime('now', '-30 days')
                ''')
                
                # Remove expired IP blocks
                c.execute('''
                    DELETE FROM blocked_ips 
                    WHERE expiry < CURRENT_TIMESTAMP
                ''')
                
                conn.commit()
                conn.close()
                
                # Clear old traffic data
                self.ip_traffic.clear()
                self.port_scans.clear()
                
            except Exception as e:
                logging.error(f"Cleanup error: {str(e)}")
            
            time.sleep(3600)  # Run every hour

    def get_recent_alerts(self, limit=50):
        """Get recent alerts from the database"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            SELECT * FROM intrusion_alerts 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,))
        
        alerts = c.fetchall()
        conn.close()
        
        return alerts

    def get_blocked_ips(self):
        """Get currently blocked IPs"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute('''
            SELECT * FROM blocked_ips 
            WHERE expiry > CURRENT_TIMESTAMP
        ''')
        
        blocked = c.fetchall()
        conn.close()
        
        return blocked