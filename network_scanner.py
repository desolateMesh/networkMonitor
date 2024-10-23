from scapy.all import ARP, Ether, srp
import json
import socket
import platform
import subprocess
from datetime import datetime
import sys
import sqlite3
import time

class DeviceTracker:
    def __init__(self):
        self.known_devices = {}
        self.initialize_database()

    def initialize_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect('devices.db', timeout=30)
        c = conn.cursor()
        
        # Create tables for device tracking
        c.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                hostname TEXT,
                custom_name TEXT,
                device_type TEXT,
                manufacturer TEXT,
                is_trusted BOOLEAN DEFAULT 0,
                is_blocked BOOLEAN DEFAULT 0,
                notes TEXT
            )
        ''')
        
        # IP history table
        c.execute('''
            CREATE TABLE IF NOT EXISTS ip_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP,
                FOREIGN KEY (mac) REFERENCES devices(mac)
            )
        ''')
        
        conn.commit()
        conn.close()

    def is_mac_random(self, mac):
        """Check if a MAC address is likely randomized"""
        first_byte = int(mac.split(':')[0].replace('-', ''), 16)
        return bool(first_byte & 0x02)

    def get_manufacturer(self, mac):
        """Get manufacturer from MAC address OUI"""
        try:
            oui = mac.replace(':', '').replace('-', '')[:6].upper()
            return "Unknown Manufacturer"  # Placeholder
        except:
            return "Unknown"

    def track_device(self, mac, ip, hostname):
        """Track device and determine if it's using randomization"""
        try:
            conn = sqlite3.connect('devices.db', timeout=30)
            c = conn.cursor()
            current_time = datetime.now()

            # Get existing device name if any
            c.execute('SELECT custom_name FROM devices WHERE mac = ?', (mac,))
            result = c.fetchone()
            custom_name = result[0] if result else None

            device_info = {
                'mac': mac,
                'ip': ip,
                'hostname': hostname,
                'name': custom_name or hostname,
                'is_random': self.is_mac_random(mac),
                'last_seen': current_time,
                'manufacturer': self.get_manufacturer(mac)
            }

            # Insert or update device
            c.execute('''
                INSERT OR REPLACE INTO devices (
                    mac, first_seen, last_seen, 
                    hostname, custom_name
                ) VALUES (?, ?, ?, ?, ?)
            ''', (mac, current_time, current_time, hostname, custom_name))

            # Record IP history
            c.execute('''
                INSERT INTO ip_history (mac, ip_address, timestamp)
                VALUES (?, ?, ?)
            ''', (mac, ip, current_time))

            conn.commit()
            conn.close()
            return device_info

        except Exception as e:
            print(f"Error tracking device: {str(e)}")
            return None

def scan_network():
    """Enhanced network scan with device tracking"""
    try:
        tracker = DeviceTracker()
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        network = '.'.join(local_ip.split('.')[:-1]) + '.0/24'

        # Create ARP request packet
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        # Send packet and get response
        result = srp(packet, timeout=3, verbose=0)[0]

        devices = []
        for sent, received in result:
            ip = received.psrc
            mac = received.hwsrc.lower()  # Normalize MAC format
            
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"

            # Track device and get enhanced info
            device_info = tracker.track_device(mac, ip, hostname)
            
            if device_info:
                # Check if device is online
                if platform.system().lower() == 'windows':
                    ping = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE)
                else:
                    ping = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE)
                
                online = ping.returncode == 0

                device = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'name': device_info.get('name', hostname),
                    'online': online,
                    'lastSeen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'isOwned': False,
                    'isRandom': device_info['is_random'],
                    'manufacturer': device_info['manufacturer']
                }
                devices.append(device)

        return devices

    except Exception as e:
        print(f"Error scanning network: {str(e)}", file=sys.stderr)
        return []

if __name__ == "__main__":
    try:
        devices = scan_network()
        print(json.dumps(devices, indent=2))
    except Exception as e:
        print(f"Error in main: {str(e)}", file=sys.stderr)
        print("[]")