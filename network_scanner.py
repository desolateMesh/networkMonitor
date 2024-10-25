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

            # Check for existing device info including custom name
            c.execute('SELECT custom_name, hostname FROM devices WHERE mac = ?', (mac,))
            result = c.fetchone()
            if result:
                custom_name = result[0]
                stored_hostname = result[1]
            else:
                custom_name = None
                stored_hostname = hostname

            # Use custom name if available, otherwise use hostname
            display_name = custom_name if custom_name else hostname

            device_info = {
                'mac': mac,
                'ip': ip,
                'hostname': hostname,
                'name': display_name,  # Use the display_name we created
                'custom_name': custom_name,  # Include the custom_name
                'is_random': self.is_mac_random(mac),
                'last_seen': current_time,
                'manufacturer': self.get_manufacturer(mac)
            }

            # Insert or update with COALESCE to preserve custom_name
            c.execute('''
                INSERT OR REPLACE INTO devices (
                    mac, first_seen, last_seen, hostname, custom_name
                ) VALUES (
                    ?, 
                    COALESCE((SELECT first_seen FROM devices WHERE mac = ?), ?),
                    ?,
                    ?,
                    COALESCE((SELECT custom_name FROM devices WHERE mac = ?), ?)
                )
            ''', (mac, mac, current_time, current_time, hostname, mac, custom_name))

            conn.commit()
            conn.close()
            
            # Update local cache
            self.known_devices[mac] = device_info
            
            return device_info

        except Exception as e:
            print(f"Error tracking device: {str(e)}")
            return None
        
    def set_device_name(self, mac, custom_name):
        """Set a custom name for a device"""
        try:
            print(f"DEBUG: Starting rename for MAC {mac} to {custom_name}")  # Debug print
            
            conn = sqlite3.connect('devices.db', timeout=30)
            c = conn.cursor()
            
            # Print current state
            c.execute('SELECT * FROM devices WHERE mac = ?', (mac,))
            before = c.fetchone()
            print(f"DEBUG: Before update - Device state: {before}")
            
            # Update both custom_name and hostname
            c.execute('''
                UPDATE devices 
                SET custom_name = ?,
                    hostname = ?
                WHERE mac = ?
            ''', (custom_name, custom_name, mac))
            
            print(f"DEBUG: Rows affected: {c.rowcount}")  # Debug print
            
            # Verify update
            c.execute('SELECT * FROM devices WHERE mac = ?', (mac,))
            after = c.fetchone()
            print(f"DEBUG: After update - Device state: {after}")
            
            conn.commit()
            conn.close()
            
            # Return detailed response
            result = {
                "success": True,
                "before": str(before),
                "after": str(after),
                "mac": mac,
                "new_name": custom_name
            }
            print(f"DEBUG: Returning result: {json.dumps(result)}")  # Debug print
            return result

        except Exception as e:
            print(f"ERROR in set_device_name: {str(e)}")
            return {"success": False, "error": str(e)}

    def get_device(self, mac):
        """Get device information"""
        try:
            conn = sqlite3.connect('devices.db', timeout=30)
            c = conn.cursor()
            c.execute('SELECT * FROM devices WHERE mac = ?', (mac,))
            device = c.fetchone()
            conn.close()
            return device
        except Exception as e:
            print(f"Error getting device: {str(e)}")
            return None

    def track_device(self, mac, ip, hostname):
        """Track device and determine if it's using randomization"""
        try:
            conn = sqlite3.connect('devices.db', timeout=30)
            c = conn.cursor()
            current_time = datetime.now()

            # Check for existing custom name
            c.execute('SELECT custom_name FROM devices WHERE mac = ?', (mac,))
            result = c.fetchone()
            device_name = result[0] if result and result[0] else hostname

            device_info = {
                'mac': mac,
                'ip': ip,
                'hostname': hostname,
                'name': device_name,  # Use custom name if it exists
                'is_random': self.is_mac_random(mac),
                'last_seen': current_time,
                'manufacturer': self.get_manufacturer(mac)
            }

            # Insert or update with COALESCE to preserve custom_name
            c.execute('''
                INSERT OR REPLACE INTO devices (
                    mac, first_seen, last_seen, hostname, custom_name
                ) VALUES (
                    ?, 
                    COALESCE((SELECT first_seen FROM devices WHERE mac = ?), ?),
                    ?,
                    ?,
                    COALESCE((SELECT custom_name FROM devices WHERE mac = ?), ?)
                )
            ''', (mac, mac, current_time, current_time, hostname, mac, device_name))

            conn.commit()
            conn.close()
            
            # Update local cache
            self.known_devices[mac] = device_info
            
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
                    'name': device_info.get('name', hostname),  # Get name from device_info
                    'custom_name': device_info.get('custom_name'),  # Get custom name
                    'display_name': device_info.get('name', hostname),  # Use name from device_info as display name
                    'online': online,
                    'lastSeen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'isOwned': False,
                    'isRandom': device_info['is_random'],
                    'manufacturer': device_info['manufacturer'],
                    'firstSeen': device_info.get('first_seen', 'Unknown')
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