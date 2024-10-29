# network_monitor.py

import sqlite3
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
import socket
import logging
from datetime import datetime
import sys
import json
import traceback
import netifaces

class NetworkMonitor:
    def __init__(self):
        self.packet_count = 0
        self.packet_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        self.dns_cache = {}
        self.name_cache = {}
        self.db_path = 'devices.db'
        self.interface = self.get_default_interface()
        self.setup_logging()
        self.refresh_name_cache()

    def get_default_interface(self):
        """Get the default network interface"""
        try:
            # Get Scapy's list of interfaces
            from scapy.arch import get_windows_if_list
            
            # Get detailed interface info
            ifaces = get_windows_if_list()
            
            # Log all found interfaces
            logging.info(f"Found interfaces: {ifaces}")
            
            # Look for our target interface by its name
            for iface in ifaces:
                if 'guid' in iface and iface['guid'] == '{8AFFFEA4-B96F-4891-ABB2-7D30800AE093}':
                    logging.info(f"Found matching interface: {iface['name']}")
                    return iface['name']  # Return the name that Scapy can use
                    
            # If we didn't find our specific interface, use the first active one
            for iface in ifaces:
                if iface.get('ips') and len(iface['ips']) > 0:  # Has IP addresses
                    logging.info(f"Using first active interface: {iface['name']}")
                    return iface['name']
                    
            logging.error("No suitable interfaces found")
            return None
                
        except Exception as e:
            logging.error(f"Error getting default interface: {e}")
            logging.error(traceback.format_exc())
            return None

    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('network_monitor.log')
            ]
        )

    def start_sniffing(self):
        """Start sniffing packets on the specified interface."""
        if not self.interface:
            logging.error("No valid interface found for packet capture")
            return

        logging.info(f"Starting packet sniffing on interface {self.interface}...")
        try:
            sniff(prn=self.packet_handler, store=0, iface=self.interface)
        except Exception as e:
            logging.error(f"Error in packet sniffing: {e}")
            logging.error(traceback.format_exc())

    def packet_handler(self, packet):
        """Handler for each captured packet."""
        try:
            if IP in packet:
                packet_data = self.create_packet_data(packet)
                if packet_data:
                    print(packet_data)
                    sys.stdout.flush()
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    def create_packet_data(self, packet):
        """Create JSON data for a captured packet."""
        try:
            protocol = 'Other'
            src_port = dst_port = None

            if TCP in packet:
                protocol = 'TCP'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = 'UDP'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                protocol = 'ICMP'

            # Update packet statistics
            self.packet_stats[protocol] += 1
            self.packet_count += 1

            # Try to get hostnames from cache or DNS
            src_host = self.get_hostname(packet[IP].src)
            dst_host = self.get_hostname(packet[IP].dst)

            data = {
                'type': 'packet',  # Add message type
                'data': {
                    'packet_number': self.packet_count,
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'length': len(packet),
                    'protocol': protocol,
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'src_host': src_host,
                    'dst_host': dst_host,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'stats': {
                        'TCP': self.packet_stats['TCP'],
                        'UDP': self.packet_stats['UDP'],
                        'ICMP': self.packet_stats['ICMP'],
                        'Other': self.packet_stats['Other']
                    }
                }
            }

            return json.dumps(data)
        except Exception as e:
            logging.error(f"Error creating packet data: {e}")
            return None

    def get_hostname(self, ip):
        """Get hostname for an IP address using cache or DNS lookup"""
        try:
            # Check name cache first
            if ip in self.name_cache:
                return self.name_cache[ip]

            # Check DNS cache
            if ip in self.dns_cache:
                return self.dns_cache[ip]

            # Try DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                self.dns_cache[ip] = hostname
                return hostname
            except (socket.herror, socket.gaierror):
                return ip

        except Exception as e:
            logging.error(f"Error resolving hostname for {ip}: {e}")
            return ip

    def refresh_name_cache(self):
        """Refresh device name cache from the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('SELECT mac, custom_name FROM devices')
            devices = c.fetchall()
            for mac, name in devices:
                self.name_cache[mac] = name
            conn.close()
            logging.info("Device name cache refreshed")
        except Exception as e:
            logging.error(f"Error refreshing name cache: {e}")

    def cleanup(self):
        """Cleanup resources"""
        logging.info("Cleaning up network monitor...")
        # Add any cleanup code here (e.g., closing sockets, saving state)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Network Monitor")
    parser.add_argument('--interface', type=str, help='Network interface to sniff on (optional)')
    args = parser.parse_args()

    monitor = NetworkMonitor()
    if args.interface:
        monitor.interface = args.interface

    try:
        monitor.start_sniffing()
    except KeyboardInterrupt:
        logging.info("Stopping network monitor...")
        monitor.cleanup()
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        logging.error(traceback.format_exc())
        sys.exit(1)