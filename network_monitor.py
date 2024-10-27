# network_monitor.py

import sqlite3
from scapy.all import sniff, IP, TCP, UDP, ICMP
import socket
import logging
from datetime import datetime
import sys
import json
import traceback

class NetworkMonitor:
    def __init__(self, interface='Ethernet'):
        self.interface = interface
        self.packet_count = 0
        self.packet_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        self.dns_cache = {}
        self.name_cache = {}
        self.db_path = 'devices.db'
        self.setup_logging()
        self.refresh_name_cache()

    def setup_logging(self):
        """Configure logging to output to both stdout and a log file."""
        logging.basicConfig(
            level=logging.DEBUG,  # Set to DEBUG for detailed logs
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('network_monitor.log')
            ]
        )

    def start_sniffing(self):
        """Start sniffing packets on the specified interface."""
        logging.info(f"Starting packet sniffing on interface {self.interface}...")
        sniff(prn=self.packet_handler, store=0, iface=self.interface)

    def packet_handler(self, packet):
        """Handler for each captured packet."""
        self.packet_count += 1
        try:
            if IP in packet:
                packet_data = self.create_packet_data(packet)
                if packet_data:
                    print(packet_data)
                    sys.stdout.flush()  # Ensure immediate output
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
            logging.error(traceback.format_exc())

    def create_packet_data(self, packet):
        """Create JSON data for a captured packet."""
        try:
            data = {
                'packet_number': self.packet_count,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'length': len(packet),
                'protocol': 'Other',
                'src_ip': None,
                'dst_ip': None,
                'src_host': None,
                'dst_host': None,
                'src_port': None,
                'dst_port': None
            }

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                # Get device names (could be via database lookup)
                src_name = self.get_device_name(src_ip)
                dst_name = self.get_device_name(dst_ip)

                data.update({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_host': src_name,
                    'dst_host': dst_name
                })

                if TCP in packet:
                    data['protocol'] = 'TCP'
                    data['src_port'] = packet[TCP].sport
                    data['dst_port'] = packet[TCP].dport
                elif UDP in packet:
                    data['protocol'] = 'UDP'
                    data['src_port'] = packet[UDP].sport
                    data['dst_port'] = packet[UDP].dport
                elif ICMP in packet:
                    data['protocol'] = 'ICMP'

            return json.dumps(data)
        except Exception as e:
            logging.error(f"Error creating packet data: {e}")
            logging.error(traceback.format_exc())
            return None  # Skip sending malformed packet

    def get_device_name(self, ip):
        """Resolve device name from IP via database or reverse DNS."""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('SELECT custom_name FROM devices WHERE ip = ?', (ip,))
            result = c.fetchone()
            conn.close()
            if result and result[0]:
                return result[0]
            else:
                # Attempt reverse DNS lookup
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    return hostname
                except socket.herror:
                    return "Unknown"
        except Exception as e:
            logging.error(f"Error getting device name for IP {ip}: {e}")
            return "Unknown"

    def refresh_name_cache(self):
        """Refresh device name cache from the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute('SELECT ip, custom_name FROM devices')
            devices = c.fetchall()
            for ip, name in devices:
                self.name_cache[ip] = name
            conn.close()
            logging.info("Device name cache refreshed.")
        except Exception as e:
            logging.error(f"Error refreshing name cache: {e}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Network Monitor")
    parser.add_argument('--interface', type=str, default='Ethernet', help='Network interface to sniff on')
    args = parser.parse_args()

    monitor = NetworkMonitor(interface=args.interface)
    monitor.start_sniffing()
