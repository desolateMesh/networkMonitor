import sqlite3
from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLS
import socket
import logging
from datetime import datetime
import sys
from pathlib import Path
from collections import defaultdict
import json
import asyncio
import websockets

class NetworkMonitor:
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_count = 0
        self.packet_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        self.dns_cache = {}  # Cache for DNS resolutions
        self.name_cache = {}  # New cache for custom names
        self.tcp_streams = defaultdict(list)
        self.connected_clients = set()
        self.db_path = 'devices.db'
        self.setup_logging()  # Set up logging first
        self.refresh_name_cache()  # Load custom names at startup

    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )

    def refresh_name_cache(self):
        """Load custom names from database into cache"""
        try:
            with sqlite3.connect(self.db_path, timeout=30) as conn:
                c = conn.cursor()
                c.execute('''
                    SELECT mac, hostname, custom_name 
                    FROM devices 
                    WHERE custom_name IS NOT NULL
                ''')
                for mac, hostname, custom_name in c.fetchall():
                    if custom_name:  # Prefer custom name if available
                        self.name_cache[mac] = custom_name
                    elif hostname:  # Fall back to hostname
                        self.name_cache[mac] = hostname
        except sqlite3.Error as e:
            logging.error(f"Database error loading names: {e}")

    def get_device_name(self, ip):
        """Get device name using IP address, checking custom names first"""
        try:
            # First try to get MAC address for this IP
            with sqlite3.connect(self.db_path, timeout=30) as conn:
                c = conn.cursor()
                c.execute('''
                    SELECT d.mac, d.custom_name, d.hostname
                    FROM devices d
                    JOIN ip_history ih ON d.mac = ih.mac
                    WHERE ih.ip_address = ?
                    ORDER BY ih.timestamp DESC
                    LIMIT 1
                ''', (ip,))
                result = c.fetchone()
                
                if result:
                    mac, custom_name, hostname = result
                    if custom_name:  # Prefer custom name
                        return custom_name
                    elif hostname:  # Then hostname
                        return hostname
                    
        except sqlite3.Error as e:
            logging.error(f"Database error getting device name: {e}")
        
        # Fall back to DNS resolution if no custom name found
        return self.resolve_dns(ip)

    def resolve_dns(self, ip):
        """Resolve IP to hostname using DNS"""
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = hostname
            return hostname
        except (socket.herror, socket.gaierror):
            self.dns_cache[ip] = ip
            return ip

    def analyze_payload(self, packet):
        """Analyze packet payload and return meaningful information"""
        payload_info = {}
        if packet.haslayer(Raw):
            try:
                # Add your payload analysis logic here
                pass
            except Exception as e:
                logging.error(f"Error analyzing payload: {e}")
        return payload_info

    def create_packet_data(self, packet, payload_info):
        """Create JSON data for web visualization with custom names"""
        data = {
            'packet_number': self.packet_count,
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'length': len(packet)
        }

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Get custom names or hostnames for both source and destination
            src_name = self.get_device_name(src_ip)
            dst_name = self.get_device_name(dst_ip)
            
            data.update({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_host': src_name,
                'dst_host': dst_name
            })

            if TCP in packet:
                data.update({
                    'protocol': 'TCP',
                    'src_port': packet[TCP].sport,
                    'dst_port': packet[TCP].dport,
                    'flags': str(packet[TCP].flags),
                    'service': 'HTTPS' if packet[TCP].dport == 443 else 'HTTP' if packet[TCP].dport == 80 else 'Unknown'
                })
            elif UDP in packet:
                data.update({
                    'protocol': 'UDP',
                    'src_port': packet[UDP].sport,
                    'dst_port': packet[UDP].dport
                })
            elif ICMP in packet:
                data.update({
                    'protocol': 'ICMP',
                    'icmp_type': packet[ICMP].type
                })
            else:
                data.update({'protocol': 'Other'})

        if payload_info:
            data['payload_info'] = payload_info

        return json.dumps(data)

    async def register_client(self, websocket):
        """Register a new WebSocket client"""
        self.connected_clients.add(websocket)
        try:
            await websocket.wait_closed()
        finally:
            self.connected_clients.remove(websocket)

    async def broadcast_packet(self, packet_data):
        """Broadcast packet data to all connected WebSocket clients"""
        if self.connected_clients:
            await asyncio.gather(
                *[client.send(packet_data) for client in self.connected_clients],
                return_exceptions=True
            )

    async def packet_callback(self, packet):
        """Process each captured packet"""
        try:
            self.packet_count += 1
            
            # Analyze packet and create data
            payload_info = self.analyze_payload(packet)
            packet_data = self.create_packet_data(packet, payload_info)
            
            # Update statistics
            if TCP in packet:
                self.packet_stats['TCP'] += 1
            elif UDP in packet:
                self.packet_stats['UDP'] += 1
            elif ICMP in packet:
                self.packet_stats['ICMP'] += 1
            else:
                self.packet_stats['Other'] += 1

            # Broadcast to clients
            await self.broadcast_packet(packet_data)
                
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")

    def packet_handler(self, packet):
        """Handler for scapy's sniff function that works with asyncio"""
        asyncio.run(self.packet_callback(packet))

    async def start_websocket_server(self):
        """Start WebSocket server"""
        async with websockets.serve(self.register_client, "localhost", 8765):
            await asyncio.Future()  # run forever

    async def start_capture(self):
        """Start packet capture"""
        try:
            logging.info("\nStarting enhanced packet capture... Press CTRL+C to stop")
            
            # Run the packet capture in a separate thread to not block asyncio
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: sniff(prn=self.packet_handler, store=0)
            )
            
        except KeyboardInterrupt:
            logging.info("\nCapture stopped by user")
        finally:
            logging.info("\nFinal Statistics:")
            for proto, count in self.packet_stats.items():
                logging.info(f"{proto}: {count} packets")

async def main():
    monitor = NetworkMonitor()
    
    # Run both WebSocket server and packet capture
    await asyncio.gather(
        monitor.start_websocket_server(),
        monitor.start_capture()
    )

if __name__ == "__main__":
    asyncio.run(main())