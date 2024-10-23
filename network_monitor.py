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
        self.setup_logging()
        self.packet_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}
        self.dns_cache = {}  # Cache for DNS resolutions
        self.tcp_streams = defaultdict(list)
        self.connected_clients = set()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )

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

    def create_packet_data(self, packet, payload_info):
        """Create JSON data for web visualization"""
        data = {
            'packet_number': self.packet_count,
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'length': len(packet)
        }

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            data.update({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_host': self.dns_cache.get(src_ip, src_ip),
                'dst_host': self.dns_cache.get(dst_ip, dst_ip)
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
        # Your existing analyze_payload method remains the same
        # The rest of your analyze_payload code stays here
        #return payload_info

    async def packet_callback(self, packet):
        """Process each captured packet"""
        try:
            self.packet_count += 1
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Resolve DNS names
                src_host = self.resolve_dns(src_ip)
                dst_host = self.resolve_dns(dst_ip)
                
                # Console output (your existing print statements)
                print(f"\nPacket #{self.packet_count}")
                print("-" * 80)
                # ... rest of your print statements ...

                # Update statistics
                if TCP in packet:
                    self.packet_stats['TCP'] += 1
                elif UDP in packet:
                    self.packet_stats['UDP'] += 1
                elif ICMP in packet:
                    self.packet_stats['ICMP'] += 1
                else:
                    self.packet_stats['Other'] += 1

                # Analyze payload
                payload_info = self.analyze_payload(packet)
                
                # Create and send packet data to web clients
                packet_data = self.create_packet_data(packet, payload_info)
                await self.broadcast_packet(packet_data)
                
        except Exception as e:
            logging.error(f"Error processing packet: {str(e)}")

    async def start_websocket_server(self):
        """Start WebSocket server"""
        async with websockets.serve(self.register_client, "localhost", 8765):
            await asyncio.Future()  # run forever

    def packet_handler(self, packet):
        """Handler for scapy's sniff function that works with asyncio"""
        asyncio.run(self.packet_callback(packet))

    async def start_capture(self):
        """Start packet capture"""
        try:
            print("\nStarting enhanced packet capture... Press CTRL+C to stop")
            print("=" * 80)
            
            # Run the packet capture in a separate thread to not block asyncio
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: sniff(prn=self.packet_handler, store=0)
            )
            
        except KeyboardInterrupt:
            print("\nCapture stopped by user")
        finally:
            print("\nFinal Statistics:")
            for proto, count in self.packet_stats.items():
                print(f"{proto}: {count} packets")

async def main():
    monitor = NetworkMonitor()
    
    # Run both WebSocket server and packet capture
    await asyncio.gather(
        monitor.start_websocket_server(),
        monitor.start_capture()
    )

if __name__ == "__main__":
    asyncio.run(main())