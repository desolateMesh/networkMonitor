from scapy.all import ARP, Ether, IP, TCP, UDP, ICMP, srp, sr1, conf
import netifaces
from ipaddress import IPv4Network, IPv4Address, IPv4Interface
import socket
import json
import sqlite3
from database import NetworkDB
from datetime import datetime
import logging
import struct
import subprocess
import platform

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class NetworkMapper:
    def __init__(self):
        self.known_devices = {}
        self.switch_manufacturers = {
            '00:0c:29': 'VMware',
            '00:1a:6c': 'Cisco',
            '00:1c:7e': 'Cisco',
            '00:21:55': 'Cisco',
            'fc:f5:28': 'Cisco',
            '00:0d:54': 'Cisco',
            '00:40:96': '3Com/HP',
            '00:60:b0': 'HP',
            '00:14:c2': 'HP',
            '00:1b:3f': 'Dell',
            '00:24:b1': 'Netgear',
            '00:14:6c': 'Netgear',
            '00:12:17': 'D-Link'
        }

    def netmask_to_cidr(self, netmask):
        """Convert netmask to CIDR notation"""
        try:
            return sum([bin(int(x)).count('1') for x in netmask.split('.')])
        except Exception as e:
            logger.error(f"Error converting netmask {netmask}: {e}")
            return 24  # Default to /24 if conversion fails

    def get_interfaces(self):
        """Get all network interfaces"""
        interfaces = {}
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if 'addr' in addr and not addr['addr'].startswith('127.'):
                            cidr = self.netmask_to_cidr(addr['netmask'])
                            network = f"{addr['addr']}/{cidr}"
                            # Create proper network address
                            ip_interface = IPv4Interface(network)
                            network_addr = str(ip_interface.network)
                            
                            interfaces[iface] = {
                                'ip': addr['addr'],
                                'netmask': addr['netmask'],
                                'cidr': cidr,
                                'network': network_addr
                            }
            logger.debug(f"Found interfaces: {json.dumps(interfaces, indent=2)}")
            return interfaces
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            return {}

    def ping_sweep(self, network):
        """Perform a ping sweep of the network"""
        active_ips = []
        try:
            network_obj = IPv4Network(network, strict=False)
            base_ip = str(network_obj.network_address)
            ping_command = "ping -n 1 -w 500" if platform.system().lower() == "windows" else "ping -c 1 -W 1"
            
            logger.debug(f"Starting ping sweep of network {network}")
            
            for ip in network_obj.hosts():
                ip_str = str(ip)
                try:
                    result = subprocess.run(
                        f"{ping_command} {ip_str}",
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    if result.returncode == 0:
                        active_ips.append(ip_str)
                        logger.debug(f"Ping successful for {ip_str}")
                except Exception as e:
                    logger.debug(f"Ping failed for {ip_str}: {e}")
                    continue
                    
            return active_ips
        except Exception as e:
            logger.error(f"Error in ping sweep: {e}")
            return []

    def scan_network(self, network):
        """Scan a network range using multiple methods"""
        logger.info(f"Scanning network: {network}")
        devices = []
        db = NetworkDB()  # Create database instance
        
        try:
            # First do a ping sweep
            active_ips = self.ping_sweep(network)
            logger.debug(f"Ping sweep found {len(active_ips)} active IPs")
            
            # Then do ARP scan
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            result = srp(ether/arp, timeout=2, verbose=0)[0]
            
            logger.debug(f"ARP scan found {len(result)} devices")
            
            # Process ARP responses
            for sent, received in result:
                try:
                    ip = received.psrc
                    mac = received.hwsrc.lower()
                    
                    # Try to get hostname
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = "Unknown"

                    # Get device info from database
                    device_info = db.get_device_info(mac)
                    if device_info and device_info['device']:
                        db_device = device_info['device']
                        custom_name = db_device[4]  # custom_name is the 5th field in devices table
                        device_type = db_device[5]  # device_type is the 6th field
                        manufacturer = db_device[6]  # manufacturer is the 7th field
                    else:
                        custom_name = None
                        device_type = None
                        manufacturer = None

                    # Check if it's a known switch/router
                    is_network_device = self.is_switch(mac)
                    if not manufacturer:
                        manufacturer = self.get_manufacturer(mac)
                    
                    # Additional port scanning for device type detection
                    if not device_type:
                        device_type = self.determine_device_type(ip, mac, is_network_device)
                    
                    device = {
                        'ip': ip,
                        'mac': mac,
                        'hostname': custom_name or hostname,
                        'custom_name': custom_name,
                        'manufacturer': manufacturer,
                        'type': device_type,
                        'response_time': self.get_response_time(ip),
                        'last_seen': datetime.now().isoformat(),
                        'subnet': str(IPv4Network(f"{ip}/24", strict=False))
                    }

                    # Update database with new information
                    db.add_or_update_device(mac, ip, hostname)
                    
                    # Print each device as JSON for real-time processing
                    print(json.dumps(device))
                    devices.append(device)
                    
                except Exception as e:
                    logger.error(f"Error processing device: {e}")
                    continue
                        
            # Add any ping-responsive devices that weren't found via ARP
            for ip in active_ips:
                if not any(d['ip'] == ip for d in devices):
                    try:
                        device = {
                            'ip': ip,
                            'mac': 'Unknown',
                            'hostname': socket.gethostbyaddr(ip)[0] if socket.gethostbyaddr(ip)[0] else 'Unknown',
                            'manufacturer': 'Unknown',
                            'type': 'host',
                            'response_time': self.get_response_time(ip),
                            'last_seen': datetime.now().isoformat(),
                            'subnet': str(IPv4Network(f"{ip}/24", strict=False))
                        }
                        print(json.dumps(device))
                        devices.append(device)
                    except Exception as e:
                        logger.debug(f"Error adding ping-responsive device {ip}: {e}")
                        
        except Exception as e:
            logger.error(f"Error scanning network {network}: {e}")
                
        return devices

    def is_switch(self, mac):
        """Check if MAC belongs to a known switch manufacturer"""
        mac = mac.lower()
        return any(mac.startswith(prefix.lower().replace(':', '')) 
                  for prefix in self.switch_manufacturers.keys())

    def get_manufacturer(self, mac):
        """Get manufacturer name from MAC address"""
        mac = mac.lower()
        for prefix, manufacturer in self.switch_manufacturers.items():
            if mac.startswith(prefix.lower().replace(':', '')):
                return manufacturer
        return 'Unknown'

    def determine_device_type(self, ip, mac, is_known_switch):
        """Determine device type based on various checks"""
        if is_known_switch:
            return 'switch'
            
        # Check common network device ports
        common_ports = {
            22: 'SSH',
            23: 'Telnet',
            80: 'HTTP',
            443: 'HTTPS',
            161: 'SNMP'
        }
        
        open_ports = []
        for port in common_ports:
            try:
                tcp_syn = IP(dst=ip)/TCP(dport=port, flags="S")
                response = sr1(tcp_syn, timeout=1, verbose=0)
                if response and response.haslayer(TCP):
                    if response[TCP].flags == 0x12:  # SYN-ACK
                        open_ports.append(port)
            except:
                continue
                
        # If multiple management ports are open, likely a network device
        if len(open_ports) >= 2:
            return 'network_device'
        
        return 'host'

    def get_response_time(self, ip):
        """Get ping response time for a device"""
        try:
            ping_command = "ping -n 1 -w 500" if platform.system().lower() == "windows" else "ping -c 1 -W 1"
            result = subprocess.run(
                f"{ping_command} {ip}",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            if result.returncode == 0:
                # Extract time from ping output
                output = result.stdout.decode()
                if "time=" in output.lower():
                    time_str = output.lower().split("time=")[1].split()[0]
                    return float(time_str.replace("ms", ""))
            return None
        except:
            return None

    def scan_all_networks(self):
        """Scan all available networks"""
        network_map = {
            'subnets': {},
            'devices': [],
            'scan_time': datetime.now().isoformat()
        }
        
        try:
            interfaces = self.get_interfaces()
            
            for iface, details in interfaces.items():
                logger.info(f"Scanning interface {iface}")
                try:
                    devices = self.scan_network(details['network'])
                    network_map['subnets'][details['network']] = {
                        'interface': iface,
                        'ip': details['ip'],
                        'netmask': details['netmask'],
                        'devices': devices
                    }
                    network_map['devices'].extend(devices)
                except Exception as e:
                    logger.error(f"Error scanning interface {iface}: {e}")
                    continue
            
            return network_map
            
        except Exception as e:
            logger.error(f"Error in network scan: {e}")
            return {'error': str(e)}

def main():
    """Main function"""
    try:
        logger.info("Starting network scan...")
        mapper = NetworkMapper()
        network_map = mapper.scan_all_networks()
        print(json.dumps(network_map, indent=2))
    except Exception as e:
        logger.error(f"Error in main: {e}")
        print(json.dumps({'error': str(e)}))

if __name__ == "__main__":
    main()