# db.py

import sqlite3
from datetime import datetime
import logging

class NetworkDB:
    def __init__(self, db_name='devices.db'):
        self.db_name = db_name
        self.setup_logging()
        self.setup_database()

    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            filename='network_monitor.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def setup_database(self):
        """Initialize the database with required tables"""
        try:
            with sqlite3.connect(self.db_name, timeout=30) as conn:
                c = conn.cursor()
                
                # Main devices table
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

                # Connection history
                c.execute('''
                    CREATE TABLE IF NOT EXISTS connection_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac TEXT,
                        connected_at TIMESTAMP,
                        disconnected_at TIMESTAMP,
                        FOREIGN KEY (mac) REFERENCES devices(mac)
                    )
                ''')

                conn.commit()
                logging.info("Database initialized successfully")

        except sqlite3.Error as e:
            logging.error(f"Database initialization error: {e}")
            raise

    def add_or_update_device(self, mac, ip_address, hostname=None):
        """Add a new device or update existing device information"""
        try:
            current_time = datetime.now()
            
            with sqlite3.connect(self.db_name, timeout=30) as conn:
                c = conn.cursor()
                
                # Check if device exists
                c.execute('SELECT mac FROM devices WHERE mac = ?', (mac,))
                device_exists = c.fetchone() is not None

                if device_exists:
                    # Update existing device
                    c.execute('''
                        UPDATE devices 
                        SET last_seen = ?,
                            hostname = COALESCE(?, hostname)
                        WHERE mac = ?
                    ''', (current_time, hostname, mac))
                else:
                    # Insert new device
                    c.execute('''
                        INSERT INTO devices (
                            mac, first_seen, last_seen, hostname
                        ) VALUES (?, ?, ?, ?)
                    ''', (mac, current_time, current_time, hostname))

                # Record IP address in history
                c.execute('''
                    INSERT INTO ip_history (mac, ip_address, timestamp)
                    VALUES (?, ?, ?)
                ''', (mac, ip_address, current_time))

                conn.commit()
                logging.info(f"{'Updated' if device_exists else 'Added'} device: {mac}")
                return True

        except sqlite3.Error as e:
            logging.error(f"Error adding/updating device {mac}: {e}")
            return False

    def set_device_name(self, mac, custom_name):
        """Set a custom name for a device"""
        try:
            with sqlite3.connect(self.db_name, timeout=30) as conn:
                c = conn.cursor()
                c.execute('''
                    UPDATE devices 
                    SET custom_name = ?
                    WHERE mac = ?
                ''', (custom_name, mac))
                conn.commit()
                logging.info(f"Set custom name for device {mac}: {custom_name}")
                return True
        except sqlite3.Error as e:
            logging.error(f"Error setting device name: {e}")
            return False

    def set_device_trust_status(self, mac, trusted=True):
        """Set device trust status"""
        try:
            with sqlite3.connect(self.db_name, timeout=30) as conn:
                c = conn.cursor()
                c.execute('''
                    UPDATE devices 
                    SET is_trusted = ?
                    WHERE mac = ?
                ''', (trusted, mac))
                conn.commit()
                logging.info(f"Set trust status for device {mac}: {trusted}")
                return True
        except sqlite3.Error as e:
            logging.error(f"Error setting trust status: {e}")
            return False

    def set_device_block_status(self, mac, blocked=True):
        """Set device block status"""
        try:
            with sqlite3.connect(self.db_name, timeout=30) as conn:
                c = conn.cursor()
                c.execute('''
                    UPDATE devices 
                    SET is_blocked = ?
                    WHERE mac = ?
                ''', (blocked, mac))
                conn.commit()
                logging.info(f"Set block status for device {mac}: {blocked}")
                return True
        except sqlite3.Error as e:
            logging.error(f"Error setting block status: {e}")
            return False

    def get_device_info(self, mac):
        """Get all information about a specific device"""
        try:
            with sqlite3.connect(self.db_name, timeout=30) as conn:
                c = conn.cursor()
                c.execute('''
                    SELECT * FROM devices WHERE mac = ?
                ''', (mac,))
                device = c.fetchone()
                
                if device:
                    # Get recent IP history
                    c.execute('''
                        SELECT ip_address, timestamp 
                        FROM ip_history 
                        WHERE mac = ? 
                        ORDER BY timestamp DESC 
                        LIMIT 5
                    ''', (mac,))
                    ip_history = c.fetchall()
                    
                    return {
                        'device': device,
                        'ip_history': ip_history
                    }
                return None
                
        except sqlite3.Error as e:
            logging.error(f"Error getting device info: {e}")
            return None

    def get_all_devices(self):
        """Get all devices with their current status"""
        try:
            with sqlite3.connect(self.db_name, timeout=30) as conn:
                c = conn.cursor()
                c.execute('''
                    SELECT 
                        d.*,
                        (SELECT ip_address 
                         FROM ip_history 
                         WHERE mac = d.mac 
                         ORDER BY timestamp DESC 
                         LIMIT 1) as last_ip
                    FROM devices d
                    ORDER BY last_seen DESC
                ''')
                return c.fetchall()
        except sqlite3.Error as e:
            logging.error(f"Error getting all devices: {e}")
            return []

    def get_device_history(self, mac):
        """Get complete history for a device"""
        try:
            with sqlite3.connect(self.db_name, timeout=30) as conn:
                c = conn.cursor()
                
                # Get IP history
                c.execute('''
                    SELECT ip_address, timestamp 
                    FROM ip_history 
                    WHERE mac = ? 
                    ORDER BY timestamp DESC
                ''', (mac,))
                ip_history = c.fetchall()
                
                # Get connection history
                c.execute('''
                    SELECT connected_at, disconnected_at 
                    FROM connection_history 
                    WHERE mac = ? 
                    ORDER BY connected_at DESC
                ''', (mac,))
                connection_history = c.fetchall()
                
                return {
                    'ip_history': ip_history,
                    'connection_history': connection_history
                }
        except sqlite3.Error as e:
            logging.error(f"Error getting device history: {e}")
            return None

    def add_device_note(self, mac, note):
        """Add or update notes for a device"""
        try:
            with sqlite3.connect(self.db_name, timeout=30) as conn:
                c = conn.cursor()
                c.execute('''
                    UPDATE devices 
                    SET notes = ?
                    WHERE mac = ?
                ''', (note, mac))
                conn.commit()
                return True
        except sqlite3.Error as e:
            logging.error(f"Error adding device note: {e}")
            return False
        
    def get_device_details(self, mac):
        """Get all details for a device"""
        try:
            conn = sqlite3.connect('devices.db', timeout=30)
            c = conn.cursor()
            c.execute('SELECT * FROM devices WHERE mac = ?', (mac,))
            device = c.fetchone()
            conn.close()
            logging.debug(f"Device details for {mac}: {device}")  # Changed from print to logging
            return device
        except Exception as e:
            logging.error(f"Error getting device details: {str(e)}")
            return None

    def reset_database(self):
        """Reset the database completely - use with caution!"""
        try:
            with sqlite3.connect(self.db_name, timeout=30) as conn:
                c = conn.cursor()
                # Drop all tables
                c.execute('DROP TABLE IF EXISTS ip_history')
                c.execute('DROP TABLE IF EXISTS connection_history')
                c.execute('DROP TABLE IF EXISTS devices')
                
                # Recreate tables
                self.setup_database()  # This will recreate all tables fresh
                
                logging.info("Database reset successfully")
                return True
        except sqlite3.Error as e:
            logging.error(f"Error resetting database: {e}")
            return False

    def get_custom_name_by_ip(self, ip):
        """Get the custom name of a device based on its current IP address."""
        try:
            with sqlite3.connect(self.db_name, timeout=30) as conn:
                c = conn.cursor()
                # Get the MAC address associated with the latest timestamp for this IP
                c.execute('''
                    SELECT mac FROM ip_history
                    WHERE ip_address = ?
                    ORDER BY timestamp DESC
                    LIMIT 1
                ''', (ip,))
                result = c.fetchone()
                if result:
                    mac = result[0]
                    # Get custom name from devices table
                    c.execute('SELECT custom_name FROM devices WHERE mac = ?', (mac,))
                    name_result = c.fetchone()
                    if name_result and name_result[0]:
                        return name_result[0]
                # If no custom name found, return None
                return None
        except sqlite3.Error as e:
            logging.error(f"Error getting custom name by IP {ip}: {e}")
            return None
