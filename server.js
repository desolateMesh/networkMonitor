// server.js

const { spawn } = require('child_process');
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Store WebSocket clients
const wsClients = new Set();

// Add middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from 'public' directory with correct MIME types
app.use(express.static(path.join(__dirname, 'public'), {
    setHeaders: (res, filePath) => {
        if (filePath.endsWith('.js')) {
            res.setHeader('Content-Type', 'application/javascript');
        }
    }
}));

// WebSocket connection handling
wss.on('connection', (ws) => {
    console.log('New WebSocket client connected');
    wsClients.add(ws);
    
    // Optional: Send a welcome message or initial data
    ws.send(JSON.stringify({
        type: 'welcome',
        message: 'Connected to Network Monitor WebSocket Server'
    }));

    ws.on('close', () => {
        wsClients.delete(ws);
        console.log('WebSocket client disconnected');
    });

    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
    });
});

// Store traffic data entries
const trafficData = {
    packets: [],
    protocols: {
        TCP: 0,
        UDP: 0,
        ICMP: 0,
        Other: 0
    }
};

// Start Python network monitor without specifying interface
const pythonMonitor = spawn('python', [
    path.join(__dirname, 'network_monitor.py')  // Remove the --interface parameter
], {
    stdio: ['pipe', 'pipe', 'pipe']
});

// Handle Python script stdout
pythonMonitor.stdout.on('data', (data) => {
    try {
        // Split the output into lines as Python might send multiple packets
        const lines = data.toString().trim().split('\n');
        
        lines.forEach(line => {
            // Try to parse any JSON data in the output
            if (line.startsWith('{') && line.endsWith('}')) {
                const packetData = JSON.parse(line);
                
                // Broadcast to all connected clients
                wsClients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify(packetData));
                    }
                });
                console.log('Broadcasted packet data:', packetData);
            }
            // Log other output for debugging
            else if (line.trim()) {
                console.log('Python output:', line);
            }
        });
    } catch (error) {
        console.error('Error processing Python output:', error);
    }
});

// Handle Python script stderr
pythonMonitor.stderr.on('data', (data) => {
    console.error('Python monitor error:', data.toString());
});

// Handle Python script exit
pythonMonitor.on('close', (code) => {
    console.log(`Python monitor exited with code ${code}`);
    // Optionally, you can restart the Python script or handle the exit gracefully
});

app.get('/api/scan-network', async (req, res) => {
    try {
        // Spawn Python script for network scanning
        const pythonProcess = spawn('python', ['network_scanner.py']);
        
        let deviceData = '';

        pythonProcess.stdout.on('data', (data) => {
            deviceData += data.toString();
        });

        pythonProcess.stderr.on('data', (data) => {
            console.error(`Error: ${data}`);
        });

        pythonProcess.on('close', (code) => {
            if (code !== 0) {
                return res.status(500).json({ error: 'Scan failed' });
            }
            try {
                const devices = JSON.parse(deviceData);
                res.json(devices);
            } catch (error) {
                res.status(500).json({ error: 'Failed to parse device data' });
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Scan failed' });
    }
});


app.post('/api/device/name', (req, res) => {
    console.log('Received rename request:', req.body);
    const { mac, name } = req.body;

    const pythonProcess = spawn('python', ['-c', `
import json
from network_scanner import DeviceTracker

try:
    print("DEBUG: Starting Python rename process")
    tracker = DeviceTracker()
    result = tracker.set_device_name("${mac}", "${name}")
    print("DEBUG: Result from set_device_name:", json.dumps(result))
except Exception as e:
    print("ERROR:", str(e))
    result = {"success": False, "error": str(e)}

print("RESULT:" + json.dumps(result))
`]);

    let resultData = '';

    pythonProcess.stdout.on('data', (data) => {
        console.log('Python output:', data.toString().trim());
        resultData += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error('Python error:', data.toString().trim());
    });

    pythonProcess.on('close', (code) => {
        console.log('Python process exited with code:', code);
        try {
            // Look for the actual result line
            const resultLine = resultData.split('\n')
                .find(line => line.startsWith('RESULT:'));
            
            if (resultLine) {
                const jsonResult = JSON.parse(resultLine.substring(7));
                res.json(jsonResult);
            } else {
                throw new Error('No result found in Python output');
            }
        } catch (e) {
            console.error('Error parsing Python response:', e);
            res.status(500).json({ 
                error: 'Invalid response',
                pythonOutput: resultData
            });
        }
    });
});


app.get('/api/device/state/:mac', (req, res) => {
    const { mac } = req.params;
    console.log('Checking state for device:', mac);  // Debug log

    const pythonProcess = spawn('python', ['-c', `
import json
import sqlite3
from datetime import datetime

try:
    # Connect to database
    conn = sqlite3.connect('devices.db')
    c = conn.cursor()
    
    # Get device info
    c.execute('SELECT * FROM devices WHERE mac = ?', ("""${mac}""",))
    device = c.fetchone()
    
    if device:
        # Convert tuple to dictionary
        device_info = {
            "mac": device[0],
            "first_seen": device[1],
            "last_seen": device[2],
            "hostname": device[3],
            "custom_name": device[4],
            "device_type": device[5],
            "manufacturer": device[6]
        }
        print(json.dumps(device_info))
    else:
        print(json.dumps({"error": "Device not found"}))
    
    conn.close()
except Exception as e:
    print(json.dumps({"error": str(e)}))
    `]);

    let result = '';
    
    pythonProcess.stdout.on('data', (data) => {
        console.log('Python output:', data.toString());  // Debug log
        result += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error('Python error:', data.toString());
    });

    pythonProcess.on('close', (code) => {
        console.log('Python process exited with code:', code);
        if (code !== 0) {
            return res.status(500).json({ error: 'Failed to get device state' });
        }
        try {
            const deviceState = JSON.parse(result);
            res.json(deviceState);
        } catch (e) {
            console.error('JSON parse error:', e);
            res.status(500).json({ error: 'Invalid response from Python' });
        }
    });
});


app.get('/api/scan-subnets', async (req, res) => {
    console.log('Starting subnet scan...');
    
    const pythonProcess = spawn('python', [
        path.join(__dirname, 'subnet_scanner.py')
    ]);

    let dataBuffer = '';

    pythonProcess.stdout.on('data', (data) => {
        const output = data.toString();
        console.log('Scanner output:', output);
        
        // Broadcast raw output to WebSocket clients
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                if (output.includes('"ip":')) {
                    // Try to parse device data
                    try {
                        const device = JSON.parse(output);
                        client.send(JSON.stringify({
                            type: 'subnet_scan',
                            data: {
                                type: 'device_found',
                                device: device
                            }
                        }));
                    } catch (e) {
                        console.error('Error parsing device data:', e);
                    }
                } else {
                    // Send progress message
                    client.send(JSON.stringify({
                        type: 'subnet_scan',
                        data: {
                            type: 'progress',
                            message: output
                        }
                    }));
                }
            }
        });
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error('Scanner error:', data.toString());
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({
                    type: 'subnet_scan',
                    data: {
                        type: 'error',
                        message: data.toString()
                    }
                }));
            }
        });
    });

    pythonProcess.on('close', (code) => {
        console.log(`Scanner process exited with code ${code}`);
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({
                    type: 'subnet_scan',
                    data: {
                        type: 'scan_complete',
                        code: code
                    }
                }));
            }
        });
    });

    res.json({ status: 'scanning' });
});


app.get('/api/device/ip/:ip', (req, res) => {
    const { ip } = req.params;
    const pythonProcess = spawn('python', ['-c', `
import sqlite3
from database import NetworkDB

try:
    db = NetworkDB()
    conn = sqlite3.connect('devices.db')
    c = conn.cursor()
    
    # Get the most recent MAC address for this IP
    c.execute('''
        SELECT mac FROM ip_history 
        WHERE ip_address = ? 
        ORDER BY timestamp DESC 
        LIMIT 1
    ''', (ip,))
    
    result = c.fetchone()
    if result:
        print({"mac": result[0]})
    else:
        print({"error": "IP not found"})
        
    conn.close()
except Exception as e:
    print({"error": str(e)})
    `]);

    let resultData = '';
    
    pythonProcess.stdout.on('data', (data) => {
        resultData += data.toString();
    });

    pythonProcess.on('close', (code) => {
        try {
            const result = JSON.parse(resultData);
            res.json(result);
        } catch (e) {
            res.status(500).json({ error: 'Invalid response from Python' });
        }
    });
});


app.get('/api/devices/history/:mac', (req, res) => {
    const { mac } = req.params;
    const pythonProcess = spawn('python', ['-c', `
        from database import NetworkDB
        db = NetworkDB()
        history = db.get_device_history('${mac}')
        print(history)
    `]);
    // ... handle process output and send response
});

app.post('/api/devices/trust/:mac', (req, res) => {
    const { mac } = req.params;
    const pythonProcess = spawn('python', ['-c', `
        from database import NetworkDB
        db = NetworkDB()
        success = db.set_device_trust_status('${mac}', True)
        print(success)
    `]);
    // ... handle process output and send response
});

app.get('/api/alerts', (req, res) => {
    const pythonProcess = spawn('python', ['-c', `
        from intrusion_detection import IntrusionDetector
        detector = IntrusionDetector()
        print(detector.get_recent_alerts_json())
    `]);
    
    let data = '';
    pythonProcess.stdout.on('data', (chunk) => {
        data += chunk;
    });
    
    pythonProcess.on('close', (code) => {
        if (code !== 0) {
            res.status(500).json({ error: 'Failed to fetch alerts' });
        } else {
            res.send(data);
        }
    });
});

app.get('/api/blocked-ips', (req, res) => {
    const pythonProcess = spawn('python', ['-c', `
        from intrusion_detection import IntrusionDetector
        detector = IntrusionDetector()
        print(detector.get_blocked_ips_json())
    `]);
    
    let data = '';
    pythonProcess.stdout.on('data', (chunk) => {
        data += chunk;
    });
    
    pythonProcess.on('close', (code) => {
        if (code !== 0) {
            res.status(500).json({ error: 'Failed to fetch blocked IPs' });
        } else {
            res.send(data);
        }
    });
});

app.post('/api/block-ip', (req, res) => {
    const { ip, reason } = req.body;
    const pythonProcess = spawn('python', ['-c', `
        from intrusion_detection import IntrusionDetector
        detector = IntrusionDetector()
        detector._block_ip("${ip}", "${reason}")
        print('{"success": true}')
    `]);
    
    pythonProcess.on('close', (code) => {
        if (code !== 0) {
            res.status(500).json({ error: 'Failed to block IP' });
        } else {
            res.json({ success: true });
        }
    });
});

app.post('/api/unblock-ip', (req, res) => {
    const { ip } = req.body;
    const pythonProcess = spawn('python', ['-c', `
        from intrusion_detection import IntrusionDetector
        detector = IntrusionDetector()
        # Add unblock method to your IntrusionDetector class
        detector._unblock_ip("${ip}")
        print('{"success": true}')
    `]);
    
    pythonProcess.on('close', (code) => {
        if (code !== 0) {
            res.status(500).json({ error: 'Failed to unblock IP' });
        } else {
            res.json({ success: true });
        }
    });
});

// Error handling for the Python process
process.on('exit', () => {
    if (global.intrusionDetector) {
        global.intrusionDetector.kill();
    }
});


process.on('SIGINT', () => {
    console.log('Shutting down server...');
    pythonMonitor.kill();
    // Kill other Python scripts if any (e.g., intrusionDetector)
    if (global.intrusionDetector) {
        global.intrusionDetector.kill();
    }
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

// Start the server
const PORT = 8080;
server.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
    console.log('Network monitor is running...');
});