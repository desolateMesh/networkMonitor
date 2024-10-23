const { spawn } = require('child_process');
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Serve static files from the public folder
app.use(express.static('public'));

// Store traffic data entries
const trafficData = {
    packets: [],
    protocols: {
        TCP: 0,
        UDP: 0,
        ICMP: 0,
        Other: 0
    },
    topTalkers: new Map()
};

// Start Python network monitor
const pythonMonitor = spawn('python', [
    path.join(__dirname, 'network_monitor.py')
], {
    stdio: ['pipe', 'pipe', 'pipe']
});

// Handle Python script output
pythonMonitor.stdout.on('data', (data) => {
    try {
        // Split the output into lines as Python might send multiple packets
        const lines = data.toString().trim().split('\n');
        
        lines.forEach(line => {
            // Try to parse any JSON data in the output
            if (line.includes('{') && line.includes('}')) {
                const jsonStr = line.substring(
                    line.indexOf('{'),
                    line.lastIndexOf('}') + 1
                );
                const packetData = JSON.parse(jsonStr);
                
                // Store packet data
                trafficData.packets.push(packetData);
                if (trafficData.packets.length > 1000) {
                    trafficData.packets.shift();
                }

                // Update protocol stats
                if (packetData.protocol) {
                    trafficData.protocols[packetData.protocol]++;
                }

                // Broadcast to all connected clients
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify(packetData));
                    }
                });
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

// Handle Python script errors
pythonMonitor.stderr.on('data', (data) => {
    console.error('Python error:', data.toString());
});

// Handle Python script exit
pythonMonitor.on('close', (code) => {
    console.log(`Python monitor exited with code ${code}`);
});

// WebSocket connection handling
wss.on('connection', (ws) => {
    console.log('New WebSocket client connected');
    
    // Send current statistics
    ws.send(JSON.stringify({
        type: 'stats',
        data: {
            protocols: trafficData.protocols,
            recentPackets: trafficData.packets.slice(-50)
        }
    }));

    // Handle client disconnection
    ws.on('close', () => {
        console.log('Client disconnected');
    });
});

// Error handling for the Python process
process.on('exit', () => {
    pythonMonitor.kill();
});

process.on('SIGINT', () => {
    pythonMonitor.kill();
    process.exit();
});

// Set correct MIME types
app.use(express.static('public', {
    setHeaders: (res, path) => {
        if (path.endsWith('.js')) {
            res.setHeader('Content-Type', 'application/javascript');
        }
    }
}));

// API endpoint for scanning the network
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
    const { mac, name } = req.body;
    const pythonProcess = spawn('python', ['-c', `
from network_scanner import DeviceTracker
tracker = DeviceTracker()
success = tracker.set_device_name("${mac}", "${name}")
print(json.dumps({"success": success}))
    `]);

    let result = '';
    
    pythonProcess.stdout.on('data', (data) => {
        result += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
        console.error(`Error: ${data}`);
    });

    pythonProcess.on('close', (code) => {
        if (code !== 0) {
            return res.status(500).json({ error: 'Failed to update device name' });
        }
        try {
            const response = JSON.parse(result);
            res.json(response);
        } catch (e) {
            res.status(500).json({ error: 'Invalid response' });
        }
    });
});


// Add these endpoints to your server.js
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





// Start the server
server.listen(8080, () => {
    console.log('Server started on port 8080');
    console.log('Network monitor starting...');
});