// WebSocket connection
const ws = new WebSocket('ws://localhost:8765');

// Traffic data storage
let trafficData = {
    packets: [],
    protocols: {
        TCP: 0,
        UDP: 0,
        ICMP: 0,
        Other: 0
    },
    bandwidthData: [],
    topTalkers: new Map()
};

// Device cache for names
let deviceCache = new Map();

// Initialize visualizations
function initializeVisualizations() {
    const trafficInfo = document.getElementById('trafficInfo');
    
    // Clear existing content
    trafficInfo.innerHTML = '';
    
    // Create protocol distribution chart
    const protocolCanvas = document.createElement('canvas');
    protocolCanvas.id = 'protocolChart';
    trafficInfo.appendChild(protocolCanvas);

    // Create bandwidth usage chart
    const bandwidthCanvas = document.createElement('canvas');
    bandwidthCanvas.id = 'bandwidthChart';
    trafficInfo.appendChild(bandwidthCanvas);

    // Create packet details table
    const tableDiv = document.createElement('div');
    tableDiv.innerHTML = `
        <table id="packetTable">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Length</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    `;
    trafficInfo.appendChild(tableDiv);

    initializeCharts();
}

// Initialize Chart.js charts
function initializeCharts() {
    const protocolCtx = document.getElementById('protocolChart').getContext('2d');
    window.protocolChart = new Chart(protocolCtx, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'Other'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0']
            }]
        },
        options: {
            responsive: true,
            title: {
                display: true,
                text: 'Protocol Distribution'
            }
        }
    });

    const bandwidthCtx = document.getElementById('bandwidthChart').getContext('2d');
    window.bandwidthChart = new Chart(bandwidthCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Bandwidth Usage (bytes)',
                data: [],
                borderColor: '#36A2EB',
                fill: false
            }]
        }
    });
}

// Helper function to get device name
function getDeviceName(mac, defaultName) {
    if (!mac) return defaultName;
    
    const deviceInfo = deviceCache.get(mac);
    if (deviceInfo) {
        return deviceInfo.custom_name || deviceInfo.hostname || defaultName;
    }
    
    // If we don't have the device info yet, trigger a fetch
    if (!deviceCache.has(mac)) {
        fetch(`/api/device/state/${mac}`)
            .then(response => response.json())
            .then(deviceInfo => {
                if (deviceInfo && !deviceInfo.error) {
                    deviceCache.set(mac, deviceInfo);
                    // Trigger a re-render of the table
                    updateVisualizations();
                }
            })
            .catch(error => console.error('Error fetching device info:', error));
    }
    
    return defaultName;
}

// Update top talkers data
function updateTopTalkers(ip, hostname) {
    const currentData = trafficData.topTalkers.get(ip) || { count: 0, hostname: hostname };
    currentData.count++;
    trafficData.topTalkers.set(ip, currentData);
}

// Update data structures with new packet information
function updateData(packet) {
    // Update protocol counts
    trafficData.protocols[packet.protocol] = (trafficData.protocols[packet.protocol] || 0) + 1;
    
    // Update bandwidth data
    trafficData.bandwidthData.push({
        time: packet.timestamp,
        bytes: packet.length
    });
    if (trafficData.bandwidthData.length > 50) {
        trafficData.bandwidthData.shift();
    }
    
    // Update device info and top talkers
    if (packet.src_mac && !deviceCache.has(packet.src_mac)) {
        const srcName = getDeviceName(packet.src_mac, packet.src_host || packet.src_ip);
        updateTopTalkers(packet.src_ip, srcName);
    }
    
    // Add to recent packets
    trafficData.packets.unshift(packet);
    if (trafficData.packets.length > 10) {
        trafficData.packets.pop();
    }
}

// Update visualizations with new data
function updateVisualizations() {
    // Update protocol chart
    if (window.protocolChart) {
        protocolChart.data.datasets[0].data = [
            trafficData.protocols.TCP || 0,
            trafficData.protocols.UDP || 0,
            trafficData.protocols.ICMP || 0,
            trafficData.protocols.Other || 0
        ];
        protocolChart.update();
    }

    // Update bandwidth chart
    if (window.bandwidthChart) {
        bandwidthChart.data.labels = trafficData.bandwidthData.map(d => d.time);
        bandwidthChart.data.datasets[0].data = trafficData.bandwidthData.map(d => d.bytes);
        bandwidthChart.update();
    }

    // Update packet table
    const tbody = document.querySelector('#packetTable tbody');
    if (tbody) {
        tbody.innerHTML = trafficData.packets.map(packet => {
            const srcName = getDeviceName(packet.src_mac, packet.src_host || packet.src_ip);
            const dstName = getDeviceName(packet.dst_mac, packet.dst_host || packet.dst_ip);
            
            return `
                <tr>
                    <td>${packet.timestamp}</td>
                    <td>${srcName}</td>
                    <td>${dstName}</td>
                    <td>${packet.protocol}</td>
                    <td>${packet.length} bytes</td>
                </tr>
            `;
        }).join('');
    }
}

// WebSocket message handler
ws.onmessage = (event) => {
    const packet = JSON.parse(event.data);
    console.log('Received packet:', packet);  // Debug log
    
    // If we have a MAC address but no device info, fetch it
    if (packet.src_mac && !deviceCache.has(packet.src_mac)) {
        fetch(`/api/device/state/${packet.src_mac}`)
            .then(response => response.json())
            .then(deviceInfo => {
                if (deviceInfo && !deviceInfo.error) {
                    deviceCache.set(packet.src_mac, deviceInfo);
                    // Trigger a re-render of the table
                    updateVisualizations();
                }
            })
            .catch(error => console.error('Error fetching device info:', error));
    }

    updateData(packet);
    updateVisualizations();
};

// WebSocket error handling
ws.onerror = (error) => {
    console.error('WebSocket error:', error);
};

ws.onclose = () => {
    console.log('WebSocket connection closed');
};

ws.onopen = () => {
    console.log('WebSocket connection established');
};

// Initialize when page loads
document.addEventListener('DOMContentLoaded', initializeVisualizations);