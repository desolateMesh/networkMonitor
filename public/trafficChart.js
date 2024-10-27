// public/trafficChart.js

const ws = new WebSocket('ws://localhost:8080'); // Connect to Node.js WebSocket server

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
};

// Initialize charts
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
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Protocol Distribution'
                }
            }
        }
    });

    const bandwidthCtx = document.getElementById('bandwidthChart').getContext('2d');
    window.bandwidthChart = new Chart(bandwidthCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Bandwidth Usage (bytes/s)',
                data: [],
                borderColor: '#36A2EB',
                fill: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Time'
                    }
                },
                y: {
                    display: true,
                    title: {
                        display: true,
                        text: 'Bytes'
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Bandwidth Usage Over Time'
                }
            }
        }
    });
}

// Update charts and table with new packet data
function updateVisualizations(packet) {
    // Update protocol chart
    if (packet.protocol && window.protocolChart) {
        trafficData.protocols[packet.protocol] = (trafficData.protocols[packet.protocol] || 0) + 1;
        window.protocolChart.data.datasets[0].data = [
            trafficData.protocols.TCP,
            trafficData.protocols.UDP,
            trafficData.protocols.ICMP,
            trafficData.protocols.Other
        ];
        window.protocolChart.update();
    }

    // Update bandwidth chart
    if (window.bandwidthChart) {
        const timestamp = packet.timestamp;
        trafficData.bandwidthData.push({
            time: timestamp,
            bytes: packet.length
        });

        // Keep last 50 data points
        if (trafficData.bandwidthData.length > 50) {
            trafficData.bandwidthData.shift();
        }

        window.bandwidthChart.data.labels = trafficData.bandwidthData.map(d => d.time);
        window.bandwidthChart.data.datasets[0].data = trafficData.bandwidthData.map(d => d.bytes);
        window.bandwidthChart.update();
    }

    // Update packet table
    updatePacketTable(packet);
}

// Update packet table with new data
function updatePacketTable(packet) {
    const tbody = document.querySelector('#packetTable tbody');
    if (!tbody) return;

    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${packet.timestamp}</td>
        <td>${packet.src_host || packet.src_ip}</td>
        <td>${packet.dst_host || packet.dst_ip}</td>
        <td>${packet.protocol}</td>
        <td>${packet.length} bytes</td>
    `;

    // Add new row at the beginning
    tbody.insertBefore(row, tbody.firstChild);

    // Keep only last 100 rows
    while (tbody.children.length > 100) {
        tbody.removeChild(tbody.lastChild);
    }
}

// WebSocket event handlers
ws.onopen = () => {
    console.log('WebSocket connection established');
    initializeCharts();
};

ws.onmessage = (event) => {
    try {
        const packet = JSON.parse(event.data);
        console.log('Received packet:', packet);
        updateVisualizations(packet);
    } catch (error) {
        console.error('Error processing packet:', error);
    }
};

ws.onerror = (error) => {
    console.error('WebSocket error:', error);
};

ws.onclose = () => {
    console.log('WebSocket connection closed');
    // Attempt to reconnect after 5 seconds
    setTimeout(() => {
        window.location.reload();
    }, 5000);
};

// Initialize when page loads
document.addEventListener('DOMContentLoaded', () => {
    // Charts are initialized on WebSocket open
});
