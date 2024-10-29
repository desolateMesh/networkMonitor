// trafficChart.js

const CONFIG = {
    MAX_DATA_POINTS: 50,
    MAX_TABLE_ROWS: 100,
    WEBSOCKET_URL: 'ws://localhost:8080',
    RECONNECT_DELAY: 5000,
    CHART_COLORS: {
        TCP: '#FF6384',
        UDP: '#36A2EB',
        ICMP: '#FFCE56',
        OTHER: '#4BC0C0'
    }
};

class TrafficMonitor {
    constructor() {
        this.ws = null;
        this.protocolChart = null;
        this.bandwidthChart = null;
        this.isInitialized = false;
        
        this.trafficData = {
            packets: [],
            protocols: {
                TCP: 0,
                UDP: 0,
                ICMP: 0,
                Other: 0
            },
            bandwidthData: []
        };

        console.log('TrafficMonitor: Initializing...');
        this.initializeWebSocket();
    }

    initializeWebSocket() {
        console.log('Initializing WebSocket connection...');
        
        this.ws = new WebSocket(CONFIG.WEBSOCKET_URL);
        
        this.ws.onopen = () => {
            console.log('WebSocket connection established');
            if (!this.isInitialized) {
                this.initializeCharts();
                this.isInitialized = true;
            }
        };

        this.ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                console.log('Received WebSocket message:', message);

                if (message.type === 'packet' && message.data) {
                    console.log('Processing packet:', message.data);
                    this.processPacket(message.data);
                }
            } catch (error) {
                console.error('Error processing message:', error);
            }
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

        this.ws.onclose = () => {
            console.log('WebSocket connection closed');
            this.isInitialized = false;
            setTimeout(() => this.initializeWebSocket(), CONFIG.RECONNECT_DELAY);
        };
    }

    initializeCharts() {
        console.log('Initializing charts...');
        
        const protocolCtx = document.getElementById('protocolChart');
        if (!protocolCtx) {
            console.error('Protocol chart canvas not found');
            return;
        }

        this.protocolChart = new Chart(protocolCtx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: Object.values(CONFIG.CHART_COLORS)
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Protocol Distribution',
                        color: '#ffffff'
                    },
                    legend: {
                        labels: {
                            color: '#ffffff'
                        }
                    }
                }
            }
        });

        const bandwidthCtx = document.getElementById('bandwidthChart');
        if (!bandwidthCtx) {
            console.error('Bandwidth chart canvas not found');
            return;
        }

        this.bandwidthChart = new Chart(bandwidthCtx.getContext('2d'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Bandwidth Usage (bytes/s)',
                    data: [],
                    borderColor: CONFIG.CHART_COLORS.TCP,
                    fill: false,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        display: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#ffffff'
                        }
                    },
                    y: {
                        display: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#ffffff'
                        }
                    }
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'Bandwidth Usage Over Time',
                        color: '#ffffff'
                    },
                    legend: {
                        labels: {
                            color: '#ffffff'
                        }
                    }
                }
            }
        });

        console.log('Charts initialized successfully');
    }

    processPacket(packet) {
        if (!this.isInitialized) {
            console.error('Charts not initialized yet!');
            return;
        }
        if (!packet) {
            console.error('Invalid packet data received');
            return;
        }

        console.log('Updating charts with packet:', packet);

        // Update protocol statistics
        if (packet.protocol) {
            console.log('Updating protocol chart for:', packet.protocol);
            this.updateProtocolChart(packet);
        }

        // Update bandwidth data
        if (packet.length) {
            console.log('Updating bandwidth chart with length:', packet.length);
            this.updateBandwidthChart(packet);
        }

        // Update packet table
        this.updatePacketTable(packet);
    }

    updateProtocolChart(packet) {
        if (!this.protocolChart) {
            console.error('Protocol chart not initialized!');
            return;
        }

        const stats = packet.stats || {};
        console.log('Protocol stats:', stats);
        
        const chartData = [
            stats.TCP || 0,
            stats.UDP || 0,
            stats.ICMP || 0,
            stats.Other || 0
        ];

        console.log('Updating protocol chart with data:', chartData);
        this.protocolChart.data.datasets[0].data = chartData;
        this.protocolChart.update('none');
    }

    updateBandwidthChart(packet) {
        if (!this.bandwidthChart) {
            console.error('Bandwidth chart not initialized!');
            return;
        }

        this.trafficData.bandwidthData.push({
            time: packet.timestamp,
            bytes: packet.length
        });

        if (this.trafficData.bandwidthData.length > CONFIG.MAX_DATA_POINTS) {
            this.trafficData.bandwidthData.shift();
        }

        const labels = this.trafficData.bandwidthData.map(d => d.time);
        const data = this.trafficData.bandwidthData.map(d => d.bytes);
        
        console.log('Updating bandwidth chart:', { labels, data });
        
        this.bandwidthChart.data.labels = labels;
        this.bandwidthChart.data.datasets[0].data = data;
        this.bandwidthChart.update('none');
    }

    updatePacketTable(packet) {
        const tbody = document.querySelector('#packetTable tbody');
        if (!tbody) {
            console.error('Packet table body not found!');
            return;
        }

        const row = document.createElement('tr');
        
        const srcEndpoint = packet.src_port ? `${packet.src_host || packet.src_ip}:${packet.src_port}` : packet.src_host || packet.src_ip;
        const dstEndpoint = packet.dst_port ? `${packet.dst_host || packet.dst_ip}:${packet.dst_port}` : packet.dst_host || packet.dst_ip;
        
        row.innerHTML = `
            <td>${packet.timestamp}</td>
            <td title="${srcEndpoint}">${srcEndpoint}</td>
            <td title="${dstEndpoint}">${dstEndpoint}</td>
            <td>${packet.protocol}</td>
            <td>${packet.length} bytes</td>
        `;

        tbody.insertBefore(row, tbody.firstChild);

        while (tbody.children.length > CONFIG.MAX_TABLE_ROWS) {
            tbody.removeChild(tbody.lastChild);
        }
        
        console.log('Updated packet table');
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }
}

// Add CSS styles for the table
const style = document.createElement('style');
style.textContent = `
    .packet-row {
        transition: background-color 0.3s ease;
    }

    .packet-row:hover {
        background-color: rgba(255, 255, 255, 0.1);
    }

    .packet-row.highlight {
        background-color: rgba(255, 255, 255, 0.15);
    }

    .protocol-tcp { border-left: 3px solid ${CONFIG.CHART_COLORS.TCP}; }
    .protocol-udp { border-left: 3px solid ${CONFIG.CHART_COLORS.UDP}; }
    .protocol-icmp { border-left: 3px solid ${CONFIG.CHART_COLORS.ICMP}; }
    .protocol-other { border-left: 3px solid ${CONFIG.CHART_COLORS.OTHER}; }

    #packetTable {
        width: 100%;
        border-collapse: collapse;
    }

    #packetTable th,
    #packetTable td {
        padding: 8px;
        text-align: left;
        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }

    #packetTable th {
        background-color: rgba(0, 0, 0, 0.2);
        font-weight: bold;
    }

    .chart-container {
        background-color: rgba(0, 0, 0, 0.2);
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 20px;
    }
`;

document.head.appendChild(style);

// Initialize when page loads
console.log('Setting up TrafficMonitor...');
const monitor = new TrafficMonitor();
window.trafficMonitor = monitor;