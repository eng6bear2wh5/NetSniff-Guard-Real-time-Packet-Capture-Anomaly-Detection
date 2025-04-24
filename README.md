# NetSniff Guard: Real-time Packet Capture & Anomaly Detection

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)

## Overview
NetSniff Guard is an advanced network security tool that captures live network packets and detects anomalies using machine learning techniques. It analyzes traffic in real-time based on multiple features including packet size, protocol, timing patterns, and flow behavior. The system provides immediate alerts for suspicious activities while storing captured data in PCAP format for further investigation.

## Features

### Real-time Packet Analysis
- Capture packets on any network interface with promiscuous mode support
- Detailed protocol identification and packet decoding (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, etc.)
- Application protocol recognition (HTTP, HTTPS, DNS, DHCP, etc.)
- BPF filter support for targeted packet capture
- TCP flags and connection state tracking

### Advanced Anomaly Detection
- Machine learning-based detection using Isolation Forest algorithm
- Multi-dimensional feature analysis:
  - Packet size deviations
  - Protocol anomalies
  - Timing pattern irregularities
  - Flow behavior analysis
  - Port usage statistics
- Adaptive learning with continuous model updates
- Persistent model storage for improved detection over time

### Flow-Based Analysis
- Track related packet streams as flows
- Detect anomalies across packet sequences
- Identify suspicious connection patterns
- Alert on abnormal flow behaviors

### Interactive Visualization
- Rich TUI (Text User Interface) with real-time updates
- Color-coded threat indicators
- Detailed packet information display
- Flow statistics and anomaly scoring
- Summary reports with top suspicious flows

### Storage and Forensics
- Automatic PCAP file generation with timestamps
- File rotation for extended captures
- Post-capture analysis capabilities
- Historical data review and trend identification

## Technical Details

### Architecture
NetSniff Guard is organized into modular components:
- **Packet Capture**: Interfaces directly with network hardware
- **Packet Parser**: Decodes and extracts packet information
- **Anomaly Detector**: Applies machine learning for threat detection
- **Visualizer**: Presents information in a readable format
- **PCAP Handler**: Manages storage and retrieval of packet data

### Machine Learning Implementation
- **Algorithm**: Isolation Forest for unsupervised anomaly detection
- **Feature Extraction**: 8 dimensional feature vectors including:
  - Packet size
  - Protocol identification
  - Source/destination port analysis
  - Inter-packet timing
  - Flow metrics (packet count, byte count)
  - Rate analysis
- **Model Persistence**: Continuous learning with model saving/loading
- **Adaptive Thresholds**: Dynamic anomaly scoring based on historical data

## Requirements
- Python 3.7 for pcap library
- Root/sudo privileges (required for packet capture)
- Linux-based operating system (tested on Ubuntu/Debian)
- Required packages:
  - pcap
  - dpkt
  - rich
  - colorama
  - scikit-learn
  - numpy
  - pandas
  - joblib

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/NetSniff-Guard.git
cd NetSniff-Guard

# Create a virtual environment with Python 3.7 (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Ensure you have libpcap development headers
# On Debian/Ubuntu systems:
sudo apt-get install libpcap-dev
```

We strongly recommend using a virtual environment with Python 3.7, as this version has been thoroughly tested with all dependencies in this project. This ensures compatibility and prevents conflicts with other Python packages installed on your system.

## Usage

### Basic Usage
```bash
# Run with sudo (required for packet capture)
sudo python3 main.py
```

The interactive prompt will guide you through:
1. Selecting a network interface from available options
2. Setting optional BPF filters (e.g., "tcp port 80" to capture only HTTP traffic)
3. Configuring maximum packet count or continuous capture
4. Specifying output directory for PCAP files
5. Selecting existing model or creating a new one

### Command Line Options
```bash
# Analyze an existing PCAP file
sudo python3 main.py -a /path/to/capture.pcap

# Specify a network interface directly
sudo python3 main.py -i eth0

# Set a maximum packet count
sudo python3 main.py -c 1000

# Specify custom output directory
sudo python3 main.py -o ./my_captures

# Use a specific model file
sudo python3 main.py -m ./my_model/custom_model.pkl
```

### Understanding the Interface
- The main display shows captured packets with protocol information and anomaly scores
- Red highlighted entries indicate potential anomalies
- The "Flow Score" column shows the suspicion level of the packet's connection
- Alerts appear when flow scores exceed the threshold
- Summary statistics are displayed at the bottom

## Project Structure
```
NetSniff-Guard/
├── main.py                      # Application entry point
├── config.py                    # Configuration settings
├── requirements.txt             # Dependencies
├── README.md                    # Documentation
├── LICENSE                      # MIT License
├── analyzer/                    # Analysis components
│   ├── __init__.py
│   ├── packet_sniffer.py        # Main packet capturing class
│   ├── pcap_analyzer.py         # PCAP file analyzer
│   └── visualizer.py            # TUI display
├── models/                      # Machine learning
│   ├── __init__.py
│   └── anomaly_detector.py      # ML-based detection
├── utils/                       # Utilities
│   ├── __init__.py
│   ├── packet_parser.py         # Packet decoding
│   ├── pcap_handler.py          # PCAP file operations
│   └── protocol_maps.py         # Protocol definitions
├── captures/                    # Output directory
└── model/                       # Saved ML models
```

## Limitations and Future Work
- Currently supports only Ethernet-based networks
- Limited support for encrypted traffic analysis
- Future enhancements:
  - Deep packet inspection capabilities
  - Traffic classification and behavioral analysis
  - Integration with threat intelligence feeds
  - Graphical user interface
  - Network topology visualization
  - Alert correlation across multiple sensors

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing
Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Acknowledgments
- Thanks to the developers of pcap, dpkt, and scikit-learn
- Inspired by tools like Wireshark, Suricata, and Zeek

## Contact
For questions or support, please open an issue on GitHub.
