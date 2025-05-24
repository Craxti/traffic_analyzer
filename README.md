<div align="center">
    <img src="logo.png" alt="Traffic Analyzer Logo">
</div>

<h1 align="center">Traffic Analyzer</h1>

<p align="center">
    <strong>Analyze, Visualize, Secure: Unveil the Mysteries of Network Traffic</strong>
</p>

<p align="center">
    <a href="#features">Features</a> •
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="#development">Development</a> •
    <a href="#contributing">Contributing</a> •
    <a href="#license">License</a>
</p>

<p align="center">
    <img src="demo.gif" alt="Traffic Analyzer Demo">
</p>

[![CI](https://github.com/craxti/traffic_analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/craxti/traffic_analyzer/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/traffic-analyzer.svg)](https://badge.fury.io/py/traffic-analyzer)
[![Python Version](https://img.shields.io/pypi/pyversions/traffic-analyzer.svg)](https://pypi.org/project/traffic-analyzer/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

## Features

- **Real-time Capture**: Analyze network traffic in real-time or from pcap files.
- **Detailed Analysis**: Dive into protocols, IP addresses, ports, packet sizes, and more.
- **Security Alerting**: Detect DDoS attacks, port scans, and suspicious network activities.
- **Interactive Visualization**: Visually grasp analysis results with intuitive graphical and console displays.
- **Seamless Integration**: Effortlessly integrate Traffic Analyzer into your projects.
- **Comprehensive Testing**: 95%+ test coverage ensures reliability and stability.
- **Application Layer Analysis**: Deep inspection of HTTP, DNS, and TLS traffic.
- **PCAP Support**: Read and analyze packet capture files.
- **IPv6 Support**: Full analysis of both IPv4 and IPv6 traffic.
- **Export Capabilities**: Export results to JSON, CSV, or SQLite for further analysis.

## Installation

Install Traffic Analyzer using pip:

```bash
pip install traffic_analyzer
```

## Usage

### Command Line

Traffic Analyzer provides a simple command-line interface:

```bash
# Basic usage (captures 100 packets on default interface)
traffic-analyzer

# List available network interfaces
traffic-analyzer --list-interfaces

# Capture traffic on a specific interface
traffic-analyzer -i eth0

# Capture a specific number of packets
traffic-analyzer -i eth0 -c 500

# Apply a BPF filter
traffic-analyzer -i eth0 -f "tcp port 80"

# Analyze PCAP file
traffic-analyzer -r capture.pcap

# Perform application layer analysis
traffic-analyzer -i eth0 --app-layer

# Export results to different formats
traffic-analyzer -i eth0 --export-json results.json
traffic-analyzer -i eth0 --export-csv results
traffic-analyzer -i eth0 --export-sqlite results.db

# Disable visualization (text output only)
traffic-analyzer --no-visualization

# Enable verbose output
traffic-analyzer -v
```

### In Your Projects

Traffic Analyzer is designed to be easily integrated into your own Python projects:

```python
import logging
from traffic_analyzer import (
    capture_traffic,
    read_pcap_file,
    analyze_traffic,
    detect_attacks,
    analyze_app_layer,
    export_to_json,
    visualize_results
)

def main():
    logging.basicConfig(level=logging.INFO)
    
    # Option 1: Capture live traffic
    interface_name = "eth0"
    packet_count = 100
    packets = capture_traffic(interface_name, packet_count)
    
    # Option 2: Read from PCAP file
    # packets = read_pcap_file("capture.pcap")

    # Basic traffic analysis
    results = analyze_traffic(packets)
    
    # Detect potential attacks
    attack_results = detect_attacks(packets)
    results.update(attack_results)
    
    # Analyze application layer protocols
    app_layer_results = analyze_app_layer(packets)
    results["app_layer"] = app_layer_results
    
    # Export results to JSON
    export_to_json(results, "results.json")
    
    # Visualize the results
    visualize_results(results)

if __name__ == "__main__":
    main()
```

### Application Layer Analysis

Traffic Analyzer now includes detailed analysis of application layer protocols:

```python
from traffic_analyzer import analyze_http, analyze_dns, analyze_tls

# Analyze HTTP traffic
http_stats = analyze_http(packets)
print(f"HTTP Requests: {http_stats['requests']}")
print(f"Top domains: {list(http_stats['hosts'].items())[:5]}")

# Analyze DNS traffic
dns_stats = analyze_dns(packets)
print(f"DNS Queries: {dns_stats['total_queries']}")
print(f"Top domains: {list(dns_stats['domains'].items())[:5]}")

# Analyze TLS/SSL traffic
tls_stats = analyze_tls(packets)
print(f"TLS Handshakes: {tls_stats['handshakes']}")
print(f"TLS Versions: {tls_stats['versions']}")
```

### Exporting Results

Export your analysis results to various formats for further processing:

```python
from traffic_analyzer import export_to_json, export_to_csv, export_to_sqlite

# Export to JSON
json_file = export_to_json(results, "analysis.json")

# Export to CSV (creates multiple files)
csv_files = export_to_csv(results, "analysis")

# Export to SQLite database
db_file = export_to_sqlite(results, "analysis.db")
```

## Development

### Setup Development Environment

1. Clone the repository:
```bash
git clone https://github.com/craxti/traffic_analyzer.git
cd traffic_analyzer
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies:
```bash
pip install -e ".[dev]"
```

### Run Tests

Run tests using pytest:

```bash
pytest
```

Check test coverage:

```bash
pytest --cov=traffic_analyzer tests/
```

### Code Quality

Format code with Black:

```bash
black .
```

Sort imports with isort:

```bash
isort .
```

Lint code with flake8:

```bash
flake8 .
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Run the tests to ensure they pass (`pytest`)
4. Commit your changes (`git commit -m 'Add some amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

Please make sure your code follows the existing style, passes all tests, and includes appropriate documentation.

## License

Traffic Analyzer is released under the [MIT License](LICENSE).
