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
    <a href="#contributing">Contributing</a> •
    <a href="#license">License</a>
</p>

<p align="center">
    <img src="demo.gif" alt="Traffic Analyzer Demo">
</p>

## Features

- **Capture Insights**: Analyze network traffic in real-time or from pcap files.
- **Detailed Analysis**: Dive into protocols, IP addresses, ports, packet sizes, and more.
- **Security Alert**: Detect DDoS attacks and suspicious network activities.
- **Interactive Visualization**: Visually grasp analysis results in an intuitive console display.
- **Seamless Integration**: Effortlessly integrate Traffic Analyzer into your projects.

## Installation

Install Traffic Analyzer using pip:

```bash
pip install traffic_analyzer
```

## Usage in Your Projects

Traffic Analyzer is designed to be easily integrated into your own Python projects. Here's how you can get started:

1. **Install Traffic Analyzer**:

    Install the library in your project's virtual environment using pip:

    ```bash
    pip install traffic_analyzer
    ```

2. **Import and Utilize**:

    Import the necessary modules and functions into your Python code:

    ```python
    import logging
    from traffic_analyzer.capture import capture_traffic
    from traffic_analyzer.analyze import analyze_traffic, detect_attacks
    from traffic_analyzer.visualizations import visualize_results
    ```

3. **Capture and Analyze**:

    Set up the network interface and packet count, capture traffic, and analyze it:

    ```python
    def main():
        logging.basicConfig(level=logging.INFO)

        interface_name = "eth0"
        packet_count = 100

        packets = capture_traffic(interface_name, packet_count)
        results = analyze_traffic(packets)
        attacks = detect_attacks(packets)
        results.update(attacks)

        visualize_results(results)

    if __name__ == "__main__":
        main()
    ```

4. **Customize and Extend**:

    Tailor the analysis and visualization to your project's needs. You can explore different methods in `analyze.py` and `visualizations.py` to extract insights from captured packets and present them in a meaningful way.

By incorporating Traffic Analyzer into your projects, you can effortlessly enhance your network analysis capabilities, uncover patterns, and identify potential security threats.

For more detailed usage examples and advanced customization options, refer to the [documentation](https://github.com/craxti/traffic_analyzer/wiki).

## License

Traffic Analyzer is released under the [MIT License](LICENSE).
