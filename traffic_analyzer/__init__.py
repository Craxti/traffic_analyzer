"""
Traffic Analyzer - A network traffic analysis library.

This package provides tools for capturing, analyzing, and visualizing network traffic.
"""

__version__ = "0.1.1"
__author__ = "Craxti"

from traffic_analyzer.analyze import (
    analyze_traffic,
    detect_attacks,
    detect_ddos,
    detect_malicious_payload,
    detect_port_scan,
)
from traffic_analyzer.app_layer import (
    analyze_app_layer,
    analyze_dns,
    analyze_http,
    analyze_tls,
)
from traffic_analyzer.capture import (
    capture_traffic,
    capture_traffic_async,
    get_packet_info,
    read_pcap_file,
)
from traffic_analyzer.export import (
    export_to_csv,
    export_to_json,
    export_to_sqlite,
)
from traffic_analyzer.utils import (
    format_time,
    get_ip_version,
    sanitize_packet_data,
    validate_ip,
    validate_ipv4,
    validate_ipv6,
)
from traffic_analyzer.visualize import update_visualizations, visualize_results

__all__ = [
    # Capture functions
    "capture_traffic",
    "capture_traffic_async",
    "read_pcap_file",
    "get_packet_info",
    
    # Analysis functions
    "analyze_traffic",
    "detect_attacks",
    "detect_port_scan",
    "detect_ddos",
    "detect_malicious_payload",
    
    # App layer analysis
    "analyze_app_layer",
    "analyze_http",
    "analyze_dns",
    "analyze_tls",
    
    # Visualization
    "visualize_results",
    "update_visualizations",
    
    # Export functions
    "export_to_json",
    "export_to_csv",
    "export_to_sqlite",
    
    # Utility functions
    "format_time",
    "validate_ip",
    "validate_ipv4",
    "validate_ipv6",
    "get_ip_version",
    "sanitize_packet_data",
]
