#!/usr/bin/env python3
"""
Traffic Analyzer - Main Entry Point

This script provides a command-line interface for the Traffic Analyzer library.
"""

import argparse
import logging
import sys
import time
from multiprocessing import Process, Queue

import psutil

from traffic_analyzer import (
    capture_traffic,
    analyze_traffic,
    analyze_app_layer,
    detect_attacks,
    visualize_results,
    update_visualizations,
    export_to_json,
    export_to_csv,
    export_to_sqlite,
    read_pcap_file,
)


def setup_logger(verbose=False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s]: %(message)s',
        handlers=[
            logging.FileHandler('traffic_analyzer.log'),
            logging.StreamHandler()
        ]
    )


def get_available_interfaces():
    """Get list of available network interfaces."""
    try:
        interfaces = psutil.net_if_addrs().keys()
        return list(interfaces)
    except Exception as e:
        logging.error("Error getting network interfaces: %s", str(e))
        return []


def get_default_interface():
    """Get the default network interface."""
    interfaces = get_available_interfaces()
    if not interfaces:
        logging.error("No network interfaces found")
        return None
    
    # Prefer common interface names
    preferred = ['eth0', 'wlan0', 'Wi-Fi', 'Ethernet']
    for name in preferred:
        if name in interfaces:
            return name
    
    return interfaces[0]


def data_processing(interface, packet_count, filter_bpf, queue, app_layer=False):
    """Process network data in a separate process."""
    try:
        logging.info("Starting data processing on interface: %s", interface)
        
        # Capture traffic
        packets = capture_traffic(interface, packet_count, filter_bpf)
        
        if not packets:
            logging.warning("No packets captured")
            queue.put({})
            return
        
        # Analyze traffic
        results = analyze_traffic(packets)
        
        # Detect attacks
        attack_results = detect_attacks(packets)
        results.update(attack_results)
        
        # Analyze application layer if requested
        if app_layer:
            app_results = analyze_app_layer(packets)
            results["app_layer"] = app_results
        
        queue.put(results)
        
    except Exception as e:
        logging.error("Error in data processing: %s", str(e))
        queue.put({})


def real_time_visualization(queue, interval=5):
    """Real-time visualization in a separate process."""
    try:
        while True:
            results = queue.get()
            if results:
                update_visualizations(results)
            time.sleep(interval)
    except KeyboardInterrupt:
        logging.info("Visualization stopped by user")
    except Exception as e:
        logging.error("Error in visualization: %s", str(e))


def export_results(results, export_format, filename):
    """Export results to specified format."""
    try:
        if export_format == 'json':
            return export_to_json(results, filename)
        elif export_format == 'csv':
            return export_to_csv(results, filename)
        elif export_format == 'sqlite':
            return export_to_sqlite(results, filename)
        else:
            logging.error("Unsupported export format: %s", export_format)
            return None
    except Exception as e:
        logging.error("Error exporting results: %s", str(e))
        return None


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Traffic Analyzer - Network traffic analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  traffic-analyzer                    # Basic usage with default interface
  traffic-analyzer -i eth0 -c 100    # Capture 100 packets on eth0
  traffic-analyzer -f "tcp port 80"  # Filter TCP traffic on port 80
  traffic-analyzer -r capture.pcap   # Analyze PCAP file
  traffic-analyzer --app-layer       # Include application layer analysis
  traffic-analyzer --export-json results.json  # Export to JSON
        """
    )
    
    # Interface options
    parser.add_argument(
        '-i', '--interface',
        help='Network interface to capture from (default: auto-detect)'
    )
    parser.add_argument(
        '--list-interfaces',
        action='store_true',
        help='List available network interfaces and exit'
    )
    
    # Capture options
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=100,
        help='Number of packets to capture (default: 100)'
    )
    parser.add_argument(
        '-f', '--filter',
        help='BPF filter to apply (e.g., "tcp port 80")'
    )
    parser.add_argument(
        '-r', '--read-pcap',
        help='Read packets from PCAP file instead of live capture'
    )
    
    # Analysis options
    parser.add_argument(
        '--app-layer',
        action='store_true',
        help='Perform application layer analysis (HTTP, DNS, TLS)'
    )
    
    # Output options
    parser.add_argument(
        '--no-visualization',
        action='store_true',
        help='Disable graphical visualization'
    )
    parser.add_argument(
        '--export-json',
        help='Export results to JSON file'
    )
    parser.add_argument(
        '--export-csv',
        help='Export results to CSV files (base filename)'
    )
    parser.add_argument(
        '--export-sqlite',
        help='Export results to SQLite database'
    )
    
    # General options
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logger(args.verbose)
    
    # List interfaces if requested
    if args.list_interfaces:
        interfaces = get_available_interfaces()
        print("Available network interfaces:")
        for interface in interfaces:
            print(f"  - {interface}")
        return
    
    # Determine interface
    interface = args.interface or get_default_interface()
    if not interface:
        logging.error("No network interface available")
        sys.exit(1)
    
    logging.info("Using interface: %s", interface)
    
    try:
        if args.read_pcap:
            # Read from PCAP file
            logging.info("Reading packets from PCAP file: %s", args.read_pcap)
            packets = read_pcap_file(args.read_pcap, args.count, args.filter)
            
            if not packets:
                logging.error("No packets found in PCAP file")
                sys.exit(1)
            
            # Analyze packets
            results = analyze_traffic(packets)
            attack_results = detect_attacks(packets)
            results.update(attack_results)
            
            if args.app_layer:
                app_results = analyze_app_layer(packets)
                results["app_layer"] = app_results
            
        else:
            # Live capture
            if args.no_visualization:
                # Single capture and analysis
                packets = capture_traffic(interface, args.count, args.filter)
                
                if not packets:
                    logging.error("No packets captured")
                    sys.exit(1)
                
                results = analyze_traffic(packets)
                attack_results = detect_attacks(packets)
                results.update(attack_results)
                
                if args.app_layer:
                    app_results = analyze_app_layer(packets)
                    results["app_layer"] = app_results
                
            else:
                # Real-time capture with visualization
                queue = Queue()
                
                process_data = Process(
                    target=data_processing,
                    args=(interface, args.count, args.filter, queue, args.app_layer)
                )
                process_viz = Process(
                    target=real_time_visualization,
                    args=(queue,)
                )
                
                process_data.start()
                process_viz.start()
                
                try:
                    process_data.join()
                    process_viz.join()
                except KeyboardInterrupt:
                    logging.info("Stopping capture...")
                    process_data.terminate()
                    process_viz.terminate()
                    process_data.join()
                    process_viz.join()
                
                return
        
        # Export results if requested
        if args.export_json:
            export_results(results, 'json', args.export_json)
        
        if args.export_csv:
            export_results(results, 'csv', args.export_csv)
        
        if args.export_sqlite:
            export_results(results, 'sqlite', args.export_sqlite)
        
        # Visualize results
        if not args.no_visualization:
            visualize_results(results)
        else:
            update_visualizations(results)
        
    except KeyboardInterrupt:
        logging.info("Operation cancelled by user")
    except Exception as e:
        logging.error("Unexpected error: %s", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
