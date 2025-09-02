"""
Export Module

This module provides functions for exporting analysis results to various formats
such as JSON, CSV, and SQLite.
"""

import json
import csv
import sqlite3
import logging
from datetime import datetime
from pathlib import Path


def export_to_json(results, filename):
    """
    Export analysis results to JSON format.
    
    :param results: Dictionary containing analysis results
    :param filename: Output filename
    :return: Path to the exported file
    """
    try:
        # Ensure filename has .json extension
        if not filename.endswith('.json'):
            filename += '.json'
        
        # Convert any non-serializable objects
        serializable_results = _make_serializable(results)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(serializable_results, f, indent=2, ensure_ascii=False)
        
        logging.info("Results exported to JSON: %s", filename)
        return filename
        
    except Exception as e:
        logging.error("Error exporting to JSON: %s", str(e))
        raise


def export_to_csv(results, base_filename):
    """
    Export analysis results to multiple CSV files.
    
    :param results: Dictionary containing analysis results
    :param base_filename: Base filename for CSV files
    :return: List of exported CSV filenames
    """
    exported_files = []
    
    try:
        # Export protocol counts
        if results.get("protocol_counts"):
            filename = f"{base_filename}_protocols.csv"
            _write_csv_dict(results["protocol_counts"], filename, ["Protocol", "Count"])
            exported_files.append(filename)
        
        # Export source IPs
        if results.get("source_ips"):
            filename = f"{base_filename}_source_ips.csv"
            _write_csv_dict(results["source_ips"], filename, ["IP Address", "Count"])
            exported_files.append(filename)
        
        # Export destination IPs
        if results.get("dest_ips"):
            filename = f"{base_filename}_dest_ips.csv"
            _write_csv_dict(results["dest_ips"], filename, ["IP Address", "Count"])
            exported_files.append(filename)
        
        # Export source ports
        if results.get("source_ports"):
            filename = f"{base_filename}_source_ports.csv"
            _write_csv_dict(results["source_ports"], filename, ["Port", "Count"])
            exported_files.append(filename)
        
        # Export destination ports
        if results.get("dest_ports"):
            filename = f"{base_filename}_dest_ports.csv"
            _write_csv_dict(results["dest_ports"], filename, ["Port", "Count"])
            exported_files.append(filename)
        
        # Export packet sizes
        if results.get("packet_sizes"):
            filename = f"{base_filename}_packet_sizes.csv"
            _write_csv_list(results["packet_sizes"], filename, ["Packet Size"])
            exported_files.append(filename)
        
        # Export packet times
        if results.get("packet_times"):
            filename = f"{base_filename}_packet_times.csv"
            _write_csv_list(results["packet_times"], filename, ["Timestamp"])
            exported_files.append(filename)
        
        # Export app layer results if available
        if results.get("app_layer"):
            app_results = results["app_layer"]
            
            # HTTP results
            if app_results.get("http"):
                http_data = app_results["http"]
                if http_data.get("hosts"):
                    filename = f"{base_filename}_http_hosts.csv"
                    _write_csv_dict(http_data["hosts"], filename, ["Host", "Count"])
                    exported_files.append(filename)
                
                if http_data.get("methods"):
                    filename = f"{base_filename}_http_methods.csv"
                    _write_csv_dict(http_data["methods"], filename, ["Method", "Count"])
                    exported_files.append(filename)
            
            # DNS results
            if app_results.get("dns"):
                dns_data = app_results["dns"]
                if dns_data.get("domains"):
                    filename = f"{base_filename}_dns_domains.csv"
                    _write_csv_dict(dns_data["domains"], filename, ["Domain", "Count"])
                    exported_files.append(filename)
        
        logging.info("Results exported to %d CSV files", len(exported_files))
        return exported_files
        
    except Exception as e:
        logging.error("Error exporting to CSV: %s", str(e))
        raise


def export_to_sqlite(results, filename):
    """
    Export analysis results to SQLite database.
    
    :param results: Dictionary containing analysis results
    :param filename: Output database filename
    :return: Path to the exported database
    """
    try:
        # Ensure filename has .db extension
        if not filename.endswith('.db'):
            filename += '.db'
        
        conn = sqlite3.connect(filename)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_metadata (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                total_packets INTEGER,
                ddos_detected BOOLEAN
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS protocol_counts (
                id INTEGER PRIMARY KEY,
                protocol TEXT,
                count INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_addresses (
                id INTEGER PRIMARY KEY,
                ip_address TEXT,
                count INTEGER,
                type TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS port_counts (
                id INTEGER PRIMARY KEY,
                port INTEGER,
                count INTEGER,
                type TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packet_sizes (
                id INTEGER PRIMARY KEY,
                size INTEGER
            )
        ''')
        
        # Insert metadata
        total_packets = len(results.get("packet_sizes", []))
        ddos_detected = results.get("ddos_detected", False)
        
        cursor.execute('''
            INSERT INTO analysis_metadata (timestamp, total_packets, ddos_detected)
            VALUES (?, ?, ?)
        ''', (datetime.now().isoformat(), total_packets, ddos_detected))
        
        # Insert protocol counts
        if results.get("protocol_counts"):
            for protocol, count in results["protocol_counts"].items():
                cursor.execute('''
                    INSERT INTO protocol_counts (protocol, count)
                    VALUES (?, ?)
                ''', (protocol, count))
        
        # Insert IP addresses
        if results.get("source_ips"):
            for ip, count in results["source_ips"].items():
                cursor.execute('''
                    INSERT INTO ip_addresses (ip_address, count, type)
                    VALUES (?, ?, ?)
                ''', (ip, count, "source"))
        
        if results.get("dest_ips"):
            for ip, count in results["dest_ips"].items():
                cursor.execute('''
                    INSERT INTO ip_addresses (ip_address, count, type)
                    VALUES (?, ?, ?)
                ''', (ip, count, "destination"))
        
        # Insert port counts
        if results.get("source_ports"):
            for port, count in results["source_ports"].items():
                cursor.execute('''
                    INSERT INTO port_counts (port, count, type)
                    VALUES (?, ?, ?)
                ''', (port, count, "source"))
        
        if results.get("dest_ports"):
            for port, count in results["dest_ports"].items():
                cursor.execute('''
                    INSERT INTO port_counts (port, count, type)
                    VALUES (?, ?, ?)
                ''', (port, count, "destination"))
        
        # Insert packet sizes
        if results.get("packet_sizes"):
            for size in results["packet_sizes"]:
                cursor.execute('''
                    INSERT INTO packet_sizes (size)
                    VALUES (?)
                ''', (size,))
        
        conn.commit()
        conn.close()
        
        logging.info("Results exported to SQLite: %s", filename)
        return filename
        
    except Exception as e:
        logging.error("Error exporting to SQLite: %s", str(e))
        raise


def _make_serializable(obj):
    """Convert object to JSON serializable format."""
    if isinstance(obj, dict):
        return {k: _make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_make_serializable(item) for item in obj]
    elif isinstance(obj, (int, float, str, bool, type(None))):
        return obj
    else:
        return str(obj)


def _write_csv_dict(data, filename, headers):
    """Write dictionary data to CSV file."""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for key, value in data.items():
            writer.writerow([key, value])


def _write_csv_list(data, filename, headers):
    """Write list data to CSV file."""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for item in data:
            writer.writerow([item])
