"""
Application Layer Analysis Module

This module provides functions for analyzing application layer protocols
such as HTTP, DNS, and TLS/SSL traffic.
"""

import logging
from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLS


def analyze_app_layer(packets):
    """
    Analyze application layer protocols in captured packets.
    
    :param packets: List of captured packets
    :return: Dictionary containing app layer analysis results
    """
    logging.info("Analyzing application layer protocols...")
    
    results = {
        "http": analyze_http(packets),
        "dns": analyze_dns(packets),
        "tls": analyze_tls(packets)
    }
    
    return results


def analyze_http(packets):
    """
    Analyze HTTP traffic in captured packets.
    
    :param packets: List of captured packets
    :return: Dictionary containing HTTP analysis results
    """
    http_stats = {
        "requests": 0,
        "responses": 0,
        "hosts": defaultdict(int),
        "methods": defaultdict(int),
        "status_codes": defaultdict(int),
        "user_agents": defaultdict(int)
    }
    
    for packet in packets:
        if IP in packet and TCP in packet:
            # Check for HTTP layer
            if HTTP in packet:
                if HTTPRequest in packet:
                    http_stats["requests"] += 1
                    
                    # Extract host
                    if packet[HTTPRequest].Host:
                        host = packet[HTTPRequest].Host.decode('utf-8', errors='ignore')
                        http_stats["hosts"][host] += 1
                    
                    # Extract method
                    if packet[HTTPRequest].Method:
                        method = packet[HTTPRequest].Method.decode('utf-8', errors='ignore')
                        http_stats["methods"][method] += 1
                    
                    # Extract User-Agent
                    if packet[HTTPRequest].User_Agent:
                        ua = packet[HTTPRequest].User_Agent.decode('utf-8', errors='ignore')
                        http_stats["user_agents"][ua] += 1
                        
                elif HTTPResponse in packet:
                    http_stats["responses"] += 1
                    
                    # Extract status code
                    if packet[HTTPResponse].Status_Code:
                        status = packet[HTTPResponse].Status_Code.decode('utf-8', errors='ignore')
                        http_stats["status_codes"][status] += 1
    
    # Convert defaultdict to regular dict
    http_stats["hosts"] = dict(http_stats["hosts"])
    http_stats["methods"] = dict(http_stats["methods"])
    http_stats["status_codes"] = dict(http_stats["status_codes"])
    http_stats["user_agents"] = dict(http_stats["user_agents"])
    
    return http_stats


def analyze_dns(packets):
    """
    Analyze DNS traffic in captured packets.
    
    :param packets: List of captured packets
    :return: Dictionary containing DNS analysis results
    """
    dns_stats = {
        "total_queries": 0,
        "total_responses": 0,
        "domains": defaultdict(int),
        "query_types": defaultdict(int),
        "response_codes": defaultdict(int)
    }
    
    for packet in packets:
        if IP in packet and UDP in packet and DNS in packet:
            dns_packet = packet[DNS]
            
            # Count queries
            if dns_packet.qr == 0:  # Query
                dns_stats["total_queries"] += 1
                
                # Extract domain names
                if DNSQR in dns_packet:
                    for qr in dns_packet[DNSQR]:
                        if qr.qname:
                            domain = qr.qname.decode('utf-8', errors='ignore').rstrip('.')
                            dns_stats["domains"][domain] += 1
                        
                        if qr.qtype:
                            qtype = qr.qtype
                            dns_stats["query_types"][qtype] += 1
            
            # Count responses
            elif dns_packet.qr == 1:  # Response
                dns_stats["total_responses"] += 1
                
                # Extract response codes
                if dns_packet.rcode is not None:
                    dns_stats["response_codes"][dns_packet.rcode] += 1
    
    # Convert defaultdict to regular dict
    dns_stats["domains"] = dict(dns_stats["domains"])
    dns_stats["query_types"] = dict(dns_stats["query_types"])
    dns_stats["response_codes"] = dict(dns_stats["response_codes"])
    
    return dns_stats


def analyze_tls(packets):
    """
    Analyze TLS/SSL traffic in captured packets.
    
    :param packets: List of captured packets
    :return: Dictionary containing TLS analysis results
    """
    tls_stats = {
        "handshakes": 0,
        "versions": defaultdict(int),
        "cipher_suites": defaultdict(int),
        "extensions": defaultdict(int)
    }
    
    for packet in packets:
        if IP in packet and TCP in packet and TLS in packet:
            tls_packet = packet[TLS]
            
            # Count handshakes
            if hasattr(tls_packet, 'type') and tls_packet.type == 1:  # Client Hello
                tls_stats["handshakes"] += 1
                
                # Extract TLS version
                if hasattr(tls_packet, 'version'):
                    version = tls_packet.version
                    tls_stats["versions"][version] += 1
                
                # Extract cipher suites
                if hasattr(tls_packet, 'ciphers'):
                    for cipher in tls_packet.ciphers:
                        tls_stats["cipher_suites"][cipher] += 1
                
                # Extract extensions
                if hasattr(tls_packet, 'ext'):
                    for ext in tls_packet.ext:
                        if hasattr(ext, 'type'):
                            tls_stats["extensions"][ext.type] += 1
    
    # Convert defaultdict to regular dict
    tls_stats["versions"] = dict(tls_stats["versions"])
    tls_stats["cipher_suites"] = dict(tls_stats["cipher_suites"])
    tls_stats["extensions"] = dict(tls_stats["extensions"])
    
    return tls_stats
