from scapy.layers.inet import IP, TCP

def detect_port_scan(packets, scan_threshold=50):
    """
    Detect port scanning activity in the captured packets.

    :param packets: List of captured packets.
    :param scan_threshold: Threshold for detecting port scanning.
    :return: List of IPs suspected of port scanning.
    """
    port_scan_ips = set()

    for packet in packets:
        if IP in packet and TCP in packet:
            if packet[TCP].flags == 2:  # SYN flag set (initial part of TCP handshake)
                source_ip = packet[IP].src
                port_scan_ips.add(source_ip)

    return list(port_scan_ips)

def detect_malicious_payload(packets, keyword="malware"):
    """
    Detect packets containing a specific keyword in payload.

    :param packets: List of captured packets.
    :param keyword: Keyword to search for in payload.
    :return: List of packets containing the keyword.
    """
    malicious_packets = [packet for packet in packets if keyword.encode() in packet]
    return malicious_packets

def analyze_network_activity(packets):
    """
    Analyze network activity based on packet types.

    :param packets: List of captured packets.
    :return: Dictionary containing analysis results.
    """
    activity_counts = {}

    for packet in packets:
        activity_type = packet[1].name
        activity_counts[activity_type] = activity_counts.get(activity_type, 0) + 1

    return activity_counts
