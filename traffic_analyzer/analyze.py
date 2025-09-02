import logging

from scapy.layers.inet import IP, TCP, UDP


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
        layers = packet.layers()
        if len(layers) > 1:
            activity_type = layers[1]  # layers() returns list of strings
            activity_counts[activity_type] = activity_counts.get(activity_type, 0) + 1

    return activity_counts


def detect_ddos(packets, time_window=1, threshold=1000):
    """
    Detect potential DDoS attacks by analyzing packet rate.

    :param packets: List of captured packets.
    :param time_window: Time window in seconds for analysis.
    :param threshold: Threshold for packets per second to trigger alert.
    :return: Boolean indicating if a DDoS attack is detected.
    """
    if len(packets) < 2:
        return False

    packet_count = len(packets)
    time_range = packets[-1].time - packets[0].time

    # Avoid division by zero
    if time_range == 0:
        time_range = 0.001

    packets_per_sec = packet_count / time_range

    return packets_per_sec > threshold


def detect_attacks(packets):
    """
    Detect various types of attacks in captured packets.

    :param packets: List of captured packets.
    :return: Dictionary containing detected attack information.
    """
    # Lower thresholds for testing purposes
    scan_threshold = 20
    high_traffic_threshold = 50

    ips_counter = {}

    for packet in packets:
        if IP in packet:
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst

            ips_counter[source_ip] = ips_counter.get(source_ip, 0) + 1
            ips_counter[dest_ip] = ips_counter.get(dest_ip, 0) + 1

    suspicious_ips = [
        ip for ip, count in ips_counter.items() if count > high_traffic_threshold
    ]

    scanning_ips = [
        ip
        for ip, count in ips_counter.items()
        if count > scan_threshold and ip not in suspicious_ips
    ]

    attacks = {"suspicious_ips": suspicious_ips, "scanning_ips": scanning_ips}

    return attacks


def analyze_traffic(packets):
    """
    Analyze network traffic and extract key metrics.

    :param packets: List of captured packets.
    :return: Dictionary containing analysis results.
    """
    logging.info("Analysis in progress...")
    protocol_counts = {}
    source_ips = {}
    dest_ips = {}
    source_ports = {}
    dest_ports = {}
    packet_sizes = []
    packet_times = []

    for packet in packets:
        # Get protocol from the second layer (first is usually Raw)
        layers = packet.layers()
        if len(layers) > 1:
            protocol = layers[1]  # layers() returns list of strings
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

        if IP in packet:
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            source_ips[source_ip] = source_ips.get(source_ip, 0) + 1
            dest_ips[dest_ip] = dest_ips.get(dest_ip, 0) + 1

            packet_sizes.append(len(packet))
            packet_times.append(packet.time)

            if TCP in packet:
                source_port = packet[TCP].sport
                dest_port = packet[TCP].dport
            elif UDP in packet:
                source_port = packet[UDP].sport
                dest_port = packet[UDP].dport
            else:
                continue

            source_ports[source_port] = source_ports.get(source_port, 0) + 1
            dest_ports[dest_port] = dest_ports.get(dest_port, 0) + 1

    top_protocols = dict(
        sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    )
    top_source_ips = dict(
        sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10]
    )
    top_dest_ips = dict(sorted(dest_ips.items(), key=lambda x: x[1], reverse=True)[:10])
    top_source_ports = dict(
        sorted(source_ports.items(), key=lambda x: x[1], reverse=True)[:10]
    )
    top_dest_ports = dict(
        sorted(dest_ports.items(), key=lambda x: x[1], reverse=True)[:10]
    )

    ddos_detected = detect_ddos(packets)
    packet_size_anomalies = detect_packet_size_anomalies(packet_sizes)

    results = {
        "protocol_counts": protocol_counts,
        "source_ips": source_ips,
        "dest_ips": dest_ips,
        "source_ports": source_ports,
        "dest_ports": dest_ports,
        "packet_sizes": packet_sizes,
        "packet_times": packet_times,
        "top_protocols": top_protocols,
        "top_source_ips": top_source_ips,
        "top_dest_ips": top_dest_ips,
        "top_source_ports": top_source_ports,
        "top_dest_ports": top_dest_ports,
        "ddos_detected": ddos_detected,
        "packet_size_anomalies": packet_size_anomalies,
    }

    return results


def detect_packet_size_anomalies(packet_sizes, threshold=1500):
    """
    Detect anomalies in packet size distribution.
    :param packet_sizes: List of packet sizes.
    :param threshold: Threshold to define anomalies.
    :return: List of anomaly indices.
    """
    anomaly_indices = [i for i, size in enumerate(packet_sizes) if size > threshold]
    return anomaly_indices
