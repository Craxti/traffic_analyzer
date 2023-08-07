import logging
from scapy.layers.inet import IP, TCP, UDP


def detect_ddos(packets, time_window=1, threshold=1000):

    packet_count = len(packets)
    time_range = packets[-1].time - packets[0].time
    packets_per_sec = packet_count / time_range

    if packets_per_sec > threshold:
        return True
    return False


def detect_attacks(packets):
    scan_threshold = 50
    high_traffic_threshold = 200

    ips_counter = {}

    for packet in packets:
        if IP in packet:
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst

            ips_counter[source_ip] = ips_counter.get(source_ip, 0) + 1
            ips_counter[dest_ip] = ips_counter.get(dest_ip, 0) + 1

    suspicious_ips = [ip for ip, count in ips_counter.items() if count > high_traffic_threshold]

    scanning_ips = [ip for ip, count in ips_counter.items() if count > scan_threshold and ip not in suspicious_ips]

    attacks = {
        "suspicious_ips": suspicious_ips,
        "scanning_ips": scanning_ips
    }

    return attacks


def detect_packet_size_anomalies(packet_sizes, threshold=1500):
    """
    Detect anomalies in packet size distribution.

    :param packet_sizes: List of packet sizes.
    :param threshold: Threshold to define anomalies.
    :return: List of anomaly indices.
    """
    anomaly_indices = [i for i, size in enumerate(packet_sizes) if size > threshold]
    return anomaly_indices


def analyze_traffic(packets):
    logging.info("Analisys")

    protocol_counts = {}
    source_ips = {}
    dest_ips = {}
    source_ports = {}
    dest_ports = {}
    packet_sizes = []
    packet_times = []

    for packet in packets:
        protocol = packet[1].name
        protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

        if IP in packet:
            source_ip = packet[IP].src
            dest_ip = packet[IP].dst
            source_ips[source_ip] = source_ips.get(source_ip, 0) + 1
            dest_ips[dest_ip] = dest_ips.get(dest_ip, 0) + 1

            packet_sizes.append(len(packet))
            packet_times.append(packet.time)

            if 'TCP' in packet:
                source_port = packet[TCP].sport
                dest_port = packet[TCP].dport
            elif 'UDP' in packet:
                source_port = packet[UDP].sport
                dest_port = packet[UDP].dport
            else:
                continue

            source_ports[source_port] = source_ports.get(source_port, 0) + 1
            dest_ports[dest_port] = dest_ports.get(dest_port, 0) + 1

    top_protocols = dict(sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    top_source_ips = dict(sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10])
    top_dest_ips = dict(sorted(dest_ips.items(), key=lambda x: x[1], reverse=True)[:10])
    top_source_ports = dict(sorted(source_ports.items(), key=lambda x: x[1], reverse=True)[:10])
    top_dest_ports = dict(sorted(dest_ports.items(), key=lambda x: x[1], reverse=True)[:10])

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
        "packet_size_anomalies": packet_size_anomalies
    }

    return results
