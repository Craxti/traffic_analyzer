import logging
import os

from scapy.all import PcapReader, sniff, IP, TCP, UDP, DNS, DNSQR, Raw
from .npcap_manager import check_capture_ready, ensure_npcap_available


def capture_traffic(interface, packet_count, filter=None):
    """
    Capture network traffic on the specified interface.

    :param interface: Network interface to capture traffic from.
    :param packet_count: Number of packets to capture.
    :param filter: Optional BPF filter to apply to captured packets.
    :return: List of captured packets.
    """
    try:
        # Check if capture is ready (Npcap installed on Windows)
        if not check_capture_ready():
            logging.warning("Npcap not available. Attempting to install...")
            if not ensure_npcap_available():
                logging.error("Failed to setup Npcap. Traffic capture may not work.")
                return []
        
        logging.info("Capturing traffic on interface: %s", interface)

        if filter:
            logging.info("Applying filter: %s", filter)

        packets = sniff(iface=interface, count=packet_count, filter=filter)

        logging.info("Captured %d packets", len(packets))

        return packets

    except OSError as os_error:
        logging.error(
            "Error capturing traffic: %s. Check if the interface exists.", os_error
        )
        return []

    except Exception as e:
        logging.error("An error occurred while capturing traffic: %s", str(e))
        return []


def capture_traffic_async(interface, packet_count, filter=None):
    """
    Asynchronously capture network traffic on the specified interface using asyncio.

    :param interface: Network interface to capture traffic from.
    :param packet_count: Number of packets to capture.
    :param filter: Optional BPF filter to apply to captured packets.
    :return: List of captured packets.
    """
    try:
        logging.info("Capturing traffic on interface (async): %s", interface)

        if filter:
            logging.info("Applying filter: %s", filter)

        packets = sniff(iface=interface, count=packet_count, filter=filter, store=False)

        logging.info("Captured %d packets asynchronously", len(packets))

        return packets

    except OSError as os_error:
        logging.error(
            "Error capturing traffic: %s. Check if the interface exists.", os_error
        )
        return []

    except Exception as e:
        logging.error("An error occurred while capturing traffic: %s", str(e))
        return []


def read_pcap_file(file_path, packet_count=None, filter=None):
    """
    Read packets from a PCAP file.

    :param file_path: Path to the PCAP file.
    :param packet_count: Number of packets to read (None for all packets).
    :param filter: Optional BPF filter to apply to read packets.
    :return: List of packets read from the file.
    """
    try:
        if not os.path.exists(file_path):
            logging.error("PCAP file not found: %s", file_path)
            return []

        logging.info("Reading PCAP file: %s", file_path)
        
        # Create a reader for the PCAP file
        pcap_reader = PcapReader(file_path)
        packets = []
        
        # Read packets with an optional limit
        if packet_count is None:
            # Read all packets
            for packet in pcap_reader:
                packets.append(packet)
        else:
            # Read limited number of packets
            for i, packet in enumerate(pcap_reader):
                if i >= packet_count:
                    break
                packets.append(packet)
        
        pcap_reader.close()
        
        # Apply filter if specified
        if filter and packets:
            try:
                # Create a temporary filter function
                from scapy.arch.common import compile_filter
                from scapy.config import conf
                
                bpf_filter = None
                try:
                    bpf_filter = compile_filter(filter)
                except ImportError:
                    logging.warning("BPF filter compilation not supported on this platform")
                    pass
                
                if bpf_filter:
                    # Apply the filter
                    filtered_packets = []
                    for packet in packets:
                        if bpf_filter(packet):
                            filtered_packets.append(packet)
                    packets = filtered_packets
                    
            except Exception as filter_error:
                logging.error("Error applying filter to PCAP: %s", str(filter_error))
        
        logging.info("Read %d packets from PCAP file", len(packets))
        return packets
        
    except Exception as e:
        logging.error("Error reading PCAP file: %s", str(e))
        return []


def get_packet_info(packet):
    """
    Extract basic information from a packet.
    
    :param packet: Packet to analyze.
    :return: Dictionary with packet information.
    """
    info = {
        "time": packet.time if hasattr(packet, "time") else None,
        "length": len(packet),
        "layers": []
    }
    
    # Extract layer information
    current = packet
    while current:
        layer_name = current.name if hasattr(current, "name") else type(current).__name__
        info["layers"].append(layer_name)
        
        # Try to get the payload
        if hasattr(current, "payload"):
            current = current.payload
        else:
            break
    
    return info


def create_test_packets():
    """
    Create synthetic test packets for testing purposes.
    
    :return: List of synthetic packets.
    """
    packets = []
    
    try:
        # Create HTTP packet
        http_packet = IP(dst="192.168.1.1") / TCP(dport=80) / Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        packets.append(http_packet)
        
        # Create HTTPS packet
        https_packet = IP(dst="192.168.1.1") / TCP(dport=443) / Raw(load="\x16\x03\x01\x00\x01\x01")
        packets.append(https_packet)
        
        # Create DNS packet
        dns_packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        packets.append(dns_packet)
        
        # Create TCP packet
        tcp_packet = IP(dst="192.168.1.100") / TCP(dport=22)
        packets.append(tcp_packet)
        
        # Create UDP packet
        udp_packet = IP(dst="192.168.1.100") / UDP(dport=123)
        packets.append(udp_packet)
        
        logging.info("Created %d test packets", len(packets))
        return packets
        
    except Exception as e:
        logging.error("Error creating test packets: %s", str(e))
        return []
