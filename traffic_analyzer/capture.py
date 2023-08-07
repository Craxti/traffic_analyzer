import logging
from scapy.all import sniff


def capture_traffic(interface, packet_count, filter=None):
    """
    Capture network traffic on the specified interface.

    :param interface: Network interface to capture traffic from.
    :param packet_count: Number of packets to capture.
    :param filter: Optional BPF filter to apply to captured packets.
    :return: List of captured packets.
    """
    try:
        logging.info("Capturing traffic on interface: %s", interface)

        if filter:
            logging.info("Applying filter: %s", filter)

        packets = sniff(iface=interface, count=packet_count, filter=filter)

        logging.info("Captured %d packets", len(packets))

        return packets

    except Exception as e:
        logging.error("An error occurred while capturing traffic: %s", str(e))
        return []
