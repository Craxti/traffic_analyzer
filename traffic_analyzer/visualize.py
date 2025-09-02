import logging

import matplotlib.pyplot as plt
from tabulate import tabulate

from traffic_analyzer.utils import format_time


def visualize_protocol_counts(protocol_counts):
    """Visualize protocol distribution."""
    if not protocol_counts:
        logging.warning("No protocol data to visualize")
        return
        
    logging.info("Visualizing Protocol Distribution")
    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())

    plt.figure(figsize=(10, 6))
    plt.bar(protocols, counts)
    plt.xlabel("Protocols")
    plt.ylabel("Packet Count")
    plt.title("Protocol Distribution")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
    plt.close()


def visualize_ip_counts(ips, title):
    """Visualize IP distribution."""
    if not ips:
        logging.warning("No IP data to visualize")
        return
        
    logging.info("Visualizing IP Distribution: %s", title)
    addresses = list(ips.keys())
    counts = list(ips.values())

    plt.figure(figsize=(12, 6))
    plt.bar(addresses, counts)
    plt.xlabel("IP Addresses")
    plt.ylabel("Packet Count")
    plt.title(title)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
    plt.close()


def visualize_port_counts(ports, title):
    """Visualize port distribution."""
    if not ports:
        logging.warning("No port data to visualize")
        return
        
    logging.info("Visualizing Top 10 Active Elements: %s", title)
    ports_list = list(ports.keys())
    counts = list(ports.values())

    plt.figure(figsize=(12, 6))
    plt.bar(ports_list, counts)
    plt.xlabel("Ports")
    plt.ylabel("Packet Count")
    plt.title(title)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
    plt.close()


def visualize_packet_sizes(packet_sizes):
    """Visualize packet size distribution."""
    if not packet_sizes:
        logging.warning("No packet size data to visualize")
        return
        
    plt.figure(figsize=(10, 6))
    plt.hist(packet_sizes, bins=50, edgecolor='black')
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Packet Count")
    plt.title("Packet Size Distribution")
    plt.tight_layout()
    plt.show()
    plt.close()


def visualize_packet_times(packet_times):
    """Visualize packet time characteristics."""
    if not packet_times:
        logging.warning("No packet time data to visualize")
        return
        
    plt.figure(figsize=(12, 6))
    plt.plot(range(len(packet_times)), packet_times, marker='o', markersize=2)
    plt.xlabel("Packet Index")
    plt.ylabel("Timestamp")
    plt.title("Packet Time Characteristics")
    plt.tight_layout()
    plt.show()
    plt.close()


def visualize_top_items(items, title, item_name):
    """Visualize top items."""
    if not items:
        logging.warning("No items data to visualize")
        return
        
    names = list(items.keys())
    counts = list(items.values())

    plt.figure(figsize=(12, 6))
    plt.bar(names, counts)
    plt.xlabel(item_name)
    plt.ylabel("Packet Count")
    plt.title(title)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
    plt.close()


def visualize_results(results):
    """Visualize all analysis results."""
    try:
        # Call your visualization functions and display results in the console
        if results.get("protocol_counts"):
            visualize_protocol_counts(results["protocol_counts"])
        if results.get("source_ips"):
            visualize_ip_counts(results["source_ips"], "Outgoing IP Distribution")
        if results.get("dest_ips"):
            visualize_ip_counts(results["dest_ips"], "Incoming IP Distribution")
        if results.get("source_ports"):
            visualize_port_counts(results["source_ports"], "Outgoing Port Distribution")
        if results.get("dest_ports"):
            visualize_port_counts(results["dest_ports"], "Incoming Port Distribution")
        if results.get("packet_sizes"):
            visualize_packet_sizes(results["packet_sizes"])
        if results.get("packet_times"):
            visualize_packet_times(results["packet_times"])
        if results.get("top_protocols"):
            visualize_top_items(
                results["top_protocols"], "Top 10 Most Active Protocols", "Protocol"
            )
        if results.get("top_source_ips"):
            visualize_top_items(
                results["top_source_ips"], "Top 10 Outgoing IP Addresses", "IP Address"
            )
        if results.get("top_dest_ips"):
            visualize_top_items(
                results["top_dest_ips"], "Top 10 Incoming IP Addresses", "IP Address"
            )
        if results.get("top_source_ports"):
            visualize_top_items(results["top_source_ports"], "Top 10 Outgoing Ports", "Port")
        if results.get("top_dest_ports"):
            visualize_top_items(results["top_dest_ports"], "Top 10 Incoming Ports", "Port")

        # Display additional information
        if results.get("ddos_detected"):
            print("⚠️  DDoS Attack Detected!")
            
    except Exception as e:
        logging.error("Error during visualization: %s", str(e))


def update_visualizations(results):
    """Update console visualizations with results."""
    try:
        if results.get("protocol_counts"):
            print("Protocol Distribution:")
            print(
                tabulate(
                    results["protocol_counts"].items(), headers=["Protocol", "Packet Count"]
                )
            )

        if results.get("source_ips"):
            print("\nOutgoing IP Distribution:")
            print(
                tabulate(results["source_ips"].items(), headers=["IP Address", "Packet Count"])
            )

        if results.get("dest_ips"):
            print("\nIncoming IP Distribution:")
            print(tabulate(results["dest_ips"].items(), headers=["IP Address", "Packet Count"]))

        if results.get("source_ports"):
            print("\nOutgoing Port Distribution:")
            print(tabulate(results["source_ports"].items(), headers=["Port", "Packet Count"]))

        if results.get("dest_ports"):
            print("\nIncoming Port Distribution:")
            print(tabulate(results["dest_ports"].items(), headers=["Port", "Packet Count"]))

        if results.get("packet_sizes"):
            print("\nPacket Size Distribution:")
            print(
                tabulate([(size,) for size in results["packet_sizes"]], headers=["Packet Size"])
            )

        if results.get("packet_times"):
            print("\nPacket Time Characteristics:")
            formatted_times = [format_time(timestamp) for timestamp in results["packet_times"]]
            print(
                tabulate(
                    zip(formatted_times, results["packet_times"]),
                    headers=["Time", "Time Characteristics"],
                )
            )

        if results.get("top_protocols"):
            print("\nTop 10 Most Active Protocols:")
            print(
                tabulate(results["top_protocols"].items(), headers=["Protocol", "Packet Count"])
            )

        if results.get("top_source_ips"):
            print("\nTop 10 Outgoing IP Addresses:")
            print(
                tabulate(
                    results["top_source_ips"].items(), headers=["IP Address", "Packet Count"]
                )
            )

        if results.get("top_dest_ips"):
            print("\nTop 10 Incoming IP Addresses:")
            print(
                tabulate(
                    results["top_dest_ips"].items(), headers=["IP Address", "Packet Count"]
                )
            )

        if results.get("top_source_ports"):
            print("\nTop 10 Outgoing Ports:")
            print(
                tabulate(results["top_source_ports"].items(), headers=["Port", "Packet Count"])
            )

        if results.get("top_dest_ports"):
            print("\nTop 10 Incoming Ports:")
            print(tabulate(results["top_dest_ports"].items(), headers=["Port", "Packet Count"]))

        # Display attack warnings
        if results.get("ddos_detected", False):
            print("\n⚠️  DDoS Attack Detected!")
            
    except Exception as e:
        logging.error("Error during console visualization: %s", str(e))
