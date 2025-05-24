import logging

import matplotlib.pyplot as plt
from tabulate import tabulate

from traffic_analyzer.utils import format_time


def visualize_protocol_counts(protocol_counts):
    logging.info("Visualizing Protocol Distribution")
    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())

    plt.bar(protocols, counts)
    plt.xlabel("Protocols")
    plt.ylabel("Packet Count")
    plt.title("Protocol Distribution")
    plt.show()
    plt.close()  # Close the plot window


def visualize_ip_counts(ips, title):
    logging.info("Visualizing IP Distribution: %s", title)
    addresses = list(ips.keys())
    counts = list(ips.values())

    plt.bar(addresses, counts)
    plt.xlabel("IP Addresses")
    plt.ylabel("Packet Count")
    plt.title(title)
    plt.xticks(rotation=45)
    plt.show()
    plt.close()  # Close the plot window


def visualize_port_counts(ports, title):
    logging.info("Visualizing Top 10 Active Elements: %s", title)
    ports_list = list(ports.keys())
    counts = list(ports.values())

    plt.bar(ports_list, counts)
    plt.xlabel("Ports")
    plt.ylabel("Packet Count")
    plt.title(title)
    plt.xticks(rotation=45)
    plt.show()
    plt.close()  # Close the plot window


def visualize_packet_sizes(packet_sizes):
    plt.hist(packet_sizes, bins=50)
    plt.xlabel("Packet Size")
    plt.ylabel("Packet Count")
    plt.title("Packet Size Distribution")
    plt.show()
    plt.close()  # Close the plot window


def visualize_packet_times(packet_times):
    formatted_times = [format_time(timestamp) for timestamp in packet_times]

    plt.plot(formatted_times, packet_times)
    plt.xlabel("Time")
    plt.ylabel("Packet Time Characteristics")
    plt.title("Packet Time Characteristics")
    plt.xticks(rotation=45)
    plt.show()
    plt.close()  # Close the plot window


def visualize_top_items(items, title, item_name):
    names = list(items.keys())
    counts = list(items.values())

    plt.bar(names, counts)
    plt.xlabel(item_name)
    plt.ylabel("Packet Count")
    plt.title(title)
    plt.xticks(rotation=45)
    plt.show()
    plt.close()  # Close the plot window


def visualize_results(results):
    # Call your visualization functions and display results in the console
    visualize_protocol_counts(results["protocol_counts"])
    visualize_ip_counts(results["source_ips"], "Outgoing IP Distribution")
    visualize_ip_counts(results["dest_ips"], "Incoming IP Distribution")
    visualize_port_counts(results["source_ports"], "Outgoing Port Distribution")
    visualize_port_counts(results["dest_ports"], "Incoming Port Distribution")
    visualize_packet_sizes(results["packet_sizes"])
    visualize_packet_times(results["packet_times"])
    visualize_top_items(
        results["top_protocols"], "Top 10 Most Active Protocols", "Protocol"
    )
    visualize_top_items(
        results["top_source_ips"], "Top 10 Outgoing IP Addresses", "IP Address"
    )
    visualize_top_items(
        results["top_dest_ips"], "Top 10 Incoming IP Addresses", "IP Address"
    )
    visualize_top_items(results["top_source_ports"], "Top 10 Outgoing Ports", "Port")
    visualize_top_items(results["top_dest_ports"], "Top 10 Incoming Ports", "Port")

    # Display additional information
    if results["ddos_detected"]:
        print("DDoS Attack Detected!")


def update_visualizations(results):
    print("Protocol Distribution:")
    print(
        tabulate(
            results["protocol_counts"].items(), headers=["Protocol", "Packet Count"]
        )
    )

    print("\nOutgoing IP Distribution:")
    print(
        tabulate(results["source_ips"].items(), headers=["IP Address", "Packet Count"])
    )

    print("\nIncoming IP Distribution:")
    print(tabulate(results["dest_ips"].items(), headers=["IP Address", "Packet Count"]))

    print("\nOutgoing Port Distribution:")
    print(tabulate(results["source_ports"].items(), headers=["Port", "Packet Count"]))

    print("\nIncoming Port Distribution:")
    print(tabulate(results["dest_ports"].items(), headers=["Port", "Packet Count"]))

    print("\nPacket Size Distribution:")
    print(
        tabulate([(size,) for size in results["packet_sizes"]], headers=["Packet Size"])
    )

    print("\nPacket Time Characteristics:")
    formatted_times = [format_time(timestamp) for timestamp in results["packet_times"]]
    print(
        tabulate(
            zip(formatted_times, results["packet_times"]),
            headers=["Time", "Time Characteristics"],
        )
    )

    print("\nTop 10 Most Active Protocols:")
    print(
        tabulate(results["top_protocols"].items(), headers=["Protocol", "Packet Count"])
    )

    print("\nTop 10 Outgoing IP Addresses:")
    print(
        tabulate(
            results["top_source_ips"].items(), headers=["IP Address", "Packet Count"]
        )
    )

    print("\nTop 10 Incoming IP Addresses:")
    print(
        tabulate(
            results["top_dest_ips"].items(), headers=["IP Address", "Packet Count"]
        )
    )

    print("\nTop 10 Outgoing Ports:")
    print(
        tabulate(results["top_source_ports"].items(), headers=["Port", "Packet Count"])
    )

    print("\nTop 10 Incoming Ports:")
    print(tabulate(results["top_dest_ports"].items(), headers=["Port", "Packet Count"]))

    # Display attack warnings
    if results.get("ddos_detected", False):
        print("\nDDoS Attack Detected!")
