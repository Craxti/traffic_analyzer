"""
Tests for the analyze module.
"""

import unittest
from unittest.mock import patch, MagicMock
from scapy.layers.inet import IP, TCP, UDP

from traffic_analyzer.analyze import (
    detect_port_scan,
    detect_malicious_payload,
    analyze_network_activity,
    detect_ddos,
    detect_attacks,
    analyze_traffic,
    detect_packet_size_anomalies
)


class TestAnalyze(unittest.TestCase):
    """Test cases for analyze module."""

    def test_detect_port_scan(self):
        """Test port scan detection."""
        # Create mock packets
        packet1 = MagicMock()
        packet1.__contains__ = lambda self, x: x == IP or x == TCP
        packet1[IP].src = "192.168.0.1"
        packet1[TCP].flags = 2  # SYN flag

        packet2 = MagicMock()
        packet2.__contains__ = lambda self, x: x == IP or x == TCP
        packet2[IP].src = "192.168.0.2"
        packet2[TCP].flags = 16  # ACK flag

        packet3 = MagicMock()
        packet3.__contains__ = lambda self, x: x == IP or x == TCP
        packet3[IP].src = "192.168.0.3"
        packet3[TCP].flags = 2  # SYN flag

        packets = [packet1, packet2, packet3]
        
        scan_ips = detect_port_scan(packets)
        expected_scan_ips = ["192.168.0.1", "192.168.0.3"]
        
        self.assertEqual(sorted(scan_ips), sorted(expected_scan_ips))

    def test_detect_port_scan_no_syn_packets(self):
        """Test port scan detection with no SYN packets."""
        packet1 = MagicMock()
        packet1.__contains__ = lambda self, x: x == IP or x == TCP
        packet1[IP].src = "192.168.0.1"
        packet1[TCP].flags = 16  # ACK flag

        packets = [packet1]
        
        scan_ips = detect_port_scan(packets)
        self.assertEqual(scan_ips, [])

    def test_detect_malicious_payload(self):
        """Test malicious payload detection."""
        packets = [
            b"This packet contains malware",
            b"Another packet with malware",
            b"Clean packet"
        ]
        
        malicious_packets = detect_malicious_payload(packets, "malware")
        expected_packets = [
            b"This packet contains malware",
            b"Another packet with malware"
        ]
        
        self.assertEqual(malicious_packets, expected_packets)

    def test_detect_malicious_payload_no_matches(self):
        """Test malicious payload detection with no matches."""
        packets = [b"Clean packet 1", b"Clean packet 2"]
        
        malicious_packets = detect_malicious_payload(packets, "malware")
        self.assertEqual(malicious_packets, [])

    def test_analyze_network_activity(self):
        """Test network activity analysis."""
        # Create mock packets with layers
        packet1 = MagicMock()
        packet1.layers.return_value = ["Raw", "IP"]
        
        packet2 = MagicMock()
        packet2.layers.return_value = ["Raw", "TCP"]
        
        packet3 = MagicMock()
        packet3.layers.return_value = ["Raw", "IP"]
        
        packets = [packet1, packet2, packet3]
        
        activity_counts = analyze_network_activity(packets)
        expected_counts = {"IP": 2, "TCP": 1}
        
        self.assertEqual(activity_counts, expected_counts)

    def test_analyze_network_activity_empty_packets(self):
        """Test network activity analysis with empty packet list."""
        activity_counts = analyze_network_activity([])
        self.assertEqual(activity_counts, {})

    def test_detect_ddos_attack(self):
        """Test DDoS attack detection."""
        # Create mock packets with timestamps
        packet1 = MagicMock()
        packet1.time = 1000.0
        
        packet2 = MagicMock()
        packet2.time = 1001.0
        
        packet3 = MagicMock()
        packet3.time = 1002.0
        
        packets = [packet1, packet2, packet3]
        
        # Test with high threshold (should not detect)
        ddos_detected = detect_ddos(packets, threshold=1000)
        self.assertFalse(ddos_detected)
        
        # Test with low threshold (should detect)
        ddos_detected = detect_ddos(packets, threshold=1)
        self.assertTrue(ddos_detected)

    def test_detect_ddos_insufficient_packets(self):
        """Test DDoS detection with insufficient packets."""
        packet = MagicMock()
        packet.time = 1000.0
        
        ddos_detected = detect_ddos([packet])
        self.assertFalse(ddos_detected)

    def test_detect_ddos_zero_time_range(self):
        """Test DDoS detection with zero time range."""
        packet1 = MagicMock()
        packet1.time = 1000.0
        
        packet2 = MagicMock()
        packet2.time = 1000.0  # Same time
        
        packets = [packet1, packet2]
        
        ddos_detected = detect_ddos(packets, threshold=1)
        self.assertTrue(ddos_detected)  # Should detect due to division by small number

    def test_detect_attacks(self):
        """Test attack detection."""
        # Create mock packets with more traffic to meet thresholds
        packets = []
        
        # Create many packets from 192.168.0.1 to make it suspicious
        for i in range(60):  # More than high_traffic_threshold (50)
            packet = MagicMock()
            packet.__contains__ = lambda self, x: x == IP
            packet[IP].src = "192.168.0.1"
            packet[IP].dst = f"192.168.0.{i+2}"
            packets.append(packet)
        
        # Create some packets from other IPs
        for i in range(5):
            packet = MagicMock()
            packet.__contains__ = lambda self, x: x == IP
            packet[IP].src = "192.168.0.2"
            packet[IP].dst = f"192.168.0.{i+10}"
            packets.append(packet)
        
        attacks = detect_attacks(packets)
        
        # Check that suspicious_ips and scanning_ips are lists
        self.assertIsInstance(attacks["suspicious_ips"], list)
        self.assertIsInstance(attacks["scanning_ips"], list)
        
        # Check that 192.168.0.1 is in suspicious_ips (high traffic)
        self.assertIn("192.168.0.1", attacks["suspicious_ips"])

    def test_detect_attacks_no_ip_packets(self):
        """Test attack detection with no IP packets."""
        packet = MagicMock()
        packet.__contains__ = lambda self, x: False
        
        attacks = detect_attacks([packet])
        
        self.assertEqual(attacks["suspicious_ips"], [])
        self.assertEqual(attacks["scanning_ips"], [])

    def test_analyze_traffic(self):
        """Test traffic analysis."""
        # Create mock packets
        packet1 = MagicMock()
        packet1.layers.return_value = ["Raw", "IP"]
        packet1.__contains__ = lambda self, x: x == IP or x == TCP
        packet1[IP].src = "192.168.0.1"
        packet1[IP].dst = "192.168.0.2"
        packet1[TCP].sport = 12345
        packet1[TCP].dport = 80
        packet1.__len__.return_value = 1500
        packet1.time = 1000.0
        
        packet2 = MagicMock()
        packet2.layers.return_value = ["Raw", "UDP"]
        packet2.__contains__ = lambda self, x: x == IP or x == UDP
        packet2[IP].src = "192.168.0.2"
        packet2[IP].dst = "192.168.0.1"
        packet2[UDP].sport = 53
        packet2[UDP].dport = 12345
        packet2.__len__.return_value = 512
        packet2.time = 1001.0
        
        packets = [packet1, packet2]
        
        results = analyze_traffic(packets)
        
        # Check basic structure
        self.assertIn("protocol_counts", results)
        self.assertIn("source_ips", results)
        self.assertIn("dest_ips", results)
        self.assertIn("source_ports", results)
        self.assertIn("dest_ports", results)
        self.assertIn("packet_sizes", results)
        self.assertIn("packet_times", results)
        self.assertIn("ddos_detected", results)
        self.assertIn("packet_size_anomalies", results)
        
        # Check protocol counts
        self.assertEqual(results["protocol_counts"]["IP"], 1)  # Only first packet has IP as layer
        self.assertEqual(results["protocol_counts"]["UDP"], 1)
        
        # Check IP counts
        self.assertEqual(results["source_ips"]["192.168.0.1"], 1)
        self.assertEqual(results["source_ips"]["192.168.0.2"], 1)
        self.assertEqual(results["dest_ips"]["192.168.0.1"], 1)
        self.assertEqual(results["dest_ips"]["192.168.0.2"], 1)
        
        # Check port counts
        self.assertEqual(results["source_ports"][12345], 1)
        self.assertEqual(results["source_ports"][53], 1)
        self.assertEqual(results["dest_ports"][80], 1)
        self.assertEqual(results["dest_ports"][12345], 1)
        
        # Check packet sizes
        self.assertEqual(results["packet_sizes"], [1500, 512])
        
        # Check packet times
        self.assertEqual(results["packet_times"], [1000.0, 1001.0])

    def test_analyze_traffic_no_ip_packets(self):
        """Test traffic analysis with no IP packets."""
        packet = MagicMock()
        packet.layers.return_value = ["Raw", "ARP"]
        packet.__contains__ = lambda self, x: False
        
        results = analyze_traffic([packet])
        
        # Should still have basic structure
        self.assertIn("protocol_counts", results)
        self.assertIn("source_ips", results)
        self.assertIn("dest_ips", results)
        
        # But no IP-related data
        self.assertEqual(results["source_ips"], {})
        self.assertEqual(results["dest_ips"], {})
        self.assertEqual(results["packet_sizes"], [])
        self.assertEqual(results["packet_times"], [])

    def test_detect_packet_size_anomalies(self):
        """Test packet size anomaly detection."""
        packet_sizes = [64, 1500, 2000, 512, 3000]
        
        # Test with default threshold (1500)
        anomalies = detect_packet_size_anomalies(packet_sizes)
        expected_anomalies = [2, 4]  # Indices of packets > 1500
        self.assertEqual(anomalies, expected_anomalies)
        
        # Test with custom threshold
        anomalies = detect_packet_size_anomalies(packet_sizes, threshold=1000)
        expected_anomalies = [1, 2, 4]  # Indices of packets > 1000
        self.assertEqual(anomalies, expected_anomalies)

    def test_detect_packet_size_anomalies_no_anomalies(self):
        """Test packet size anomaly detection with no anomalies."""
        packet_sizes = [64, 512, 1024]
        
        anomalies = detect_packet_size_anomalies(packet_sizes, threshold=1500)
        self.assertEqual(anomalies, [])

    def test_detect_packet_size_anomalies_empty_list(self):
        """Test packet size anomaly detection with empty list."""
        anomalies = detect_packet_size_anomalies([])
        self.assertEqual(anomalies, [])


if __name__ == '__main__':
    unittest.main()
