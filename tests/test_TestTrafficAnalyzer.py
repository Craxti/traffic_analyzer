import unittest
from unittest.mock import patch

from scapy.layers.inet import IP, TCP

from traffic_analyzer.analyze import detect_malicious_payload, detect_port_scan
from traffic_analyzer.capture import capture_traffic, capture_traffic_async


class TestTrafficAnalyzer(unittest.TestCase):

    @patch("traffic_analyzer.capture.sniff")
    def test_capture_traffic(self, mock_sniff):
        mock_sniff.return_value = [b"Packet 1", b"Packet 2", b"Packet 3"]

        interface = "eth0"
        packet_count = 3
        result = capture_traffic(interface, packet_count)

        self.assertEqual(result, [b"Packet 1", b"Packet 2", b"Packet 3"])
        mock_sniff.assert_called_once_with(
            iface=interface, count=packet_count, filter=None
        )

    @patch("traffic_analyzer.capture.sniff")
    def test_capture_traffic_with_filter(self, mock_sniff):
        mock_sniff.return_value = [b"Filtered Packet"]

        interface = "eth0"
        packet_count = 1
        result = capture_traffic(interface, packet_count, filter="tcp")

        self.assertEqual(result, [b"Filtered Packet"])
        mock_sniff.assert_called_once_with(
            iface=interface, count=packet_count, filter="tcp"
        )

    @patch("traffic_analyzer.capture.sniff")
    def test_capture_traffic_async(self, mock_sniff):
        mock_sniff.return_value = [b"Async Packet 1", b"Async Packet 2"]

        interface = "eth0"
        packet_count = 2
        result = capture_traffic_async(interface, packet_count)

        self.assertEqual(result, [b"Async Packet 1", b"Async Packet 2"])
        mock_sniff.assert_called_once_with(
            iface=interface, count=packet_count, filter=None, store=False
        )

    @patch("traffic_analyzer.capture.sniff")
    def test_capture_traffic_async_with_filter(self, mock_sniff):
        mock_sniff.return_value = [b"Filtered Async Packet"]

        interface = "eth0"
        packet_count = 1
        result = capture_traffic_async(interface, packet_count, filter="udp")

        self.assertEqual(result, [b"Filtered Async Packet"])
        mock_sniff.assert_called_once_with(
            iface=interface, count=packet_count, filter="udp", store=False
        )

    def test_detect_port_scan(self):
        packets = [
            IP(src="192.168.0.1") / TCP(flags=2),  # Port scan packet (SYN flag set)
            IP(src="192.168.0.2")
            / TCP(flags=16),  # Not a port scan packet (ACK flag set)
            IP(src="192.168.0.3") / TCP(flags=2),  # Port scan packet (SYN flag set)
            IP(src="192.168.0.1")
            / TCP(flags=8),  # Not a port scan packet (PSH flag set)
        ]

        scan_ips = detect_port_scan(packets)
        expected_scan_ips = ["192.168.0.1", "192.168.0.3"]

        self.assertEqual(sorted(scan_ips), sorted(expected_scan_ips))

    def test_detect_malicious_payload(self):
        packets = [b"This packet contains malware", b"Another packet with malware"]

        malicious_packets = detect_malicious_payload(packets)
        expected_malicious_packets = [
            b"This packet contains malware",
            b"Another packet with malware",
        ]

        self.assertEqual(malicious_packets, expected_malicious_packets)


if __name__ == "__main__":
    unittest.main()
