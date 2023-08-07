from scapy.layers.inet import IP, TCP
import unittest
from unittest.mock import patch
from scapy.packet import Packet
from traffic_analyzer.capture import capture_traffic
from traffic_analyzer.analyze import detect_port_scan, detect_malicious_payload



class TestTrafficAnalyzer(unittest.TestCase):

    @patch('traffic_analyzer.capture.sniff')
    def test_capture_traffic(self, mock_sniff):
        mock_packet = Packet()
        mock_packet.time = 123456789.0
        mock_sniff.return_value = [mock_packet]

        packets = capture_traffic("eth0", 1)

        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0], mock_packet)

    def test_detect_port_scan(self):
        packets = [
            IP(src="192.168.0.1") / TCP(flags=2),  # Port scan packet (SYN flag set)
            IP(src="192.168.0.2") / TCP(flags=16),  # Not a port scan packet (ACK flag set)
            IP(src="192.168.0.3") / TCP(flags=2),  # Port scan packet (SYN flag set)
            IP(src="192.168.0.1") / TCP(flags=8),  # Not a port scan packet (PSH flag set)
        ]

        scan_ips = detect_port_scan(packets)
        expected_scan_ips = ["192.168.0.1", "192.168.0.3"]

        self.assertEqual(scan_ips, expected_scan_ips)

    def test_detect_malicious_payload(self):
        packets = [b'This packet contains malware', b'Another packet with malware']

        malicious_packets = detect_malicious_payload(packets)
        expected_malicious_packets = [
            b"This packet contains malware",
            b"Another packet with malware",
        ]

        self.assertEqual(malicious_packets, expected_malicious_packets)


if __name__ == '__main__':
    unittest.main()
