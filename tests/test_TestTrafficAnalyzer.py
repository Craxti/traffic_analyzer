import unittest
from unittest.mock import patch
from scapy.packet import Packet
from traffic_analyzer.capture import capture_traffic


class TestTrafficAnalyzer(unittest.TestCase):

    @patch('traffic_analyzer.capture.sniff')
    def test_capture_traffic(self, mock_sniff):
        mock_packet = Packet()
        mock_packet.time = 123456789.0
        mock_sniff.return_value = [mock_packet]

        packets = capture_traffic("eth0", 1)

        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0], mock_packet)


if __name__ == '__main__':
    unittest.main()
