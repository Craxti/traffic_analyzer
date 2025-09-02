"""
Tests for the visualize module.
"""

import unittest
from unittest.mock import patch, MagicMock
import matplotlib.pyplot as plt

from traffic_analyzer.visualize import (
    visualize_protocol_counts,
    visualize_ip_counts,
    visualize_port_counts,
    visualize_packet_sizes,
    visualize_packet_times,
    visualize_top_items,
    update_visualizations
)


class TestVisualize(unittest.TestCase):
    """Test cases for visualize module."""

    @patch('matplotlib.pyplot.show')
    @patch('matplotlib.pyplot.close')
    def test_visualize_protocol_counts(self, mock_close, mock_show):
        """Test protocol counts visualization."""
        protocol_counts = {"TCP": 100, "UDP": 50, "ICMP": 25}
        
        visualize_protocol_counts(protocol_counts)
        
        mock_show.assert_called_once()
        mock_close.assert_called_once()

    @patch('matplotlib.pyplot.show')
    @patch('matplotlib.pyplot.close')
    def test_visualize_protocol_counts_empty(self, mock_close, mock_show):
        """Test protocol counts visualization with empty data."""
        visualize_protocol_counts({})
        
        # Should not call show or close for empty data
        mock_show.assert_not_called()
        mock_close.assert_not_called()

    @patch('matplotlib.pyplot.show')
    @patch('matplotlib.pyplot.close')
    def test_visualize_ip_counts(self, mock_close, mock_show):
        """Test IP counts visualization."""
        ip_counts = {"192.168.1.1": 50, "192.168.1.2": 30}
        
        visualize_ip_counts(ip_counts, "Source IP Distribution")
        
        mock_show.assert_called_once()
        mock_close.assert_called_once()

    @patch('matplotlib.pyplot.show')
    @patch('matplotlib.pyplot.close')
    def test_visualize_ip_counts_empty(self, mock_close, mock_show):
        """Test IP counts visualization with empty data."""
        visualize_ip_counts({}, "Test Title")
        
        # Should not call show or close for empty data
        mock_show.assert_not_called()
        mock_close.assert_not_called()

    @patch('matplotlib.pyplot.show')
    @patch('matplotlib.pyplot.close')
    def test_visualize_port_counts(self, mock_close, mock_show):
        """Test port counts visualization."""
        port_counts = {80: 100, 443: 80, 22: 20}
        
        visualize_port_counts(port_counts, "Destination Port Distribution")
        
        mock_show.assert_called_once()
        mock_close.assert_called_once()

    @patch('matplotlib.pyplot.show')
    @patch('matplotlib.pyplot.close')
    def test_visualize_port_counts_empty(self, mock_close, mock_show):
        """Test port counts visualization with empty data."""
        visualize_port_counts({}, "Test Title")
        
        # Should not call show or close for empty data
        mock_show.assert_not_called()
        mock_close.assert_not_called()

    @patch('matplotlib.pyplot.show')
    @patch('matplotlib.pyplot.close')
    def test_visualize_packet_sizes(self, mock_close, mock_show):
        """Test packet sizes visualization."""
        packet_sizes = [64, 1500, 512, 1024, 1500]
        
        visualize_packet_sizes(packet_sizes)
        
        mock_show.assert_called_once()
        mock_close.assert_called_once()

    @patch('matplotlib.pyplot.show')
    @patch('matplotlib.pyplot.close')
    def test_visualize_packet_sizes_empty(self, mock_close, mock_show):
        """Test packet sizes visualization with empty data."""
        visualize_packet_sizes([])
        
        # Should not call show or close for empty data
        mock_show.assert_not_called()
        mock_close.assert_not_called()

    @patch('matplotlib.pyplot.show')
    @patch('matplotlib.pyplot.close')
    def test_visualize_packet_times(self, mock_close, mock_show):
        """Test packet times visualization."""
        packet_times = [1000.0, 1001.0, 1002.0, 1003.0]
        
        visualize_packet_times(packet_times)
        
        mock_show.assert_called_once()
        mock_close.assert_called_once()

    @patch('matplotlib.pyplot.show')
    @patch('matplotlib.pyplot.close')
    def test_visualize_packet_times_empty(self, mock_close, mock_show):
        """Test packet times visualization with empty data."""
        visualize_packet_times([])
        
        # Should not call show or close for empty data
        mock_show.assert_not_called()
        mock_close.assert_not_called()

    @patch('builtins.print')
    def test_update_visualizations(self, mock_print):
        """Test console visualization update."""
        analysis_results = {
            "protocol_counts": {"TCP": 100, "UDP": 50},
            "source_ips": {"192.168.1.1": 30, "192.168.1.2": 20},
            "dest_ips": {"192.168.1.3": 25, "192.168.1.4": 15},
            "packet_sizes": [64, 1500, 512],
            "ddos_detected": False,
            "packet_size_anomalies": []
        }
        
        update_visualizations(analysis_results)
        
        # Check that print was called (visualization was generated)
        self.assertGreater(mock_print.call_count, 0)

    @patch('matplotlib.pyplot.show')
    @patch('matplotlib.pyplot.close')
    def test_visualize_all(self, mock_close, mock_show):
        """Test visualization of all components."""
        analysis_results = {
            "protocol_counts": {"TCP": 100, "UDP": 50},
            "source_ips": {"192.168.1.1": 30, "192.168.1.2": 20},
            "dest_ips": {"192.168.1.3": 25, "192.168.1.4": 15},
            "source_ports": {80: 50, 443: 30},
            "dest_ports": {22: 20, 53: 10},
            "packet_sizes": [64, 1500, 512],
            "packet_times": [1000.0, 1001.0, 1002.0],
            "ddos_detected": False,
            "packet_size_anomalies": []
        }
        
        # Test all visualization functions
        visualize_protocol_counts(analysis_results["protocol_counts"])
        visualize_ip_counts(analysis_results["source_ips"], "Source IPs")
        visualize_ip_counts(analysis_results["dest_ips"], "Destination IPs")
        visualize_port_counts(analysis_results["source_ports"], "Source Ports")
        visualize_port_counts(analysis_results["dest_ports"], "Destination Ports")
        visualize_packet_sizes(analysis_results["packet_sizes"])
        visualize_packet_times(analysis_results["packet_times"])
        
        # Should have called show and close multiple times
        self.assertGreater(mock_show.call_count, 0)
        self.assertGreater(mock_close.call_count, 0)


if __name__ == '__main__':
    unittest.main()
