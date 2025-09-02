"""
Tests for the export module.
"""

import unittest
import tempfile
import os
import json
import csv
from unittest.mock import patch, mock_open, MagicMock

from traffic_analyzer.export import (
    export_to_json,
    export_to_csv
)


class TestExport(unittest.TestCase):
    """Test cases for export module."""

    def setUp(self):
        """Set up test data."""
        self.test_data = {
            "protocol_counts": {"TCP": 100, "UDP": 50, "ICMP": 25},
            "source_ips": {"192.168.1.1": 30, "192.168.1.2": 20},
            "dest_ips": {"192.168.1.3": 25, "192.168.1.4": 15},
            "source_ports": {80: 50, 443: 30},
            "dest_ports": {22: 20, 53: 10},
            "packet_sizes": [64, 1500, 512],
            "packet_times": [1000.0, 1001.0, 1002.0],
            "ddos_detected": False,
            "packet_size_anomalies": []
        }

    def test_export_to_json(self):
        """Test JSON export."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_filename = temp_file.name
        
        try:
            export_to_json(self.test_data, temp_filename)
            
            # Verify file was created and contains valid JSON
            self.assertTrue(os.path.exists(temp_filename))
            
            with open(temp_filename, 'r') as f:
                exported_data = json.load(f)
            
            self.assertEqual(exported_data["protocol_counts"], self.test_data["protocol_counts"])
            self.assertEqual(exported_data["source_ips"], self.test_data["source_ips"])
            self.assertEqual(exported_data["ddos_detected"], self.test_data["ddos_detected"])
            
        finally:
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)

    def test_export_to_csv(self):
        """Test CSV export."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as temp_file:
            temp_filename = temp_file.name
        
        try:
            exported_files = export_to_csv(self.test_data, temp_filename)
            
            # Should return a list of exported files
            self.assertIsInstance(exported_files, list)
            self.assertGreater(len(exported_files), 0)
            
            # Verify at least one file was created
            for filename in exported_files:
                self.assertTrue(os.path.exists(filename))
                
                # Verify CSV structure
                with open(filename, 'r', newline='') as f:
                    reader = csv.reader(f)
                    rows = list(reader)
                
                # Should have headers and data rows
                self.assertGreater(len(rows), 1)
            
        finally:
            # Clean up all created files
            for filename in exported_files:
                if os.path.exists(filename):
                    os.unlink(filename)



    def test_export_to_json_empty_data(self):
        """Test JSON export with empty data."""
        empty_data = {}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_filename = temp_file.name
        
        try:
            export_to_json(empty_data, temp_filename)
            
            # Verify file was created
            self.assertTrue(os.path.exists(temp_filename))
            
            with open(temp_filename, 'r') as f:
                exported_data = json.load(f)
            
            self.assertEqual(exported_data, {})
            
        finally:
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)

    def test_export_to_csv_empty_data(self):
        """Test CSV export with empty data."""
        empty_data = {}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as temp_file:
            temp_filename = temp_file.name
        
        try:
            exported_files = export_to_csv(empty_data, temp_filename)
            
            # Should return an empty list for empty data
            self.assertIsInstance(exported_files, list)
            self.assertEqual(len(exported_files), 0)
            
        finally:
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)




if __name__ == '__main__':
    unittest.main()
