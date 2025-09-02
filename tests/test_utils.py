"""
Tests for the utils module.
"""

import unittest
from unittest.mock import patch
import time

from traffic_analyzer.utils import (
    format_time,
    validate_ip,
    validate_ipv4,
    validate_ipv6,
    get_ip_version,
    sanitize_packet_data,
    save_to_file
)


class TestUtils(unittest.TestCase):
    """Test cases for utils module."""

    def test_format_time(self):
        """Test time formatting."""
        # Test current time
        current_time = time.time()
        formatted = format_time(current_time)
        self.assertIsInstance(formatted, str)
        self.assertGreater(len(formatted), 0)

        # Test None
        formatted = format_time(None)
        self.assertEqual(formatted, "N/A")

    def test_validate_ip(self):
        """Test IP address validation."""
        # Valid IP addresses
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("10.0.0.1"))
        self.assertTrue(validate_ip("172.16.0.1"))
        self.assertTrue(validate_ip("127.0.0.1"))
        
        # Invalid IP addresses
        self.assertFalse(validate_ip("256.1.2.3"))
        self.assertFalse(validate_ip("192.168.1"))
        self.assertFalse(validate_ip("192.168.1.256"))
        self.assertFalse(validate_ip("invalid"))
        self.assertFalse(validate_ip(""))

    def test_validate_ipv4(self):
        """Test IPv4 address validation."""
        # Valid IPv4 addresses
        self.assertTrue(validate_ipv4("192.168.1.1"))
        self.assertTrue(validate_ipv4("10.0.0.1"))
        self.assertTrue(validate_ipv4("172.16.0.1"))
        self.assertTrue(validate_ipv4("127.0.0.1"))
        
        # Invalid IPv4 addresses
        self.assertFalse(validate_ipv4("256.1.2.3"))
        self.assertFalse(validate_ipv4("192.168.1"))
        self.assertFalse(validate_ipv4("192.168.1.256"))
        self.assertFalse(validate_ipv4("invalid"))
        self.assertFalse(validate_ipv4(""))

    def test_validate_ipv6(self):
        """Test IPv6 address validation."""
        # Valid IPv6 addresses
        self.assertTrue(validate_ipv6("::1"))
        self.assertTrue(validate_ipv6("2001:db8::1"))
        self.assertTrue(validate_ipv6("fe80::1%lo0"))
        
        # Invalid IPv6 addresses
        self.assertFalse(validate_ipv6("192.168.1.1"))
        self.assertFalse(validate_ipv6("invalid"))
        self.assertFalse(validate_ipv6(""))

    def test_get_ip_version(self):
        """Test IP version detection."""
        # IPv4 addresses
        self.assertEqual(get_ip_version("192.168.1.1"), 4)
        self.assertEqual(get_ip_version("127.0.0.1"), 4)
        
        # IPv6 addresses
        self.assertEqual(get_ip_version("::1"), 6)
        self.assertEqual(get_ip_version("2001:db8::1"), 6)
        
        # Invalid addresses
        self.assertEqual(get_ip_version("invalid"), 0)
        self.assertEqual(get_ip_version(""), 0)

    def test_sanitize_packet_data(self):
        """Test packet data sanitization."""
        # Test normal data
        self.assertEqual(sanitize_packet_data("Hello World"), "Hello World")
        
        # Test data with control characters
        self.assertEqual(sanitize_packet_data("Hello\x00World"), "Hello?World")
        self.assertEqual(sanitize_packet_data("Hello\r\nWorld"), "Hello\r\nWorld")
        
        # Test empty data
        self.assertEqual(sanitize_packet_data(""), "")

    def test_save_to_file(self):
        """Test file saving functionality."""
        import tempfile
        import os
        
        test_data = "Test data content"
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_filename = temp_file.name
        
        try:
            save_to_file(test_data, temp_filename)
            
            # Verify file was created and contains correct data
            self.assertTrue(os.path.exists(temp_filename))
            
            with open(temp_filename, 'r') as f:
                content = f.read()
            
            self.assertEqual(content, test_data)
            
        finally:
            if os.path.exists(temp_filename):
                os.unlink(temp_filename)

    def test_format_time_edge_cases(self):
        """Test time formatting edge cases."""
        # Test very large timestamp
        large_time = 9999999999.0
        formatted = format_time(large_time)
        self.assertIsInstance(formatted, str)
        
        # Test zero timestamp
        formatted = format_time(0)
        self.assertIsInstance(formatted, str)


if __name__ == '__main__':
    unittest.main()
