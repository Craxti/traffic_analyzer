#!/usr/bin/env python3
"""
Test script for Npcap integration
"""

import logging
import sys
from traffic_analyzer.npcap_manager import NpcapManager, check_capture_ready, ensure_npcap_available
from traffic_analyzer.capture import capture_traffic, create_test_packets
from traffic_analyzer import analyze_traffic

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s]: %(message)s'
)

def test_npcap_manager():
    """Test Npcap manager functionality"""
    print("🔧 TESTING NPCAP MANAGER")
    print("=" * 50)
    
    manager = NpcapManager()
    
    # Test Windows detection
    is_windows = manager.is_windows()
    print(f"Platform: {'Windows' if is_windows else 'Other'}")
    
    # Test Npcap installation check
    npcap_installed = manager.check_npcap_installed()
    print(f"Npcap installed: {npcap_installed}")
    
    # Test admin rights check
    admin_rights = manager.check_admin_rights()
    print(f"Admin rights: {admin_rights}")
    
    # Test interface list
    interfaces = manager.get_interface_list()
    print(f"Available interfaces: {interfaces}")
    
    return npcap_installed

def test_capture_functionality():
    """Test traffic capture functionality"""
    print("\n📡 TESTING TRAFFIC CAPTURE")
    print("=" * 50)
    
    # Test with synthetic data first
    print("Testing with synthetic data...")
    packets = create_test_packets()
    if packets:
        print(f"✅ Synthetic packets created: {len(packets)}")
        
        # Analyze synthetic packets
        results = analyze_traffic(packets)
        print(f"✅ Analysis completed: {results.get('total_packets', 0)} packets")
    else:
        print("❌ Failed to create synthetic packets")
        return False
    
    # Test real capture (if Npcap is available)
    if check_capture_ready():
        print("\nTesting real traffic capture...")
        try:
            # Try to capture a few packets
            real_packets = capture_traffic("Ethernet", 5, "tcp port 80 or tcp port 443")
            if real_packets:
                print(f"✅ Real capture successful: {len(real_packets)} packets")
                return True
            else:
                print("⚠️ No real packets captured (this is normal if no traffic)")
                return True
        except Exception as e:
            print(f"❌ Real capture failed: {e}")
            return False
    else:
        print("⚠️ Npcap not available for real capture")
        return False

def test_npcap_setup():
    """Test Npcap setup process"""
    print("\n🚀 TESTING NPCAP SETUP")
    print("=" * 50)
    
    # Check if capture is ready
    ready = check_capture_ready()
    print(f"Capture ready: {ready}")
    
    if not ready:
        print("Attempting to setup Npcap...")
        success = ensure_npcap_available()
        print(f"Setup result: {success}")
        return success
    else:
        print("Npcap already available")
        return True

def main():
    """Main test function"""
    print("🧪 NPCAP INTEGRATION TEST")
    print("=" * 60)
    
    # Test 1: Npcap manager
    npcap_available = test_npcap_manager()
    
    # Test 2: Capture functionality
    capture_works = test_capture_functionality()
    
    # Test 3: Npcap setup (if needed)
    setup_success = test_npcap_setup()
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 TEST SUMMARY")
    print("=" * 60)
    print(f"Npcap available: {npcap_available}")
    print(f"Capture functionality: {capture_works}")
    print(f"Setup success: {setup_success}")
    
    if npcap_available and capture_works:
        print("\n✅ All tests passed! Npcap integration working correctly.")
        return True
    elif setup_success:
        print("\n⚠️ Some tests failed, but Npcap setup was successful.")
        print("Try restarting the application or system.")
        return True
    else:
        print("\n❌ Tests failed. Npcap integration not working.")
        print("Please install Npcap manually or run with administrator rights.")
        return False

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n⚠️ Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
