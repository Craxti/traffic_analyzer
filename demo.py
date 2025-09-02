#!/usr/bin/env python3
"""
Traffic analyzer capabilities demonstration
"""

import time
import json
from traffic_analyzer import analyze_traffic, analyze_app_layer, detect_attacks
from traffic_analyzer.capture import create_test_packets

def demo_basic_analysis():
    """Basic analysis demonstration"""
    print("🔍 BASIC ANALYSIS DEMONSTRATION")
    print("=" * 50)
    
    # Create test packets
    packets = create_test_packets()
    print(f"📦 Created test packets: {len(packets)}")
    
    # Analyze traffic
    results = analyze_traffic(packets)
    
    print("\n📊 ANALYSIS RESULTS:")
    print(f"   Total packets: {results.get('total_packets', 0)}")
    print(f"   TCP packets: {results.get('tcp_packets', 0)}")
    print(f"   UDP packets: {results.get('udp_packets', 0)}")
    print(f"   HTTP packets: {results.get('http_packets', 0)}")
    print(f"   HTTPS packets: {results.get('https_packets', 0)}")

def demo_app_layer_analysis():
    """Application layer analysis demonstration"""
    print("\n🌐 APPLICATION LAYER ANALYSIS DEMONSTRATION")
    print("=" * 50)
    
    packets = create_test_packets()
    
    try:
        app_results = analyze_app_layer(packets)
        if app_results:
            print("📋 APPLICATION LAYER ANALYSIS RESULTS:")
            print(f"   HTTP requests: {len(app_results.get('http_requests', []))}")
            print(f"   DNS queries: {len(app_results.get('dns_queries', []))}")
            print(f"   TLS connections: {len(app_results.get('tls_connections', []))}")
            
            # Show HTTP request details
            http_requests = app_results.get('http_requests', [])
            if http_requests:
                print("\n📄 HTTP REQUESTS:")
                for i, req in enumerate(http_requests[:3], 1):
                    print(f"   {i}. {req.get('method', 'N/A')} {req.get('url', 'N/A')}")
        else:
            print("   No application layer data")
    except Exception as e:
        print(f"   Error: {e}")

def demo_attack_detection():
    """Attack detection demonstration"""
    print("\n🛡️ ATTACK DETECTION DEMONSTRATION")
    print("=" * 50)
    
    packets = create_test_packets()
    
    try:
        attack_results = detect_attacks(packets)
        if attack_results:
            print("🚨 ATTACK SEARCH RESULTS:")
            for attack_type, count in attack_results.items():
                if count > 0:
                    print(f"   ⚠️ {attack_type}: {count}")
                else:
                    print(f"   ✅ {attack_type}: not detected")
        else:
            print("   No attacks detected")
    except Exception as e:
        print(f"   Error: {e}")

def demo_website_testing():
    """Website testing demonstration"""
    print("\n🌍 WEBSITE TESTING DEMONSTRATION")
    print("=" * 50)
    
    import requests
    
    test_sites = [
        "http://httpbin.org/get",
        "https://httpbin.org/get",
        "http://example.com"
    ]
    
    for site in test_sites:
        try:
            print(f"\n🔗 Testing: {site}")
            response = requests.get(site, timeout=5)
            print(f"   ✅ Status: {response.status_code}")
            print(f"   📏 Size: {len(response.content)} bytes")
            print(f"   ⏱️  Protocol: {site.split(':')[0].upper()}")
        except Exception as e:
            print(f"   ❌ Error: {e}")

def demo_export_capabilities():
    """Export capabilities demonstration"""
    print("\n💾 EXPORT CAPABILITIES DEMONSTRATION")
    print("=" * 50)
    
    # Create test data
    test_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_packets": 5,
        "protocols": {
            "tcp": 3,
            "udp": 1,
            "http": 1,
            "https": 1
        },
        "security": {
            "attacks_detected": 0,
            "suspicious_ips": []
        }
    }
    
    # Save to JSON
    try:
        with open("demo_results.json", "w", encoding="utf-8") as f:
            json.dump(test_data, f, indent=2, ensure_ascii=False)
        print("✅ Results saved to demo_results.json")
    except Exception as e:
        print(f"❌ Save error: {e}")

def main():
    """Main demonstration function"""
    print("🚀 TRAFFIC ANALYZER DEMONSTRATION")
    print("=" * 60)
    print("This script demonstrates the main capabilities of the analyzer")
    print("=" * 60)
    
    # Demonstrations
    demo_basic_analysis()
    demo_app_layer_analysis()
    demo_attack_detection()
    demo_website_testing()
    demo_export_capabilities()
    
    print("\n" + "=" * 60)
    print("🎉 DEMONSTRATION COMPLETED!")
    print("=" * 60)
    print("\n📋 WHAT WAS DEMONSTRATED:")
    print("   ✅ Basic network traffic analysis")
    print("   ✅ Application layer analysis (HTTP, DNS, TLS)")
    print("   ✅ Attack detection and suspicious activity")
    print("   ✅ Real website connectivity testing")
    print("   ✅ Results export to JSON")
    
    print("\n🔧 FOR FULL TRAFFIC CAPTURE YOU NEED:")
    print("   1. Install Npcap (https://npcap.com/)")
    print("   2. Run with administrator rights")
    print("   3. Select the correct network interface")
    
    print("\n📚 ADDITIONAL INFORMATION:")
    print("   - Documentation: README.md")
    print("   - Tests: tests/")
    print("   - Examples: demo.py, test_websites.py")

if __name__ == "__main__":
    main()
