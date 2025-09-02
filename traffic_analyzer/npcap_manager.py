"""
Npcap management module for traffic analyzer
"""

import os
import sys
import subprocess
import logging
import platform
from pathlib import Path

logger = logging.getLogger(__name__)

class NpcapManager:
    """Manager for working with Npcap"""
    
    def __init__(self):
        self.npcap_paths = [
            r"C:\Program Files\Npcap",
            r"C:\Program Files (x86)\Npcap"
        ]
        self.winpcap_paths = [
            r"C:\Program Files\Wireshark\WinPcap",
            r"C:\Program Files (x86)\Wireshark\WinPcap"
        ]
    
    def is_windows(self):
        """Check if system is Windows"""
        return platform.system().lower() == "windows"
    
    def check_npcap_installed(self):
        """Check Npcap installation"""
        if not self.is_windows():
            logger.info("Npcap not required on this platform")
            return True
        
        for path in self.npcap_paths:
            if os.path.exists(path):
                logger.info(f"Npcap found in: {path}")
                return True
        
        for path in self.winpcap_paths:
            if os.path.exists(path):
                logger.info(f"WinPcap found in: {path}")
                return True
        
        logger.warning("Npcap/WinPcap not found")
        return False
    
    def check_admin_rights(self):
        """Check administrator rights"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def get_installer_path(self):
        """Get Npcap installer path"""
        # Check if installer exists in project folder
        project_dir = Path(__file__).parent.parent
        installer_path = project_dir / "tools" / "npcap-installer.exe"
        
        if installer_path.exists():
            return str(installer_path)
        
        return None
    
    def download_npcap_installer(self, target_path):
        """Download Npcap installer"""
        try:
            import urllib.request
            
            npcap_version = "1.79"
            npcap_url = f"https://github.com/nmap/npcap/releases/download/v{npcap_version}/npcap-{npcap_version}-oem.exe"
            
            logger.info(f"Downloading Npcap version {npcap_version}...")
            urllib.request.urlretrieve(npcap_url, target_path)
            
            return True
        except Exception as e:
            logger.error(f"Error downloading Npcap: {e}")
            return False
    
    def install_npcap(self, installer_path):
        """Install Npcap"""
        try:
            logger.info("Installing Npcap...")
            
            cmd = [
                installer_path,
                "/S",  # Silent installation
                "/NPCAP=1",
                "/NPCAP_OPTIONS=0",
                "/WINPCAP=0",
                "/DLL=1",
                "/LOOPBACK=1",
                "/ADMIN=1"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("Npcap successfully installed")
                return True
            else:
                logger.error(f"Error installing Npcap: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Installation error: {e}")
            return False
    
    def setup_npcap(self):
        """Setup Npcap"""
        if not self.is_windows():
            logger.info("Npcap not required on this platform")
            return True
        
        # Check if Npcap is already installed
        if self.check_npcap_installed():
            logger.info("Npcap already installed")
            return True
        
        # Check administrator rights
        if not self.check_admin_rights():
            logger.error("Administrator rights required to install Npcap")
            return False
        
        # Get installer path
        installer_path = self.get_installer_path()
        
        if not installer_path or not os.path.exists(installer_path):
            # Create tools folder and download installer
            tools_dir = Path(__file__).parent.parent / "tools"
            tools_dir.mkdir(exist_ok=True)
            
            installer_path = tools_dir / "npcap-installer.exe"
            
            if not self.download_npcap_installer(str(installer_path)):
                return False
        
        # Install Npcap
        if not self.install_npcap(str(installer_path)):
            return False
        
        # Verify installation
        if not self.check_npcap_installed():
            logger.error("Npcap was not installed correctly")
            return False
        
        logger.info("Npcap successfully configured")
        return True
    
    def get_interface_list(self):
        """Get list of network interfaces"""
        try:
            import psutil
            return list(psutil.net_if_addrs().keys())
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            return []
    
    def test_capture_capability(self, interface="Ethernet"):
        """Test traffic capture capability"""
        try:
            from scapy.all import sniff
            
            # Try to capture one packet
            packets = sniff(iface=interface, count=1, timeout=1)
            
            if packets:
                logger.info("Traffic capture working correctly")
                return True
            else:
                logger.warning("Failed to capture packets")
                return False
                
        except Exception as e:
            logger.error(f"Error testing capture: {e}")
            return False

def ensure_npcap_available():
    """Function to ensure Npcap availability"""
    manager = NpcapManager()
    
    if not manager.setup_npcap():
        logger.error("Failed to configure Npcap")
        return False
    
    return True

def check_capture_ready():
    """Check readiness for traffic capture"""
    manager = NpcapManager()
    
    if not manager.is_windows():
        return True
    
    if not manager.check_npcap_installed():
        logger.warning("Npcap not installed. Traffic capture may not work.")
        return False
    
    return True
