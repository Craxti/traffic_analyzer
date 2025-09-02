#!/usr/bin/env python3
"""
Automatic Npcap installation for traffic analyzer
"""

import os
import sys
import subprocess
import urllib.request
import zipfile
import tempfile
import shutil
import logging
from pathlib import Path

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s]: %(message)s'
)

class NpcapInstaller:
    """Class for Npcap installation"""
    
    def __init__(self):
        self.npcap_version = "1.79"
        self.npcap_url = f"https://github.com/nmap/npcap/releases/download/v{self.npcap_version}/npcap-{self.npcap_version}-oem.exe"
        self.temp_dir = tempfile.mkdtemp()
        self.installer_path = os.path.join(self.temp_dir, f"npcap-{self.npcap_version}-oem.exe")
        
    def check_admin_rights(self):
        """Check administrator rights"""
        try:
            return os.getuid() == 0
        except AttributeError:
            # Windows
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
    
    def download_npcap(self):
        """Download Npcap installer"""
        print(f"📥 Downloading Npcap version {self.npcap_version}...")
        
        try:
            urllib.request.urlretrieve(self.npcap_url, self.installer_path)
            print(f"✅ Npcap downloaded: {self.installer_path}")
            return True
        except Exception as e:
            print(f"❌ Error downloading Npcap: {e}")
            return False
    
    def install_npcap(self):
        """Install Npcap"""
        print("🔧 Installing Npcap...")
        
        try:
            # Command for silent Npcap installation
            cmd = [
                self.installer_path,
                "/S",  # Silent installation
                "/NPCAP=1",  # Install Npcap
                "/NPCAP_OPTIONS=0",  # Basic options
                "/WINPCAP=0",  # Don't install WinPcap
                "/DLL=1",  # Install DLL
                "/LOOPBACK=1",  # Enable loopback
                "/ADMIN=1"  # Require administrator rights
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Npcap successfully installed!")
                return True
            else:
                print(f"❌ Error installing Npcap: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Installation error: {e}")
            return False
    
    def verify_installation(self):
        """Verify Npcap installation"""
        print("🔍 Verifying installation...")
        
        # Check for Npcap files
        npcap_paths = [
            r"C:\Program Files\Npcap",
            r"C:\Program Files (x86)\Npcap"
        ]
        
        for path in npcap_paths:
            if os.path.exists(path):
                print(f"✅ Npcap found in: {path}")
                return True
        
        print("❌ Npcap not found in standard folders")
        return False
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            shutil.rmtree(self.temp_dir)
            print("🧹 Temporary files removed")
        except Exception as e:
            print(f"⚠️ Failed to remove temporary files: {e}")
    
    def install(self):
        """Main installation method"""
        print("🚀 Installing Npcap for traffic analyzer")
        print("=" * 50)
        
        # Check administrator rights
        if not self.check_admin_rights():
            print("❌ Administrator rights required!")
            print("Run the script as administrator")
            return False
        
        # Download Npcap
        if not self.download_npcap():
            return False
        
        # Install Npcap
        if not self.install_npcap():
            return False
        
        # Verify installation
        if not self.verify_installation():
            return False
        
        # Clean up temporary files
        self.cleanup()
        
        print("\n🎉 Npcap installation completed successfully!")
        print("You can now use traffic capture")
        return True

def main():
    """Main function"""
    installer = NpcapInstaller()
    
    try:
        success = installer.install()
        if success:
            print("\n✅ Npcap ready to use!")
            print("Restart the traffic analyzer to apply changes")
        else:
            print("\n❌ Installation failed")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n⚠️ Installation interrupted by user")
        installer.cleanup()
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        installer.cleanup()
        sys.exit(1)

if __name__ == "__main__":
    main()
