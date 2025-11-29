import sys
import os
import ctypes
from colorama import init
from core.sniffer import PacketSniffer

# Initialize Colorama
init()

def is_admin():
    """Checks if the script is running with Administrator/Root privileges."""
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def main():
    if not is_admin():
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("CRITICAL: ADMINISTRATOR PRIVILEGES REQUIRED")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("Network sniffing requires access to the network card driver.")
        print("1. Windows: Close this, Right-click Command Prompt -> 'Run as Administrator'")
        print("2. Linux/Mac: Run 'sudo python main.py'")
        input("\nPress Enter to exit...")
        sys.exit(1)

    print("\n=== NetGuard Lite: Traffic Analysis Tool ===")
    
    try:
        val = input("Enter number of packets to capture (Default 50): ")
        count = int(val) if val.strip() else 50
        
        sniffer = PacketSniffer()
        sniffer.start_sniffing(packet_count=count)
        
    except KeyboardInterrupt:
        print("\n\n[!] Stopped by user.")
    except ValueError:
        print("\n[!] Invalid number entered.")

if __name__ == "__main__":
    main()