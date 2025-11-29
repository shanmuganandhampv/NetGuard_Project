from scapy.all import sniff, wrpcap, conf
from .detector import IntrusionDetector
from colorama import Fore, Style
import os
import time
import sys

# Silence Scapy's own loading messages
conf.verb = 0

class PacketSniffer:
    def __init__(self, capture_dir="captures"):
        self.detector = IntrusionDetector()
        self.capture_dir = capture_dir
        self.packet_list = []
        
        if not os.path.exists(capture_dir):
            os.makedirs(capture_dir)

    def start_sniffing(self, packet_count=50):
        print(f"{Fore.CYAN}[*] Initializing Sniffer... Listening for {packet_count} packets.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Note: If this crashes immediately, check if Npcap is installed.{Style.RESET_ALL}")
        
        def process_packet(packet):
            self.packet_list.append(packet)
            
            # Analyze
            alerts = self.detector.analyze_packet(packet)
            
            # Display Alerts
            for alert in alerts:
                print(f"\n{Fore.RED}[ALERT] {alert}{Style.RESET_ALL}")
            
            # Heartbeat
            print(".", end="", flush=True)

        try:
            # iface=None lets Scapy pick the default interface.
            sniff(count=packet_count, prn=process_packet)
            
        except PermissionError:
            print(f"\n\n{Fore.RED}[CRITICAL ERROR] Access Denied.{Style.RESET_ALL}")
            print("You must run this script as Administrator (Windows) or 'sudo' (Linux).")
            sys.exit(1)
        except OSError as e:
            print(f"\n\n{Fore.RED}[CRITICAL ERROR] Network Interface Error.{Style.RESET_ALL}")
            print(f"Details: {e}")
            print("Windows Users: Ensure 'Npcap' is installed from https://npcap.com/")
            sys.exit(1)
        except Exception as e:
            print(f"\n\n{Fore.RED}[ERROR] Unknown error: {e}{Style.RESET_ALL}")
            sys.exit(1)

        self._save_capture()

    def _save_capture(self):
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"{self.capture_dir}/capture_{timestamp}.pcap"
        print(f"\n\n{Fore.GREEN}[+] Capture Complete.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Saving {len(self.packet_list)} packets to {filename}{Style.RESET_ALL}")
        
        try:
            wrpcap(filename, self.packet_list)
            print(f"{Fore.WHITE}--> File saved. Open in Wireshark.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to write PCAP file: {e}{Style.RESET_ALL}")