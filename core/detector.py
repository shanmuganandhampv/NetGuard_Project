from scapy.all import IP, TCP, Raw
from colorama import Fore, Style
import time

class IntrusionDetector:
    def __init__(self):
        self.syn_counter = {} 

    def analyze_packet(self, packet):
        alerts = []
        
        # 1. IP Layer Check
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # 2. TCP Layer Check (Port Scan Detection)
            if packet.haslayer(TCP):
                # Check for SYN flag (0x02). 'S' works in string representation usually, 
                # but checking the bit value 0x02 is safer.
                tcp_layer = packet[TCP]
                
                # Flag check: 'S' means SYN (Start Connection)
                if tcp_layer.flags == 0x02 or tcp_layer.flags == 'S':
                    self._detect_syn_scan(src_ip)
                
                # 3. Payload Check (Keyword Searching like Snort)
                if packet.haslayer(Raw):
                    try:
                        # CRITICAL FIX: Decode bytes to string, ignoring binary errors
                        # This turns b'user=admin' into "user=admin"
                        payload_bytes = packet[Raw].load
                        payload_str = payload_bytes.decode('utf-8', errors='ignore').lower()
                        
                        keywords = ["password", "user", "admin", "login", "pass="]
                        for key in keywords:
                            if key in payload_str:
                                alerts.append(f"CRITICAL: Clear text '{key}' found. Source: {src_ip} -> Dest: {dst_ip}")
                    except Exception:
                        # If payload is purely binary/encrypted, skip it
                        pass

        return alerts

    def _detect_syn_scan(self, src_ip):
        current_time = time.time()
        
        if src_ip not in self.syn_counter:
            self.syn_counter[src_ip] = []
            
        self.syn_counter[src_ip].append(current_time)
        
        # Keep timestamps only from the last 10 seconds (Sliding Window)
        self.syn_counter[src_ip] = [t for t in self.syn_counter[src_ip] if current_time - t < 10]
        
        # Threshold: > 15 SYNs in 10 seconds
        if len(self.syn_counter[src_ip]) > 15:
            print(f"{Fore.RED}[!] ALERT: Potential Port Scan detected from: {src_ip}{Style.RESET_ALL}")
            self.syn_counter[src_ip] = [] # Reset to avoid spam