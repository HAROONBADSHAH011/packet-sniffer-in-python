#!/usr/bin/env python3
"""
Network Sniffer - Raw Packet Capture & Analysis Tool
Requires root/administrator privileges to run.
"""

import socket
import struct
import textwrap
import time
import signal
import sys
from datetime import datetime
from collections import defaultdict
from typing import Dict, Tuple, Optional

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class PacketSniffer:
    def __init__(self, interface: Optional[str] = None, pcap_file: Optional[str] = None):
        self.interface = interface
        self.pcap_file = pcap_file
        self.running = True
        self.stats = {
            'total': 0,
            'ethernet': 0,
            'ip': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'other': 0,
            'bytes': 0
        }
        self.start_time = time.time()
        self.pcap_handle = None
        
        # Setup raw socket
        try:
            # AF_PACKET with SOCK_RAW requires Linux; for cross-platform, use AF_INET with IPPROTO_IP
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            if self.interface:
                self.sock.bind((self.interface, 0))
        except (AttributeError, OSError):
            # Fallback for Windows/macOS (requires WinPcap/Npcap or root on macOS)
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                # Enable promiscuous mode on Windows
                if sys.platform == "win32":
                    self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            except Exception as e:
                print(f"{Colors.RED}Error: Could not create raw socket. Run as root/admin. {e}{Colors.ENDC}")
                sys.exit(1)
        
        if self.pcap_file:
            self._init_pcap()
        
        # Graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        
    def _init_pcap(self):
        """Write PCAP global header for Wireshark compatibility."""
        # PCAP magic number, version, timezone, sigfigs, snaplen, network (Ethernet)
        global_header = struct.pack('@IHHiIII', 
            0xa1b2c3d4,  # Magic number
            2, 4,        # Version
            0,           # Timezone
            0,           # Sigfigs
            65535,       # Snaplen
            1            # Link-type (Ethernet)
        )
        self.pcap_handle = open(self.pcap_file, 'wb')
        self.pcap_handle.write(global_header)
        
    def _write_pcap_packet(self, data: bytes):
        """Write packet to PCAP file with timestamp."""
        ts_sec, ts_usec = divmod(time.time(), 1)
        pkt_header = struct.pack('@IIII',
            int(ts_sec),
            int(ts_usec * 1000000),
            len(data),
            len(data)
        )
        self.pcap_handle.write(pkt_header + data)
        self.pcap_handle.flush()
        
    def _signal_handler(self, signum, frame):
        print(f"\n{Colors.YELLOW}Shutting down sniffer...{Colors.ENDC}")
        self.running = False
        if self.pcap_handle:
            self.pcap_handle.close()
        self._print_final_stats()
        sys.exit(0)
        
    def _mac_format(self, raw_bytes: bytes) -> str:
        """Convert 6 bytes to MAC address string."""
        return ':'.join(f'{b:02x}' for b in raw_bytes).upper()
        
    def _ipv4_format(self, raw_addr: bytes) -> str:
        """Convert 4 bytes to IPv4 dotted string."""
        return '.'.join(str(b) for b in raw_addr)
        
    def parse_ethernet(self, data: bytes) -> Tuple[Dict, bytes]:
        """Parse Ethernet II frame."""
        dest_mac, src_mac, eth_type = struct.unpack('!6s6sH', data[:14])
        return {
            'dest_mac': self._mac_format(dest_mac),
            'src_mac': self._mac_format(src_mac),
            'eth_type': eth_type,  # 0x0800 = IPv4, 0x0806 = ARP, etc.
            'eth_type_name': self._get_ethertype_name(eth_type)
        }, data[14:]
        
    def _get_ethertype_name(self, eth_type: int) -> str:
        """Map common EtherTypes to names."""
        types = {
            0x0800: 'IPv4',
            0x0806: 'ARP',
            0x0842: 'Wake-on-LAN',
            0x86DD: 'IPv6',
            0x8100: 'VLAN',
            0x8870: 'Jumbo Frames',
            0x8899: 'Realtek Protocol'
        }
        return types.get(eth_type, f'0x{eth_type:04x}')
        
    def parse_ipv4(self, data: bytes) -> Tuple[Dict, bytes]:
        """Parse IPv4 packet header."""
        version_ihl = data[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0xF) * 4
        
        tos, total_length, identification, flags_offset, ttl, protocol, checksum = \
            struct.unpack('!BBHHHBBH', data[1:12])
            
        src_ip = self._ipv4_format(data[12:16])
        dst_ip = self._ipv4_format(data[16:20])
        
        flags = (flags_offset >> 13) & 0x7
        fragment_offset = flags_offset & 0x1FFF
        
        return {
            'version': version,
            'header_len': ihl,
            'tos': tos,
            'total_length': total_length,
            'id': identification,
            'flags': {
                'reserved': bool(flags & 0x4),
                'dont_fragment': bool(flags & 0x2),
                'more_fragments': bool(flags & 0x1)
            },
            'fragment_offset': fragment_offset,
            'ttl': ttl,
            'protocol': protocol,
            'protocol_name': self._get_protocol_name(protocol),
            'checksum': checksum,
            'src_ip': src_ip,
            'dst_ip': dst_ip
        }, data[ihl:]
        
    def _get_protocol_name(self, proto: int) -> str:
        """Map IP protocol numbers to names."""
        protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            2: 'IGMP',
            41: 'IPv6 Encap',
            47: 'GRE',
            50: 'ESP',
            51: 'AH',
            89: 'OSPF',
            132: 'SCTP'
        }
        return protocols.get(proto, str(proto))
        
    def parse_tcp(self, data: bytes) -> Tuple[Dict, bytes]:
        """Parse TCP segment."""
        src_port, dst_port, seq, ack, offset_flags = struct.unpack('!HHIIH', data[:14])
        offset = (offset_flags >> 12) * 4
        flags = offset_flags & 0x3F
        
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        if flags & 0x40: flag_names.append('ECE')
        if flags & 0x80: flag_names.append('CWR')
        
        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'sequence': seq,
            'acknowledgment': ack,
            'data_offset': offset,
            'flags': flags,
            'flag_names': flag_names,
            'window': struct.unpack('!H', data[14:16])[0],
            'checksum': struct.unpack('!H', data[16:18])[0],
            'urgent': struct.unpack('!H', data[18:20])[0]
        }, data[offset:]
        
    def parse_udp(self, data: bytes) -> Tuple[Dict, bytes]:
        """Parse UDP datagram."""
        src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])
        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'length': length,
            'checksum': checksum
        }, data[8:]
        
    def parse_icmp(self, data: bytes) -> Tuple[Dict, bytes]:
        """Parse ICMP packet."""
        icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
        return {
            'type': icmp_type,
            'type_name': self._get_icmp_type(icmp_type),
            'code': code,
            'checksum': checksum
        }, data[4:]
        
    def _get_icmp_type(self, icmp_type: int) -> str:
        """Map ICMP type numbers to names."""
        types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            5: 'Redirect',
            8: 'Echo Request',
            11: 'Time Exceeded',
            12: 'Parameter Problem',
            13: 'Timestamp Request',
            14: 'Timestamp Reply'
        }
        return types.get(icmp_type, f'Type {icmp_type}')
        
    def _format_flags(self, flag_names: list) -> str:
        """Format TCP flags with color."""
        if not flag_names:
            return ""
        color = Colors.GREEN if 'SYN' in flag_names or 'ACK' in flag_names else \
                Colors.RED if 'RST' in flag_names else Colors.YELLOW
        return f"{color}[{' '.join(flag_names)}]{Colors.ENDC}"
        
    def _print_packet(self, eth: Dict, ip: Optional[Dict], transport: Optional[Dict], 
                      payload: bytes, raw_data: bytes):
        """Print formatted packet information."""
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        
        print(f"\n{Colors.BOLD}{Colors.HEADER}[{timestamp}] Packet #{self.stats['total']}{Colors.ENDC}")
        print(f"{Colors.CYAN}  Ethernet:{Colors.ENDC} {eth['src_mac']} -> {eth['dest_mac']} | {eth['eth_type_name']}")
        
        if ip:
            print(f"{Colors.CYAN}  IPv4:{Colors.ENDC} {ip['src_ip']} -> {ip['dst_ip']} | "
                  f"TTL={ip['ttl']} | Proto={ip['protocol_name']} | "
                  f"Len={ip['total_length']} | ID=0x{ip['id']:04x}")
            
            if transport:
                if ip['protocol'] == 6:  # TCP
                    flags = self._format_flags(transport['flag_names'])
                    print(f"{Colors.CYAN}  TCP:{Colors.ENDC}  Port {transport['src_port']} -> {transport['dst_port']} | "
                          f"Seq={transport['sequence']} | Ack={transport['acknowledgment']} | "
                          f"Win={transport['window']} {flags}")
                elif ip['protocol'] == 17:  # UDP
                    print(f"{Colors.CYAN}  UDP:{Colors.ENDC}  Port {transport['src_port']} -> {transport['dst_port']} | "
                          f"Len={transport['length']}")
                elif ip['protocol'] == 1:  # ICMP
                    print(f"{Colors.CYAN}  ICMP:{Colors.ENDC} Type={transport['type_name']}({transport['type']}) | "
                          f"Code={transport['code']}")
            
            # Payload preview (first 64 bytes)
            if payload:
                hex_str = ' '.join(f'{b:02x}' for b in payload[:32])
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload[:32])
                print(f"{Colors.YELLOW}  Payload:{Colors.ENDC} {hex_str}")
                print(f"{Colors.YELLOW}  ASCII:{Colors.ENDC}   {ascii_str}")
                
    def _print_live_stats(self):
        """Print running statistics line."""
        elapsed = time.time() - self.start_time
        rate = self.stats['total'] / elapsed if elapsed > 0 else 0
        bw = (self.stats['bytes'] / elapsed / 1024) if elapsed > 0 else 0
        
        line = (f"\r{Colors.BOLD}Stats:{Colors.ENDC} "
                f"{Colors.GREEN}IP:{self.stats['ip']}{Colors.ENDC} | "
                f"{Colors.BLUE}TCP:{self.stats['tcp']}{Colors.ENDC} | "
                f"{Colors.CYAN}UDP:{self.stats['udp']}{Colors.ENDC} | "
                f"{Colors.YELLOW}ICMP:{self.stats['icmp']}{Colors.ENDC} | "
                f"{Colors.RED}Other:{self.stats['other']}{Colors.ENDC} | "
                f"Total:{self.stats['total']} | "
                f"Rate:{rate:.1f} pkt/s | "
                f"BW:{bw:.1f} KB/s")
        print(line, end='', flush=True)
        
    def _print_final_stats(self):
        """Print final summary statistics."""
        elapsed = time.time() - self.start_time
        print(f"\n\n{Colors.BOLD}{Colors.HEADER}=== Capture Summary ==={Colors.ENDC}")
        print(f"Duration: {elapsed:.2f} seconds")
        print(f"Total Packets: {self.stats['total']}")
        print(f"Total Bytes: {self.stats['bytes']:,}")
        print(f"Average Rate: {self.stats['total']/elapsed:.1f} packets/sec")
        print(f"\nProtocol Breakdown:")
        print(f"  IPv4:     {self.stats['ip']}")
        print(f"  TCP:      {self.stats['tcp']}")
        print(f"  UDP:      {self.stats['udp']}")
        print(f"  ICMP:     {self.stats['icmp']}")
        print(f"  Other:    {self.stats['other']}")
        if self.pcap_file:
            print(f"\nSaved to: {self.pcap_file}")
            
    def capture(self, count: int = 0, filter_protocol: Optional[str] = None, 
                verbose: bool = True):
        """
        Main capture loop.
        
        Args:
            count: Number of packets to capture (0 = infinite)
            filter_protocol: Filter by protocol name ('TCP', 'UDP', 'ICMP', etc.)
            verbose: Print packet details
        """
        print(f"{Colors.GREEN}Starting packet capture...{Colors.ENDC}")
        print(f"{Colors.YELLOW}Press Ctrl+C to stop{Colors.ENDC}\n")
        
        while self.running:
            try:
                raw_data, addr = self.sock.recvfrom(65535)
                self.stats['total'] += 1
                self.stats['bytes'] += len(raw_data)
                
                if self.pcap_handle:
                    self._write_pcap_packet(raw_data)
                
                # Parse Ethernet
                eth, eth_payload = self.parse_ethernet(raw_data)
                self.stats['ethernet'] += 1
                
                ip = None
                transport = None
                payload = b''
                
                # Parse IPv4
                if eth['eth_type'] == 0x0800 and len(eth_payload) >= 20:
                    ip, ip_payload = self.parse_ipv4(eth_payload)
                    self.stats['ip'] += 1
                    
                    # Parse Transport Layer
                    if ip['protocol'] == 6 and len(ip_payload) >= 20:  # TCP
                        transport, payload = self.parse_tcp(ip_payload)
                        self.stats['tcp'] += 1
                    elif ip['protocol'] == 17 and len(ip_payload) >= 8:  # UDP
                        transport, payload = self.parse_udp(ip_payload)
                        self.stats['udp'] += 1
                    elif ip['protocol'] == 1 and len(ip_payload) >= 4:  # ICMP
                        transport, payload = self.parse_icmp(ip_payload)
                        self.stats['icmp'] += 1
                    else:
                        payload = ip_payload
                        self.stats['other'] += 1
                else:
                    self.stats['other'] += 1
                
                # Apply protocol filter
                if filter_protocol:
                    current_proto = ip['protocol_name'] if ip else eth['eth_type_name']
                    if current_proto.upper() != filter_protocol.upper():
                        continue
                
                # Output
                if verbose:
                    self._print_packet(eth, ip, transport, payload, raw_data)
                else:
                    self._print_live_stats()
                    
                # Stop if count reached
                if count > 0 and self.stats['total'] >= count:
                    break
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"\n{Colors.RED}Error: {e}{Colors.ENDC}")
                    
        self._signal_handler(None, None)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Python Network Sniffer')
    parser.add_argument('-i', '--interface', help='Network interface to sniff on')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0=unlimited)')
    parser.add_argument('-f', '--filter', help='Filter by protocol (TCP, UDP, ICMP, IPv4)')
    parser.add_argument('-w', '--write', help='Write captured packets to PCAP file')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (only statistics)')
    args = parser.parse_args()
    
    sniffer = PacketSniffer(interface=args.interface, pcap_file=args.write)
    sniffer.capture(count=args.count, filter_protocol=args.filter, verbose=not args.quiet)


if __name__ == '__main__':
    main()
