import socket
import struct
from ctypes import *
import binascii as bin_to_hex
from datetime import datetime
import sys

class Eth_Header(): 

    global dest, src, eth_type

    def __init__(self, packet_buffer):
        dest, src, eth_type = struct.unpack("!6s6s2s", packet_buffer)
        self.source_mac = self.binary_to_ascii(src)
        self.destination_mac = self.binary_to_ascii(dest)
        self.ether_type = (bin_to_hex.hexlify(eth_type)).decode()

    def binary_to_ascii(self, header_field):
        raw_dst_mac = (bin_to_hex.hexlify(header_field)).decode('utf-8')
        return ":".join([raw_dst_mac[x:x+2] for x in range(0, len(raw_dst_mac), 2)])


class IP_Header(Structure):
    _fields_ = [
        ("version", c_ubyte, 4),
        ("ihl", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32)
        ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # map protocol constants to their names
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))

        #human readable protocol
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)


class ARP_Header():

    global arp_data

    def __init__(self, frame_buffer):
        arp_data = struct.unpack("!2s2s1s1s2s6s4s6s4s", frame_buffer)
        self.target_ip = socket.inet_ntoa(arp_data[8])
        self.sender_ip = socket.inet_ntoa(arp_data[6])
        self.op_code = (arp_data[4].hex())
        self.sender_mac = self.binary_to_ascii(arp_data[5])

    def binary_to_ascii(self, header_field):
        raw_dst_mac = (bin_to_hex.hexlify(header_field)).decode('utf-8')
        return ":".join([raw_dst_mac[x:x+2] for x in range(0, len(raw_dst_mac), 2)])

def get_protocol_name(hex_val):
    common_eth_list = {'0800':'IP', '0806':'ARP', '86dd':'IPv6' }
    return (common_eth_list[hex_val])

def get_hostname_from_ip(ip_addr):
    try:
        return socket.gethostbyaddr(ip_addr)[0]
    except socket.herror as  error:
        return "Domain Name Not Found!"

class TCP_Header():
    tcp_raw_data = ""

    def __init__(self, packet_buffer):
        tcp_raw_data = struct.unpack("!2s2s4s4s2s2s2s2s", packet_buffer)
        self.src_port = self.binary_to_ascii(tcp_raw_data[0])
        self.dst_port = self.binary_to_ascii(tcp_raw_data[1])

    def binary_to_ascii(self, binary_data):
        return ((bin_to_hex.hexlify(binary_data)).decode("utf-8"))

class UDP_Header():
    udp_raw_data = ""

    def __init__(self, packet_buffer):
        udp_raw_data = struct.unpack("!2s2s2s2s", packet_buffer)
        self.src_port = self.binary_to_ascii(udp_raw_data[0])
        self.dst_port = self.binary_to_ascii(udp_raw_data[1])

    def binary_to_ascii(self, binary_data):
        return ((bin_to_hex.hexlify(binary_data)).decode("utf-8"))

class ICMP_Header():
    icmp_data = ""

    def __init__(self, packet_buffer):
        icmp_data = struct.unpack("!1s1s2s", packet_buffer)
        self.icmp_type = self.binary_to_ascii(icmp_data[0])

    def binary_to_ascii(self, binary_data):
        return ((bin_to_hex.hexlify(binary_data)).decode("utf-8"))



#socket.htons(0x0003) for capture all the traffic(send & recv)
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
sock.bind(("ens33", 0))

#Initilize the importnant variables
timestamp = ""
protocol_name = ""
packet_data = ""

try:
    while True:
        frame = sock.recvfrom(65565)[0]
        eth_frame = Eth_Header(frame[:14])

        #Check the IP layer protocol(IPv4, IPv6)
        if(eth_frame.ether_type == "0800"):
            packet = IP_Header(frame[14:34])
            packet_data = f"{packet.src_address} -> {packet.dst_address}"
        
            #Check Transport Layer Protocol(TCP, UDP) | ICMP
            if(packet.protocol_num == 6):
                packet_data += " TCP"
                tcp_packet = TCP_Header(frame[34:54])
                packet_data += " SRC PORT " + str((int(tcp_packet.src_port, 16)))
                packet_data += " DST PORT " + str((int(tcp_packet.dst_port, 16)))

            elif(packet.protocol_num == 17):
                packet_data += " UDP"
                udp_packet = UDP_Header(frame[34:42])
                packet_data += " SRC PORT " + str((int(udp_packet.src_port, 16)))
                packet_data += " DST PORT " + str((int(udp_packet.dst_port, 16)))

            elif(packet.protocol_num == 1):
                packet_data += " ICMP"
                
                icmp_packet = ICMP_Header(frame[34:38])
                if(icmp_packet.icmp_type == "00"):
                    packet_data += " Echo Reply"
                elif(icmp_packet.icmp_type == "08"):
                    packet_data += " Echo Request"
        
        elif(eth_frame.ether_type == "0806"):
            data = ARP_Header(frame[14:42])
            if(data.op_code == "0001"):
                hostname = ''
                hostname = get_hostname_from_ip(data.sender_ip)
                packet_data = f"Request who-has {data.target_ip} tell {hostname}"
            elif(data.op_code == "0002"):
                packet_data = f"Reply {get_hostname_from_ip(data.sender_ip)[0]} is-at {data.sender_mac} "
        
        #Get Timestamp
        timestamp = str(datetime.now())[12:]
        protocol_name = get_protocol_name(eth_frame.ether_type)
        
        #Print the final output
        print(f"{timestamp}  {protocol_name} {packet_data} SRC MAC:{eth_frame.source_mac}  DST_MAC:{eth_frame.destination_mac}")

except KeyboardInterrupt as key_error:
    sys.exit()
