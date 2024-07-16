import dpkt

import hash
import socket

class Packet:
    def __init__(self, timestamp, packet):
        self.flow_hash = 0
        self.timestamp = timestamp
        self.length = len(packet)
        self.ip_src = 0
        self.ip_dst = 0
        self.proto = 0
        self.tp_src = 0
        self.tp_dst = 0
        self.tp_flags = 0
        self.ingested = False

        try:
            # Read packet into dpkt to parse headers:
            eth = dpkt.ethernet.Ethernet(packet)
        except:
            print("failed to unpack packet, skipping...")
            return

        ip = eth.data

        # Get the length of IPv4 packet:
        if isinstance(eth.data, dpkt.ip.IP):
            self.length = ip.len
        # Get the length of IPv6 packet:
        elif isinstance(eth.data, dpkt.ip6.IP6):
            self.length = len(ip.data)
        else:
            return
            # Ignore if non-IP packet:

        # convert IP addresses from binary do decimal format
        try:
            self.ip_src = socket.inet_ntop(socket.AF_INET, ip.src)
            self.ip_dst = socket.inet_ntop(socket.AF_INET, ip.dst)
        except ValueError:
            self.ip_src = socket.inet_ntop(socket.AF_INET6, ip.src)
            self.ip_dst = socket.inet_ntop(socket.AF_INET6, ip.dst)

        self.proto = ip.p
        if ip.p == 6:
            # TCP
            tcp = ip.data
            self.tp_src = tcp.sport
            self.tp_dst = tcp.dport
            self.tp_flags = tcp.flags
        elif ip.p == 17:
            # UDP
            udp = ip.data
            self.tp_src = udp.sport
            self.tp_dst = udp.dport
            self.tp_flags = ""
        else:
            pass

        if self.proto == 6 or self.proto == 17:
            self.flow_hash = hash.hash_b5((self.ip_src, self.ip_dst, self.proto, self.tp_src, self.tp_dst))
        else:
            self.flow_hash = hash.hash_b3((self.ip_src, self.ip_dst, self.proto))

        self.ingested = True

    @staticmethod
    def has_fin_flag(flags):
        return flags & dpkt.tcp.TH_FIN != 0

    @staticmethod
    def has_syn_flag(flags):
        return flags & dpkt.tcp.TH_SYN != 0

    @staticmethod
    def has_rst_flag(flags):
        return flags & dpkt.tcp.TH_RST != 0
    
    @staticmethod
    def has_syn_ack_flag(flags):
        return Packet.has_syn_flag(flags) and Packet.has_ack_flag(flags)

    @staticmethod
    def has_ack_flag(flags):
        return flags & dpkt.tcp.TH_ACK != 0

    @staticmethod
    def _has_3way_connection(all_flags):
        if len(all_flags) < 3:
            return False
        # check 'all_flags' array and find 3 consecutive packet that has SYN, SYN_ACK, ACK flag
        for i in range(len(all_flags) - 2):
            if Packet.has_syn_flag(all_flags[i]) and Packet.has_syn_ack_flag(all_flags[i]) and \
            Packet.has_ack_flag(all_flags[i]):
                return True;
        return False;