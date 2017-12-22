import socket
import struct


class IPPacket(object):
    def __init__(self, data):
        self._decode(data)

    def _decode(self, raw):
        ETHERNET_HEADER_LEN = 14
        ETHERNET_HEADER_FORMAT = '!6s6sH'
        ETHERNET_PROTOCOL_IPV4 = 8

        IP_HEADER_LEN = 20
        IP_HEADER_FORMAT = '!BBHHHBBH4s4s'
        IP_PROTOCOL_ICMP = 1
        IP_PROTOCOL_IGMP = 2
        IP_PROTOCOL_TCP = 6
        IP_PROTOCOL_UDP = 17

        ICMP_HEADER_LEN = 4

        TCP_HEADER_LEN = 20
        TCP_HEADER_FORMAT = '!HHLLBBHHH'

        UDP_HEADER_LEN = 8
        UDP_HEADER_FORMAT = '!HHHH'

        def decode_mac_address(addr):
            return ":".join(["%.2x".format(chunk) for chunk in addr])

        self._src_mac_address = decode_mac_address(raw[6:12])
        self._src_ip_address = None
        self._src_ip_port = None

        self._dst_mac_address = decode_mac_address(raw[0:6])
        self._dst_ip_address = None
        self._dst_ip_port = None

        ethnet_header = raw[:ETHERNET_HEADER_LEN]
        ethnet = struct.unpack(ETHERNET_HEADER_FORMAT, ethnet_header)

        self._ethernet_protocol = socket.ntohs(ethnet[2])
        self._ip_protocol = None
        self._payload = None

        if self._ethernet_protocol != ETHERNET_PROTOCOL_IPV4:
            return

        ip_header = raw[ETHERNET_HEADER_LEN:ETHERNET_HEADER_LEN + IP_HEADER_LEN]
        iph = struct.unpack(IP_HEADER_FORMAT, ip_header)
        iph_length = (iph[0] & 0xF) * 4

        self._ip_protocol = iph[6]
        self._src_ip_address = socket.inet_ntoa(iph[8])
        self._dst_ip_address = socket.inet_ntoa(iph[9])

        if self._ip_protocol == IP_PROTOCOL_ICMP:
            u = ETHERNET_HEADER_LEN + iph_length
            icmp_header = raw[u:u + ICMP_HEADER_LEN]

            h_size = ETHERNET_HEADER_LEN + iph_length + ICMP_HEADER_LEN
            self._payload = raw[h_size:]
        elif self._ip_protocol == IP_PROTOCOL_TCP:
            t = ETHERNET_HEADER_LEN + iph_length
            tcp_header = raw[t:t + TCP_HEADER_LEN]
            tcph = struct.unpack(TCP_HEADER_FORMAT, tcp_header)

            self._src_ip_port = tcph[0]
            self._dst_ip_port = tcph[1]
            tcph_length = tcph[4] >> 4

            h_size = ETHERNET_HEADER_LEN + iph_length + tcph_length * 4
            self._payload = raw[h_size:]
        elif self._ip_protocol == IP_PROTOCOL_UDP:
            u = ETHERNET_HEADER_LEN + iph_length
            udph_length = UDP_HEADER_LEN
            udp_header = raw[u:u + UDP_HEADER_LEN]
            udph = struct.unpack(UDP_HEADER_FORMAT, udp_header)

            self._src_ip_port = udph[0]
            self._dst_ip_port = udph[1]

            h_size = ETHERNET_HEADER_LEN + iph_length + udph_length
            self._payload = raw[h_size:]

    @property
    def source_mac_address(self):
        return self._src_mac_address

    @property
    def destination_mac_address(self):
        return self._dst_mac_address

    @property
    def ethernet_protocol(self):
        protocols = {0x0008: 'ipv4', 0x0608: 'arp', 0xDD86: 'ipv6'}
        return protocols[self._ethernet_protocol] if self._ethernet_protocol in protocols else None

    @property
    def ip_protocol(self):
        protocols = {1: 'icmp', 2: 'igmp', 6: 'tcp', 17: 'udp'}
        return protocols[self._ip_protocol] if self._ip_protocol in protocols else None

    @property
    def source_ip_address(self):
        return self._src_ip_address

    @property
    def destination_ip_address(self):
        return self._dst_ip_address

    @property
    def source_ip_port(self):
        return self._src_ip_port

    @property
    def destination_ip_port(self):
        return self._dst_ip_port

    @property
    def payload(self):
        return self._payload
