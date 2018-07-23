import socket
import struct

MAC_ADDRESS_TEMPLATE = ":".join(['%.2x'] * 6)


def decode_mac_address(addr):
    return MAC_ADDRESS_TEMPLATE % tuple(addr)


class IPPacket(object):
    """
    A packet of data on an IP network comm
    """

    def __init__(self, data):
        """
        Parameters
        ----------
        data: bytes
            Binary packet to decode
        """
        self._src_ip_address = None
        self._src_ip_port = 0
        self._dst_ip_address = None
        self._dst_ip_port = 0
        self._ip_protocol = 0
        self.header_size = 0

        self._parse(data)

    def _parse(self, raw):
        ETHERNET_VLAN_LEN = 4
        ETHERNET_TYPE_LEN = 2
        ETHERNET_TYPE_FORMAT = '!H'
        ETHERNET_PROTOCOL_IPV4 = 0x0800

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

        self._src_mac_address = raw[6:12]
        self._dst_mac_address = raw[0:6]

        ethernet_header_len = 12  # two MAC addresses

        # skip all Ethernet VLAN tags (802.1q, 802.1ad)
        while True:
            data = raw[ethernet_header_len:ethernet_header_len + ETHERNET_TYPE_LEN]
            ethertype, = struct.unpack(ETHERNET_TYPE_FORMAT, data)
            if ethertype not in [0x8100, 0x88A8, 0x9100]:
                ethernet_header_len += ETHERNET_TYPE_LEN
                break
            ethernet_header_len += ETHERNET_VLAN_LEN

        self._ethernet_protocol = ethertype

        if self._ethernet_protocol != ETHERNET_PROTOCOL_IPV4:
            return

        ip_header = raw[ethernet_header_len:ethernet_header_len + IP_HEADER_LEN]
        iph = struct.unpack(IP_HEADER_FORMAT, ip_header)
        iph_length = (iph[0] & 0xF) * 4

        self._ip_protocol = iph[6]
        self._src_ip_address = iph[8]
        self._dst_ip_address = iph[9]

        if self._ip_protocol == IP_PROTOCOL_ICMP:
            self.header_size = ethernet_header_len + iph_length + ICMP_HEADER_LEN
        elif self._ip_protocol == IP_PROTOCOL_TCP:
            t = ethernet_header_len + iph_length
            tcp_header = raw[t:t + TCP_HEADER_LEN]
            tcph = struct.unpack(TCP_HEADER_FORMAT, tcp_header)

            self._src_ip_port = tcph[0]
            self._dst_ip_port = tcph[1]
            tcph_length = tcph[4] >> 4

            self.header_size = ethernet_header_len + iph_length + tcph_length * 4
        elif self._ip_protocol == IP_PROTOCOL_UDP:
            u = ethernet_header_len + iph_length
            udph_length = UDP_HEADER_LEN
            udp_header = raw[u:u + UDP_HEADER_LEN]
            udph = struct.unpack(UDP_HEADER_FORMAT, udp_header)

            self._src_ip_port = udph[0]
            self._dst_ip_port = udph[1]

            self.header_size = ethernet_header_len + iph_length + udph_length

    @property
    def source_mac_address(self):
        return decode_mac_address(self._src_mac_address)

    @property
    def destination_mac_address(self):
        return decode_mac_address(self._dst_mac_address)

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
        return socket.inet_ntoa(self._src_ip_address)

    @property
    def destination_ip_address(self):
        return socket.inet_ntoa(self._dst_ip_address)

    @property
    def source_ip_port(self):
        return self._src_ip_port

    @property
    def destination_ip_port(self):
        return self._dst_ip_port
