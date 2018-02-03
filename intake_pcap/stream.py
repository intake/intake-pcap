from collections import namedtuple, OrderedDict

import pandas as pd

import pcapy

from .packet import IPPacket


base_columns = ['time', 'src_host', 'src_port', 'dst_host', 'dst_port', 'protocol']
BasePacket = namedtuple('BasePacket', base_columns)
FullPacket = namedtuple('FullPacket', base_columns + ['payload'])


class PacketStream(object):
    def __init__(self, reader, protocol, payload):
        self._reader = reader
        self._payload = payload
        self.set_filter(protocol)

    @property
    def dtype(self):
        items = [
            ('time', 'datetime64[ns]'),
            ('src_host', 'category'),
            ('src_port', 'category'),
            ('dst_host', 'category'),
            ('dst_port', 'category'),
            ('protocol', 'category')]

        if self._payload:
            items.append(('payload', 'object'))

        return OrderedDict(items)

    def set_filter(self, protocol):
        """
        Filters all IP traffic except packets matching given protocol.

        Parameters:
            protocol : str
                Show only traffic for given IP protocol.

                Allowed values are icmp, icmp6, igmp, igrp, pim, ah,
                esp, vrrp, udp, and tcp. If None, all traffic is shown.
        """
        if protocol:
            self._bpf = "ip proto \{0} || (vlan && ip proto \{0})".format(protocol)
        else:
            self._bpf = "ip || (vlan && ip)"

    def to_dataframe(self, n=-1):
        packets = []

        def decode_ip_packet(header, data):
            seconds, fractional = header.getts()
            ts = pd.to_datetime(10**6 * seconds + fractional, unit='us')

            packet = IPPacket(data)

            if self._payload:
                return FullPacket(ts,
                                  packet.source_ip_address,
                                  packet.source_ip_port,
                                  packet.destination_ip_address,
                                  packet.destination_ip_port,
                                  packet.ip_protocol,
                                  packet.payload)

            return BasePacket(ts,
                              packet.source_ip_address,
                              packet.source_ip_port,
                              packet.destination_ip_address,
                              packet.destination_ip_port,
                              packet.ip_protocol)

        def decoder(header, data):
            packets.append(decode_ip_packet(header, data))

        self._reader.setfilter(self._bpf)
        self._reader.loop(n, decoder)

        columns = FullPacket._fields if self._payload else BasePacket._fields
        df = pd.DataFrame(packets, columns=columns)
        return df.astype(dtype=self.dtype)


class LiveStream(PacketStream):
    def __init__(self, interface, protocol=None, payload=False, max_packet=2**16, timeout=1000):
        """
        Parameters:
            interface : str
                Network interface from which to capture packets.
            protocol : str
                Exclude all other IP traffic except packets matching this
                protocol. If None, all traffic is shown.
            payload : bool
                Toggle whether to include packet data.
            max_packet : int
                Maximum allowed packet size.
            timeout: int
                Maximum time to wait for packets from interface.
        """
        reader = pcapy.open_live(interface, max_packet, 1, timeout)
        super(LiveStream, self).__init__(reader, protocol, payload)


class OfflineStream(PacketStream):
    def __init__(self, path, protocol=None, payload=False):
        """
        Parameters:
            path : str
                Absolute path to source file.
            protocol : str
                Exclude all other IP traffic except packets matching this
                protocol. If None, all traffic is shown.
            payload : bool
                Toggle whether to include packet data.
        """
        reader = pcapy.open_offline(path)
        super(OfflineStream, self).__init__(reader, protocol, payload)
