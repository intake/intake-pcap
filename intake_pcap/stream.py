from collections import namedtuple, OrderedDict

import pandas as pd
from cyberpandas import to_ipaddress

from .packet import IPPacket


base_columns = ['time', 'src_host', 'src_port', 'dst_host', 'dst_port', 'protocol']
BasePacket = namedtuple('BasePacket', base_columns)
FullPacket = namedtuple('FullPacket', base_columns + ['payload'])


class PacketStream(object):
    """A set of IP packets
    """

    def __init__(self, reader, protocol, payload):
        self._reader = reader
        self._payload = payload
        self.set_filter(protocol)

    @property
    def dtype(self):
        items = [
            ('time', 'datetime64[ns]'),
            ('src_host', 'ip'),
            ('src_port', 'u4'),
            ('dst_host', 'ip'),
            ('dst_port', 'u4'),
            ('protocol', 'str')]

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
            seconds, fractional = header.getts()  # fractional is in microseconds
            ts = seconds * 10**9 + fractional * 10**3  # convert to nanoseconds

            packet = IPPacket(data)

            if self._payload:
                return FullPacket(ts,
                                  packet.source_ip_address,
                                  packet.source_ip_port,
                                  packet.destination_ip_address,
                                  packet.destination_ip_port,
                                  packet.ip_protocol,
                                  data[packet.header_size:])

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

        # DataFrame.astype doesn't work with extension types (yet).
        # https://github.com/pandas-dev/pandas/issues/20557
        known_types = {k: v for k, v in self.dtype.items()
                       if k not in ('src_host', 'dst_host')}
        df = df.astype(known_types)
        df['src_host'] = to_ipaddress(df['src_host'])
        df['dst_host'] = to_ipaddress(df['dst_host'])
        return df


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
        import pcapy
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
        import pcapy
        reader = pcapy.open_offline(path)
        super(OfflineStream, self).__init__(reader, protocol, payload)
