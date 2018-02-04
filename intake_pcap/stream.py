from collections import OrderedDict

import pandas as pd

import pcapy

from .packet import IPPacket


class PacketStream(object):
    def __init__(self, reader, protocol, payload):
        self._reader = reader
        self._payload = payload
        self.set_filter(protocol)

    @property
    def dtype(self):
        items = [
            ('time', 'datetime64[ns]'),
            ('src_host', 'object'),
            ('src_port', 'object'),
            ('dst_host', 'object'),
            ('dst_port', 'object'),
            ('protocol', 'object')]

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

            items = [
                ('time', ts),
                ('src_host', packet.source_ip_address),
                ('src_port', packet.source_ip_port),
                ('dst_host', packet.destination_ip_address),
                ('dst_port', packet.destination_ip_port),
                ('protocol', packet.ip_protocol)]

            if self._payload:
                items.append(('payload', packet.payload))

            return dict(items)

        def decoder(header, data):
            packets.append(decode_ip_packet(header, data))

        self._reader.setfilter(self._bpf)
        self._reader.loop(n, decoder)

        df = pd.DataFrame(packets, columns=self.dtype.keys())
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
