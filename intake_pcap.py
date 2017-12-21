from collections import OrderedDict
from functools import partial
from glob import glob
import socket
import struct

from dask.delayed import delayed
import dask.dataframe as dd
import pandas as pd

from intake.source import base

import pcapy


class Plugin(base.Plugin):
    def __init__(self):
        super(Plugin, self).__init__(name='pcap', version='0.1', container='dataframe', partition_access=False)

    def open(self, urlpath, **kwargs):
        base_kwargs, source_kwargs = self.separate_base_kwargs(kwargs)
        return PCAPSource(urlpath=urlpath, pcap_kwargs=source_kwargs, metadata=base_kwargs['metadata'])


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


class PacketStream(object):
    def __init__(self, reader, protocol):
        self._reader = reader
        self.to_bpf(protocol)

    def to_bpf(self, protocol):
        if protocol:
            self._bpf = "ip proto \{}".format(protocol)
        else:
            self._bpf = "ip"

    def to_dataframe(self, n=-1, payload=False):
        packets = []

        def decode_ip_packet(header, data):
            seconds, fractional = header.getts()
            ts = pd.to_datetime(10**6 * seconds + fractional, unit='us')

            packet = IPPacket(data)

            items = [
                ('time', ts),
                ('src_host', packet.source_ip_address),
                ('src_port', packet.source_ip_port),
                ('dst_host', packet.destination_ip_address),
                ('dst_port', packet.destination_ip_port),
                ('protocol', packet.ip_protocol)]

            if payload:
                items.append(('payload', packet.payload))

            return dict(items)

        def decoder(header, data):
            packets.append(decode_ip_packet(header, data))

        self._reader.setfilter(self._bpf)
        self._reader.loop(n, decoder)

        items = [
            ('time', 'datetime64[ns]'),
            ('src_host', 'object'),
            ('src_port', 'object'),
            ('dst_host', 'object'),
            ('dst_port', 'object'),
            ('protocol', 'object')]

        if payload:
            items.append(('payload', 'object'))

        dtypes = OrderedDict(items)
        df = pd.DataFrame(packets, columns=dtypes.keys())
        return df.astype(dtype=dtypes)


class LiveStream(PacketStream):
    def __init__(self, interface, protocol=None, max_packet=2**16, timeout=1000):
        reader = pcapy.open_live(interface, max_packet, 1, timeout)
        super(LiveStream, self).__init__(reader, protocol)


class OfflineStream(PacketStream):
    def __init__(self, path, protocol=None):
        reader = pcapy.open_offline(path)
        super(OfflineStream, self).__init__(reader, protocol)


class PCAPSource(base.DataSource):
    def __init__(self, urlpath, pcap_kwargs, metadata):
        self._init_args = dict(pcap_kwargs=pcap_kwargs, metadata=metadata)

        if urlpath:
            self._live = False
        else:
            self._live = True

        self._urlpath = urlpath
        self._interface = None
        self._protocol = None
        self._payload = False

        if self._live:
            self._chunksize = 100
        else:
            self._chunksize = -1

        if 'interface' in pcap_kwargs:
            self._interface = pcap_kwargs['interface']
        if 'chunksize' in pcap_kwargs:
            self._chunksize = pcap_kwargs['chunksize']
        if 'protocol' in pcap_kwargs:
            self._protocol = pcap_kwargs['protocol']
        if 'payload' in pcap_kwargs:
            self._payload = pcap_kwargs['payload']

        self._pcap_kwargs = pcap_kwargs
        self._dataframe = None

        super(PCAPSource, self).__init__(container='dataframe', metadata=metadata)

    def _get_dataframe(self):
        if self._dataframe is None:
            def _read_stream(filename, cls):
                return cls(filename, self._protocol).to_dataframe(n=self._chunksize, payload=self._payload)

            if self._live:
                reader = partial(_read_stream, cls=LiveStream)
                dfs = [delayed(reader)(self._interface)]
            else:
                reader = partial(_read_stream, cls=OfflineStream)
                filenames = sorted(glob(self._urlpath))
                dfs = [delayed(reader)(filename) for filename in filenames]
            self._dataframe = dd.from_delayed(dfs)

            dtypes = self._dataframe.dtypes
            self.datashape = None
            self.dtype = list(zip(dtypes.index, dtypes))
            self.shape = (len(self._dataframe),)
            self.npartitions = self._dataframe.npartitions

        return self._dataframe

    def discover(self):
        self._get_dataframe()
        return dict(datashape=self.datashape, dtype=self.dtype, shape=self.shape, npartitions=self.npartitions)

    def read(self):
        return self._get_dataframe().compute()

    def read_chunked(self):
        df = self._get_dataframe()

        for i in range(df.npartitions):
            yield df.get_partition(i).compute()

    def read_partition(self, i):
        df = self._get_dataframe()
        return df.get_partition(i).compute()

    def to_dask(self):
        return self._get_dataframe()

    def close(self):
        self._dataframe = None

    def __getstate__(self):
        return self._init_args

    def __setstate__(self, state):
        self.__init__(**state)
