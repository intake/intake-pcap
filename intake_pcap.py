from collections import OrderedDict
from functools import partial
from glob import glob

from dask.delayed import delayed
import dask.dataframe as dd
import pandas as pd

from intake.source import base

from impacket.ImpactDecoder import EthDecoder
from impacket import ImpactPacket
import pcapy


class Plugin(base.Plugin):
    def __init__(self):
        super(Plugin, self).__init__(name='pcap', version='0.1', container='dataframe', partition_access=False)

    def open(self, urlpath, **kwargs):
        base_kwargs, source_kwargs = self.separate_base_kwargs(kwargs)
        return PCAPSource(urlpath=urlpath, pcap_kwargs=source_kwargs, metadata=base_kwargs['metadata'])


class PacketStream(object):
    def __init__(self, reader, protocol):
        self._reader = reader
        self.to_bpf(protocol)

    def to_bpf(self, protocol):
        if protocol:
            self._bpf = "ip proto \{}".format(protocol)
        else:
            self._bpf = "ip"

    @staticmethod
    def to_protocol(code):
        protocols = {
            ImpactPacket.ICMP.protocol: 'icmp',
            ImpactPacket.IGMP.protocol: 'igmp',
            ImpactPacket.TCP.protocol: 'tcp',
            ImpactPacket.UDP.protocol: 'udp'
            }

        return protocols[code] if code in protocols else None

    @staticmethod
    def decode_ip_payload(header, data):
        seconds, fractional = header.getts()
        ts = pd.to_datetime(10**6 * seconds + fractional, unit='us')

        p = EthDecoder().decode(data)
        ip = p.child()

        protocol = PacketStream.to_protocol(ip.get_ip_p())

        if protocol == "tcp":
            tcp = ip.child()
            src_port = tcp.get_th_sport()
            dst_port = tcp.get_th_dport()
        elif protocol == "udp":
            udp = ip.child()
            src_port = udp.get_uh_sport()
            dst_port = udp.get_uh_dport()
        else:
            src_port = None
            dst_port = None

        return dict(
            time=ts,
            src_host=ip.get_ip_src(),
            src_port=src_port,
            dst_host=ip.get_ip_dst(),
            dst_port=dst_port,
            protocol=protocol)

    def to_dataframe(self, n=-1):
        packets = []

        def decoder(header, data):
            packets.append(PacketStream.decode_ip_payload(header, data))

        self._reader.setfilter(self._bpf)
        self._reader.loop(n, decoder)

        dtypes = OrderedDict([
            ('time', 'datetime64[ns]'),
            ('src_host', 'object'),
            ('src_port', 'object'),
            ('dst_host', 'object'),
            ('dst_port', 'object'),
            ('protocol', 'object')])

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

        self._pcap_kwargs = pcap_kwargs
        self._dataframe = None

        super(PCAPSource, self).__init__(container='dataframe', metadata=metadata)

    def _get_dataframe(self):
        if self._dataframe is None:
            def _read_stream(filename, cls, protocol, limit):
                return cls(filename, protocol).to_dataframe(n=limit)

            if self._live:
                reader = partial(_read_stream, cls=LiveStream, protocol=self._protocol, limit=self._chunksize)
                dfs = [delayed(reader)(self._interface)]
            else:
                reader = partial(_read_stream, cls=OfflineStream, protocol=self._protocol, limit=self._chunksize)
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
