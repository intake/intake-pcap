from glob import glob

from intake.source import base
from . import __version__


class PCAPSource(base.DataSource):
    """
    Load PCAP data

    Supports either .pcap file format (e.g., as produced by TCPdump) or
    reading live from an interface.

    """

    name = 'pcap'
    version = __version__
    container = 'dataframe'
    partition_access = True

    def __init__(self, urlpath, metadata=None, **pcap_kwargs):
        """
        Parameters
        ----------
        urlpath: str or None
            If a path, will load files; can contain glob character, in which
            case each file will become a partition of the source
        pcap_pars: can include
            interface: where to pull live data from, e.g., eth0
            chunksize: in live mode, how big the parts will be
            protocol: to filter live data by protocol
            payload: whether to include only metadata in each row, or full
                bytes data
        """
        self._live = not bool(urlpath)

        self._urlpath = urlpath
        self._interface = None

        if 'interface' in pcap_kwargs:
            self._interface = pcap_kwargs['interface']
        self._chunksize = pcap_kwargs.get('chunksize',
                                          100 if self._live else -1)
        self._protocol = pcap_kwargs.get('protocol', None)
        self._payload = pcap_kwargs.get('payload', False)

        self._pcap_kwargs = pcap_kwargs
        self._streams = None
        self._stream_class = None
        self._stream_sources = None

        super(PCAPSource, self).__init__(metadata=metadata)

    def _create_stream(self, src):
        return self._stream_class(src, self._protocol, self._payload)

    def _get_schema(self):
        if self._schema is None:
            if self._live:
                from .stream import LiveStream
                self._stream_class = LiveStream
                self._stream_sources = [self._interface]
            else:
                from .stream import OfflineStream
                self._stream_class = OfflineStream
                self._stream_sources = sorted(glob(self._urlpath))

            stream = self._create_stream(self._stream_sources[0])

            dtypes = dict(stream.dtype)
            self._schema = base.Schema(datashape=None,
                                       dtype=dtypes,
                                       shape=(None, len(dtypes)),
                                       npartitions=len(self._stream_sources),
                                       extra_metadata={})

        return self._schema

    def _get_partition(self, i):
        self._get_schema()
        df = load_stream(self._stream_class, self._stream_sources,
                         self._protocol, self._payload, self._chunksize)
        return df

    def to_dask(self):
        import dask.delayed
        import dask.dataframe as dd
        self._get_schema()
        dload = dask.delayed(load_stream)
        parts = [dload(self._stream_class, s,
                       self._protocol, self._payload, self._chunksize)
                 for s in self._stream_sources]
        return dd.from_delayed(parts)

    def read(self):
        return self.to_dask().compute()

    def _close(self):
        self._streams = None
        self._stream_class = None
        self._stream_sources = None


def load_stream(c, source, protocol, payload, chunksize):
    return c(source, protocol, payload).to_dataframe(n=chunksize)
