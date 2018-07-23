from glob import glob
from ._version import get_versions
__version__ = get_versions()['version']
del get_versions

from intake.source import base

from .stream import LiveStream, OfflineStream


class PCAPSource(base.DataSource):

    name = 'pcap'
    version = __version__
    container = 'dataframe'
    partition_access = True

    def __init__(self, urlpath, metadata=None, **pcap_kwargs):
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
                self._stream_class = LiveStream
                self._stream_sources = [self._interface]
            else:
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
        return dd.from_delayed(parts, meta=self._schema.dtype)

    def read(self):
        return self.to_dask().compute()

    def _close(self):
        self._streams = None
        self._stream_class = None
        self._stream_sources = None


def load_stream(c, source, protocol, payload, chunksize):
    return c(source, protocol, payload).to_dataframe(n=chunksize)
