from functools import partial
from glob import glob

from dask.delayed import delayed
import dask.dataframe as dd

from intake.source import base

from .stream import LiveStream, OfflineStream


class Plugin(base.Plugin):
    def __init__(self):
        super(Plugin, self).__init__(name='pcap', version='0.1', container='dataframe', partition_access=False)

    def open(self, urlpath, **kwargs):
        """
        Parameters:
            urlpath : str
                Absolute or relative path to source files that can contain shell-style wildcards.
            kwargs : dict
                Additional parameters to pass to ``intake_ppad.stream.PacketStream`` subclass.
        """
        base_kwargs, source_kwargs = self.separate_base_kwargs(kwargs)
        return PCAPSource(urlpath=urlpath, pcap_kwargs=source_kwargs, metadata=base_kwargs['metadata'])


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
        self._streams = None

        super(PCAPSource, self).__init__(container='dataframe', metadata=metadata)

    def _get_schema(self):
        if self._streams is None:
            def _read_stream(src, cls):
                return cls(src, self._protocol, self._payload)

            if self._live:
                reader = partial(_read_stream, cls=LiveStream)
                self._streams = [reader(self._interface)]
            else:
                reader = partial(_read_stream, cls=OfflineStream)
                filenames = sorted(glob(self._urlpath))
                self._streams = [reader(filename) for filename in filenames]

        # All streams have same schema
        dtypes = self._streams[0].dtype

        return base.Schema(datashape=None,
                           dtype=dtypes,
                           shape=(None, len(dtypes)),
                           npartitions=len(self._streams),
                           extra_metadata={})

    def _get_partition(self, i):
        return self._streams[i].to_dataframe(n=self._chunksize)

    def _close(self):
        self._streams = None
