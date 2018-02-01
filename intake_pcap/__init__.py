from glob import glob

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
        self._stream_class = None
        self._stream_sources = None

        super(PCAPSource, self).__init__(container='dataframe', metadata=metadata)

    def _create_stream(self, src):
        return self._stream_class(src, self._protocol, self._payload)

    def _get_schema(self):
        if self._streams is None:
            if self._live:
                self._stream_class = LiveStream
                self._stream_sources = [self._interface]
            else:
                self._stream_class = OfflineStream
                self._stream_sources = sorted(glob(self._urlpath))

            self._streams = [self._create_stream(src) for src in self._stream_sources]

        # All streams have same schema
        dtypes = self._streams[0].dtype

        return base.Schema(datashape=None,
                           dtype=dtypes,
                           shape=(None, len(dtypes)),
                           npartitions=len(self._streams),
                           extra_metadata={})

    def _get_partition(self, i):
        df = self._streams[i].to_dataframe(n=self._chunksize)

        # Since pcapy doesn't make it easy to reset a stream iterator,
        # we need to close and re-open the stream after reading
        self._streams[i] = self._create_stream(self._stream_sources[i])

        return df

    def _close(self):
        self._streams = None
        self._stream_class = None
        self._stream_sources = None
