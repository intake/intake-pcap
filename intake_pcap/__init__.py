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
