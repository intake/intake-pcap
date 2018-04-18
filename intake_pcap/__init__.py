from intake.source import base

from ._version import get_versions

__version__ = get_versions()['version']
del get_versions


class Plugin(base.Plugin):
    def __init__(self):
        super(Plugin, self).__init__(name='pcap', version='0.1', container='dataframe', partition_access=False)

    def open(self, urlpath, **kwargs):
        """
        Parameters:
            urlpath : str
                Absolute or relative path to source files that can contain shell-style wildcards.
            kwargs : dict
                Additional parameters to pass to ``intake_pcap.stream.PacketStream`` subclass.
        """
        from .source import PCAPSource
        base_kwargs, source_kwargs = self.separate_base_kwargs(kwargs)
        return PCAPSource(urlpath=urlpath, pcap_kwargs=source_kwargs, metadata=base_kwargs['metadata'])
