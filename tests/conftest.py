import os.path

import pytest

from intake_pcap import PCAPSource
from intake_pcap.stream import OfflineStream


@pytest.fixture
def data_filenames():
    basedir = os.path.dirname(__file__)
    return dict(ping=os.path.join(basedir, '96pings.pcap'),
                http=os.path.join(basedir, 'http.pcap'),
                vlan=os.path.join(basedir, 'vlan.pcap'),
                multiple=os.path.join(basedir, '*.pcap'))


@pytest.fixture
def ping_stream(data_filenames):
    return OfflineStream(data_filenames['ping'])


@pytest.fixture
def ping_source(data_filenames):
    return PCAPSource(urlpath=data_filenames['ping'], pcap_kwargs={}, metadata={})


@pytest.fixture
def http_stream(data_filenames):
    return OfflineStream(data_filenames['http'])


@pytest.fixture
def raw_http_source(data_filenames):
    return PCAPSource(urlpath=data_filenames['http'], pcap_kwargs={}, metadata={})


@pytest.fixture
def tcp_http_source(data_filenames):
    return PCAPSource(urlpath=data_filenames['http'], pcap_kwargs=dict(protocol="tcp"), metadata={})


@pytest.fixture
def vlan_stream(data_filenames):
    return OfflineStream(data_filenames['vlan'])


@pytest.fixture
def raw_vlan_source(data_filenames):
    return PCAPSource(urlpath=data_filenames['vlan'], pcap_kwargs={}, metadata={})


@pytest.fixture
def tcp_vlan_source(data_filenames):
    return PCAPSource(urlpath=data_filenames['vlan'], pcap_kwargs=dict(protocol="tcp"), metadata={})


@pytest.fixture
def multiple_stream(data_filenames):
    return OfflineStream(data_filenames['multiple'])


@pytest.fixture
def multiple_source(data_filenames):
    return PCAPSource(urlpath=data_filenames['multiple'], pcap_kwargs={}, metadata={})
