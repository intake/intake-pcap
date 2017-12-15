import pytest

from intake_pcap import OfflineStream, PCAPSource


@pytest.fixture
def ping_stream():
    return OfflineStream("96pings.pcap")


@pytest.fixture
def ping_source():
    return PCAPSource(urlpath="96pings.pcap", pcap_kwargs={}, metadata={})


@pytest.fixture
def http_stream():
    return OfflineStream("http.pcap")


@pytest.fixture
def raw_http_source():
    return PCAPSource(urlpath="http.pcap", pcap_kwargs={}, metadata={})


@pytest.fixture
def tcp_http_source():
    return PCAPSource(urlpath="http.pcap", pcap_kwargs=dict(protocol="tcp"), metadata={})
