from .utils import dataframe_has_required_columns


def test_offline_unfiltered(ping_stream):
    df = ping_stream.to_dataframe()
    assert dataframe_has_required_columns(df, payload=False)
    assert len(df) == 96


def test_offline_filter_tcp(http_stream):
    http_stream.to_bpf("tcp")
    df = http_stream.to_dataframe()
    assert dataframe_has_required_columns(df, payload=False)
    assert len(df) == 41


def test_offline_filter_udp(http_stream):
    http_stream.to_bpf("udp")
    df = http_stream.to_dataframe()
    assert dataframe_has_required_columns(df, payload=False)
    assert len(df) == 2


def test_offline_filter_icmp(http_stream):
    http_stream.to_bpf("icmp")
    df = http_stream.to_dataframe()
    assert dataframe_has_required_columns(df, payload=False)
    assert len(df) == 0


def test_offline_limit(http_stream):
    df = http_stream.to_dataframe(n=10)
    assert dataframe_has_required_columns(df, payload=False)
    assert len(df) == 10


def test_offline_filter_vlan(vlan_stream):
    vlan_stream.to_bpf("tcp")
    df = vlan_stream.to_dataframe()
    assert dataframe_has_required_columns(df, payload=False)
    assert len(df) == 18
