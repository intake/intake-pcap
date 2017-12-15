from .utils import dataframe_has_required_columns


def test_unfiltered_source(ping_source):
    metadata = ping_source.discover()
    assert metadata['npartitions'] == 1

    df = ping_source.read()
    assert dataframe_has_required_columns(df)
    assert len(df) == 96

    ping_source.close()


def test_filtered_source(tcp_http_source):
    metadata = tcp_http_source.discover()
    assert metadata['npartitions'] == 1

    df = tcp_http_source.read()
    assert dataframe_has_required_columns(df)
    assert len(df) == 41

    tcp_http_source.close()
