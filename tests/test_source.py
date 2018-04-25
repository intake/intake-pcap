from .utils import assert_dataframe_has_required_columns


def test_unfiltered_source(ping_source):
    metadata = ping_source.discover()
    assert metadata['npartitions'] == 1

    df = ping_source.read()
    assert_dataframe_has_required_columns(df, payload=False)
    assert len(df) == 96

    ping_source.close()


def test_filtered_source(tcp_http_source):
    metadata = tcp_http_source.discover()
    assert metadata['npartitions'] == 1

    df = tcp_http_source.read()
    assert_dataframe_has_required_columns(df, payload=False)
    assert len(df) == 41

    tcp_http_source.close()


def test_multiple_source(multiple_source):
    metadata = multiple_source.discover()
    assert metadata['npartitions'] == 3

    df = multiple_source.read()
    assert_dataframe_has_required_columns(df, payload=False)
    assert len(df) == 157

    multiple_source.close()


def test_repeated_reads(ping_source):
    metadata = ping_source.discover()
    assert metadata['npartitions'] == 1

    df = ping_source.read()
    assert_dataframe_has_required_columns(df, payload=False)
    assert len(df) == 96

    df = ping_source.read()
    assert_dataframe_has_required_columns(df, payload=False)
    assert len(df) == 96

    ping_source.close()
