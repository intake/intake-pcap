import os.path

import pytest

from intake import open_catalog

from .utils import assert_dataframe_has_required_columns


@pytest.fixture
def catalog1():
    path = os.path.dirname(__file__)
    return open_catalog(os.path.join(path, 'catalog1.yml'))


def test_raw_http(catalog1):
    src = catalog1['raw_http'].get()

    metadata = src.discover()
    assert metadata['npartitions'] == 1

    df = src.read()
    assert_dataframe_has_required_columns(df, payload=True)
    assert len(df) == 43

    src.close()


def test_tcp_http(catalog1):
    src = catalog1['tcp_http'].get()

    metadata = src.discover()
    assert metadata['npartitions'] == 1

    df = src.read()
    assert_dataframe_has_required_columns(df, payload=False)
    assert len(df) == 41

    src.close()
