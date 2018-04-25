import pandas as pd
import pandas.util.testing as tm


def assert_dataframe_has_required_columns(df, payload):
    items = [
        ('time', 'datetime64[ns]'),
        ('src_host', 'ip'),
        ('src_port', 'u4'),
        ('dst_host', 'ip'),
        ('dst_port', 'u4'),
        ('protocol', object)
    ]

    if payload:
        items.append(("payload", 'object'))

    names, types = zip(*items)

    expected = pd.Series(types, index=names)
    tm.assert_series_equal(df.dtypes, expected)
