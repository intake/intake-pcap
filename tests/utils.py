def dataframe_has_required_columns(df):
    return set(df.columns) == set(['time', 'src_host', 'src_port', 'dst_host', 'dst_port', 'protocol', 'payload'])
