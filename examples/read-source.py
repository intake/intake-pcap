import sys

import pandas as pd

from intake.catalog import Catalog


if __name__ == '__main__':
    pd.set_option('display.max_columns', 10)
    pd.set_option('display.width', 1000)

    if len(sys.argv) <= 2:
        print("usage: read-source CATALOG NAME")
        sys.exit(1)

    catalog = sys.argv[1]
    name = sys.argv[2]

    c = Catalog(catalog)
    src = c[name].get()
    print(src.read())
