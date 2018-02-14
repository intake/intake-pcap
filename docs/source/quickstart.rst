Quickstart
==========

This guide will show you how to get started using Intake to read packet capture
(PCAP) data. It assumes the reader is already familiar with ``tcpdump``, the
command-line packet analyzer. Given a ``tcpdump`` command, we will show how you
can find the equivalent set of network packets with the Intake PCAP plugin.


Installation
------------

For Anaconda or Miniconda users, the Intake PCAP plugin is installed with the
following commands::

  conda install -c intake intake-pcap

If you wish to follow along with the ``tcpdump`` examples, consult your OS for
the appropriate installation instructions.


Creating Sample Data
--------------------

To bootstrap a sample PCAP file with local traffic, run the following::

  sudo tcpdump -c 100 -w local.pcap

This will capture 100 packets (including but not exclusive to IP traffic) from
the default network interface and write it to a file.

You will also need to write a catalog description file, ``catalog.yml``, to the
same directory as ``local.pcap`` to run the following examples. The necessary
data is::

  sources:
    - name: raw_live
      driver: pcap
      args:
        urlpath: ~
        interface: en0
        chunksize: 10
    - name: raw_local
      driver: pcap
      args:
        urlpath: !template '{{ CATALOG_DIR }}/local.pcap'
    - name: tcp_local
      driver: pcap
      args:
        urlpath: !template '{{ CATALOG_DIR }}/local.pcap'
        protocol: tcp
    - name: udp_local
      driver: pcap
      args:
        urlpath: !template '{{ CATALOG_DIR }}/local.pcap'
        protocol: udp


Reading a Live Stream
---------------------

To read a live stream of packets, you will need to start the Python interpreter
or Jupyter as a privileged user (``root`` on Unix-like systems).

**NOTE**: Intake does not currently support streaming packets from the network
interface. Packets will be placed into a dataframe in chunks (which can be
adjusted by the user).

Example: Unfiltered tcpdump
~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example will show the first 10 packets on the default interface. Each
packet will be timestamped and the raw IP address will be displayed. No packets
will be filtered. The exact output will vary depending on your local machine.::

  $ sudo tcpdump -c 10 -tttt -n -q
  2018-01-08 23:37:21.882212 IP 8.8.8.8.53 > 192.168.0.39.61362: UDP, length 172
  2018-01-08 23:37:21.882927 IP 192.168.0.39.61447 > 52.12.34.56.443: tcp 0
  2018-01-08 23:37:21.953415 IP 52.23.45.67.443 > 192.168.0.39.61445: tcp 0
  2018-01-08 23:37:21.953528 IP 192.168.0.39.61445 > 52.23.45.67.443: tcp 0
  2018-01-08 23:37:21.991435 IP 52.12.34.56.443 > 192.168.0.39.61447: tcp 0
  2018-01-08 23:37:21.991523 IP 192.168.0.39.61447 > 52.12.34.56.443: tcp 0
  2018-01-08 23:37:21.993620 IP 192.168.0.39.61447 > 52.12.34.56.443: tcp 517
  2018-01-08 23:37:22.093955 IP 52.12.34.56.443 > 192.168.0.39.61447: tcp 0
  2018-01-08 23:37:22.099580 IP 52.12.34.56.443 > 192.168.0.39.61447: tcp 1448
  2018-01-08 23:37:22.099587 IP 52.12.34.56.443 > 192.168.0.39.61447: tcp 1448

Example: Get unfiltered stream of packets without catalog
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example is equivalent to the ``tcpdump`` example, except the packets will
be available in a dataframe. The network interface is required though (typical
values are ``en0`` for macOS and ``eth0`` for Linux).::

  >>> import intake
  >>> ds = intake.open_pcap(None, interface='en0', chunksize=10)
  >>> df = ds.read()
  >>> df
                          time      src_host src_port         dst_host dst_port protocol
  0 2018-01-09 07:42:36.055605   52.12.34.56      443     192.168.0.39    61614      tcp
  1 2018-01-09 07:42:36.055682  192.168.0.39    61614      52.12.34.56      443      tcp
  2 2018-01-09 07:42:37.839555  192.168.0.39    17500  255.255.255.255    17500      udp
  3 2018-01-09 07:42:37.840472  192.168.0.39    17500    192.168.0.255    17500      udp
  4 2018-01-09 07:42:37.890092  192.168.0.39    61614      52.12.34.56      443      tcp
  5 2018-01-09 07:42:37.890243  192.168.0.39    61616      52.12.34.56      443      tcp
  6 2018-01-09 07:42:37.912166   52.12.34.56      443     192.168.0.39    61616      tcp
  7 2018-01-09 07:42:37.912237  192.168.0.39    61616      52.12.34.56      443      tcp
  8 2018-01-09 07:42:37.912399  192.168.0.39    61616      52.12.34.56      443      tcp
  9 2018-01-09 07:42:37.912833  192.168.0.39    61376     104.12.34.56     4070      tcp

Example: Get unfiltered stream of packets with catalog
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example is equivalent to the ``tcpdump`` example, except the packets will
be available in a dataframe. The ``raw_live`` data source is defined above.::

  >>> from intake.catalog import Catalog
  >>> c = Catalog("catalog.yml")
  >>> df = c.raw_live.read()
  >>> df
                          time     src_host src_port         dst_host dst_port protocol
  0 2018-01-09 07:47:26.825023  192.168.0.1    36123  239.255.255.250     1900      udp
  1 2018-01-09 07:47:26.825845  192.168.0.1    36123  239.255.255.250     1900      udp
  2 2018-01-09 07:47:26.826602  192.168.0.1    36123  239.255.255.250     1900      udp
  3 2018-01-09 07:47:26.827547  192.168.0.1    36123  239.255.255.250     1900      udp
  4 2018-01-09 07:47:26.828168  192.168.0.1    36123  239.255.255.250     1900      udp
  5 2018-01-09 07:47:26.829162  192.168.0.1    36123  239.255.255.250     1900      udp
  6 2018-01-09 07:47:26.829865  192.168.0.1    36123  239.255.255.250     1900      udp
  7 2018-01-09 07:47:26.830832  192.168.0.1    36123  239.255.255.250     1900      udp
  8 2018-01-09 07:47:26.831615  192.168.0.1    36123  239.255.255.250     1900      udp
  9 2018-01-09 07:47:26.832476  192.168.0.1    36123  239.255.255.250     1900      udp


Reading a PCAP File
-------------------

Example: Unfiltered tcpdump
~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example will show the first 10 packets from ``local.pcap``. Each packet
will be timestamped and the raw IP address will be displayed. No packets
will be filtered. The exact output will vary depending on your local machine::

  $ sudo tcpdump -c 10 -tttt -n -q -r local.pcap
  2018-01-09 00:16:12.210010 IP 192.168.0.39.54703 > 172.123.4.567.443: UDP, length 1350
  2018-01-09 00:16:12.210910 IP 192.168.0.39.54703 > 172.123.4.567.443: UDP, length 998
  2018-01-09 00:16:12.236176 IP 172.123.4.567.443 > 192.168.0.39.54703: UDP, length 1350
  2018-01-09 00:16:12.236543 IP 172.123.4.567.443 > 192.168.0.39.54703: UDP, length 31
  2018-01-09 00:16:12.236726 IP 192.168.0.39.54703 > 172.123.4.567.443: UDP, length 41
  2018-01-09 00:16:12.236791 IP 192.168.0.39.54703 > 172.123.4.567.443: UDP, length 38
  2018-01-09 00:16:12.251367 STP 802.1d, Config, Flags [none], bridge-id 7b00.01:23:45:67:89:00.8002, length 35
  2018-01-09 00:16:12.252565 IP 172.123.4.567.443 > 192.168.0.39.54703: UDP, length 30
  2018-01-09 00:16:12.313082 IP 172.123.4.567.443 > 192.168.0.39.54703: UDP, length 814
  2018-01-09 00:16:12.313479 IP 172.123.4.567.443 > 192.168.0.39.54703: UDP, length 16

Example: Get unfiltered stream of packets without catalog
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example is equivalent to the ``tcpdump`` example, except the packets will
be available in a dataframe. You should note that there is one less packet in
the output since the plugin only shows IP traffic; the ``tcpdump`` command
includes all traffic by default.::

  >>> import intake
  >>> ds = intake.open_pcap("local.pcap")
  >>> df = ds.read()
  >>> df
                          time       src_host src_port       dst_host dst_port protocol
  0 2018-01-09 08:16:12.210010   192.168.0.39    54703  172.123.4.567      443      udp
  1 2018-01-09 08:16:12.210910   192.168.0.39    54703  172.123.4.567      443      udp
  2 2018-01-09 08:16:12.236176  172.123.4.567      443   192.168.0.39    54703      udp
  3 2018-01-09 08:16:12.236543  172.123.4.567      443   192.168.0.39    54703      udp
  4 2018-01-09 08:16:12.236726   192.168.0.39    54703  172.123.4.567      443      udp
  5 2018-01-09 08:16:12.236791   192.168.0.39    54703  172.123.4.567      443      udp
  6 2018-01-09 08:16:12.252565  172.123.4.567      443   192.168.0.39    54703      udp
  7 2018-01-09 08:16:12.313082  172.123.4.567      443   192.168.0.39    54703      udp
  8 2018-01-09 08:16:12.313479  172.123.4.567      443   192.168.0.39    54703      udp

Example: Get unfiltered stream of packets with catalog
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example is equivalent to the ``tcpdump`` example, except the packets will
be available in a dataframe. You should note that there is one less packet in
the output since the plugin only shows IP traffic; the ``tcpdump`` command
includes all traffic by default.::

  >>> from intake.catalog import Catalog
  >>> c = Catalog("catalog.yml")
  >>> df = c.raw_local.read()
  >>> df
                          time       src_host src_port       dst_host dst_port protocol
  0 2018-01-09 08:16:12.210010   192.168.0.39    54703  172.123.4.567      443      udp
  1 2018-01-09 08:16:12.210910   192.168.0.39    54703  172.123.4.567      443      udp
  2 2018-01-09 08:16:12.236176  172.123.4.567      443   192.168.0.39    54703      udp
  3 2018-01-09 08:16:12.236543  172.123.4.567      443   192.168.0.39    54703      udp
  4 2018-01-09 08:16:12.236726   192.168.0.39    54703  172.123.4.567      443      udp
  5 2018-01-09 08:16:12.236791   192.168.0.39    54703  172.123.4.567      443      udp
  6 2018-01-09 08:16:12.252565  172.123.4.567      443   192.168.0.39    54703      udp
  7 2018-01-09 08:16:12.313082  172.123.4.567      443   192.168.0.39    54703      udp
  8 2018-01-09 08:16:12.313479  172.123.4.567      443   192.168.0.39    54703      udp


Filter data
-----------

The PCAP plugin will only show IP traffic. If you wish to only see traffic from
one protocol, then you can specify one of these values (``tcp``, ``udp``,
``icmp``, and ``igmp``) on the data source.

If you are familiar with the powerful filtering capabilities of ``tcpdump``,
then you will notice that the plugin's filter is limited at this time.

Example: Get filtered stream of packets without catalog
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

  >>> import intake
  >>> ds = intake.open_pcap("local.pcap", protocol='udp')
  >>> df = ds.read()
  >>> df
                          time       src_host src_port       dst_host dst_port protocol
  0 2018-01-09 08:16:12.210010   192.168.0.39    54703  172.123.4.567      443      udp
  1 2018-01-09 08:16:12.210910   192.168.0.39    54703  172.123.4.567      443      udp
  2 2018-01-09 08:16:12.236176  172.123.4.567      443   192.168.0.39    54703      udp
  3 2018-01-09 08:16:12.236543  172.123.4.567      443   192.168.0.39    54703      udp
  4 2018-01-09 08:16:12.236726   192.168.0.39    54703  172.123.4.567      443      udp
  5 2018-01-09 08:16:12.236791   192.168.0.39    54703  172.123.4.567      443      udp
  6 2018-01-09 08:16:12.252565  172.123.4.567      443   192.168.0.39    54703      udp
  7 2018-01-09 08:16:12.303790  172.123.4.567      443   192.168.0.39    54703      udp
  8 2018-01-09 08:16:12.313082  172.123.4.567      443   192.168.0.39    54703      udp
  9 2018-01-09 08:16:12.313479  172.123.4.567      443   192.168.0.39    54703      udp

Example: Get filtered stream of packets with catalog
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

  >>> from intake.catalog import Catalog
  >>> c = Catalog("catalog.yml")
  >>> df = c.udp_local.read()
  >>> df
                          time       src_host src_port       dst_host dst_port protocol
  0 2018-01-09 08:16:12.210010   192.168.0.39    54703  172.123.4.567      443      udp
  1 2018-01-09 08:16:12.210910   192.168.0.39    54703  172.123.4.567      443      udp
  2 2018-01-09 08:16:12.236176  172.123.4.567      443   192.168.0.39    54703      udp
  3 2018-01-09 08:16:12.236543  172.123.4.567      443   192.168.0.39    54703      udp
  4 2018-01-09 08:16:12.236726   192.168.0.39    54703  172.123.4.567      443      udp
  5 2018-01-09 08:16:12.236791   192.168.0.39    54703  172.123.4.567      443      udp
  6 2018-01-09 08:16:12.252565  172.123.4.567      443   192.168.0.39    54703      udp
  7 2018-01-09 08:16:12.303790  172.123.4.567      443   192.168.0.39    54703      udp
  8 2018-01-09 08:16:12.313082  172.123.4.567      443   192.168.0.39    54703      udp
  9 2018-01-09 08:16:12.313479  172.123.4.567      443   192.168.0.39    54703      udp


Display packet payload
----------------------

By default, the full packet data is not included. However, if you wish to see
the binary data, then you can set ``payload=True`` on the data source. For
example,::

  >>> import intake
  >>> ds = intake.open_pcap("local.pcap", payload=True)
  >>> df = ds.read()
  >>> df
                          time       src_host src_port       dst_host dst_port protocol  payload
  0 2018-01-09 08:16:12.210010   192.168.0.39    54703  172.123.4.567      443      udp  j23j4n234023023d
  1 2018-01-09 08:16:12.210910   192.168.0.39    54703  172.123.4.567      443      udp  df9b9i293ivaiqid
  2 2018-01-09 08:16:12.236176  172.123.4.567      443   192.168.0.39    54703      udp  j23irg93f9129ed1
  3 2018-01-09 08:16:12.236543  172.123.4.567      443   192.168.0.39    54703      udp  ni23nf2jg92j3f91
  4 2018-01-09 08:16:12.236726   192.168.0.39    54703  172.123.4.567      443      udp  12dj1nd1281j2d12
  5 2018-01-09 08:16:12.236791   192.168.0.39    54703  172.123.4.567      443      udp  ni12rn30fj9j1j2e
  6 2018-01-09 08:16:12.252565  172.123.4.567      443   192.168.0.39    54703      udp  18291n182d12j912
  7 2018-01-09 08:16:12.303790  172.123.4.567      443   192.168.0.39    54703      udp  21nd91n2f192fn91
  8 2018-01-09 08:16:12.313082  172.123.4.567      443   192.168.0.39    54703      udp  n93f293nf2398f23
  9 2018-01-09 08:16:12.313479  172.123.4.567      443   192.168.0.39    54703      udp  9tt9090239d903g9
