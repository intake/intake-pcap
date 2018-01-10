### Installation

While `requirements.txt` contains the package dependencies, we currently need to
install a mixture of conda and pip packages. The install instructions are:

```
conda install -c intake intake
conda install libpcap
pip install pcapy
python setup.py develop
```

### Examples

To bootstrap a sample PCAP file, run the following given your local network
interface (macOS is `en0`, Linux is `eth0`) and a sample size of packets:

```
sudo python examples/dump-live.py examples/local.pcap en0 100
```

NOTE: If you output to `examples/local.pcap`, the provided catalog,
`sample.yml`, will be able to read this.

To read a live stream, run the following with an optional protocol filter
(valid values are `tcp`, `udp`, `icmp`, and `igmp`):

```
sudo python examples/read-live.py INTERFACE [PROTOCOL]
```

To read a local PCAP file, run the following with an optional protocol filter
(valid values are `tcp`, `udp`, `icmp`, and `igmp`):

```
sudo python examples/read-pcap.py PATH [PROTOCOL]
```

To read a catalog source, run the following with a valid name (`local` reads
PCAP file, `raw_live` reads Ethernet packets from default macOS network,
`udp_live` reads UDP packets from default macOS network):

```
sudo python examples/read-source.py examples/sample.yml NAME
```
