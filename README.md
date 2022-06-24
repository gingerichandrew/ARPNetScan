<h3 align="center">Python Network Scanner - ARP</h3>

## Usage
Written in Python 3.6

Using Scapy(2.4.5) -> https://scapy.net/

Flags:

  ** REQUIRED **

    -n: <'local network address'> -> '192.168.1.1' ... '10.0.0.1'

  ** OPTIONAL **

    -d -> If present will display device hostnames(if available). Not optimized for a large network

EX:

   -python ARPScan.py -n '192.168.1.1/24' -d

   -python ARPScan.py -n '10.0.0.1/24'

