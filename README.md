# portscanner

Rinkydink port scanner created for class assignment

-Allow command-line switches to specify a host and port.
-Present a simple response to the user.
-Allow multiple ports to be specified
-Traceroute
-Use of more than one protocol, TCP and UDP

Usage: Port scanner using Scapy [-h] -t HOST [-p PORTS] [-max MAXPORT] [-min MINPORT] -s SCANTYPE

optional arguments:
  -h, --help                         Show this help message and exit
  -t HOST, --host HOST               Specify target IP
  -p PORT, --port PORT               Specify port
  -max MAXPORT, --maxport MAXPORT    Specify max port
  -min MINPORT, --minport MINPORT    Specify min port
  -s SCANTYPE, --scantype SCANTYPE   Scan type, tcp/udp
  
  
  Must install argparse and scapy on machine running python script
  pip install argparse
  pip install scapy
