# TCP and UDP port scanner created by Daniel T
import argparse, sys
from scapy.all import *

# output format
def print_ports(port, state):
	print("%s | %s" % (port, state))

# tcp scan with syn flag set
# traceroute built in 
def tcp_scan(host, ports):
	print("tcp scan, %s with ports %s" % (host, ports))
	sport = RandShort()
	traceroute(host)
	for port in ports:
		pack = sr1(IP(dst=host)/TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)
		if pack != None:
			if pack.haslayer(TCP):
				if pack[TCP].flags == 20:
					print_ports(port, "Closed")
                    
				elif pack[TCP].flags == 18:
					print_ports(port, "Open")
				else:
					print_ports(port, "TCP packet resp / filtered")
			elif pack.haslayer(ICMP):
				print_ports(port, "ICMP resp / filtered")
			else:
				print_ports(port, "Unknown resp")
				print(pack.summary())
		else:
			print_ports(port, "Unanswered")

# udp scan
# traceroute built in
def udp_scan(host, ports):
	print("udp scan, %s with ports %s" % (host, ports))
	traceroute(host)
	for port in ports:
		pack = sr1(IP(dst=host)/UDP(sport=port, dport=port), timeout=2, verbose=0)
		if pack == None:
			print_ports(port, "Open / filtered")
		else:
			if pack.haslayer(ICMP):
				print_ports(port, "Closed")
			elif pack.haslayer(UDP):
				print_ports(port, "Open / filtered")
			else:
				print_ports(port, "Unknown")
				print(pack.summary())


# parse arguments
parser = argparse.ArgumentParser("Port scanner using Scapy")
parser.add_argument("-t", "--host", help="Specify target IP", required=True)
parser.add_argument("-p", "--ports", type=int, help="Specify port")
parser.add_argument("-max", "--maxport", type=int, help="Specify max port")
parser.add_argument("-min", "--minport", type=int, help="Specify min port")
parser.add_argument("-s", "--scantype", help="Scan type, tcp/udp", required=True)
args = parser.parse_args()

# define arguments
host = args.host
scantype = args.scantype.lower()
# set ports if passed
if args.ports:
	ports = args.ports
elif args.minport and args.maxport:
    ports = range(args.minport, args.maxport)
else:
	# default port range covers the well known ports
	ports = range(1, 1024)

# run designated scan type
if scantype == "tcp" or scantype == "t":
	tcp_scan(host, ports)
elif scantype == "udp" or scantype == "u":
	udp_scan(host, ports)
else:
	print("Scan type not supported")
