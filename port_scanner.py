#!/bin/python3
import argparse
import re
import socket

# Validates the input argument IPv4 address.
def validate_ipv4_address(ipv4_address):
	regex = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
	ipv4_num_args = 4
	regex_match = re.match(regex, ipv4_address)
	if regex_match is None:
		raise argparse.ArgumentTypeError(f"Invalid format for IPv4 address: {ipv4_address}")
	else:
		try:
			values = [int(regex_match.group(i)) for i in range(1,ipv4_num_args+1)]
			for v in values:
				if not (0 <= v <= 255):
					raise ValueError(v)
		except:
			raise argparse.ArgumentTypeError(f"IPv4 address not in the correct range: {ipv4_address}")
	return

# Setup Argparse to parse input strings.
parser = argparse.ArgumentParser(
	prog='port_scanner.py',
	description='Scans an IPv4 address for open ports.')

parser.add_argument('ipv4_address')

# Read in the IPv4 address.
args = parser.parse_args()

# Scan TCP ports
PORT_MAX = 2**16 - 1
PORT_MIN = 1
open_tcp_ports = []
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
	for port in range(PORT_MIN, PORT_MAX + 1):
		try:
			sock.connect((args.ipv4_address, port))
			open_tcp_ports.append(port)
			print(f"Open TCP port: {port}")
		except:
			pass
		sock.close()

if len(open_tcp_ports) == 0:
	print("No open TCP ports.")
