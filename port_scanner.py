#!/bin/python3
import argparse
import multiprocessing as mp
import re
import socket

# Validates the input argument IPv4 address.
def validate_ipv4_address(ipv4_address):
	REGEX = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
	IPV4_NUM_ARGS = 4

	regex_match = re.match(REGEX, ipv4_address)

	if regex_match is None:
		raise argparse.ArgumentTypeError(f"Invalid format for IPv4 address: {ipv4_address}")
	else:
		try:
			values = [int(regex_match.group(i)) for i in range(1,IPV4_NUM_ARGS+1)]
			for v in values:
				if not (0 <= v <= 255):
					raise ValueError(v)
		except:
			raise argparse.ArgumentTypeError(f"IPv4 address not in the correct range: {ipv4_address}")
	return ipv4_address

def validate_ports(ports):
	REGEX = r'^(\d{0,5})\-(\d{0,5})$'
	PORT_MAX = 2 ** 16 - 1
	PORT_MIN = 1

	regex_match = re.match(REGEX, ports)
	if regex_match is None:
		raise argparse.ArgumentTypeError(f"Invalid format for port range: {ports}")
	else:
		try:
			port_from_str = regex_match.group(1)
			port_to_str = regex_match.group(2)

			port_from = PORT_MIN if port_from_str == '' else int(port_from_str)
			port_to = PORT_MAX if port_to_str == '' else int(port_to_str)

			if not (PORT_MIN <= port_from <= PORT_MAX) or not (PORT_MIN <= port_to <= PORT_MAX):
				raise argparse.ArgumentTypeError(f'Invalid port range: {port_from}-{port_to}')
		except:
			raise argparse.ArgumentTypeError(f'Invalid port range: {ports}')

	return (port_from, port_to)

# Setup Argparse to parse input strings.
parser = argparse.ArgumentParser(
	prog='port_scanner.py',
	description='Scans an IPv4 address for open ports.')

parser.add_argument('ipv4_address', help='IPv4 address to scan')
parser.add_argument('-p' ,'--ports', default='-', help='Range of TCP Ports to scan (e.g. 1-65536)')

# Read in the IPv4 address.
args = parser.parse_args()
ip_address = validate_ipv4_address(args.ipv4_address)
port_from, port_to = validate_ports(args.ports)


# Asynchronous port scan - allows multiple simultaneous port scans
def scan_port_async(ipv4_address, port):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
		try:
			sock.connect((ipv4_address, port))
			sock.close()
			return port
		except:
			return None

MAX_SIMUL_SCANS = 8

## Asynchronous port scanning
with mp.Pool(processes = MAX_SIMUL_SCANS) as pool:
	results = set(pool.starmap(scan_port_async, [(ip_address, port) for port in range(port_from, port_to + 1)]))
	if None in results:
		results.remove(None)

if len(results) == 0:
	print("No open TCP ports.")
else:
	print(f"Open ports: {results}")
