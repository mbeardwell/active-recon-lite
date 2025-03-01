#!/bin/python3
import argparse
import multiprocessing as mp
import re
import socket
import sys

VERSION = '1.0'
MAX_SIMUL_SCANS = 8
BANNER_LEN = 1024 #bytes
SCAN_TIMEOUT = 3 #seconds

PORT_MAX = 2 ** 16 - 1
PORT_MIN = 1

# Validates the input argument IPv4 address.
def validate_ipv4_address(ipv4_address):
	REGEX = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
	IPV4_NUM_ARGS = 4

	regex_match = re.match(REGEX, ipv4_address)

	if regex_match is None:
		raise argparse.ArgumentTypeError(f'Invalid format for IPv4 address: {ipv4_address}')
	else:
		try:
			values = [int(regex_match.group(i)) for i in range(1,IPV4_NUM_ARGS+1)]
			for v in values:
				if not (0 <= v <= 255):
					raise ValueError(v)
		except ValueError:
			raise argparse.ArgumentTypeError(f'Invalid format for IPv4 address: {ipv4_address}')

	return ipv4_address

# Validates the input argument port range.
def validate_ports(ports):
	if ports is None:
		return (PORT_MIN, PORT_MAX)

	REGEX = r'^(\d{0,5})(\-(\d{0,5}))?$'
	PORT_MIN_CAPT_GRP = 1
	PORT_MAX_CAPT_GRP = 3

	regex_match = re.match(REGEX, ports)

	if regex_match is None:
		raise argparse.ArgumentTypeError(f'Invalid port range: {ports}')
	else:
		try:
			port_from = int(regex_match.group(PORT_MIN_CAPT_GRP))

			wants_scan_one_port = regex_match.group(PORT_MAX_CAPT_GRP) == None

			if wants_scan_one_port:
				port_to = port_from
			else:
				port_to = int(regex_match.group(PORT_MAX_CAPT_GRP))

			if not (PORT_MIN <= port_from <= PORT_MAX) or not (PORT_MIN <= port_to <= PORT_MAX):
				raise argparse.ArgumentTypeError(f'Invalid port range: {ports}')

		except ValueError:
			raise argparse.ArgumentTypeError(f'Invalid port range: {ports}')

	return (port_from, port_to)

# Asynchronous port scan - allows multiple simultaneous scans.
def scan_port_async(ipv4_address, port):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
		sock.settimeout(SCAN_TIMEOUT)

		try:
			sock.connect((ipv4_address, port))
		except ConnectionRefusedError:
			return None
		except Exception as e:
			if args.verbose:
				print(f'Error: {e}')
			return None

		try:
			banner = sock.recv(BANNER_LEN).decode(errors='ignore').strip()
		except TimeoutError:
			banner = None

		sock.close()

		return (port, banner)

def is_reachable_async(ipv4_address, port):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
		sock.settimeout(SCAN_TIMEOUT)
		try:
			sock.connect((ipv4_address, port))
			return True
		except socket.timeout:
			return False

def is_reachable(ipv4_address, ports=[20, 21, 22, 23, 25, 80, 443]):
	with mp.Pool(processes = MAX_SIMUL_SCANS) as pool:
		successes = pool.starmap(is_reachable_async, [(ipv4_address, port) for port in ports])
		return True in successes

def get_user_response(prompt):
	response = None
	while not response in ['y', 'n']:
		response = input(prompt)
		if len(response) == 0:
			continue
		response = response.lower()[0]

	return response == 'y'

def print_basic_info():
	print(f'Port scanner version {VERSION}')
	print('Author: Matthew Beardwell')
	print('Performs a basic TCP connect scan and grabs banners where they exist.')

if __name__ == '__main__':
	print_basic_info()

	# Setup Argparse to parse input strings.
	parser = argparse.ArgumentParser(
		prog='port_scanner.py',
		description='Scans an IPv4 address for open TCP ports with a TCP Connect scan.')

	parser.add_argument('ipv4_address', help='IPv4 address to scan')
	parser.add_argument('-p' ,'--ports', help='Range of TCP Ports to scan (e.g. 123, 1-65536)')
	parser.add_argument('-v', '--verbose', action='store_true')
	parser.add_argument('-o', '--output', help='Filename to write output to')
	parser.add_argument('-y', '--yes', action='store_true', help='Replies yes to any prompts')

	# Read in the IPv4 address and port range.
	try:
		args = parser.parse_args()
		ip_address = validate_ipv4_address(args.ipv4_address)
		port_from, port_to = validate_ports(args.ports)

	except argparse.ArgumentTypeError as e:
		print(f'{e}')
		sys.exit(1)

	## Check host is reachable.
	## This is not foolproof as a firewall may filter these packets even when the host is reachable via other ports.
	if not is_reachable(ip_address):
		print(f'Host {ip_address} appears to be unreachable. The scan may not show valid results.')
		if args.yes:
			print('Would you like to end scan? (Y/n) >>> Y')
			sys.exit()
		else:
			if get_user_response('Would you like to end scan? (Y/n) >>> '):
				sys.exit()

	## Asynchronous port scanning.
	if args.verbose:
		if port_from == port_to:
			print(f'Running TCP Connect scans for IPv4 address {ip_address} for port {port_from}')
		else:
			print(f'Running TCP Connect scans for IPv4 address {ip_address} for port range {port_from}-{port_to}')
	else:
		print('Scanning TCP ports')

	with mp.Pool(processes = MAX_SIMUL_SCANS) as pool:
		open_ports_unprocessed = pool.starmap(scan_port_async, [(ip_address, port) for port in range(port_from, port_to + 1)])

		# Remove 'None' entries and sort results
		open_ports_unprocessed = set(open_ports_unprocessed)

		if None in open_ports_unprocessed:
			open_ports_unprocessed.remove(None)

		open_ports_unprocessed.sort(key=lambda t: t[0])
		open_ports = dict()

		for (port, banner) in open_ports_unprocessed:
			open_ports[port] = banner

	## Print results.
	if len(open_ports.keys()) == 0:
		if port_from == port_to:
			print(f'Port {port_from} is not open at {ip_address}')
		else:
			print(f'No open ports in the range {port_from}-{port_to} at {ip_address}') 
	else:
		# Print ports and banner if found.
		print('Open ports: ')
		for port in sorted(open_ports.keys()):
			banner = open_ports.get(port)

			if banner is None:
				banner = 'No banner received'

			print(f'{port} | Banner: {banner}')

	# Output results to a file.
	if args.output is not None:
		try:
			with open(args.output, 'w') as file:
				print(f'Writing results to \'{args.output}\'')

				file.write(f'TCP Connect scan results for IPv4 address {ip_address} with TCP port range {port_from} to {port_to}\n')

				if len(open_ports.keys()) == 0:
					file.write(f'No open TCP ports in range {port_from} to {port_to}\n')
				else:
					file.write(f'Open TCP ports in range {port_from} to {port_to}:\n')
					for port in sorted(open_ports.keys()):
						banner = open_ports.get(port)

						if banner is None:
							banner = 'No banner received'

						file.write(f'{port} | Banner: {banner}\n')

		except IOError:
			print(f'Failed to write to \'{args.output}\'')
