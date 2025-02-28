#!/bin/python3
import argparse
import multiprocessing as mp
import re
import socket
import sys

PORT_MAX = 2 ** 16 - 1
PORT_MIN = 1
MAX_SIMUL_SCANS = 8
BANNER_LEN = 1024 #bytes
SCAN_TIMEOUT = 5 #seconds

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
			argparse.ArgumentTypeError(f"Invalid format for IPv4 address: {ipv4_address}")

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
		raise argparse.ArgumentTypeError(f"Invalid port range: {ports}")
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
		try:
			sock.settimeout(SCAN_TIMEOUT)
			sock.connect((ipv4_address, port))
			sock.close()
			return port
		except ConnectionRefusedError:
			return None
		except Exception as e:
			return None

# Asynchronous banner grab - allows multiple simultaneous scans.
def grab_banner_async(ipv4_address, port):
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
		try:
			sock.settimeout(SCAN_TIMEOUT)
			sock.connect((ipv4_address, port))
			banner = sock.recv(BANNER_LEN)
			sock.close()
			return (port, banner)
		except Exception as e:
			return None

if __name__ == '__main__':
	# Setup Argparse to parse input strings.
	parser = argparse.ArgumentParser(
		prog='port_scanner.py',
		description='Scans an IPv4 address for open TCP ports with a TCP Connect scan.')

	parser.add_argument('ipv4_address', help='IPv4 address to scan')
	parser.add_argument('-p' ,'--ports', help='Range of TCP Ports to scan (e.g. 123, 1-65536)')
	parser.add_argument('-v', '--verbose', action='store_true')
	parser.add_argument('-o', '--output', help='Filename to write output to')

	# Read in the IPv4 address and port range.
	try:
		args = parser.parse_args()
		ip_address = validate_ipv4_address(args.ipv4_address)
		port_from, port_to = validate_ports(args.ports)

	except argparse.ArgumentTypeError as e:
		print(f"{e}")
		sys.exit(1)

	## Asynchronous port scanning.
	if args.verbose:
		if port_from == port_to:
			print(f"Running TCP Connect scans for IPv4 address {ip_address} for port {port_from}")
		else:
			print(f"Running TCP Connect scans for IPv4 address {ip_address} for port range {port_from}-{port_to}")
	else:
		print("Scanning TCP ports")

	with mp.Pool(processes = MAX_SIMUL_SCANS) as pool:
		open_ports_unprocessed = pool.starmap(scan_port_async, [(ip_address, port) for port in range(port_from, port_to + 1)])
		# Remove 'None' entries and sort results
		open_ports_unprocessed = set(open_ports_unprocessed)
		if None in open_ports_unprocessed:
			open_ports_unprocessed.remove(None)
		open_ports = sorted(open_ports_unprocessed)

	## Print results.
	if len(open_ports) == 0:
		if port_from == port_to:
			print(f"Port {port_from} is not open at {ip_address}")
		else:
			print(f'No open ports in the range {port_from}-{port_to} at {ip_address}') 
	else:
		if args.verbose:
			print(f"Grabbing banners for open ports at {ip_address}")

		# Grab banners with asynchronous scans.
		with mp.Pool(processes = MAX_SIMUL_SCANS) as pool:
			banners_unprocessed = pool.starmap(grab_banner_async, [(ip_address, port) for port in open_ports])

			# Filter and sort banner messages by TCP port number.
			banners_unprocessed = set(banners_unprocessed)
			if None in banners_unprocessed:
				banners_unprocessed.remove(None)
			banners = dict()
			for key_val in banners_unprocessed:
				banners[key_val[0]] = key_val[1].decode(errors="ignore").strip()

		if args.verbose:
			no_banners = {None} == set(banners.values())
			if no_banners:
				print(f'No banners found for open ports at {ip_address}')

		# Print ports and banner if found.
		print("Open ports: ")
		for port in open_ports:
			try:
				banner = banners[port]
			except KeyError:
				banner = None

			if banner is not None:
				print(f"\t{port} - {banner}")
			else:
				print(f"\t{port}")

	# Output results to a file.
	if args.output is not None:
		print(f'Writing results to file {args.output}')

		with open(args.output, 'a') as file:
			file.write(f'TCP Connect scan results for IPv4 address {ip_address} with TCP port range {port_from} to {port_to}\n')

			if len(open_ports) == 0:
				file.write(f'No open TCP ports in range {port_from} to {port_to}\n')
			else:
				file.write(f'Open TCP ports in range {port_from} to {port_to}:\n')
				for port in open_ports:
					try:
						banner = banners[port]
					except KeyError:
						banner = None

					if banner is not None:
						file.write(f'{port} | Banner: {banner}\n')
					else:
						file.write(f'{port}\n')

