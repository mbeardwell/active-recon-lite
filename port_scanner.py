#!/bin/python3
import argparse
import re
import socket

# Setup Argparse to parse input strings.

parser = argparse.ArgumentParser(
	prog='port_scanner.py',
	description='Scans an IPv4 address for open ports.')

parser.add_argument('ipv4_address')

def process_ipv4_from_args(ipv4_address):
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
	return values

args = parser.parse_args()
