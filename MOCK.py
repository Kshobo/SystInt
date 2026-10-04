
import socket
import sys
import random
import ipaddress
from DNSStarter import *

# DNS server used for all lookups.
# Change this address here if you want to test a different recursive DNS server.
DNS_SERVER = "8.8.8.8"
DNS_PORT = 53

QTYPE_A = 1
QTYPE_CNAME = 5
QTYPE_AAAA = 28


def build_query(domain, qtype):
    # ident: random transaction ID
    # qr=0: query
    # rd=1: request recursive resolution
    header = DNSHeader(
        random.randint(0, 65535),
        0,  # qr
        0,  # opcode
        0,  # aa
        0,  # tc
        1,  # rd
        0,  # ra
        0,  # z
        0,  # rcode
        1,  # qdcount
        0,  # ancount
        0,  # nscount
        0   # arcount
    )

    question = DNSQuestion(domain.split("."), qtype, 1)
    datagram = DNSDatagram(header, [question], [])

    return write_datagram(datagram), header.ident


def lookup(domain, qtype):
    query, ident = build_query(domain, qtype)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        sock.sendto(query, (DNS_SERVER, DNS_PORT))
        response, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    return read_datagram(response), ident


def print_results(datagram):
    # Check the DNS response code.
    if datagram.header.rcode != 0:
        print("Error: rcode", datagram.header.rcode)
        return

    # Make sure this is a DNS response rather than a query.
    if datagram.header.qr != 1:
        print("Error: received a DNS query instead of a response")
        return

    # Process every answer returned by the DNS server.
    for answer in datagram.answers:

        # A record = IPv4 address
        if answer.type == QTYPE_A:
            # An A record contains 4 bytes.
            # Convert each byte to an unsigned decimal number
            # and join them with dots.
            ip = ".".join(str(byte & 0xff) for byte in answer.rdata)

            print("IPv4 address:", ip)

        # AAAA record = IPv6 address
        elif answer.type == QTYPE_AAAA:
            # An AAAA record contains 16 bytes.
            # IPv6Address automatically formats the address and
            # compresses the longest sequence of zero groups using ::.
            ip = str(ipaddress.IPv6Address(bytes(answer.rdata)))

            print("IPv6 address:", ip)

        # CNAME record = canonical name
        elif answer.type == QTYPE_CNAME:
            # The starter code handles DNS name compression.
            # The complete datagram must be passed to this method.
            name = ".".join(answer.cname_as_array_list(datagram))

            print("Canonical name:", name)


def main():
    # Check that the user supplied a domain name.
    if len(sys.argv) < 2:
        print("Usage: python resolver.py <domain>")
        return

    # Get the domain from the command line.
    # Remove a trailing dot if the user supplies a fully-qualified name.
    domain = sys.argv[1].rstrip(".")

    # Make two DNS requests:
    # 1. A record for IPv4
    # 2. AAAA record for IPv6
    for qtype in (QTYPE_A, QTYPE_AAAA):

        datagram, ident = lookup(domain, qtype)

        # Check that the response belongs to our request.
        if datagram.header.ident != ident:
            print("Mismatched transaction ID")
            continue

        print_results(datagram)


main()
