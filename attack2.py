import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re


def parsePacket(packet):
    if not packet.haslayer("TCP") or not packet.haslayer(Raw):
        return

    data = bytes(packet["TCP"].payload).decode('utf-8','replace')

    # find the GET request packet and extract the host and resource lines
    if data[:3] == 'GET':
        split_payload = data.split('\r\n')
        host = split_payload[1].split('Host: ')[1]
        resource = split_payload[0].split(' ')[1]
        # put the lines together to create the full URL
        return host + resource


if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]):
        URL = parsePacket(packet)
        if URL:
            print(f"URL:{URL}")
