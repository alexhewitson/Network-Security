import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re

ip_dict = {}

def parsePacket(packet):
    if not packet.haslayer("TCP"):
        return

    data = bytes(packet["TCP"].payload).decode('utf-8','replace')
    # get the reciever's IP address
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if data[:4] == 'USER':
        # add a new entry if this is a new ip address, increment the request counter regardless
        if  src_ip not in ip_dict:
            ip_dict[src_ip] = (0, 0)

        ip_dict[src_ip] = (ip_dict[src_ip][0] + 1, ip_dict[src_ip][1])

    if data[:3] == '530':
        # add a new entry if this is a new ip address, increment the failures counter regardless
        if dst_ip not in ip_dict:
            ip_dict[dst_ip] = (0, 0)

        ip_dict[dst_ip] = (ip_dict[dst_ip][0], ip_dict[dst_ip][1] + 1)


def printResults():
    for key in ip_dict:
        reqs, fails = ip_dict[key]
        print(f"IP:{key}, REQS:{reqs}, FAILS:{fails}")


if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)

    printResults()
