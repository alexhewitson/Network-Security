import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re

ip_dict = {}

def parsePacket(packet):
    if not packet.haslayer("TCP"):
        return

    # check each packet for syn or synack tags
    tcp_flags = packet[TCP].flags
    if tcp_flags == 'S':
        ip_src = packet[IP].src
        # add a new entry if this is a new ip address, increment the SYN counter regardless
        if ip_src not in ip_dict:
            ip_dict[ip_src] = (0, 0)

        ip_dict[ip_src] = (ip_dict[ip_src][0] + 1, ip_dict[ip_src][1])

    elif tcp_flags == 'SA':
        ip_dst = packet[IP].dst
        # add a new entry if this is a new ip address, increment the SYNACK counter regardless
        if ip_dst not in ip_dict:
            ip_dict[ip_dst] = (0, 0)

        ip_dict[ip_dst] = (ip_dict[ip_dst][0], ip_dict[ip_dst][1] + 1)


def printResults():
    for ip in ip_dict:
        syn, ack = ip_dict[ip]
        # print the SYN and SYNACK counts for each ip if it sent over 3x more SYN than SYNACKs recieved
        if syn > ack * 3:
            print(f"IP:{ip}, SYN:{syn}, SYNACK:{ack}")


if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)

    printResults()
