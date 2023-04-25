import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re

ip_dict = {}

def parsePacket(packet):
    if not packet.haslayer("TCP"):
        return

    data = bytes(packet["TCP"].payload).decode('utf-8','replace')

    # check FTP packets (port 21) that have a Raw layer
    if packet.payload.dport == 21 and packet.haslayer(Raw):
        data = data.split()
        # store the FTP username
        if data[0] == 'USER':
            # handle case where the same IP makes multiple requests
            if packet[IP].src in ip_dict:
                # print that IP's information before it is overwritten
                proto, user, pwd = ip_dict[packet[IP].src]
                print(f"{proto}, USERNAME:{user}, PASSWORD:{pwd}")

            ip_dict[packet[IP].src] = ('FTP', data[1], '')

        # store the FTP password, matching ip addresses
        if data[0] == 'PASS':
            ip_dict[packet[IP].src] = ('FTP', ip_dict[packet[IP].src][1], data[1])

    # check imap packets (port 143) that have a Raw layer
    elif packet.payload.dport == 143 and packet.haslayer(Raw):
        data = data.split()
        # find the login packet
        if data[1] == 'LOGIN':
            # handle case where the same IP makes multiple requests
            if packet[IP].src in ip_dict:
                # print that IP's information before it is overwritten
                proto, user, pwd = ip_dict[packet[IP].src]
                print(f"{proto}, USERNAME:{user}, PASSWORD:{pwd}")
            # store the username and password
            ip_dict[packet[IP].src] = ('IMAP', data[2], data[3])


def printResults():
    for ip in ip_dict:
        proto, user, pwd = ip_dict[ip]
        print(f"{proto}, USERNAME:{user}, PASSWORD:{pwd}")


if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)

    printResults()
