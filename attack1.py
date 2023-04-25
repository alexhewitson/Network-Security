import logging
import base64
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re


def decode(creds):
    decoded_creds = base64.b64decode(creds).decode('utf-8')
    # split the format: 'username:password'
    username, password = decoded_creds.split(':')
    return (username, password)


def parsePacket(packet):
    if not packet.haslayer("TCP") or not packet.haslayer(Raw) or not packet[TCP].dport == 80: 
        return

    data = bytes(packet["TCP"].payload).decode('utf-8','replace')

    # find the packet with the credentials and extract the relevant line in data
    if 'Authorization: Basic ' in data:
        encoded_creds = data.split('Authorization: Basic ')[1].split('\r\n')[0]
        username, password = decode(encoded_creds)
        return (username, password)


if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]):
        login_info = parsePacket(packet)
        if login_info:
            print(f'USERNAME:{login_info[0]}, PASSWORD:{login_info[1]}')
