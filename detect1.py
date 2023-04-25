import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re

null_scan_ips = {}
fin_scan_ips = {}
xmas_scan_ips = {}

def parsePacket(packet):
    if not packet.haslayer("TCP"):
        return

    tcp_flags = packet[TCP].flags
    # check each TCP flag for scan types
    if tcp_flags == 0:
        ip_src = packet[IP].src
        # add a new entry if this is a new ip address, increment the NULL scan counter regardless
        if ip_src not in null_scan_ips:
            null_scan_ips[ip_src] = 0

        null_scan_ips[ip_src] += 1

    elif tcp_flags == 'F':
        ip_src = packet[IP].src
        # add a new entry if this is a new ip address, increment the FIN scan counter regardless
        if ip_src not in fin_scan_ips:
            fin_scan_ips[ip_src] = 0

        fin_scan_ips[ip_src] += 1

    elif tcp_flags == 'FPU':
        ip_src = packet[IP].src
        # add a new entry if this is a new ip address, increment the XMAS scan counter regardless
        if ip_src not in xmas_scan_ips:
            xmas_scan_ips[ip_src] = 0

        xmas_scan_ips[ip_src] += 1


def printResults():
    for ip in null_scan_ips:
        print(f"NULLScan, IP:{ip}, COUNT:{null_scan_ips[ip]}")

    for ip in fin_scan_ips:
        print(f"FINScan, IP:{ip}, COUNT:{fin_scan_ips[ip]}")

    for ip in xmas_scan_ips:
        print(f"XMASScan, IP:{ip}, COUNT:{xmas_scan_ips[ip]}")


if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)

    printResults()
