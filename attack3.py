import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

build_file = False
bytes_list = []
filename = ''
files = {}

def parsePacket(packet):
    global build_file
    global filename
    global bytes_list
    if not packet.haslayer("TCP") or not packet.haslayer(Raw):
        return

    data = bytes(packet["TCP"].payload).decode('utf-8','replace')

    if '150 Data connection' in data:
        file_name = data.split('for ')[1].split(' (')[0]
        if 'bin/' not in file_name:
            bytes_list = []
            # the remaining packets will contain the file data
            build_file = True
            # get the filename
            filename = file_name
    elif '150 Opening' in data:
        file_name = data.split("'")[1]
        if 'bin/' not in file_name:
            bytes_list = []
            # the remaining packets will contain the file data
            build_file = True
            # get the filename
            filename = file_name
    elif 'Transfer complete' in data:
        build_file = False
        if filename != '':
            files[filename] = bytes_list
    elif build_file:
        # add the data from wach raw layer to the end of the list
        bytes_list.append(packet[Raw].load)


def outputFiles():
    # output the file currently stored in filename and bytes list
    # combine the file segments
    file_bytes = b''.join(bytes_list)

    global filename
    # open file in binary write mode
    with open(filename, 'wb') as f:
        # write bytes to file
        f.write(file_bytes)

    print(f'Generated file "{filename}"')

    for file_name in files:
        # output the remaining files
        if file_name != filename:
            # combine the file segments
            file_bytes = b''.join(files[file_name])

            # open file in binary write mode
            with open(file_name, 'wb') as f:
                # write bytes to file
                f.write(file_bytes)

            print(f'Generated file "{file_name}"')


if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]):
         parsePacket(packet)

    outputFiles()
