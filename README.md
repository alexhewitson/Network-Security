# Network-Security

The below files extract information from given .pcap files to demonstrate the risks of using outdated and unencrypted networking protocols, such as FTP and HTTP.

detect0.py – Searches the .pcap file for IP addresses that make FTP login requests and output the number of successful and failed requests to help determine if a brute forcing attack occurred on an FTP server.

detect1.py – Searches the .pcap file for IP addresses that may be conducting a port scan based on the number of NULL, FIN, and XMAS scans they perform.

detect2.py – Searches the .pcap file for IP addresses potentially conducting SYN scans by outputting those that sent more than three times the number of SYN packets as SYN-ACK packets they received.

attack0.py – Searches the .pcap file for login credentials transmitted in plaintext in both FTP and IMAP conversations and outputs those credentials.

attack1.py – Searches the .pcap file for HTTP v1.0 credentials. Although these credentials are encoded, extracting the plaintext is trivial.

attack2.py – Searches the .pcap file for any HTTP URLS accessed during the capture and output those URLs with the resources accessed.

attack3.py – Searches the .pcap file for any files transmitted over FTP and reconstructs and outputs those files.
