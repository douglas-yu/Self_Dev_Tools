# File: http_sniffer.py
import socket

def start_sniffing():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    while True:
        packet = s.recvfrom(65565)
        print(packet)

if __name__ == "__main__":
    start_sniffing()