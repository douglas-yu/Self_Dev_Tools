#!/usr/bin/env python3
# rtp_echo_server.py

import socket

UDP_IP = "0.0.0.0"   # Listen on all interfaces
UDP_PORT = 5004      # Must match RTP Port in the GUI

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    print(f"UDP echo server listening on {UDP_IP}:{UDP_PORT}")

    while True:
        data, addr = sock.recvfrom(2048)  # buffer size
        if not data:
            continue
        # Echo packet back unchanged
        sock.sendto(data, addr)

if __name__ == "__main__":
    main()