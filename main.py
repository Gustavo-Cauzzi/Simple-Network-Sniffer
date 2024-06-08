import socket
from sniffer.sniffer import sniff
from sniffer.utils import log

if __name__ == '__main__':
    log('Capturing network trafic:', clear=True)
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except socket.error:
        log('Socket could not be created.')
        exit(1)

    sniff(sock)
