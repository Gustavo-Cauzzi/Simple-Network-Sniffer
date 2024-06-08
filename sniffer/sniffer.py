

import socket
import struct
from sniffer.helpers import EthernetProtocolsEnum, ProtocolsEnum
from sniffer.utils import format_binary_to_hex, get_mac_address_from_bytes, log


def sniff(sock):
    while True:
        raw_data, address = sock.recvfrom(65565)
        destination_mac_bytes, src_mac_bytes, eth_proto_id = struct.unpack(
            '! 6s 6s H', raw_data[:14]
        )

        destination_mac = get_mac_address_from_bytes(destination_mac_bytes)
        src_mac = get_mac_address_from_bytes(src_mac_bytes)
        eth_proto_id = socket.htons(eth_proto_id)
        eth_data = raw_data[14:]

        log('\nEthernet frame:')
        log(
            f'\tDestination: {destination_mac}, Source: {src_mac}, Ethernet Protocol: {eth_proto_id}'
        )

        try:
            ethernet_proto = EthernetProtocolsEnum(eth_proto_id)
        except ValueError:
            log(f"\tEthernet protocol {eth_proto_id} not recognized. Skipping")
            continue
        
        log(f"Detected ethernet protocol {ethernet_proto.name}")

        if ethernet_proto == EthernetProtocolsEnum.IPv4:
            header_len = (eth_data[0] & 15) * 4
            ipv4_data = eth_data[header_len:]
            version = header_len >> 4
            ttl, proto_id, src, target = struct.unpack(
                '! 8x B B 2x 4s 4s', eth_data[:20]
            )

            src = '.'.join(map(str, src))
            target = '.'.join(map(str, target))
            log('\tIPv4 packet:')
            log(f'\t\tVersion: {version}')
            log(f'\t\tHeader length: {header_len}')
            log(f'\t\tTTL: {ttl}')
            log(f'\t\tSource: {src}')
            log(f'\t\tTarget: {target}')
            log(f'\t\tProto ID: {proto_id}')

            try:
                protocol = ProtocolsEnum(proto_id)
            except ValueError:
                log(f"\t\tIPv4 protocol {proto_id} not recognized. Skipping")
                continue
            log(f"\t\tDetected IPv4 protocol: {protocol.name}")

            if protocol == ProtocolsEnum.UDP:
                source_port, target_port, size = struct.unpack('! H H 2x H', ipv4_data[:8])
                data = ipv4_data[8:]
                log(f'\t\t\tSource port: {source_port}')
                log(f'\t\t\tTarget port: {target_port}')
                log(f'\t\t\tSize: {size}')
                log(f'\t\t\tData: {format_binary_to_hex(data)}')


            if protocol == ProtocolsEnum.TCP:
                (
                    source_port,
                    target_port,
                    sequence,
                    acknowledgment,
                    flags,
                ) = struct.unpack('! H H L L H', ipv4_data[:14])
                offset = (flags >> 12) * 4
                flag_urg = (flags & 32) >> 5
                flag_ack = (flags & 16) >> 4
                flag_psh = (flags & 8) >> 3
                flag_rst = (flags & 4) >> 2
                flag_syn = (flags & 2) >> 1
                flag_fin = flags & 1
                tcp_data = raw_data[offset:]

                log(f'\t\t\tSource port: {source_port}')
                log(f'\t\t\tTarget port: {target_port}')
                log(f'\t\t\tSequence: {sequence}')
                log(f'\t\t\tAcknowledgment: {acknowledgment}')
                log(f'\t\t\tFlags: Urg: {flag_urg} | Ack: {flag_ack} | Psh: {flag_psh}')
                log(f'\t\t\t       Rst: {flag_rst} | Syn: {flag_syn} | Fin: {flag_fin}')
                log(f'\t\t\tData: {format_binary_to_hex(tcp_data)}')

