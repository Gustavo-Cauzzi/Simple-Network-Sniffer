import socket
from enum import Enum

from sniffer.constants import PROTOCOL_KEYS_PREFIX


protocols_id_by_name = dict(
    (
        key[len(PROTOCOL_KEYS_PREFIX) :],
        getattr(socket, key),
    )
    for key in dir(socket)
    if key.startswith(PROTOCOL_KEYS_PREFIX)
)
protocols_name_by_id = {value: key for key, value in protocols_id_by_name.items()}


class ProtocolsEnum(Enum):
    AH = protocols_id_by_name['AH']
    DSTOPTS = protocols_id_by_name['DSTOPTS']
    EGP = protocols_id_by_name['EGP']
    ESP = protocols_id_by_name['ESP']
    FRAGMENT = protocols_id_by_name['FRAGMENT']
    GRE = protocols_id_by_name['GRE']
    IP = protocols_id_by_name['IP']
    ICMP = protocols_id_by_name['ICMP']
    ICMPV6 = protocols_id_by_name['ICMPV6']
    IDP = protocols_id_by_name['IDP']
    IGMP = protocols_id_by_name['IGMP']
    IPIP = protocols_id_by_name['IPIP']
    IPV6 = protocols_id_by_name['IPV6']
    NONE = protocols_id_by_name['NONE']
    PIM = protocols_id_by_name['PIM']
    PUP = protocols_id_by_name['PUP']
    RAW = protocols_id_by_name['RAW']
    ROUTING = protocols_id_by_name['ROUTING']
    RSVP = protocols_id_by_name['RSVP']
    SCTP = protocols_id_by_name['SCTP']
    TCP = protocols_id_by_name['TCP']
    TP = protocols_id_by_name['TP']
    UDP = protocols_id_by_name['UDP']


class EthernetProtocolsEnum(Enum):
    IPv4 = 8
    # TODO: add more protocols if necessary
