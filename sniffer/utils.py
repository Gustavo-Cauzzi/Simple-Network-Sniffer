import re
from sniffer.constants import OUTPUT_FILE


def get_mac_address_from_bytes(bytes_string):
    bytes_string = map('{:02x}'.format, bytes_string)
    destination_mac = ':'.join(bytes_string).upper()
    return destination_mac


def log(*args, clear=False):
    '''
    Prints to the console and logs into the main output file
    '''
    print(*args)
    with open(OUTPUT_FILE, 'w' if clear else "a") as file:
        file.write(''.join(args) + '\n')


def format_binary_to_hex(b_string):
    return ' '.join(re.findall('..', b_string.hex().upper()))
