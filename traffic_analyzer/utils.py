from datetime import datetime


def format_time(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def validate_ip(ip):
    """
    Validate an IP address.

    :param ip: IP address to validate.
    :return: True if valid, False otherwise.
    """
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True


def sanitize_packet_data(data):
    """
    Sanitize packet data by removing non-printable characters.

    :param data: Packet data to sanitize.
    :return: Sanitized data.
    """
    return ''.join(c if 32 <= ord(c) < 127 else '?' for c in data)


def save_to_file(data, filename):
    """
    Save data to a file.

    :param data: Data to save.
    :param filename: Name of the file.
    """
    with open(filename, 'w') as file:
        file.write(data)


def load_from_file(filename):
    """
    Load data from a file.

    :param filename: Name of the file.
    :return: Loaded data.
    """
    with open(filename, 'r') as file:
        return file.read()
