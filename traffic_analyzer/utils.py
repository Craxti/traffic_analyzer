from datetime import datetime
import ipaddress


def format_time(timestamp):
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def validate_ipv4(ip):
    """
    Validate an IPv4 address.

    :param ip: IPv4 address to validate.
    :return: True if valid, False otherwise.
    """
    parts = ip.split(".")
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


def validate_ipv6(ip):
    """
    Validate an IPv6 address.

    :param ip: IPv6 address to validate.
    :return: True if valid, False otherwise.
    """
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def validate_ip(ip):
    """
    Validate an IP address (IPv4 or IPv6).

    :param ip: IP address to validate.
    :return: True if valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_ip_version(ip):
    """
    Determine the version of an IP address.

    :param ip: IP address to check.
    :return: 4 for IPv4, 6 for IPv6, 0 if invalid.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version
    except ValueError:
        return 0


def sanitize_packet_data(data):
    """
    Sanitize packet data by removing non-printable characters.

    :param data: Packet data to sanitize.
    :return: Sanitized data.
    """
    # Special handling for common control characters
    result = ""
    for c in data:
        if 32 <= ord(c) < 127:
            result += c
        elif c == "\r":
            result += "\r"
        elif c == "\n":
            result += "\n"
        else:
            result += "?"
    return result


def save_to_file(data, filename):
    """
    Save data to a file.

    :param data: Data to save.
    :param filename: Name of the file.
    """
    with open(filename, "w") as file:
        file.write(data)


def load_from_file(filename):
    """
    Load data from a file.

    :param filename: Name of the file.
    :return: Loaded data.
    """
    with open(filename, "r") as file:
        return file.read()
