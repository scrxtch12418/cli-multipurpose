import re
import ipaddress

def is_valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_ipv6(ip):
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def is_valid_domain(domain):
    # Regular expression for validating a domain name
    regex = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
    return re.match(regex, domain) is not None

def is_valid_target(target):
    return is_valid_ipv4(target) or is_valid_ipv6(target) or is_valid_domain(target)
