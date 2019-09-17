# _*_ coding:utf-8 _*_
__author__ = "JuneZhu"
__date__ = "2019/9/17 14:17"

def host_is_ipv6(hostname):
    """
    Detect (naively) if the hostname is an IPV6 host.
    Return a boolean.
    """
    # empty strings or anything that is not a string is automatically not an
    # IPV6 address
    if not hostname or not isinstance(hostname, str):
        return False

    if hostname.startswith('['):
        return True

    if len(hostname.split(':')) > 2:
        return True

    # Anything else that doesn't start with brackets or doesn't have more than
    # one ':' should not be an IPV6 address. This is very naive but the rest of
    # the connection chain should error accordingly for typos or ill formed
    # addresses
    return False
def parse_host(hostname):
    """
    Given a hostname that may have a port name, ensure that the port is trimmed
    returning only the host, including hostnames that are IPV6 and may include
    brackets.
    """
    # ensure that hostname does not have any whitespaces
    hostname = hostname.strip()

    if host_is_ipv6(hostname):
        return hostname.split(']:', 1)[0].strip('[]')
    else:
        return hostname.split(':', 1)[0]
