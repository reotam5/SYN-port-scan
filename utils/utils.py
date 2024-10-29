import ipaddress
import argparse


def validateIp(value):
    try:
        ip = ipaddress.ip_address(str(value))
        if ip.version != 4:
            raise
        else:
            return str(value)
    except:
        raise argparse.ArgumentTypeError(
            "IP address has to be in a valid IPv4 format. Got '{value}'".format(
                value=value
            )
        )

def validatePort(value):
    try:
        port = int(value)
        if port >= 1 and port <= 65535:
            return port
        else:
            raise
    except:
        raise argparse.ArgumentTypeError(
            "Port number has to be an integer between 1 and 65535. Got '{value}'".format(
                value=value
            )
        )

def validatePositive(value):
    try:
        delay = float(value)
        if delay >= 0:
            return delay
        else:
            raise
    except:
        raise argparse.ArgumentTypeError(
            "Delay has to be a positive number. Got '{value}'".format(
                value=value
            )
        )
