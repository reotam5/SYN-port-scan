from enum import Enum
from utils.utils import validateIp, validatePort, validatePositive
from time import sleep
from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import sr1
import datetime
from concurrent.futures import ThreadPoolExecutor
import argparse


class PortState(Enum):
    OPEN = "Open"
    CLOSED = "Closed"
    FILTERED = "Filtered"
    UNKNOWN = "Unknown"


class PortScanner():
    def send_syn(self, targetIp: str, port: int, timeout = 2, retry = 1) -> PortState:
        ip = IP(dst=targetIp)
        tcp = TCP(dport=port, flags="S")
        print("\rScanning port: {port}    ".format(port = port), end='', flush=True)
        res = sr1(ip / tcp, timeout=timeout, verbose=False)
        if res == None:
            if retry:
                return self.send_syn(targetIp, port, timeout, retry - 1) 
            else:
                return PortState.FILTERED
        else:
            if res.haslayer(TCP):
                tcpRes = res.getlayer(TCP)
                if tcpRes and tcpRes.flags == "SA":
                    return PortState.OPEN
                elif tcpRes and "R" in tcpRes.flags:
                    return PortState.CLOSED
            if res.haslayer(ICMP):
                icmpRes = res.getlayer(ICMP)
                if icmpRes and icmpRes.type == 3 and icmpRes.code in [1, 2, 3, 9, 10, 13]:
                    return PortState.FILTERED
        return PortState.UNKNOWN


    def is_up(self, targetIp: str, timeout = 2):
        ip = IP(dst=targetIp)
        icmp = ICMP()
        res = sr1(ip / icmp, timeout = timeout, verbose = False)
        if res and res.haslayer(ICMP):
            icmpRes = res.getlayer(ICMP)
            if icmpRes:
                if icmpRes and icmpRes.type == 0 and icmpRes.code == 0:
                    return True
        return False


    def scan(self, targetIp: str, start: int = 1, end: int = 65535, delay = 0):
        if not self.is_up(targetIp):
            print("Target seems down.")
            return

        openPorts = []
        closedPorts = 0
        filteredPorts = 0
        total = end - start + 1 
        startTime = datetime.datetime.now()

        with ThreadPoolExecutor() as executor:
            futures = {}
            for p in range(start, end + 1):
                futures[p] = executor.submit(self.send_syn, targetIp, p)
                if delay:
                    sleep(delay / 1000)
            
            executor.shutdown(wait = True)

            for port in futures:
                port_state = futures[port].result()
                if port_state == PortState.OPEN:
                    openPorts.append(port)
                elif port_state == PortState.FILTERED:
                    filteredPorts += 1
                elif port_state == PortState.CLOSED:
                    closedPorts += 1


        print("\rScanned {total} ports in {time} seconds".format(total = total, time = (datetime.datetime.now() - startTime).total_seconds()))
        print("Found {open} open ports".format(open = len(openPorts)))
        print("Found {closed} closed ports".format(closed = closedPorts))
        print("Found {filtered} filtered ports\n".format(filtered = filteredPorts))

        if len(openPorts) > 0:
            print("Open ports:")
            for p in openPorts:
                print(p)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SYN scan ports on a specified host.")
    parser.add_argument(
        "targetIp",
        help="IP address of a machine to perform SYN scan against",
        type=validateIp
    )
    parser.add_argument(
        "--start",
        required=False,
        help="Optionally specify the start port range to SYN scan. Defaults to 1",
        type=validatePort,
        default=1
    )
    parser.add_argument(
        "--end",
        required=False,
        help="Optionally specify the end port range to SYN scan. Defaults to 65535",
        type=validatePort,
        default=65535
    )
    parser.add_argument(
        "--delay",
        required=False,
        help="Optionally specify the delay between each scan in milliseconds. Defaults to 0",
        type=validatePositive,
        default=0
    )

    args = parser.parse_args()

    if args.start != None and args.end != None:
        if args.start > args.end:
            parser.error("--start cannot be larger than --end")


    scanner = PortScanner()
    scanner.scan(args.targetIp, args.start, args.end, args.delay)

