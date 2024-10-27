from enum import Enum
from time import sleep
from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import sr1
import datetime
from concurrent.futures import ThreadPoolExecutor


class PortState(Enum):
    OPEN = "Open"
    CLOSED = "Closed"
    FILTERED = "Filtered"


class PortScanner():
    def send_syn(self, targetIp: str, port: int, timeout = 2, retry = 1) -> PortState:
        ip = IP(dst=targetIp)
        tcp = TCP(dport=port, flags="S")
        print("\rScanning port: {port}".format(port = port), end='', flush=True)
        res = sr1(ip / tcp, timeout=timeout, verbose=False)
        if res:
            if res.haslayer(TCP):
                tcpRes = res.getlayer(TCP)
                if tcpRes and tcpRes.flags == "SA":
                    return PortState.OPEN
                elif tcpRes and "R" in tcpRes.flags:
                    return PortState.CLOSED
            if res.haslayer(ICMP):
                icmpRes = res.getlayer(ICMP)
                if icmpRes and icmpRes.type == 3:
                    return PortState.FILTERED

        if not res and retry:
            return self.send_syn(targetIp, port, timeout, retry - 1) 

        return PortState.FILTERED
    
    def scan(self, targetIp: str, start: int = 1, end: int = 65535, delay = 0):
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
    scanner = PortScanner()
    scanner.scan("10.0.0.58")




