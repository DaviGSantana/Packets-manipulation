from scapy.all import *
import ipaddress
import threading
import time
import pandas as pd
import logging
import os

log = logging.getLogger("scapy.runtime")
log.setLevel(logging.ERROR)

print_lock = threading.Lock()
NUM_IPS_PER_CHUNK = 10

def get_connected_devices_arp(ip, timeout=3):
    connected_devices = []
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    answered_list = srp(arp_request, timeout=timeout, verbose=False)[0]
    for element in answered_list:
        connected_devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc, "hostname": None, "vendor_id": None})
    return connected_devices

def get_connected_devices_icmp(ip, timeout=3):
    connected_devices = []
    icmp_packet = IP(dst=ip)/ICMP()
    response = sr1(icmp_packet, timeout=timeout, verbose=False)
    if response is not None:
        connected_devices.append({"ip": response.src, "mac": None, "hostname": None, "vendor_id": None})
    return connected_devices

def get_connected_devices_udp(ip, timeout=3):
    connected_devices = []
    udp_packet = IP(dst=ip)/UDP(dport=0)
    response = sr1(udp_packet, timeout=timeout, verbose=False)
    if response is not None:
        connected_devices.append({"ip": response.src, "mac": None, "hostname": None, "vendor_id": None})
    return connected_devices

def get_mac(ip, timeout=3):
    connected_device = get_connected_devices_arp(ip, timeout)
    if connected_device:
        try:
            return connected_device[0]["mac"]
        except (IndexError, KeyError):
            return None

def get_ip_subnet(subnet):
    ip_subnet = []
    for ip_int in ipaddress.IPv4Network(subnet):
        ip_subnet.append(str(ip_int))
    return ip_subnet

def get_gateway_subnet_netmask(iface):
    iface_name = iface.network_name if os.name == "nt" else iface
    routes = [route for route in conf.route.routes if route[3] == iface_name]
    subnet, gateway, netmask = None, None, None
    for route in routes:
        if route[2] != "0.0.0.0":
            gateway = route[2]
        elif str(ipaddress.IPv4Address(route[0])).endswith(".0"):
            subnet = str(ipaddress.IPv4Address(route[0]))
            netmask = str(ipaddress.IPv4Address(route[1]))
            break
    return gateway, subnet, netmask

def netmask_to_cidr(netmask):
    binary_str = ""
    for octet in netmask.split("."):
        binary_str += bin(int(octet))[2:].zfill(8)
    return str(len(binary_str.rstrip("0")))

def is_valid_subnet_cidr(subnet_cidr):
    try:
        subnet, cidr = subnet_cidr.split("/")
        if not 0 <= int(cidr) <= 32:
            return False
        ipaddress.IPv4Network(subnet_cidr)
        return True
    except ValueError:
        return False

def is_valid_ip_range(ip_range):
    try:
        start, end = ip_range.split("-")
        if not is_valid_ip(start) or not is_valid_ip(end):
            return False
        return True
    except ValueError:
        return False

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def ip_range_to_subnets(ip_range):
    start_ip, end_ip = ip_range.split("-")
    return [str(ip) for ip in ipaddress.summarize_address_range(ipaddress.IPv4Address(start_ip), ipaddress.IPv4Address(end_ip))]

class ARPScanner(threading.Thread):
    def __init__(self, subnets, timeout=3, interval=60):
        super().__init__()
        self.subnets = subnets
        self.timeout = timeout
        self.interval = interval
        self.name = f"ARPScanner-{subnets}-{timeout}-{interval}"
        self.connected_devices = []
        self.lock = threading.Lock()

    def run(self):
        try:
            while True:
                for subnet in self.subnets:
                    connected_devices = get_connected_devices_arp(subnet, self.timeout)
                    with self.lock:
                        self.connected_devices += connected_devices
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print(f"[-] Stopping {self.name}")
            return

class Scanner(threading.Thread):
    def __init__(self, subnets, timeout=3, interval=60):
        super().__init__()
        self.subnets = subnets
        self.timeout = timeout
        self.interval = interval
        self.connected_devices = []
        self.lock = threading.Lock()

    def get_connected_devices(self, ip_address):
        raise NotImplementedError("This method should be implemented in UDPScanner or ICMPScanner")

    def run(self):
        while True:
            for subnet in self.subnets:
                ip_addresses = get_ip_subnet(subnet)
                ip_addresses_chunks = [ip_addresses[i:i+NUM_IPS_PER_CHUNK] for i in range(0, len(ip_addresses), NUM_IPS_PER_CHUNK)]
                threads = []
                for ip_addresses_chunk in ip_addresses_chunks:
                    thread = threading.Thread(target=self.scan, args=(ip_addresses_chunk,))
                    threads.append(thread)
                    thread.start()
                for thread in threads:
                    thread.join()
                time.sleep(self.interval)

    def scan(self, ip_addresses):
        for ip_address in ip_addresses:
            connected_devices = self.get_connected_devices(ip_address)
            with self.lock:
                self.connected_devices += connected_devices

class ICMPScanner(Scanner):
    def __init__(self, subnets, timeout=3, interval=60):
        super().__init__(subnets, timeout, interval)
        self.name = f"ICMPScanner-{subnets}-{timeout}-{interval}"

    def get_connected_devices(self, ip_address):
        return get_connected_devices_icmp(ip_address, self.timeout)

class UDPScanner(Scanner):
    def __init__(self, subnets, timeout=3, interval=60):
        super().__init__(subnets, timeout, interval)
        self.name = f"UDPScanner-{subnets}-{timeout}-{interval}"

    def get_connected_devices(self, ip_address):
        return get_connected_devices_udp(ip_address, self.timeout)

class PassiveSniffer(threading.Thread):
    def __init__(self, subnets):
        super().__init__()
        self.subnets = subnets
        self.connected_devices = []
        self.lock = threading.Lock()
        self.networks = [ipaddress.IPv4Network(subnet) for subnet in self.subnets]
        self.stop_sniff = threading.Event()

    def run(self):
        sniff(prn=self.process_packet, store=0, stop_filter=self.stop_sniffer)

    def process_packet(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            if self.is_ip_in_network(src_ip):
                src_mac = packet[Ether].src
                device = {"ip": src_ip, "mac": src_mac, "hostname": None, "vendor_id": None}
                if device not in self.connected_devices:
                    with self.lock:
                        self.connected_devices.append(device)
            if packet.haslayer(DHCP):
                target_mac, requested_ip, hostname, vendor_id = [None] * 4
                if packet.haslayer(Ether):
                    target_mac = packet.getlayer(Ether).src
                dhcp_options = packet[DHCP].options
                for item in dhcp_options:
                    try:
                        label, value = item
                    except ValueError:
                        continue
                    if label == "requested_addr":
                        requested_ip = value
                    elif label == "hostname":
                        hostname = value.decode()
                    elif label == "vendor_class_id":
                        vendor_id = value.decode()
                device = {"ip": requested_ip, "mac": target_mac, "hostname": hostname, "vendor_id": vendor_id}
                if device not in self.connected_devices:
                    with self.lock:
                        self.connected_devices.append(device)

    def is_ip_in_network(self, ip):
        for network in self.networks:
            if ipaddress.IPv4Address(ip) in network:
                return True
        return False

    def join(self):
        self.stop_sniff.set()
        super().join()

    def stop_sniffer(self, packet):
        return self.stop_sniff.is_set()

class NetworkScanner(threading.Thread):
    def __init__(self, subnets, timeout=3, **kwargs):
        super().__init__()
        self.subnets = subnets
        self.timeout = timeout
        self.daemon = True
        self.connected_devices = pd.DataFrame(columns=["ip", "mac"])
        self.arpscanner_interval = kwargs.get("arpscanner_interval", 60)
        self.udpscanner_interval = kwargs.get("udpscanner_interval", 60)
        self.icmpscanner_interval = kwargs.get("icmpscanner_interval", 60)
        self.interval = kwargs.get("interval", 5)
        self.lock = threading.Lock()
        self.threads = []

    def run(self):
        connected_devices = pd.DataFrame(columns=["ip", "mac"])
        if self.arpscanner_interval:
            thread = ARPScanner(self.subnets, self.timeout, self.arpscanner_interval)
            self.threads.append(thread)
            thread.start()
        if self.udpscanner_interval:
            thread = UDPScanner(self.subnets, self.timeout, self.udpscanner_interval)
            self.threads.append(thread)
            thread.start()
        if self.icmpscanner_interval:
            thread = ICMPScanner(self.subnets, self.timeout, self.icmpscanner_interval)
            self.threads.append(thread)
            thread.start()
        if self.interval:
            thread = PassiveSniffer(self.subnets)
            self.threads.append(thread)
            thread.start()
        while True:
            time.sleep(self.interval)
            with self.lock:
                connected_devices = pd.DataFrame(self.collect_data(), columns=["ip", "mac"])
            print(connected_devices)
            print(f"Connected devices count: {len(connected_devices)}")

    def collect_data(self):
        connected_devices = []
        for thread in self.threads:
            if isinstance(thread, (ARPScanner, UDPScanner, ICMPScanner)):
                connected_devices.extend(thread.connected_devices)
            elif isinstance(thread, PassiveSniffer):
                connected_devices.extend(thread.connected_devices)
        return connected_devices

    def stop(self):
        for thread in self.threads:
            thread.join()
