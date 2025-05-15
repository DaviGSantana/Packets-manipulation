from scapy.all import *
from threading import Thread
from faker import Faker


def send_beacon(ssid, mac, infinite=True):
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)

    beacon = Dot11Beacon()

    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))

    frame = RadioTap()/dot11/beacon/essid

    if infinite:
        sendp(frame, inter=0.1, loop=1, iface=iface, verbose=0)
    else:
        sendp(frame, iface=iface, verbose=0)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Fake Access Point Generator")
    parser.add_argument("interface", default="wlan0mon", help="The interface to send beacon frames with, must be in monitor mode")
    parser.add_argument("-n", "--access-points", type=int, dest="n_ap", help="Number of access points to be generated")
    args = parser.parse_args()
    n_ap = args.n_ap
    iface = args.interface

    faker = Faker()

    ssids_macs = [ (faker.name(), faker.mac_address()) for i in range(n_ap) ]
    for ssid, mac in ssids_macs:

    Thread(target=send_beacon, args=(ssid, mac)).start()
