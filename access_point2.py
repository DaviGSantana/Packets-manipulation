from scapy.all import *
from faker import Faker

def send_beacon(ssid, mac, iface, infinite=True):
    
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
    
    parser = argparse.ArgumentParser(description="Subir um ponto de acesso falso (Fake AP)")
    parser.add_argument("interface", default="wlan0mon", help="A interface a ser usada para enviar pacotes beacon, deve estar em modo monitor")
    parser.add_argument("ssid", help="Nome da rede Wi-Fi (SSID) do ponto de acesso falso")
    parser.add_argument("mac", help="Endereço MAC do ponto de acesso falso")
    args = parser.parse_args()

    iface = args.interface
    ssid = args.ssid
    mac = args.mac

    print(f"Subindo ponto de acesso falso com SSID: {ssid} e MAC: {mac} na interface {iface}...")
    send_beacon(ssid, mac, iface)


"""
sudo ip link set wlan0mon type monitor
python3 fake_ap.py wlan0mon "MinhaRede" "00:11:22:33:44:55"
"""