from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=0)[0]
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    print("Available devices:")
    print("IP" + " "*18+"MAC")
    for client in clients:
        print(f"{client['ip']:16s} {client['mac']}")

if __name__ == "__main__":
    scan_network("192.168.1.0/24")
