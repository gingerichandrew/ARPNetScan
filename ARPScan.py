from scapy.all import ARP, Ether, srp, send
import time

# Structure to hold individual network Node MAC & IP Address
class Node:
  def __init__(self, ip, mac):
    self.ip = ip
    self.mac = mac

# Takes network IP range and returns every device that responds to ARP request < 5s
def scan_network(target_network):
    arp = ARP(pdst=target_network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    network_devices = []

    packet = ether/arp
    result = srp(packet, timeout=5, verbose=0)[0]

    for sent, received in result:
        device = Node(received.psrc, received.hwsrc)
        network_devices.append(device)

    return [ network_devices[1:], network_devices[0] ]

# Display network to terminal
def show_devices(network):
    # Get current users MAC address / Set gateway / Set network
    attacker = Node(0, Ether().src)
    gateway = network[1]
    network_devices = network[0]

    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    print("| {:16}    {} - {} ".format(gateway.ip, gateway.mac, "Gateway"))

    i = 0 
    for device in network_devices:
        if(device.mac == attacker.mac):
            print("| {:16}    {} - {} ".format(device.ip, device.mac,"You"))
            attacker.ip = device.ip 
            i = i + 1
        else:
            print("| {:16}    {} |".format(device.ip, device.mac))
            i = i + 1

def main():
    # Network to scan
    target_net = "192.168.1.1/24"
    # Returned network devices
    network = scan_network(target_net)
    # Display network
    show_devices(network)

        
main()
