import time
import argparse
import socket
import sys

from scapy.all import ARP, Ether, srp, send

# Parser Starter
parser = argparse.ArgumentParser(description='A tool to scan local network for active devices')

# Required Flags
parser.add_argument('-n', action="store", metavar="'192.168.1.1/24'", help="Network IP, 'xxx.xxx.xxx.xxx/xxx'", required=True)

# Opional Flags
parser.add_argument('-d', action="store_true", help='Attempt to display devices names', required=False)

# Parse arguments
args = parser.parse_args()

# Structure to hold individual network Node MAC & IP Address
class Node:
  def __init__(self, ip, mac):
    self.ip = ip
    self.mac = mac

# Takes network IP range and returns every device that responds to ARP request < 5s
def scan_network(target_network):
    arp = ARP(pdst=target_network)
    # Broadcast
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # List of Nodes
    network_devices = []

    packet = ether/arp
    result = srp(packet, timeout=5, verbose=1)[0]
    for sent, received in result:
        # Create new Node
        device = Node(received.psrc, received.hwsrc)
        # Append to list of Nodes
        network_devices.append(device)
    #Returns 'touple', where [1] = Network Gateway, and [0] = list of network devices
    return [ network_devices[1:], network_devices[0] ]

# Display network to terminal
def show_devices(network):
    # Get current users MAC address / Set gateway / Set network
    user = Node(0, Ether().src)
    gateway = network[1]
    network_devices = network[0]
    # Default device name
    device_name = "Unknown"

    print("Available devices in the network:")
    print("IP" + " "*18+"MAC" + " "*18+"Device Name")
    print("-"*60)
    print(":- {:16} {:18}   {:16}".format(gateway.ip, gateway.mac, "Gateway"))

    for device in network_devices:
        if(device.mac == user.mac):
            print(":- {:16} {:16}    {:16} ".format(device.ip, device.mac,"User"))
            user.ip = device.ip 
        else:
            if args.d:
                try:
                    # Try to resolve hostname
                    device_name = socket.gethostbyaddr(device.ip)
                    print(":- {:16} {:18}   {:16} ".format(device.ip, device.mac, device_name[0]))
                except:
                    # Couldn't find hostname
                    print(":- {:16} {:18}   {:16} ".format(device.ip, device.mac, "Unknown"))
            else:
                print(":- {:16} {:18} ".format(device.ip, device.mac))

def main():
    # Network to scan
    target_net = args.n
    # Returned network devices
    network = scan_network(target_net)
    # Display network
    show_devices(network)
        
main()
