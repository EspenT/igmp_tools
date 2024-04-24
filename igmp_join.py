import argparse
from scapy.all import sendp, IP, Ether, hexdump
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3gr, IGMPv3mr

def send_igmp_join(interface, multicast_ip, sources):
    """
    Send an IGMPv3 join with source filtering using Scapy.

    Args:
        interface (str): Network interface to use for sending the packet.
        multicast_ip (str): IP address of the multicast group to join.
        sources (list): List of source IP addresses to receive multicast data from.
    """
    # Create the Ethernet frame (optional, depending on your network setup)
    eth = Ether()

    # Create the IP layer
    ip = IP(dst="224.0.0.22")  # Typical destination for IGMP messages

    # Create the IGMPv3 Membership Report layer
    igmp = IGMPv3(type=0x22, mrcode=10)  # Membership Report

    # Create the IGMPv3 Group Records
    records = [IGMPv3gr(rtype=1, maddr=multicast_ip, numsrc=len(sources), srcaddrs=sources)]

    # Create the IGMPv3 Membership Report with group records
    membership_report = IGMPv3mr(numgrp=len(records), records=records)

    # Assemble the complete packet
    packet = eth / ip / igmp / membership_report

    # Show and send the packet
    packet.show()
    hexdump(packet)
    sendp(packet, iface=interface, verbose=True)

def main():
    parser = argparse.ArgumentParser(description="Send IGMPv3 Join Requests")
    parser.add_argument("interface", help="Network interface to send the packet")
    parser.add_argument("multicast_ip", help="Multicast group IP address")
    parser.add_argument("sources", nargs='+', help="Source IP addresses to receive multicast data from")

    args = parser.parse_args()

    # Call the function with the parsed arguments
    send_igmp_join(args.interface, args.multicast_ip, args.sources)

if __name__ == "__main__":
    main()
