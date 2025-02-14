from scapy.all import sniff  # Line 1

# Defining a function packet_capture with packet as a parameter
def packet_capture(packet):  # Line 4
    if packet.haslayer("IP"):  # Line 6
        print(f"Source IP: {packet['IP'].src} -> Destination IP: {packet['IP'].dst} | {packet.summary()}")  # Line 7
    else:  # Line 8
        print(packet.summary())  # Line 9

    # Prints a one-line summary of each packet
    print(packet.summary())  # Line 12

# Starts sniffing packets on the network interface
print("Starting Network sniffer ....")  # Line 15

# Capture packets in real-time and process them using packet_capture without storing them.
sniff(prn=packet_capture, store=False)  # Line 18
