import pandas as pd
from scapy.all import rdpcap

def analyze_pcap(pcap_file):
    try:
        # Read the PCAP file
        packets = rdpcap(pcap_file)
        
        # Initialize Pandas DataFrames to store counts
        source_ip_counts = pd.DataFrame(columns=["IP", "Count"])
        destination_ip_counts = pd.DataFrame(columns=["IP", "Count"])
        port_counts = pd.DataFrame(columns=["Port", "Count"])
        protocol_counts = pd.DataFrame(columns=["Protocol", "Count"])
        
        # Iterate through the packets in the PCAP file
        for packet in packets:
            if packet.haslayer('IP'):
                ip_layer = packet['IP']
                
                # Count source IPs
                source_ip = ip_layer.src
                source_ip_counts = source_ip_counts.append({"IP": source_ip}, ignore_index=True)
                
                # Count destination IPs
                dest_ip = ip_layer.dst
                destination_ip_counts = destination_ip_counts.append({"IP": dest_ip}, ignore_index=True)
                
                # Count protocols
                protocol = ip_layer.proto
                protocol_counts = protocol_counts.append({"Protocol": protocol}, ignore_index=True)
                
            if packet.haslayer('TCP'):
                tcp_layer = packet['TCP']
                
                # Count unique ports
                port = tcp_layer.dport
                port_counts = port_counts.append({"Port": port}, ignore_index=True)
        
        # Display the results using Pandas
        print("Source IP Counts:")
        print(source_ip_counts['IP'].value_counts())
        
        print("\nDestination IP Counts:")
        print(destination_ip_counts['IP'].value_counts())
        
        print("\nPort Counts:")
        print(port_counts['Port'].value_counts())
        
        print("\nProtocol Counts:")
        print(protocol_counts['Protocol'].value_counts())
            
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    pcap_file = input("Enter the path to the PCAP file: ")
    analyze_pcap(pcap_file)
