import os
from flask import Flask, request, render_template
import pandas as pd
from scapy.all import rdpcap

app = Flask(__name__)

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
        
        # Get and return the counts as Pandas Series
        source_ip_counts = source_ip_counts['IP'].value_counts()
        destination_ip_counts = destination_ip_counts['IP'].value_counts()
        port_counts = port_counts['Port'].value_counts()
        protocol_counts = protocol_counts['Protocol'].value_counts()
        
        return source_ip_counts, destination_ip_counts, port_counts, protocol_counts
            
    except Exception as e:
        return None

@app.route("/", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        # Check if a file was submitted
        if "file" not in request.files:
            return render_template("index.html", message="No file part")
        
        file = request.files["file"]
        
        # Check if the file is empty
        if file.filename == "":
            return render_template("index.html", message="No selected file")
        
        # Check if the file is a PCAP file
        if not file.filename.endswith(".pcap"):
            return render_template("index.html", message="File must be in PCAP format (.pcap)")
        
        # Save the file temporarily
        file_path = os.path.join("uploads", file.filename)
        file.save(file_path)
        
        # Analyze the PCAP file
        results = analyze_pcap(file_path)
        
        if results is None:
            return render_template("index.html", message="An error occurred while analyzing the PCAP file.")
        
        return render_template("results.html", source_ips=results[0], destination_ips=results[1],
                               ports=results[2], protocols=results[3])
    
    return render_template("index.html", message=None)

if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
    app.run(debug=True)
