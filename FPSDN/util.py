import networkx as nx
import os
import random
import matplotlib.pyplot as plt
import json



def write_log(openflow_packets, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    all_openflow_messages = open(path, "w")
    for idx, packet in enumerate(openflow_packets, 1):
        all_openflow_messages.write(f"\nPacket {idx}:\n")
        for field, value in packet.items():
            all_openflow_messages.write(f"{field}: {value}\n")
        all_openflow_messages.write("\n----------\n")

def Save_Json(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


def merge_two_dicts(x, y):
    z = x.copy()
    z.update(y)
    return z

def is_json(fpath):
    return len(fpath) > 5 and fpath[-5:] == ".json"

def is_exe(fpath):
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)


def save_topo_graph(topo, ports,path):
    G = topo
    color_map = []
    for node in list(G.nodes()):
        if G.nodes[node]["type"] == "host":
            color_map.append('pink')
        else: 
            color_map.append('lightblue')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    # Prepare edge labels with port information
    edge_labels = {}
    checker = []
    edge_checker = []
    for edge in G.edges():
        src, dst = edge
        reverse_edge = (dst, src)
        if edge not in edge_checker and reverse_edge not in edge_checker and (src, dst) in ports and (dst, src) in ports:
            edge_labels[edge] = f"{ports[(src, dst)]}--{ports[(dst, src)]}"
            edge_checker.append(edge)
            edge_checker.append(reverse_edge)
        elif edge not in edge_checker and reverse_edge not in edge_checker and (src, dst) in ports:
            edge_labels[edge] = f"{ports[(src, dst)]}"
            edge_checker.append(edge)
            edge_checker.append(reverse_edge)
    
    seed = 50
    random.seed(seed)
    
    pos = nx.spring_layout(G, seed=seed) 
    # pos = nx.spring_layout(G)  # Define the layout for better visualization

    plt.figure(figsize=(15, 12))
    # Draw the nodes and edges
    nx.draw(G, pos, node_color=color_map, with_labels=True, node_size=700, font_size=16)

    
    # Draw edge labels
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=13, label_pos=0.5)
    plt.axis('off')
    plt.savefig(path, format="PNG")
    plt.close()  # Close the figure to free up resources




def sort_packets(packets_cap):
    # Sort packets based on packet_in and corresponding response after that
    packets = packets_cap
    
    sorted_packets = []
    matched_flow_mod_packet = []
    matched_packet_out = []
    
    for i in range(len(packets)):
        if int(packets[i].openflow_v1.openflow_1_0_type) == 10 and packets[i].openflow_v1.get_field_value("eth.dst").split(":")[0] == "00": # PACKET_IN
            packet_in = packets[i]
            for j in range(i+1, len(packets)):
                response_packet = packets[j]

                if (int(response_packet.openflow_v1.openflow_1_0_type) == 14) and (not(j in matched_flow_mod_packet)): # FLOW_MOD
                    matched_flow_mod_packet.append(j)
                    sorted_packets.append(packet_in)
                    sorted_packets.append(response_packet)
                    break
                elif (int(response_packet.openflow_v1.openflow_1_0_type) == 13) and (not(j in matched_packet_out)): # PACKET_OUT ---> Drop or forward ?
                    matched_packet_out.append(j)
    return sorted_packets