import os
import pyshark
import pickle
import json
import networkx as nx
import matplotlib.pyplot as plt
from collections import OrderedDict
import itertools as it
import subprocess
from time import perf_counter
import gc


def find_partial_topology(log_file_path):
    try:
        with pyshark.FileCapture(log_file_path, display_filter='openflow_v1') as cap:
            packets_cap = []
            ipsrc_ipdst_sw_type_packet_checker = []
        
            numberofins = 0
            numberofflowmods = 0

            for packet in cap:
                if int(packet.openflow_v1.openflow_1_0_type) == 10 and packet.openflow_v1.get_field_value("ip.src") != None:
                    src_dst_sw_type = packet.openflow_v1.get_field_value("ip.src") + "_" + packet.openflow_v1.get_field_value("ip.dst") + "_" + packet.tcp.get_field_value("tcp.srcport") + "_" + str(packet.openflow_v1.openflow_1_0_type)
                    # print(src_dst_sw_type)
                    if src_dst_sw_type not in ipsrc_ipdst_sw_type_packet_checker:
                        ipsrc_ipdst_sw_type_packet_checker.append(src_dst_sw_type)
                        packets_cap.append(packet)
                        numberofins += 1
                elif int(packet.openflow_v1.openflow_1_0_type) == 14 and packet.openflow_v1.get_field_value("openflow.ofp_match.source_addr").split(".")[0] == "10" and int(packet.openflow_v1.get_field_value("openflow.ofp_match.dl_type")) != 2054:
                    src_dst_sw_type = packet.openflow_v1.get_field_value("openflow.ofp_match.source_addr") + "_" + packet.openflow_v1.get_field_value("openflow.ofp_match.dest_addr") + "_" + packet.tcp.get_field_value("tcp.dstport") + "_" + str(packet.openflow_v1.openflow_1_0_type)
                    # print(src_dst_sw_type)
                    if src_dst_sw_type not in ipsrc_ipdst_sw_type_packet_checker:
                        ipsrc_ipdst_sw_type_packet_checker.append(src_dst_sw_type)
                        packets_cap.append(packet)
                        numberofflowmods += 1
            G = nx.DiGraph()

            number_devices = 0

            for packet in packets_cap:
                if int(packet.openflow_v1.openflow_1_0_type) == 10:
                    flag_add_edge = False
        
                    host_ip = packet.openflow_v1.get_field_value("ip.src")
                    host_ip = host_ip.split(".")[-1]
                    switch = packet.tcp.get_field_value("tcp.srcport")
                    controller = packet.tcp.get_field_value("tcp.dstport")

                    if not(switch in G):
                        G.add_node(switch, type='switch', controller = controller)
                        number_devices+=1
                    if not(host_ip in G):
                        G.add_node(host_ip, type='host')
                        number_devices+=1
                        flag_add_edge = True

                    if flag_add_edge: 
                        G.add_edge(switch, host_ip)
                        G.add_edge(host_ip,switch)

        # print(packets_cap[0])
        # print("......................................")
        # print(packets_cap[1])
    except FileNotFoundError:
        print(f"Couldn't find the file: {log_file_path}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None
    
    return packets_cap, G

def find_topo(partial_topo, packets):
    G = partial_topo
    switches_links = []
    for i in range(1,len(packets)-2,2):
        s1, s2 = packets[i]["to_switch"], packets[i+2]["to_switch"]
        src1, dst1 = find_src_dst(packets[i])
        src2, dst2 = find_src_dst(packets[i+2])
        if s1 != s2 and src1 == src2 and dst1 == dst2:
            link = [s1,s2]
            switches_links.append(link)

    G.add_edges_from(switches_links)
    
    return G

def save_topo_graph(topo, ports,path):
    # G = topo
    # color_map = []
    # for node in list(G.nodes()):
    #     if G.nodes[node]["type"] == "host":
    #         color_map.append('blue')
    #     else: 
    #         color_map.append('red')
    
    # os.makedirs(os.path.dirname(path), exist_ok=True)
    # pos = nx.spring_layout(G)
    # nx.draw(G, node_color=color_map, with_labels=True)
    # nx.draw_networkx_edge_labels(G, pos, edge_labels=ports, font_color='red')
    # plt.savefig(path, format="PNG")
    G = topo
    color_map = []
    for node in list(G.nodes()):
        if G.nodes[node]["type"] == "host":
            color_map.append('blue')
        else: 
            color_map.append('red')
    
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    pos = nx.spring_layout(G)  # Define the layout for better visualization

    plt.figure(figsize=(12, 8))
    # Draw the nodes and edges
    nx.draw(G, pos, node_color=color_map, with_labels=True, node_size=500, font_size=10)
    
    # Prepare edge labels with port information
    edge_labels = {}
    checker = []
    for edge in G.edges():
        # TODO BUG
        # print(edge)
        # Ports are typically given for both directions
        src, dst = edge
        if (src, dst) in ports and (dst, src) in ports:
            if f"{ports[(dst, src)]}-------{ports[(src, dst)]}" not in checker:
                edge_labels[edge] = f"{ports[(dst, src)]}-------{ports[(src, dst)]}"
                checker.append(f"{ports[(src, dst)]}-------{ports[(dst, src)]}")
        elif (src, dst) in ports:
            edge_labels[edge] = f"{ports[(src, dst)]}"
        elif (dst, src) in ports:
            edge_labels[edge] = f"{ports[(dst, src)]}"
    
    # Draw edge labels
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=10, label_pos=0.5)
    
    plt.savefig(path, format="PNG")
    plt.close()  # Close the figure to free up resources


def list_of_hosts(topo_graph):
    hosts = []
    for node in list(topo_graph.nodes()):
        if topo_graph.nodes[node]["type"] == "host":
            hosts.append(node)
    return hosts


def number_of_hosts(topo_graph):
    return len(list_of_hosts(topo_graph))


def list_of_switches(topo_graph):
    switches = []
    for node in list(topo_graph.nodes()):
        if topo_graph.nodes[node]["type"] == "switch":
            switches.append(node)
    return switches

def number_of_switches(topo_graph):
    return len(list_of_switches(topo_graph))    


def allocate_ports(topo):
    n_hosts = number_of_hosts(topo)
    port_counter_for_switches = n_hosts + 1
    counter = 1
    ports = {}
    for node in list(topo.nodes()):
        if topo.nodes[node]["type"] == "switch":
            for n in topo.neighbors(node):
                ports[(node,n)] = counter 
                counter += 1
                # if topo.nodes[n]["type"] == "host":
                #     ports[(node,n)] = n
                # else:
                #     ports[(node,n)] = port_counter_for_switches
                #     port_counter_for_switches +=1
    # print("ports: ", ports)
    return ports

def string_topo(topo,ports):
    l = [] 
    for k in ports.keys():
        s1 , s2 = k[0], k[1]
        if (s2,s1) in ports.keys():
            t = "(pt = " + str(ports[(s1,s2)]) + " . pt <- " + str(ports[(s2,s1)]) +")"
        elif (topo.nodes[s1]["type"] == "switch" and topo.nodes[s2]["type"] == "host"):
            t = "(pt = " + str(ports[(s1,s2)]) +")"
        elif (topo.nodes[s2]["type"] == "switch" and topo.nodes[s1]["type"] == "host"):
            t = "(pt = " + str(ports[(s2,s1)]) +")"
        l.append(t)
    topo = "(" + " + ".join(l) + ")"
    return topo
    
def sorted_packets(packets_cap):
    # Sort packets based on packet_in and corresponding response after that


    # Convert capture to a list to allow indexing
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

def pre_processing(packets_cap):
    # packets = sorted_packets(packets_cap) 
 
    packets = packets_cap
    # print(len(packets))  

    
    # important_fields = ["openflow_1_0.type", "openflow.xid", "openflow.in_port", "openflow.eth_src",
    #                 "openflow.eth_dst", "openflow.dl_vlan", "openflow.ofp_match.dl_type", "openflow.ofp_match.nw_proto", 
    #                 "openflow.ofp_match.source_addr", "openflow.ofp_match.dest_addr", "openflow.ofp_match.source_port",
    #                 "openflow.ofp_match.dest_port", "openflow.command", "openflow.reason", "openflow.priority", "eth.src", "eth.dst",
    #                 "openflow.action_typ"]

    important_fields = ["openflow_1_0.type", "openflow.xid", "openflow.eth_src",
                    "openflow.eth_dst", "openflow.ofp_match.source_addr", 
                    "openflow.ofp_match.dest_addr", "eth.src", "eth.dst", "ip.src", "ip.dst"]


    packets_info = []
    
    for packet in packets:
        packet_info = {}

        if int(packet.openflow_v1.openflow_1_0_type) == 10:
            switch = packet.tcp.get_field_value("tcp.srcport")
            controller = packet.tcp.get_field_value("tcp.dstport")
            packet_info["to_switch"] = switch
            packet_info["to_controller"] = controller
        else:
            controller = packet.tcp.get_field_value("tcp.srcport")
            switch = packet.tcp.get_field_value("tcp.dstport")
            packet_info["to_switch"] = switch
            packet_info["to_controller"] = controller
        
        for field in packet.openflow_v1._all_fields:
                        if field in important_fields:
                            field_value = packet.openflow_v1.get_field_value(field)
                            packet_info[field] = field_value

        packets_info.append(packet_info)

    result = [] # List of packets
    i = 0

    # remove duplicated packets_in and their responses.
    while i < len(packets_info):
        if not packets_info[i] in result:
            result.append(packets_info[i])
            i += 1
        else:
            i += 2

    return result

def write_log(openflow_packets, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    all_openflow_messages = open(path, "w")
    for idx, packet in enumerate(openflow_packets, 1):
        all_openflow_messages.write(f"\nPacket {idx}:\n")
        for field, value in packet.items():
            all_openflow_messages.write(f"{field}: {value}\n")
        all_openflow_messages.write("\n----------\n")

def find_src_dst(packet):
    try:
        src = packet["ip.src"]
        dst = packet["ip.dst"]
    except:
        src = packet["openflow.ofp_match.source_addr"]
        dst = packet["openflow.ofp_match.dest_addr"]
    return src,dst

def find_match_rules(packet):
    match_src = packet["openflow.ofp_match.source_addr"]
    match_dst = packet["openflow.ofp_match.dest_addr"]
    return match_src,match_dst

def Save_Json(data, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

def change_controller(C, ch1, ch2, m):
    if C == "":
        return "((" + ch1 + " ? \"one\") ; ((" + ch2 + ' ! "' + m + '") ; ' + "C))"
    else: 
        return C + " o+ ((" + ch1 + " ? \"one\") ; ((" + ch2 + ' ! "' + m + '") ; ' + "C))"


def calculate_recursive_variables(initial_policy, topology, flow_tables, C):
    rec_var_name = "D"
    rec_var_def = '"((@Pol) . ({})) *" ; @IRV o+ @sum'.format(topology)
    
    
    merged_dict = {}
    for k, v in flow_tables.items():
        id_list = []
        for i, x in enumerate(v):
            id_list.append(k + "-" + str(i+2))
        id_list.insert(0, k + "-1")
        merged_dict[k] = id_list

    combinations = list(it.product(*(merged_dict[x] for x in merged_dict.keys())))

    # print(merged_dict)
    channels = []
    id_dict = {}
    comms = {}
    for k, v in merged_dict.items():
        flow_iteration = 1
        for x in v:
            number = int(x.rsplit("-")[1])
            if number == 1:
                id_dict[x] = initial_policy[k]
                
            else:
                comms[x] = (k + "Up" + "flow" + str(flow_iteration), flow_tables[k][number-2], k + "Req" + "flow" + str(flow_iteration))
                flow_iteration += 1
                C = change_controller(C, comms[x][2], comms[x][0], comms[x][1])
                channels.append(comms[x][2])
                channels.append(comms[x][0])
                id_dict[x] = flow_tables[k][number-2]
    
    output = {}
    counter = 1

    for x in combinations:
        current_var = rec_var_name + "-" + str(counter)
        counter += 1

        args = []
        for i in x:
            args.append(id_dict[i])
        initial_term = ' + '.join(args)


        comm = []
        for i, v in comms.items():
            find_term = []
            for j in x:
                if j.rsplit('-')[0] != i.rsplit('-')[0]:
                    find_term.append(j)
                else:
                    find_term.append(i)
            index = combinations.index(tuple(find_term))
            one = "one"
            comm.append("(" + v[2] + ' ! "' + one + '") ; {}'.format(current_var))
            comm.append("(" + v[0] + ' ? "' + v[1] + '") ; {}-{}'.format(rec_var_name, index + 1))
        output[current_var] = rec_var_def.replace("@Pol", initial_term).replace("@IRV", current_var).replace("@sum", ' o+ '.join(comm))
    return output, C, channels

def merge_two_dicts(x, y):
    z = x.copy()
    z.update(y)
    return z

def find_events(packets):
    events = {}
    event_counter = 1
    i = 0
    while i < len(packets)-1:
        j = i +1
        while j < len(packets):
            src1, dst1 = find_src_dst(packets[j-1])
            src2, dst2 = find_src_dst(packets[j])
            if src1 == src2 and dst1 == dst2:
                j+=1
            else:
                break
        events["event-"+str(event_counter)] = packets[i:j]
        event_counter += 1
        i = j
    return events


def construct_rule(p1, p2):
    return "pt = {} . pt <- {}".format(p1, p2)


def path_event(event):
    path = []
    l = len(event)
    for i in range(0, l, 2):
        if i == 0:
            path.append(event[i]["ip.src"].split(".")[-1])
            path.append(event[i]["to_switch"])
        elif i != 0 and i != l-2:
            path.append(event[i]["to_switch"])
        else:
            path.append(event[i]["to_switch"])
            path.append(event[i]["ip.dst"].split(".")[-1])
    return path

def DyNetKAT(topo_graph, packets, expriment_name):
    switches = list_of_switches(topo_graph)
    hosts = list_of_hosts(topo_graph)
    n_switch = number_of_switches(topo_graph)
    
    ports = allocate_ports(topo_graph)
    topo_str = string_topo(topo_graph, ports)
    topology = topo_str
    # topology = "TOPO"
    # print("ports: ", ports)
    # topology = "((pt = 1) + (pt = 2 . pt <- 5) + (pt = 4 . pt <- 7) + (pt = 6))"
    print("topology: ", topology)


    events = find_events(packets)


    policy = {}
    for i in range(n_switch):
        policy["S"+str(switches[i])] = ""

    flow_tables = {}
    for i in range(n_switch):
        flow_tables["S"+str(switches[i])] = []

    # print("len events: ", len(events))
    
    forward_flag = True
    forward_events = {}
    response_events = {}
    for k, v in events.items():
        if forward_flag:
            forward_events[k] = v
            forward_flag = False
        else:
            response_events[k] = v
            forward_flag = True
    
    # print("len(forward)", len(forward_events))
    # print("len(response)", len(response_events))

    events = forward_events

    event_iteration = 1
    for k, v in events.items():
        print("event_iteration: ", event_iteration)
        event_iteration += 1
        path = path_event(v)
        print("path: ", path)
        path_l = len(path)
        for i in range(1, path_l-1):
            sw = path[i]
            p1 = ports[(sw, path[i-1])]
            p2 = ports[(sw, path[i+1])]
            rule = construct_rule(p1,p2)
            reverse_rule = construct_rule(p2,p1)
            if rule not in flow_tables["S"+sw] and reverse_rule not in flow_tables["S"+sw]:
                if policy["S"+sw] == "":
                    policy["S"+sw] = rule
                elif policy["S"+sw] != rule:
                    flow_tables["S"+sw].append(rule)


    # return None
    n_combinations = 1
    print("flow tables:")
    for k, v in flow_tables.items():
        n_combinations = n_combinations * (len(v)+1)
        print(k, " --> policy: ", policy[k])
        print(k, " --> number of rules: ", len(v), " rules: ",v)
    
    print("n_combinations: ", n_combinations)
    # return None

    # policy["S47246"] = "pt = 1 . pt <- 3"
    # policy["S47184"] = "pt = 9 . pt <- 8"
    # policy["S47168"] = "pt = 11 . pt <- 13"

    # policy["S47232"] = "pt = 29 . pt <- 28"
    # policy["S47298"] = "pt = 32 . pt <- 31"
    
    # policy["S47218"] = "pt = 22 . pt <- 21"
    # policy["S47276"] = "pt = 25 . pt <- 24"
    
    # print(policy)


    # flow_tables = {}
    
    # # flow_tables['S47182']= ['pt = 5 . pt <- 4']
    # # flow_tables['S47248']= ['pt = 7 . pt <- 6']
    # flow_tables["S47246"] = []
    # flow_tables["S47184"] = []
    # flow_tables["S47168"] = ['pt = 11 . pt <- 12']
    # # flow_tables["S47168"] = []


    # flow_tables["S47232"] = []
    # flow_tables["S47298"] = []
    
    # flow_tables["S47218"] = []
    # flow_tables["S47276"] = []


    C = ""

    switch_rec_vars, new_C, channels = calculate_recursive_variables(policy, topology, flow_tables, C)

    controllers = {}
    controllers["C"] = new_C    # controllers["C2"] = '((upS2 ! "zero") ; ((syn ? "one") ; ((upS4 ! "{}") ; ((upS6 ! "{}") ; bot))))'.format(flow_tables["S4"][0], flow_tables["S6"][0])
    
    recursive_variables = merge_two_dicts(controllers, switch_rec_vars)
    
    data = OrderedDict()
    data['module_name'] = expriment_name
    data['recursive_variables'] = recursive_variables
    data['program'] = "D-1 || C"
    data['channels'] = channels
    
    in_packets = {"H1toH5": "(pt = 1)", "H1toH7": "(pt = 1)"}
    out_packets = {"H1toH5": "(pt = 10)", "H1toH7": "(pt = 14)"}
    
    # all_rcfgs = []
    # all_rcfgs.append('rcfg(event1sendS37596, "one")')
    # all_rcfgs.append('rcfg(event1upS37596, "pt = 1 . pt <- 2")')
    # all_rcfgs.append('rcfg(event1sendS37582, "one")')
    # all_rcfgs.append('rcfg(event1upS37582, "pt = 5 . pt <- 4")')


    

    properties = {
                  "H1toH5": [
                               ("r", "(head(@Program))", "!0", 2),
                               ("r", "(head(tail(@Program, { rcfg(S48230Reqflow1, \"one\") , rcfg(S48230Upflow1, \"pt = 6 . pt <- 7\") })))", "!0", 3)
                              ],
                  "H1toH7": [
                               ("r", "(head(@Program))", "=0", 2),
                               ("r", "(head(tail(@Program, { rcfg(S48230Reqflow1, \"one\") , rcfg(S48230Upflow1, \"pt = 6 . pt <- 7\") })))", "=0", 3)
                              ]
                 }


    data['in_packets'] = in_packets
    data['out_packets'] = out_packets
    data['properties'] = properties

    return data

if __name__ == "__main__":

    expriment_name = "h1pingh5h7"
    # expriment_name = "h1pingall"
    # expriment_name = "pingall"
    # expriment_name = "h1pingh2"
    # expriment_name = "linear_3_1"
    # expriment_name = "linear_10_1_h1h5_h6h10"
    # expriment_name = "linear_3_1_new"
    # expriment_name = "linear_4_1"
    # expriment_name = "linear_3_2_ping_h1s1_h1s3" 
    # expriment_name = "single3"

    log_file_path = "./FPSDN/data/" + expriment_name + ".pcapng"
    save_topo_path = "./FPSDN/output/"+ expriment_name +"/" + expriment_name + ".png"
    after_preprocessing_log_path = "./FPSDN/output/" +  expriment_name +"/"  + expriment_name + "_After_Preprocessing.txt"
    ports_path = "./FPSDN/output/" +  expriment_name +"/"  + expriment_name + "_ports.txt"
    save_DyNetKAT_path = "./FPSDN/output/"+ expriment_name +"/" + "DyNetKAT_" + expriment_name + ".json"

    FPSDN_start = perf_counter()
    packets_cap, partial_topo = find_partial_topology(log_file_path)
    packets = pre_processing(packets_cap)
    topo_graph = find_topo(partial_topo, packets)
    data = DyNetKAT(topo_graph, packets, expriment_name)

    FPSDN_end = perf_counter()

    print("\nPreprocessing + Extraction Rueles time: {:.2f} seconds\n".format(FPSDN_end-FPSDN_start))


    ports = allocate_ports(topo_graph)
    os.makedirs(os.path.dirname(ports_path), exist_ok=True)
    ports_file = open(ports_path, "w")
    ports_file.write(str(ports))

    save_topo_graph(topo_graph, ports,path=save_topo_path)
    write_log(packets, after_preprocessing_log_path)

    

    Save_Json(data, save_DyNetKAT_path)

    print("END Preprocessing and Extraction Rueles - Now we can run DyNetiKAT\n")


    maude_path = "./maude-3.1/maude.linux64"
    netkat_katbv_path = "./netkat/_build/install/default/bin/katbv"
    example_path = save_DyNetKAT_path
    # example_path = "./FPSDN/output/"+ expriment_name +"/" + "DyNetKAT_" + expriment_name + ".json"


    DyNetiKAT_results = subprocess.run(["python3", "dnk.py", "--time-stats" , maude_path, netkat_katbv_path, example_path])
    


