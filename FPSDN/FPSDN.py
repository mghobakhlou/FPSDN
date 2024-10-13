import os
import pyshark
import networkx as nx
import matplotlib.pyplot as plt
from collections import OrderedDict
import itertools as it
import subprocess
from time import perf_counter
import re
import optparse
import sys
from util import save_topo_graph, Save_Json, write_log, is_exe, merge_two_dicts
from util import draw_Fault_Scenario
from util import draw_results_preprocessingtime_exprs, draw_results_extraction_exprs

def read_log_file(log_file_path):
    try:
        with pyshark.FileCapture(log_file_path, display_filter='openflow_v1') as cap:
            packets_cap = []
            ipsrc_ipdst_sw_type_packet_checker = []

            for packet in cap:
                if int(packet.openflow_v1.openflow_1_0_type) == 10 and packet.openflow_v1.get_field_value("ip.src") != None:
                    src_dst_sw_type = packet.openflow_v1.get_field_value("ip.src") + "_" + packet.openflow_v1.get_field_value("ip.dst") + "_" + packet.tcp.get_field_value("tcp.srcport") + "_" + str(packet.openflow_v1.openflow_1_0_type)
                    if src_dst_sw_type not in ipsrc_ipdst_sw_type_packet_checker:
                        ipsrc_ipdst_sw_type_packet_checker.append(src_dst_sw_type)
                        packets_cap.append(packet)
                elif int(packet.openflow_v1.openflow_1_0_type) == 14 and packet.openflow_v1.get_field_value("openflow.ofp_match.source_addr").split(".")[0] == "10" and int(packet.openflow_v1.get_field_value("openflow.ofp_match.dl_type")) != 2054:
                    src_dst_sw_type = packet.openflow_v1.get_field_value("openflow.ofp_match.source_addr") + "_" + packet.openflow_v1.get_field_value("openflow.ofp_match.dest_addr") + "_" + packet.tcp.get_field_value("tcp.dstport") + "_" + str(packet.openflow_v1.openflow_1_0_type)
                    if src_dst_sw_type not in ipsrc_ipdst_sw_type_packet_checker:
                        ipsrc_ipdst_sw_type_packet_checker.append(src_dst_sw_type)
                        packets_cap.append(packet)
    except FileNotFoundError:
        print(f"Couldn't find the file: {log_file_path}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None
    
    return packets_cap


def find_partial_topology(packets_cap):
    
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
    return G


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


def pre_processing(packets_cap):
 
    packets = packets_cap

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


def DyNetKAT(topo_graph, packets, expriment_name, add_first_switch_rule_as_predefined_rule_in_switch=False):
    switches = list_of_switches(topo_graph)
    hosts = list_of_hosts(topo_graph)
    n_switch = number_of_switches(topo_graph)
    
    ports = allocate_ports(topo_graph)
    topo_str = string_topo(topo_graph, ports)
    topology = topo_str

    events = find_events(packets)

    policy = {}
    for i in range(n_switch):
        policy["S"+str(switches[i])] = ""

    flow_tables = {}
    for i in range(n_switch):
        flow_tables["S"+str(switches[i])] = []

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

    events = forward_events

    
    if add_first_switch_rule_as_predefined_rule_in_switch:
        event_iteration = 1
        for k, v in events.items():
            event_iteration += 1
            path = path_event(v)
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
    else:
        for i in range(n_switch):
            policy["S"+str(switches[i])] = "pt = 0"

        event_iteration = 1
        for k, v in events.items():
            event_iteration += 1
            path = path_event(v)
            path_l = len(path)
            for i in range(1, path_l-1):
                sw = path[i]
                p1 = ports[(sw, path[i-1])]
                p2 = ports[(sw, path[i+1])]
                rule = construct_rule(p1,p2)
                reverse_rule = construct_rule(p2,p1)
                if rule not in flow_tables["S"+sw] and reverse_rule not in flow_tables["S"+sw]:
                    flow_tables["S"+sw].append(rule)



    C = ""

    switch_rec_vars, new_C, channels = calculate_recursive_variables(policy, topology, flow_tables, C)

    controllers = {}
    controllers["C"] = new_C    
    
    recursive_variables = merge_two_dicts(controllers, switch_rec_vars)
    
    data = OrderedDict()
    data['module_name'] = expriment_name
    data['recursive_variables'] = recursive_variables
    data['program'] = "D-1 || C"
    data['channels'] = channels
    
    in_packets = {}
    out_packets = {}
    properties = {}
    

    data['in_packets'] = in_packets
    data['out_packets'] = out_packets
    data['properties'] = properties

    return data



def run(folder_path, expriment_name, add_first_switch_rule_as_predefined_rule_in_switch=False, maude_path="", netkat_katbv_path=""):
    
    print("\n#### Running... ####")
    print("Expriment name: ", expriment_name)

    folder_path = folder_path + "/"
    log_file_path = folder_path + expriment_name + ".pcapng"
    save_topo_path = folder_path + "result_" + expriment_name +"/" + expriment_name + ".png"
    after_preprocessing_log_path = folder_path + "result_" + expriment_name +"/" + expriment_name + "_log_After_Preprocessing.txt"
    ports_path = folder_path  + "result_" + expriment_name + "/" + expriment_name + "_ports.txt"
    save_DyNetKAT_path = folder_path + "result_" + expriment_name +"/" + "DyNetKAT_" + expriment_name + ".json"

    print("Preprocessing...")
    topology_preprocessing_start_time = perf_counter()
    packets_cap = read_log_file(log_file_path)
    packets = pre_processing(packets_cap)
    topology_preprocessing_end_time = perf_counter()
    preprocessing_time = topology_preprocessing_end_time - topology_preprocessing_start_time
    preprocessing_time = float("{:.2f}".format(preprocessing_time))
    print("Preprocessing Done. Total Preprocessing time(s): ", preprocessing_time)


    print("Extracting rules...")
    FPSDN_start = perf_counter()
    partial_topo = find_partial_topology(packets_cap)
    topo_graph = find_topo(partial_topo, packets)
    data = DyNetKAT(topo_graph, packets, expriment_name, add_first_switch_rule_as_predefined_rule_in_switch=add_first_switch_rule_as_predefined_rule_in_switch)
    FPSDN_end = perf_counter()
    rules_extraction_time = FPSDN_end-FPSDN_start
    rules_extraction_time = float("{:.4f}".format(rules_extraction_time))
    print("DyNetKAT Rules Extraction Done. Total DyNetKAT Rules Extraction time(s): ", rules_extraction_time)

    total_extraction_time = preprocessing_time + rules_extraction_time
    total_extraction_time = float("{:.2f}".format(total_extraction_time))

    ports = allocate_ports(topo_graph)
    os.makedirs(os.path.dirname(ports_path), exist_ok=True)
    ports_file = open(ports_path, "w")
    ports_file.write(str(ports))
    save_topo_graph(topo_graph, ports,path=save_topo_path)
    write_log(packets, after_preprocessing_log_path)


    in_packets = {}
    out_packets = {}
    properties = {}
    data['in_packets'] = in_packets
    data['out_packets'] = out_packets
    data['properties'] = properties
    
    if expriment_name == "Fattree_with_Fault":
        in_packets = {"h1toh7": "(pt = 5)"}
        out_packets = {"h1toh7": "(pt = 20)"}
        data['in_packets'] = in_packets
        data['out_packets'] = out_packets

        props =[("r", "(head(@Program))", "=0", 2),
                ("r", "(head(tail(@Program, { rcfg(S53252Reqflow1, \"one\") , rcfg(S53252Upflow1, \"pt = 5 . pt <- 6\") })))", "=0", 3),
                ("r", "(head(tail(tail(@Program, { rcfg(S53252Reqflow1, \"one\") , rcfg(S53252Upflow1, \"pt = 5 . pt <- 6\") }), { rcfg(S53322Reqflow1, \"one\") , rcfg(S53322Upflow1, \"pt = 12 . pt <- 13\") })))", "=0", 5)
                ]

        times = check_properties(save_DyNetKAT_path, data, props, maude_path, netkat_katbv_path)
        draw_Fault_Scenario(folder_path, expriment_name,times)

        packet_name = list(data["in_packets"].keys())[0]
        properties[packet_name] = props
        data['properties'] = properties

    elif expriment_name == "Linear_with_Fault":
        in_packets = {"h4toh10": "(pt = 14)"}
        out_packets = {"h4toh10": "(pt = 9)"}
        data['in_packets'] = in_packets
        data['out_packets'] = out_packets

        props =[("r", "(head(@Program))", "=0", 2),
                ("r", "(head(tail(@Program, { rcfg(S38128Reqflow1, \"one\") , rcfg(S38128Upflow1, \"pt = 3 . pt <- 2\") })))", "=0", 3),
                ("r", "(head(tail(tail(@Program, { rcfg(S38128Reqflow1, \"one\") , rcfg(S38128Upflow1, \"pt = 3 . pt <- 2\") }), { rcfg(S38086Reqflow1, \"one\") , rcfg(S38086Upflow1, \"pt = 13 . pt <- 12\") })))", "=0", 5)
                ]

        times = check_properties(save_DyNetKAT_path, data, props, maude_path, netkat_katbv_path)
        draw_Fault_Scenario(folder_path, expriment_name,times)

        packet_name = list(data["in_packets"].keys())[0]
        properties[packet_name] = props
        data['properties'] = properties
        

    Save_Json(data, save_DyNetKAT_path) 
    return preprocessing_time, rules_extraction_time

def check_properties(json_path, data, props, maude_path, netkat_katbv_path):
    properties = {}
    times = []
    for i in range(len(props)):
        print("Checking DyNetKAT Property ", i)
        packet_name = list(data["in_packets"].keys())[0]
        properties[packet_name] = [props[i]]
        data['properties'] = properties

        Save_Json(data, json_path) 



        # print("data: ", data)

        DyNetiKAT_output = subprocess.run(["python3", "dnk.py", "--time-stats" , maude_path, netkat_katbv_path, json_path],
                                        capture_output=True, text=True)
        output = DyNetiKAT_output.stdout.strip()

        print(output)
        # TODO : write property output for each property
        match_value = re.search(r'DyNetKAT Total time: (\d+.\d+) seconds', output)
        DyNetKat_total_time = float(match_value.group(1))
        DyNetKat_total_time = float("{:.4f}".format(DyNetKat_total_time))
        times.append(DyNetKat_total_time)

    return times




if __name__ == "__main__":

    #  TODO --> Clean fault scenarios and generate properties automatically.

    parser = optparse.OptionParser()
    parser.add_option("-e", "--extraction-expriments", dest="extraction_expriments", default=False, action="store_true",
                      help="Extract Topology and DyNetKAT rules of expriments (linear topology with 4 switches, linear topology with 10 switches, fattree topology, fattree topology with more complicated log file) and save results.")
    parser.add_option("-f", "--fault_scenarios", dest="fault_scenarios", default=False, action="store_true",
                      help="Fault Scenarios: Extract Topology and DyNetKAT rules of fault scenarios example and save results.")
    parser.add_option("-l", "--from-logfile", dest="from_logfile", default=False, action="store_true",
                      help="Extract Topology and DyNetKAT rules of your specific logfile (provide correct lof file path).")
    
    
    (options, args) = parser.parse_args()

    if options.from_logfile and len(args) < 3:
        print("Error: provide the arguments <path_to_maude> <path_to_netkat> <logfile_containing_folder>.")
        sys.exit()

    if not options.from_logfile and len(args) < 2:
        print("Error: provide the arguments <path_to_maude> <path_to_netkat> ")
        sys.exit()

    if not os.path.exists(args[0]) or not is_exe(args[0]):
        print("Please provide the path to the Maude executable!")
        sys.exit()

    if not os.path.exists(args[1]) or not is_exe(args[1]):
        print("NetKAT tool could not be found in the given path!")
        sys.exit()

    if options.from_logfile:
        if not os.path.exists(args[2]) or args[2][-7:] != ".pcapng":
            print("Please provide a .pcapng file path!")
            sys.exit()

    maude_path = args[0]
    netkat_path = args[1]
    folder_path = args[2]
    
    expriment_names = [f.split(".")[0] for f in os.listdir(folder_path) if f.endswith('.pcapng')]

    preprocessing_times = []
    rules_extraction_times = []
    if options.extraction_expriments:
        for f in expriment_names:
            expriment_name = f
            results = run(folder_path, expriment_name, add_first_switch_rule_as_predefined_rule_in_switch=False, maude_path=maude_path, netkat_katbv_path=netkat_path)
            preprocessing_times.append(results[0])
            rules_extraction_times.append(results[1])
        draw_results_preprocessingtime_exprs(folder_path, expriment_names,preprocessing_times)
        draw_results_extraction_exprs(folder_path, expriment_names, rules_extraction_times)

    if options.fault_scenarios:
        for f in expriment_names:
            expriment_name = f
            results = run(folder_path, expriment_name, add_first_switch_rule_as_predefined_rule_in_switch=True, maude_path=maude_path, netkat_katbv_path=netkat_path)

    if options.from_logfile:
        expriment_name = expriment_names[0]
        results = run(folder_path, expriment_name, add_first_switch_rule_as_predefined_rule_in_switch=False, maude_path=maude_path, netkat_katbv_path=netkat_path)

