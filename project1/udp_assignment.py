import ruamel.yaml

"""
----------------------------------------------------------------------------------------------------------
Function that checks if the communication is complete or incomplete
----------------------------------------------------------------------------------------------------------
"""


def check_valid(packet_list):
    complete_list = []
    incomplete_list = []

    for group in packet_list:
        len_check = False
        ack_check = False
        penultimate = group[-2]  # second last packet
        last = group[-1]  # last packet
        penultimate_len = int(
            penultimate.ethernet_frame[
                14 + penultimate.ihl + 4 : 14 + penultimate.ihl + 6
            ].hex(),
            16,
        )
        last_ack = last.ethernet_frame[14 + last.ihl + 8 : 14 + last.ihl + 10].hex()
        if penultimate_len < 512:  # if the second last packet is less than 512 bytes
            len_check = True
            if last_ack == "0004":  # if the last packet is an ACK
                ack_check = True
        if len_check and ack_check:
            complete_list.append(group)
        else:
            incomplete_list.append(group)

    return complete_list, incomplete_list


"""
----------------------------------------------------------------------------------------------------------
Method for yaml output
----------------------------------------------------------------------------------------------------------
"""


def output_for_yaml(object_list):
    yaml_list = []
    for item in object_list:
        yaml_list.append(item.to_dict())

    return yaml_list


def dump_yaml(complete_list, incomplete_list, file_name, user_input):
    # Sort the packets in each group by frame number
    for i, inner_list in enumerate(complete_list):
        complete_list[i] = sorted(
            inner_list, key=lambda packet_info: packet_info.frame_number
        )

    # Sort the packets in each group by frame number
    for i, inner_list in enumerate(incomplete_list):
        incomplete_list[i] = sorted(
            inner_list, key=lambda packet_info: packet_info.frame_number
        )

    complete_comms = []
    incomplete_comms = []

    if complete_list:
        for i, group in enumerate(complete_list):
            group_out = output_for_yaml(group)
            complete_comm = {
                "number_comm": i + 1,
                "src_comm": group[0].src_ip,
                "dst_comm": group[0].dst_ip,
                "packets": group_out,
            }
            complete_comms.append(complete_comm)

    if incomplete_list:
        for i, group in enumerate(incomplete_list):
            group_out = output_for_yaml(group)
            incomplete_comm = {
                "number_comm": i + 1,
                "packets": group_out,
            }
            incomplete_comms.append(incomplete_comm)

    yaml_data = {
        "name": "PKS2023/24",
        "pcap_name": file_name,
        "filter_name": user_input,
    }
    if complete_list:
        yaml_data["complete_comms"] = complete_comms
    if incomplete_list:
        yaml_data["partial_comms"] = incomplete_comms

    with open("project1/output.yaml", "w") as yaml_file:
        ruamel.yaml.dump(
            yaml_data,
            yaml_file,
            default_flow_style=False,
            Dumper=ruamel.yaml.RoundTripDumper,
        )


"""
----------------------------------------------------------------------------------------------------------
Function for UDP assignment, sorts the packets into lists based on the source and destination ports
----------------------------------------------------------------------------------------------------------
"""


def udp_quest(packet_list, keys_list, all_packets, file_name, user_input):
    for i, item in enumerate(keys_list):
        des = None
        for j, packet in enumerate(all_packets):
            if (
                packet.frame_type == "ETHERNET II"
                and packet.ether_type == "IPv4"
                and packet.protocol == "UDP"
            ):
                if des == None and packet.dst_port == item:
                    des = packet.src_port
                    packet_list[i].append(packet)

                elif des != None and (
                    (packet.src_port == item and packet.dst_port == des)
                    or (packet.src_port == des and packet.dst_port == item)
                ):
                    packet_list[i].append(packet)

    complete_list, incomplete_list = check_valid(packet_list)

    dump_yaml(complete_list, incomplete_list, file_name, user_input)
