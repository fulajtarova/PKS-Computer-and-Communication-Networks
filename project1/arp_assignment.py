import ruamel.yaml


"""
----------------------------------------------------------------------------------------------------------
Method for finding the complete and incomplete communications
----------------------------------------------------------------------------------------------------------
"""


def check_valid(packet_list):
    complete_list = []
    incomplete_list = []

    for group in packet_list:
        request = False
        request_index = None
        reply = False
        reply_index = None
        complete_group = []

        for i, packet in enumerate(group):
            # Check if the packet is a request or reply and save the index
            if packet.arp_opcode == "Request":
                request = True
                request_index = i
            elif packet.arp_opcode == "Reply" and request:
                reply_index = i
                reply = True

            if reply:
                # append the request and reply to the complete group
                complete_group.append(group[request_index])
                complete_group.append(group[reply_index])
                # reset the flags
                reply = False
                request = False

        if complete_group:
            complete_list.append(complete_group)

    # Go through each group of packets and if it is not in the complete list, add it to the incomplete list
    for group in packet_list:
        incomplete_group = []
        for item in group:
            if not any(item in complete for complete in complete_list):
                incomplete_group.append(item)
        if incomplete_group:
            incomplete_list.append(incomplete_group)

    return complete_list, incomplete_list


"""
----------------------------------------------------------------------------------------------------------
Method for outputting the data into a YAML file
----------------------------------------------------------------------------------------------------------
"""


def output_for_yaml(object_list):
    yaml_list = []
    for item in object_list:
        yaml_list.append(item.to_dict())

    return yaml_list


def dump_yaml2(complete_list, incomplete_list, file_name, user_input):
    complete_comms = []
    incomplete_comms = []

    if complete_list:
        for i, group in enumerate(complete_list):
            group_out = output_for_yaml(group)
            complete_comm = {
                "number_comm": i + 1,
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
Method for sorting the packets into groups IPs and MACs, finding the complete and incomplete communications
and outputting the data into a YAML file
----------------------------------------------------------------------------------------------------------
"""


def arp_quest(packet_list, file_name, user_input):
    sorted_list = []

    for item in packet_list:
        found_group = None

        for group in sorted_list:
            if (
                (item.src_ip == group[0].src_ip or item.src_ip == group[0].dst_ip)
                and (item.dst_ip == group[0].dst_ip or item.dst_ip == group[0].src_ip)
                and (
                    item.dst_mac == "ff:ff:ff:ff:ff:ff"
                    or item.dst_mac == group[0].src_mac
                    or item.src_mac == group[0].src_mac
                )
            ):
                found_group = group
                break

        if found_group:
            found_group.append(item)
        else:
            sorted_list.append([item])

    complete_list, incomplete_list = check_valid(sorted_list)

    dump_yaml2(complete_list, incomplete_list, file_name, user_input)
