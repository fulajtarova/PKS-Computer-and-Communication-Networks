import ruamel.yaml

"""
----------------------------------------------------------------------------------------------------------
Method that returns complete and incomplete lists of communications
----------------------------------------------------------------------------------------------------------
"""


def check_valid(packet_list):
    complete_list = []
    incomplete_list = []

    # Go through each group of packets and check if it is complete or incomplete
    for group in packet_list:
        request = False
        reply = False
        request_index = None
        reply_index = None
        complete_group = []

        for i, packet in enumerate(group):
            if packet.icmp_type == "Echo Request":
                request = True
                request_index = i
            elif (
                (
                    packet.icmp_type == "Echo Reply"
                    or packet.icmp_type == "Time Exceeded"
                )
            ) and request == True:
                reply = True
                reply_index = i

            if reply:
                complete_group.append(group[request_index])
                complete_group.append(group[reply_index])
                reply = False
                request = False

        if complete_group:
            complete_list.append(complete_group)

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


def dump_yaml(complete_list, incomplete_list, file_name, user_input):
    for i, inner_list in enumerate(complete_list):
        complete_list[i] = sorted(
            inner_list, key=lambda packet_info: packet_info.frame_number
        )

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
def find_his_complice(fragmented_packet, packet_list):
    packets_with_same_id = []
    packets_with_same_id.append(fragmented_packet)
    for group in packet_list:
        for packet in group:
            if (
                fragmented_packet.id == int(packet.ethernet_frame[18:20].hex(), 16)
                and fragmented_packet != packet
            ):
                packets_with_same_id.append(packet)

    return packets_with_same_id


def check_fragmented(packet_list):
    fragmented_packet_list = []
    for group in packet_list:
        fragmented_packet_list_group = []
        for packet in group:
            fragmentation = packet.ethernet_frame[20:22].hex()
            fragmentation = bin(int(fragmentation, 16))[2:].zfill(16)
            packet.flag_mf = int(fragmentation[2])
            packet.frag_offset = int(fragmentation[3:])
            packet.id = int(packet.ethernet_frame[18:20].hex(), 16)
            if packet.flag_mf == 1 and packet not in fragmented_packet_list_group:
                fragmented_comms = find_his_complice(packet, packet_list)
                fragmented_packet_list_group.extend(fragmented_comms)
        fragmented_packet_list.append(fragmented_packet_list_group)

    print(fragmented_packet_list)"""


"""
----------------------------------------------------------------------------------------------------------
Method for sorting the packets into groups based on the IP addresses and the ICMP ID and finding the complete and incomplete communications
----------------------------------------------------------------------------------------------------------
"""


def complete_group(packet_list):
    sorted_list = []

    for old_group in packet_list:
        found_group = None

        for group in sorted_list:
            if (
                (
                    old_group[0].src_ip == group[0].src_ip
                    or old_group[0].src_ip == group[0].dst_ip
                )
                and (
                    old_group[0].dst_ip == group[0].dst_ip
                    or old_group[0].dst_ip == group[0].src_ip
                )
                and old_group[0].icmp_id == group[0].icmp_id
            ):
                found_group = group
                break

        if found_group:
            found_group.extend(old_group)
        else:
            sorted_list.append(old_group)

    return sorted_list


def icmp_quest(packet_list, file_name, user_input):
    sorted_list = []

    for item in packet_list:
        found_group = None

        for group in sorted_list:
            if item.icmp_type != "Time Exceeded":
                if (
                    (item.src_ip == group[0].src_ip or item.src_ip == group[0].dst_ip)
                    and (
                        item.dst_ip == group[0].dst_ip or item.dst_ip == group[0].src_ip
                    )
                    and item.icmp_id == group[0].icmp_id
                    and item.icmp_seq == group[0].icmp_seq
                ):
                    found_group = group
                    break
            else:
                if (
                    item.dst_ip == group[0].src_ip
                    and item.icmp_id == group[0].icmp_id
                    and item.icmp_seq == group[0].icmp_seq
                ):
                    found_group = group
                    break

        if found_group:
            found_group.append(item)
        else:
            sorted_list.append([item])

    # check_fragmented(sorted_list)

    complete_list, incomplete_list = check_valid(sorted_list)

    complete_list = complete_group(complete_list)
    incomplete_list = complete_group(incomplete_list)

    dump_yaml(complete_list, incomplete_list, file_name, user_input)
