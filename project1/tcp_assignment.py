import ruamel.yaml

"""
----------------------------------------------------------------------------------------------------------
Function for outputting the data to a YAML file
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
        yaml_data["partial_comms"] = incomplete_comms[0:1]

    with open("project1/output.yaml", "w") as yaml_file:
        ruamel.yaml.dump(
            yaml_data,
            yaml_file,
            default_flow_style=False,
            Dumper=ruamel.yaml.RoundTripDumper,
        )


"""
----------------------------------------------------------------------------------------------------------
Function for sorting the list of packets into individual groups based on the IP addresses and ports
----------------------------------------------------------------------------------------------------------
"""


def list_sorting(list_old):
    sorted_list = []

    for item in list_old:
        found_group = None

        for group in sorted_list:
            if (
                (item.src_ip == group[0].src_ip or item.src_ip == group[0].dst_ip)
                and (item.dst_ip == group[0].dst_ip or item.dst_ip == group[0].src_ip)
                and (
                    item.src_port == group[0].src_port
                    or item.src_port == group[0].dst_port
                )
                and (
                    item.dst_port == group[0].dst_port
                    or item.dst_port == group[0].src_port
                )
            ):
                found_group = group
                break

        if found_group:
            found_group.append(item)
        else:
            sorted_list.append([item])

    return sorted_list


"""
----------------------------------------------------------------------------------------------------------
Function for finding the complete or incomplete communication
----------------------------------------------------------------------------------------------------------
"""


def find_communication(used_flags, sorted_list):
    complete_list = []
    incomplete_list = []

    for j, group in enumerate(used_flags):
        # setting the flags to false
        opening = False
        closing = False

        opening_syn1 = False
        opening_syn2 = False
        opening_ack1 = False
        opening_ack2 = False

        closing_fin1 = False
        closing_fin2 = False
        closing_ack1 = False
        closing_ack2 = False

        for i, item in enumerate(group):
            if "SYN" in item[1]:
                if not opening_syn1:
                    first_o = item[0]  # defining who sent the first SYN
                    opening_syn1 = True
                if (
                    first_o != item[0] and opening_syn1
                ):  # checking if the second SYN is from the other side
                    opening_syn2 = True
            if "ACK" in item[1] and opening_syn1 and opening_syn2:
                if first_o != item[0]:  # checking if the ACK is from the other side
                    opening_ack1 = True
                elif (
                    first_o == item[0] and opening_ack1
                ):  # checking if the second ACK is from the first side
                    opening_ack2 = True

            if opening_syn1 and opening_syn2 and opening_ack1 and opening_ack2:
                opening = True

            if opening:
                # if there is a RST flag, the communication is considered complete
                if "RST" in item[1]:
                    closing = True
                    break
                if "FIN" in item[1]:
                    if not closing_fin1:
                        first_c = item[0]
                        closing_fin1 = True
                    if first_c != item[0] and closing_fin1:
                        closing_fin2 = True
                if "ACK" in item[1] and closing_fin1:
                    if first_c != item[0]:
                        closing_ack1 = True
                    elif first_c == item[0] and closing_ack1:
                        closing_ack2 = True

                if closing_fin1 and closing_fin2 and closing_ack1 and closing_ack2:
                    closing = True
        if not (opening and closing):
            incomplete_list.append(sorted_list[j])
        else:
            complete_list.append(sorted_list[j])

    return complete_list, incomplete_list


"""
----------------------------------------------------------------------------------------------------------
Function for analyzing TCP packets, sorting them into groups and finding the complete or incomplete communication
----------------------------------------------------------------------------------------------------------
"""


def tcp_quest(new_list, file_name, user_input, flags):
    sorted_list = list_sorting(new_list)

    used_flags = []

    for group in sorted_list:
        client = group[0].src_ip

        temp_group = []
        for i in range(0, len(group)):
            temp = (
                group[i]
                .ethernet_frame[14 + group[i].ihl + 13 : 14 + group[i].ihl + 14]
                .hex()
            )

            if temp in flags:
                if group[i].src_ip == client:
                    temp_group.append([1, flags[temp]])
                else:
                    temp_group.append([2, flags[temp]])

        used_flags.append(temp_group)

    complete, incomplete = find_communication(used_flags, sorted_list)

    dump_yaml(complete, incomplete, file_name, user_input)
