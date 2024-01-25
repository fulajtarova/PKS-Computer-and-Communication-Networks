# validator
# python C:\Users\Laura\Desktop\škola\3semester\PKS\project1\validator.py -s C:\Users\Laura\Desktop\škola\3semester\PKS\project1\schema-all.yaml -d C:\Users\Laura\Desktop\škola\3semester\PKS\project1\output.yaml
import scapy.all as scapy
import ruamel.yaml
import tcp_assignment
import udp_assignment
import icmp_assignment
import arp_assignment
import analyze_packets

# Colors for the terminal
Orange = "\033[0;33m"
green = "\033[0;92m"
blue = "\033[0;94m"
magenta = "\033[0;95m"
cyan = "\033[0;96m"
pink_back = "\033[0;45m"
reset = "\033[0m"


"""
----------------------------------------------------------------------------------------------------------
Function for yaml dump
----------------------------------------------------------------------------------------------------------
"""


def dump_yaml(packet_info_list, file_name, senders):
    # Calculate the maximum packet count
    max_packet_count = max([ip[1] for ip in senders])

    # Find IP addresses with the maximum packet count
    top_senders = [ip for ip in senders if ip[1] == max_packet_count]

    # Create YAML data
    yaml_data = {
        "name": "PKS2023/24",
        "pcap_name": file_name,
        "packets": packet_info_list,
        "ipv4_senders": [
            {"node": ip[0], "number_of_sent_packets": ip[1]} for ip in senders
        ],
        "max_send_packets_by": [
            {
                "node and number_of_sent_packets": str(
                    sender[0] + " " + str(sender[1])
                ),
            }
            for sender in top_senders
        ],
    }

    """
        "max_send_packets_by": [sender[0] for sender in top_senders],
    """

    # Save the packet information to a YAML file
    with open("project1/output.yaml", "w") as yaml_file:
        ruamel.yaml.dump(
            yaml_data,
            yaml_file,
            default_flow_style=False,
            Dumper=ruamel.yaml.RoundTripDumper,
        )


"""
----------------------------------------------------------------------------------------------------------
Function for reading the data from the data.txt file
----------------------------------------------------------------------------------------------------------
"""


def read_data():
    # Create dictionaries for the data
    ethertypes = {}
    protocols = {}
    tcps_udps = {}
    pids = {}
    saps = {}
    flags = {}
    icmp_types = {}

    current_dict = None

    # Read the data from the data.txt file and save it to the dictionaries
    with open("project1/data.txt", "r") as file:
        for line in file:
            line = line.strip()
            if line.startswith("#ethertypes"):
                current_dict = ethertypes
            elif line.startswith("#protocol"):
                current_dict = protocols
            elif line.startswith("#tcp_udp"):
                current_dict = tcps_udps
            elif line.startswith("#pid"):
                current_dict = pids
            elif line.startswith("#sap"):
                current_dict = saps
            elif line.startswith("#flags"):
                current_dict = flags
            elif line.startswith("#icmp"):
                current_dict = icmp_types
            elif ":" in line:
                key, value = line.split(":")
                current_dict[key.strip()] = value.strip()

    return ethertypes, protocols, tcps_udps, pids, saps, flags, icmp_types


"""
----------------------------------------------------------------------------------------------------------
Main function
----------------------------------------------------------------------------------------------------------
"""


def main():
    # Get the file name from the user
    file_path = "project1/vzorky_pcap_na_analyzu/"
    user_file = input(green + "\nEnter file name: " + reset).strip()
    file_path += user_file
    file_path += ".pcap"
    last_slash_index = file_path.rfind("/")
    if last_slash_index != -1:
        file_name = file_path[last_slash_index + 1 :]
    else:
        file_name = file_path

    # Read the data from the data.txt file and save it to variables
    ethertypes, protocols, tcps_udps, pids, saps, flags, icmp_types = read_data()
    senders = []

    # Read the packets from the pcap file
    try:
        packets = scapy.rdpcap(file_path)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        main()

    # Create a list of packet information
    packet_info_list = []
    all_packets = []

    # Analyze packets and create packet_info_list for YAML dump and all_packets list consisting of PacketInfo objects for further analysis
    for i, packet in enumerate(packets):
        packet_info = analyze_packets.PacketInfo(
            packet,
            i + 1,
            ethertypes,
            protocols,
            tcps_udps,
            pids,
            saps,
            icmp_types,
            senders,
        )
        all_packets.append(packet_info)
        packet_info_list.append(packet_info.to_dict())

    # Main loop for interaction with the user
    while True:
        print(
            blue
            + '\nEnter:\n   1) "all"\n   2) "filter name"\n   3) "new" to enter a new file name\n   4) "h" print valid filters\n   5) "q" to quit'
            + reset
        )
        user_input = str(input("Enter your choice: ")).upper()

        # Valid filters
        tcp_values = ["HTTP", "HTTPS", "TELNET", "SSH", "FTP-CONTROL", "FTP-DATA"]
        udp_values = ["TFTP"]
        icmp_values = ["ICMP"]
        arp_values = ["ARP"]

        if user_input == "Q":
            print(cyan + "Goodbye" + reset)
            exit()
        elif user_input == "H":
            print(
                "Valid filters: HTTP, HTTPS, TELNET, SSH, FTP-CONTROL, FTP-DATA, TFTP, ICMP, ARP"
            )
        elif user_input == "DNS":
            dns_list = []
            for packet in all_packets:
                if (
                    packet.frame_type == "ETHERNET II"
                    and packet.ether_type == "IPv4"
                    and packet.protocol == "UDP"
                    and packet.app_protocol == "DNS"
                ):
                    dns_list.append(packet.to_dict())

            yaml_data = {
                "name": "PKS2023/24",
                "pcap_name": file_name,
                "packets": dns_list,
                "number_frames": len(dns_list),
            }

            with open("project1/output.yaml", "w") as yaml_file:
                ruamel.yaml.dump(
                    yaml_data,
                    yaml_file,
                    default_flow_style=False,
                    Dumper=ruamel.yaml.RoundTripDumper,
                )

        elif user_input == "ALL":
            dump_yaml(packet_info_list, file_name, senders)
            print(Orange + "Analysis done" + reset)

        elif user_input in tcp_values:
            new_list = []

            # Create a list of packets with the selected filter
            for packet in all_packets:
                if (
                    packet.frame_type == "ETHERNET II"
                    and packet.ether_type == "IPv4"
                    and packet.protocol == "TCP"
                    and packet.app_protocol == user_input
                ):
                    new_list.append(packet)

            # Call the function for TCP analysis
            tcp_assignment.tcp_quest(new_list, file_name, user_input, flags)
            print(Orange + "TCP analysis done" + reset)

        elif user_input in udp_values:
            keys_list = []
            start_list = []

            # Create a list of packets with the selected filter
            for packet in all_packets:
                if (
                    packet.frame_type == "ETHERNET II"
                    and packet.ether_type == "IPv4"
                    and packet.protocol == "UDP"
                    and packet.app_protocol == user_input
                ):
                    keys_list.append(packet.src_port)
                    start_list.append([packet])

            # Call the function for UDP analysis
            udp_assignment.udp_quest(
                start_list, keys_list, all_packets, file_name, user_input
            )
            print(Orange + "UDP analysis done" + reset)
        elif user_input in icmp_values:
            new_list = []

            # Create a list of packets with the selected filter
            for packet in all_packets:
                if (
                    packet.frame_type == "ETHERNET II"
                    and packet.ether_type == "IPv4"
                    and packet.protocol == "ICMP"
                ):
                    new_list.append(packet)

            # Call the function for ICMP analysis
            icmp_assignment.icmp_quest(new_list, file_name, user_input)
            print(Orange + "ICMP analysis done" + reset)

        elif user_input in arp_values:
            new_list = []

            # Create a list of packets with the selected filter
            for packet in all_packets:
                if packet.frame_type == "ETHERNET II" and packet.ether_type == "ARP":
                    new_list.append(packet)

            # Call the function for ARP analysis
            arp_assignment.arp_quest(new_list, file_name, user_input)
            print(Orange + "ARP analysis done" + reset)
        elif user_input == "NEW":
            main()

        else:
            print(magenta + "Wrong input" + reset)


# Run the main function
main()
