import ruamel.yaml

"""
----------------------------------------------------------------------------------------------------------
PacketInfo class for storing and analyzing packet information
----------------------------------------------------------------------------------------------------------
"""


class PacketInfo:
    def __init__(
        self,
        packet,
        seq_num,
        ethertypes,
        protocols,
        tcps_udps,
        pids,
        saps,
        icmp_types,
        senders,
    ):
        # Initialize packet information
        self.frame_number = seq_num

        self.packet = packet
        self.ethernet_frame = bytes(packet)

        # Determine frame type
        self.frame_type = self.get_frametype(
            self.ethernet_frame[12:14].hex(), self.ethernet_frame[14:16].hex()
        )

        # Calculate frame and medium lengths
        self.frame_length = len(self.ethernet_frame)
        self.frame_medium_length = self.calculate_medium_length()

        # Format MAC addresses
        self.dst_mac = self.format_mac(self.ethernet_frame[:6].hex())
        self.src_mac = self.format_mac(self.ethernet_frame[6:12].hex())

        # Format hex frame
        self.hexa_frame = self.hexa_frame_wrap(self.ethernet_frame.hex())

        # Divide the packet into sections based on the frame type
        if self.frame_type == "IEEE 802.3 LLC":
            self.sap = self.get_sap(self.ethernet_frame[15:16].hex(), saps)
        elif self.frame_type == "IEEE 802.3 LLC & SNAP":
            self.pid = self.get_pid(
                self.ethernet_frame[20:22].hex(), self.ethernet_frame[46:48].hex(), pids
            )
        elif self.frame_type == "ETHERNET II":
            self.ether_type = self.get_ether_type(
                self.ethernet_frame[12:14].hex(), ethertypes
            )
            if self.ether_type == "ARP":
                self.src_ip = self.get_ip(
                    self.ethernet_frame[28:32].hex(), True, senders
                )
                self.dst_ip = self.get_ip(
                    self.ethernet_frame[38:42].hex(), False, senders
                )
                operation = int(self.ethernet_frame[20:22].hex(), 16)
                if operation == 1:
                    self.arp_opcode = "Request"
                elif operation == 2:
                    self.arp_opcode = "Reply"
            elif self.ether_type == "IPv4":
                self.src_ip = self.get_ip(
                    self.ethernet_frame[26:30].hex(), True, senders
                )
                self.dst_ip = self.get_ip(
                    self.ethernet_frame[30:34].hex(), False, senders
                )
                self.protocol = self.get_protocol(
                    self.ethernet_frame[23:24].hex(), protocols
                )
                self.ihl = int((self.ethernet_frame[14:15].hex())[1], 16) * 4
                if self.protocol == "UDP" or self.protocol == "TCP":
                    self.src_port = int(
                        self.ethernet_frame[14 + self.ihl : 14 + self.ihl + 2].hex(), 16
                    )
                    self.dst_port = int(
                        self.ethernet_frame[
                            14 + self.ihl + 2 : 14 + self.ihl + 4
                        ].hex(),
                        16,
                    )
                    self.app_protocol = self.get_app_protocol(
                        self.dst_port, self.src_port, tcps_udps
                    )
                elif self.protocol == "ICMP":
                    self.icmp_type = self.get_icmp_type(
                        int(
                            self.ethernet_frame[
                                14 + self.ihl : 14 + self.ihl + 1
                            ].hex(),
                            16,
                        ),
                        icmp_types,
                    )
                    if self.icmp_type == "Time Exceeded":
                        icmp_length = (
                            int(
                                (
                                    self.ethernet_frame[
                                        14 + self.ihl + 8 : 14 + self.ihl + 9
                                    ].hex()
                                )[1],
                                16,
                            )
                            * 4
                        )
                        self.icmp_id = int(
                            self.ethernet_frame[
                                14
                                + self.ihl
                                + 8
                                + icmp_length
                                + 4 : 14
                                + self.ihl
                                + 8
                                + icmp_length
                                + 6
                            ].hex(),
                            16,
                        )
                        self.icmp_seq = int(
                            self.ethernet_frame[
                                14
                                + self.ihl
                                + 8
                                + icmp_length
                                + 6 : 14
                                + self.ihl
                                + 8
                                + icmp_length
                                + 8
                            ].hex(),
                            16,
                        )
                    elif (
                        self.icmp_type == "Echo Request"
                        or self.icmp_type == "Echo Reply"
                    ):
                        self.icmp_id = int(
                            self.ethernet_frame[
                                14 + self.ihl + 4 : 14 + self.ihl + 6
                            ].hex(),
                            16,
                        )
                        self.icmp_seq = int(
                            self.ethernet_frame[
                                14 + self.ihl + 6 : 14 + self.ihl + 8
                            ].hex(),
                            16,
                        )
                    else:
                        self.icmp_id = -1
                        self.icmp_seq = -1

            elif self.ether_type == "IPv6":
                self.src_ip = self.get_ip(
                    self.ethernet_frame[22:38].hex(), True, senders
                )
                self.dst_ip = self.get_ip(
                    self.ethernet_frame[38:54].hex(), False, senders
                )

    """
    ----------------------------------------------------------------------------------------------------------
    Method for determining the frame type
    ----------------------------------------------------------------------------------------------------------
    """

    def get_frametype(self, frametype, type):
        frametype_int = int(frametype, 16)

        if frametype_int >= 1518:
            return "ETHERNET II"
        else:
            if type == "aaaa":
                return "IEEE 802.3 LLC & SNAP"
            if type == "ffff":
                return "IEEE 802.3 RAW"
            else:
                return "IEEE 802.3 LLC"

    """
    ----------------------------------------------------------------------------------------------------------
    Method for calculating the frame and medium lengths
    ----------------------------------------------------------------------------------------------------------
    """

    def calculate_frame_length(self, lenght):
        if self.frametype == "ETHERNET II":
            return
        else:
            return int(lenght, 16)

    def calculate_medium_length(self):
        if int(self.frame_length) <= 60:
            return 64
        else:
            return self.frame_length + 4

    """
    ----------------------------------------------------------------------------------------------------------
    Method for formatting destination and source MAC addresses
    ----------------------------------------------------------------------------------------------------------
    """

    def format_mac(self, mac_address):
        return ":".join([mac_address[i : i + 2] for i in range(0, len(mac_address), 2)])

    """
    ----------------------------------------------------------------------------------------------------------
    Method for determining the SAP and PID
    ----------------------------------------------------------------------------------------------------------
    """

    def get_pid(self, pid, pid2, pids):
        if pid in pids:
            return pids[pid]
        elif pid2 in pids:
            return pids[pid2]

        return "Unknown"

    def get_sap(self, sap, saps):
        if sap in saps:
            return saps[sap]

        return "Unknown"

    """
    ----------------------------------------------------------------------------------------------------------
    Method for determining the EtherType
    ----------------------------------------------------------------------------------------------------------
    """

    def get_ether_type(self, ether_type, ethertypes):
        if ether_type in ethertypes:
            return ethertypes[ether_type]

        return "Unknown"

    """
    ----------------------------------------------------------------------------------------------------------
    Method for determining the source and destination IP
    ----------------------------------------------------------------------------------------------------------
    """

    def get_ip(self, ip_hex, sender, senders):
        ip = ".".join([str(int(ip_hex[i : i + 2], 16)) for i in range(0, 8, 2)])

        # Check if sender and if it's an IPv4 packet
        if sender and self.ether_type == "IPv4":
            found = False
            for item in senders:
                if item[0] == ip:
                    item[1] += 1
                    found = True
                    break

            if not found:
                senders.append([ip, 1])

        return ip

    """
    ----------------------------------------------------------------------------------------------------------
    Method for determining the protocol
    ----------------------------------------------------------------------------------------------------------
    """

    def get_protocol(self, protocol, protocols):
        protocol = str(int(protocol, 16))
        if protocol in protocols:
            return protocols[protocol]

        return "Unknown"

    """
    ----------------------------------------------------------------------------------------------------------
    Method for formatting the hex frame for output
    ----------------------------------------------------------------------------------------------------------
    """

    def hexa_frame_wrap(self, hexa_frame):
        formatted_hexa_frame = ""
        for i in range(0, len(hexa_frame)):
            if i % 2 == 0 and i > 0 and i % 32 != 0:
                formatted_hexa_frame += " "
            if i % 32 == 0 and i > 0:
                formatted_hexa_frame += "\n"
            formatted_hexa_frame += hexa_frame[i]

        return formatted_hexa_frame

    """
    ----------------------------------------------------------------------------------------------------------
    Method for determining the application protocol
    ----------------------------------------------------------------------------------------------------------
    """

    def get_app_protocol(self, app_protocol, app_protocol2, tcps_udps):
        app_protocol = str(app_protocol)
        app_protocol2 = str(app_protocol2)

        if app_protocol in tcps_udps:
            return tcps_udps[app_protocol]
        elif app_protocol2 in tcps_udps:
            return tcps_udps[app_protocol2]

        return "Unknown"

    def get_icmp_type(self, icmp_type, icmp_types):
        icmp_type = str(icmp_type)

        if icmp_type in icmp_types:
            return icmp_types[icmp_type]

        return "Unknown"

    """
    ----------------------------------------------------------------------------------------------------------
    Method for converting the packet information to a dictionary for YAML output
    ----------------------------------------------------------------------------------------------------------
    """

    def to_dict(self):
        hexa_frame_with_newline = self.hexa_frame + "\n"

        hexa_frame_literal = ruamel.yaml.scalarstring.LiteralScalarString(
            hexa_frame_with_newline
        )

        packet_info_dict = {
            "frame_number": self.frame_number,
            "len_frame_pcap": self.frame_length,
            "len_frame_medium": self.frame_medium_length,
            "frame_type": self.frame_type,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
        }

        if self.frame_type == "IEEE 802.3 LLC":
            if self.sap != "Unknown":
                packet_info_dict["sap"] = self.sap
        elif self.frame_type == "IEEE 802.3 LLC & SNAP":
            if self.pid != "Unknown":
                packet_info_dict["pid"] = self.pid
        elif self.frame_type == "ETHERNET II":
            if self.ether_type != "Unknown":
                packet_info_dict["ether_type"] = self.ether_type
            if self.ether_type == "ARP":
                packet_info_dict["arp_opcode"] = self.arp_opcode
                packet_info_dict["src_ip"] = self.src_ip
                packet_info_dict["dst_ip"] = self.dst_ip
            if self.ether_type == "IPv4":
                packet_info_dict["src_ip"] = self.src_ip
                packet_info_dict["dst_ip"] = self.dst_ip
                if self.protocol != "Unknown":
                    packet_info_dict["protocol"] = self.protocol
                if self.protocol == "UDP" or self.protocol == "TCP":
                    packet_info_dict["src_port"] = self.src_port
                    packet_info_dict["dst_port"] = self.dst_port
                    if self.app_protocol != "Unknown":
                        packet_info_dict["app_protocol"] = self.app_protocol
                elif self.protocol == "ICMP":
                    if self.icmp_type != "Unknown":
                        packet_info_dict["icmp_type"] = self.icmp_type
                        if self.icmp_type != "Destination Unreachable":
                            packet_info_dict["icmp_id"] = self.icmp_id
                            packet_info_dict["icmp_seq"] = self.icmp_seq

        packet_info_dict["hexa_frame"] = hexa_frame_literal

        return packet_info_dict
