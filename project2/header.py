import struct
import zlib


def decode_header(byte_message):
    # divide header and data
    header_bytes = byte_message[:16]
    data_bytes = byte_message[16:]

    # unpack header
    flag, crc, frag_size, frag_count, frag_order = struct.unpack("!HIHII", header_bytes)

    return flag, crc, frag_size, frag_count, frag_order, data_bytes


def create_header(flag, frag_size, frag_count, frag_order, data, error):
    # if data is a string, encode it to bytes
    if isinstance(data, str):
        data = data.encode("utf-8")

    # calculate crc
    crc = calculate_crc(data)

    # pack header
    header_bytes = struct.pack("!HIHII", flag, crc, frag_size, frag_count, frag_order)

    # if sending error, change data to "error"
    if error:
        data = b"error"

    # add header to data
    header_bytes += data
    return header_bytes


def calculate_crc(data):
    # calculate crc value
    crc32_value = zlib.crc32(data)
    return crc32_value
