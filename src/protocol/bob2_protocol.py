import struct
import socket
import zlib

CURRENT_MAJOR_VERSION=0
CURRENT_MINOR_VERISON=2

class Bob2Protocol:
    def __init__(self, version_major=0, version_minor=2):
        self.version_major = version_major
        self.version_minor = version_minor

    def build_message(self, message_type, dest_ipv6, dest_port, message_content, multiple_packets=False, packet_num=0):
        try:
            dest_ip_bytes = socket.inet_pton(socket.AF_INET6, dest_ipv6)
        except socket.error:
            raise ValueError("Invalid IPv6 address")

        header = struct.pack('!BBB', self.version_major, self.version_minor, message_type)
        if multiple_packets:
            packet_bytes = packet_num.to_bytes(2, byteorder='big')
        else:
            packet_bytes = bytes(2)

        dest_port_bytes = struct.pack('!H', dest_port)

        message_length = len(message_content)
        if message_length > (1 << 40) - 1:
            raise ValueError("Message content exceeds maximum allowed size")

        length_bytes = message_length.to_bytes(5, byteorder='big')
        checksum = zlib.crc32(message_content.encode('utf-8'))
        checksum_bytes = struct.pack('!I', checksum)

        full_message = (header + packet_bytes + dest_ip_bytes + dest_port_bytes + length_bytes +
                        checksum_bytes + message_content.encode('utf-8'))
        return full_message

    def parse_message(self, raw_data):
        version_major, version_minor, message_type = struct.unpack('!BBB', raw_data[:3])
        packet_num = int.from_bytes(raw_data[3:5], byteorder='big')
        if packet_num == 0:
            multiple_packets = False
        dest_ip_bytes = raw_data[5:21]
        dest_ipv6 = socket.inet_ntop(socket.AF_INET6, dest_ip_bytes)
        dest_port = struct.unpack('!H', raw_data[21:23])[0]
        message_length = int.from_bytes(raw_data[23:28], byteorder='big')

        expected_checksum = struct.unpack('!I', raw_data[28:32])[0]
        message_content = raw_data[32:32 + message_length]
        actual_checksum = zlib.crc32(message_content)

        if expected_checksum != actual_checksum:
            raise ValueError("Checksum verification failed")

        response =  {
            "version_major": version_major,
            "version_minor": version_minor,
            "message_type": message_type,
            "destination_ip": dest_ipv6,
            "destination_port": dest_port,
            "message_length": message_length,
            "checksum": expected_checksum,
            "message_content": message_content.decode('utf-8')
        }
        if multiple_packets:
            response["packet_num"] = packet_num
        else:
            response['multiple_packets'] = False

        return response
