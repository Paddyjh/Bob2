import struct
import socket
import zlib
from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random

CURRENT_MAJOR_VERSION=0
CURRENT_MINOR_VERISON=2

class Bob2Protocol:
    def __init__(self, version_major=0, version_minor=0):
        self.version_major = version_major
        self.version_minor = version_minor
        self.session_key = None

    def initiate_key_exchange(self):
        private_key = PrivateKey.generate()
        public_key = private_key.public_key
        self.private_key = private_key
        return public_key

    def complete_key_exchange(self, public_key_bytes):
        public_key = PublicKey(public_key_bytes)
        self.session_key = Box(self.private_key, public_key)

    def encrypt_message(self, message_content):
        if not self.session_key:
            raise ValueError("Session key not established")
        
        nonce = random(24)
        encrypted_content = self.session_key.encrypt(message_content.encode('utf-8'), nonce)
        return nonce + encrypted_content.ciphertext

    def decrypt_message(self, encrypted_content_with_nonce):
        if not self.session_key:
            raise ValueError("Session key not established")
        
        nonce = encrypted_content_with_nonce[:24]
        encrypted_content = encrypted_content_with_nonce[24:]
        decrypted_content = self.session_key.decrypt(nonce + encrypted_content)
        return decrypted_content.decode('utf-8')

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
        
        encrypted_content = self.encrypt_message(message_content)

        message_length = len(encrypted_content)
        if message_length > (1 << 40) - 1:
            raise ValueError("Message content exceeds maximum allowed size")

        length_bytes = message_length.to_bytes(5, byteorder='big')
        checksum = zlib.crc32(encrypted_content)
        checksum_bytes = struct.pack('!I', checksum)

        full_message = (header + packet_bytes + dest_ip_bytes + dest_port_bytes + length_bytes +
                        checksum_bytes + encrypted_content)
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
        encrypted_content = raw_data[32:32 + message_length]
        actual_checksum = zlib.crc32(encrypted_content)

        if expected_checksum != actual_checksum:
            raise ValueError("Checksum verification failed")
        
        message_content = self.decrypt_message(encrypted_content)

        response =  {
            "version_major": version_major,
            "version_minor": version_minor,
            "message_type": message_type,
            "destination_ip": dest_ipv6,
            "destination_port": dest_port,
            "message_length": message_length,
            "checksum": expected_checksum,
            "message_content": message_content
        }
        if multiple_packets:
            response["packet_num"] = packet_num
        else:
            response['multiple_packets'] = False

        return response
