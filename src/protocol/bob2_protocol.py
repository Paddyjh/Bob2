import struct
import socket
import zlib
import os
from nacl.secret import SecretBox
from nacl.utils import random

class Bob2Protocol:
    def __init__(self, version_major=0, version_minor=0, key = None):
        self.version_major = version_major
        self.version_minor = version_minor
        self.key = key or random(SecretBox.KEY_SIZE)
        
    def encrypt_message(self, message_content):
        nonce = random(24)
        box = SecretBox(self.key)
        encrypted_content = box.encrypt(message_content.encode('utf-8'), nonce)

        return nonce + encrypted_content.ciphertext

    def decrypt_message(self, encrypted_content):
        nonce = encrypted_content[:24]
        content = encrypted_content[24:]
        box = SecretBox(self.key)
        decrypted_content = box.decrypt(nonce + content)
        
        return decrypted_content.decode('utf-8')

    def build_message(self, message_type, dest_ipv6, dest_port, message_content):
        try:
            dest_ip_bytes = socket.inet_pton(socket.AF_INET6, dest_ipv6)
        except socket.error:
            raise ValueError("Invalid IPv6 address")

        header = struct.pack('!BBB', self.version_major, self.version_minor, message_type)
        dest_port_bytes = struct.pack('!H', dest_port)
        
        encrypted_content = self.encrypt_message(message_content)

        message_length = len(encrypted_content)
        if message_length > (1 << 40) - 1:
            raise ValueError("Message content exceeds maximum allowed size")

        length_bytes = message_length.to_bytes(5, byteorder='big')
        checksum = zlib.crc32(encrypted_content)
        checksum_bytes = struct.pack('!I', checksum)

        full_message = (header + dest_ip_bytes + dest_port_bytes + length_bytes +
                        checksum_bytes + encrypted_content)
        return full_message

    def parse_message(self, raw_data):
        version_major, version_minor, message_type = struct.unpack('!BBB', raw_data[:3])
        dest_ip_bytes = raw_data[3:19]
        dest_ipv6 = socket.inet_ntop(socket.AF_INET6, dest_ip_bytes)
        dest_port = struct.unpack('!H', raw_data[19:21])[0]
        message_length = int.from_bytes(raw_data[21:26], byteorder='big')

        expected_checksum = struct.unpack('!I', raw_data[26:30])[0]
        encrypted_content = raw_data[30:30 + message_length]
        actual_checksum = zlib.crc32(encrypted_content)

        if expected_checksum != actual_checksum:
            raise ValueError("Checksum verification failed")
        
        message_content = self.decrypt_message(encrypted_content)

        return {
            "version_major": version_major,
            "version_minor": version_minor,
            "message_type": message_type,
            "destination_ip": dest_ipv6,
            "destination_port": dest_port,
            "message_length": message_length,
            "checksum": expected_checksum,
            "message_content": message_content
        }
