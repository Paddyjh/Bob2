# src/protocol/bob2_protocol.py

import struct
import socket
import zlib
from src.protocol.necessary_headers import Bob2Headers
from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random


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

    def build_message(self, message_type, dest_ipv6, dest_port, source_ipv6, source_port, sequence_number, message_content):
        # Create the header using Bob2Headers
        header = Bob2Headers(
            version_major=self.version_major,
            version_minor=self.version_minor,
            message_type=message_type,
            dest_ipv6=dest_ipv6,
            dest_port=dest_port,
            source_ipv6=source_ipv6,
            source_port=source_port,
            sequence_number=sequence_number
        ).build_header()
        
        encrypted_content = self.encrypt_message(message_content)
        message_length = len(encrypted_content)

        # Calculate checksum
        checksum = zlib.crc32(encrypted_content)
        checksum_bytes = struct.pack('!I', checksum)

        # Build the full message
        message_length = len(encrypted_content)
        length_bytes = message_length.to_bytes(5, byteorder='big')

        full_message = header + length_bytes + \
            checksum_bytes + encrypted_content
        return full_message

    def parse_message(self, raw_data):
        # Parse the header
        header_data = raw_data[:47]  # Header size is 47 bytes
        header_info = Bob2Headers().parse_header(header_data)

        # Parse the rest of the message
        message_length = int.from_bytes(raw_data[47:52], byteorder='big')
        expected_checksum = struct.unpack('!I', raw_data[52:56])[0]
        encrypted_content = raw_data[56:56 + message_length]
        actual_checksum = zlib.crc32(encrypted_content)

        if expected_checksum != actual_checksum:
            raise ValueError("Checksum verification failed")

        message_content = self.decrypt_message(encrypted_content)
        # Add parsed message content to the header info
        header_info.update({
            "message_length": message_length,
            "checksum": expected_checksum,
            "message_content": message_content
        })

        return header_info
