import struct
import socket
import zlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class Bob2Protocol:
    def __init__(self, version_major=0, version_minor=0, encryption_key=None):
        self.version_major = version_major
        self.version_minor = version_minor

        if encryption_key is None or len(encryption_key) != 32:
            raise ValueError("Encryption key must be a 32-byte (256-bit) value")
        self.encryption_key = encryption_key

    def encrypt_message(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        encrypted_message = iv + encryptor.update(padded_plaintext) + encryptor.finalize()
        return encrypted_message

    def decrypt_message(self, encrypted_message):
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext

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
        if len(raw_data) < 30:
            raise ValueError("Insufficient data for parsing")

        version_major, version_minor, message_type = struct.unpack('!BBB', raw_data[:3])
        dest_ip_bytes = raw_data[3:19]
        dest_ipv6 = socket.inet_ntop(socket.AF_INET6, dest_ip_bytes)
        dest_port = struct.unpack('!H', raw_data[19:21])[0]
        message_length = int.from_bytes(raw_data[21:26], byteorder='big')

        expected_checksum = struct.unpack('!I', raw_data[26:30])[0]
        encrypted_content = raw_data[30:]

        if len(encrypted_content) != message_length:
            raise ValueError("Length of encrypted content does not match the message length")

        decrypted_content = self.decrypt_message(encrypted_content)

        actual_checksum = zlib.crc32(encrypted_content)

        if expected_checksum != actual_checksum:
            raise ValueError("Checksum verification failed")

        return {
            "version_major": version_major,
            "version_minor": version_minor,
            "message_type": message_type,
            "destination_ip": dest_ipv6,
            "destination_port": dest_port,
            "message_length": message_length,
            "checksum": expected_checksum,
            "message_content": decrypted_content.decode('utf-8')
        }
