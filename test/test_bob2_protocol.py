import unittest
# Use the following two lines only on Windows, as the project path was not recognized
import sys
sys.path.append('../')
from src.protocol.bob2_protocol import Bob2Protocol
import os

class TestBob2Protocol(unittest.TestCase):
    def setUp(self):
        self.encryption_key = os.urandom(32)
        self.bob2 = Bob2Protocol(encryption_key=self.encryption_key)

    def test_message_build_and_parse(self):
        message_content = "Test Message"
        message = self.bob2.build_message(
            message_type=1,
            dest_ipv6="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            dest_port=12345,
            message_content=message_content
        )
        parsed_message = self.bob2.parse_message(message)
        self.assertEqual(parsed_message["message_content"], message_content)

    def test_encryption(self):
        message_content = "This is a test message"
        encrypted_message = self.bob2.build_message(
            message_type=1,
            dest_ipv6="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            dest_port=12345,
            message_content=message_content
        )

        self.assertNotIn(message_content.encode('utf-8'), encrypted_message, 
                         "Message content should be encrypted and not appear in plaintext")

        parsed_message = self.bob2.parse_message(encrypted_message)
        self.assertEqual(parsed_message["message_content"], message_content,
                         "Decrypted message content should match the original")

if __name__ == "__main__":
    unittest.main()
