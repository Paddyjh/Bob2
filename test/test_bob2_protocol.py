import unittest
from src.protocol.bob2_protocol import Bob2Protocol

class TestBob2Protocol(unittest.TestCase):
    def setUp(self):
        self.device_a = Bob2Protocol()
        self.device_b = Bob2Protocol()

    def test_message_build_and_parse(self):
        
        device_a_public_key = self.device_a.initiate_key_exchange()
        device_b_public_key = self.device_b.initiate_key_exchange()

        self.device_a.complete_key_exchange(device_b_public_key.encode())
        self.device_b.complete_key_exchange(device_a_public_key.encode())
        message_content = "Test Message"
        
        message = self.device_a.build_message(
            message_type=1,
            dest_ipv6="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            dest_port=12345,
            message_content=message_content
        )
        parsed_message = self.device_b.parse_message(message)
        parsed_message_content = parsed_message["message_content"]
        self.assertEqual(parsed_message_content, message_content)

if __name__ == "__main__":
    unittest.main()
