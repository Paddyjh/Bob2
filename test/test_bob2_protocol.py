import unittest
from src.protocol.bob2_protocol import Bob2Protocol

class TestBob2Protocol(unittest.TestCase):
    def setUp(self):
        self.bob2 = Bob2Protocol()

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

if __name__ == "__main__":
    unittest.main()
