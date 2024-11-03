from protocol.bob2_protocol import Bob2Protocol
import os

if __name__ == "__main__":
    bob2 = Bob2Protocol(encryption_key=os.urandom(32))
    message = bob2.build_message(
        message_type=0,
        dest_ipv6="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        dest_port=12345,
        message_content="Hello, LEO Satellite!"
    )

    parsed_message = bob2.parse_message(message)
    print(parsed_message)
