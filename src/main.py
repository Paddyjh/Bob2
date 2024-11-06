import argparse
from protocol.bob2_protocol import Bob2Protocol


def main():
    parser = argparse.ArgumentParser(
        description="Bob2 Protocol Message Builder and Parser")

    parser.add_argument('--version_major', type=int,
                        required=True, help='Protocol version major')
    parser.add_argument('--version_minor', type=int,
                        required=True, help='Protocol version minor')
    parser.add_argument('--message_type', type=int, required=True,
                        help='Message type (e.g., data, control, etc.)')
    parser.add_argument('--dest_ipv6', type=str,
                        required=True, help='Destination IPv6 address')
    parser.add_argument('--dest_port', type=int,
                        required=True, help='Destination port number')
    parser.add_argument('--source_ipv6', type=str,
                        required=True, help='Source IPv6 address')
    parser.add_argument('--source_port', type=int,
                        required=True, help='Source port number')
    parser.add_argument('--sequence_number', type=int,
                        required=True, help='Sequence number for the message')
    parser.add_argument('--message_content', type=str,
                        required=True, help='Content of the message')

    args = parser.parse_args()

    device_a = Bob2Protocol()
    device_b = Bob2Protocol()

    device_a_public_key = device_a.initiate_key_exchange()
    device_b_public_key = device_b.initiate_key_exchange()

    # The public keys need to be exchanged between devices at this stage
    device_a.complete_key_exchange(device_b_public_key.encode())
    device_b.complete_key_exchange(device_a_public_key.encode())

    # Build the message
    message = device_a.build_message(
        message_type=args.message_type,
        dest_ipv6=args.dest_ipv6,
        dest_port=args.dest_port,
        source_ipv6=args.source_ipv6,
        source_port=args.source_port,
        sequence_number=args.sequence_number,
        message_content=args.message_content
    )
    
    parsed_message = device_b.parse_message(message)
    parsed_message_content = parsed_message["message_content"]
    print("Decrypted message on Device B:", parsed_message_content)

    assert parsed_message_content == args.message_content, "Message content mismatch!"
    print("Message transmission successful.")

if __name__ == "__main__":
    main()