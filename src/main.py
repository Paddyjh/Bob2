from protocol.bob2_protocol import Bob2Protocol

if __name__ == "__main__":
    device_a = Bob2Protocol()
    device_b = Bob2Protocol()

    device_a_public_key = device_a.initiate_key_exchange()
    device_b_public_key = device_b.initiate_key_exchange()

    # The public keys need to be exchanged between devices at this stage
    device_a.complete_key_exchange(device_b_public_key.encode())
    device_b.complete_key_exchange(device_a_public_key.encode())

    message_content = "Hello from Device A to Device B!"
    message = device_a.build_message(
        message_type=0,
        dest_ipv6="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        dest_port=12345,
        message_content=message_content
    )

    parsed_message = device_b.parse_message(message)
    parsed_message_content = parsed_message["message_content"]
    print("Decrypted message on Device B:", parsed_message_content)

    assert parsed_message_content == message_content, "Message content mismatch!"
    print("Message transmission successful.")

