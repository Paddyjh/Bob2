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
    encrypted_message = device_a.encrypt_message(message_content)

    decrypted_message = device_b.decrypt_message(encrypted_message)
    print("Decrypted message on Device B:", decrypted_message)

    assert decrypted_message == message_content, "Message content mismatch!"
    print("Message transmission successful.")

