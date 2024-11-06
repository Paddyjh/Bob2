PYTHONPATH=$(pwd)/src python3 test/test_bob2_protocol.py \
# --version_major 1 --version_minor 0 --message_type 1 \
# --dest_ipv6 "2001:0db8:85a3:0000:0000:8a2e:0370:7334" --dest_port 12345 \
# --source_ipv6 "2001:0db8:85a3:0000:0000:8a2e:0370:1111" --source_port 54321 \
# --sequence_number 42 --message_content "Test Message"