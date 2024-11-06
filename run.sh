#!/bin/zsh

python3 -m venv venv

source ./venv/bin/activate

pip3 install -r requirements.txt

# source_ipv6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d'/' -f1)
# echo "Source IPv6: $source_ipv6"



# to run main.py
python3 src/main.py --version_major 1 --version_minor 0 --message_type 0 \
--dest_ipv6 "2001:0db8:85a3:0000:0000:8a2e:0370:7334" --dest_port 12345 \
--source_ipv6 "2001:0db8:85a3:0000:0000:8a2e:0370:1111" --source_port 54321 \
--sequence_number 1 --message_content "Hello, LEO Satellite\!"


# to test
PYTHONPATH=$(pwd)/src python3 test/test_bob2_protocol.py \
--version_major 1 --version_minor 0 --message_type 1 \
--dest_ipv6 "2001:0db8:85a3:0000:0000:8a2e:0370:7334" --dest_port 12345 \
--source_ipv6 "2001:0db8:85a3:0000:0000:8a2e:0370:1111" --source_port 54321 \
--sequence_number 42 --message_content "Test Message"


# to run flask server 
python3 main.py --port 8189


# to get your satellites
python3 get_my_satellites.py --ping_ip 10.35.70 --curl_addr http://10.35.70.1:8189 --output_csv ping_results.csv

