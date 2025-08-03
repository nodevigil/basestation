# Test if MySQL responds to legitimate protocol at all
# Real MySQL initial handshake packet
echo -ne "\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x32\x35\x00\x36\x00\x00\x00\x7a\x42\x7a\x60\x51\x56\x3b\x55\x00\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x69\x2f\x44\x72\x3d\x3d\x63\x72\x66\x3a\x43\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00" | nc -w 5 mainnet.validator.haedal.xyz 3306 | xxd -c 32

# Try MySQL authentication with timing
(echo -ne "\x20\x00\x00\x01\x85\xa6\xff\x01\x00\x00\x00\x01\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x72\x6f\x6f\x74\x00\x00"; sleep 2) | nc mainnet.validator.haedal.xyz 3306 | strings

# For MongoDB - try different protocol versions
# MongoDB 3.6+ wire protocol
python3 << 'EOF'
import socket
import struct
import time

def send_mongodb_hello(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.connect((host, port))
        print(f"Connected to {host}:{port}")

        # OP_MSG format (MongoDB 3.6+)
        # Try isMaster command
        command = b'{"isMaster": 1, "$db": "admin"}'

        message_length = 21 + len(command)
        request_id = 1
        response_to = 0
        op_code = 2013  # OP_MSG
        flags = 0

        header = struct.pack("<iiii", message_length, request_id, response_to, op_code)
        body = struct.pack("<I", flags) + b'\x00' + command

        full_message = header + body
        print(f"Sending {len(full_message)} bytes")
        s.send(full_message)

        # Try to receive response
        response = s.recv(4096)
        print(f"Received {len(response)} bytes")
        if response:
            print(f"Response hex: {response.hex()[:200]}...")
            print(f"Response ASCII: {response}")
    except socket.timeout:
        print("Connection timed out - possible tarpit")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()

send_mongodb_hello('mainnet.validator.haedal.xyz', 27107)
EOF
