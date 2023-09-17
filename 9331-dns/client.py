import sys
import socket
import struct 
import traceback
from rules import my_DNS, TYPE, CLASS,resolve

if len(sys.argv) < 4 or len(sys.argv)>5:
    print("Error: invalid arguments")
    print("Usage: client resolver_ip resolver_port name [type=A]")
    sys.exit(1)

resolver_ip = sys.argv[1]
resolver_port = int(sys.argv[2])
domain_name = sys.argv[3]
timeout=5
query_type = 'A'
if (len(sys.argv)==5):
    query_type = sys.argv[4].upper()
if query_type not in TYPE.keys():
    print("Error: invalid arguments")
    print("Only the following types of queries are supported:",','.join(TYPE.keys()))
    sys.exit(1)

# if not (1025 <= resolver_port <= 65535):
#     print("Error: invalid arguments")
#     print("resolver_port should be a value in the range 1024 – 65535")
#     sys.exit(1)

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP

# Prepare the DNS query message and send it to the resolver
udp_socket.sendto(my_DNS(domain_name, TYPE[query_type], CLASS["IN"]), (resolver_ip, resolver_port))

udp_socket.settimeout(timeout)

try:
    response = udp_socket.recv(1024)
    dns_header = response[:12]
    # Extract the response code from the DNS header
    #response_code = struct.unpack("!H", dns_header[3:5])[0] 
    id, flags, number_of_questions, number_of_answers, number_of_authorities, number_of_additions = struct.unpack("!HHHHHH", dns_header)
    response_code = flags & 3
    # Check if there's an error code in the response
    if response_code == 1:
        print("Error: Format Error - The name server was unable to interpret the query.")
    elif response_code == 2:
        print("Error: Server Failure - The name server was unable to process the query.")
    elif response_code == 3:
        print(f"Error: Name Error - The server can't find the domain name '{domain_name}'.")
    else:
        answers = resolve(response)
        print(f"Successfully received answers: {answers}")

except socket.timeout:
    print("Timeout: Resolver did not respond in time.")
except Exception as e:
    print(f"An error occurred: {e}")
    traceback.print_exc()
finally:
    udp_socket.close()
