import sys
import socket
import struct
import random
from rules import read_domain_name, my_DNS, TYPE, CLASS,get_query_type_class,reverse_dns_lookup,QueryResponse

def read_root_hints(filename):
    root_hints = []

    with open(filename, "r") as file:
        lines = file.readlines()

    record = {}
    for line in lines:
        parts = line.strip().split()
        if not parts:
            continue

        if parts[0].startswith(";"):
            continue

        if parts[0] == ".":
            if record:
                root_hints.append(record)
                record = {}
        else:
            if parts[2] == "A": 
                record["name"] = parts[0]
                record["ttl"] = int(parts[1])
                record["type"] = parts[2]
                record["data"] = parts[3]
    
    if record:
        root_hints.append(record)

    return root_hints

def resolve_query(query,root_hints):
    r_type,r_class = get_query_type_class(query)
    if r_type==TYPE['A']:
        return resolve_query_a(query,root_hints)
    else:
        return resolve_query_other(query,root_hints)

def check_response_code(response):
    # Extract the response code from the DNS header
    dns_header = response[:12]
    id, flags, number_of_questions, number_of_answers, number_of_authorities, number_of_additions = struct.unpack("!HHHHHH", dns_header)
    response_code = flags & 3

    domain_name, _ = read_domain_name(query, 12)
    domain_name = domain_name.decode("ASCII")

    # Check if there's an error code in the response
    if response_code == 1:
        print("Error: Format Error - The name server was unable to interpret the query.")
    elif response_code == 2:
        print("Error: Server Failure - The name server was unable to process the query.")
    elif response_code == 3:
        print(f"Error: Name Error - The server can't find the domain name '{domain_name}'.")

def resolve_query_a(query,root_hints):
    domain_name, _ = read_domain_name(query, 12)
    domain_name = domain_name.decode("ASCII")
    r_type,r_class = get_query_type_class(query)

    root_hint = random.choice(root_hints)
    root_ip = root_hint["data"]
    server_ip = root_ip

    #record_type = TYPE["A"]
    record_type = r_type
    query_class = CLASS["IN"]

    dns_query_message = my_DNS(domain_name, record_type, query_class)
    flag_sucess = False 
    response=[]
    while  not flag_sucess:
        root_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        root_udp_socket.sendto(dns_query_message, (server_ip, 53))
        root_udp_socket.settimeout(5)
        response, _ = root_udp_socket.recvfrom(1024)
        root_udp_socket.close()
        query_resp = QueryResponse(response)
        if(query_resp.response_code!=0):
            break
        if query_resp.number_of_answers==0:
            if query_resp.number_of_additions>0:
                server_ip = query_resp.additions[0].data
            else:
                break
        elif query_resp.answers[0].type==5:
            dns_query_message = my_DNS(query_resp.answers[0].data, record_type, query_class)
            server_ip = root_ip
        elif query_resp.answers[0].type==1:
            flag_sucess = True
    check_response_code(response)
    return response

def resolve_query_other(query,root_hints):
    r_type,r_class = get_query_type_class(query)
    domain_name, _ = read_domain_name(query, 12)
    domain_name = domain_name.decode("ASCII")

    if r_type == TYPE["PTR"]:
        domain_name = reverse_dns_lookup(domain_name)

    root_hint = random.choice(root_hints)
    root_ip = root_hint["data"]
    server_ip = root_ip

    record_type = r_type
    query_class = CLASS["IN"]

    dns_query_message = my_DNS(domain_name, record_type, query_class)
    flag_sucess = False 
    response=[]
    while  not flag_sucess:
        root_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if r_type==TYPE['PTR']:
            server_ip = '114.114.114.114'
        root_udp_socket.sendto(dns_query_message, (server_ip, 53))
        root_udp_socket.settimeout(5)
        response, _ = root_udp_socket.recvfrom(1024)
        root_udp_socket.close()

        query_resp = QueryResponse(response)
        if(query_resp.response_code!=0):
            break
        if query_resp.number_of_answers==0:
            if query_resp.number_of_additions>0:
                server_ip = query_resp.additions[0].data
            else:
                break
        elif query_resp.answers[0].type==r_type:
            flag_sucess = True
        else:
            break

    check_response_code(response)
    return response


if len(sys.argv) != 2:
    print("Error: invalid arguments")
    print("Usage: resolver port")
    sys.exit(1)

port = int(sys.argv[1])

if not (1024 <= port <= 65535):
    print("Error: invalid arguments")
    print("resolver_port should be a value in the range 1024 – 65535")
    sys.exit(1)

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
udp_socket.bind(("127.0.0.1", port))


print(f"Resolver is listening on 127.0.0.1: {port}")

root_hints = read_root_hints("named.root")
while True:
    udp_socket.settimeout(None)
    query, client_address = udp_socket.recvfrom(1024)
    print(f"Received query from {client_address}")
    timeout = 10
    udp_socket.settimeout(timeout)
    try:
        response = resolve_query(query,root_hints)
        udp_socket.sendto(response, client_address)
    except socket.timeout:
        print("Timeout: Resolver did not respond in time.")
    except Exception as e:
        print(f"An error occurred: {e}")
 

