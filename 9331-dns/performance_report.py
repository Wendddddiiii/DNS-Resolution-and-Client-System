from rules import my_DNS, TYPE, CLASS,QueryResponse
import pandas as pd
import socket
import traceback
import time

def get_performance_data(site,server_ip,port):
    timeout = 5
    data = {'domain_name':site,
            'number_of_answers':0,
            'response_code':None,
            'time':None}
    try:
        start_time = time.time()*1000
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP

        # Prepare the DNS query message and send it to the resolver
        udp_socket.sendto(my_DNS(site, TYPE['A'], CLASS["IN"]), (server_ip, port))
        udp_socket.settimeout(timeout)

        response = udp_socket.recv(1024)
        end_time = time.time()*1000
        query_resp = QueryResponse(response)
        data['number_of_answers']=query_resp.number_of_answers
        data['response_code']=query_resp.response_code
        data['time']=end_time-start_time
    except socket.timeout:
        data['response_code']=4
        print("Timeout: Resolver did not respond in time.")
    except Exception as e:
        data['response_code']=5
        print(f"An error occurred: {e}")
        traceback.print_exc()
    finally:
        udp_socket.close()
    return data

def test_server(sites,server_ip,port):
    performance_data = []
    total = len(sites)
    i = 0
    for domain_name in sites:
        if(i%10==0):
            print(f'{i}/{total}')
        i+=1
        data = get_performance_data(domain_name,server_ip,port)
        performance_data.append(data)
    return performance_data

if __name__=='__main__':
    servers={
        'MyResolver':{'name':'MyResolver','ip':'127.0.0.1','port':5300},
        'OpenDNS':{'name':'OpenDNS','ip':'208.67.222.222','port':53},
        'GoogleDNS':{'name':'GoogleDNS', 'ip': '8.8.8.8', 'port': 53}
    }

    server = servers['MyResolver']

    sites = []
    with open('sites.txt', 'r') as file:
        sites = file.read().splitlines()

    data = test_server(sites,server['ip'],server['port'])
    df = pd.DataFrame(data)
    df.to_csv(server['name']+"_report.csv")
