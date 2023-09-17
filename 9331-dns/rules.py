
import struct 
import socket
import dataclasses 
from dataclasses import dataclass
import random

TYPE = {
    "A": 1,
    "NS": 2,
    "CNAME":5,
    "PTR":12,
    "MX":15,
}

CLASS = {
    "IN": 1,
    "CS": 2,
}


@dataclass
class dnsquery:
    name: bytes
    type: int
    class_: int

@dataclass
class dnsrecord:
    name: bytes
    type: int
    class_: int
    ttl:int
    length:int
    data:str
    

@dataclass
class header:
    id: int
    flags: int
    number_of_questions: int
    number_of_answers: int
    number_of_authorities: int
    number_of_additions: int


@dataclass
class Flag:
    QR: int
    Opcode: int
    AA: int
    TC: int
    RD: int
    RA: int
    zero: int
    rCode: int

def my_DNS(name, record_type, query_class):
    # convert name to bytes
    name_parts = name.split(".")
    name_bytes = b"".join(struct.pack("B", len(part)) + part.encode("ASCII") for part in name_parts) + b"\x00"
    
    id = random.randint(0, 65535)
    flags = Flag(0, 0, 0, 0, 1, 0, 0, 0)
    header1 = header(id, int(flags.QR << 15 | flags.Opcode << 11 | flags.AA << 10 | flags.TC << 9 | flags.RD << 8 | flags.RA << 7 | flags.zero << 4 | flags.rCode), 1, 0, 0, 0)
  
    query1 = dnsquery(name_bytes, record_type, query_class)
    
    header_bytes = struct.pack("!HHHHHH", *dataclasses.astuple(header1))
    
    query_bytes = name_bytes + struct.pack("!HH", record_type, query_class)
    
    return header_bytes + query_bytes


def read_domain_name(response, offset):
    parts=[]
    if(response[offset]==0xc0):
        offset1 = response[offset+1]
        parts,_ = read_label(response,offset1)
        _,offset = read_label(response,offset)
    # parts = []
    # while True:
    #     length = response[offset]
    #     if length == 0:
    #         offset += 1
    #         break
    #     offset += 1
    #     parts.append(response[offset : offset + length].decode("ASCII"))
    #     offset += length
    else:
        parts,offset = read_label(response,offset)
    name = ".".join(parts).encode("ASCII")
    return name, offset

def parse_domain_name(data,response):
    offset=0
    parts=[]
    while True and offset<len(data):
        #to the end
        if data[offset]==0xc0:
            p,_=read_label(response,data[offset+1])
            parts.extend(p)
            break
        length = data[offset]
        if length == 0:
            break
        offset += 1
        parts.append(data[offset : offset + length].decode("ASCII"))
        offset += length
    return ".".join(parts).encode("ASCII").decode('utf-8')

def read_resource_record(response, offset):
    name, offset = read_domain_name(response, offset)
    r_type, r_class, r_ttl, r_length = struct.unpack("!HHIH", response[offset : offset + 10])
    data = response[offset + 10 : offset + 10 + r_length]
    offset += 10 + r_length
    if r_type == 1:  # "A" record type
        data = socket.inet_ntoa(data)
    elif r_type==2 or r_type == 5 or r_type == 12: #"CNAME"
        data=parse_domain_name(data,response)
    record =dnsrecord(name, r_type, r_class, r_ttl, r_length, data)
    return record, offset


def resolve(response):
    # decode
    id, flags, number_of_questions, number_of_answers, number_of_authorities, number_of_additions = struct.unpack("!HHHHHH", response[:12])
    # Initialize variables to store the resource records
    questions = []
    answers = []
    authorities = []
    additions = []

    # Process resource records
    offset = 12  # Start offset for reading resource records
    for _ in range(number_of_questions):
        # Read question section (for simplicity, we skip the actual processing here)
        offset = response.find(b"\x00", offset) + 5

    for _ in range(number_of_answers):
        record, offset = read_resource_record(response, offset)
        answers.append(record)

    for _ in range(number_of_authorities):
        record, offset = read_resource_record(response, offset)
        authorities.append(record)

    for _ in range(number_of_additions):
        record, offset = read_resource_record(response, offset)
        additions.append(record)

    #extract the IP addresses from the answer section
    ip_addresses = []
    for answer in answers:
        ip_addresses.append(answer.data)
    return ip_addresses

def read_label(response,offset):
    parts=[]
    while True and offset<len(response):
        #to the end
        if response[offset]==0xc0:
            offset+=2
            continue
        length = response[offset]
        if length == 0:
            #offset += 1
            break
        offset += 1
        parts.append(response[offset : offset + length].decode("ASCII"))
        offset += length
    return parts,offset

def get_query_type_class(response):
    r_type,r_class = 0,0
    offset = 12
    while offset<len(response):
        if response[offset]==0:
            offset+=1
            break
        offset+=1
    if (offset+4)<=len(response):
        r_type,r_class = struct.unpack('!HH',response[offset:offset+4])
    return r_type,r_class

def reverse_dns_lookup(ip_address):
    ip_parts = ip_address.split('.')
    ip_parts.reverse()
    reversed_ip = '.'.join(ip_parts)
    reversed_dns = reversed_ip + '.in-addr.arpa'
    return reversed_dns

class QueryResponse:
    def __init__(self,response):
        self.id, self.flags, self.number_of_questions, self.number_of_answers, self.number_of_authorities, self.number_of_additions = struct.unpack("!HHHHHH", response[:12])
        self.questions = []
        self.answers = []
        self.authorities = []
        self.additions = []
        self.response_code = self.flags & 3
        #print(self.number_of_questions,self.number_of_answers,self.number_of_authorities,self.number_of_additions)
            # Process resource records
        offset = 12  # Start offset for reading resource records
        for _ in range(self.number_of_questions):
            # Read question section (for simplicity, we skip the actual processing here)
            offset = response.find(b"\x00", offset) + 5

        for _ in range(self.number_of_answers):
            record, offset = read_resource_record(response, offset)
            self.answers.append(record)

        for _ in range(self.number_of_authorities):
            record, offset = read_resource_record(response, offset)
            self.authorities.append(record)

        for _ in range(self.number_of_additions):
            record, offset = read_resource_record(response, offset)
            self.additions.append(record)