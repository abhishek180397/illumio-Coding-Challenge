import pandas as pd
import heapq

class Firewall:

   
    
    def __init__(self, filepath):
        """creates firewall object based on csv of rules"""

        rules = pd.read_csv(filepath, names=["direction", "protocol", "port_r", "ip_address_r"])

        # 1-> inbound and tcp  2-> inbound and udp 3->outbound and tcp 4-> outbound and udp
         
        self.inb_tcp= rules[(rules["direction"]=='inbound') & (rules["protocol"]=="tcp")]
        self.outb_tcp = rules[(rules["direction"]=='outbound') & (rules["protocol"]=="tcp")]
        self.inb_udp = rules[(rules["direction"]=='inbound') & (rules["protocol"]=="udp")]
        self.outb_udp = rules[(rules["direction"]=='outbound') & (rules["protocol"]=="udp")]
        self.map = {"inbound": {"tcp": self.inb_tcp, "udp": self.inb_udp}, "outbound": {"tcp": self.outb_tcp, "udp": self.outb_udp}}
    

    def accept_packet(self, direction, protocol, port, ip_address):

        #rtype:boolean
        # direction (string): “inbound” or “outbound”
        # protocol (string): exactly one of “tcp” or “udp”, all lowercase
        # port (integer) – an integer in the range [1, 65535]
        # ip_address (string): a single well-formed IPv4 address.

        rules = self.map[direction][protocol] 

        for row in rules.head().itertuples():
            rule_port, rule_ip = row.port_r, row.ip_address_r
            rule_port_r, rule_ip_r = range_out_port(rule_port), range_out_ip(rule_ip)
            if range_in_port(port, rule_port_r) and range_in_ip(ip_address, rule_ip_r):
                return True
        return False

# class Rule:
#     def __init__(self, direction, protocol, port_r, ip_address_r):
#         """ Standardize port and ip_address to all be ranges"""
#         self.direction = direction
#         self.protocol = protocol
#         self.port_r = port_r #list containing start and end (inclusive)
#         self.ip_address_r = ip_address_r #list containing start and end (inclusive)



# helper functions

def range_in_port(value, r): 
    if value >= r[0] and value <= r[1]:
        return True
    else:
        return False

def range_in_ip(value, r):
    #for comparision converts ip to list
    value_ip = list(map(int, value.split('.')))
    start_ip = list(map(int, r[0].split('.')))
    end_ip = list(map(int, r[1].split('.')))
    if value_ip >= start_ip and value_ip <= end_ip:
        return True
    else:
        return False

def range_out_port(port):
        #converts input to range if it isn't already
        #returns list of start and end (inclusive)

        if "-" in port:
            port_r = port.split("-")
            port_r[0] = int(port_r[0])
            port_r[1] = int(port_r[1])
        else:
            port_r = [int(port), int(port)]
        return port_r

def range_out_ip(ip):
    if "-" in ip:
        ip_r = ip.split("-")
    else:
        ip_r = [ip, ip]
    return ip_r



def intervals(arr):
    interval = []
    heap = arr.deepcopy()
    heapq.heapify(heap)
    if len(heap) == 0:
        return []
    first= heapq.heappop(heap)
    while len(heap) > 0:
        second = heapq.heappop(heap)
        if first[1] >= second[0]:
            second = [first[0], second[1]]
        else:
            interval.append(first)
        first = second
    interval.append(first)
    return interval

#test cases

fw = Firewall("fw.csv")
print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")) # matches first rule
print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1")) # matches third rule
print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11")) # matches second rule
print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2")) # false
print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92")) # false
