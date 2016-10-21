'''
author: Jakub Syrek
OS: Manjaro Linux 4.1.12-1
Interpreter: Python 2.7.10
Date: 11 November 2015
'''

import socket, sys, time, random
from struct import *


#--------------------------------------------
#---------------Parser-----------------------
#--------------------------------------------

#parse program options
def parse_args():
    #check how many arguments
    try:
      raw = sys.argv[3]
      scanner_type = sys.argv[2]
      ip = sys.argv[1]
    except:
      print "Usage: scanner.py IP [TCP-Connect/TCP-SYN] PORTS"
      sys.exit()

    #parse port numbers into table
    separate = raw.split(',')
    ports = []
    for argument in separate:
        rng = argument.split('-')
        if rng.__len__() >= 2:
            for x in range(int(rng[0]),int(rng[1])):
                ports.append(x)
                pass
        else:
            ports.append(int(argument))
        pass

    # Select scanner type
    if scanner_type=="Connect":
        print '\n\nTCP_CONNECT_SCAN'
        tcp_connect(ip, ports)
        pass
    elif scanner_type=="SYN":
        print '\n\nTCP_SYN_SCAN'
        tcp_syn(ip, ports)
        pass
    elif 1:
        print "Incorrect scan type"
        sys.exit()

#--------------------------------------------
#---------------TCP_connect------------------
#--------------------------------------------

#scanning for open ports using system sockets
def tcp_connect(ip, ports):
    #create a socket
    try:
        #AF_INET -> Internet Protocol v4 addresses, STREAMing socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error,err_msg:
      print 'Cannot create a socket'
      sys.exit()

    #checking ports
    for port in ports:
        try:
            #try to connect, if success port is opened
            result = s.connect_ex((ip,port))
            if result == 0:
                print 'port ' + str(port) + ' open'
                pass
            #close scoket and prepare new one
            s.close()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            pass

#--------------------------------------------
#---------------TCP_SYN----------------------
#--------------------------------------------

# create checksum
def make_checksum(data):

#From Wikipedia:
#The checksum field is the 16 bit one's complement of the one's complement sum of all 16-bit words in the header and text.
#If a segment contains an odd number of header and text octets to be checksummed,
#the last octet is padded on the right with zeros to form a 16-bit word for checksum purposes.
#The pad is not transmitted as part of the segment. While computing the checksum, the checksum field itself is replaced with zeros.

    result = 0
    # taking 2 characters to convert
    for i in range(0, len(data), 2):
        word = (ord(data[i]) <<8) + (ord(data[i+1]))
        result = result + word

    # 0xffff is binary 1111111111111111, AND operator, shift data 16 bits right
    result = (result>>16) + (result & 0xffff);
    # negation result and AND operator with 1111111111111111 bits
    result = ~result & 0xffff
    return result

#----------------------------------------------------

#create a raw socket
def raw_socket():
    try:
        #AF_INET -> Internet Protocol v4 addresses, RAW socket, RAW TCP ip packets
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error,err_msg:
        print 'Cannot create a socket'
        sys.exit()

    #set options on sockets
    #IPPROTO_IP = Dummy protocol for TCP (raw packet)
    #IP_HDRINCL = The IPv4 layer DONT generates an IP header (we do that)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return s

#----------------------------------------------------
def create_ip_header(src, dst):

    # ip header fields
    header_length = 5  # Internet Header Length, the minimum value for this field is 5 (RFC 791), which is a length of 5x32 = 160 bits = 20 bytes
    ver = 4 # version IPv4
    TOS = 0 # Type of service (0 = default)
    #This 16-bit field defines the entire packet size, including header and data, in bytes.
    #The minimum-length packet is 20 bytes (20-byte header + 0 bytes data). I use aditional 20 bytes of data
    length = 20 + 20
    id = random.randrange(1,1000,1) # uniquely identifying the group of fragments of a single IP datagram
    offset = 0 # The fragment offset field, default
    ttl = 255 # Time To leave, default
    prot = socket.IPPROTO_TCP # protocol TCP
    checsum = 10 # the 16-bit header checsum field is used for error-checsuming of the header
    # inet_aton -> converts the Internet host address cp from the IPv4 numbers-and-dots notation into binary form
    source = socket.inet_aton(src) # source adress
    destination = socket.inet_aton(dst) # destination adress

	#we have to shift the first element 4 bits left
	#first four bits are ip version and the last 4 bites are the header lenght
    hl_ver = (ver << 4) + header_length
    # pack all elements into ip header
    ip_header = pack('!BBHHHBBH4s4s', hl_ver, TOS, length, id, offset, ttl, prot, checsum, source, destination)

    #return ready header
    return ip_header

#----------------------------------------------------
def create_tcp_syn_header(src, dst, port):

    # --- tcp header fields---

    src_port = random.randrange(1,100,1)    # source port
    #SYN flag is set (1) -> this is the initial sequenceuence number.
    #The sequenceuence number of the actual first data byte and the acknowledged number in the corresponding ACK are then this sequenceuence number plus 1.
    sequence = 0
    # Acknowledgment number
    ack_sequence = 0
    #data offset
    offset = 5

    #----- tcp flags----- => only syn has value 1
    syn = 1
    fin = 0
    ack = 0
    rst = 0
    urg = 0
    psh = 0

    # shift left 6 flags to create flags header
    tcp_flags = fin +\
            (syn << 1) +\
            (rst << 2) +\
            (psh << 3) +\
            (ack << 4) +\
            (urg << 5)

    #Window size -> the size of the receive window, which specifies the number of window size units
    win_size = socket.htons (8192)    # maximum value = 8192

    # checksum, for now 0
    checksum = 0

    # Urgent pointer -> if the URG flag is set, then this 16-bit field is an offset from the sequence number indicating the last urgent data byte
    urg_pointer = 0

    # Reserved (3 bits) for future use and should be set to zero
    # have to shift offset left and add 0
    offset_reserved = (offset << 4) + 0

    # pack all elements into tcp header
    tcp_header = pack('!HHLLBBHHH', src_port, port, sequence, ack_sequence, offset_reserved, tcp_flags, win_size, checksum, urg_pointer)

    # other fields
    # inet_aton -> converts the Internet host address cp from the IPv4 numbers-and-dots notation into binary form
    src_port_address = socket.inet_aton(src) # source adress
    dest_address = socket.inet_aton(dst) # destination adress

    # SYN placeholder
    placeholder = 0
    protocol = socket.IPPROTO_TCP #TCP
    tcp_len = len(tcp_header) #length of tcp header

    # pack header to prepare checksum
    data = pack('!4s4sBBH', src_port_address, dest_address, placeholder, protocol, tcp_len);
    data = data + tcp_header;
    tcp_checksum = make_checksum(data)

    #make the tcp header again and fill in the correct checksum
    tcp_header = pack('!HHLLBBHHH', src_port, port, sequence, ack_sequence, offset_reserved, tcp_flags, win_size, tcp_checksum, urg_pointer)
    return tcp_header

#----------------------------------------------------
def TCP_SYN_SCAN(src, dest, port):

    # create raw socket
    s = raw_socket()
    # create ip header
    ip_header = create_ip_header(src, dest)
    # create tcp header
    tcp_header = create_tcp_syn_header(src, dest,port)
    # create packet connecting tcp and ip header
    packet = ip_header + tcp_header
    #send packet using raw socket
    s.sendto(packet, (dest, 0))
    # receive a message from a socket
    data = s.recvfrom(1024) [0][0:]

    # create information from recived packet
    # 0x0f is a hexadecimal representation of a byte, & is s a bitwise AND operation.
    ip_header_length = (ord(data[0]) & 0x0f) * 4
    ip_header_data = data[0: ip_header_length - 1]
    # 0xf0 is decimal 240, shift right 2 bits
    tcp_header_length = (ord(data[32]) & 0xf0)>>2
    tcp_header_data = data[ip_header_length:ip_header_length+tcp_header_length - 1]

    # SYN/ACK flags are set = port is opened
    if ord(tcp_header_data[13]) == 0x12:
        print 'port ' + str(port) + ' open'
    return port

def tcp_syn(ip, ports):
    # get ipaddres of our machine using simple socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("google.com",80))
    ipsource = str(s.getsockname()[0])
    s.close()

    # scan to find all open ports
    for port in ports:
        TCP_SYN_SCAN(ipsource, ip, port)
        time.sleep(0.1)
        pass

#--------------------------------------------
#---------------Main-------------------------
#--------------------------------------------
if __name__=='__main__':
    parse_args()
