import socket
import sys
import struct
import time

# load config file
dict = {}
file = open('config', 'r')
while True:
    line = file.readline()
    if not line:
        break
    ip, name = line.strip('\n').split(' ')
    dict[name] = ip

# create sockets
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
clientAddr = ('localhost', 53)
clientSocket.bind(clientAddr)

while True:
    # receive dns query from local client
    print('waiting for dns request...')
    data, recvAddr = clientSocket.recvfrom(4096)
    time_start = time.time()

    # convert dns message to domain name
    name = list(data.decode('utf-8', 'ignore'))[11:]
    for i in range(len(name)):
        if name[i] != '-' and name[i].isalnum() == False:
            name[i] = '.'
    name = ''.join(name).strip('.')

    # find record in local config
    if dict.__contains__(name):
        s = list(struct.unpack('>'+'B'*len(data), data))    # convert request bytes to int
        
        s[2] = 0x80                                         # set QR = 1
        s[7] = 0x01                                         # set ANCOUNT = 1
        s += s[12:]                                         # repeat Question
        s[-1:-5:-1] = [0x01, 0x00, 0x01, 0x00]              # hide ipv6
        s += [0x00, 0x00, 0x00, 0x01]                       # set TTL = 1
        s += [0x00, 0x04]                                   # set RDLENGTH = 4
        
        if dict[name] == '0.0.0.0':                         # Intercept
            print('request name(intercept): ' + name)
            s[3] = 0x03
        else:
            print('request name(local resolve): ' + name)
        ip = dict[name].split('.')                          # find ip address
        s += [int(x) for x in ip]                           # add ip to respond message
        
        # send respond to local client
        data = struct.pack('>'+'B'*len(s), *s)
        clientSocket.sendto(data, recvAddr)
    else:
        print('request name(relay): ' + name)
        # sent request to true DNS server
        serverSocket.sendto(data, ('202.141.180.1', 53))
        print('waiting for dns server respond...')
    
        # receive respond from true DNS server
        data, sendAddr = serverSocket.recvfrom(4096)
        
        # send data to local client
        clientSocket.sendto(data, recvAddr)
    print('query time: ' + str(time.time() - time_start) + ' s')