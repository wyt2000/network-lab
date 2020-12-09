import socket
import sys
import struct
import time

# load config file
def initConfig(filename):
    dict = {}
    file = open(filename, 'r')
    while True:
        line = file.readline()
        if not line:
            break
        ip, name = line.strip('\n').split(' ')
        dict[name] = ip
    return dict

# get domain name from DNS message
def getName(data):
    name = list(data.decode('utf-8', 'ignore'))[11:]
    for i in range(len(name)):
        if name[i] != '-' and name[i].isalnum() == False:
            name[i] = '.'
    name = ''.join(name).strip('.')
    return name

# create local resolve message
def local_resolve(data, name, ip):
    s = list(struct.unpack('>'+'B'*len(data), data))                    # convert request bytes to int
    s[2] = 0x80                                                         # set QR = 1
    s[7] = 0x01                                                         # set ANCOUNT = 1
    s += s[12:]                                                         # repeat Question
    s[-1:-5:-1] = [0x01, 0x00, 0x01, 0x00]                              # hide ipv6
    s += [0x00, 0x00, 0x00, 0x01]                                       # set TTL = 1
    s += [0x00, 0x04]                                                   # set RDLENGTH = 4

    if ip == '0.0.0.0':                                                 # Intercept
        print('request name(intercept): ' + name)
        s[3] = 0x03
    else:
        print('request name(local resolve): ' + name)
    ip = ip.split('.')                                                  # get ip address
    s += [int(x) for x in ip]                                           # add ip to respond message
    data = struct.pack('>'+'B'*len(s), *s)                              # pack respond message
    return data

if __name__ == "__main__":

    dict = initConfig('config')                                         # get ip config
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)     # create sockets
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.bind(('localhost', 53))                                # bind local DNS port

    # handle DNS request
    while True:
        print('waiting for dns request...')
        data, recvAddr = clientSocket.recvfrom(4096)                    # receive dns query from local client
        time_start = time.time()

        name = getName(data)
        if dict.__contains__(name):                                     # search for domain name in local config
            data = local_resolve(data, name, dict[name])                # get local resolve message
        else:
            print('request name(relay): ' + name)
            serverSocket.sendto(data, ('202.141.180.1', 53))            # sent request to true DNS server
            print('waiting for dns server respond...')
            data, sendAddr = serverSocket.recvfrom(4096)                # receive respond from true DNS server
        clientSocket.sendto(data, recvAddr)                             # send data to local client
        print('query time: ' + str(time.time() - time_start) + ' s')