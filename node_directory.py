import rsa
import socket
from cryptography.fernet import Fernet
import threading
import sys
import random


(MY_PUBLIC_KEY, MY_PRIVATE_KEY) = rsa.newkeys(512)
MY_PORT = int(sys.argv[1])
print("PORT: ", MY_PORT)
JOIN_BUFFER_SIZE = 100
BUFFER_JOIN_SIZE = 64
CIR_SIZE = 3

class SocketClosedException(Exception):
    pass

def check_recv(recv_mssg):
    if len(recv_mssg) == 0:
        raise SocketClosedException


def handle_nodes(joining_socket: socket.socket):
    #Continues recieveing datagrams from node
    while True:
        recv_data, join_address = joining_socket.recvfrom(JOIN_BUFFER_SIZE)
        recv_mssg = recv_data.decode()
        if recv_mssg != "JOIN" and recv_mssg != "EXIT":
            continue
        #If node joins adds to list
        if recv_mssg == "JOIN":
            node_set.add(join_address)
        #Otherwise it leaves
        if recv_mssg == "EXIT":
            node_set.remove(join_address)
        
        #Send acknowledgement to node
        joining_socket.sendto("SUCC".encode(), join_address)

        print(node_set)


#Client wants a set of nodes to use
def handle_clients(client_socket: socket.socket):

    try:
        #Send client directory's public key
        client_socket.send(MY_PUBLIC_KEY['n'].to_bytes(BUFFER_JOIN_SIZE, "big"))
        client_socket.send(MY_PUBLIC_KEY['e'].to_bytes(BUFFER_JOIN_SIZE, "big"))

        #Recieve clients public key
        client_public_n = client_socket.recv(BUFFER_JOIN_SIZE)
        check_recv(client_public_n)
        client_public_e = client_socket.recv(BUFFER_JOIN_SIZE)
        check_recv(client_public_e)
        client_public_key = rsa.PublicKey(int.from_bytes(client_public_n, "big"), int.from_bytes(client_public_e, "big"))

        #Random bytes from client to sign
        random_bytes = client_socket.recv(BUFFER_JOIN_SIZE)
        #Signs bytes and send signiture to client
        signed_bytes = rsa.sign(random_bytes, MY_PRIVATE_KEY, "SHA-256")
        client_socket.send(signed_bytes)

        #Nodes for clients to use
        client_node_set = set()

        #Not enough nodes available and sends error to lcient
        if len(node_set) < CIR_SIZE:
            client_socket.send(rsa.encrypt("NONE".encode(), client_public_key))
            client_socket.close()
            return

        #removes random nodes from node set, those nodes will join again when finished
        while len(client_node_set) != CIR_SIZE:
            node_addr = node_set.pop()
            client_node_set.add(node_addr)
        
        #Send address for each node one at a time to client
        while len(client_node_set) != 0:
            node_addr = client_node_set.pop()
            addr_format = str(node_addr[0]) + "," + str(node_addr[1])
            client_socket.send(rsa.encrypt(addr_format.encode(), client_public_key))
        
        client_socket.close()
    except:
        #Unexpected socket closure by client
        client_socket.close()

node_set= set()

join_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serve_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    join_socket.bind(("", MY_PORT))
    serve_socket.bind(("", MY_PORT))
    serve_socket.listen(socket.SOMAXCONN)
except:
    print("ERROR: Invalid Socket Bind")
    exit()

threading.Thread(target=handle_nodes, args=[join_socket]).start()


while True:
    socket_client, client_addr = serve_socket.accept()
    threading.Thread(target=handle_clients, args=[socket_client]).start()
        
