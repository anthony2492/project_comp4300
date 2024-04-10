import rsa
import random
import socket
from cryptography.fernet import Fernet
import threading
import sys
import select
import random

BUFFER_SIZE = 64
ONION_BUFFER_SIZE = 4096
INPUT_BUFFER_SIZE = 100
(MY_PUBLIC_KEY, MY_PRIVATE_KEY) = rsa.newkeys(512)
MY_PORT = random.randint(5000,65000)
DIRECTORY_IP = sys.argv[1]
DIRECTORY_PORT = int(sys.argv[2])
DEST_IP = sys.argv[3]
DEST_PORT = int(sys.argv[4])
PRINT_MODE = int(sys.argv[5])
DIRECTORY_PUBLIC_KEY = None

if PRINT_MODE:
    print("PORT: ", MY_PORT)

if len(sys.argv) != 6:
    exit()

#Custom exception
class SocketClosedException(Exception):
    pass

#If TCP socket receive a zero byte message that means the socket was closed on the other end
#Raise error that socket was closed
def check_recv(recv_mssg):
    if len(recv_mssg) == 0:
        raise SocketClosedException

def handle_exception(exception):
    if type(exception) == SocketClosedException:# or type(exception) == BrokenPipeError:
        if PRINT_MODE:
            print("ERROR: Connection Unexpectedly Closed")
    else:
        if PRINT_MODE:
            print("ERROR: Timeout With Directory")

def get_nodes():

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind(("", MY_PORT))
        server_socket.connect((DIRECTORY_IP, DIRECTORY_PORT))
    except:
        server_socket.close()
        if PRINT_MODE:
            print("ERROR: Invalid Socket Bind or Invalid Directory Address")
        return None

    server_socket.settimeout(5)
    try:
        #Get directory public key
        server_public_n = server_socket.recv(BUFFER_SIZE)
        check_recv(server_public_n)
        server_socket_public_e = server_socket.recv(BUFFER_SIZE)
        check_recv(server_socket_public_e)

        server_public_key = rsa.PublicKey(int.from_bytes(server_public_n, "big"), int.from_bytes(server_socket_public_e, "big"))
        global DIRECTORY_PUBLIC_KEY
        DIRECTORY_PUBLIC_KEY = server_public_key 
        
        #Send client public key
        server_socket.send(MY_PUBLIC_KEY['n'].to_bytes(BUFFER_SIZE, "big"))
        server_socket.send(MY_PUBLIC_KEY['e'].to_bytes(BUFFER_SIZE, "big"))

        #Random bytes sent to directory to check identity
        random_bytes = random.randbytes(BUFFER_SIZE)
        server_socket.send(random_bytes)
        signed_bytes = server_socket.recv(BUFFER_SIZE)
        check_recv(signed_bytes)
    except Exception as e:
        #Timeout from directory or socket was closed on other side
        server_socket.close()
        handle_exception(e)
        return None

    #Verify directory signiture
    try:
        rsa.verify(random_bytes, signed_bytes, DIRECTORY_PUBLIC_KEY)
    except:
        #Otherwise signiture cannot be verified and ends client
        server_socket.close()
        if PRINT_MODE:
            print("Error: Invalid Directory")
        return None

    try:
        #Get the 3 nodes to form the path from directory
        node1_enrypted = server_socket.recv(BUFFER_SIZE)
        check_recv(node1_enrypted)
        #If the first message is NONE then there is not enough node to create a path
        #More nodes need to connenct to directory
        if rsa.decrypt(node1_enrypted, MY_PRIVATE_KEY).decode() == "NONE":
            #End connection
            server_socket.close()
            return None

        #Otherwise there are enough nodes can can recieve the nodes
        node2_enrypted = server_socket.recv(BUFFER_SIZE)
        check_recv(node2_enrypted)
        node3_enrypted = server_socket.recv(BUFFER_SIZE)
        check_recv(node3_enrypted)

        #Decrypt to the actual address of nodes using private key since directory has client public key
        node1_decrypted = rsa.decrypt(node1_enrypted, MY_PRIVATE_KEY).decode().split(",")
        node2_decrypted = rsa.decrypt(node2_enrypted, MY_PRIVATE_KEY).decode().split(",")
        node3_decrypted = rsa.decrypt(node3_enrypted, MY_PRIVATE_KEY).decode().split(",")

        node1_IP, node1_port = node1_decrypted[0], int(node1_decrypted[1])
        node2_IP, node2_port = node2_decrypted[0], int(node2_decrypted[1])
        node3_IP, node3_port = node3_decrypted[0], int(node3_decrypted[1])

        server_socket.close()
    except Exception as e:
        #Otherwise directory unexpectedly closed
        server_socket.close()
        handle_exception(e)
        return None

    node_list = [(node1_IP, node1_port), (node2_IP, node2_port), (node3_IP, node3_port)]
    return node_list

def setup_sym_and_path(node_list):
    node1_IP, Node1_Port = (node_list[0][0], node_list[0][1])
    node2_IP, Node2_Port = (node_list[1][0], node_list[1][1])
    node3_IP, Node3_Port = (node_list[2][0], node_list[2][1])

    if PRINT_MODE:
        print("PATH")
        print(node1_IP, Node1_Port)
        print(node2_IP, Node2_Port)
        print(node3_IP, Node3_Port)
        print("--------------------")

    #dest_IP, dest_Port = ("", 8000)

    #Client generates symmetric that the nodes will use
    node1_sym_key = Fernet.generate_key()
    node2_sym_key = Fernet.generate_key()
    node3_sym_key = Fernet.generate_key()

    node1_fernet = Fernet(node1_sym_key)
    node2_fernet = Fernet(node2_sym_key)
    node3_fernet = Fernet(node3_sym_key)


    #Tries to connect to the first node in the path
    node1_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        node1_socket.connect((node1_IP, Node1_Port))
    except:
        if PRINT_MODE:
            print("ERROR: Could Not Connect To Node")

    try:
        #Recieve the first node's public key
        node1_public_n = node1_socket.recv(BUFFER_SIZE)
        check_recv(node1_public_n)
        node1_public_e = node1_socket.recv(BUFFER_SIZE)
        check_recv(node1_public_e)
        node1_public_key = rsa.PublicKey(int.from_bytes(node1_public_n, "big"), int.from_bytes(node1_public_e, "big"))
        
        #Send first node it's symmetric key 
        encrypted_key_1 = rsa.encrypt(node1_sym_key, node1_public_key)
        node1_socket.send(encrypted_key_1)
        
        #Send second node address for node1 to connect to
        node1_socket.send(rsa.encrypt(node2_IP.encode(), node1_public_key))
        node1_socket.send(rsa.encrypt(str(Node2_Port).encode(), node1_public_key))

        #Recieve the second node's public key which is sent by first node
        node2_public_n = node1_socket.recv(BUFFER_SIZE)
        check_recv(node2_public_n)
        node2_public_e = node1_socket.recv(BUFFER_SIZE)
        check_recv(node2_public_e)
        node2_public_key = rsa.PublicKey(int.from_bytes(node2_public_n, "big"), int.from_bytes(node2_public_e, "big"))
        
        #Send second node it's symmetric key to second node through first node
        encrypted_key_2 = rsa.encrypt(node2_sym_key, node2_public_key)
        node1_socket.send(encrypted_key_2)


        #Send third node address to second node which will be fowarded by first node
        node1_socket.send(rsa.encrypt(node3_IP.encode(), node2_public_key))
        node1_socket.send(rsa.encrypt(str(Node3_Port).encode(), node2_public_key))

        #Recieve the third node's public key which is sent by first node
        node3_public_n = node1_socket.recv(BUFFER_SIZE)
        check_recv(node3_public_n)
        node3_public_e = node1_socket.recv(BUFFER_SIZE)
        check_recv(node3_public_e)
        node3_public_key = rsa.PublicKey(int.from_bytes(node3_public_n, "big"), int.from_bytes(node3_public_e, "big"))

        #Send second node it's symmetric key which is encrypted and will be
        #fowarded by first node and second node
        encrypted_key_3 = rsa.encrypt(node3_sym_key, node3_public_key)
        node1_socket.send(encrypted_key_3)

        #Send final destination address to third node for it to connect to
        node1_socket.send(rsa.encrypt(DEST_IP.encode(), node3_public_key))
        node1_socket.send(rsa.encrypt(str(DEST_PORT).encode(), node3_public_key))

        #Sends a STOP to all nodes so they start using symmetric key for encryption
        #Have to send to last node first so it can recieve STOP or else
        #first node would use symmetric key when not needed
        node1_socket.send(rsa.encrypt("STOP".encode(), node3_public_key))
        node1_socket.send(rsa.encrypt("STOP".encode(), node2_public_key))
        node1_socket.send(rsa.encrypt("STOP".encode(), node1_public_key))
    except Exception as e:
        #Unexpected socket closing from something along path
        handle_exception(e)
        socket.close()
        return


    while True:
        #Continue sending and reading input until client stops or connection is closed

        #Check for input form input or socket
        input_ready, _ , _ = select.select([node1_socket.fileno(), sys.stdin], [], [], 1) 
        
        for input_source in input_ready:
            if input_source == node1_socket.fileno():
                encrypted_data = node1_socket.recv(ONION_BUFFER_SIZE)
                #Unexpected socket closing
                if len(encrypted_data) == 0:
                    node1_socket.close()
                    return
                
                #Decrypt layers of encryption since original message was first encypted by third node
                dencrypted_data = node3_fernet.decrypt(node2_fernet.decrypt(node1_fernet.decrypt(encrypted_data))).decode()
                print(dencrypted_data)
            
            if input_source == sys.stdin:
                user_input = input("")
                user_input_bytes = user_input.encode()
                
                #Client closes the connection sends message to third node to close connection and other nodes follow
                #after third node closes connection
                if len(user_input) == 0:            
                    node1_socket.send(node1_fernet.encrypt(node2_fernet.encrypt(node3_fernet.encrypt("END".encode()))))
                    node1_socket.close()
                    return

                #Breaks the user message into chucks to send to destination 
                #For when sending large messages or input is being piped in              
                while len(user_input_bytes) > INPUT_BUFFER_SIZE:
                    send_bytes = user_input_bytes[:INPUT_BUFFER_SIZE]
                    user_input_bytes = user_input_bytes[INPUT_BUFFER_SIZE:]
                    encrypted_data = node1_fernet.encrypt(node2_fernet.encrypt(node3_fernet.encrypt(send_bytes)))
                    node1_socket.send(encrypted_data)

                #Send last bit of message
                encrypted_data = node1_fernet.encrypt(node2_fernet.encrypt(node3_fernet.encrypt(user_input_bytes)))
                node1_socket.send(encrypted_data)

                
list_node = get_nodes()
if list_node == None:
    if PRINT_MODE:
        print("ERROR: Cannot Get Nodes.")
else:
    setup_sym_and_path(list_node)





