import rsa
import socket
from cryptography.fernet import Fernet
import threading
import select
import sys

class SocketClosedException(Exception):
    pass

def check_recv(recv_mssg):
    if len(recv_mssg) == 0:
        raise SocketClosedException


def join_directory():
    #Let directory know that current node is available for use
    while True:
        #Will keep trying to join directory until it recieves a aknowledgement form directory
        directory_socket.sendto("JOIN".encode(), (DIRECTORY_IP, DIRECTORY_PORT))
        recv_ready = select.select([directory_socket.fileno()], [], [], 1) 
        if recv_ready and recv_ready[0]:
            recv_mssg = directory_socket.recv(BUFFER_SIZE).decode()
            if recv_mssg == "SUCC":
                return
        else:
            continue

BUFFER_SIZE = 64
ONION_BUFFER_SIZE = 4096
STOP_NEXT_PREV_ONION = False
(MY_PUBLIC_KEY, MY_PRIVATE_KEY) = rsa.newkeys(512)
MY_PORT = int(sys.argv[1])
DIRECTORY_IP = sys.argv[2]
DIRECTORY_PORT = int(sys.argv[3])

directory_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#Tries to bind on port
try:
    directory_socket.bind(("",MY_PORT))

    listen_socket.bind(("",MY_PORT))
    listen_socket.listen(socket.SOMAXCONN)
except:
    print("Error: Invalid Socket Bind")
    exit()

print("PORT: ", MY_PORT)

while True:
    join_directory()

    try:
        #Accept connection from previous node or client
        prev_node_socket, prev_address = listen_socket.accept()
        #Sends public key to previous node
        prev_node_socket.send(MY_PUBLIC_KEY['n'].to_bytes(BUFFER_SIZE, "big"))
        prev_node_socket.send(MY_PUBLIC_KEY['e'].to_bytes(BUFFER_SIZE, "big"))

        #Recieve and decrypt symmetric key
        my_sym_key_encrpyted = prev_node_socket.recv(BUFFER_SIZE)
        check_recv(my_sym_key_encrpyted)
        my_sym_key = rsa.decrypt(my_sym_key_encrpyted, MY_PRIVATE_KEY)
        my_fernet = Fernet(my_sym_key)

        #Recieve address of next node to connect to in the chain
        next_node_IP_encrypted = prev_node_socket.recv(BUFFER_SIZE)
        check_recv(next_node_IP_encrypted)
        next_node_Port_encrypted = prev_node_socket.recv(BUFFER_SIZE)
        check_recv(next_node_Port_encrypted)

        #Decrypte address from previous node
        next_node_IP = rsa.decrypt(next_node_IP_encrypted, MY_PRIVATE_KEY).decode()
        next_node_Port = int(rsa.decrypt(next_node_Port_encrypted, MY_PRIVATE_KEY).decode())
    except:
        #Unexpected socket closing by previous node
        print("ERROR: Connection Unexpectedly Closed")
        prev_node_socket.close()
        continue

    
    next_node_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    #Try to connect to next node
    try:
        next_node_socket.connect((next_node_IP, next_node_Port))
    except:
        #Next node is unavailable
        print("ERROR: Cannot Connect To Next Node")
        next_node_socket.close()
        prev_node_socket.close()
        continue


    foward_mode = True
    continue_next = True
    #Foward mode where path is still being setup and no actaul data transfer
    while foward_mode:
        recv_ready, _, _ = select.select([prev_node_socket.fileno(), next_node_socket.fileno()], [], [], 1) 

        for sock_recv in recv_ready:
            if sock_recv == prev_node_socket.fileno():
                recv_data = prev_node_socket.recv(BUFFER_SIZE)
                #Unexpected socket closing
                if len(recv_data) == 0:
                    next_node_socket.close()
                    prev_node_socket.close()
                    print("ERROR: Connection Unexpectedly Closed")
                    foward_mode = False  
                    continue_next = False    
                    break
                
                #Checks if message is top meaning that the path is finished being setup
                try:
                    if "STOP" == rsa.decrypt(recv_data, MY_PRIVATE_KEY).decode():
                        foward_mode = False      
                        break  
                except:
                    #foward message
                    next_node_socket.send(recv_data)
            
            if sock_recv == next_node_socket.fileno():
                recv_data = next_node_socket.recv(BUFFER_SIZE)
                #Unexpected socket closing
                if len(recv_data) == 0:
                    next_node_socket.close()
                    prev_node_socket.close()
                    print("ERROR: Connection Unexpectedly Closed")
                    foward_mode = False  
                    continue_next = False    
                    break
                else:
                    #foward message
                    prev_node_socket.send(recv_data)
    
    #If path was not setup then wait until next connection
    if not continue_next:
        continue

    onion_mode = True
    while onion_mode:
        recv_ready, _, _ = select.select([prev_node_socket.fileno(), next_node_socket.fileno()], [], [], 1) 

        for sock_recv in recv_ready:
            
            if sock_recv == prev_node_socket.fileno():
                try:
                    recv_data = prev_node_socket.recv(ONION_BUFFER_SIZE)
                except:
                    #Unexpected socket closing
                    next_node_socket.close()
                    prev_node_socket.close()
                    onion_mode = False
                    break

                
                if len(recv_data) == 0:
                    #Unexpected socket closing
                    next_node_socket.close()
                    prev_node_socket.close()
                    onion_mode = False
                    break
                print("Received")
                print(recv_data)

                #message from client so we remove our layer
                enrpyted_data = my_fernet.decrypt(recv_data)
                if enrpyted_data.decode() == "END":
                    #Client closes the connection so ends the session
                    next_node_socket.close()
                    prev_node_socket.close()
                    onion_mode = False
                    break
                else:
                    print("Sent")
                    print(enrpyted_data)
                    next_node_socket.send(enrpyted_data)

            if sock_recv == next_node_socket.fileno():
                try:
                    recv_data = next_node_socket.recv(ONION_BUFFER_SIZE)
                except:
                    #Unexpected socket closing
                    next_node_socket.close()
                    prev_node_socket.close()
                    onion_mode = False
                    break
                #Unexpected socket closing
                if len(recv_data) == 0:
                    next_node_socket.close()
                    prev_node_socket.close()
                    onion_mode = False
                    break
                print("Received")
                print(recv_data)

                #Message is from destination so add our layer to message
                enrpyted_data = my_fernet.encrypt(recv_data)
                print("Sent")
                print(enrpyted_data)
                prev_node_socket.send(enrpyted_data)






    