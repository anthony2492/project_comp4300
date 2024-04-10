import socket
import threading
import sys

MY_PORT = int(sys.argv[1])
print("PORT: ", MY_PORT)

listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listen_socket.bind(("",MY_PORT))
listen_socket.listen(socket.SOMAXCONN)

client_socket, client_address = listen_socket.accept()


def send_input(send_socket):
    while True:
        user_input = input("Input:")
        send_socket.send(user_input.encode())


input_thread = threading.Thread(target=send_input, args=[client_socket])
input_thread.daemon = False
input_thread.start()

while True:
    recv_data = client_socket.recv(4096)
    if len(recv_data) == 0:
        break
    print(recv_data.decode())