import socket
from threading import Thread
import importlib
import parser

PROXY_IP = "127.0.0.2"
SERVER_IP = "192.168.1.75"
client_sockets: dict[int, socket.SocketType] = {}
server_sockets: dict[int, socket.SocketType] = {}

def client2server(port: int):
    ## accept client connection
    socket_proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # SOL_SOCKET is a socket level option (it could be also IP, TCP, etc. level option)
    # SO_REUSEADDR allows the program to immediately rebind to (ip, port)
    socket_proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socket_proxy.bind((PROXY_IP, port))
    socket_proxy.listen(1)
    while True:
        socket_client, client_addr = socket_proxy.accept()   # blocks until a client accepts a connection
        print(f"========== Connected by {client_addr} ==========")
        client_sockets[port] = socket_client
        while True:
            data = socket_client.recv(4096)
            if data:
                try:
                    importlib.reload(parser)
                    data = parser.parse(data, port, 'client')
                    #if data == b'':
                    #    print(f"client[{port}]: Packet intercepted, not forwarding to server")
                    #    # Send fake response directly
                    #    #if port == 6900 and data[:2].hex() == '5802':
                    #    fake_response = parser.FAKE_GAMEGUARD_RESPONSE
                    #    print(f"client[{port}]: Sending fake GameGuard response (0x259)")
                    #    socket_client.sendall(fake_response)
                    #    #continue  # Skip forwarding to server
                except Exception as e:
                    print(f"client[{port}]: {e}")
                try:
                    server_sockets[port].sendall(data) # send to server
                except Exception as e:
                    print(f"client[{port}]: {e}")
            else:
                break
        socket_client.close()

def server2client(port: int):
    ## connect to server
    server_addr = (SERVER_IP, port)
    while True:
        socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_server.connect(server_addr)
        server_sockets[port] = socket_server
        while True:
            data = socket_server.recv(4096)
            if data:
                try:
                    importlib.reload(parser)
                    data = parser.parse(data, port, 'server')
                except Exception as e:
                    print(f"server[{port}]: {e}")
                try:
                    client_sockets[port].sendall(data)   # send to client
                except Exception as e:
                    print(f"server[{port}]: {e}")
            else:
                break
        socket_server.close()

def main(port: int):
    Thread(target=client2server, args=(port,)).start()
    Thread(target=server2client, args=(port,)).start()


if __name__ == '__main__':
    for port in [5121, 6121, 6900]:
        Thread(target=main, args=(port,)).start()
