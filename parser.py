import struct
from socket import inet_aton
from proxy import PROXY_IP

DEBUG = True

# Add this to send fake response from the proxy itself
FAKE_GAMEGUARD_RESPONSE = bytes([0x59, 0x02, 0x01])  # 0x259 + success flag

def bytes_to_str(bs: bytes) -> str:
    return "".join([chr(b) for b in bs])

def default_handler(data, port, origin) -> bytes:
    print(f"{origin}[{port}] {'->' if origin == 'client' else '<-'}", data.hex())
    return data

def login_request_handler(data, port, origin) -> bytes:
    username = bytes_to_str(data[6:30])
    password = bytes_to_str(data[30:-1])
    print(f"{origin}[{port}]: login packet, username={username.split('\0')[0]}, password={password.split('\0')[0]}")
    return data

def login_failed_handler(data, port, origin) -> bytes:
    if data.hex()[2:3] == "01":
        print(f"{origin}[{port}]: login failed, wrong password")
    elif data.hex()[2:3] == "00":
        print(f"{origin}[{port}]: login failed, username does not exists")
    return data

def login_success_handler(data, port, origin) -> bytes:
    web_auth_token = bytes_to_str(data[47:63])
    ip_addr = ".".join([str(c) for c in struct.unpack('4B', data[64:68])])
    data_array = bytearray(data)
    new_ip_addr = inet_aton(PROXY_IP)
    print(f"[+] Info (Login -> Char): Changing IP to PROXY_IP = {PROXY_IP} = {new_ip_addr.hex()}")
    for i in range(4):
        data_array[64+i] = new_ip_addr[i]
    data = bytes(data_array)
    default_handler(data, port, origin)
    return data

def char_to_map_handler(data, port, origin) -> bytes:
    ip_addr = ".".join([str(c) for c in struct.unpack('4B', data[22:26])])
    data_array = bytearray(data)
    new_ip_addr = inet_aton(PROXY_IP)
    print(f"[+] Info (Char -> Map): Changing IP to PROXY_IP = {PROXY_IP} = {new_ip_addr.hex()}")
    for i in range(4):
        data_array[22+i] = new_ip_addr[i]
    data = bytes(data_array)
    default_handler(data, port, origin)
    return data

# Add this new handler function
def gameguard_request_handler(data, port, origin) -> bytes:
    print(f"{origin}[{port}]: GameGuard handshake detected (0x258)!")
    print("*** Intercepting - will NOT forward to server ***")
    # Return empty bytes to signal NOT to forward
    return b''

handlers = {
    "6400": default_handler,  # client, "640000000080"
    "3e08": login_failed_handler, # server, "3e0800000000" or "3e0801000000"
    "c40a": login_success_handler,  # server, "c40ae000"
    "c50a": char_to_map_handler, # server
    #"5802": gameguard_request_handler, # to handle the 0x258 packet
}

def parse(data: bytes, port: int, origin: str) -> bytes:
    data = handlers.get(data[:2].hex(), default_handler)(data, port, origin)
    #if data[:1].hex() == '7f':  # it seems this is a ping packet
    #    pass
    #elif data[:1].hex() == '87':
    #    data = handlers.get(data[:2].hex(), default_handler)(data, port, origin)
    #elif origin == 'server':
    #    data = handlers.get(data[:2].hex(), default_handler)(data, port, origin)
    return data
