# server.py
import socket
import threading
from cryptography.fernet import Fernet

HOST = ""  # listen on all interfaces
PORT = 8897

# load server-shared key for transport-level encryption to server
with open("secret.key", "rb") as f:
    key = f.read()
fernet = Fernet(key)

clients = set()
# THE LOCK IS USED FOR TO HANDLE WITHOUT ANHY DATA LOOSES 
clients_lock = threading.Lock()

# THIS FUNCTION FOR BROADCAST THE CLIENT MESSAGE TO ALL USERS 
def broadcast(raw_msg: str, sender_socket=None):
    encrypted = fernet.encrypt(raw_msg.encode())
    with clients_lock:
        dead = []
        for c in list(clients):
            if c is sender_socket:
                continue
            try:
                c.sendall(encrypted)
            except:
                dead.append(c)
        for d in dead:
            clients.discard(d)
            try:
                d.close()
            except:
                pass

# THIS FUCNTION FOR HANDLE THE CLIENTS DATA 
def handle_client(conn, addr):
    print(f"[+] {addr} connected")
    try:
        # Welcome message
        conn.sendall(fernet.encrypt("Server: Welcome! Please send your chat messages.".encode()))
        while True:
            data = conn.recv(4096)
            if not data:
                break
            try:
                message = fernet.decrypt(data).decode()
            except Exception as e:
                print("[!] Decrypt error:", e)
                continue

            # print(f"[{addr}] {message}")
            broadcast(message, sender_socket=conn)
            
    except Exception as e:
        print("[!] Client error:", e)
    finally:
        with clients_lock:
            clients.discard(conn)
        try:
            conn.close()
        except:
            pass
        print(f"[-] {addr} disconnected")

# THIS FUCNTION FOR TO INTIALIZE THE SOCKET CONNECTION 
# WE USE THE TCP CONNECTION
# TO BIND THE HOST AND PORT

def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(50)
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            with clients_lock:
                clients.add(conn)
            
            # THREADING FOR MULTI CLIENT SERVER MANGEMNET
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    run_server()
