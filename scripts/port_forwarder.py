import socket
import threading

def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            src.close()
        except Exception:
            pass
        try:
            dst.close()
        except Exception:
            pass

def handle_client(client_socket):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect(('172.17.0.4', 9090))
        
        t1 = threading.Thread(target=forward, args=(client_socket, server_socket))
        t2 = threading.Thread(target=forward, args=(server_socket, client_socket))
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
    except Exception:
        try:
            client_socket.close()
        except Exception:
            pass

def start_forwarder():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 9090))
    s.listen(100)
    print("Port forwarder listening on host port 9090 -> 172.17.0.4:9090")
    while True:
        try:
            client, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(client,))
            t.daemon = True
            t.start()
        except KeyboardInterrupt:
            break
        except Exception:
            pass

if __name__ == '__main__':
    try:
        start_forwarder()
    except KeyboardInterrupt:
        print("\nShutting down port forwarder...")
