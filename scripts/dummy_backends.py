import socket
import threading

def handle_client(conn, addr):
    try:
        # 1. SOCKS5 Greeting
        greeting = conn.recv(1024)
        if not greeting or greeting[0] != 0x05:
            conn.close()
            return
        conn.sendall(b"\x05\x00")

        # 2. SOCKS5 CONNECT Request
        req = conn.recv(1024)
        if not req or req[1] != 0x01: # CONNECT
            conn.close()
            return
        # Respond SUCCESS
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        # 3. Read HTTP GET Request and respond HTTP 200 OK
        http_req = conn.recv(1024)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
    except Exception as e:
        pass
    finally:
        try:
            conn.close()
        except:
            pass

def start_mock_backend(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    s.listen(10)
    print(f"Mock SOCKS5 backend running on port {port}")
    while True:
        try:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr))
            t.daemon = True
            t.start()
        except KeyboardInterrupt:
            break
        except Exception:
            pass

if __name__ == '__main__':
    ports = [10800, 10801, 10802, 10803]
    threads = []
    for port in ports:
        t = threading.Thread(target=start_mock_backend, args=(port,))
        t.daemon = True
        t.start()
        threads.append(t)
    
    import time
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down mock backends...")
