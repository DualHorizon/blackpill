import socket

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 1339


def dummy_server() -> None:
    """A dummy server to mimic the kernel module."""
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((SERVER_HOST, SERVER_PORT))
            server_socket.listen(1)
            print(f"Listening on {SERVER_HOST}:{SERVER_PORT}")
            conn, addr = server_socket.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    print(f"Received: {data.hex()}")
                    conn.sendall(b"\xde\xad\xbe\xef")  # 0xdeadbeef, dummy data


if __name__ == "__main__":
    dummy_server()
