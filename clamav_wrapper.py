import socket


class ClamavWrapper:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

        try:
            self.sock = socket.create_connection((self.host, self.port))
        except Exception as e:
            raise ConnectionError('cannot connect to clamd. is the clamd server running?')

    def scan_file(self, file_path: str):
        file = open(file_path, 'rb')
        file_content = file.read()
        file.close()

        self.sock.sendall(b'zINSTREAM\0')

        # send content to clamd each chunk size
        chunk_size = 8192
        for i in range(0, len(file_content), chunk_size):
            chunk = file_content[i:i + chunk_size]
            self.sock.sendall(len(chunk).to_bytes(4, byteorder='big') + chunk)

        self.sock.sendall(b'\0\0\0\0')

        response = self.sock.recv(1024)
        return response.decode('utf-8')[8:]
