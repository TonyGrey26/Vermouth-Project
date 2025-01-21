import socket
from logger_config import setup_logger

logger = setup_logger("scan_log.txt")

class ClamavWrapper:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

        try:
            self.sock = socket.create_connection((self.host, self.port))
            logger.info(f"Connected to clamd server at {self.host}:{self.port}")
        except Exception as e:
            logger.error("Cannot connect to clamd server. Is the clamd server running?")
            logger.error(f"Error details: {e}")
            raise ConnectionError("Cannot connect to clamd. Is the clamd server running?")

    def scan_file(self, file_path: str):
        try:
            with open(file_path, 'rb') as file:
                file_content = file.read()
            logger.info(f"Scanning file: {file_path}")

            self.sock.sendall(b'zINSTREAM\0')

            # Gửi nội dung file theo từng chunk
            chunk_size = 8192
            for i in range(0, len(file_content), chunk_size):
                chunk = file_content[i:i + chunk_size]
                self.sock.sendall(len(chunk).to_bytes(4, byteorder='big') + chunk)

            self.sock.sendall(b'\0\0\0\0')

            response = self.sock.recv(1024)
            result = response.decode('utf-8')[8:]

            logger.info(f"Scan result for {file_path}: {result}")
            return result
        except FileNotFoundError:
            logger.warning(f"File not found: {file_path}")
            return "File not found"
        except Exception as e:
            logger.error(f"Error while scanning file {file_path}: {e}")
            raise
