import socket
import vt
import time
from hashlib import sha256

class ClamavWrapper:
    def __init__(self, host: str, port: int):
        self.api = "61b4925ac790639b0a40724eb4d90f49021ef59b4ea7507f1ff63e8a4b95a670"
        self.client = vt.Client(self.api)
    
    def __del__(self):
        self.client.close()

    def scan_file(self, file_path: str):
        # Use 'with' to ensure file is properly closed
        with open(file_path, 'rb') as f:
            # analysis = client.scan_file(f, wait_for_completion=True)
            file_hash = sha256(f.read()).hexdigest()
            try:
                file = self.client.get_object(f"/files/{file_hash}")
                result = file.last_analysis_stats
            except:
                print("File hasn't been uploaded to VirusTotal before. Start scanning...")
                with open(file_path, 'rb') as f:
                    analysis = self.client.scan_file(f)
                    while True:
                        analysis = self.client.get_object("/analyses/{}", analysis.id)
                        print(analysis.status)
                        if analysis.status == "completed":
                            break
                        time.sleep(5)
                    file = self.client.get_object(f"/files/{file_hash}")
                    result = file.last_analysis_stats
        
        print(result)
        if result["malicious"] >= 8 or result["suspicious"] >= 10:
            return "FOUND"
        return "OK"