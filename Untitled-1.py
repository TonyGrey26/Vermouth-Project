from tkinter import *
from tkinter.ttk import Progressbar
from tkinter import filedialog, messagebox
import threading
import time
import os
import hashlib
import logging
import shutil
import socket

class ClamavWrapper:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

        try:
            self.sock = socket.create_connection((self.host, self.port))
        except Exception as e:
            raise ConnectionError('Cannot connect to clamd. Is the clamd server running?')

    def scan_file(self, file_path: str):
        with open(file_path, 'rb') as file:
            file_content = file.read()

        self.sock.sendall(b'zINSTREAM\0')

        # Send content to ClamAV in chunks
        chunk_size = 8192
        for i in range(0, len(file_content), chunk_size):
            chunk = file_content[i:i + chunk_size]
            self.sock.sendall(len(chunk).to_bytes(4, byteorder='big') + chunk)

        self.sock.sendall(b'\0\0\0\0')
        response = self.sock.recv(1024)
        return response.decode('utf-8')[8:]

class FileScanner:
    def __init__(self):
        self.setup_logging()
        self.malware_hashes = {
            "e1112134b6dcc8bed54e0e34d8ac272795e73d74": "Malware Sample 1",
            "f2223456c7eddbfed65f1f45e9bd383896f84e85": "Malware Sample 2"
        }
        self.scan_result = None
        self.quarantine_dir = "quarantine"

        # Create quarantine directory if not exists
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

    def setup_logging(self):
        logging.basicConfig(
            filename='scan_log.txt',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('FileScanner')

    def quarantine_file(self, filepath):
        try:
            filename = os.path.basename(filepath)
            quarantine_path = os.path.join(self.quarantine_dir, filename)
            shutil.move(filepath, quarantine_path)
            self.logger.info(f"File quarantined: {filepath} -> {quarantine_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error quarantining file {filepath}: {str(e)}")
            return False

    def delete_quarantined_files(self):
        try:
            files = os.listdir(self.quarantine_dir)
            for file in files:
                file_path = os.path.join(self.quarantine_dir, file)
                os.remove(file_path)
                self.logger.info(f"Deleted quarantined file: {file_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error deleting quarantined files: {str(e)}")
            return False

    def scan_file(self, filepath, progress_callback=None):
        try:
            # Get file size
            file_size = os.path.getsize(filepath)

            # Identify file type based on the header
            with open(filepath, 'rb') as f:
                header = f.read(8)

            fsign = {
                b'MZ': 'Executable',
                b'PK': 'ZIP Archive',
                b'%PDF': 'PDF Document',
                b'\x89PNG': 'PNG Image',
                b'GIF8': 'GIF Image',
                b'\xFF\xD8': 'JPEG Image'
            }
            file_type = 'Unknown'
            for sig, ftype in fsign.items():
                if header.startswith(sig):
                    file_type = ftype
                    break

            # Scan file with ClamAV
            try:
                clamav = ClamavWrapper(host='localhost', port=3310)
                clamav_result = clamav.scan_file(filepath)
            except ConnectionError as e:
                clamav_result = f"ClamAV scan error: {str(e)}"
                is_malicious = False
                message = f"Unable to scan file: {clamav_result}"
            else:
                # Interpret ClamAV results
                if "FOUND" in clamav_result:
                    is_malicious = True
                    message = f"WARNING: Malware detected! (ClamAV Result: {clamav_result.strip()})"
                elif "OK" in clamav_result:
                    is_malicious = False
                    message = "File is safe (ClamAV result: OK)."
                else:
                    is_malicious = False
                    message = f"Unknown ClamAV result: {clamav_result.strip()}"

            # Prepare the result dictionary
            result = {
                'file_type': file_type,
                'file_size': file_size,
                'is_malicious': is_malicious,
                'message': message,
                'clamav_result': clamav_result.strip(),
            }

            # Log the scan result
            self.logger.info(f"Scanned file: {filepath}")
            self.logger.info(f"Result: {message}")

            return result

        except Exception as e:
            self.logger.error(f"Error scanning file {filepath}: {str(e)}")
            return {
                'is_malicious': False,
                'message': f"Error scanning file: {str(e)}"
            }




# Khởi tạo scanner
scanner = FileScanner()

# Biến toàn cục để theo dõi kết quả quét gần nhất
last_scan_result = None
last_scanned_file = None

# Cập nhật hàm sprogress với timing mới
def sprogress():
    global last_scan_result, last_scanned_file
    if not sfile:
        flbl.config(text="Please select a file first!")
        return

    bar.place(x=120, y=450)
    slb.place(x=200, y=480)
    bar['value'] = 0

    # Quét file
    result = scanner.scan_file(sfile)
    last_scan_result = result
    last_scanned_file = sfile

    for i in range(1, 101):
        time.sleep(0.05)  
        bar['value'] = i
        if i < 30:
            slb.config(text=f"Scanning... {i}%")
        elif i < 60:
            slb.config(text=f"Analyzing... {i}%")
        elif i < 90:
            slb.config(text=f"Verifying... {i}%")
        else:
            slb.config(text=f"Finalizing... {i}%")
            
        vx.update_idletasks()

    # Hiển thị kết quả cuối cùng
    if result['is_malicious']:
        slb.config(text="UNSAFE FILE", fg='red', font='Gothic 15 bold')
        messagebox.showerror("Warning", result['message'])
    else:
        slb.config(text="SAFE FILE", fg='green', font='Gothic 15 bold')
        info_message = f"""
        Scan Complete!
        File: {os.path.basename(sfile)}
        Type: {result['file_type']}
        Size: {result['file_size']} bytes
        Status: {result['message']}
        """
        messagebox.showinfo("Scan Result", info_message)

def show_quarantine():
    """Hiển thị cửa sổ quản lý file cách ly"""
    quarantine_window = Toplevel(vx)
    quarantine_window.title("Quarantine Management")
    quarantine_window.geometry("400x300")
    quarantine_window.config(background='black')

    # Hiển thị danh sách file trong thư mục cách ly
    files = os.listdir(scanner.quarantine_dir)
    if files:
        for file in files:
            Label(quarantine_window, text=file, bg='black', fg='white').pack(pady=5)
    else:
        Label(quarantine_window, text="No files in quarantine", bg='black', fg='white').pack(pady=5)

def quarantine_current_file():
    """Hàm xử lý việc cách ly file"""
    if not last_scanned_file:
        messagebox.showwarning("Warning", "Please scan a file first!")
        return
        
    if not last_scan_result or not last_scan_result['is_malicious']:
        messagebox.showinfo("Information", "Only malicious files can be quarantined!")
        return
        
    if scanner.quarantine_file(last_scanned_file):
        messagebox.showinfo("Success", "File has been quarantined successfully!")
        flbl.config(text="File has been quarantined")
    else:
        messagebox.showerror("Error", "Failed to quarantine file!")

def delete_quarantined():
    """Hàm xử lý việc xóa các file bị cách ly"""
    if scanner.delete_quarantined_files():
        messagebox.showinfo("Success", "All quarantined files have been deleted!")
    else:
        messagebox.showerror("Error", "Failed to delete quarantined files!")

# Mở ứng dụng
vx = Tk()
vx.title("VERMOUTHSECUREX")
vx.geometry("540x620+480+100")
vx.iconbitmap("C:\\Users\\admin\\OneDrive\\Máy tính\\vermouth\\Vermouth-Project\\Vermouth-Project\\vmsx.ico")
vx.config(background='black')
vx.resizable(False, False)

# Biến lưu file đã chọn
sfile = None

# Hình nền
bg = PhotoImage(file="C:\\Users\\admin\\OneDrive\\Máy tính\\vermouth\\Vermouth-Project\\Vermouth-Project\\bg600.png")
canvas1 = Canvas(vx, width=400, height=400)
canvas1.pack(fill="both", expand=True)
canvas1.create_image(0, 0, image=bg, anchor="nw")

# Tiêu đề và label
lbt = Label(vx, text="Vermouth Secure X", font='Gothic 40 bold', background='black', fg='red')
lbt.pack()
lbp = Label(vx, text="Made by Vermouth Team", font='Gothic 15', background='black', fg='grey')
lbp.pack()

# Label hiển thị file đã chọn - ẩn ban đầu
flbl = Label(vx, text="", font='Gothic 15', background='black', fg='white', wraplength=400)
flbl.place(x=205,y=420)

# Thanh Progressbar
bar = Progressbar(vx, orient=HORIZONTAL, length=300, mode='determinate')

# Label trạng thái tiến trình
slb = Label(vx, text="", font='Gothic 15 bold', fg='white', background='black', borderwidth=0)

# Hàm chọn file
def select_file():
    global sfile
    filetypes = (
        ('All files', '*.*'),
        ('Text files', '*.txt'),
        ('Executable files', '*.exe'),
        ('Document files', '*.doc;*.docx;*.pdf')
    )
    
    sfile = filedialog.askopenfilename(
        title='Select a file to scan',
        filetypes=filetypes
    )
    
    if sfile:
        flbl.config(text=f"Selected: {os.path.basename(sfile)}")

# Chạy trên luồng mới
def sthread():
    threading.Thread(target=sprogress).start()  

# Hàm Exit
def exit():
    vx.destroy()

# Buttons
b0 = Button(vx, text="Select File", font='Gothic 20 bold', bg='black', fg='white', bd=5, command=select_file)
b1 = Button(vx, text="Start Checking", font='Gothic 20 bold', bg='black', fg='white', bd=5, command=sthread)
b2 = Button(vx, text="Delete Quarantine", font='Gothic 20 bold', bg='black', fg='white', bd=5, command=delete_quarantined)
b3 = Button(vx, text="Quarantine", font='Gothic 20 bold', bg='black', fg='white', bd=5, command=quarantine_current_file)
# b4 = Button(vx, text="Show Quarantine", font='Gothic 20 bold', bg='black', fg='white', bd=5, command=show_quarantine)
b5 = Button(vx, text="Exit", font='Gothic 20 bold', bg='black', fg='white', bd=5, command=exit)



# Hiển thị các button
canvas1.create_window(180, 50, anchor="nw", window=b0)  # Nút Select File
canvas1.create_window(165, 130, anchor="nw", window=b1)  # Nút Start Checking
canvas1.create_window(135, 210, anchor="nw", window=b2)  # Nút Delete Quarantine
canvas1.create_window(190, 290, anchor="nw", window=b3)  # Nút Quarantine
# canvas1.create_window(160, 450, anchor="nw", window=b4) # nút show file quarantine
canvas1.create_window(235, 370, anchor="nw", window=b5)  # Nút Exit

# Chạy ứng dụng
vx.mainloop()