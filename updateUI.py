import os
import threading
import time
import shutil
import logging
from tkinter import *
from tkinter import filedialog, messagebox
from tkinter.ttk import Progressbar
import ttkbootstrap as tb
from clamav_wrapper import ClamavWrapper

class FileScanner:
    def __init__(self):
        self.setup_logging()
        self.quarantine_dir = "quarantine"
        self.malware_hashes = {
            "e1112134b6dcc8bed54e0e34d8ac272795e73d74": "Malware Sample 1",
            "f2223456c7eddbfed65f1f45e9bd383896f84e85": "Malware Sample 2",
        }
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

    def setup_logging(self):
        logging.basicConfig(
            filename='scan_log.txt',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('FileScanner')

    def scan_file(self, filepath):
        try:
            file_size = os.path.getsize(filepath)
            file_type = "Unknown"
            with open(filepath, "rb") as f:
                header = f.read(8)
                if header.startswith(b"MZ"):
                    file_type = "Executable"
                elif header.startswith(b"%PDF"):
                    file_type = "PDF Document"

            clamav = ClamavWrapper(host="localhost", port=3310)
            clamav_result = clamav.scan_file(filepath)
            is_malicious = "FOUND" in clamav_result

            result = {
                "file_type": file_type,
                "file_size": file_size,
                "is_malicious": is_malicious,
                "clamav_result": clamav_result.strip(),
            }
            self.logger.info(f"Scanned file: {filepath}")
            self.logger.info(f"Result: {result}")

            return result
        except Exception as e:
            self.logger.error(f"Error scanning file {filepath}: {str(e)}")
            return {"is_malicious": False, "clamav_result": str(e)}

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

scanner = FileScanner()
last_scanned_file = None
last_scan_result = None

def select_file():
    global last_scanned_file
    last_scanned_file = filedialog.askopenfilename(
        title="Select a file", filetypes=(("All Files", "*.*"), ("Executables", "*.exe"))
    )
    if last_scanned_file:
        file_label.config(text=f"Selected: {os.path.basename(last_scanned_file)}")
    else:
        file_label.config(text="No file selected.")

def scan_file():
    global last_scan_result
    if not last_scanned_file:
        messagebox.showwarning("Warning", "Please select a file first!")
        return

    progress_bar["value"] = 0
    status_label.config(text="Scanning...")
    vx.update_idletasks()

    def perform_scan():
        global last_scan_result
        for i in range(1, 101):
            time.sleep(0.02)
            progress_bar["value"] = i
            vx.update_idletasks()
        last_scan_result = scanner.scan_file(last_scanned_file)
        if last_scan_result["is_malicious"]:
            status_label.config(text="Malicious file detected!", foreground="red")
            messagebox.showerror("Warning", "This file contains malware!")
        else:
            status_label.config(text="File is safe.", foreground="green")
            messagebox.showinfo("Result", "The file is safe.")

    threading.Thread(target=perform_scan).start()

def quarantine_file():
    if not last_scan_result or not last_scan_result["is_malicious"]:
        messagebox.showwarning("Warning", "No malicious file to quarantine!")
        return
    if scanner.quarantine_file(last_scanned_file):
        messagebox.showinfo("Success", "File has been quarantined successfully!")
    else:
        messagebox.showerror("Error", "Failed to quarantine the file.")

def delete_quarantined():
    try:
        for file in os.listdir(scanner.quarantine_dir):
            file_path = os.path.join(scanner.quarantine_dir, file)
            os.remove(file_path)
            scanner.logger.info(f"Deleted quarantined file: {file_path}")
        messagebox.showinfo("Success", "All quarantined files have been deleted.")
    except Exception as e:
        scanner.logger.error(f"Error deleting quarantined files: {str(e)}")
        messagebox.showerror("Error", "Failed to delete quarantined files.")

# Hover effect functions
def on_enter(event):
    event.widget.config(bootstyle="warning")

def on_leave(event):
    event.widget.config(bootstyle="success")

from PIL import Image, ImageTk

vx = tb.Window(themename="superhero")
vx.title("Vermouth Secure X")
vx.geometry("1000x1200")
vx.config(background='black')
vx.resizable(False, False)

background_image = Image.open("./hinhnen3.png")
background_photo = ImageTk.PhotoImage(background_image)
background_label = Label(vx, image=background_photo)
background_label.place(relx=0, rely=0, relwidth=1, relheight=1)

title_label = tb.Label(vx, text="Vermouth Secure X", font=("Helvetica", 40), bootstyle="danger")
title_label.pack(pady=50)

subtitle_label = tb.Label(vx, text="Advanced File Scanner", font=("Helvetica", 16), bootstyle="primary")
subtitle_label.pack(pady=20)

file_label = tb.Label(vx, text="No file selected.", font=("Helvetica", 16), bootstyle="warning")
file_label.pack(pady=20)

select_button = tb.Button(vx, text="Select File", bootstyle="primary", command=select_file, padding=20)
select_button.pack(pady=20)

progress_bar = Progressbar(vx, orient=HORIZONTAL, length=600, mode="determinate")
progress_bar.pack(pady=20)

status_label = tb.Label(vx, text="", font=("Helvetica", 20), bootstyle="info")
status_label.pack(pady=0)

scan_button = tb.Button(vx, text="Start Scan", bootstyle="success", command=scan_file, padding=20)
scan_button.pack(pady=15)

quarantine_button = tb.Button(vx, text="Quarantine File", bootstyle="warning", command=quarantine_file, padding=20)
quarantine_button.pack(pady=15)

delete_button = tb.Button(vx, text="Delete Quarantined Files", bootstyle="danger", command=delete_quarantined, padding=20)
delete_button.pack(pady=15)

exit_button = tb.Button(vx, text="Exit", bootstyle="secondary", command=vx.destroy, padding=20)
exit_button.pack(pady=20)

vx.mainloop()
