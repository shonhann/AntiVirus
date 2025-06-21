import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

# Simulated virus keywords
SUSPICIOUS_KEYWORDS = ["virus", "malware", "trojan", "worm", "spyware", "ransomware"]

def scan_folder(folder_path):
    infected_files = []

    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read().lower()
                    if any(keyword in content for keyword in SUSPICIOUS_KEYWORDS):
                        infected_files.append(file_path)
            except Exception as e:
                print(f"Could not read {file_path}: {e}")
    
    return infected_files

def choose_folder():
    folder = filedialog.askdirectory()
    if folder:
        folder_entry.delete(0, tk.END)
        folder_entry.insert(0, folder)

def start_scan():
    folder = folder_entry.get()
    result_text.delete(1.0, tk.END)

    if not os.path.isdir(folder):
        messagebox.showerror("Error", "Please choose a valid folder.")
        return

    result_text.insert(tk.END, f"Scanning folder:\n{folder}\n\n")
    infected = scan_folder(folder)

    if infected:
        result_text.insert(tk.END, "⚠️ Infected files found:\n\n")
        for f in infected:
            result_text.insert(tk.END, f + "\n")
    else:
        result_text.insert(tk.END, "✅ No infected files found.")

# Create the GUI
root = tk.Tk()
root.title("🛡️ Simple Virus Scanner")
root.geometry("600x400")
root.config(bg="#1e1e1e")

# Styling
style = {
    "bg": "#1e1e1e",
    "fg": "#ffffff",
    "font": ("Segoe UI", 10)
}

title_label = tk.Label(root, text="🛡️ Simple Virus Scanner", font=("Segoe UI", 16, "bold"), bg="#1e1e1e", fg="#00ff88")
title_label.pack(pady=10)

folder_frame = tk.Frame(root, bg="#1e1e1e")
folder_frame.pack(pady=5)

folder_entry = tk.Entry(folder_frame, width=50, **style)
folder_entry.pack(side=tk.LEFT, padx=5)

browse_button = tk.Button(folder_frame, text="Browse", command=choose_folder, bg="#00ff88", fg="#000", font=("Segoe UI", 9, "bold"))
browse_button.pack(side=tk.LEFT, padx=5)

scan_button = tk.Button(root, text="Start Scan", command=start_scan, bg="#00c0ff", fg="#000", font=("Segoe UI", 10, "bold"))
scan_button.pack(pady=10)

result_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=70, height=15, bg="#252526", fg="#ffffff", font=("Consolas", 10))
result_text.pack(padx=10, pady=10)

root.mainloop()
