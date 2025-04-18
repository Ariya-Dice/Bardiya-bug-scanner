import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, Entry
from tkinter import ttk

def create_gui():
    root = tk.Tk()
    root.title("AriyaBot - Kali Security Bot")
    
    tk.Label(root, text="Domain/Rules/Tests:").pack()
    test_entry = scrolledtext.ScrolledText(root, height=10)
    test_entry.pack()
    
    button_frame = tk.Frame(root)
    button_frame.pack()
    start_button = tk.Button(button_frame, text="Start Tests", bg="gray")
    start_button.pack(side=tk.LEFT)
    
    tk.Label(root, text="Results:").pack()
    output_text = scrolledtext.ScrolledText(root, height=10)
    output_text.pack(fill=tk.BOTH, expand=True)
    
    return root, test_entry, start_button, output_text