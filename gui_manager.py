import tkinter as tk
from tkinter import scrolledtext, messagebox

class GUIManager:
    def __init__(self, master, start_test_callback, stop_test_callback):
        self.master = master
        master.title("Advanced Penetration Testing Tool")

        self.start_test_callback = start_test_callback
        self.stop_test_callback = stop_test_callback
        self.test_running = False

        # Target URL/Domain Input
        self.target_label = tk.Label(master, text="Target URL/Domain:")
        self.target_label.pack(pady=(10, 0))
        self.target_entry = tk.Entry(master, width=50)
        self.target_entry.pack(pady=(0, 10))
        self.target_entry.insert(0, "https://example.com") # Default value

        # Test Control Buttons
        self.button_frame = tk.Frame(master)
        self.button_frame.pack(pady=5)

        self.start_button = tk.Button(self.button_frame, text="Start Test", command=self.start_test_action)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(self.button_frame, text="Stop Test", command=self.stop_test_action, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # New Buttons: Clear All and Copy Results
        self.clear_button = tk.Button(self.button_frame, text="Clear All", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.copy_button = tk.Button(self.button_frame, text="Copy Results", command=self.copy_results_to_clipboard)
        self.copy_button.pack(side=tk.LEFT, padx=5)

        # Results Display Area
        self.results_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=100, height=30)
        self.results_text.pack(pady=10)
        self.results_text.config(state=tk.DISABLED) # Make it read-only initially

    def start_test_action(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Input Error", "Please enter a target URL or domain.")
            return

        self.test_running = True
        self.update_gui_state()
        self.clear_results() # Clear previous results before starting a new test
        self.append_to_results(f"Starting test on: {target}\n\n")
        self.start_test_callback(target) # Call the function in main.py to start tests

    def stop_test_action(self):
        self.append_to_results("\nTest stopped by user.\n")
        self.stop_test_callback() # Call the function in main.py to stop tests
        self.test_running = False
        self.update_gui_state()

    def update_gui_state(self):
        """Updates the state of GUI elements based on whether a test is running."""
        if self.test_running:
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.target_entry.config(state=tk.DISABLED)
            self.clear_button.config(state=tk.DISABLED) # Disable clear during test run
            self.copy_button.config(state=tk.DISABLED) # Disable copy during test run
        else:
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.target_entry.config(state=tk.NORMAL)
            self.clear_button.config(state=tk.NORMAL)
            self.copy_button.config(state=tk.NORMAL)

    def append_to_results(self, text):
        """Appends text to the results display area."""
        self.results_text.config(state=tk.NORMAL) # Enable writing
        self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END) # Scroll to the end
        self.results_text.config(state=tk.DISABLED) # Disable writing

    def clear_results(self):
        """Clears all text from the results display area."""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        self.append_to_results("Results cleared.\n") # Optional: confirm clear

    def copy_results_to_clipboard(self):
        """Copies the entire content of the results display area to the clipboard."""
        try:
            results_content = self.results_text.get(1.0, tk.END)
            self.master.clipboard_clear()
            self.master.clipboard_append(results_content)
            self.append_to_results("\nResults copied to clipboard!\n")
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy results: {e}")

    def on_test_completion(self):
        """Called by the main application when a test run completes."""
        self.test_running = False
        self.update_gui_state()
        self.append_to_results("\nTest run completed.\n")