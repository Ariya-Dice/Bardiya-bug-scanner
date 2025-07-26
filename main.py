import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, Entry
from tkinter import ttk # For Progressbar
import os
import threading
import logging # For logging
import re # <-- This import must be present


# Global logging settings
logging.basicConfig(
    level=logging.INFO, # Default display level: INFO and above
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.FileHandler("ariyabot.log"), # Log to file
        logging.StreamHandler() # Log to console
    ]
)
logging.info("AriyaBot started.")


from dependency_manager import check_system_tools, check_python_libs, full_installation
from prompt_manager import load_prompts, save_prompt
from api_interaction import check_api_status, analyze_test_output, suggest_next_test
from test_executor import run_tests # This function includes filtering and AI logic


# --- Placeholder functions for API interaction (This section was explained previously) ---
if 'analyze_test_output' not in globals():
    def check_api_status():
        logging.warning("[WARN] Using placeholder for check_api_status.")
        return True, "API functionality is temporarily disabled."

    def analyze_test_output(output):
        logging.warning("[WARN] Using placeholder for analyze_test_output.")
        return f"Analysis (AI disabled): Output received for test. Length: {len(output)}."

    def suggest_next_test(output):
        logging.warning("[WARN] Using placeholder for suggest_next_test.")
        return "Next test (AI disabled): Manual analysis or re-enable AI features."
# --- End of placeholder functions ---


# Request sudo password from the user (This section is constant)
sudo_password = simpledialog.askstring("Sudo Password", "Enter your sudo password:", show="*")
if not sudo_password:
    messagebox.showerror("Error", "Sudo password is required. Exiting program.")
    logging.critical("Sudo password not provided. Exiting.")
    exit()

# Check and install dependencies (This section is constant)
logging.info("Starting dependency check and installation...")
success, msg = full_installation(sudo_password)
if not success:
    messagebox.showwarning("Warning", f"Some dependencies failed to install: {msg}. Program might not function correctly.")
    logging.warning(f"Dependency installation issues: {msg}")
else:
    messagebox.showinfo("Success", "All dependencies checked and installed successfully!")
    logging.info("All dependencies checked/installed successfully.")

# Load prompts (This section is constant)
prompts = load_prompts()


# Extending your create_gui function to add new widgets
def create_gui_extended():
    root = tk.Tk()
    root.title("AriyaBot - Kali Security Bot")
    root.geometry("800x750") # Increased initial window size slightly

    # Field for target link input
    tk.Label(root, text="Target Link (e.g., http://example.com):").pack(pady=2)
    link_entry = tk.Entry(root, width=70)
    link_entry.pack(pady=2)
    link_entry.insert(tk.END, "http://example.com") # Default value

    # Field for test commands input
    tk.Label(root, text="Commands/Tests:").pack(pady=2)
    test_entry = scrolledtext.ScrolledText(root, height=10, width=80)
    test_entry.pack(fill=tk.BOTH, expand=False, padx=5, pady=2)

    # Load commands from commands.txt when the program starts
    try:
        with open("commands.txt", "r", encoding="utf-8") as f:
            default_commands = f.read()
        test_entry.insert(tk.END, default_commands)
    except FileNotFoundError:
        logging.warning("commands.txt not found. Commands box will be empty.")
        messagebox.showwarning("Warning", "commands.txt not found. Please enter commands manually.")
    except Exception as e:
        logging.error(f"Error loading commands.txt: {e}")
        messagebox.showerror("Error", f"Error loading commands.txt: {e}")


    # Frame for control buttons
    button_frame = tk.Frame(root)
    button_frame.pack(pady=5)

    # New button for URL replacement
    replace_url_button = tk.Button(button_frame, text="Replace URL (example.com)", bg="blue", fg="white")
    replace_url_button.pack(side=tk.LEFT, padx=5)

    start_button_ai = tk.Button(button_frame, text="Start Tests (with AI)", bg="green", fg="white")
    start_button_ai.pack(side=tk.LEFT, padx=5)

    start_button_no_ai = tk.Button(button_frame, text="Run Tests (without AI)", bg="orange", fg="white")
    start_button_no_ai.pack(side=tk.LEFT, padx=5)
    
    stop_button = tk.Button(button_frame, text="Stop Tests", bg="red", fg="white")
    stop_button.pack(side=tk.LEFT, padx=5)
    
    # Test status labels
    status_frame = tk.Frame(root)
    status_frame.pack(fill=tk.X, padx=5, pady=2)
    
    tests_done_label = tk.Label(status_frame, text="Tests completed: 0")
    tests_done_label.pack(side=tk.LEFT, padx=10)
    
    tests_pending_label = tk.Label(status_frame, text="Tests pending: 0")
    tests_pending_label.pack(side=tk.RIGHT, padx=10)

    # Progress bar
    progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
    progress_bar.pack(fill=tk.X, padx=5, pady=5)
    
    tk.Label(root, text="Results:").pack(pady=2)
    output_text = scrolledtext.ScrolledText(root, height=15, width=80)
    output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
    
    return root, test_entry, start_button_ai, start_button_no_ai, stop_button, output_text, link_entry, progress_bar, tests_pending_label, tests_done_label, replace_url_button

# Call the extended create_gui function
root, test_entry, start_button_ai, start_button_no_ai, stop_button, output_text, link_entry, progress_bar, tests_pending_label, tests_done_label, replace_url_button = create_gui_extended()


# Variable for stopping tests
stop_event = threading.Event()

def prepare_commands_for_display(commands_raw_list, target_link_val):
    """
    This function takes a list of raw commands and replaces example.com with the target link.
    This version is for display in the GUI.
    """
    if not re.match(r"https?://", target_link_val):
        target_link_with_protocol = "http://" + target_link_val
    else:
        target_link_with_protocol = target_link_val
    
    target_link_no_protocol = target_link_with_protocol.replace("http://", "").replace("https://", "")

    prepared_commands_list = []
    example_pattern = re.compile(r'https?://example\.com|example\.com', re.IGNORECASE)

    tools_without_protocol = [
        "nmap", "dirb", "gobuster", "hydra", "wafw00f", 
        "sublist3r", "assetfinder", "host", "dig", "grep", "find",
        "netstat", "ss", "journalctl", "cat", "tail"
    ]

    for cmd in commands_raw_list:
        found_tool_without_protocol = False
        for tool in tools_without_protocol:
            if re.match(r'^\s*' + re.escape(tool) + r'\b', cmd, re.IGNORECASE):
                found_tool_without_protocol = True
                break

        if found_tool_without_protocol:
            prepared_cmd = example_pattern.sub(target_link_no_protocol, cmd)
        else:
            prepared_cmd = example_pattern.sub(target_link_with_protocol, cmd)
        
        prepared_commands_list.append(prepared_cmd)
    
    return "\n".join(prepared_commands_list)


def on_replace_url_click():
    """
    This function is executed when the 'Replace URL' button is clicked.
    It replaces example.com with the target link in the test commands box.
    """
    target_link = link_entry.get().strip()
    if not target_link:
        messagebox.showwarning("Warning", "Please enter a target link in the 'Target Link' box.")
        logging.warning("User attempted to replace URL but target link was empty.")
        return

    # Get current commands from test_entry
    current_commands_raw = test_entry.get("1.0", tk.END).strip().splitlines()
    if not current_commands_raw:
        messagebox.showwarning("Warning", "The commands box is empty. Please load default commands or enter them manually.")
        logging.warning("No commands in test_entry to replace URL.")
        return

    # Prepare commands for display
    updated_commands_text = prepare_commands_for_display(current_commands_raw, target_link)
    
    # Clear test_entry box and insert updated commands
    test_entry.delete("1.0", tk.END)
    test_entry.insert(tk.END, updated_commands_text)
    
    messagebox.showinfo("Operation Successful", "example.com has been replaced with the target link in the commands.")
    logging.info(f"example.com replaced with {target_link} in test commands.")


def start_tests_common(use_ai_flag):
    stop_event.clear()
    commands_raw = test_entry.get("1.0", tk.END).strip().splitlines()
    
    if not commands_raw:
        messagebox.showwarning("Warning", "Please enter tests.")
        logging.warning("No commands entered by user.")
        return

    target_link = link_entry.get().strip()
    if not target_link:
        messagebox.showwarning("Warning", "Please enter a target link (e.g., example.com).")
        logging.warning("No target link entered by user.")
        return
    
    # Final preparation of commands for execution
    # Note: This logic also exists in test_executor.py,
    # but for extra assurance and in case the user did not press the replace button,
    # we apply it here as well to ensure replacement occurs.
    commands_to_execute = prepare_commands_for_display(commands_raw, target_link).splitlines()


    output_text.delete(1.0, tk.END) # Clear previous outputs
    logging.info(f"Starting test execution for {target_link} with AI: {'Enabled' if use_ai_flag else 'Disabled'}")
    
    # Execute tests in a separate thread
    thread = threading.Thread(target=run_tests, args=(
        commands_to_execute, output_text, progress_bar, stop_event,
        tests_pending_label, tests_done_label, sudo_password, use_ai_flag
    ))
    thread.start()

def stop_tests_action():
    stop_event.set() # Sets the stop signal
    logging.info("Stop signal sent to active tests.")
    messagebox.showinfo("Tests Stopped", "Attempting to stop active tests. Please wait for current tests to finish.")

# Configure buttons
replace_url_button.config(command=on_replace_url_click) # Connect the new button
start_button_ai.config(command=lambda: start_tests_common(True))
start_button_no_ai.config(command=lambda: start_tests_common(False))
stop_button.config(command=stop_tests_action)

root.mainloop()