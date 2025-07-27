import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, Entry
from tkinter import ttk # For Progressbar
import os
import threading
import logging # For logging
import re


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


# --- Placeholder functions for API interaction ---
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


# Request sudo password from the user
sudo_password = simpledialog.askstring("Sudo Password", "Enter your sudo password:", show="*")
if not sudo_password:
    messagebox.showerror("Error", "Sudo password is required. Exiting program.")
    logging.critical("Sudo password not provided. Exiting.")
    exit()

# Check and install dependencies
logging.info("Starting dependency check and installation...")
success, msg = full_installation(sudo_password)
if not success:
    messagebox.showwarning("Warning", f"Some dependencies failed to install: {msg}. Program might not function correctly.")
    logging.warning(f"Dependency installation issues: {msg}")
else:
    logging.info("All dependencies checked/installed successfully.")

# Load prompts
prompts = load_prompts()

# Global variable to store the original commands template from commands.txt
original_commands_template = ""

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
            global original_commands_template # Declare intent to modify global variable
            original_commands_template = f.read() # Store the original content
        test_entry.insert(tk.END, original_commands_template)
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

    # NEW: Clear All Button
    clear_all_button = tk.Button(button_frame, text="Clear All", bg="gray", fg="white")
    clear_all_button.pack(side=tk.LEFT, padx=5)

    # NEW: Copy Results Button
    copy_results_button = tk.Button(button_frame, text="Copy Results", bg="purple", fg="white")
    copy_results_button.pack(side=tk.LEFT, padx=5)
    
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
    
    return root, test_entry, start_button_ai, start_button_no_ai, stop_button, output_text, link_entry, progress_bar, tests_pending_label, tests_done_label, replace_url_button, clear_all_button, copy_results_button

# Call the extended create_gui function and unpack new return values
root, test_entry, start_button_ai, start_button_no_ai, stop_button, output_text, link_entry, progress_bar, tests_pending_label, tests_done_label, replace_url_button, clear_all_button, copy_results_button = create_gui_extended()


# Variable for stopping tests
stop_event = threading.Event()

def prepare_commands_for_display(commands_raw_list, target_link_val):
    """
    This function takes a list of raw commands and replaces [TARGET_URL],
    [TARGET_DOMAIN], and [ATTACKER_SERVER_URL] with the appropriate values.
    """
    # Ensure target_link_val has a protocol for [TARGET_URL]
    if not re.match(r"https?://", target_link_val):
        target_link_with_protocol = "http://" + target_link_val
    else:
        target_link_with_protocol = target_link_val
    
    # Extract domain without protocol for [TARGET_DOMAIN]
    # .strip('/') added to remove trailing slash if present, for cleaner domain
    target_link_no_protocol = target_link_with_protocol.replace("http://", "").replace("https://", "").strip('/')

    # Define placeholders
    target_url_placeholder = "[TARGET_URL]"
    target_domain_placeholder = "[TARGET_DOMAIN]"
    # [ATTACKER_SERVER_URL] is meant to be user-controlled or set for specific RFI tests.
    # It's not automatically replaced by target_link_val.

    prepared_commands_list = []

    for cmd in commands_raw_list:
        prepared_cmd = cmd

        # Replace [TARGET_URL] with the full URL (with protocol)
        prepared_cmd = prepared_cmd.replace(target_url_placeholder, target_link_with_protocol)

        # Replace [TARGET_DOMAIN] with the domain only (without protocol)
        prepared_cmd = prepared_cmd.replace(target_domain_placeholder, target_link_no_protocol)

        prepared_commands_list.append(prepared_cmd)
    
    return "\n".join(prepared_commands_list)


def on_replace_url_click():
    """
    This function is executed when the 'Replace URL' button is clicked.
    It replaces example.com with the target link in the test commands box,
    always starting from the original commands template.
    """
    logging.info("on_replace_url_click called!") # Debugging log

    target_link = link_entry.get().strip()
    if not target_link:
        messagebox.showwarning("Warning", "Please enter a target link in the 'Target Link' box.")
        logging.warning("User attempted to replace URL but target link was empty.")
        return

    # Use the stored original_commands_template for replacement
    if not original_commands_template:
        messagebox.showwarning("Warning", "Original commands template not loaded. Please ensure commands.txt exists.")
        logging.warning("Original commands template is empty. Cannot replace URL.")
        return

    # Prepare commands for display using the original template
    updated_commands_text = prepare_commands_for_display(original_commands_template.splitlines(), target_link)
    
    # Clear test_entry box and insert updated commands
    test_entry.delete("1.0", tk.END)
    test_entry.insert(tk.END, updated_commands_text)
    
    messagebox.showinfo("Operation Successful", "Placeholders ([TARGET_URL], [TARGET_DOMAIN]) have been replaced with the target link in the commands.")
    logging.info(f"Placeholders replaced with {target_link} in test commands. Updated commands text length: {len(updated_commands_text)}")


# Function to clear all results
def clear_results_action():
    print("clear_results_action called!") # Debugging print
    output_text.config(state=tk.NORMAL) # Enable writing
    output_text.delete(1.0, tk.END)
    output_text.config(state=tk.DISABLED) # Disable writing
    logging.info("Results display cleared by user.")
    print("Results cleared in GUI (if visible).") # Debugging print

# Function to copy results to clipboard
def copy_results_to_clipboard_action():
    try:
        # Enable text widget temporarily to get content
        output_text.config(state=tk.NORMAL)
        results_content = output_text.get(1.0, tk.END)
        output_text.config(state=tk.DISABLED)

        root.clipboard_clear()
        root.clipboard_append(results_content)
        messagebox.showinfo("Copy Successful", "Test results copied to clipboard!")
        logging.info("Test results copied to clipboard.")
    except Exception as e:
        messagebox.showerror("Copy Error", f"Failed to copy results: {e}")
        logging.error(f"Error copying results to clipboard: {e}")

def _set_gui_state(is_running: bool):
    """
    Sets the state of GUI elements based on whether a test is running.
    If is_running is True, inputs and start buttons are disabled, stop button is enabled.
    If is_running is False, inputs and start buttons are enabled, stop button is disabled.
    """
    if is_running:
        link_entry.config(state=tk.DISABLED)
        test_entry.config(state=tk.DISABLED)
        replace_url_button.config(state=tk.DISABLED)
        start_button_ai.config(state=tk.DISABLED)
        start_button_no_ai.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL) # Only enable stop when running
        clear_all_button.config(state=tk.DISABLED) # Disable clear during run
        copy_results_button.config(state=tk.DISABLED) # Disable copy during run
    else:
        link_entry.config(state=tk.NORMAL)
        test_entry.config(state=tk.NORMAL)
        replace_url_button.config(state=tk.NORMAL)
        start_button_ai.config(state=tk.NORMAL)
        start_button_no_ai.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED) # Disable stop when not running
        clear_all_button.config(state=tk.NORMAL)
        copy_results_button.config(state=tk.NORMAL)

def run_tests_thread_wrapper(commands, output_widget, progress_widget, stop_event_obj,
                             pending_label, done_label, sudo_pass, use_ai_flag):
    """
    Wrapper function to run tests in a separate thread and handle GUI state updates
    after completion or interruption.
    """
    try:
        run_tests(commands, output_widget, progress_widget, stop_event_obj,
                  pending_label, done_label, sudo_pass, use_ai_flag)
    finally:
        # Ensure GUI state is reset on completion/interruption.
        # Use root.after to safely update GUI from a non-main thread.
        root.after(0, lambda: _set_gui_state(False))


def start_tests_common(use_ai_flag):
    stop_event.clear() # Clear stop flag for a new test run
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
    # This ensures the commands are correctly formatted with the target_link
    commands_to_execute = prepare_commands_for_display(commands_raw, target_link).splitlines()

    output_text.delete(1.0, tk.END) # Clear previous outputs
    logging.info(f"Starting test execution for {target_link} with AI: {'Enabled' if use_ai_flag else 'Disabled'}")
    
    # Set GUI state to 'running'
    _set_gui_state(True)

    # Execute tests in a separate thread using the wrapper
    thread = threading.Thread(target=run_tests_thread_wrapper, args=(
        commands_to_execute, output_text, progress_bar, stop_event,
        tests_pending_label, tests_done_label, sudo_password, use_ai_flag
    ))
    thread.start()

def stop_tests_action():
    stop_event.set() # Sets the stop signal
    logging.info("Stop signal sent to active tests.")
    messagebox.showinfo("Tests Stopped", "Attempting to stop active tests. Please wait for current tests to finish.")
    # GUI state will be reset by run_tests_thread_wrapper when it detects the stop_event


# Configure buttons
replace_url_button.config(command=on_replace_url_click) # Connect the new button
start_button_ai.config(command=lambda: start_tests_common(True))
start_button_no_ai.config(command=lambda: start_tests_common(False))
stop_button.config(command=stop_tests_action)
clear_all_button.config(command=clear_results_action) # Connect clear button
copy_results_button.config(command=copy_results_to_clipboard_action) # Connect copy button

# Set initial GUI state (all inputs/start buttons enabled, stop disabled)
_set_gui_state(False)

root.mainloop()