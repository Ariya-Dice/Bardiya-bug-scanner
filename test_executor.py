import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk # For accessing tk.END and Tkinter functions
import os # For os.geteuid()
import logging # For logging
import re # For more precise URL replacement

# Assume output_filters.py and api_interaction.py are available
# You must ensure these files are located next to test_executor.py.
from output_filters import (
    filter_nmap, filter_curl, filter_openssl, filter_dirb_gobuster,
    filter_sqlmap, filter_testssl, filter_sslyze,
    filter_maltego, filter_theharvester, filter_shodan,
    filter_recon_ng, filter_google_dorks, filter_wafw00f,
    filter_hydra, filter_assetfinder
)

# If OpenAI / DeepSeek functionality is enabled, keep this line active.
# Otherwise, you can comment it out and use placeholder functions.
from api_interaction import analyze_test_output, suggest_next_test

# Logging settings for test_executor
# These settings should be configured at the beginning of program execution (e.g., in main.py).
# We've included it here just to ensure the logger is defined.
try:
    logging.getLogger(__name__).setLevel(logging.INFO)
except:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    logging.info("Logging configured in test_executor.py (fallback).")


# Dictionary to map commands/tools to their respective filter functions
# This dictionary should be carefully reviewed to cover all your tools and commands.
# Use keys that appear at the beginning of your commands
# or are easily identifiable.
COMMAND_FILTERS = {
    "nmap": filter_nmap,
    "curl": filter_curl,
    "openssl": filter_openssl,
    "dirb": filter_dirb_gobuster,
    "gobuster": filter_dirb_gobuster,
    "sqlmap": filter_sqlmap,
    "testssl.sh": filter_testssl,
    "sslyze": filter_sslyze,
    "wafw00f": filter_wafw00f,
    "hydra": filter_hydra,
    "sublist3r": filter_assetfinder, # Sublist3r output is similar to assetfinder
    "assetfinder": filter_assetfinder,
    "theharvester": filter_theharvester,
    "shodan": filter_shodan,
    "recon-ng": filter_recon_ng,
    # grep and find commands usually don't need specific filtering, their raw output is useful
    # The same applies to netstat, ss, journalctl, and cat log files
}

def run_test(command, stop_event, sudo_password, use_ai=False):
    """
    Executes a command and filters its output, with optional AI analysis.
    """
    if stop_event.is_set():
        logging.info(f"Test '{command[:50]}...' stopped by user request.")
        return None, "Test stopped by user.", None, None, "stopped" # Added status

    # Sudo management: if the command needs sudo and the script is not run as root, add the password.
    original_command = command # Keep the original command before adding password
    if "sudo" in command and os.geteuid() != 0:
        command_to_execute = f"echo '{sudo_password}' | sudo -S {command.replace('sudo ', '', 1)}"
    else:
        command_to_execute = command
    
    raw_output = ""
    error_output = ""
    filtered_output = ""
    ai_analysis = ""
    ai_suggestion = ""
    status = "failed" # Default status

    try:
        logging.info(f"Executing command: {original_command}")
        proc = subprocess.run(command_to_execute, shell=True, capture_output=True, text=True, timeout=1300)
        raw_output = proc.stdout
        error_output = proc.stderr
        
        if proc.returncode == 0:
            status = "success"
        else:
            status = "failed"
            logging.error(f"Command '{original_command}' failed with exit code {proc.returncode}: {error_output}")

        # Apply filter
        selected_filter = None
        for key_prefix, filter_func in COMMAND_FILTERS.items():
            # Use re.match to detect the tool appearing at the beginning of the command
            if re.match(r'^\s*' + re.escape(key_prefix), original_command):
                selected_filter = filter_func
                break
        
        if selected_filter:
            filtered_output = selected_filter(raw_output)
            logging.debug(f"Applied filter {selected_filter.__name__} for command: {original_command}")
        else:
            filtered_output = raw_output # If no specific filter, use raw output
            logging.debug(f"No specific filter found for command: {original_command}, showing raw output.")

        # AI analysis (if enabled)
        if use_ai and filtered_output:
            try:
                ai_analysis = analyze_test_output(filtered_output)
                # For suggest_next_test, you can also send a history of previous tests or important outputs.
                # Currently, we are only sending filtered_output.
                ai_suggestion = suggest_next_test(filtered_output)
                logging.info(f"AI analysis/suggestion completed for: {original_command[:50]}...")
            except Exception as ai_e:
                ai_analysis = f"AI analysis failed: {str(ai_e)}"
                ai_suggestion = "No AI suggestion due to error."
                logging.error(f"AI interaction failed for command '{original_command[:50]}...': {ai_e}")


    except subprocess.TimeoutExpired:
        raw_output = ""
        error_output = "Test timed out after 1300 seconds."
        status = "timeout"
        logging.warning(f"Command '{original_command}' timed out.")
    except Exception as e:
        raw_output = ""
        error_output = f"Test failed due to an unexpected error: {str(e)}"
        status = "error"
        logging.critical(f"Unexpected error running command '{original_command}': {e}")
    
    return filtered_output, error_output, ai_analysis, ai_suggestion, status


def run_tests(commands, output_widget, progress_bar, stop_event, tests_pending_label, tests_done_label, sudo_password, use_ai=False):
    """
    Executes multiple commands in parallel and displays results in the GUI.
    """
    total_tests = len(commands)
    tests_done = 0
    
    # Configure the progress bar
    if progress_bar:
        progress_bar.config(maximum=total_tests, value=0)
        progress_bar.start() # Start animation if in indeterminate mode

    tests_pending_label.config(text=f"Tests pending: {total_tests}")
    tests_done_label.config(text=f"Tests completed: 0")

    logging.info(f"Starting {total_tests} tests. AI analysis: {'Enabled' if use_ai else 'Disabled'}")

    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_command = {executor.submit(run_test, cmd, stop_event, sudo_password, use_ai): cmd for cmd in commands}
        
        for future in as_completed(future_to_command):
            if stop_event.is_set():
                logging.info("Test execution interrupted by user.")
                # If the user stopped, try to cancel remaining futures
                for pending_future in future_to_command:
                    if not pending_future.done():
                        pending_future.cancel()
                break # Exit the loop
            
            cmd = future_to_command[future]
            try:
                filtered_output, error_output, ai_analysis, ai_suggestion, status = future.result()
            except Exception as exc:
                logging.error(f"Command '{cmd[:50]}...' generated an exception: {exc}")
                filtered_output, error_output, ai_analysis, ai_suggestion, status = "", f"Error in future result: {exc}", "", "", "error"

            # Update GUI in the main Tkinter thread
            output_widget.after(0, lambda: _update_gui_output(
                output_widget, cmd, filtered_output, error_output, ai_analysis, ai_suggestion, use_ai, status
            ))
            
            tests_done += 1
            output_widget.after(0, lambda: _update_gui_progress(
                tests_done_label, tests_pending_label, progress_bar, total_tests, tests_done
            ))
            
    # End ThreadPoolExecutor and progress bar
    if progress_bar:
        output_widget.after(0, progress_bar.stop)
        output_widget.after(0, lambda: progress_bar.config(value=total_tests)) # Ensure bar is full

    if not stop_event.is_set():
        final_message = "\n--- All tests completed ---\n"
        logging.info("All tests completed.")
    else:
        final_message = "\n--- Test execution interrupted ---\n"
        logging.info("Test execution flow stopped by user.")

    output_widget.after(0, lambda: output_widget.insert(tk.END, final_message))
    output_widget.after(0, lambda: output_widget.see(tk.END))


def _update_gui_output(output_widget, cmd, filtered_output, error_output, ai_analysis, ai_suggestion, use_ai, status):
    """
    Helper function to update GUI output from the main Tkinter thread.
    """
    status_emoji = "✅" if status == "success" else ("❌" if status == "failed" else "⚠️")
    
    output_widget.insert(tk.END, f"Command {status_emoji}: {cmd}\n", "bold_cmd")
    output_widget.tag_configure("bold_cmd", font=("TkFixedFont", 10, "bold")) # To bold commands

    if filtered_output:
        output_widget.insert(tk.END, f"Filtered Output:\n{filtered_output}\n")
    if error_output:
        output_widget.insert(tk.END, f"Errors:\n{error_output}\n", "error_output")
        output_widget.tag_configure("error_output", foreground="red")
    
    if use_ai:
        if ai_analysis:
            output_widget.insert(tk.END, f"AI Analysis:\n{ai_analysis}\n", "ai_analysis")
            output_widget.tag_configure("ai_analysis", foreground="blue")
        if ai_suggestion:
            output_widget.insert(tk.END, f"AI Suggestion:\n{ai_suggestion}\n", "ai_suggestion")
            output_widget.tag_configure("ai_suggestion", foreground="purple")
    
    output_widget.insert(tk.END, f"{'-'*60}\n\n") # Longer separator for readability
    output_widget.see(tk.END) # Scroll to bottom

def _update_gui_progress(tests_done_label, tests_pending_label, progress_bar, total_tests, tests_done):
    """
    Helper function to update GUI progress from the main Tkinter thread.
    """
    tests_pending_label.config(text=f"Tests pending: {total_tests - tests_done}")
    tests_done_label.config(text=f"Tests completed: {tests_done}")
    if progress_bar:
        progress_bar.config(value=tests_done)