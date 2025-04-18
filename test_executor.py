import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

def run_test(command, stop_event, sudo_password):
    if stop_event.is_set():
        return None, "Test stopped by user."
    if "sudo" in command and os.geteuid() != 0:
        command = f"echo '{sudo_password}' | sudo -S {command.replace('sudo ', '')}"
    try:
        proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=1300)
        return proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return None, "Test timed out."
    except Exception as e:
        return None, f"Test failed: {str(e)}"

def run_tests(commands, output_widget, indicator, stop_event, tests_pending_label, tests_done_label, sudo_password):
    total_tests = len(commands)
    tests_done = 0
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_command = {executor.submit(run_test, cmd, stop_event, sudo_password): cmd for cmd in commands}
        for future in as_completed(future_to_command):
            if stop_event.is_set():
                break
            cmd = future_to_command[future]
            output, error = future.result()
            output_widget.insert(tk.END, f"Command: {cmd}\nOutput: {output or error}\n{'-'*40}\n")
            tests_done += 1
            tests_pending_label.config(text=f"Tests pending: {total_tests - tests_done}")
            tests_done_label.config(text=f"Tests completed: {tests_done}")