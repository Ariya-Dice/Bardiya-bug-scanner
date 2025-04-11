import subprocess
import importlib
import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog, Entry
from tkinter import ttk
import threading
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import time
from openai import OpenAI
from dotenv import load_dotenv
import re

# List of dependencies
SYSTEM_TOOLS = [
    "nmap", "curl", "nuclei", "whatweb", "sqlmap", "dirb", "metasploit-framework",
    "dnsenum", "testssl.sh", "sublist3r", "nikto", "wpscan", "ping", "traceroute", "openssl"
]
PYTHON_LIBS = ["openai", "tkinter", "python-dotenv"]

# Function to check and install dependencies
def check_dependencies(sudo_password):
    missing_tools = []
    missing_libs = []

    # Check system tools
    for tool in SYSTEM_TOOLS:
        result = subprocess.run(f"command -v {tool}", shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            missing_tools.append(tool)

    # Check Python libraries
    for lib in PYTHON_LIBS:
        try:
            importlib.import_module(lib if lib != "python-dotenv" else "dotenv")
        except ImportError:
            missing_libs.append(lib)

    # Notify and install if dependencies are missing
    if missing_tools or missing_libs:
        missing_msg = ""
        if missing_tools:
            missing_msg += f"Missing tools: {', '.join(missing_tools)}\n"
        if missing_libs:
            missing_msg += f"Missing Python libraries: {', '.join(missing_libs)}\n"
        
        install = messagebox.askyesno(
            "Missing Dependencies",
            f"{missing_msg}Would you like to install these dependencies?"
        )
        
        if install:
            try:
                # Install system tools
                if missing_tools:
                    cmd = f"echo '{sudo_password}' | sudo -S apt-get install -y {' '.join(missing_tools)}"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    if result.returncode != 0:
                        messagebox.showerror("Error", f"Failed to install tools:\n{result.stderr}")
                        return False

                # Install Python libraries
                if missing_libs:
                    for lib in missing_libs:
                        cmd = f"pip install {lib}"
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                        if result.returncode != 0:
                            messagebox.showerror("Error", f"Failed to install {lib}:\n{result.stderr}")
                            return False
                messagebox.showinfo("Success", "All dependencies installed successfully!")
                return True
            except Exception as e:
                messagebox.showerror("Error", f"Error installing dependencies: {str(e)}")
                return False
        else:
            messagebox.showwarning("Warning", "Some dependencies are missing. The bot may not function correctly.")
            return True  # Proceed even if not installed
    return True  # All dependencies are present

# Load environment variables and configure OpenAI client
load_dotenv()
api_key = os.getenv("OPENROUTER_API_KEY")
if not api_key:
    raise ValueError("OPENROUTER_API_KEY not found in .env file!")

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=api_key,
)

# Initial prompt
default_prompt = (
    "You are a machine-like security assistant specialized in penetration testing and vulnerability detection. "
    "The user provides domains and rules. You suggest initial concise and precise test commands in a single field, "
    "one per line, no extra explanations, for the user to copy and feed to the testing bot. The bot runs the tests, "
    "filters results, and returns output. The user gives you the results, you analyze them, and suggest new, creative "
    "test commands in a single field, one per line, for copying back to the bot. This cycle repeats. If you spot a "
    "vulnerability or interesting finding, mention it briefly and move on—no tangents, stay focused on tests.\n\n"
    "Instructions:\n"
    "- Use creative, novel test methods; skip obvious vulnerabilities.\n"
    "- Commands must work in Kali Linux, consider all possible angles.\n"
    "- Think like an all-knowing machine, find unique, unexplored paths.\n"
    "- Optimize tests: limit ports (e.g., critical ones), use Nmap flags like -T4 and --min-rate, leverage parallel "
    "for concurrency, prioritize lightweight tests.\n"
    "- Start with 'Information Disclosure' and suggest related tests. If results are useful, dig deeper; otherwise, "
    "move to the next vulnerability (e.g., XSS Generic, Secure Design Flaws, etc.).\n\n"
    "Output Format:\n"
    "All test commands in one field, each on a new line, no explanations.\n\n"
    "Vulnerability List:\n"
    "1. Information Disclosure\n2. XSS Generic\n3. Secure Design Flaws\n4. Improper Authentication\n5. CSRF\n"
    "6. XSS Stored\n7. Privilege Escalation\n8. Denial of Service\n9. XSS Reflected\n10. Improper Access Control\n"
    "11. Open Redirect\n12. SQL Injection\n13. Code Injection\n14. Command Injection\n15. Memory Corruption\n"
    "16. Cryptographic Issues\n17. IDOR\n18. SSRF\n\n"
    "Workflow:\n"
    "Begin with 'Information Disclosure' tests. Analyze results when provided. If promising, suggest more; if not, "
    "move to the next vulnerability.\n\n"
    "Input domain/rules and test output:\n{input_data}"
)

# Global variable for current prompt
current_prompt = default_prompt

# Path for storing prompts
PROMPT_FILE = "prompts.json"

# Function to save prompts to file
def save_prompt_to_file(name, prompt):
    prompts = load_prompts()
    prompts[name] = prompt
    with open(PROMPT_FILE, "w") as f:
        json.dump(prompts, f, indent=4)

# Function to load prompts
def load_prompts():
    if os.path.exists(PROMPT_FILE):
        with open(PROMPT_FILE, "r") as f:
            return json.load(f)
    return {"Default": default_prompt}

# Function to select prompt
def select_prompt():
    global current_prompt
    prompts = load_prompts()
    
    prompt_window = tk.Toplevel(root)
    prompt_window.title("Select Prompt")
    prompt_window.geometry("400x300")

    tk.Label(prompt_window, text="Choose a prompt to use:").pack(pady=5)
    
    prompt_listbox = tk.Listbox(prompt_window, height=10)
    for name in prompts.keys():
        prompt_listbox.insert(tk.END, name)
    prompt_listbox.pack(pady=5)

    def on_select():
        selected = prompt_listbox.get(prompt_listbox.curselection())
        if selected:
            current_prompt = prompts[selected]
            prompt_window.destroy()
            messagebox.showinfo("Success", f"Prompt '{selected}' loaded successfully!")
        else:
            prompt_window.destroy()
            messagebox.showwarning("Warning", "No prompt selected, using default.")
            current_prompt = default_prompt

    select_button = tk.Button(prompt_window, text="Select", command=on_select)
    select_button.pack(pady=5)

# Function to check API status
def check_api_status():
    try:
        response = client.chat.completions.create(
            model="deepseek/deepseek-r1:free",
            messages=[{"role": "user", "content": "Test API status"}],
            max_tokens=10
        )
        return True if response.choices else False
    except Exception:
        return False

# Function to generate default local tests
def generate_default_tests(input_data):
    domain = re.search(r"Domain/rules: (.+)", input_data)
    domain = domain.group(1).strip().splitlines()[0] if domain else "unknown"
    return (
        f"curl -s http://{domain}/robots.txt\n"
        f"curl -I http://{domain}/.env\n"
        f"nmap -T4 -p80,443 {domain}\n"
        f"whatweb http://{domain}"
    )

# Function to analyze test output with DeepSeek
def analyze_test_output(filtered_output):
    if not check_api_status():
        return "DeepSeek unavailable: API is down or rate limit exceeded."
    try:
        prompt = f"Analyze the following security test output and provide recommendations:\n{filtered_output}"
        response = client.chat.completions.create(
            model="deepseek/deepseek-r1:free",
            messages=[{"role": "user", "content": prompt}]
        )
        if response.choices and response.choices[0].message:
            return response.choices[0].message.content
        else:
            return "DeepSeek analysis failed: No valid response received."
    except Exception as e:
        return f"DeepSeek analysis failed: {str(e)}"

# Function to suggest next test
def suggest_next_test(input_data):
    if not check_api_status():
        return generate_default_tests(input_data)
    try:
        prompt = current_prompt.format(input_data=input_data)
        response = client.chat.completions.create(
            model="deepseek/deepseek-r1:free",
            messages=[{"role": "user", "content": prompt}]
        )
        if response.choices and response.choices[0].message:
            return response.choices[0].message.content
        else:
            return generate_default_tests(input_data)
    except Exception as e:
        return f"Next test suggestion failed: {str(e)}"

# Global variable for sudo password
global_sudo_password = None

# Filter functions
def filter_nmap(output):
    lines = output.splitlines()
    open_ports = []
    for line in lines:
        if re.search(r"\d+/tcp\s+open", line) or "vulnerable" in line.lower():
            open_ports.append(line.strip())
    return "\n".join(open_ports) if open_ports else "No open ports or vulnerabilities found"

def filter_curl(output):
    lines = output.splitlines()
    suspicious = []
    keywords = ["key", "secret", "password", "token", "config", "admin", "error", "denied", "forbidden", "server", "backup", "log", "api_key", "url", "branch", "login", "file", "dir", "archive", "status", "disallow", "allow", "loc"]
    status_codes = ["200", "301", "302", "401", "403", "404", "500"]
    for line in lines:
        line = line.strip()
        if not line or "Not found" in line or "Empty" in line or "No sensitive" in line or "No secrets" in line:
            continue
        if any(code in line for code in status_codes) or any(kw in line.lower() for kw in keywords):
            suspicious.append(line)
        elif re.search(r"(Server|X-.*|Location):", line, re.I):
            suspicious.append(line)
    if "<html" in output.lower() or "<!doctype" in output.lower():
        suspicious = []
        for kw in keywords:
            if kw in output.lower():
                suspicious.append(f"Suspicious keyword '{kw}' found in HTML")
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", output)
        if emails:
            suspicious.append(f"Emails found: {', '.join(emails[:3])}" + (" (and more)" if len(emails) > 3 else ""))
        tokens = re.findall(r"(?i)(token|key|secret)\s*[:=]\s*['\"]?[a-zA-Z0-9-_]+['\"]?", output)
        if tokens:
            suspicious.append(f"Possible tokens: {', '.join(tokens[:3])}" + (" (and more)" if len(tokens) > 3 else ""))
    return "\n".join(suspicious[:10]) if suspicious else "No suspicious data found"

def filter_nuclei(output):
    lines = output.splitlines()
    issues = [line.strip() for line in lines if any(sev in line for sev in ["[high]", "[critical]", "[medium]"])]
    return "\n".join(issues) if issues else "No significant vulnerabilities found"

def filter_whatweb(output):
    lines = output.splitlines()
    tech = [line.strip() for line in lines if any(kw in line for kw in ["Server", "Framework", "CMS", "Version"])]
    return "\n".join(tech) if tech else "No notable tech found"

def filter_sqlmap(output):
    lines = output.splitlines()
    issues = [line.strip() for line in lines if "injection" in line.lower() or "vulnerable" in line.lower()]
    return "\n".join(issues) if issues else "No SQL injection found"

def filter_dirb(output):
    lines = output.splitlines()
    dirs = [line.strip() for line in lines if "DIRECTORY" in line or "CODE:" in line]
    return "\n".join(dirs) if dirs else "No directories found"

def filter_burp(output):
    lines = output.splitlines()
    issues = [line for line in lines if "VULNERABILITY" in line]
    return "\n".join(issues) if issues else "No vulnerabilities found in Burp Suite output."

def filter_metasploit(output):
    lines = output.splitlines()
    vulnerabilities = [line for line in lines if "exploit" in line]
    return "\n".join(vulnerabilities) if vulnerabilities else "No exploits found in Metasploit output."

def filter_dnsenum(output):
    lines = output.splitlines()
    domains = [line for line in lines if "Host:" in line]
    return "\n".join(domains) if domains else "No domains found"

def filter_testssl(output):
    lines = output.splitlines()
    issues = [line for line in lines if "VULNERABLE" in line]
    return "\n".join(issues) if issues else "No SSL issues found"

def filter_sublist3r(output):
    lines = output.splitlines()
    subdomains = [line for line in lines if "." in line]
    return "\n".join(subdomains) if subdomains else "No subdomains found"

def filter_nikto(output):
    lines = output.splitlines()
    vulns = [line for line in lines if "+ " in line and "OSVDB" in line]
    return "\n".join(vulns) if vulns else "No vulnerabilities found"

def filter_wpscan(output):
    lines = output.splitlines()
    issues = [line for line in lines if "Vulnerability" in line]
    return "\n".join(issues) if issues else "No vulnerabilities found"

def filter_ping(output):
    lines = output.splitlines()
    ping_results = [line for line in lines if "time=" in line]
    return "\n".join(ping_results) if ping_results else "No ping results found"

def filter_traceroute(output):
    lines = output.splitlines()
    hops = [line for line in lines if "ms" in line]
    return "\n".join(hops) if hops else "No traceroute results found"

def filter_openssl(output):
    lines = output.splitlines()
    relevant = [line for line in lines if any(kw in line.lower() for kw in ["connected", "error", "certificate", "protocol"])]
    return "\n".join(relevant) if relevant else "No significant SSL data found"

def general_filter(output):
    lines = output.splitlines()
    suspicious = []
    keywords = ["error", "failed", "timeout", "key", "secret", "password", "token", "config", "admin", "denied", "backup", "log", "api_key", "url", "branch", "login", "file", "dir", "archive", "status"]
    for line in lines:
        if any(kw in line.lower() for kw in keywords) or re.search(r"\d{3}\s+[A-Za-z]", line):
            suspicious.append(line.strip())
    return "\n".join(suspicious[:10]) if suspicious else "No significant data found"

filters = {
    "nmap": filter_nmap,
    "curl": filter_curl,
    "wget": filter_curl,
    "nuclei": filter_nuclei,
    "whatweb": filter_whatweb,
    "sqlmap": filter_sqlmap,
    "dirb": filter_dirb,
    "burp": filter_burp,
    "metasploit": filter_metasploit,
    "dnsenum": filter_dnsenum,
    "testssl.sh": filter_testssl,
    "sublist3r": filter_sublist3r,
    "nikto": filter_nikto,
    "wpscan": filter_wpscan,
    "ping": filter_ping,
    "traceroute": filter_traceroute,
    "openssl": filter_openssl,
}

def get_command_name(command):
    parts = command.split()
    return parts[0] if parts else "unknown"

def check_internet_with_retry(retries=3, delay=5):
    for _ in range(retries):
        try:
            subprocess.run("ping -c 1 8.8.8.8", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
            return True
        except subprocess.TimeoutExpired:
            time.sleep(delay)
    return False

def get_ip():
    try:
        result = subprocess.run("curl -s ifconfig.me", shell=True, capture_output=True, text=True)
        return result.stdout.strip() if result.returncode == 0 else "Failed to get IP"
    except Exception as e:
        return f"Error: {str(e)}"

def blink_indicator(indicator, active):
    if active[0]:
        current_color = indicator.cget("bg")
        new_color = "red" if current_color == "white" else "white"
        indicator.config(bg=new_color)
        root.after(500, blink_indicator, indicator, active)

def run_test(command, stop_event):
    global global_sudo_password
    if stop_event.is_set():
        return None, "Test stopped by user."
    if "sudo" in command and os.geteuid() != 0:
        command = f"echo '{global_sudo_password}' | sudo -S {command.replace('sudo ', '')}"
    try:
        proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=1300)
        output = proc.stdout
        error = proc.stderr
        if error:
            output += f"\nError: {error}"
        return output, None
    except subprocess.TimeoutExpired:
        return None, "Test timed out."
    except Exception as e:
        return None, f"Test failed: {str(e)}"

def save_results_to_json(results):
    with open("results.json", "w") as f:
        json.dump(results, f, indent=4)

def run_tests_without_ai(commands, output_widget, indicator, stop_event, tests_pending_label, tests_done_label, cdn_indicator):
    total_tests = len(commands)
    tests_done = 0
    output_widget.insert(tk.END, f"Total tests: {total_tests}\n")
    active = [True]
    results = []
    progress_bar["maximum"] = total_tests

    def run():
        nonlocal tests_done
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_command = {executor.submit(run_test, command, stop_event): command for command in commands}
            for future in as_completed(future_to_command):
                if stop_event.is_set():
                    output_widget.insert(tk.END, "Tests stopped by user.\n")
                    break
                command = future_to_command[future]
                try:
                    output, error = future.result()
                    if error:
                        filtered_output = f"Error encountered:\n{error}"
                    else:
                        cmd_name = get_command_name(command)
                        filter_func = filters.get(cmd_name, general_filter)
                        filtered_output = filter_func(output)

                    if output and check_cdn_filter(output):
                        cdn_indicator.config(bg="red")
                    else:
                        cdn_indicator.config(bg="green")

                    completion_msg = (
                        f"Test {tests_done + 1} of {total_tests} completed: {command}\n"
                        f"Result:\n{filtered_output}\n"
                        f"{'-'*40}\n"
                    )
                    output_widget.insert(tk.END, completion_msg, "normal")
                    if "error" in completion_msg.lower() or "failed" in completion_msg.lower():
                        output_widget.tag_add("error", "end-2l", "end-1l")
                        output_widget.tag_config("error", foreground="red")

                    results.append({
                        "command": command,
                        "output": filtered_output,
                        "error": error
                    })

                    tests_done += 1
                    tests_pending_label.config(text=f"Tests pending: {total_tests - tests_done}")
                    tests_done_label.config(text=f"Tests completed: {tests_done}")
                    progress_bar["value"] = tests_done
                except Exception as e:
                    error_msg = f"Error in test {command}: {str(e)}\n"
                    output_widget.insert(tk.END, error_msg, "error")

        active[0] = False
        indicator.config(bg="white")
        start_button.config(text="Start Tests", bg="gray", state="normal")
        no_ai_button.config(state="normal")
        analyze_button.config(state="normal")
        final_msg = "All tests completed without AI! Results saved in results.json.\n" if not stop_event.is_set() else "Tests stopped.\n"
        output_widget.insert(tk.END, final_msg)
        save_results_to_json(results)

    threading.Thread(target=run).start()
    blink_indicator(indicator, active)

def run_tests_with_ai(commands, output_widget, indicator, stop_event, tests_pending_label, tests_done_label, cdn_indicator):
    total_tests = len(commands)
    tests_done = 0
    output_widget.insert(tk.END, f"Total tests: {total_tests}\n")
    active = [True]
    results = []
    progress_bar["maximum"] = total_tests

    if not check_api_status():
        output_widget.insert(tk.END, "Warning: DeepSeek API unavailable, using default test suggestions.\n")

    def run():
        nonlocal tests_done
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_command = {executor.submit(run_test, command, stop_event): command for command in commands}
            for future in as_completed(future_to_command):
                if stop_event.is_set():
                    output_widget.insert(tk.END, "Tests stopped by user.\n")
                    break
                command = future_to_command[future]
                try:
                    output, error = future.result()
                    if error:
                        filtered_output = f"Error encountered:\n{error}"
                    else:
                        cmd_name = get_command_name(command)
                        filter_func = filters.get(cmd_name, general_filter)
                        filtered_output = filter_func(output)

                    input_data = f"Domain/rules: {test_entry.get('1.0', tk.END).strip()}\nOutput: {filtered_output}"
                    deepseek_analysis = analyze_test_output(filtered_output)
                    next_test = suggest_next_test(input_data)

                    if output and check_cdn_filter(output):
                        cdn_indicator.config(bg="red")
                    else:
                        cdn_indicator.config(bg="green")

                    completion_msg = (
                        f"Test {tests_done + 1} of {total_tests} completed: {command}\n"
                        f"Result:\n{filtered_output}\n"
                        f"DeepSeek Analysis:\n{deepseek_analysis}\n"
                        f"Next Suggested Tests:\n{next_test}\n"
                        f"{'-'*40}\n"
                    )
                    output_widget.insert(tk.END, completion_msg, "normal")
                    if "error" in completion_msg.lower() or "failed" in completion_msg.lower():
                        output_widget.tag_add("error", "end-2l", "end-1l")
                        output_widget.tag_config("error", foreground="red")

                    results.append({
                        "command": command,
                        "output": filtered_output,
                        "deepseek_analysis": deepseek_analysis,
                        "next_test": next_test,
                        "error": error
                    })

                    tests_done += 1
                    tests_pending_label.config(text=f"Tests pending: {total_tests - tests_done}")
                    tests_done_label.config(text=f"Tests completed: {tests_done}")
                    progress_bar["value"] = tests_done
                except Exception as e:
                    error_msg = f"Error in test {command}: {str(e)}\n"
                    output_widget.insert(tk.END, error_msg, "error")

        active[0] = False
        indicator.config(bg="white")
        start_button.config(text="Start Tests", bg="gray", state="normal")
        no_ai_button.config(state="normal")
        analyze_button.config(state="normal")
        final_msg = "All tests completed! Results saved in results.json.\n" if not stop_event.is_set() else "Tests stopped.\n"
        output_widget.insert(tk.END, final_msg)
        save_results_to_json(results)

    threading.Thread(target=run).start()
    blink_indicator(indicator, active)

def analyze_previous_results():
    current_results = output_text.get("1.0", tk.END).strip()
    if not current_results:
        messagebox.showwarning("Warning", "No previous results to analyze.")
        return

    output_widget = output_text
    output_widget.delete("1.0", tk.END)
    output_widget.insert(tk.END, "Analyzing previous results with AI...\n")

    commands = []
    filtered_outputs = []
    for line in current_results.splitlines():
        line = line.strip()
        if line.startswith("Test ") and "completed: " in line:
            command = line.split("completed: ")[1]
            commands.append(command)
        elif line.startswith("Result:"):
            filtered_output = []
            for result_line in current_results.splitlines()[current_results.splitlines().index(line)+1:]:
                if result_line.startswith("---"):
                    break
                filtered_output.append(result_line)
            filtered_outputs.append("\n".join(filtered_output))

    total_tests = len(commands)
    progress_bar["maximum"] = total_tests
    tests_done = 0
    results = []

    for command, filtered_output in zip(commands, filtered_outputs):
        input_data = f"Domain/rules: {test_entry.get('1.0', tk.END).strip()}\nOutput: {filtered_output}"
        deepseek_analysis = analyze_test_output(filtered_output)
        next_test = suggest_next_test(input_data)

        completion_msg = (
            f"Test {tests_done + 1} of {total_tests} analyzed: {command}\n"
            f"Result:\n{filtered_output}\n"
            f"DeepSeek Analysis:\n{deepseek_analysis}\n"
            f"Next Suggested Tests:\n{next_test}\n"
            f"{'-'*40}\n"
        )
        output_widget.insert(tk.END, completion_msg, "normal")
        if "error" in completion_msg.lower() or "failed" in completion_msg.lower():
            output_widget.tag_add("error", "end-2l", "end-1l")
            output_widget.tag_config("error", foreground="red")

        results.append({
            "command": command,
            "output": filtered_output,
            "deepseek_analysis": deepseek_analysis,
            "next_test": next_test,
            "error": None
        })

        tests_done += 1
        tests_pending_label.config(text=f"Tests pending: {total_tests - tests_done}")
        tests_done_label.config(text=f"Tests completed: {tests_done}")
        progress_bar["value"] = tests_done

    output_widget.insert(tk.END, "AI analysis completed! Results saved in results.json.\n")
    save_results_to_json(results)
    analyze_button.config(state="normal")

def check_cdn_filter(output):
    cdn_indicators = ["403 Forbidden", "429 Too Many Requests", "503 Service Unavailable", "Cloudflare", "Access Denied", "Captcha", "blocked", "cf-ray"]
    return any(indicator.lower() in output.lower() for indicator in cdn_indicators)

def start_tests():
    global stop_event
    stop_event = threading.Event()
    commands = test_entry.get("1.0", tk.END).strip().splitlines()
    if not commands:
        messagebox.showwarning("Warning", "Please enter domain/rules or tests.")
        return
    if not check_internet_with_retry():
        messagebox.showwarning("Warning", "No internet connection detected.")
        internet_indicator.config(bg="red")
        return
    if global_sudo_password is None:
        messagebox.showwarning("Warning", "Sudo password not provided.")
        return

    start_button.config(text="Testing...", state="disabled")
    no_ai_button.config(state="disabled")
    analyze_button.config(state="disabled")
    internet_indicator.config(bg="green")
    ip_label.config(text=f"Current IP: {get_ip()}")
    output_text.delete("1.0", tk.END)
    run_tests_with_ai(commands, output_text, indicator, stop_event, tests_pending_label, tests_done_label, cdn_indicator)

def start_tests_without_ai():
    global stop_event
    stop_event = threading.Event()
    commands = test_entry.get("1.0", tk.END).strip().splitlines()
    if not commands:
        messagebox.showwarning("Warning", "Please enter domain/rules or tests.")
        return
    if not check_internet_with_retry():
        messagebox.showwarning("Warning", "No internet connection detected.")
        internet_indicator.config(bg="red")
        return
    if global_sudo_password is None:
        messagebox.showwarning("Warning", "Sudo password not provided.")
        return

    no_ai_button.config(text="Testing...", state="disabled")
    start_button.config(state="disabled")
    analyze_button.config(state="disabled")
    internet_indicator.config(bg="green")
    ip_label.config(text=f"Current IP: {get_ip()}")
    output_text.delete("1.0", tk.END)
    run_tests_without_ai(commands, output_text, indicator, stop_event, tests_pending_label, tests_done_label, cdn_indicator)

def stop_tests():
    global stop_event
    stop_event.set()

def copy_results():
    output_content = output_text.get("1.0", tk.END).strip()
    root.clipboard_clear()
    root.clipboard_append(output_content)
    messagebox.showinfo("Success", "Results copied to clipboard!")

def paste_clipboard():
    try:
        clipboard_content = root.clipboard_get()
        test_entry.delete("1.0", tk.END)
        test_entry.insert(tk.END, clipboard_content)
    except tk.TclError:
        messagebox.showwarning("Warning", "Clipboard is empty or contains non-text data.")

def add_suggested_tests():
    current_results = output_text.get("1.0", tk.END).strip()
    suggested_tests = []
    capture = False
    
    valid_commands = ["curl", "nmap", "nikto", "dirb", "gobuster", "sqlmap", "whatweb", "nuclei", "testssl", "sublist3r", "wpscan", "dnsenum", "ping", "traceroute", "openssl"]
    
    for line in current_results.splitlines():
        line = line.strip()
        if line.startswith("Next Suggested Tests:"):
            capture = True
            continue
        if capture and line.startswith("---"):
            capture = False
            continue
        if capture and line and not any(x in line for x in ["failed", "Analysis", "Error", "Result", "Test ", "Total tests"]):
            if not line.startswith(" ") and not line.startswith("*") and not line.isspace():
                if any(line.startswith(cmd) for cmd in valid_commands):
                    suggested_tests.append(line)
    
    if suggested_tests:
        test_entry.delete("1.0", tk.END)
        test_entry.insert(tk.END, "\n".join(suggested_tests))
    else:
        messagebox.showwarning("Warning", "No valid suggested tests found in results.")

def edit_prompt():
    global current_prompt
    prompt_window = tk.Toplevel(root)
    prompt_window.title("Edit Prompt")
    prompt_window.geometry("600x400")

    tk.Label(prompt_window, text="Edit the DeepSeek Prompt:").pack(pady=5)
    prompt_text = scrolledtext.ScrolledText(prompt_window, height=15, width=70)
    prompt_text.insert(tk.END, current_prompt)
    prompt_text.pack(pady=5)

    tk.Label(prompt_window, text="Prompt Name:").pack(pady=5)
    name_entry = tk.Entry(prompt_window, width=30)
    name_entry.pack(pady=5)
    name_entry.insert(0, "Custom Prompt")

    def save_prompt():
        global current_prompt
        current_prompt = prompt_text.get("1.0", tk.END).strip()
        prompt_name = name_entry.get().strip() or "Custom Prompt"
        save_prompt_to_file(prompt_name, current_prompt)
        prompt_window.destroy()
        messagebox.showinfo("Success", f"Prompt '{prompt_name}' saved and updated successfully!")

    save_button = tk.Button(prompt_window, text="Save Changes", command=save_prompt)
    save_button.pack(pady=5)

# New functions for the requested feature
def load_and_replace_commands():
    link = link_entry.get().strip()
    if not link:
        messagebox.showwarning("Warning", "Please enter a link.")
        return

    try:
        with open("commands.txt", "r") as file:
            commands = file.readlines()
        commands = [cmd.strip() for cmd in commands if cmd.strip()]
        if not commands:
            messagebox.showwarning("Warning", "No commands found in commands.txt.")
            return

        # Replace example.com with the user-provided link
        replaced_commands = [cmd.replace("example.com", link) for cmd in commands]
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, "\n".join(replaced_commands))
    except FileNotFoundError:
        messagebox.showerror("Error", "commands.txt not found.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load commands: {str(e)}")

def edit_commands_file():
    try:
        # Open commands.txt in the default text editor
        subprocess.run(["xdg-open", "commands.txt"])
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open commands.txt: {str(e)}")

# GUI setup
root = tk.Tk()
root.title("AriyaBot - Kali Security Bot")

# Request sudo password
global_sudo_password = simpledialog.askstring("Sudo Password", "Enter your sudo password (required for sudo commands):", show="*")
if global_sudo_password is None:
    messagebox.showwarning("Warning", "Sudo password is required to proceed. Exiting.")
    root.destroy()
    exit()

# Check dependencies before starting GUI
if not check_dependencies(global_sudo_password):
    messagebox.showerror("Error", "Bot startup aborted due to dependency issues.")
    root.destroy()
    exit()

# Select prompt at startup
select_prompt()

# New link input field
tk.Label(root, text="Enter Link (e.g., http://checksw.com):").pack()
link_entry = Entry(root, width=50)
link_entry.pack()

# New buttons for loading and editing commands
command_button_frame = tk.Frame(root)
command_button_frame.pack()
load_commands_button = tk.Button(command_button_frame, text="Load Commands", command=load_and_replace_commands)
load_commands_button.pack(side=tk.LEFT)
edit_commands_button = tk.Button(command_button_frame, text="Edit Commands File", command=edit_commands_file)
edit_commands_button.pack(side=tk.LEFT)

# New RESULT field for replaced commands
tk.Label(root, text="RESULT (Modified Commands):").pack()
result_text = scrolledtext.ScrolledText(root, height=5)
result_text.pack(fill=tk.BOTH, expand=True)

# Original test input field
tk.Label(root, text="Domain/Rules/Tests (one per line):").pack()
test_entry = scrolledtext.ScrolledText(root, height=10)
test_entry.pack()

# Original buttons
button_frame = tk.Frame(root)
button_frame.pack()
start_button = tk.Button(button_frame, text="Start Tests (AI)", command=start_tests, bg="gray")
start_button.pack(side=tk.LEFT)
no_ai_button = tk.Button(button_frame, text="Run Tests Without AI", command=start_tests_without_ai, bg="gray")
no_ai_button.pack(side=tk.LEFT)
analyze_button = tk.Button(button_frame, text="Analyze with AI", command=analyze_previous_results, bg="gray")
analyze_button.pack(side=tk.LEFT)
stop_button = tk.Button(button_frame, text="Stop Tests", command=stop_tests)
stop_button.pack(side=tk.LEFT)
copy_button = tk.Button(button_frame, text="Copy Results", command=copy_results)
copy_button.pack(side=tk.LEFT)
paste_button = tk.Button(button_frame, text="Paste Clipboard", command=paste_clipboard)
paste_button.pack(side=tk.LEFT)
add_button = tk.Button(button_frame, text="Add Suggested Tests", command=add_suggested_tests)
add_button.pack(side=tk.LEFT)
prompt_button = tk.Button(button_frame, text="Edit Prompt", command=edit_prompt)
prompt_button.pack(side=tk.LEFT)

indicator = tk.Label(button_frame, text="", bg="white", width=2, height=1)
indicator.pack(side=tk.LEFT, padx=5)
internet_indicator = tk.Label(button_frame, text="Internet", bg="red")
internet_indicator.pack(side=tk.LEFT, padx=5)
cdn_indicator = tk.Label(button_frame, text="CDN Filter", bg="green")
cdn_indicator.pack(side=tk.LEFT, padx=5)

progress_bar = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
progress_bar.pack()

status_frame = tk.Frame(root)
status_frame.pack()
ip_label = tk.Label(status_frame, text="Current IP: Unknown")
ip_label.pack(side=tk.LEFT, padx=5)
tests_pending_label = tk.Label(status_frame, text="Tests pending: 0")
tests_pending_label.pack(side=tk.LEFT, padx=5)
tests_done_label = tk.Label(status_frame, text="Tests completed: 0")
tests_done_label.pack(side=tk.LEFT, padx=5)

tk.Label(root, text="Results:").pack()
output_text = scrolledtext.ScrolledText(root, height=10)
output_text.pack(fill=tk.BOTH, expand=True)

root.mainloop()