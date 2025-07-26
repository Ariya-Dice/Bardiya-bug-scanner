import subprocess
import importlib
import os
import sys

TOOLS_DIR = os.path.expanduser("~/tools")

APT_TOOLS = [
    "nmap", "curl", "whatweb", "sqlmap", "dirb", "metasploit-framework",
    "dnsenum", "nikto", "wpscan", "ping", "traceroute", "openssl",
    "theharvester", "shodan", "recon-ng"
]

GITHUB_TOOLS = {
    "nuclei": "https://github.com/projectdiscovery/nuclei.git",
    "testssl.sh": "https://github.com/drwetter/testssl.sh.git",
    "sublist3r": "https://github.com/aboul3la/Sublist3r.git"
}

EXTERNAL_TOOLS = {
    "Maltego": "https://www.maltego.com/downloads/"
}

PYTHON_LIBS = ["openai", "tkinter", "python-dotenv"]

def check_system_tools():
    missing = []
    for tool in APT_TOOLS:
        result = subprocess.run(f"command -v {tool}", shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            missing.append(tool)
    
    for name in GITHUB_TOOLS.keys():
        path = os.path.join(TOOLS_DIR, name)
        if not os.path.exists(path):
            missing.append(name)

    for tool in EXTERNAL_TOOLS.keys():
        result = subprocess.run(f"command -v {tool}", shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            if tool not in missing:
                missing.append(tool)
    
    return missing

def check_python_libs():
    missing = []
    for lib in PYTHON_LIBS:
        try:
            importlib.import_module(lib if lib != "python-dotenv" else "dotenv")
        except ImportError:
            missing.append(lib)
    return missing

def install_with_apt(sudo_password, tools):
    if not tools:
        print("[+] No APT tools to install.", file=sys.stderr)
        return True, "No apt tools missing."
    
    print(f"[+] Installing APT tools: {', '.join(tools)}", file=sys.stderr)
    # Add retry for apt update in case of 403 or signature error
    # This is just an extra attempt and doesn't solve core server/network issues
    apt_update_cmd = f"echo '{sudo_password}' | sudo -S apt update"
    update_result = subprocess.run(apt_update_cmd, shell=True, capture_output=True, text=True)
    if update_result.returncode != 0:
        return False, f"Error updating APT (sudo apt update): {update_result.stderr.strip()}"

    cmd = f"echo '{sudo_password}' | sudo -S apt install -y {' '.join(tools)}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.returncode != 0:
        return False, f"Error installing APT tools: {result.stderr.strip()}"
    return True, "APT tools installed successfully."

def install_python_libs(libs):
    if not libs:
        print("[+] No Python libraries to install.", file=sys.stderr)
        return True, "No Python libraries missing."

    print(f"[+] Installing Python libraries: {', '.join(libs)}", file=sys.stderr)
    all_successful = True
    errors = []
    for lib in libs:
        result = subprocess.run(f"pip install {lib}", shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            all_successful = False
            errors.append(f"Error installing Python library {lib}: {result.stderr.strip()}")
            print(f"[WARN] Failed to install Python library: {lib}. Error: {result.stderr.strip()}", file=sys.stderr)
        else:
            print(f"    [+] {lib} installed successfully.", file=sys.stderr)
    
    if not all_successful:
        return False, "Some Python libraries failed to install: " + "\n".join(errors)
    return True, "Python libraries installed successfully."

def install_github_tools():
    os.makedirs(TOOLS_DIR, exist_ok=True)
    installed = []
    
    print("[+] Checking and installing GitHub tools...", file=sys.stderr)
    all_successful = True
    errors = []
    for name, repo in GITHUB_TOOLS.items():
        path = os.path.join(TOOLS_DIR, name)
        if not os.path.exists(path):
            print(f"    [+] Cloning {name} from {repo} to {path}", file=sys.stderr)
            result = subprocess.run(f"git clone {repo} {path}", shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                all_successful = False
                errors.append(f"Error cloning {repo} for {name}: {result.stderr.strip()}")
                print(f"[WARN] Failed to clone {name}. Error: {result.stderr.strip()}", file=sys.stderr)
            else:
                installed.append(name)
        else:
            print(f"    [+] {name} already exists: {path}", file=sys.stderr)

    if not all_successful:
        return False, "Some GitHub tools failed to install: " + "\n".join(errors)
    if not installed:
        return True, "No new GitHub tools to install."
    return True, f"GitHub tools installed or updated: {', '.join(installed)}"

def show_manual_tools(tools):
    if not tools:
        return ""
    message = "\n[!] The following tools need to be installed manually:\n"
    for tool in tools:
        if tool in EXTERNAL_TOOLS:
            message += f"- {tool}: {EXTERNAL_TOOLS[tool]}\n"
    return message

def full_installation(sudo_password):
    """
    Responsible for checking and installing all dependencies.
    In case of an error, it only displays a warning and continues.
    """
    overall_status = True
    overall_messages = []

    print("--- Starting dependency check and installation ---", file=sys.stderr)

    missing_tools = check_system_tools()
    missing_libs = check_python_libs()

    apt_missing = [t for t in missing_tools if t in APT_TOOLS]
    github_missing = [t for t in missing_tools if t in GITHUB_TOOLS]
    external_missing = [t for t in missing_tools if t in EXTERNAL_TOOLS]

    # Install APT tools
    ok, msg = install_with_apt(sudo_password, apt_missing)
    if not ok:  
        print(f"❌ [WARN] APT installation error: {msg}. Continuing...", file=sys.stderr)
        overall_status = False
        overall_messages.append(f"APT Install Warning: {msg}")
    else:
        print(f"✅ {msg}", file=sys.stderr)

    # Install Python libraries
    ok, msg = install_python_libs(missing_libs)
    if not ok:  
        print(f"❌ [WARN] Python library installation error: {msg}. Continuing...", file=sys.stderr)
        overall_status = False
        overall_messages.append(f"Python Libs Install Warning: {msg}")
    else:
        print(f"✅ {msg}", file=sys.stderr)

    # Install GitHub tools
    ok, msg = install_github_tools()
    if not ok:  
        print(f"❌ [WARN] GitHub tool installation error: {msg}. Continuing...", file=sys.stderr)
        overall_status = False
        overall_messages.append(f"GitHub Tools Install Warning: {msg}")
    else:
        print(f"✅ {msg}", file=sys.stderr)

    # Show manual tools
    manual_msg = show_manual_tools(external_missing)
    if manual_msg:
        print(manual_msg, file=sys.stderr)
        overall_messages.append(f"Manual Tools: {manual_msg.strip()}")

    print("--- Finished dependency check and installation ---", file=sys.stderr)
    
    if overall_status:
        return True, "✅ All installable dependencies managed successfully."
    else:
        final_message = "⚠️ Some dependencies encountered warnings/errors. Some features might not work.\n"
        final_message += "\n".join(overall_messages)
        return True, final_message # Still return True to allow the main program to run