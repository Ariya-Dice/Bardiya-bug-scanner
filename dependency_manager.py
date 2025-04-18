import subprocess
import importlib

SYSTEM_TOOLS = [
    "nmap", "curl", "nuclei", "whatweb", "sqlmap", "dirb", "metasploit-framework",
    "dnsenum", "testssl.sh", "sublist3r", "nikto", "wpscan", "ping", "traceroute", "openssl",
    "Maltego", "theharvester", "shodan", "recon-ng"  # ابزارهای جدید
]
PYTHON_LIBS = ["openai", "tkinter", "python-dotenv"]

def check_system_tools():
    missing_tools = []
    for tool in SYSTEM_TOOLS:
        result = subprocess.run(f"command -v {tool}", shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            missing_tools.append(tool)
    return missing_tools

def check_python_libs():
    missing_libs = []
    for lib in PYTHON_LIBS:
        try:
            importlib.import_module(lib if lib != "python-dotenv" else "dotenv")
        except ImportError:
            missing_libs.append(lib)
    return missing_libs

def install_dependencies(sudo_password, missing_tools, missing_libs):
    if missing_tools:
        cmd = f"echo '{sudo_password}' | sudo -S apt-get install -y {' '.join(missing_tools)}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return False, result.stderr
    if missing_libs:
        for lib in missing_libs:
            cmd = f"pip install {lib}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                return False, result.stderr
    return True, "Dependencies installed successfully"