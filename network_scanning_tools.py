import subprocess

def run_nmap(target):
    return subprocess.run(f"nmap -T4 {target}", shell=True, capture_output=True, text=True)

def run_ping(target):
    return subprocess.run(f"ping -c 10 {target}", shell=True, capture_output=True, text=True)

def run_traceroute(target):
    return subprocess.run(f"traceroute {target}", shell=True, capture_output=True, text=True)

def run_shodan(query):
    return subprocess.run(f"shodan search {query}", shell=True, capture_output=True, text=True)