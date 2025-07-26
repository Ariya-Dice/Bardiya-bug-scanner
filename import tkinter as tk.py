import subprocess

def run_curl(url):
    return subprocess.run(f"curl -s {url}", shell=True, capture_output=True, text=True)

def run_dirb(url):
    return subprocess.run(f"dirb {url}", shell=True, capture_output=True, text=True)

def run_openssl(target):
    return subprocess.run(f"openssl s_client -connect {target}:443", shell=True, capture_output=True, text=True)

def run_testssl(target):
    return subprocess.run(f"testssl.sh {target}", shell=True, capture_output=True, text=True)

def run_google_dorks(query):
    return subprocess.run(f"python google_dorks.py '{query}'", shell=True, capture_output=True, text=True)