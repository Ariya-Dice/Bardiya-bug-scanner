import subprocess

def run_sublist3r(domain):
    return subprocess.run(f"sublist3r -d {domain}", shell=True, capture_output=True, text=True)

def run_dnsenum(domain):
    return subprocess.run(f"dnsenum {domain}", shell=True, capture_output=True, text=True)

def run_whatweb(url):
    return subprocess.run(f"whatweb {url}", shell=True, capture_output=True, text=True)

def run_maltego(config_file):
    return subprocess.run(f"maltego -c {config_file}", shell=True, capture_output=True, text=True)

def run_theharvester(domain):
    return subprocess.run(f"theharvester -d {domain} -b all", shell=True, capture_output=True, text=True)

def run_recon_ng(script):
    return subprocess.run(f"recon-ng -r {script}", shell=True, capture_output=True, text=True)