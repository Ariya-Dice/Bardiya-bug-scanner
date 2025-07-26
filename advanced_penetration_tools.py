import subprocess

def run_metasploit(script):
    return subprocess.run(f"msfconsole -q -x '{script}'", shell=True, capture_output=True, text=True)