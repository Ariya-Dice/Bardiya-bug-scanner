def filter_nmap(output):
    """Filters nmap output for open ports and services."""
    lines = output.splitlines()
    filtered_lines = []
    for line in lines:
        if ("open" in line and "/" in line and "tcp" in line) or \
           ("Nmap scan report for" in line) or \
           ("Host is up" in line):
            filtered_lines.append(line.strip())
    return "\n".join(filtered_lines) if filtered_lines else "No open ports or services found by Nmap."

def filter_curl(output):
    """Filters curl output to display main content and HTTP status codes."""
    lines = output.splitlines()
    body = []
    headers = []
    in_body = False
    
    for line in lines:
        if line.startswith("HTTP/"): # Headers
            headers.append(line.strip())
        elif line.strip() == "": # Empty line separating headers from body
            in_body = True
        elif in_body:
            body.append(line.strip())
    
    if body:
        return f"Headers: {', '.join(headers)}\nBody:\n{'\n'.join(body)}"
    elif headers:
        return f"Headers: {', '.join(headers)}\nNo body content received."
    else:
        return "No meaningful output received from curl."

def filter_openssl(output):
    """Filters openssl output for SSL/TLS certificate information."""
    lines = output.splitlines()
    filtered_lines = []
    for line in lines:
        if "issuer" in line or "subject" in line or "start date" in line or \
           "expire date" in line or "public key" in line or "cipher" in line or \
           "protocol" in line or "handshake failure" in line:
            filtered_lines.append(line.strip())
    return "\n".join(filtered_lines) if filtered_lines else "No significant SSL/TLS information found."

def filter_dirb_gobuster(output):
    """Filters dirb or gobuster output for discovered paths."""
    lines = output.splitlines()
    found_paths = []
    for line in lines:
        # For dirb
        if "+ " in line and "(CODE:" in line:
            found_paths.append(line.strip())
        # For gobuster
        elif line.startswith("/") and "Status:" in line: # More precise for gobuster lines
            found_paths.append(line.strip())
    return "\n".join(found_paths) if found_paths else "No directories or files found."

def filter_sqlmap(output):
    """Filters sqlmap output for found databases, tables, and columns."""
    lines = output.splitlines()
    filtered_lines = []
    for line in lines:
        if "[+]" in line and ("database" in line or "table" in line or "column" in line or "dumped" in line):
            filtered_lines.append(line.strip())
    return "\n".join(filtered_lines) if filtered_lines else "No databases, tables, or columns found by sqlmap."

def filter_testssl(output):
    """Filters testssl.sh output for SSL/TLS vulnerabilities and important configurations."""
    lines = output.splitlines()
    filtered_lines = []
    for line in lines:
        if "vulnerable" in line.lower() or "not offered" in line.lower() or "weak" in line.lower() or \
           "protocol" in line.lower() or "cipher" in line.lower() or "chain" in line.lower() or \
           "heartbleed" in line.lower() or "freak" in line.lower() or "poodle" in line.lower() or \
           "ccs injection" in line.lower() or "rc4" in line.lower() or "preferred" in line.lower():
            filtered_lines.append(line.strip())
    return "\n".join(filtered_lines) if filtered_lines else "No critical SSL/TLS vulnerabilities found."

def filter_sslyze(output):
    """Filters sslyze output for SSL/TLS vulnerabilities and important configurations."""
    lines = output.splitlines()
    filtered_lines = []
    for line in lines:
        if "SUCCESS" not in line and "Scan results for" not in line and "TLS" in line and \
           ("ERROR" in line or "VULNERABLE" in line or "WARNING" in line or "NOT RECOMMENDED" in line or "deficiency" in line.lower()):
            filtered_lines.append(line.strip())
        elif "TLS" in line and ("Protocol" in line or "Cipher Suite" in line): # Protocol and Cipher details
            filtered_lines.append(line.strip())
    return "\n".join(filtered_lines) if filtered_lines else "No significant SSL/TLS findings from SSLyze."

def filter_maltego(output):
    """Filters Maltego output for discovered entities."""
    lines = output.splitlines()
    entities = [line for line in lines if "Entity:" in line]
    return "\n".join(entities) if entities else "No entities found by Maltego."

def filter_theharvester(output):
    """Filters The Harvester output for discovered emails."""
    lines = output.splitlines()
    # Remove header lines like "E-mail addresses found:"
    emails = [line for line in lines if "@" in line and not line.strip().lower().startswith("e-mail")]
    return "\n".join(emails) if emails else "No emails found by The Harvester."

def filter_shodan(output):
    """Filters Shodan output for key information."""
    lines = output.splitlines()
    # Include key information like IP, Port, Organization, Product
    results = [line for line in lines if "IP:" in line or "Port:" in line or "Organization:" in line or "Product:" in line or "Vulnerability:" in line]
    return "\n".join(results) if results else "No significant results found by Shodan."

def filter_recon_ng(output):
    """Filters Recon-ng output for discovered data."""
    lines = output.splitlines()
    # Recon-ng has various outputs; this filter looks for lines containing "FOUND" or IP/Host/Domain information.
    data = [line for line in lines if "FOUND" in line or "Host:" in line or "IP:" in line or "Domain:" in line or "Vulnerability Found" in line]
    return "\n".join(data) if data else "No data found by recon-ng."

def filter_google_dorks(output):
    """Filters Google Dorks output for URLs."""
    lines = output.splitlines()
    # Assumes Google Dorks output includes URLs.
    # Filter for clean URLs that contain "http" and "://" and no spaces (to avoid fragmented lines).
    urls = [line for line in lines if "http" in line and "://" in line and " " not in line]
    return "\n".join(urls) if urls else "No URLs found from Google Dorks."

def filter_wafw00f(output):
    """Filters wafw00f output for WAF identification."""
    lines = output.splitlines()
    filtered_lines = [line for line in lines if "WAF/CDN" in line or "is behind" in line or "No WAF detected" in line or "detected" in line.lower()]
    return "\n".join(filtered_lines) if filtered_lines else "WAF status could not be determined."

def filter_hydra(output):
    """Filters hydra output for successful login credentials."""
    lines = output.splitlines()
    credentials = [line for line in lines if "login:" in line and "password:" in line]
    return "\n".join(credentials) if credentials else "No successful logins found by Hydra."

def filter_assetfinder(output):
    """Filters assetfinder output for subdomains."""
    lines = output.splitlines()
    # Assetfinder typically only returns subdomains, so most lines are relevant.
    return "\n".join([line.strip() for line in lines if line.strip()]) if lines else "No subdomains found by Assetfinder."

# Add more specific filters for grep, find, netstat, ss, journalctl, cat log files if needed.
# For these, raw output is often useful, so a simple filter might just return the entire output
# or search for specific keywords if you know what you're looking for.