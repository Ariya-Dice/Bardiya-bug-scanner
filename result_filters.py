def filter_maltego(output):
    lines = output.splitlines()
    entities = [line for line in lines if "Entity:" in line]
    return "\n".join(entities) if entities else "No entities found"

def filter_theharvester(output):
    lines = output.splitlines()
    emails = [line for line in lines if "@" in line]
    return "\n".join(emails) if emails else "No emails found"

def filter_shodan(output):
    lines = output.splitlines()
    results = [line for line in lines if "IP:" in line]
    return "\n".join(results) if results else "No results found"

def filter_recon_ng(output):
    lines = output.splitlines()
    data = [line for line in lines if "FOUND" in line]
    return "\n".join(data) if data else "No data found"

def filter_google_dorks(output):
    lines = output.splitlines()
    urls = [line for line in lines if "http" in line]
    return "\n".join(urls) if urls else "No URLs found"

# فیلترهای موجود مانند filter_nmap, filter_curl و ... نیز به این ماژول منتقل می‌شوند