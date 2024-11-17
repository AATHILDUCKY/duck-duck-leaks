import requests
import sublist3r

def gather_subdomains(domain):
    # Gather subdomains using Sublist3r
    subdomains = sublist3r.main(domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    
    available_subdomains = []
    
    # Check each subdomain for availability
    for subdomain in subdomains:
        url_http = f"http://{subdomain}"
        url_https = f"https://{subdomain}"
        
        try:
            # Try HTTPS first
            response = requests.get(url_https, timeout=5)
            protocol = 'https'
            status_code = response.status_code
        except requests.RequestException:
            try:
                # Fallback to HTTP if HTTPS fails
                response = requests.get(url_http, timeout=5)
                protocol = 'http'
                status_code = response.status_code
            except requests.RequestException:
                # If both HTTP and HTTPS fail, skip the subdomain
                continue
        
        # Append as a tuple (subdomain, protocol, status_code)
        available_subdomains.append((subdomain, protocol, status_code))
    
    return available_subdomains
