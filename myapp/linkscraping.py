# linkscraping.py
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

# Define file extensions to look for
file_extensions = [
    '.js', '.php', '.bak', '.config', '.html', '.json', '.xml', '.txt', '.env', '.config', '.yml',
    '.yaml', '.ini', '.log', '.backup', '.sql', '.inc', '.key', '.crt', '.pem', '.cert', '.csr',
    '.pfx', '.p12', '.ovpn', '.db', '.sqlite', '.sqlite3', '.md', '.pwd', '.passwd', '.htpasswd',
    '.htaccess', '.bash_history', '.ssh', '.ssh_config', '.pub', '.ppk', '.rdp', '.cfg', '.dat',
    '.old', '.properties', '.xls', '.xlsx', '.doc', '.docx', '.ppt', '.pptx', '.pdf', '.rdlc',
    '.pswd', '.jsp', '.aspx', '.asp', '.cfm', '.pl', '.cgi' , '.css'
]

# Regex pattern to detect URLs with specified extensions
file_pattern = re.compile(r'(\.(js|php|html|sql|xml|json|txt|config|yml|yaml|ini|bak|backup|log|sql|inc|key|crt|pem|csr|pfx|db|sqlite|sqlite3|md|pwd|passwd|cfg|dat|xls|xlsx|doc|ppt|pdf|jsp|aspx|asp|cfm|pl|cgi)(\?.*)?)$')

def get_links(url):
    """Fetch all internal and resource links from the URL."""
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return [], []
        
        soup = BeautifulSoup(response.text, 'html.parser')
        links, resources = [], []

        for tag in soup.find_all(['a', 'link', 'script', 'img']):
            href = tag.get('href') or tag.get('src')
            if href:
                full_url = urljoin(url, href)
                if full_url.startswith(('http', 'https')):
                    if re.search(file_pattern, full_url):
                        resources.append(full_url)
                    else:
                        links.append(full_url)
        
        return list(set(links)), list(set(resources))
    
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return [], []

def recursive_crawl(url, visited, resources_found):
    """Recursively crawl and collect resources."""
    if url in visited:
        return
    visited.add(url)
    
    links, resources = get_links(url)
    resources_found.extend(resources)
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(recursive_crawl, link, visited, resources_found) for link in links]
        for future in futures:
            future.result()

def scan_multiple_urls(urls):
    """Scan multiple URLs and return all found resources."""
    all_resources = {}
    for url in urls:
        resources_found = []
        recursive_crawl(url, set(), resources_found)
        all_resources[url] = resources_found if resources_found else ["No resources found."]
    return all_resources
