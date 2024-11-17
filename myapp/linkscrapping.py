import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from .models import Linkscrap  # Import the modified Django model

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
}

file_extensions = ['.js', '.php', '.bak', '.config', '.html', '.json', '.xml', '.txt', '.env', '.config', '.yml', 
                    '.yaml', '.ini', '.log', '.backup', '.sql', '.inc', '.key', '.crt', '.pem', '.cert', '.csr', 
                    '.pfx', '.p12', '.ovpn', '.db', '.sqlite', '.sqlite3', '.md', '.pwd', '.passwd', '.htpasswd', 
                    '.htaccess', '.bash_history', '.ssh', '.ssh_config', '.pub', '.ppk', '.rdp', '.cfg', '.dat', 
                    '.old', '.properties', '.xls', '.xlsx', '.doc', '.docx', '.ppt', '.pptx', '.pdf', '.rdlc', 
                    '.pswd', '.jsp', '.aspx', '.asp', '.cfm', '.pl', '.cgi']

def is_valid(url):
    return url.startswith('http') or url.startswith('https')

def find_all_links(base_url, visited, depth):
    urls = []  # Array to store unique URLs

    if depth == 0:
        return []

    try:
        response = requests.get(base_url, headers=headers, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')

            for tag in soup.find_all(['a', 'link', 'script', 'img']):
                link = tag.get('href') or tag.get('src')

                if link:
                    full_link = urljoin(base_url, link)
                    if is_valid(full_link) and full_link not in visited:
                        visited.add(full_link)
                        if any(full_link.endswith(ext) for ext in file_extensions):
                            urls.append(full_link)
                            Linkscrap.objects.get_or_create(link=full_link)

                            urls.extend(find_all_links(full_link, visited, depth - 1))

    except requests.RequestException:
        pass

    return urls
