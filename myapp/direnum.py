import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

def check_url(full_url):
    """Send a GET request to the URL and return the URL if found."""
    try:
        response = requests.get(full_url, timeout=5)  # Set a timeout for the request
        if response.status_code == 200:
            print(f"Found: {full_url}")  # Print found URL
            return full_url
    except requests.RequestException as e:
        # Optionally log errors
        print(f"Request failed for {full_url}: {e}")
    return None

def web_directory_enumeration(url, wordlist, max_workers=10):
    """
    Performs fast web directory enumeration using multi-threading.
    
    Parameters:
        url (str): The target URL for enumeration (must include protocol, e.g., http://).
        wordlist (str): The path to the wordlist file containing directory names.
        max_workers (int): The maximum number of threads to use for requests.
    
    Returns:
        list: A list of found URLs that exist on the server.
    """
    found_urls = []
    
    # Load the wordlist from the specified file
    try:
        with open(wordlist, 'r') as file:
            paths = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Wordlist file '{wordlist}' not found.")
        return found_urls

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(check_url, urljoin(url, path)): path for path in paths}
        
        for future in as_completed(future_to_url):
            result = future.result()
            if result:
                found_urls.append(result)

    return found_urls