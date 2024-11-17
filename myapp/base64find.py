import requests
from bs4 import BeautifulSoup
import base64
import re

def is_base64_encoded(data):
    try:
        if isinstance(data, str):
            if len(data) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', data):
                # Attempt to decode the base64 string
                base64.b64decode(data, validate=True)
                return True
        return False
    except Exception:
        return False

def decode_base64(data):
    try:
        decoded_bytes = base64.b64decode(data)
        return decoded_bytes.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"Error decoding base64: {e}")
        return None

def find_and_decode_base64_in_source(url):
    decoded_results = []
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        page_content = soup.get_text()
        
        potential_base64_strings = re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', page_content)
        
        for encoded_str in potential_base64_strings:
            if is_base64_encoded(encoded_str):
                decoded_str = decode_base64(encoded_str)
                if decoded_str:
                    decoded_results.append((encoded_str, decoded_str))
        
        if not decoded_results:
            print(f"No Base64 encoded strings found in {url}")
        
    except requests.RequestException as e:
        print(f"Failed to retrieve the webpage at {url}: {e}")
        
    return decoded_results

