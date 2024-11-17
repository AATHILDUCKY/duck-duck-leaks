import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import concurrent.futures

# Set of visited URLs to avoid duplicate crawling
visited_urls = set()

# Function to find and process links and resources on a given page
def crawl(url, base_url):
    links = []
    resources = []
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Find all anchor tags and their href attributes
        for a_tag in soup.find_all("a", href=True):
            link = urljoin(url, a_tag["href"])
            # Process only internal links
            if is_internal_link(link, base_url):
                links.append(link)

        # Find resources like images, scripts, and stylesheets
        for tag in soup.find_all(["img", "script", "link"]):
            src = tag.get("src") or tag.get("href")
            if src:
                resource_url = urljoin(url, src)
                resources.append(resource_url)

    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
    
    return links, resources

# Helper function to check if a link is internal
def is_internal_link(url, base_url):
    return urlparse(url).netloc == urlparse(base_url).netloc

# Function to crawl the website and return all unique links
def crawl_website(base_url):
    visited_urls.clear()  # Reset visited URLs for each new crawl
    all_links = set()

    def _crawl_recursive(url):
        if url in visited_urls:
            return
        visited_urls.add(url)
        links, resources = crawl(url, base_url)
        all_links.update(links)

        # Crawl each link concurrently
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.map(_crawl_recursive, links)

    # Start crawling from the base URL
    _crawl_recursive(base_url)
    return list(all_links)  # Return all unique links as a list
