# sitemap_scan.py
from usp.tree import sitemap_tree_for_homepage

def fetch_sitemap_urls(base_url):
    """
    Fetches all URLs from the sitemap of the given base URL.
    """
    sitemap_urls = []

    try:
        # Fetch the sitemap tree from the base URL
        tree = sitemap_tree_for_homepage(base_url)
        for page in tree.all_pages():
            url = page.url
            sitemap_urls.append(url)
    except Exception as e:
        print(f"Error fetching sitemap for {base_url}: {e}")
    
    return sitemap_urls
