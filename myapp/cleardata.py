# cleardata.py
from .models import GoogleLink, Subdomain, DirectoryEnumeration, GitHubScan, SecretScan, Linkscrap, SitemapURL,GitDataLeak

def clear_data():
    GoogleLink.objects.all().delete()
    Subdomain.objects.all().delete()
    DirectoryEnumeration.objects.all().delete()
    GitHubScan.objects.all().delete()
    SecretScan.objects.all().delete()
    Linkscrap.objects.all().delete()
    SitemapURL.objects.all().delete()
    GitDataLeak.objects.all().delete()
