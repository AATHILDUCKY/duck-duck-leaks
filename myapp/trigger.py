# trigger.py
from django.db.models import Q
from myapp.models import GoogleLink, DirectoryEnumeration, Linkscrap, SitemapURL

def trigger_search(keywords):
    keywords = [keyword.strip() for keyword in keywords.split(',')]

    google_links_q = Q()
    for keyword in keywords:
        google_links_q |= Q(query__icontains=keyword) | Q(link__icontains=keyword)
    google_links_results = GoogleLink.objects.filter(google_links_q)

    directory_enum_q = Q()
    for keyword in keywords:
        directory_enum_q |= Q(domain__icontains=keyword) | Q(directory__icontains=keyword)
    directory_enum_results = DirectoryEnumeration.objects.filter(directory_enum_q)

    linkscrap_q = Q()
    for keyword in keywords:
        linkscrap_q |= Q(link__icontains=keyword)
    linkscrap_results = Linkscrap.objects.filter(linkscrap_q)

    sitemap_url_q = Q()
    for keyword in keywords:
        sitemap_url_q |= Q(url__icontains=keyword)
    sitemap_url_results = SitemapURL.objects.filter(sitemap_url_q)

    return {
        'google_links': google_links_results,
        'directory_enumerations': directory_enum_results,
        'linkscraps': linkscrap_results,
        'sitemap_urls': sitemap_url_results,
    }
