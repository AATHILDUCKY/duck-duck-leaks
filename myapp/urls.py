from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='home'),
    path('show-tables/', views.show_tables, name='show_tables'),
    path('google_search/', views.google_search, name='google_search'),
    path('subdomain/', views.subdomain, name='subdomain'),
    path('base64_multiple/', views.base64_multiple, name='base64_multiple'),
    path('scrape_links/', views.scrape_links, name='scrape_links'),
    path('directory_enumeration_view/', views.directory_enumeration_view, name='directory_enumeration_view'),
    path('scan_github_repository/', views.scan_github_repository, name='scan_github_repository'),
    path('scan_secrets/', views.scan_secrets, name='scan_secrets'),
    path('scrape_linksM/', views.scrape_linksM, name='scrape_linksM'),
    path('sitemap_scan_view/', views.sitemap_scan_view, name='sitemap_scan_view'),
    path('search_multiple_tables/', views.search_multiple_tables, name='search_multiple_tables'),
    path('clear_data_view/', views.clear_data_view, name='clear_data_view'),
    path('scan_links/', views.scan_links, name='scan_links'),
    path('scan_git_repo/', views.scan_git_repo, name='scan_git_repo'),
]