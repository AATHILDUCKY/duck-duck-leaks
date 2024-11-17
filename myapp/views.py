from django.shortcuts import render
from django.http import HttpResponse
from django.template import loader
from .glsearch import find_google_link
from .subdom import gather_subdomains
from .base64find import find_and_decode_base64_in_source
from .direnum import web_directory_enumeration
from .secret import find_secrets
from .linkscrapping import find_all_links
from .sitemap_scan import fetch_sitemap_urls
from .trigger import trigger_search
from .cleardata import clear_data
from .linkscraping import recursive_crawl
from .git_secret import clone_and_scan_repo
from .forms import ScanForm, MultiInputSearchForm, DomainInputForm, GitHubScanForm, SecretScanForm,LinkScrapingForm,LinkScrapingFormM,SitemapScanForm,KeywordSearchForm,URLScanForm,GitRepoForm
from .models import GoogleLink, Subdomain,DirectoryEnumeration,GitHubScan, SecretScan, Linkscrap,SitemapURL,Link_Resource,GitDataLeak
from django.db import connection
import subprocess
import json
import requests

# Create your views here.
def index(request):
    template = loader.get_template('index.html')
    return HttpResponse(template.render())


def google_search(request):
    result = None
    google_links = []
    if request.method == 'POST':
        form = MultiInputSearchForm(request.POST)
        if form.is_valid():
            # Get the input data from the form and concatenate them to form the search query
            input1 = form.cleaned_data['input1']
            input2 = form.cleaned_data['input2']
            input3 = form.cleaned_data['input3']
            input4 = form.cleaned_data['input4']
            input5 = form.cleaned_data['input5']
            site_qry = f"{input1} {input2} {input3} {input4} {input5}".strip()

            # Get the list of Google links
            google_links = find_google_link(site_qry)

            # Store the links in the database
            for link in google_links:
                if not GoogleLink.objects.filter(link=link).exists():
                    GoogleLink.objects.create(query=site_qry, link=link)

            # Retrieve the links from the database
            result = GoogleLink.objects.filter(query=site_qry)
    else:
        form = MultiInputSearchForm()

    context = {
        'form': form,
        'google_links': result or google_links,
    }
    return render(request, 'google_search.html', context)


# ----------------------------------------------------------
# this section for showing data base
def show_tables(request):
    with connection.cursor() as cursor:
        # Execute a raw SQL query to get the table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()  # Fetch all results

    # Extract table names from the fetched data
    table_names = [table[0] for table in tables]

    selected_table = request.GET.get('table')
    search_query = request.GET.get('search')  # Get search query from the input
    table_data = None
    columns = []

    if selected_table:
        with connection.cursor() as cursor:
            # If a search query exists, modify the SQL to filter results
            if search_query:
                cursor.execute(f"SELECT * FROM {selected_table} WHERE {get_filter_condition(selected_table, search_query)};")
            else:
                cursor.execute(f"SELECT * FROM {selected_table};")  # Fetch all rows if no filter
            
            table_data = cursor.fetchall()
            columns = [col[0] for col in cursor.description]  # Get column names

    context = {
        'table_names': table_names,
        'table_data': table_data,
        'columns': columns,
        'selected_table': selected_table,
        'search_query': search_query,
    }
    return render(request, 'show_tables.html', context)


def get_filter_condition(table_name, query):
    # Define which column(s) to filter for each table (based on your table schema)
    # Adjust the WHERE clause depending on the structure of your table
    # For simplicity, we'll search across all columns

    # Dynamic filtering based on table and query. Adjust based on specific table structures.
    return f" OR ".join([f"{col} LIKE '%{query}%'" for col in get_column_names(table_name)])


def get_column_names(table_name):
    # A helper function to get column names dynamically from the selected table
    with connection.cursor() as cursor:
        cursor.execute(f"PRAGMA table_info({table_name});")
        columns = [col[1] for col in cursor.fetchall()]  # Column names are in the second field of each row
    return columns

# ----------------------------------------------------------

# ----------------------------------------------------------------
# this is for Subdomains
def subdomain(request):
    available_subdomains = None
    subdomain_list = []

    if request.method == 'POST':
        form1 = ScanForm(request.POST)

        if form1.is_valid():
            domain = form1.cleaned_data['domain']
            subdomain_list = gather_subdomains(domain)  # Get available subdomains

            # Store subdomains in the database and avoid duplicates using get_or_create
            for subs in subdomain_list:
                if not Subdomain.objects.filter(subdomains=subs[0]):
                    Subdomain.objects.get_or_create(domain_name=domain, subdomains=subs[0])

            subdomain_list = Subdomain.objects.filter(domain_name=domain)

    else:
        form1 = ScanForm()

    context = {
        'form1': form1,
        'subdomain_list':subdomain_list,
    }

    return render(request, 'subdomain.html', context)
# ----------------------------------------------------------

# ----------------------------------------------------------------
def base64_multiple(request):
    result = {}
    if request.method == 'POST':
        if 'domain_text' in request.POST:
            # Read textarea input and split by lines (assuming each line is a domain)
            domains = request.POST['domain_text'].splitlines()

            for domain in domains:
                # Call your custom function to process each domain
                encoded_decoded_pairs = find_and_decode_base64_in_source(domain)
                result[domain] = encoded_decoded_pairs

    return render(request, 'findbase64_mul.html', {'result': result})

# ------------------------------------------------------------------------
# ------------------------------------------------------------------------
def scrape_links(request):
    form = LinkScrapingForm(request.POST or None)
    scraped_links = []

    if request.method == 'POST' and form.is_valid():
        base_url = form.cleaned_data['base_url']
        visited_links = set()

        find_all_links(base_url, visited_links, depth=2)

        scraped_links = Linkscrap.objects.filter(link__startswith=base_url)

    context = {
        'form': form,
        'scraped_links': scraped_links,
    }
    return render(request, 'scrape_links.html', context)

# ------------------------------------------------------------------------
# ------------------------------------------------------------------------
def directory_enumeration_view(request):
    enumerated_directories = []
    
    if request.method == 'POST':
        form = DomainInputForm(request.POST)
        
        if form.is_valid():
            url = form.cleaned_data['domain']
            wordlist_path = "C:\\Users\\User\\Desktop\\duck-duck-leak\\duck_duck_leak\\myapp\\payloads\\common.txt"
            # Call the directory enumeration function
            enumerated_directories = web_directory_enumeration(url, wordlist_path, max_workers=20)

            # Store the found directories in the database
            for directory in enumerated_directories:
                if not DirectoryEnumeration.objects.filter(directory=directory).exists():
                    DirectoryEnumeration.objects.create(domain=url, directory=directory)
            
            # Retrieve the stored directories from the database
            enumerated_directories = DirectoryEnumeration.objects.filter(domain=url)
    else:
        form = DomainInputForm()

    context = {
        'form': form,
        'enumerated_directories': enumerated_directories,
    }
    
    return render(request, 'directory_enumeration.html', context)
# ------------------------------------------------------------------------
# ------------------------------------------------------------------------

def scan_github_repository(request):
    scan_results = None
    if request.method == 'POST':
        form = GitHubScanForm(request.POST)
        if form.is_valid():
            repository_url = form.cleaned_data['repository_url']
            
            # Run truffleHog command
            command = f"trufflehog git --json {repository_url}"
            try:
                # Execute the command
                result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
                
                # Parse the JSON output
                scan_results = json.loads(result.stdout)
                
                # Save the results to the database
                GitHubScan.objects.create(repository_url=repository_url, scan_results=scan_results)
            except subprocess.CalledProcessError as e:
                print(f"Error occurred while running truffleHog: {e}")
                scan_results = {"error": str(e)}
    else:
        form = GitHubScanForm()

    context = {
        'form': form,
        'scan_results': scan_results,
    }
    return render(request, 'gitscan.html', context)
# ------------------------------------------------------------------------
# ------------------------------------------------------------------------

def scan_secrets(request):
    scan_results = []
    
    if request.method == 'POST':
        form = SecretScanForm(request.POST)
        if form.is_valid():
            urls = form.cleaned_data['urls'].splitlines()

            for url in urls:
                try:
                    response = requests.get(url)
                    if response.status_code == 200:
                        # Scan the page content for secrets
                        secrets = find_secrets(response.text)
                        for secret_type, secret_values in secrets.items():
                            for value in secret_values:
                                if not SecretScan.objects.filter(secret_value=value).exists():
                                # Save the result to the database
                                    SecretScan.objects.create(
                                        url=url,
                                        secret_type=secret_type,
                                        secret_value=value
                                    )
                        scan_results.append({'url': url, 'secrets': secrets})
                    else:
                        scan_results.append({'url': url, 'error': 'Failed to retrieve content'})
                except requests.exceptions.RequestException as e:
                    scan_results.append({'url': url, 'error': str(e)})
    else:
        form = SecretScanForm()

    return render(request, 'secret.html', {'form': form, 'scan_results': scan_results})

# ----------------------------------------------------------------
# scrapping the multiple links
#-----------------------------------------------------------------


def scrape_linksM(request):
    form = LinkScrapingFormM(request.POST or None)
    scraped_links = []

    if request.method == 'POST' and form.is_valid():
        base_urls = form.cleaned_data['base_urls'].splitlines()  # Split lines for multiple URLs
        visited_links = set()

        for base_url in base_urls:
            if base_url.strip():  # Ignore empty lines
                find_all_links(base_url.strip(), visited_links, depth=2)

        # Query the database for links matching any base URL entered
        scraped_links = Linkscrap.objects.filter(link__in=visited_links)

    context = {
        'form': form,
        'scraped_links': scraped_links,
    }
    return render(request, 'scrap_mul_links.html', context)

# ----------------------------------------------------------------
#-----------------------------------------------------------------

def sitemap_scan_view(request):
    form = SitemapScanForm(request.POST or None)
    sitemap_urls = []

    if request.method == 'POST' and form.is_valid():
        base_url = form.cleaned_data['base_url']
        
        # Fetch sitemap URLs from the base URL
        fetched_urls = fetch_sitemap_urls(base_url)
        
        # Loop through each fetched URL and store it if it's not already in the database
        for url in fetched_urls:
            if not SitemapURL.objects.filter(url=url).exists():
                SitemapURL.objects.create(url=url)
            sitemap_urls.append(url)  # Add to list to display on the page

    context = {
        'form': form,
        'sitemap_urls': sitemap_urls,  # Display both new and existing URLs
    }
    return render(request, 'sitemap_scan.html', context)
# ----------------------------------------------------------------
#-----------------------------------------------------------------
def search_multiple_tables(request):
    form = KeywordSearchForm(request.POST or None)
    results = {}

    if request.method == 'POST' and form.is_valid():
        # Get keywords from the form and pass to trigger_search
        keywords = form.cleaned_data['keywords']
        results = trigger_search(keywords)  # Perform the search and get results

    context = {
        'form': form,
        'results': results,
    }
    return render(request, 'search_results.html', context)

# ----------------------------------------------------------------
#-----------------------------------------------------------------

def clear_data_view(request):
    if request.method == "POST":
        clear_data()
        return render(request, "clear_data.html", {"data_cleared": True})
    return render(request, "clear_data.html", {"data_cleared": False})
# ------------------------------------------------------------------------
# ------------------------------------------------------------------------

def scan_links(request):
    results = []

    if request.method == 'POST':
        form = URLScanForm(request.POST)
        if form.is_valid():
            # Get URLs from the form input, split by lines
            urls = form.cleaned_data['urls'].splitlines()

            # Loop through each URL and crawl
            for url in urls:
                visited = set()
                resources_found = []

                # Call the recursive_crawl function
                recursive_crawl(url, visited, resources_found)
                
                # Save resources found to the results list
                for resource in resources_found:
                    results.append({
                        'url': url,
                        'resource': resource
                    })
                    # Save to the database
                    Link_Resource.objects.create(url=url, resource=resource)

            # Display "No resources found" if the list is empty
            if not results:
                results = [{"url": url, "resource": "No resources found"}]

    else:
        form = URLScanForm()

    # Pass form and results to the template
    return render(request, 'scan_links.html', {'form': form, 'results': results})

# ------------------------------------------------------------------------
# ------------------------------------------------------------------------

def scan_git_repo(request):
    form = GitRepoForm()
    findings = []

    if request.method == 'POST':
        form = GitRepoForm(request.POST)
        if form.is_valid():
            repo_url = form.cleaned_data['repo_url']
            findings = clone_and_scan_repo(repo_url)

            # Store findings in the database
            for finding in findings:
                GitDataLeak.objects.create(
                    pattern_name=finding['pattern_name'],
                    file_path=finding['file_path'],
                    line_num=finding['line_num'],
                    content=finding['content'],
                )

    return render(request, 'scangit_repo.html', {'form': form, 'findings': findings})