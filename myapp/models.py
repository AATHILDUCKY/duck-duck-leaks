from django.db import models

class GoogleLink(models.Model):
    query = models.CharField(max_length=255)
    link = models.URLField()  # URLField is used for links
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.link


class Subdomain(models.Model):
    domain_name = models.CharField(max_length=255)
    subdomains = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.subdomains


class DirectoryEnumeration(models.Model):
    domain = models.CharField(max_length=255)
    directory = models.URLField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.directory
    
class GitHubScan(models.Model):
    repository_url = models.URLField(max_length=255)
    scan_results = models.JSONField()  # Store results as JSON
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.repository_url
    
class SecretScan(models.Model):
    url = models.URLField(max_length=500)
    secret_type = models.CharField(max_length=100)
    secret_value = models.TextField()
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.secret_type} found in {self.url}'

class Linkscrap(models.Model):
    link = models.URLField()  
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.link
    
    

class SitemapURL(models.Model):
    url = models.URLField(unique=True)  # Ensure URLs are unique
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url
    
class Link_Resource(models.Model):
    url = models.URLField()
    resource = models.CharField(max_length=500)

    def __str__(self):
        return f"{self.url} - {self.resource}"
    

class GitDataLeak(models.Model):
    pattern_name = models.CharField(max_length=100)
    file_path = models.CharField(max_length=255)
    line_num = models.IntegerField()
    content = models.TextField()

    def __str__(self):
        return f"{self.pattern_name} found in {self.file_path} at line {self.line_num}"