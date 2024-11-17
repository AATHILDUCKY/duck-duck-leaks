from django import forms

class ScanForm(forms.Form):
    domain = forms.CharField(label='Domain', max_length=100, required=True)


class GoogleSearchForm(forms.Form):
    site_qry = forms.CharField(label='Search Query', max_length=255)


class URLScanForm(forms.Form):
    urls = forms.CharField(widget=forms.Textarea(attrs={
        'placeholder': 'Enter multiple URLs, one per line',
        'rows': 10,
        'cols': 50,
    }), label='URLs to scan')

class DomainScanForm(forms.Form):
    domain = forms.URLField(label='Domain to Scan', max_length=255)

class DomainInputForm(forms.Form):
    domain = forms.CharField(
        max_length=255, 
        label='Domain', 
        widget=forms.TextInput(attrs={'placeholder': 'Enter domain to enumerate'})
    )

class GitHubScanForm(forms.Form):
    repository_url = forms.URLField(label='GitHub Repository URL', required=True)

class SecretScanForm(forms.Form):
    urls = forms.CharField(widget=forms.Textarea(attrs={'rows': 5, 'cols': 60}), label='Enter URLs (one per line)', required=True)

class LinkScrapingForm(forms.Form):
    base_url = forms.URLField(label='Enter the Base URL', required=True)


class LinkScrapingFormM(forms.Form):
    base_urls = forms.CharField(widget=forms.Textarea, label='Enter URLs (one per line)', required=True)

class SitemapScanForm(forms.Form):
    base_url = forms.URLField(label="Enter the Base URL", required=True)

class KeywordSearchForm(forms.Form):
    keywords = forms.CharField(label="Enter keywords (comma-separated)", required=True, widget=forms.TextInput(attrs={'placeholder': 'e.g., keyword1, keyword2'}))


class URLScanForm(forms.Form):
    urls = forms.CharField(widget=forms.Textarea, label="Enter URLs (one per line)")

class GitRepoForm(forms.Form):
    repo_url = forms.URLField(label="Git Repository URL")

class MultiInputSearchForm(forms.Form):
    input1 = forms.CharField(label='Input 1', required=True)
    input2 = forms.CharField(label='Input 2', required=False)
    input3 = forms.CharField(label='Input 3', required=False)
    input4 = forms.CharField(label='Input 4', required=False)
    input5 = forms.CharField(label='Input 5', required=False)