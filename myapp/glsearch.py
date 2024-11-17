from googlesearch import search

def find_google_link(site_qry):
    site = str(site_qry)
    google_link=[]
    query = f"{site}"
    for j in search(query, tld="co.in", num=10, stop=10, pause=2):
        google_link.append(j)
    
    return google_link