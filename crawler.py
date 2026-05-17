import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

visited = set()

def crawl_recursive(url, depth=2):
    if depth == 0 or url in visited:
        return []

    visited.add(url)
    found = []

    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        for link in soup.find_all("a", href=True):
            full_url = urljoin(url, link["href"])
            found.append(full_url)
            found += crawl_recursive(full_url, depth - 1)

    except:
        pass

    return list(set(found))
