from urllib.parse import urlparse, parse_qs

def extract_data(urls):
    params = {}
    js_files = []

    for url in urls:
        parsed = urlparse(url)

        # Extract parameters
        query = parse_qs(parsed.query)
        if query:
            params[url] = query

        # Extract JS files
        if url.endswith(".js"):
            js_files.append(url)

    return {
        "parameters": params,
        "js_files": js_files
    }
