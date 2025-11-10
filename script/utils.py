from urllib.parse import urlparse

def load_list(list_path):
    data = []
    with open(list_path, 'r') as file:
        data = file.readlines()
    return [entry.split(',')[0] for entry in data]

def get_replacement(resources_path, resource_hash):
    replacement_path = resources_path+'/'+resource_hash[0]+'/'+ resource_hash[1]+'/'+resource_hash+".js"
    try:
        with open(replacement_path, 'rb') as file:
            data = file.read()
    except Exception as e:
        data = None
    return data

def truncate_url(url):
    truncate_size = 90
    return (url if len(url) < truncate_size else url[:truncate_size] + "...")

def get_domain(url):
    return urlparse(url).netloc

def is_base_domain(url):
    parsed_url = urlparse(url)
    return (parsed_url.path == '' or parsed_url.path == '/'), parsed_url.netloc
