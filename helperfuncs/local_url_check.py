from urllib.parse import urlparse, urljoin
from flask import request

ALLOWED_HOSTS = {"127.0.0.1"}

def is_local_url(target):
    if not target:
        return False


    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    print(target,host_url,host_url.hostname,redirect_url)
    if host_url.hostname not in ALLOWED_HOSTS:
        return False
    return (
        redirect_url.scheme == host_url.scheme and
        host_url.netloc == redirect_url.netloc
    )
