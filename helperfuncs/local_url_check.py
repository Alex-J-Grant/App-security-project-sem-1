from urllib.parse import urlparse, urljoin
from flask import request



def is_local_url(target):
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return (
        redirect_url.scheme == host_url.scheme and
        host_url.netloc == redirect_url.netloc
    )